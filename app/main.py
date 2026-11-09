"""Console Hangar : routes web."""
import asyncio
import calendar
import ipaddress
import json
import os
import re
import secrets
import time

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import access, alerts, backup, cloudflare, db, dbadmin, ha, monitor, move, nodes, security, stats, system
from . import domains as D
from . import platform as P

HERE = os.path.dirname(__file__)
LAN = access.parse_nets(os.environ.get("LAN_CIDR", "192.168.91.0/24"))
ph = PasswordHasher()

db.init()
P.recover()
monitor.start()


def _secret():
    path = "/srv/platform/hangar.secret"
    if not os.path.exists(path):
        P.write_private(path, secrets.token_hex(32))
    return open(path).read().strip()


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=f"{HERE}/static"), name="static")
tpl = Jinja2Templates(directory=f"{HERE}/templates")
tpl.env.globals.update(LABELS=P.LABELS, mask_env=P.mask_env)
tpl.env.globals["asset_v"] = int(max(os.path.getmtime(f"{HERE}/static/{f}") for f in ("app.js", "style.css")))
tpl.env.filters["when"] = lambda ts: time.strftime("%d/%m %H:%M", time.localtime(ts)) if ts else "—"
tpl.env.filters["clock"] = lambda ts: time.strftime("%d/%m %H:%M:%S", time.localtime(ts))
tpl.env.filters["size"] = backup.human
tpl.env.filters["ago"] = lambda ts: _ago(ts)
tpl.env.filters["dur"] = lambda sec: _dur(sec)


def _dur(sec):
    if sec is None:
        return "—"
    sec = int(sec)
    d, h, m = sec // 86400, sec % 86400 // 3600, sec % 3600 // 60
    return f"{d} j {h} h" if d else f"{h} h {m:02d}" if h else f"{m} min"


def _ago(ts):
    if not ts:
        return "jamais"
    d = time.time() - ts
    if d < 90:
        return "à l'instant"
    if d < 3600:
        return f"il y a {d // 60:.0f} min"
    if d < 86400 * 2:
        return f"il y a {d // 3600:.0f} h"
    return f"il y a {d // 86400:.0f} j"


@app.middleware("http")
async def guard(request: Request, call_next):
    ip = request.client.host if request.client else ""
    try:
        addr = ipaddress.ip_address(ip)
        allowed = any(addr in n for n in LAN) or addr.is_loopback
    except ValueError:
        allowed = False
    if not allowed:
        return PlainTextResponse("Console réservée au réseau local.", status_code=403)
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        # formulaires : refusés s'ils viennent d'un autre site (en plus du cookie SameSite=Strict)
        # Sec-Fetch-Site d'abord (envoyé par tous les navigateurs récents) ; sinon l'en-tête Origin.
        # Avec Referrer-Policy no-referrer, Chrome envoie « Origin: null » même pour la page elle-même.
        sfs, origin = request.headers.get("sec-fetch-site"), request.headers.get("origin")
        if (sfs and sfs not in ("same-origin", "none")) or (
                not sfs and origin not in (None, "null", f"{request.url.scheme}://{request.url.netloc}")):
            return PlainTextResponse("Requête d'un autre site refusée.", status_code=403)
    request.state.nonce = secrets.token_urlsafe(16)
    if not request.url.path.startswith(("/login", "/static")):
        u, sid = request.session.get("user"), request.session.get("sid")
        row = db.one("SELECT s.seen FROM sessions s JOIN users u ON u.username = s.username "
                     "WHERE s.id = ? AND s.username = ?", (sid or "", u or "")) if u and sid else None
        now = time.time()
        if not row or now - row["seen"] > SESSION_IDLE:   # déconnectée, compte supprimé ou inactive trop longtemps
            if sid:
                db.x("DELETE FROM sessions WHERE id = ?", (sid,))
            request.session.clear()
            return RedirectResponse("/login", status_code=303)
        if now - row["seen"] > 60:
            db.x("UPDATE sessions SET seen = ? WHERE id = ?", (now, sid))
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        f"default-src 'self'; script-src 'self' 'nonce-{request.state.nonce}'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'")
    return response


app.add_middleware(SessionMiddleware, secret_key=_secret(), session_cookie="hangar",
                   max_age=8 * 3600, same_site="strict", https_only=True)


# ---------------------------------------------------------------- aides

def go(url):
    return RedirectResponse(url, status_code=303)


def flash(request, msg, kind="ok"):
    request.session["flash"] = {"msg": msg, "kind": kind}


def _sec_alerts():
    """Nœuds avec un problème de sécurité (pastille du menu)."""
    try:
        return sum(1 for n in nodes.all_nodes() if n["id"] != nodes.LOCAL and n["state"] == "ok"
                   and any(c["level"] == "error" for c in security.checks(n)))
    except Exception:
        return 0


def render(request, name, status_code=200, **ctx):
    ctx.setdefault("title", "Hangar")
    ctx.update(flash=request.session.pop("flash", None), s=db.settings(), csp_nonce=getattr(request.state, "nonce", ""),
               user=request.session.get("user"), app_count=len(db.apps()), sec_alerts=_sec_alerts())
    return tpl.TemplateResponse(request, name, ctx, status_code=status_code)


def get_app_or_404(slug):
    a = db.app(slug)
    if not a:
        from fastapi import HTTPException
        raise HTTPException(404, "Application inconnue")
    return a


SLUG = P.SLUG
DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
PKG, IMAGE, GIT, VERSION = P.PKG, P.IMAGE, P.GIT, P.VERSION
RESERVED = {"health", "static", "well-known", "admin"}


def validate(f, cur=None):
    """Retourne (données, erreurs) à partir du formulaire d'une appli."""
    d, e = {}, {}
    s = db.settings()
    d["name"] = (f.get("name") or "").strip()[:80]
    if not d["name"]:
        e["name"] = "Donne un nom à l'application."
    d["pkg"] = (f.get("pkg") or "").strip()
    if d["pkg"] and not PKG.match(d["pkg"]):
        e["pkg"] = "Format attendu : fr.piperault.monappli"
    elif d["pkg"] and db.one("SELECT 1 FROM apps WHERE pkg = ? AND slug != ?", (d["pkg"], cur["slug"] if cur else "")):
        e["pkg"] = "Ce package est déjà relié à une autre appli."

    if cur:
        d["slug"] = cur["slug"]
    else:
        d["slug"] = (f.get("slug") or "").strip().lower()
        if not SLUG.match(d["slug"]):
            e["slug"] = "Lettres minuscules, chiffres et tirets, 32 caractères au plus."
        elif d["slug"] in RESERVED:
            e["slug"] = "Cet identifiant est réservé."
        elif db.app(d["slug"]):
            e["slug"] = "Cet identifiant est déjà utilisé."

    d["routes"], err = D.parse_routes(f, d["slug"] or "-")
    if err:
        e["routes"] = err

    for key, lo, hi, default, msg in (("port", 1, 65535, 8080, "Port entre 1 et 65535."),
                                      ("mem_mb", 32, 4096, 256, "Entre 32 et 4096 Mo.")):
        try:
            d[key] = int(f.get(key) or default)
            if not lo <= d[key] <= hi:
                raise ValueError
        except ValueError:
            d[key] = f.get(key)
            e[key] = msg
    d["data_user"] = (f.get("data_user") or "").strip()
    if d["data_user"] and not P.USER_RE.match(d["data_user"]):
        e["data_user"] = "Laisse vide (automatique) ou indique un UID, par exemple 1000 ou 1000:1000."
    d["health_path"] = (f.get("health_path") or "/").strip()
    if not P.HEALTH.match(d["health_path"]):
        e["health_path"] = "Chemin commençant par /, sans espace."

    d["source"] = "git" if f.get("source") == "git" else "image"
    d["image"] = (f.get("image") or "").strip()
    version = (f.get("version") or "").strip()
    if d["source"] == "image":
        last = d["image"].rsplit("/", 1)[-1]
        if ":" in last:  # tag collé à l'image : on le sépare
            d["image"], tag = d["image"].rsplit(":", 1)
            version = version or tag
        if not IMAGE.match(d["image"]):
            e["image"] = "Image Docker sans tag, par exemple ghcr.io/piperault/courses-api"
    elif not GIT.match(d["image"]):
        e["image"] = "URL du dépôt sans branche, par exemple https://github.com/piperault/meteo-backend.git"
    if not cur:
        d["version"] = version or ("latest" if d["source"] == "image" else "main")
        if not VERSION.match(d["version"]):
            e["version"] = "Tag ou branche : lettres, chiffres, . _ - /"

    env_text = (f.get("env") or "").replace("\r\n", "\n")
    d["env"] = P.unmask_env(env_text, cur["env"]) if cur else env_text.strip()
    env, errs = P.parse_env(d["env"])
    if errs:
        e["env"] = " ; ".join(errs[:3])
    elif "DATABASE_URL" in env and f.get("db") == "on":
        e["env"] = "DATABASE_URL est injectée automatiquement quand la base est activée."
    d["db"] = 1 if f.get("db") == "on" else 0
    if not cur:
        choices = {c["id"] for c in node_choices()}
        d["node"] = f.get("node") or "local"
        if d["node"] not in choices:
            e["node"] = "Nœud indisponible."
    return d, e


def node_choices(purpose="app"):
    """Nœuds où déployer : la console (sauf en « gestion seulement ») et les nœuds installés, avec la RAM
    encore libre (total - réservée). purpose='standby' : choix d'un secours à chaud."""
    out = []
    reserved = {}
    for a in db.apps():
        if a["desired"] == "running":
            reserved[a["node"]] = reserved.get(a["node"], 0) + a["mem_mb"]
    local_total = stats.host_now()["mem_total"]
    if nodes.console_hosts(purpose):
        out.append({"id": "local", "name": "Ce serveur (console)", "free": local_total - reserved.get("local", 0)})
    for n in nodes.all_nodes():
        if n["id"] == "local" or n["state"] != "ok":
            continue
        total = (n["info"] or {}).get("mem_total") or 0
        out.append({"id": n["id"], "name": n["name"], "free": total - reserved.get(n["id"], 0)})
    return out


async def apply_registry(f, d):
    """Si un jeton est saisi dans la fiche, connecte Docker au registre de l'image.
    Retourne (connecté, erreurs) ; le jeton n'est jamais stocké par Hangar lui-même."""
    token = (f.get("reg_token") or "").strip()
    if d.get("source") != "image" or not token:
        return False, {}
    reg = P.registry_of(d["image"])
    user = (f.get("reg_user") or "").strip() or P.registry_owner(d["image"])
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$", user or ""):
        return False, {"reg_user": "Indique ton nom d'utilisateur sur le registre."}
    if len(token) > 4096 or any(c.isspace() for c in token):
        return False, {"reg_token": "Jeton invalide."}
    try:
        await asyncio.to_thread(P.registry_login, reg, user, token)
    except ValueError as e:
        return False, {"reg_token": str(e)}
    return True, {}


# ---------------------------------------------------------------- connexion

@app.get("/login")
async def login_page(request: Request):
    if request.session.get("user"):
        return go("/")
    return render(request, "login.html", title="Connexion")


SESSION_IDLE = 30 * 60            # session fermée après 30 min sans activité
LOGIN_WINDOW = 15 * 60            # fenêtre de comptage des échecs
LOGIN_MAX_IP, LOGIN_MAX_USER = 5, 20
_fails = {}                       # ("ip"|"user", valeur) -> [horodatages d'échec]
_verify_gate = asyncio.Semaphore(2)
_DUMMY = ph.hash(secrets.token_hex(16))   # vérifié pour un compte inconnu : même temps de réponse


def _recent(key, now):
    lst = [t for t in _fails.get(key, []) if now - t < LOGIN_WINDOW]
    if lst:
        _fails[key] = lst
    else:
        _fails.pop(key, None)
    return lst


def _new_session(request, username):
    request.session.clear()
    sid = secrets.token_urlsafe(32)
    now = time.time()
    db.x("INSERT INTO sessions(id, username, created, seen, ip) VALUES(?, ?, ?, ?, ?)",
         (sid, username, now, now, request.client.host if request.client else ""))
    db.x("DELETE FROM sessions WHERE seen < ?", (now - SESSION_IDLE,))
    request.session.update(user=username, sid=sid)


@app.post("/login")
async def login(request: Request):
    f = await request.form()
    name = (f.get("username") or "").strip()[:64]
    ip = request.client.host if request.client else "?"
    now = time.time()
    by_ip, by_user = _recent(("ip", ip), now), _recent(("user", name.lower()), now)
    if len(by_ip) >= LOGIN_MAX_IP or len(by_user) >= LOGIN_MAX_USER:
        await asyncio.sleep(1.5)
        wait = int(LOGIN_WINDOW - (now - min(by_ip if len(by_ip) >= LOGIN_MAX_IP else by_user))) // 60 + 1
        flash(request, f"Trop d'essais. Réessaie dans {wait} min.", "error")
        return go("/login")
    user = db.one("SELECT * FROM users WHERE username = ?", (name,))
    async with _verify_gate:   # vérifications Argon2 en série : pas de force brute en parallèle
        try:
            ok = await asyncio.to_thread(ph.verify, user["hash"] if user else _DUMMY, f.get("password") or "")
            ok = ok and bool(user)
        except (VerifyMismatchError, InvalidHashError):
            ok = False
    if not ok:
        for k in (("ip", ip), ("user", name.lower())):
            _fails.setdefault(k, []).append(now)
        n = len(_fails[("ip", ip)])
        if n <= LOGIN_MAX_IP:
            P.log("warn", "console", f"échec de connexion pour « {name[:32]} » depuis {ip}"
                  + (" : adresse bloquée 15 min" if n == LOGIN_MAX_IP else ""))
        if n == LOGIN_MAX_IP or len(_fails[("user", name.lower())]) == LOGIN_MAX_USER:
            P.spawn(alerts.send, "Hangar : tentatives de connexion", f"{n} échecs depuis {ip} (compte « {name[:32]} »), "
                    "connexion bloquée 15 min.", 4, ["warning"], f"login-{ip}", 900)
        await asyncio.sleep(1.5)
        flash(request, "Identifiant ou mot de passe incorrect.", "error")
        return go("/login")
    _fails.pop(("ip", ip), None)
    _new_session(request, user["username"])
    P.log("info", "console", f"connexion de {user['username']} depuis {ip}")
    return go("/")


@app.post("/logout")
async def logout(request: Request):
    if request.session.get("sid"):
        db.x("DELETE FROM sessions WHERE id = ?", (request.session["sid"],))
    request.session.clear()
    return go("/login")


# ---------------------------------------------------------------- applications

@app.get("/")
async def home(request: Request):
    rows = await asyncio.to_thread(P.apps_with_status)
    return render(request, "apps.html", title="Applications", nav="apps", apps=rows, req24=stats.requests_24h(),
                  refresh=any(r["status"] == "deploying" for r in rows),
                  ram_total=sum(r["ram"] for r in rows))


@app.get("/apps/new")
async def new_app(request: Request):
    ch = node_choices()
    if not ch:
        flash(request, "La console est en « gestion seulement » et aucun nœud n'est en ligne : ajoute un nœud "
                       "ou réautorise les applis sur la console.", "error")
        return go("/nodes#console")
    best = max(ch, key=lambda c: c["free"])["id"]
    dft = D.default()
    blank = {"name": "", "pkg": "fr.piperault.", "slug": "", "port": 8080,
             "routes": [{"kind": "sub", "domain": dft["name"] if dft else "", "sub": ""}],
             "health_path": "/", "mem_mb": 256, "source": "image", "image": "", "version": "", "env": "", "db": 0,
             "data_user": "", "node": best}
    return render(request, "app_form.html", title="Nouvelle application", nav="apps", a=blank, new=True, errors={},
                  registries=P.registry_logins(), node_choices=ch, best=best, domains=D.all_domains())


@app.post("/apps/new")
async def create_app(request: Request):
    f = await request.form()
    d, errors = validate(f)
    if not errors:
        _, errors = await apply_registry(f, d)
    if errors:
        return render(request, "app_form.html", 400, title="Nouvelle application", nav="apps", a=d, new=True,
                      errors=errors, registries=P.registry_logins(), reg_user=f.get("reg_user") or "",
                      node_choices=node_choices(), best=None, domains=D.all_domains())
    slug = d.pop("slug")
    rts = d.pop("routes")
    d.update(host_port=P.next_host_port(), state="deploying", desired="running", created_at=time.time(),
             db_password=secrets.token_hex(16) if d["db"] else None)
    db.insert_app(slug, d)
    D.set_routes(slug, rts)
    P.log("info", slug, f"appli créée, port local {d['host_port']}")
    P.spawn(P.deploy, slug, d["version"], "create")
    flash(request, f"{d['name']} créée. Déploiement de {d['version']} en cours.")
    return go(f"/apps/{slug}")


async def _app_ctx(request, slug):
    """Contexte complet de la fiche d'une appli (affichage, ou réaffichage après une erreur de saisie)."""
    rows = await asyncio.to_thread(P.apps_with_status)
    a = next(r for r in rows if r["slug"] == slug)
    events = db.q("SELECT * FROM events WHERE app = ? ORDER BY id DESC LIMIT 8", (slug,))
    names = await asyncio.to_thread(P.app_public_names, a, db.settings())
    rng = request.query_params.get("r") if request.query_params.get("r") in stats.RANGES else "24h"
    st = stats.app_charts(stats.series(slug, rng), a["mem_mb"])
    dbi = await asyncio.to_thread(dbadmin.info, slug) if a["db"] and a["status"] != "deploying" else None
    others = [c for c in node_choices() if c["id"] != a["node"]]
    dsize = await asyncio.to_thread(P.dir_size, a["node"], f"{P.app_dir(slug)}/data") if others else None
    a["routes"] = D.routes(slug)
    hst = await asyncio.to_thread(ha.status, slug)
    busy = (hst and (hst["busy"] or hst["h"]["state"] == "setup"))
    return dict(title=a["name"], nav="apps", a=a, new=False, errors={}, events=events, names=names, ha=hst,
                console_only=nodes.console_role()["manage_only"],
                ha_nodes=[c for c in node_choices("standby") if c["id"] != a["node"]],
                ha_inst=[c for c in others if c["id"] != a["node"]],
                refresh=a["status"] == "deploying" or bool(busy), registries=P.registry_logins(), st=st, dbi=dbi,
                ranges=list(stats.RANGES), others=others, dsize=dsize, domains=D.all_domains(), cf=cloudflare.status())


# ---------------------------------------------------------------- haute disponibilité

def _int(v, lo, hi, default):
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


@app.post("/apps/{slug}/ha/enable")
async def ha_enable(request: Request, slug: str):
    a = get_app_or_404(slug)
    f = await request.form()
    mode = f.get("mode")
    chosen = [f.get("standby")] if mode == "standby" else f.getlist("inst")
    err = await asyncio.to_thread(ha.validate, a, mode, chosen, bool(f.get("ack")))
    if not err and (ha.get(slug) or a["state"] == "deploying"):
        err = "Une opération est déjà en cours sur cette appli."
    if err:
        flash(request, err, "error")
        return go(f"/apps/{slug}#hautedispo")
    P.spawn(ha.enable, slug, mode, chosen, bool(f.get("auto")), _int(f.get("delay"), 4, 60, 4),
            _int(f.get("sync_min"), 1, 1440, 5), request.session.get("user"))
    flash(request, "Mise en place de la haute dispo lancée : suis l'avancement dans les événements.")
    return go(f"/apps/{slug}#hautedispo")


@app.post("/apps/{slug}/ha/options")
async def ha_options(request: Request, slug: str):
    get_app_or_404(slug)
    f = await request.form()
    if ha.get(slug):
        ha.update_options(slug, bool(f.get("auto")), _int(f.get("delay"), 4, 60, 4), _int(f.get("sync_min"), 1, 1440, 5),
                          request.session.get("user"))
        flash(request, "Réglages de la bascule enregistrés.")
    return go(f"/apps/{slug}#hautedispo")


def _ha_job(fn, slug, user, what):
    try:
        fn(slug, user)
    except Exception as e:
        P.log("error", slug, f"{what} : {e}")


@app.post("/apps/{slug}/ha/{action}")
async def ha_action(request: Request, slug: str, action: str):
    get_app_or_404(slug)
    fns = {"switch": (ha.switchover, "bascule programmée", "Bascule lancée."),
           "resync": (ha.resync, "resynchronisation", "Resynchronisation lancée."),
           "disable": (ha.disable, "retrait de la haute dispo", "Retrait de la haute dispo lancé.")}
    if action in fns and ha.get(slug):
        fn, what, msg = fns[action]
        P.spawn(_ha_job, fn, slug, request.session.get("user"), what)
        flash(request, msg + " Suis l'avancement dans les événements.")
    return go(f"/apps/{slug}#hautedispo")


@app.post("/nodes/console")
async def console_settings(request: Request):
    f = await request.form()
    await asyncio.to_thread(nodes.save_console_role, f.get("role") == "manage", f.get("standby") == "on",
                            request.session.get("user"))
    flash(request, "Rôle de la console enregistré.")
    return go("/nodes#console")


@app.post("/ha/settings")
async def ha_settings(request: Request):
    f = await request.form()
    try:
        await asyncio.to_thread(ha.save_settings, f.get("fence"), f.get("fence_after") or 180, request.session.get("user"))
        flash(request, "Réglages de haute dispo enregistrés et envoyés aux nœuds.")
    except (ValueError, TypeError) as e:
        flash(request, str(e), "error")
    return go("/nodes#hautedispo")


@app.get("/apps/{slug}")
async def show_app(request: Request, slug: str):
    get_app_or_404(slug)
    return render(request, "app_form.html", **await _app_ctx(request, slug))


@app.post("/apps/{slug}")
async def save_app(request: Request, slug: str):
    cur = get_app_or_404(slug)
    if cur["state"] == "deploying":
        flash(request, "Un déploiement est en cours. Réessaie quand il sera terminé.", "error")
        return go(f"/apps/{slug}")
    f = await request.form()
    d, errors = validate(f, cur)
    logged = False
    if not errors:
        logged, errors = await apply_registry(f, d)
    if errors:
        ctx = await _app_ctx(request, slug)
        ctx["a"].update(d)          # saisie conservée, adresses comprises
        ctx.update(errors=errors, refresh=False, reg_user=f.get("reg_user") or "")
        return render(request, "app_form.html", 400, **ctx)
    d.pop("slug")
    rts = d.pop("routes")
    D.set_routes(slug, rts)
    runtime = ("port", "health_path", "mem_mb", "source", "image", "env", "db", "data_user")
    changed = [k for k in runtime if str(d[k]) != str(cur[k])]
    if logged and cur["state"] == "error":
        changed.append("identifiants du registre")  # le téléchargement avait échoué : on retente
    if d["db"] and not cur["db_password"]:
        d["db_password"] = secrets.token_hex(16)
    db.update_app(slug, **d)
    if changed and cur["desired"] == "running":
        db.update_app(slug, state="deploying")
        P.spawn(P.deploy, slug, cur["version"], "config", cur)
        flash(request, "Enregistré. Redéploiement en cours, l'ancienne configuration revient si le healthcheck échoue.")
    else:
        try:
            await asyncio.to_thread(P.apply_routing)
            flash(request, "Enregistré. Adresses publiques mises à jour.")
        except RuntimeError as e:
            flash(request, str(e), "error")
    P.log("info", slug, "configuration modifiée" + (f" ({', '.join(changed)})" if changed else ""))
    return go(f"/apps/{slug}")


@app.post("/apps/{slug}/version")
async def deploy_version(request: Request, slug: str):
    a = get_app_or_404(slug)
    v = ((await request.form()).get("version") or "").strip()
    if a["state"] == "deploying":
        flash(request, "Un déploiement est déjà en cours.", "error")
    elif not VERSION.match(v):
        flash(request, "Version invalide : lettres, chiffres, . _ - /", "error")
    else:
        db.update_app(slug, state="deploying")
        P.spawn(P.deploy, slug, v, "update")
        flash(request, f"Déploiement de {v} en cours. Si le healthcheck échoue, {a['version']} reste en ligne.")
    return go(f"/apps/{slug}")


@app.post("/apps/{slug}/rollback")
async def rollback(request: Request, slug: str):
    a = get_app_or_404(slug)
    if a["state"] == "deploying" or not a["prev_version"]:
        flash(request, "Retour arrière impossible pour l'instant.", "error")
    else:
        db.update_app(slug, state="deploying")
        P.spawn(P.deploy, slug, a["prev_version"], "rollback")
        flash(request, f"Retour à {a['prev_version']} en cours.")
    return go(f"/apps/{slug}")


@app.post("/apps/{slug}/{action}")
async def app_action(request: Request, slug: str, action: str):
    a = get_app_or_404(slug)
    back = (await request.form()).get("back") or f"/apps/{slug}"
    back = back if back.startswith("/") and not back.startswith("//") else "/"
    if a["state"] == "deploying":
        flash(request, "Un déploiement est en cours.", "error")
        return go(back)
    if action in ("start", "restart"):
        db.update_app(slug, state="deploying")
        P.spawn(P.start if action == "start" else P.restart, slug)
        flash(request, f"{a['name']} : {'démarrage' if action == 'start' else 'redémarrage'} en cours.")
    elif action == "stop":
        await asyncio.to_thread(P.stop, slug)
        flash(request, f"{a['name']} arrêtée. Ses adresses répondent 503.")
    elif action == "delete":
        f = await request.form()
        if (f.get("confirm") or "").strip() != slug:
            flash(request, f"Tape {slug} pour confirmer la suppression.", "error")
            return go(f"/apps/{slug}#supprimer")
        db.update_app(slug, state="deploying")
        P.spawn(P.delete, slug)
        flash(request, f"{a['name']} en cours de suppression. Fichiers et dump conservés dans /srv/backups/deleted.")
        return go("/")
    else:
        flash(request, "Action inconnue.", "error")
    return go(back)


@app.get("/apps/{slug}/logs")
async def app_logs(request: Request, slug: str):
    a = get_app_or_404(slug)
    out = await asyncio.to_thread(P.logs, slug)
    return render(request, "logs.html", title=f"Logs · {a['name']}", nav="apps", a=a, logs=out)


# ---------------------------------------------------------------- domaines

def _entry_choices():
    out = [{"id": "local", "name": "Ce serveur (console)"}]
    out += [{"id": n["id"], "name": n["name"], "address": n["address"]} for n in nodes.all_nodes()
            if n["id"] != "local" and n["state"] in ("ok", "offline")]
    return out


@app.get("/domains")
async def domains_page(request: Request):
    names = await asyncio.to_thread(P.public_names)
    doms = D.all_domains()
    usage = {d["name"]: db.one("SELECT COUNT(DISTINCT slug) AS n FROM routes WHERE domain = ?", (d["name"],))["n"]
             for d in doms}
    return render(request, "domains.html", title="Domaines", nav="domains", doms=doms, usage=usage, names=names,
                  missing=[n for n in names if n["ok"] is False], cf=cloudflare.status(), entries=_entry_choices(),
                  tunnel_id=P.tunnel_id(), tunnel=P.tunnel_status(), form=request.session.pop("dform", None))


async def _after_domains(request, tunnel_before):
    try:
        await asyncio.to_thread(P.apply_routing)
    except RuntimeError as e:
        flash(request, str(e), "error")
        return False
    if P.tunnel_ready() != tunnel_before:
        P.spawn(P.sync_all_tunnels)   # connecteurs des nœuds : actifs seulement s'il y a un domaine en tunnel
    return True


@app.post("/domains/add")
async def domains_add(request: Request):
    f = await request.form()
    before = P.tunnel_ready()
    errs = D.save(f.get("name"), f.get("mode"), f.get("hub"), f.get("entry") or "local", f.get("ip"),
                  make_default=f.get("default") == "on")
    if errs:
        request.session["dform"] = {k: f.get(k) or "" for k in ("name", "mode", "hub", "entry", "ip")}
        flash(request, " ".join(errs.values()), "error")
        return go("/domains#ajouter")
    name = f.get("name").strip().lower().rstrip(".")
    if await _after_domains(request, before):
        P.log("ok", "caddy", f"domaine {name} ajouté ({f.get('mode')})")
        flash(request, f"{name} ajouté. Les applis peuvent maintenant y avoir une adresse.")
    return go("/domains")


@app.post("/domains/{name}")
async def domains_edit(request: Request, name: str):
    old = D.get(name)
    if not old:
        return go("/domains")
    f = await request.form()
    before = P.tunnel_ready()
    errs = D.save(name, f.get("mode"), f.get("hub"), f.get("entry") or "local", f.get("ip"),
                  make_default=f.get("default") == "on", old=old)
    if errs:
        flash(request, " ".join(errs.values()), "error")
        return go(f"/domains#d-{name}")
    if not await _after_domains(request, before):
        D.save(name, old["mode"], old["hub"], old["entry"], old["ip"], old=old)   # retour à l'ancien réglage
        await asyncio.to_thread(P.apply_routing)
        return go("/domains")
    P.log("ok", "caddy", f"domaine {name} modifié : {f.get('mode')}, préfixe {f.get('hub') or 'aucun'}")
    msg = f"{name} enregistré, Caddy rechargé."
    if f.get("mode") != old["mode"]:
        msg += (" Ses noms passent maintenant par le tunnel Cloudflare." if f.get("mode") == "tunnel"
                else " Les ports 80 et 443 doivent arriver jusqu'à la machine d'entrée choisie.")
    flash(request, msg)
    return go("/domains")


@app.post("/domains/{name}/remove")
async def domains_remove(request: Request, name: str):
    before = P.tunnel_ready()
    try:
        D.remove(name)
    except ValueError as e:
        flash(request, str(e), "error")
        return go("/domains")
    if await _after_domains(request, before):
        P.log("info", "caddy", f"domaine {name} retiré")
        flash(request, f"{name} retiré.")
    return go("/domains")


@app.post("/cloudflare/token")
async def cf_token(request: Request):
    f = await request.form()
    try:
        zones = await asyncio.to_thread(cloudflare.set_token, f.get("token"))
    except ValueError as e:
        flash(request, str(e), "error")
        return go("/domains#cloudflare")
    st = await asyncio.to_thread(cloudflare.sync_quiet) or cloudflare.status()
    err = cloudflare.status().get("error")
    flash(request, f"Jeton accepté (zones : {', '.join(zones) or 'aucune'}). " +
          (f"Synchronisation en échec : {err}" if err else "Noms publics synchronisés."), "error" if err else "ok")
    return go("/domains#cloudflare")


@app.post("/cloudflare/remove")
async def cf_remove(request: Request):
    await asyncio.to_thread(cloudflare.remove_token)
    flash(request, "Jeton d'API retiré. Ce qui existe chez Cloudflare reste en place.")
    return go("/domains#cloudflare")


@app.post("/cloudflare/sync")
async def cf_sync(request: Request):
    await asyncio.to_thread(cloudflare.sync_quiet)
    st = cloudflare.status()
    flash(request, f"Synchronisation en échec : {st['error']}" if st.get("error") else
          "Cloudflare est à jour." + (" " + " ; ".join(st.get("changes") or []) if st.get("changes") else ""),
          "error" if st.get("error") else "ok")
    return go("/domains")


@app.post("/settings/tunnel")
async def save_tunnel_token(request: Request):
    f = await request.form()
    try:
        tid = await asyncio.to_thread(P.set_tunnel_token, f.get("token") or "")
    except (ValueError, RuntimeError) as e:
        flash(request, str(e), "error")
        return go("/domains#tunnel")
    P.spawn(cloudflare.sync_quiet)
    flash(request, f"Jeton enregistré. cloudflared est connecté au tunnel {tid}.")
    return go("/domains#tunnel")


# ---------------------------------------------------------------- réglages : accès, comptes, registres

@app.get("/settings")
async def settings_page(request: Request):
    return render(request, "settings.html", title="Réglages", nav="settings", acc=access.current(),
                  ips=access.local_ips(), pending=access.pending(), client=request.client.host,
                  users=db.q("SELECT username FROM users ORDER BY username"), registries=P.registry_logins(),
                  aform=request.session.pop("aform", None), aerr=request.session.pop("aerr", None))


@app.post("/settings/access")
async def settings_access(request: Request):
    f = await request.form()
    errs, new = access.validate(f.get("ip"), f.get("port"), f.get("nets"), request.client.host)
    cur = access.current()
    if not errs and new["ip"] == cur["ip"] and new["port"] == cur["port"] and new["nets"] == cur["nets"]:
        flash(request, "Rien n'a changé.")
        return go("/settings#acces")
    if errs:
        request.session["aform"] = {"ip": f.get("ip"), "port": f.get("port"), "nets": f.get("nets")}
        request.session["aerr"] = errs
        flash(request, " ".join(errs.values()), "error")
        return go("/settings#acces")
    try:
        url = await asyncio.to_thread(access.apply, new, request.session.get("user"))
    except (ValueError, RuntimeError) as e:
        flash(request, str(e), "error")
        return go("/settings#acces")
    return render(request, "access_moved.html", title="Accès modifié", nav="settings", url=url, delay=access.DELAY)


@app.post("/settings/access/confirm")
async def settings_access_confirm(request: Request):
    await asyncio.to_thread(access.confirm, request.session.get("user"))
    flash(request, "Nouvel accès confirmé : il est gardé.")
    return go("/settings#acces")


@app.post("/settings/access/revert")
async def settings_access_revert(request: Request):
    P.spawn(access.revert)
    return PlainTextResponse("Ancien réglage remis : la console redémarre sur son ancienne adresse.")


@app.post("/settings/registry/remove")
async def remove_registry(request: Request):
    reg = ((await request.form()).get("registry") or "").strip()
    if reg in P.registry_logins():
        await asyncio.to_thread(P.registry_logout, reg)
        flash(request, f"Identifiants retirés pour {reg}. Les images déjà téléchargées restent utilisables.")
    return go("/settings")


USER_RE = re.compile(r"^[a-z][a-z0-9._-]{1,31}$")


def _check_pw(f):
    pw = f.get("password") or ""
    if len(pw) < 10:
        return None, "Mot de passe : 10 caractères au moins."
    if pw != (f.get("password2") or ""):
        return None, "Les deux saisies du mot de passe diffèrent."
    return pw, None


@app.post("/users/add")
async def users_add(request: Request):
    f = await request.form()
    name = (f.get("username") or "").strip().lower()
    pw, err = _check_pw(f)
    if not USER_RE.match(name):
        err = "Identifiant : lettres minuscules, chiffres, . _ -, 2 à 32 caractères."
    elif db.one("SELECT 1 FROM users WHERE username = ?", (name,)):
        err = "Ce compte existe déjà."
    if err:
        flash(request, err, "error")
        return go("/settings#comptes")
    db.x("INSERT INTO users(username, hash) VALUES(?, ?)", (name, ph.hash(pw)))
    P.log("ok", "console", f"compte {name} créé par {request.session.get('user')}")
    flash(request, f"Compte {name} créé.")
    return go("/settings#comptes")


@app.post("/users/{name}/password")
async def users_password(request: Request, name: str):
    f = await request.form()
    me = request.session.get("user")
    u = db.one("SELECT * FROM users WHERE username = ?", (name,))
    if not u:
        return go("/settings#comptes")
    if name == me:
        try:
            ok = ph.verify(u["hash"], f.get("current") or "")
        except (VerifyMismatchError, InvalidHashError):
            ok = False
        if not ok:
            await asyncio.sleep(1)
            flash(request, "Mot de passe actuel incorrect.", "error")
            return go("/settings#comptes")
    pw, err = _check_pw(f)
    if err:
        flash(request, err, "error")
        return go("/settings#comptes")
    db.x("UPDATE users SET hash = ? WHERE username = ?", (ph.hash(pw), name))
    db.x("DELETE FROM sessions WHERE username = ? AND id != ?", (name, request.session.get("sid") or ""))
    P.log("ok", "console", f"mot de passe de {name} changé par {me} (ses autres sessions sont fermées)")
    flash(request, f"Mot de passe de {name} changé.")
    return go("/settings#comptes")


@app.post("/users/{name}/remove")
async def users_remove(request: Request, name: str):
    me = request.session.get("user")
    if name == me:
        flash(request, "Tu ne peux pas supprimer ton propre compte.", "error")
    elif db.one("SELECT COUNT(*) AS n FROM users")["n"] <= 1:
        flash(request, "Il faut garder au moins un compte.", "error")
    else:
        db.x("DELETE FROM users WHERE username = ?", (name,))
        db.x("DELETE FROM sessions WHERE username = ?", (name,))
        P.log("info", "console", f"compte {name} supprimé par {me}")
        flash(request, f"Compte {name} supprimé, ses sessions sont fermées.")
    return go("/settings#comptes")


# ---------------------------------------------------------------- prompt de déploiement

@app.get("/prompt")
async def prompt_page(request: Request):
    s = db.settings()
    a = db.app(request.query_params.get("app") or "")
    dft = D.default()
    hangar = {"platform": {"base": dft["name"], "hub": dft["hub"], "mode": dft["mode"],
                           "domains": [{"name": d["name"], "hub": d["hub"], "mode": d["mode"]} for d in D.all_domains()]}}
    if a:
        m = re.match(r"^ghcr\.io/([^/]+)/", a["image"]) if a["source"] == "image" else None
        r0 = (D.routes(a["slug"]) or [{"kind": "path", "domain": dft["name"], "sub": ""}])[0]
        dom = D.get(r0["domain"]) or dft
        hangar["platform"].update(base=dom["name"], hub=dom["hub"], mode=dom["mode"])
        hangar["app"] = {"name": a["name"], "slug": a["slug"], "pkg": a["pkg"],
                         "expose": "path" if r0["kind"] == "path" else "sub",
                         "sub": r0["sub"], "port": a["port"], "mem": a["mem_mb"], "db": bool(a["db"]),
                         "gh": m.group(1) if m else None, "url": D.primary_url(a["slug"])}
    return render(request, "prompt.html", title="Prompt de déploiement", nav="prompt", app=a,
                  apps=db.apps(), hangar=hangar)


# ---------------------------------------------------------------- journal

@app.get("/journal")
async def journal(request: Request):
    app_filter = request.query_params.get("app") or ""
    if app_filter:
        events = db.q("SELECT * FROM events WHERE app = ? ORDER BY id DESC LIMIT 300", (app_filter,))
    else:
        events = db.q("SELECT * FROM events ORDER BY id DESC LIMIT 300")
    names = [r["app"] for r in db.q("SELECT DISTINCT app FROM events ORDER BY app")]
    return render(request, "journal.html", title="Journal", nav="journal", events=events, names=names, app_filter=app_filter)


# ---------------------------------------------------------------- sauvegardes

def _confirmed(f, slug):
    return (f.get("confirm") or "").strip() == slug


@app.get("/backups")
async def backups_page(request: Request):
    ds = backup.dests()
    cur = request.query_params.get("d") or (ds[0]["id"] if ds else "")
    if not backup.dest(cur):
        cur = ds[0]["id"] if ds else ""
    snaps, snap_err = (await asyncio.to_thread(backup.snapshots, cur)) if cur else ([], None)
    keep = json.loads(db.settings().get("backup_keep") or "{}")
    nxt = P.run(["systemctl", "show", "platform-backup.timer", "-p", "NextElapseUSecRealtime", "--value"], timeout=10)[1]
    m = re.search(r"(\d{4})-(\d{2})-(\d{2}) (\d{2}:\d{2})", nxt)
    nxt = f"{m.group(3)}/{m.group(2)} à {m.group(4)}" if m else nxt
    busy = backup.running()
    arch_busy = backup.archive_running()
    for d in ds:
        d["last"] = backup.last_ok(d["id"])
    return render(request, "backups.html", title="Sauvegardes", nav="backups", drive_conf=backup.drive_configured(),
                  dests=ds, cur=cur, runs=backup.last_runs(12), last_ok=backup.last_ok(), busy=busy or arch_busy,
                  arch_busy=arch_busy, snaps=snaps, snap_err=snap_err, nas=backup.nas_info(),
                  pending=backup.auth_pending(), google_url=backup._auth.get("google_url"),
                  pw=backup.password(), keep=keep, next_run=nxt.strip(), apps=db.apps(), refresh=busy or arch_busy,
                  folder=backup.FOLDER, own_client=backup.client_id(), archives=backup.archives())


@app.post("/backups/password")
async def backup_password(request: Request):
    f = await request.form()
    try:
        backup.set_password(f.get("password") or "")
        flash(request, "Mot de passe enregistré. Connecte maintenant Drive ou le NAS : les sauvegardes existantes seront reprises.")
    except ValueError as e:
        flash(request, str(e), "error")
    return go("/backups")


@app.post("/backups/full-restore")
async def backup_full_restore(request: Request):
    f = await request.form()
    dest_id, snap = f.get("dest") or "", (f.get("snap") or "").strip()
    if not backup.dest(dest_id) or not re.fullmatch(r"[0-9a-f]{8,64}", snap):
        flash(request, "Choisis une sauvegarde.", "error")
    else:
        P.spawn(backup.snapshot_to_archive, dest_id, snap)
        flash(request, "Préparation de la reprise : la sauvegarde est téléchargée puis convertie en archive. "
                       "Elle apparaîtra dans « Archives » (importée) ; ouvre-la pour lancer la restauration.")
    return go("/backups#archives")


@app.post("/backups/nas/connect")
async def nas_connect(request: Request):
    f = await request.form()
    try:
        await asyncio.to_thread(backup.nas_connect, f.get("kind"), (f.get("host") or "").strip(), f.get("port"),
                                (f.get("user") or "").strip(), f.get("password") or "", (f.get("share") or "").strip(),
                                (f.get("path") or "").strip())
        flash(request, "NAS connecté. Les prochaines sauvegardes y seront aussi envoyées.")
    except (ValueError, RuntimeError) as e:
        flash(request, str(e), "error")
    return go("/backups#nas")


@app.post("/backups/nas/disconnect")
async def nas_disconnect(request: Request):
    await asyncio.to_thread(backup.nas_disconnect)
    flash(request, "NAS déconnecté. Les sauvegardes déjà envoyées restent sur le NAS.")
    return go("/backups")


@app.post("/backups/archive/create")
async def archive_create(request: Request):
    if backup.running() or backup.archive_running():
        flash(request, "Une sauvegarde ou une archive est déjà en cours.", "error")
    else:
        try:
            await asyncio.to_thread(backup.start_archive)
            flash(request, "Création de l'archive lancée. Elle apparaîtra dans la liste une fois prête.")
        except RuntimeError as e:
            flash(request, str(e), "error")
    return go("/backups#archives")


@app.get("/backups/archive/{name}/download")
async def archive_download(request: Request, name: str):
    path = backup.archive_path(name)
    if not path:
        return go("/backups#archives")
    P.log("info", "sauvegarde", f"archive {name} téléchargée")
    return FileResponse(path, media_type="application/gzip", filename=name)


@app.post("/backups/archive/{name}/delete")
async def archive_delete(request: Request, name: str):
    path = backup.archive_path(name)
    if path:
        os.remove(path)
        P.log("info", "sauvegarde", f"archive {name} supprimée")
        flash(request, f"Archive {name} supprimée.")
    return go("/backups#archives")


ARCHIVE_MAX = 20 * 1024 ** 3


@app.post("/backups/archive/upload")
async def archive_upload(request: Request):
    f = await request.form()
    up = f.get("file")
    if not up or not getattr(up, "filename", ""):
        flash(request, "Choisis une archive .tar.gz créée par Hangar.", "error")
        return go("/backups#archives")
    os.makedirs(backup.ARCHIVES, mode=0o700, exist_ok=True)
    name = backup.save_upload_name()
    part = f"{backup.ARCHIVES}/.{name}.part"
    size = 0
    with open(part, "wb") as out:
        os.chmod(part, 0o600)
        while chunk := await up.read(4 * 1024 * 1024):
            size += len(chunk)
            if size > ARCHIVE_MAX:
                break
            out.write(chunk)
    if size > ARCHIVE_MAX:
        os.remove(part)
        flash(request, "Archive trop grosse (20 Go maximum).", "error")
        return go("/backups#archives")
    try:
        await asyncio.to_thread(backup.read_manifest, part)
    except ValueError as e:
        os.remove(part)
        flash(request, f"{up.filename} : {e}", "error")
        return go("/backups#archives")
    os.replace(part, f"{backup.ARCHIVES}/{name}")
    P.log("info", "sauvegarde", f"archive {up.filename} importée ({backup.human(size)}) sous le nom {name}")
    return go(f"/backups/archive/{name}")


@app.get("/backups/archive/{name}")
async def archive_page(request: Request, name: str):
    path = backup.archive_path(name)
    if not path:
        return go("/backups#archives")
    try:
        man = await asyncio.to_thread(backup.read_manifest, path)
    except ValueError as e:
        flash(request, str(e), "error")
        return go("/backups#archives")
    return render(request, "archive.html", title="Restaurer une archive", nav="backups", aname=name, man=man, s_domains=[d["name"] for d in D.all_domains()],
                  size=os.path.getsize(path))


@app.post("/backups/archive/{name}/restore")
async def archive_restore(request: Request, name: str):
    path = backup.archive_path(name)
    if not path:
        return go("/backups#archives")
    f = await request.form()
    if (f.get("confirm") or "").strip().lower() != "restaurer":
        flash(request, "Tape « restaurer » pour confirmer.", "error")
        return go(f"/backups/archive/{name}")
    man = await asyncio.to_thread(backup.read_manifest, path)
    choices = {}
    for a in man["apps"]:
        slug = a["slug"]
        if f.get(f"app_{slug}") != "on":
            continue
        cur = db.app(slug)
        if cur and cur["state"] == "deploying":
            flash(request, f"{slug} : une opération est en cours, réessaie plus tard.", "error")
            return go(f"/backups/archive/{name}")
        parts = [p for p in ("data", "db") if f.get(f"{p}_{slug}") == "on" and a.get(f"has_{p}")]
        if cur and not parts:
            continue
        choices[slug] = parts
    with_settings = f.get("settings") == "on" and man.get("settings")
    if not choices and not with_settings:
        flash(request, "Coche au moins une appli et ce qu'il faut restaurer.", "error")
        return go(f"/backups/archive/{name}")
    if with_settings:
        try:
            await asyncio.to_thread(backup.apply_settings, man["settings"])
        except RuntimeError as e:
            flash(request, f"Réglages non repris : {e}", "error")
            return go(f"/backups/archive/{name}")
    if not choices:
        flash(request, "Domaines repris de l'archive.")
        return go("/domains")
    for slug in choices:
        if db.app(slug):
            db.update_app(slug, state="deploying")
    backup.start_archive_restore(name, choices)
    flash(request, f"Restauration lancée pour {', '.join(choices)}. Suis l'avancement dans la liste des applis.")
    return go("/")


@app.post("/backups/drive/start")
async def drive_start(request: Request):
    f = await request.form()
    cid, csec = (f.get("client_id") or "").strip(), (f.get("client_secret") or "").strip()
    if cid and not re.fullmatch(r"[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com", cid):
        flash(request, "Client ID invalide : il se termine par .apps.googleusercontent.com", "error")
        return go("/backups#drive")
    if cid and not re.fullmatch(r"[A-Za-z0-9_-]{10,100}", csec):
        flash(request, "Indique aussi le code secret du client (Client secret).", "error")
        return go("/backups#drive")
    try:
        url = await asyncio.to_thread(backup.auth_start, cid, csec)
        backup._auth["google_url"] = url
    except RuntimeError as e:
        flash(request, str(e), "error")
    return go("/backups#drive")


@app.post("/backups/drive/finish")
async def drive_finish(request: Request):
    f = await request.form()
    try:
        await asyncio.to_thread(backup.auth_finish, f.get("url") or "")
        flash(request, "Google Drive connecté. Note le mot de passe des sauvegardes ci-dessous, puis lance une première sauvegarde.")
    except (ValueError, RuntimeError) as e:
        flash(request, str(e), "error")
    return go("/backups#drive")


@app.post("/backups/drive/cancel")
async def drive_cancel(request: Request):
    backup.auth_cancel()
    return go("/backups")


@app.post("/backups/drive/disconnect")
async def drive_disconnect(request: Request):
    await asyncio.to_thread(backup.disconnect)
    flash(request, "Google Drive déconnecté. Les sauvegardes déjà envoyées restent dans ton Drive.")
    return go("/backups")


@app.post("/backups/run")
async def backup_run(request: Request):
    if backup.running():
        flash(request, "Une sauvegarde est déjà en cours.", "error")
    else:
        try:
            await asyncio.to_thread(backup.start_now)
            flash(request, "Sauvegarde lancée. Cette page se met à jour toute seule.")
        except RuntimeError as e:
            flash(request, str(e), "error")
    return go("/backups")


@app.post("/backups/keep")
async def backup_keep(request: Request):
    f = await request.form()
    try:
        keep = {k: int(f.get(k)) for k in ("daily", "weekly", "monthly")}
        if not all(0 <= v <= 365 for v in keep.values()) or not any(keep.values()):
            raise ValueError
    except (TypeError, ValueError):
        flash(request, "Indique des nombres entre 0 et 365, dont au moins un non nul.", "error")
        return go("/backups")
    db.set_setting("backup_keep", keep)
    flash(request, "Rétention enregistrée. Elle s'applique à la prochaine sauvegarde.")
    return go("/backups")


@app.post("/backups/restore")
async def backup_restore(request: Request):
    f = await request.form()
    slug, snap, dest_id = f.get("slug") or "", (f.get("snap") or "").strip(), f.get("dest") or ""
    parts = [p for p in ("data", "db") if f.get(p) == "on"]
    a = db.app(slug)
    if not backup.dest(dest_id):
        flash(request, "Destination inconnue.", "error")
    elif not a or not re.fullmatch(r"[0-9a-f]{8,64}", snap):
        flash(request, "Choisis une appli et une sauvegarde.", "error")
    elif not parts:
        flash(request, "Coche au moins « fichiers » ou « base ».", "error")
    elif "db" in parts and not a["db"]:
        flash(request, f"{a['name']} n'a pas de base.", "error")
    elif not _confirmed(f, slug):
        flash(request, f"Tape {slug} pour confirmer la restauration.", "error")
    elif a["state"] == "deploying":
        flash(request, "Une opération est déjà en cours sur cette appli.", "error")
    else:
        db.update_app(slug, state="deploying")
        P.spawn(backup.restore_app, slug, dest_id, snap, parts)
        flash(request, f"Restauration de {a['name']} en cours. L'état actuel est mis de côté avant d'être remplacé.")
        return go(f"/apps/{slug}")
    return go("/backups#restaurer")


# ---------------------------------------------------------------- système, mises à jour, alertes

@app.get("/system")
async def system_page(request: Request):
    chk = db.kv_get("sys_check")
    busy = system.running()
    info = await asyncio.to_thread(P.system_info)
    events = db.q("SELECT * FROM events WHERE app IN ('système', 'alertes') ORDER BY id DESC LIMIT 12")
    return render(request, "system.html", title="Système", nav="system", chk=chk, chk_ts=db.kv_ts("sys_check"),
                  busy=busy, comps=system.COMPONENTS, info=info, events=events, refresh=bool(busy))


@app.post("/system/check")
async def system_check(request: Request):
    try:
        await asyncio.to_thread(system.check)
        flash(request, "Vérification terminée.")
    except Exception as e:
        flash(request, f"Vérification impossible : {e}", "error")
    return go("/system")


@app.post("/system/update/{cid}")
async def system_update(request: Request, cid: str):
    try:
        await asyncio.to_thread(system.launch, cid)
        msg = f"Mise à jour de {system.COMPONENTS[cid]['name']} lancée."
        if cid == "docker":
            msg += " La console va redémarrer : recharge la page dans une minute."
        flash(request, msg)
    except (ValueError, RuntimeError) as e:
        flash(request, str(e), "error")
    return go("/system")


@app.post("/system/alerts")
async def alerts_save(request: Request):
    f = await request.form()
    server = (f.get("ntfy_server") or "").strip().rstrip("/")
    topic = (f.get("ntfy_topic") or "").strip()
    token = (f.get("ntfy_token") or "").strip()
    if not re.fullmatch(r"https://[A-Za-z0-9.-]+(:\d+)?(/[A-Za-z0-9._~/-]*)?", server):
        flash(request, "Serveur ntfy invalide (https://…).", "error")
    elif not re.fullmatch(r"[A-Za-z0-9_-]{6,64}", topic):
        flash(request, "Sujet invalide : 6 à 64 lettres, chiffres, - ou _.", "error")
    else:
        db.set_setting("ntfy_server", server)
        db.set_setting("ntfy_topic", topic)
        if token != P.MASK:
            db.set_setting("ntfy_token", token)
        db.set_setting("alerts_on", "1" if f.get("alerts_on") == "on" else "0")
        flash(request, "Alertes enregistrées.")
    return go("/system#alertes")


@app.post("/system/alerts/test")
async def alerts_test(request: Request):
    ok, err = await asyncio.to_thread(alerts.send, "Test Hangar", "Si tu lis ceci, les alertes arrivent bien sur ton téléphone.",
                                      3, ["bell"], None, 0, True)
    flash(request, "Notification de test envoyée." if ok else f"Envoi impossible : {err}", "ok" if ok else "error")
    return go("/system#alertes")


# ---------------------------------------------------------------- versions, base, statistiques d'une appli

@app.post("/apps/{slug}/versions/check")
async def versions_check(request: Request, slug: str):
    get_app_or_404(slug)
    await asyncio.to_thread(monitor.check_versions, slug)
    a = db.app(slug)
    if a["latest_error"]:
        flash(request, f"Vérification impossible : {a['latest_error']}", "error")
    elif a["latest_version"]:
        flash(request, f"Version {a['latest_version']} disponible.")
    else:
        flash(request, f"{a['version']} est la version la plus récente.")
    return go(f"/apps/{slug}")


@app.post("/apps/{slug}/node/move")
async def app_move(request: Request, slug: str):
    a = get_app_or_404(slug)
    target = (await request.form()).get("target") or ""
    if a["state"] == "deploying":
        flash(request, "Une opération est en cours sur cette appli.", "error")
    elif target == a["node"] or target not in {c["id"] for c in node_choices()}:
        flash(request, "Choisis un autre nœud, en ligne.", "error")
    else:
        db.update_app(slug, state="deploying")
        P.spawn(move.move, slug, target)
        flash(request, f"Déplacement vers {target} lancé. L'appli reste en ligne pendant la copie, puis est coupée "
                       "quelques secondes ; si la cible ne répond pas, elle redémarre sur son nœud actuel.")
    return go(f"/apps/{slug}")


@app.get("/apps/{slug}/db/export")
async def db_export(request: Request, slug: str):
    a = get_app_or_404(slug)
    if not a["db"]:
        return go(f"/apps/{slug}")
    name = f"{slug}-{time.strftime('%Y%m%d-%H%M')}.sql.gz"
    return StreamingResponse(dbadmin.export_stream(slug), media_type="application/gzip",
                             headers={"Content-Disposition": f'attachment; filename="{name}"'})


IMPORT_DIR = "/srv/backups/import-tmp"
IMPORT_MAX = 2 * 1024 ** 3


@app.post("/apps/{slug}/db/import")
async def db_import(request: Request, slug: str):
    a = get_app_or_404(slug)
    f = await request.form()
    up = f.get("file")
    if not a["db"] or a["state"] == "deploying":
        flash(request, "Import impossible pour l'instant.", "error")
        return go(f"/apps/{slug}#base")
    if not _confirmed(f, slug):
        flash(request, f"Tape {slug} pour confirmer l'import : il remplace tout le contenu de la base.", "error")
        return go(f"/apps/{slug}#base")
    if not up or not getattr(up, "filename", ""):
        flash(request, "Choisis un fichier .sql, .sql.gz ou .dump.", "error")
        return go(f"/apps/{slug}#base")
    os.makedirs(IMPORT_DIR, mode=0o700, exist_ok=True)
    path = f"{IMPORT_DIR}/{slug}-{secrets.token_hex(4)}"
    size, head = 0, b""
    with open(path, "wb") as out:
        while chunk := await up.read(1024 * 1024):
            if not head:
                head = chunk[:8]
            size += len(chunk)
            if size > IMPORT_MAX:
                out.close()
                os.remove(path)
                flash(request, "Fichier trop gros (2 Go maximum).", "error")
                return go(f"/apps/{slug}#base")
            out.write(chunk)
    kind = "dump" if head.startswith(b"PGDMP") else "sqlgz" if head.startswith(b"\x1f\x8b") else "sql"
    if kind == "sql" and b"\x00" in head:
        os.remove(path)
        flash(request, "Format non reconnu : attendu un export SQL (.sql, .sql.gz) ou pg_dump -Fc (.dump).", "error")
        return go(f"/apps/{slug}#base")
    db.update_app(slug, state="deploying")
    P.spawn(dbadmin.import_file, slug, path, kind)
    flash(request, f"Import de {up.filename} en cours. Une copie de la base actuelle est faite avant.")
    return go(f"/apps/{slug}")


@app.post("/apps/{slug}/db/reset")
async def db_reset(request: Request, slug: str):
    a = get_app_or_404(slug)
    f = await request.form()
    if not a["db"] or a["state"] == "deploying":
        flash(request, "Remise à zéro impossible pour l'instant.", "error")
    elif not _confirmed(f, slug):
        flash(request, f"Tape {slug} pour confirmer la remise à zéro.", "error")
    else:
        db.update_app(slug, state="deploying")
        P.spawn(dbadmin.reset, slug)
        flash(request, "Remise à zéro en cours. Une copie de la base actuelle est faite avant.")
        return go(f"/apps/{slug}")
    return go(f"/apps/{slug}#base")


# ---------------------------------------------------------------- supervision

def _services():
    def active(u):
        return P.run(["systemctl", "is-active", u], timeout=10)[1].strip()
    s = db.settings()
    out = []
    caddy = active("caddy")
    out.append({"name": "Serveur web (Caddy)", "ok": caddy == "active", "state": "en ligne" if caddy == "active" else caddy})
    if P.tunnel_ready():
        t = P.tunnel_status()
        out.append({"name": "Tunnel Cloudflare", "ok": t["active"], "state": "connecté" if t["active"] else t["state"]})
    dk = active("docker")
    out.append({"name": "Docker", "ok": dk == "active", "state": "en ligne" if dk == "active" else dk})
    pg = P.run(["docker", "inspect", "-f", "{{.State.Health.Status}}", P.PG], timeout=10)[1].strip()
    out.append({"name": "PostgreSQL", "ok": pg == "healthy", "state": {"healthy": "en ligne"}.get(pg, pg or "absent")})
    fw = P.run(["nft", "list", "table", "inet", "platform"], timeout=10)[0] == 0
    out.append({"name": "Pare-feu", "ok": fw, "state": "actif" if fw else "règles absentes"})
    last = backup.last_ok()
    if backup.configured():
        fresh = bool(last and time.time() - last["ts"] < 36 * 3600)
        out.append({"name": "Sauvegardes", "ok": fresh, "state": ("dernière " + _ago(last["ts"])) if last else "aucune réussie"})
    else:
        out.append({"name": "Sauvegardes", "ok": None, "state": "Drive non connecté"})
    out.append({"name": "Alertes", "ok": True if s.get("alerts_on") == "1" else None,
                "state": "actives" if s.get("alerts_on") == "1" else "désactivées"})
    return out


def _containers():
    def one(node):
        rc, out = P.dk(node, "ps", "-a", "--filter", "label=fr.hangar.app", "--format", "{{.ID}}", timeout=20)
        ids = out.split() if rc == 0 else []
        if not ids:
            return ""
        return P.dk(node, "inspect", "-f", '{{index .Config.Labels "fr.hangar.app"}}\t{{.RestartCount}}\t'
                    '{{.State.StartedAt}}\t{{.State.OOMKilled}}', *ids, timeout=20)[1]
    res = {}
    for out in P._on_nodes(one).values():
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) == 4:
                try:
                    ts = calendar.timegm(time.strptime(parts[2][:19], "%Y-%m-%dT%H:%M:%S"))   # Docker donne l'heure UTC
                except ValueError:
                    ts = None
                res[parts[0]] = {"restarts": int(parts[1] or 0), "started": ts, "oom": parts[3] == "true"}
    return res


def _postgres():
    q = ("SELECT datname, pg_database_size(datname) FROM pg_database WHERE datname NOT IN ('template0','template1') "
         "ORDER BY 2 DESC;")
    rc, out = P._psql(q)
    dbs = [{"name": l.split("|")[0], "size": int(l.split("|")[1])} for l in out.splitlines() if "|" in l] if rc == 0 else []
    rc, conn = P._psql("SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'client backend';")
    rc2, mx = P._psql("SHOW max_connections;")
    return {"dbs": dbs, "total": sum(d["size"] for d in dbs), "conn": conn.strip() if rc == 0 else "?",
            "max": mx.strip() if rc2 == 0 else "?"}


@app.get("/monitoring")
async def monitoring(request: Request):
    rng = request.query_params.get("r") if request.query_params.get("r") in stats.RANGES else "24h"
    host = stats.host_now()
    hs = stats.host_charts(stats.host_series(rng), host["mem_total"])
    rows = await asyncio.to_thread(P.apps_with_status)
    req, spark, res24 = stats.apps_overview()
    cont = await asyncio.to_thread(_containers)
    svc = await asyncio.to_thread(_services)
    pg = await asyncio.to_thread(_postgres)
    for a in rows:
        a["h"] = monitor.health.get(a["slug"])
        a["r"] = req.get(a["slug"])
        a["c"] = cont.get(a["slug"], {})
        a["cpu24"] = (res24.get(a["slug"]) or {}).get("cpu")
        a["spark"] = stats.spark_path(spark.get(a["slug"], [0] * 24))
        a["spark_max"] = max(spark.get(a["slug"], [0]))
    incidents = db.q("SELECT * FROM events WHERE level IN ('error', 'warn') AND ts > ? ORDER BY id DESC LIMIT 15",
                     (time.time() - 86400,))
    return render(request, "monitoring.html", title="Supervision", nav="monitoring", host=host, hs=hs, rng=rng,
                  ranges=list(stats.RANGES), rows=rows, svc=svc, pg=pg, incidents=incidents, auto_refresh=60,
                  now=time.time())


# ---------------------------------------------------------------- nœuds

@app.get("/nodes")
async def nodes_page(request: Request):
    rows = nodes.all_nodes()
    if not nodes.get(nodes.LOCAL):
        rows.insert(0, {"id": nodes.LOCAL, "name": "Ce serveur (console)", "address": db.settings()["admin_bind"].rsplit(":", 1)[0],
                        "wg_ip": "—", "state": "ok", "info": {}, "created_at": 0})
    hs = await asyncio.to_thread(nodes.handshakes)
    loc = await asyncio.to_thread(nodes.local_info)
    apps_by = {}
    for a in db.apps():
        apps_by.setdefault(a["node"], []).append(a)
    for n in rows:
        if n["id"] == nodes.LOCAL:
            n["info"] = loc
        n["hs"] = hs.get(n.get("wg_pubkey") or "")
        n["apps"] = apps_by.get(n["id"], [])
        n["reserved"] = sum(a["mem_mb"] for a in n["apps"] if a["desired"] == "running")
    key = await asyncio.to_thread(nodes.ensure_key)
    busy = any(n["state"] == "installing" for n in rows)
    hrows = []
    for h in ha.all_ha():
        ap = db.app(h["slug"])
        if ap:
            hrows.append({"a": ap, "h": h})
    return render(request, "nodes.html", title="Nœuds", nav="nodes", rows=rows, key=key, now=time.time(),
                  has=ha.settings(), hrows=hrows, crole=nodes.console_role(), on_console=apps_by.get(nodes.LOCAL, []),
                  fence_auto=len([n for n in nodes.all_nodes() if n["id"] != nodes.LOCAL]) >= 2,
                  refresh=busy, auto_refresh=None if busy else 60)


@app.post("/nodes/add")
async def nodes_add(request: Request):
    f = await request.form()
    try:
        await asyncio.to_thread(nodes.add, f.get("id"), f.get("name"), f.get("address"), f.get("ssh_port"),
                                f.get("ssh_user"), f.get("sudo_password") or "")
        flash(request, "Installation du nœud lancée : quelques minutes. Cette page se met à jour toute seule.")
    except (ValueError, RuntimeError) as e:
        flash(request, str(e), "error")
    return go("/nodes")


@app.post("/nodes/{node_id}/retry")
async def nodes_retry(request: Request, node_id: str):
    f = await request.form()
    n = nodes.get(node_id)
    if n and node_id != nodes.LOCAL and n["state"] != "installing":
        P.spawn(nodes.install, node_id, f.get("sudo_password") or "")
        flash(request, f"Réinstallation de {n['name']} lancée. Rien n'est effacé : le script reprend là où il en était.")
    return go("/nodes")


@app.post("/nodes/{node_id}/remove")
async def nodes_remove(request: Request, node_id: str):
    f = await request.form()
    if (f.get("confirm") or "").strip() != node_id:
        flash(request, f"Tape {node_id} pour confirmer.", "error")
        return go(f"/nodes/{node_id}")
    try:
        await asyncio.to_thread(nodes.remove, node_id)
        flash(request, f"Nœud {node_id} retiré du réseau privé.")
    except ValueError as e:
        flash(request, str(e), "error")
        return go(f"/nodes/{node_id}")
    return go("/nodes")


# ---------------------------------------------------------------- sécurité des nœuds

def _sec_values(p, f=None):
    """Valeurs du formulaire de sécurité : la politique, ou ce qui a été tapé (en cas d'erreur)."""
    v = security.to_form(p)
    if f is not None:
        for k in ("ssh_sources", "admin_keys", "extra", "ssh_port", "reboot"):
            v[k] = f.get(k) or ""
    return v


def _sec_row(n):
    st = security.state(n)
    obs = st.get("obs") or {}
    cs = security.checks(n)
    lv, count = security.level(cs)
    return {"n": n, "st": st, "own": bool(n.get("security")), "applying": security.applying(n),
            "checks": cs, "level": lv, "count": count, "banned": obs.get("banned") or [],
            "web": security.web_needed(n["id"]), "pending": security.pending(n),
            "summary": security.summary(security.node_policy(n)[0])}


JOURNAL_CATS = [("all", "Tout"), ("sec", "Sécurité"), ("install", "Installation"), ("route", "Tunnel et routage"),
                ("other", "Autres")]


def _event_cat(msg):
    m = msg.lower()
    if m.startswith("sécurité") or "bannie" in m or "redémarrage" in m:
        return "sec"
    if any(w in m for w in ("installation", "réparation", "préparation", "nœud prêt", "réseau privé", "wireguard")):
        return "install"
    if any(w in m for w in ("tunnel", "caddy", "trafic", "route")):
        return "route"
    return "other"


@app.get("/security")
async def security_page(request: Request):
    return await _security_render(request)


async def _security_render(request, f=None, err=None):
    rows = [await asyncio.to_thread(_sec_row, n) for n in nodes.all_nodes() if n["id"] != nodes.LOCAL]
    busy = any(r["applying"] for r in rows)
    return render(request, "security.html", title="Sécurité", nav="security", rows=rows,
                  f=f or _sec_values(security.policy()), err=err, lan=", ".join(access.current()["nets"]),
                  gsum=security.summary(security.policy()), cssh=await asyncio.to_thread(security.console_ssh),
                  refresh=busy, status_code=400 if err else 200)


@app.post("/security/console-ssh")
async def console_ssh(request: Request):
    f = await request.form()
    err = await asyncio.to_thread(security.console_ssh_apply, f.get("keys_only") == "on", f.get("f2b") == "on",
                                  f.get("keys"), request.session.get("user"))
    flash(request, err or "SSH de la console réglé.", "error" if err else "ok")
    return go("/security#console")


@app.post("/security")
async def security_save(request: Request):
    f = await request.form()
    p, err = security.parse_form(f)
    if err:
        flash(request, "Rien n'est appliqué : corrige les champs en rouge.", "error")
        return await _security_render(request, f=_sec_values(p, f), err=err)
    security.save_global(p, request.session.get("user"))
    targets = [n["id"] for n in nodes.all_nodes() if n["id"] != nodes.LOCAL and not n.get("security")
               and n["state"] == "ok"]
    for nid in targets:
        P.spawn(security.apply, nid, request.session.get("user"))
    flash(request, "Politique enregistrée" + (f" : application sur {len(targets)} nœud(s), une à la fois." if targets
                                               else ". Elle s'appliquera à chaque nœud installé."))
    return go("/security")


@app.post("/security/{node_id}/apply")
async def security_apply(request: Request, node_id: str):
    n = nodes.get(node_id)
    if n and node_id != nodes.LOCAL:
        P.spawn(security.apply, node_id, request.session.get("user"))
        flash(request, f"Application sur {n['name']} lancée.")
    return go("/security")


@app.post("/security/{node_id}/collect")
async def security_collect(request: Request, node_id: str):
    n = nodes.get(node_id)
    if n and node_id != nodes.LOCAL:
        obs = await asyncio.to_thread(security.collect, node_id)
        flash(request, "État relevé." if obs else "Nœud injoignable : état non relevé.", "ok" if obs else "error")
    back = request.headers.get("referer") or "/security"
    return go("/security" if back.split("#")[0].rstrip("/").endswith("/security") else f"/nodes/{node_id}#securite")


@app.get("/security/myip")
async def security_myip(request: Request):
    return JSONResponse({"ip": await asyncio.to_thread(security.public_ip)})


@app.post("/nodes/{node_id}/security")
async def node_security(request: Request, node_id: str):
    n = nodes.get(node_id)
    if not n or node_id == nodes.LOCAL:
        return go("/nodes")
    f = await request.form()
    user = request.session.get("user")
    if f.get("which") == "own":
        p, err = security.parse_form(f)
        if err:
            flash(request, "Rien n'est appliqué : corrige les champs en rouge.", "error")
            return await _node_render(request, node_id, sec_f=_sec_values(p, f), sec_err=err)
        security.save_node(node_id, p, user)
    else:
        security.save_node(node_id, None, user)
    if n["state"] == "ok":
        P.spawn(security.apply, node_id, user)
        flash(request, "Réglage enregistré, application en cours.")
    else:
        flash(request, "Réglage enregistré : il s'appliquera quand le nœud répondra.")
    return go(f"/nodes/{node_id}#securite")


@app.post("/nodes/{node_id}/reboot")
async def node_reboot(request: Request, node_id: str):
    try:
        lxc = await asyncio.to_thread(security.reboot, node_id, request.session.get("user"))
        flash(request, "Redémarrage lancé : le nœud et ses applis reviennent en une à deux minutes." + (
            " C'est un conteneur LXC : selon sa configuration, Proxmox peut le laisser arrêté. "
            "S'il ne revient pas, démarre-le depuis Proxmox." if lxc else ""))
    except (ValueError, RuntimeError) as e:
        flash(request, f"Redémarrage impossible : {e}", "error")
    return go(f"/nodes/{node_id}#securite")


@app.post("/nodes/{node_id}/unban")
async def node_unban(request: Request, node_id: str):
    f = await request.form()
    try:
        await asyncio.to_thread(security.unban, node_id, (f.get("ip") or "").strip())
        flash(request, f"{f.get('ip')} débannie.")
    except (ValueError, RuntimeError) as e:
        flash(request, f"Débannissement impossible : {e}", "error")
    return go(f.get("back") if f.get("back") == "/security" else f"/nodes/{node_id}#securite")


@app.get("/nodes/{node_id}")
async def node_page(request: Request, node_id: str):
    return await _node_render(request, node_id)


async def _node_render(request, node_id, sec_f=None, sec_err=None):
    n = nodes.get(node_id)
    if not n:
        return go("/nodes")
    rng = request.query_params.get("r") if request.query_params.get("r") in stats.RANGES else "24h"
    if node_id == nodes.LOCAL:
        n["info"] = await asyncio.to_thread(nodes.local_info)
    se = nodes.series(node_id, rng)
    mem_total = (n["info"] or {}).get("mem_total") or 0
    se["charts"] = [
        {"title": "Processeur", "sub": "moyenne (% des cœurs)", "unit": "%", "kind": "line", "values": se["cpu"],
         "limit": 100, "limitLabel": "100 %", "extra": [{"label": "charge", "values": se["load1"], "unit": ""}]},
        {"title": "Mémoire utilisée", "sub": "max sur l'intervalle (Mo)", "unit": "Mo", "kind": "line", "values": se["mem"],
         "limit": round(mem_total) or None, "limitLabel": f"total {mem_total:.0f} Mo"},
    ]
    events = db.q("SELECT * FROM events WHERE app = ? ORDER BY id DESC LIMIT 150", (f"nœud {node_id}",))
    for e in events:
        e["cat"] = _event_cat(e["msg"])
    hs = (await asyncio.to_thread(nodes.handshakes)).get(n.get("wg_pubkey") or "")
    sec = None
    if node_id != nodes.LOCAL:
        sec = await asyncio.to_thread(_sec_row, n)
        sec["f"] = sec_f or _sec_values(security.own_raw(n) or security.policy())
        sec["err"] = sec_err
        if sec_err:
            sec["own"] = True
    return render(request, "node.html", title=n["name"], nav="nodes", n=n, se=se, rng=rng, ranges=list(stats.RANGES),
                  events=events, hs=hs, now=time.time(), apps=[a for a in db.apps() if a["node"] == node_id],
                  sec=sec, cats=JOURNAL_CATS, refresh=n["state"] == "installing" or bool(sec and sec["applying"]),
                  status_code=400 if sec_err else 200)
