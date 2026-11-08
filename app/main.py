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
from fastapi.responses import PlainTextResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import alerts, backup, db, dbadmin, monitor, stats, system
from . import platform as P

HERE = os.path.dirname(__file__)
LAN = ipaddress.ip_network(os.environ.get("LAN_CIDR", "192.168.91.0/24"), strict=False)
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
        allowed = addr in LAN or addr.is_loopback
    except ValueError:
        allowed = False
    if not allowed:
        return PlainTextResponse("Console réservée au réseau local.", status_code=403)
    if not request.url.path.startswith(("/login", "/static")) and not request.session.get("user"):
        return RedirectResponse("/login", status_code=303)
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


app.add_middleware(SessionMiddleware, secret_key=_secret(), session_cookie="hangar",
                   max_age=8 * 3600, same_site="strict", https_only=True)


# ---------------------------------------------------------------- aides

def go(url):
    return RedirectResponse(url, status_code=303)


def flash(request, msg, kind="ok"):
    request.session["flash"] = {"msg": msg, "kind": kind}


def render(request, name, status_code=200, **ctx):
    ctx.setdefault("title", "Hangar")
    ctx.update(flash=request.session.pop("flash", None), s=db.settings(),
               user=request.session.get("user"), app_count=len(db.apps()))
    return tpl.TemplateResponse(request, name, ctx, status_code=status_code)


def get_app_or_404(slug):
    a = db.app(slug)
    if not a:
        from fastapi import HTTPException
        raise HTTPException(404, "Application inconnue")
    return a


SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
PKG = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$")
IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]*(:[0-9]+/[a-z0-9._/-]+)?$")
GIT = re.compile(r"^(https://[^\s#@]+|git@[^\s#]+:[^\s#]+)$")
VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
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
    d["expose"] = f.get("expose") if f.get("expose") in ("path", "sub", "both") else "path"

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

    d["sub"] = (f.get("sub") or "").strip().lower()
    if d["expose"] in ("sub", "both"):
        if not SLUG.match(d["sub"]):
            e["sub"] = "Lettres minuscules, chiffres et tirets."
        elif d["sub"] == s["hub"] or d["sub"] in ("www",):
            e["sub"] = f"{d['sub']}.{s['base_domain']} est réservé."
        elif db.one("SELECT 1 FROM apps WHERE sub = ? AND expose != 'path' AND slug != ?", (d["sub"], d["slug"])):
            e["sub"] = "Ce sous-domaine est déjà pris par une autre appli."
    else:
        d["sub"] = ""

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
    if not re.match(r"^/[A-Za-z0-9._~/?=&%-]*$", d["health_path"]):
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
    return d, e


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


@app.post("/login")
async def login(request: Request):
    f = await request.form()
    user = db.one("SELECT * FROM users WHERE username = ?", ((f.get("username") or "").strip(),))
    try:
        ok = bool(user) and ph.verify(user["hash"], f.get("password") or "")
    except (VerifyMismatchError, InvalidHashError):
        ok = False
    if not ok:
        await asyncio.sleep(1.5)
        flash(request, "Identifiant ou mot de passe incorrect.", "error")
        return go("/login")
    request.session.clear()
    request.session["user"] = user["username"]
    P.log("info", "console", f"connexion de {user['username']} depuis {request.client.host}")
    return go("/")


@app.post("/logout")
async def logout(request: Request):
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
    blank = {"name": "", "pkg": "fr.piperault.", "expose": "sub", "slug": "", "sub": "", "port": 8080,
             "health_path": "/", "mem_mb": 256, "source": "image", "image": "", "version": "", "env": "", "db": 0,
             "data_user": ""}
    return render(request, "app_form.html", title="Nouvelle application", nav="apps", a=blank, new=True, errors={},
                  registries=P.registry_logins())


@app.post("/apps/new")
async def create_app(request: Request):
    f = await request.form()
    d, errors = validate(f)
    if not errors:
        _, errors = await apply_registry(f, d)
    if errors:
        return render(request, "app_form.html", 400, title="Nouvelle application", nav="apps", a=d, new=True,
                      errors=errors, registries=P.registry_logins(), reg_user=f.get("reg_user") or "")
    slug = d.pop("slug")
    d.update(host_port=P.next_host_port(), state="deploying", desired="running", created_at=time.time(),
             db_password=secrets.token_hex(16) if d["db"] else None)
    db.insert_app(slug, d)
    P.log("info", slug, f"appli créée, port local {d['host_port']}")
    P.spawn(P.deploy, slug, d["version"], "create")
    flash(request, f"{d['name']} créée. Déploiement de {d['version']} en cours.")
    return go(f"/apps/{slug}")


@app.get("/apps/{slug}")
async def show_app(request: Request, slug: str):
    get_app_or_404(slug)
    rows = await asyncio.to_thread(P.apps_with_status)
    a = next(r for r in rows if r["slug"] == slug)
    events = db.q("SELECT * FROM events WHERE app = ? ORDER BY id DESC LIMIT 8", (slug,))
    names = await asyncio.to_thread(P.app_public_names, a, db.settings())
    rng = request.query_params.get("r") if request.query_params.get("r") in stats.RANGES else "24h"
    st = stats.app_charts(stats.series(slug, rng), a["mem_mb"])
    dbi = await asyncio.to_thread(dbadmin.info, slug) if a["db"] and a["status"] != "deploying" else None
    return render(request, "app_form.html", title=a["name"], nav="apps", a=a, new=False, errors={},
                  events=events, names=names, refresh=a["status"] == "deploying", registries=P.registry_logins(),
                  st=st, dbi=dbi, ranges=list(stats.RANGES))


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
        a = {**cur, **d, "status": "error" if cur["state"] == "error" else "running", "urls": P.urls({**cur, **d}, db.settings())}
        return render(request, "app_form.html", 400, title=cur["name"], nav="apps", a=a, new=False, errors=errors,
                      events=[], names=[], registries=P.registry_logins(), reg_user=f.get("reg_user") or "")
    d.pop("slug")
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


# ---------------------------------------------------------------- domaine et accès

@app.get("/settings")
async def settings_page(request: Request):
    tunnel = await asyncio.to_thread(P.tunnel_status)
    names = await asyncio.to_thread(P.public_names, db.settings())
    tid = await asyncio.to_thread(P.tunnel_id)
    return render(request, "settings.html", title="Domaine et accès", nav="settings",
                  names=names, missing=[n for n in names if n["ok"] is False], tunnel=tunnel, tunnel_id=tid,
                  registries=P.registry_logins())


@app.post("/settings/registry/remove")
async def remove_registry(request: Request):
    reg = ((await request.form()).get("registry") or "").strip()
    if reg in P.registry_logins():
        await asyncio.to_thread(P.registry_logout, reg)
        flash(request, f"Identifiants retirés pour {reg}. Les images déjà téléchargées restent utilisables.")
    return go("/settings")


@app.post("/settings/tunnel")
async def save_tunnel_token(request: Request):
    f = await request.form()
    try:
        tid = await asyncio.to_thread(P.set_tunnel_token, f.get("token") or "")
    except (ValueError, RuntimeError) as e:
        flash(request, str(e), "error")
        return go("/settings")
    flash(request, f"Jeton enregistré. cloudflared est connecté au tunnel {tid}.")
    return go("/settings")


@app.post("/settings")
async def save_settings(request: Request):
    f = await request.form()
    old = db.settings()
    base = (f.get("base_domain") or "").strip().lower().rstrip(".")
    hub = (f.get("hub") or "").strip().lower()
    mode = f.get("mode") if f.get("mode") in ("tunnel", "direct") else old["mode"]
    aliases = [x.strip().lower().rstrip(".") for x in re.split(r"[\s,]+", f.get("aliases") or "") if x.strip()]
    if not DOMAIN.match(base):
        flash(request, "Domaine de base invalide, par exemple piperault.fr", "error")
        return go("/settings")
    if not SLUG.match(hub):
        flash(request, "Préfixe invalide, par exemple apps", "error")
        return go("/settings")
    bad = [x for x in aliases if not DOMAIN.match(x)]
    if bad:
        flash(request, f"Alias invalide : {bad[0]}", "error")
        return go("/settings")
    if db.one("SELECT 1 FROM apps WHERE sub = ? AND expose != 'path'", (hub,)):
        flash(request, f"Le préfixe {hub} est déjà le sous-domaine d'une appli.", "error")
        return go("/settings")
    if base != old["base_domain"] and old["base_domain"] not in aliases:
        aliases.append(old["base_domain"])
    aliases = list(dict.fromkeys(a for a in aliases if a != base))
    db.set_setting("base_domain", base)
    db.set_setting("hub", hub)
    db.set_setting("aliases", aliases)
    db.set_setting("mode", mode)
    try:
        await asyncio.to_thread(P.apply_routing)
    except RuntimeError as e:
        for k in ("base_domain", "hub", "aliases", "mode"):
            db.set_setting(k, old[k])
        flash(request, f"{e} Les réglages précédents sont conservés.", "error")
        return go("/settings")
    mode_txt = "mode tunnel Cloudflare" if mode == "tunnel" else "mode direct"
    P.log("ok", "caddy", f"domaine {hub}.{base}, {mode_txt}" + (f", alias {', '.join(aliases)}" if aliases else "") + ", Caddy rechargé")
    msg = f"Caddy rechargé en {mode_txt}. {hub}.{base} est actif" + (", anciens domaines toujours servis." if aliases else ".")
    if mode != old["mode"]:
        msg += (" Caddy n'écoute plus qu'en local : le trafic doit arriver par cloudflared." if mode == "tunnel"
                else " Les ports 80 et 443 doivent maintenant arriver jusqu'à cette machine.")
    flash(request, msg)
    return go("/settings")


# ---------------------------------------------------------------- prompt de déploiement

@app.get("/prompt")
async def prompt_page(request: Request):
    s = db.settings()
    a = db.app(request.query_params.get("app") or "")
    hangar = {"platform": {"base": s["base_domain"], "hub": s["hub"], "mode": s["mode"]}}
    if a:
        m = re.match(r"^ghcr\.io/([^/]+)/", a["image"]) if a["source"] == "image" else None
        hangar["app"] = {"name": a["name"], "slug": a["slug"], "pkg": a["pkg"], "expose": a["expose"],
                         "sub": a["sub"], "port": a["port"], "mem": a["mem_mb"], "db": bool(a["db"]),
                         "gh": m.group(1) if m else None}
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
    conf = backup.configured()
    snaps, snap_err = (await asyncio.to_thread(backup.snapshots)) if conf else ([], None)
    keep = json.loads(db.settings().get("backup_keep") or "{}")
    nxt = P.run(["systemctl", "show", "platform-backup.timer", "-p", "NextElapseUSecRealtime", "--value"], timeout=10)[1]
    m = re.search(r"(\d{4})-(\d{2})-(\d{2}) (\d{2}:\d{2})", nxt)
    nxt = f"{m.group(3)}/{m.group(2)} à {m.group(4)}" if m else nxt
    busy = backup.running()
    return render(request, "backups.html", title="Sauvegardes", nav="backups", conf=conf, runs=backup.last_runs(12),
                  last_ok=backup.last_ok(), busy=busy, snaps=snaps, snap_err=snap_err,
                  pending=backup.auth_pending(), google_url=backup._auth.get("google_url"),
                  pw=backup.password(), keep=keep, next_run=nxt.strip(), apps=db.apps(), refresh=busy,
                  folder=backup.FOLDER, own_client=backup.client_id())


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
    slug, snap = f.get("slug") or "", (f.get("snap") or "").strip()
    parts = [p for p in ("data", "db") if f.get(p) == "on"]
    a = db.app(slug)
    if not a or not re.fullmatch(r"[0-9a-f]{8,64}", snap):
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
        P.spawn(backup.restore_app, slug, snap, parts)
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
    if s.get("mode") == "tunnel":
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
    rc, out = P.run(["docker", "ps", "-a", "--filter", "label=fr.hangar.app", "--format", "{{.ID}}"], timeout=20)
    ids = out.split()
    if not ids:
        return {}
    rc, out = P.run(["docker", "inspect", "-f", '{{index .Config.Labels "fr.hangar.app"}}\t{{.RestartCount}}\t{{.State.StartedAt}}\t{{.State.OOMKilled}}', *ids], timeout=20)
    res = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 4:
            started = parts[2][:19]
            try:
                ts = calendar.timegm(time.strptime(started, "%Y-%m-%dT%H:%M:%S"))   # Docker donne l'heure UTC
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
