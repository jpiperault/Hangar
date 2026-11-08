"""Console Hangar : routes web."""
import asyncio
import ipaddress
import os
import re
import secrets
import time

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from . import db
from . import platform as P

HERE = os.path.dirname(__file__)
LAN = ipaddress.ip_network(os.environ.get("LAN_CIDR", "192.168.91.0/24"), strict=False)
ph = PasswordHasher()

db.init()
P.recover()


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
    return render(request, "apps.html", title="Applications", nav="apps", apps=rows,
                  refresh=any(r["status"] == "deploying" for r in rows),
                  ram_total=sum(r["ram"] for r in rows))


@app.get("/apps/new")
async def new_app(request: Request):
    blank = {"name": "", "pkg": "fr.piperault.", "expose": "sub", "slug": "", "sub": "", "port": 8080,
             "health_path": "/", "mem_mb": 256, "source": "image", "image": "", "version": "", "env": "", "db": 0,
             "data_user": ""}
    return render(request, "app_form.html", title="Nouvelle application", nav="apps", a=blank, new=True, errors={})


@app.post("/apps/new")
async def create_app(request: Request):
    f = await request.form()
    d, errors = validate(f)
    if errors:
        return render(request, "app_form.html", 400, title="Nouvelle application", nav="apps", a=d, new=True, errors=errors)
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
    return render(request, "app_form.html", title=a["name"], nav="apps", a=a, new=False, errors={},
                  events=events, names=names, refresh=a["status"] == "deploying")


@app.post("/apps/{slug}")
async def save_app(request: Request, slug: str):
    cur = get_app_or_404(slug)
    if cur["state"] == "deploying":
        flash(request, "Un déploiement est en cours. Réessaie quand il sera terminé.", "error")
        return go(f"/apps/{slug}")
    f = await request.form()
    d, errors = validate(f, cur)
    if errors:
        a = {**cur, **d, "status": "error" if cur["state"] == "error" else "running", "urls": P.urls({**cur, **d}, db.settings())}
        return render(request, "app_form.html", 400, title=cur["name"], nav="apps", a=a, new=False, errors=errors, events=[])
    d.pop("slug")
    runtime = ("port", "health_path", "mem_mb", "source", "image", "env", "db", "data_user")
    changed = [k for k in runtime if str(d[k]) != str(cur[k])]
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
    info = await asyncio.to_thread(P.system_info)
    tunnel = await asyncio.to_thread(P.tunnel_status)
    names = await asyncio.to_thread(P.public_names, db.settings())
    tid = await asyncio.to_thread(P.tunnel_id)
    return render(request, "settings.html", title="Domaine et accès", nav="settings", info=info,
                  names=names, missing=[n for n in names if n["ok"] is False], tunnel=tunnel, tunnel_id=tid)


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
