"""Aides partagées par les routes : gabarits, redirections, messages, validation d'une appli."""
import asyncio
import os
import re
import time

from argon2 import PasswordHasher
from fastapi.responses import RedirectResponse
import jinja2
from fastapi.templating import Jinja2Templates

from .. import access, backup, db, gameports, i18n, kinds, nodes, security, services, stats
from .. import domains as D
from .. import platform as P


HERE = os.path.dirname(os.path.dirname(__file__))   # dossier app/
ph = PasswordHasher()
class _Loader(jinja2.FileSystemLoader):
    """Gabarits français tels quels ; dans une autre langue, traduits à leur chargement (i18n.translate_source)."""

    def __init__(self, path, lang):
        super().__init__(path)
        self.lang = lang

    def get_source(self, environment, template):
        src, filename, uptodate = super().get_source(environment, template)
        return i18n.translate_source(src, self.lang), filename, uptodate


def _size(n, lang="fr"):
    s = backup.human(n)
    if lang == "fr":
        return s
    return s.replace(",", ".").replace(" Ko", " KB").replace(" Mo", " MB").replace(" Go", " GB").replace(" To", " TB") \
        .replace(" o", " B")


def _make(lang):
    t = Jinja2Templates(env=jinja2.Environment(loader=_Loader(f"{HERE}/templates", lang), autoescape=True))
    t.env.globals.update(LABELS={k: i18n.tr(v, lang) for k, v in P.LABELS.items()}, mask_env=P.mask_env, lang=lang,
                         LANGS=i18n.LANGS)
    t.env.globals["asset_v"] = int(max(os.path.getmtime(f"{HERE}/static/{f}") for f in ("app.js", "style.css")))
    t.env.filters["when"] = lambda ts: time.strftime("%d/%m %H:%M" if lang == "fr" else "%m/%d %H:%M", time.localtime(ts)) if ts else "—"
    t.env.filters["clock"] = lambda ts: time.strftime("%d/%m %H:%M:%S" if lang == "fr" else "%m/%d %H:%M:%S", time.localtime(ts))
    t.env.filters["size"] = lambda n: _size(n, lang)
    t.env.filters["ago"] = lambda ts: _ago(ts, lang)
    t.env.filters["dur"] = lambda sec: _dur(sec, lang)
    t.env.filters["tr"] = lambda v: i18n.tr(v, lang)
    from .. import msgs
    t.env.filters["trmsg"] = lambda v: msgs.tr(v, lang)   # journal, erreurs : messages composés par le code
    return t


TPLS = {lang: _make(lang) for lang in i18n.LANGS}
tpl = TPLS["fr"]


def tpl_for(request):
    return TPLS.get(getattr(request.state, "lang", "fr"), tpl)


def _dur(sec, lang="fr"):
    if sec is None:
        return "—"
    sec = int(sec)
    d, h, m = sec // 86400, sec % 86400 // 3600, sec % 3600 // 60
    day = "j" if lang == "fr" else "d"
    return f"{d} {day} {h} h" if d else f"{h} h {m:02d}" if h else f"{m} min"


def _ago(ts, lang="fr"):
    en = lang != "fr"
    if not ts:
        return "never" if en else "jamais"
    d = time.time() - ts
    if d < 90:
        return "just now" if en else "à l'instant"
    if d < 3600:
        return f"{d // 60:.0f} min ago" if en else f"il y a {d // 60:.0f} min"
    if d < 86400 * 2:
        return f"{d // 3600:.0f} h ago" if en else f"il y a {d // 3600:.0f} h"
    return f"{d // 86400:.0f} days ago" if en else f"il y a {d // 86400:.0f} j"


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


def _app_count(request):
    from .. import perms
    if getattr(request.state, "role", "admin") == perms.ROLE:
        return len(perms.scopes(request.session.get("user")))
    return len(db.apps())


def render(request, name, status_code=200, **ctx):
    ctx.setdefault("title", "Hangar")
    ctx.update(flash=request.session.pop("flash", None), s=db.settings(), csp_nonce=getattr(request.state, "nonce", ""),
               user=request.session.get("user"), role=getattr(request.state, "role", "admin"), app_count=_app_count(request), sec_alerts=_sec_alerts())
    lang = getattr(request.state, "lang", "fr")
    ctx["title"] = i18n.tr(ctx["title"], lang)
    if ctx.get("flash") and lang != "fr":   # message après une action, écrit en français par le code
        from .. import msgs
        ctx["flash"] = {**ctx["flash"], "msg": msgs.tr(ctx["flash"]["msg"], lang)}
    return tpl_for(request).TemplateResponse(request, name, ctx, status_code=status_code)


def get_app_or_404(slug):
    a = db.app(slug)
    if not a:
        from fastapi import HTTPException
        raise HTTPException(404, "Application inconnue")
    return a


SLUG = P.SLUG
DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
PKG, IMAGE, GIT, VERSION = P.PKG, P.IMAGE, P.GIT, P.VERSION
RESERVED = {"health", "static", "well-known", "admin", "confidentialite"}


def validate(f, cur=None):
    """Retourne (données, erreurs) à partir du formulaire d'une appli."""
    d, e = {}, {}
    d["name"] = (f.get("name") or "").strip()[:80]
    if not d["name"]:
        e["name"] = "Donne un nom à l'application."
    d["kind"] = f.get("kind") if kinds.valid(f.get("kind")) else (cur["kind"] if cur else kinds.DEFAULT)
    d["pkg"] = (f.get("pkg") or "").strip()
    if d["pkg"] and not PKG.match(d["pkg"]):
        e["pkg"] = "Format attendu : fr.exemple.monappli"
    elif d["pkg"] and db.one("SELECT 1 FROM apps WHERE (pkg = ? OR ios_bundle = ?) AND slug != ?",
                             (d["pkg"], d["pkg"], cur["slug"] if cur else "")):
        e["pkg"] = "Ce package est déjà relié à une autre appli."
    d["ios_bundle"] = (f.get("ios_bundle") or "").strip()
    if d["ios_bundle"] and not re.fullmatch(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+", d["ios_bundle"]):
        e["ios_bundle"] = "Format attendu : fr.exemple.monappli"
    elif d["ios_bundle"] and db.one("SELECT 1 FROM apps WHERE (ios_bundle = ? OR pkg = ?) AND slug != ?",
                                    (d["ios_bundle"], d["ios_bundle"], cur["slug"] if cur else "")):
        e["ios_bundle"] = "Ce bundle est déjà relié à une autre appli."
    d["web_client"] = 1 if f.get("web_client") == "on" else 0

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

    if kinds.http(d["kind"]):
        d["routes"], err = D.parse_routes(f, d["slug"] or "-")
        if err:
            e["routes"] = err
    else:   # sans page web : pas d'adresse publique
        d["routes"] = []
    d["_ports"], d["_from"] = None, []
    if kinds.ports(d["kind"]):
        try:
            d["_from"] = gameports.parse_sources(f.get("gfrom") or "")
        except ValueError as x:
            e["gfrom"] = str(x)
        try:
            d["_ports"] = gameports.parse(f.get("gports") or "", d["slug"], cur["node"] if cur else f.get("node"))
            if not d["_ports"] and kinds.ports(d["kind"]) == "required":
                e["gports"] = "Indique au moins un port public, par exemple « tcp 25565 »."
        except ValueError as x:
            e["gports"] = str(x)

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
    if kinds.static(d["kind"]):   # site statique : ni image, ni conteneur, ni base, ni variables
        d.update(source="static", image="", port=80, health_path="/", mem_mb=32, env="", db=0, data_user="",
                 pkg="", ios_bundle="", web_client=0)
        if not cur:
            d["version"] = "—"
            d["node"] = P.LOCAL
        return d, e
    if d["source"] == "image":
        last = d["image"].rsplit("/", 1)[-1]
        if ":" in last:  # tag collé à l'image : on le sépare
            d["image"], tag = d["image"].rsplit(":", 1)
            version = version or tag
        if not IMAGE.match(d["image"]):
            e["image"] = "Image Docker sans tag, par exemple ghcr.io/moi/courses-api"
    elif not GIT.match(d["image"]):
        e["image"] = "URL du dépôt sans branche, par exemple https://github.com/moi/meteo-backend.git"
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


SESSION_IDLE = 30 * 60            # session fermée après 30 min sans activité


# ---------------------------------------------------------------- haute disponibilité

def _int(v, lo, hi, default):
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


def _redis_state(a):
    r = services.redis(a["slug"])
    name = f"app-{a['slug']}-redis-1"
    rc, st = P.dk(a["node"], "inspect", "-f", "{{.State.Status}}", name, timeout=20)
    if rc:
        return {"state": "absent"}
    out = {"state": st.strip()}
    if out["state"] == "running":
        rc, info = P.dk(a["node"], "exec", name, "valkey-cli", "--no-auth-warning", "-a", r["password"], "info",
                        timeout=20)
        for line in info.splitlines() if rc == 0 else []:
            k, _, v = line.strip().partition(":")
            if k in ("used_memory_human", "db0", "redis_version", "valkey_version", "connected_clients"):
                out[k] = v
    return out


def _rc_url(a, key):
    """Adresse publique de la configuration à distance d'un client mobile (hôte des routes de son domaine)."""
    if not key:
        return None
    for name, m in P.manifests().items():
        if key in m:
            return f"https://{D.get(name)['hub']}.{name}/.well-known/apps/{key}.json"
    return None


def _public_addr(a):
    """Adresse publique de la machine d'une appli (serveur de jeu : là où les joueurs se connectent)."""
    n = P.node_row(a["node"])
    return (n["address"] if n and not P.is_local(a["node"]) else None) or access.current().get("ip") or "?"


def _client_names(a):
    return [n for n, on in (("client Android", a["pkg"]), ("client iOS", a["ios_bundle"]), ("client web", a["web_client"])) if on]


# ---------------------------------------------------------------- sauvegardes

def _confirmed(f, slug):
    return (f.get("confirm") or "").strip() == slug
