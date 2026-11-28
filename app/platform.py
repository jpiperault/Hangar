"""Opérations sur la plateforme : fichiers compose, Docker, Caddy, PostgreSQL."""
import base64
import calendar
import concurrent.futures
import gzip
import json
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import alerts, cache, db
from . import domains as D

PLATFORM = "/srv/platform"
APPS_DIR = "/srv/apps"
BACKUPS = os.environ.get("HANGAR_BACKUPS", "/srv/backups")   # essais : dossier jetable
WORK_TMP = os.environ.get("HANGAR_IMPORTS_TMP", f"{BACKUPS}/restore-tmp")   # extractions et builds temporaires
CADDYFILE = f"{PLATFORM}/Caddyfile"
PUBLIC = f"{PLATFORM}/public"
ENV_FILE = f"{PLATFORM}/.env"
ACCESS_LOG = "/var/log/caddy/access.log"
LOG_SECRET_FIELDS = ("request>headers>Cookie", "request>headers>Authorization", "request>headers>Proxy-Authorization",
                     "request>headers>X-Hangar-Key", "request>headers>Cf-Access-Jwt-Assertion", "resp_headers>Set-Cookie")
PG = "platform-postgres-1"
HOST_PORT_MIN = 18001

op_lock = threading.Lock()        # une seule opération Docker à la fois
routing_lock = threading.Lock()   # une seule régénération Caddy à la fois

LABELS = {"running": "En ligne", "stopped": "Arrêtée", "error": "En erreur", "deploying": "Déploiement"}
SECRET_KEY = re.compile(r"(SECRET|PASSWORD|PASSWD|TOKEN|KEY|PASS|RECOVERY_ADMIN)$", re.I)   # + compte temporaire Stalwart
MASK = "••••••"


# ---------------------------------------------------------------- utilitaires

def run(cmd, cwd=None, timeout=600, input=None, env=None):
    try:
        binary = isinstance(input, bytes)
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=not binary, timeout=timeout, input=input, env=env)
    except subprocess.TimeoutExpired:
        return 124, f"délai dépassé ({timeout} s) : {' '.join(cmd)}"
    out = p.stdout + p.stderr
    return p.returncode, (out.decode(errors="replace") if binary else out).strip()


def tail(text, n=6):
    return " | ".join([l for l in text.splitlines() if l.strip()][-n:])


def log(level, app, msg):
    db.x("INSERT INTO events(ts, level, app, msg) VALUES(?, ?, ?, ?)",
         (time.time(), level, app, str(msg)[:2000]))


def spawn(fn, *args):
    def safe():
        try:
            fn(*args)
        except Exception as e:  # le thread ne doit jamais mourir en silence
            log("error", args[0] if args else "console", f"erreur interne : {e}")
            if args and db.app(args[0]):
                db.update_app(args[0], state="error")
    threading.Thread(target=safe, daemon=True).start()


def write_private(path, text):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, path)


# ---------------------------------------------------------------- nœuds (exécution locale ou distante)

LOCAL = "local"
NODE_SSH = "/srv/platform/nodes/ssh_config"


def node_row(node_id):
    return db.one("SELECT * FROM nodes WHERE id = ?", (node_id or LOCAL,))


def is_local(node_id):
    return (node_id or LOCAL) == LOCAL


def node_wg(node_id):
    """Adresse privée WireGuard d'un nœud (None si le réseau privé n'existe pas encore)."""
    r = node_row(node_id)
    return r["wg_ip"] if r else None


def denv(node_id):
    """Environnement pour piloter le Docker d'un nœud (None = Docker local)."""
    if is_local(node_id):
        return None
    return {**os.environ, "DOCKER_HOST": f"ssh://root@{node_wg(node_id)}"}


def dk(node_id, *args, cwd=None, timeout=600, input=None):
    if "compose" in args and "up" in args:   # réseau cloisonné de l'appli prêt avant le démarrage
        from . import segment
        try:
            segment.before_up(node_id, list(args), cwd)
        except RuntimeError as e:
            return 1, str(e)
    return run(["docker", *args], cwd=cwd, timeout=timeout, input=input, env=denv(node_id))


def nsh(node_id, cmd, timeout=120, input=None):
    """Commande shell sur un nœud (root)."""
    if is_local(node_id):
        return run(["bash", "-c", cmd], timeout=timeout, input=input)
    return run(["ssh", "-F", NODE_SSH, f"root@{node_wg(node_id)}", cmd], timeout=timeout, input=input)


def _rsync(src, dst, delete=True, timeout=6 * 3600):
    args = ["rsync", "-a", "--numeric-ids", "-e", f"ssh -F {NODE_SSH}"] + (["--delete"] if delete else [])
    return run(args + [src, dst], timeout=timeout)


def pull_dir(node, remote_dir, local_dir, delete=True):
    """Copie (incrémentale) d'un dossier d'un nœud vers la console. Propriétaires conservés (numériques)."""
    os.makedirs(local_dir, mode=0o700, exist_ok=True)
    src = f"{remote_dir.rstrip('/')}/" if is_local(node) else f"root@{node_wg(node)}:{remote_dir.rstrip('/')}/"
    rc, out = _rsync(src, f"{local_dir.rstrip('/')}/", delete)
    if rc:
        raise RuntimeError(f"copie depuis {node} impossible : " + tail(out, 2))


def push_dir(node, local_dir, remote_dir, delete=True):
    """Copie d'un dossier de la console vers un nœud (créé au besoin)."""
    rc, out = nsh(node, f"install -d {remote_dir}", timeout=60)
    if rc:
        raise RuntimeError(f"nœud {node} injoignable : " + tail(out, 2))
    dst = f"{remote_dir.rstrip('/')}/" if is_local(node) else f"root@{node_wg(node)}:{remote_dir.rstrip('/')}/"
    rc, out = _rsync(f"{local_dir.rstrip('/')}/", dst, delete)
    if rc:
        raise RuntimeError(f"copie vers {node} impossible : " + tail(out, 2))


def dir_size(node, path):
    rc, out = nsh(node, f"du -sb {path} 2>/dev/null | cut -f1", timeout=120)
    try:
        return int(out.split()[0]) if rc == 0 else None
    except (ValueError, IndexError):
        return None


def app_host(a):
    """Adresse à laquelle la console joint le port d'une appli."""
    return "127.0.0.1" if is_local(a.get("node")) else node_wg(a["node"])


def drop_orphan_routes():
    """Adresses d'applis qui n'existent plus (suppressions d'avant ce correctif) : retirées."""
    gone = [r["slug"] for r in db.q("SELECT DISTINCT slug FROM routes WHERE slug NOT IN (SELECT slug FROM apps)")]
    for slug in gone:
        D.set_routes(slug, [])
        log("info", slug, "adresses d'une appli supprimée retirées")
    return gone


def recover():
    """Au démarrage : un déploiement interrompu par un redémarrage passe en erreur."""
    for a in db.q("SELECT slug FROM apps WHERE state = 'deploying'"):
        db.update_app(a["slug"], state="error")
        log("warn", a["slug"], "déploiement interrompu par un redémarrage de la console")
    drop_orphan_routes()


# ---------------------------------------------------------------- variables d'environnement

ENV_LINE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


def parse_env(text):
    env, errors = {}, []
    for i, line in enumerate((text or "").splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = ENV_LINE.match(s)
        if not m:
            errors.append(f"ligne {i} : format attendu CLE=valeur")
            continue
        env[m.group(1)] = m.group(2)
    return env, errors


def mask_env(text):
    out = []
    for line in (text or "").splitlines():
        m = ENV_LINE.match(line.strip())
        if m and SECRET_KEY.search(m.group(1)) and m.group(2):
            out.append(f"{m.group(1)}={MASK}")
        else:
            out.append(line)
    return "\n".join(out)


def unmask_env(new_text, old_text):
    old, _ = parse_env(old_text)
    out = []
    for line in (new_text or "").splitlines():
        m = ENV_LINE.match(line.strip())
        if m and m.group(2) == MASK and m.group(1) in old:
            out.append(f"{m.group(1)}={old[m.group(1)]}")
        else:
            out.append(line.rstrip())
    return "\n".join(out).strip()


# ---------------------------------------------------------------- adresses publiques

def urls(a, s=None):
    return D.urls(a["slug"])


def primary_url(a, s=None):
    return D.primary_url(a["slug"])


def next_host_port():
    used = {r["host_port"] for r in db.q("SELECT host_port FROM apps")}
    p = HOST_PORT_MIN
    while p in used:
        p += 1
    return p


# ---------------------------------------------------------------- Caddy

MAINT_HTML = ("<!doctype html><html lang=fr><meta charset=utf-8><meta name=viewport content='width=device-width'>"
              "<title>Maintenance</title><body style='font:17px/1.6 system-ui,sans-serif;max-width:560px;margin:15vh auto;"
              "padding:0 16px;color:#1d2330'><h1 style='font-size:1.5rem'>Maintenance en cours</h1><p>{msg}</p>"
              "<p style='color:#6b7385'>{name}</p></body></html>")


# ---------------------------------------------------------------- noms publics et tunnel

TUNNEL_TOKEN = "/etc/cloudflared/token"
_dns_cache = {}
_dns_pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)


PAGE = """<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>body{{font:16px/1.6 system-ui,sans-serif;max-width:680px;margin:40px auto;padding:0 16px;color:#1d2330;background:#fff}}
h1{{font-size:1.6rem;margin:0 0 4px}}h2{{font-size:1.1rem;margin:28px 0 6px}}p,li{{color:#3b4352}}a{{color:#0b6e5a}}
.sub{{color:#6b7385;margin:0 0 24px}}footer{{margin-top:40px;font-size:.85rem;color:#6b7385}}
@media (prefers-color-scheme:dark){{body{{background:#14171d;color:#e7e9ee}}p,li{{color:#c3c8d2}}a{{color:#5fd0b5}}}}</style>
</head><body>
{body}
<footer>{host} · <a href="/">Accueil</a> · <a href="/confidentialite">Règles de confidentialité</a></footer>
</body></html>
"""


# ---------------------------------------------------------------- entrée du trafic sur les nœuds


PUSH_CADDY = r"""set -e
install -d /srv/platform/public/.well-known /var/log/caddy
[ -f /var/log/caddy/access.log ] || install -m 640 /dev/null /var/log/caddy/access.log
chown caddy:caddy /var/log/caddy /var/log/caddy/access.log
cat > /srv/platform/Caddyfile.new
if ! caddy validate --config /srv/platform/Caddyfile.new --adapter caddyfile >/tmp/hangar-caddy.err 2>&1; then
  rm -f /srv/platform/Caddyfile.new; tail -3 /tmp/hangar-caddy.err; exit 3
fi
mv /srv/platform/Caddyfile.new /srv/platform/Caddyfile
systemctl reload caddy 2>/dev/null || systemctl restart caddy
"""


PUSH_PUBLIC = r"""set -e
rm -rf /srv/platform/public.new && mkdir -p /srv/platform/public.new
tar -C /srv/platform/public.new -xf -
chmod -R a+rX /srv/platform/public.new
rm -rf /srv/platform/public.old
[ -d /srv/platform/public ] && mv /srv/platform/public /srv/platform/public.old
mv /srv/platform/public.new /srv/platform/public && rm -rf /srv/platform/public.old
"""


TUNNEL_UNIT = """[Unit]
Description=Cloudflare Tunnel client (connecteur Hangar)
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/cloudflared --no-autoupdate tunnel run --token-file /etc/cloudflared/token
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
"""


# ---------------------------------------------------------------- fichiers d'une appli

# Règles des champs d'une appli : formulaire de la console et manifeste d'une archive importée.
SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")
PKG = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$")
IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]*(:[0-9]+/[a-z0-9._/-]+)?$")
GIT = re.compile(r"^(https://[^\s#@'\"$`\\;|&<>]+|git@[^\s#'\"$`\\;|&<>]+:[^\s#'\"$`\\;|&<>]+)$")
VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
HEALTH = re.compile(r"^/[A-Za-z0-9._~/?=&%-]*$")


def app_dir(slug):
    # garde-fou : le chemin finit dans des commandes shell (console et nœuds), jamais d'identifiant hors règle
    if not isinstance(slug, str) or not SLUG.match(slug):
        raise ValueError(f"identifiant d'appli invalide : {slug!r}"[:120])
    return f"{APPS_DIR}/{slug}"


def check_app_entry(e):
    """Valide une appli venue d'ailleurs que le formulaire (manifeste d'archive). Retourne la liste des problèmes."""
    bad = []
    def chk(ok, msg):
        if not ok:
            bad.append(msg)
    slug = e.get("slug")
    chk(isinstance(slug, str) and SLUG.match(slug), "identifiant")
    name = e.get("name")
    chk(isinstance(name, str) and 0 < len(name) <= 80 and not re.search(r"[\x00-\x1f\x7f]", name), "nom")
    chk(not e.get("pkg") or (isinstance(e["pkg"], str) and PKG.match(e["pkg"])), "package")
    chk(not e.get("ios_bundle") or (isinstance(e["ios_bundle"], str) and re.fullmatch(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+", e["ios_bundle"])), "bundle iOS")
    chk(e.get("web_client", 0) in (0, 1, True, False), "client web")
    src = e.get("source", "image")
    chk(src in ("image", "git", "static"), "source")
    img = e.get("image")
    chk(src == "static" or (isinstance(img, str) and (IMAGE if src == "image" else GIT).match(img)), "image")
    chk(isinstance(e.get("version"), str) and VERSION.match(e["version"]), "version")
    for k, lo, hi in (("port", 1, 65535), ("mem_mb", 32, 4096)):
        chk(isinstance(e.get(k), int) and not isinstance(e.get(k), bool) and lo <= e[k] <= hi, k)
    chk(isinstance(e.get("health_path", "/"), str) and HEALTH.match(e.get("health_path", "/")), "chemin de santé")
    chk(not e.get("data_user") or (isinstance(e["data_user"], str) and USER_RE.match(e["data_user"])), "propriétaire de /data")
    env = e.get("env") or ""
    chk(isinstance(env, str) and len(env) < 65536 and not parse_env(env)[1], "variables")
    chk(e.get("db", 0) in (0, 1, True, False), "base")
    chk(not e.get("db_password") or (isinstance(e["db_password"], str) and re.match(r"^[A-Za-z0-9]{8,128}$", e["db_password"])),
        "mot de passe de base")
    chk(e.get("desired", "running") in ("running", "stopped"), "état")
    from . import kinds
    chk(e.get("kind", "web") in kinds.KINDS, "type")
    chk(e.get("expose", "path") in ("path", "sub", "both", "none", None), "exposition")
    chk(not e.get("sub") or (isinstance(e["sub"], str) and re.match(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", e["sub"])),
        "sous-domaine")
    chk(e.get("node") is None or (isinstance(e["node"], str) and re.match(r"^[a-z0-9][a-z0-9-]{0,30}$", e["node"])), "nœud")
    return bad


def db_name(slug):
    return "app_" + slug.replace("-", "_")


def safe_tag(ref):
    return re.sub(r"[^A-Za-z0-9_.-]", "-", ref)[:120]


def base_ref(a, version):
    """Image d'origine de l'appli pour cette version (sans correction des paquets système)."""
    if a["source"] == "git":
        return f"hangar/{a['slug']}:{safe_tag(version)}"
    return f"{a['image']}:{version}"


def image_ref(a, version):
    """Image déployée : l'image corrigée (patch.py) si elle existe pour cette version, sinon l'originale."""
    from . import patch
    p = patch.active(a, version) if a.get("slug") else None
    return p["ref"] if p else base_ref(a, version)


# ---------------------------------------------------------------- registres privés

DOCKER_CFG = "/root/.docker/config.json"
DOCKER_HUB = "https://index.docker.io/v1/"


def registry_of(image):
    """ghcr.io/moi/x -> ghcr.io ; nginx ou user/x -> docker.io."""
    first = image.split("/", 1)[0]
    if "/" in image and ("." in first or ":" in first or first == "localhost"):
        return first
    return "docker.io"


def registry_owner(image):
    parts = image.split("/")
    if registry_of(image) != "docker.io":
        parts = parts[1:]
    return parts[0] if len(parts) > 1 else ""


def _cfg_key(registry):
    return DOCKER_HUB if registry == "docker.io" else registry


def registry_logins():
    """{registre: utilisateur} d'après /root/.docker/config.json (jamais le jeton)."""
    try:
        auths = json.load(open(DOCKER_CFG)).get("auths", {})
    except (OSError, ValueError):
        return {}
    out = {}
    for k, v in auths.items():
        try:
            user = base64.b64decode(v.get("auth", "")).decode().split(":", 1)[0]
        except (ValueError, UnicodeDecodeError):
            user = "?"
        out["docker.io" if k == DOCKER_HUB else k] = user
    return out


def registry_login(registry, user, token):
    """docker login, jeton passé sur stdin (jamais en argument). Lève ValueError si refusé."""
    rc, out = run(["docker", "login", _cfg_key(registry), "-u", user, "--password-stdin"],
                  input=token.strip() + "\n", timeout=60)
    if rc:
        msg = tail(out).replace(token.strip(), "••••••")
        log("error", "registre", f"connexion à {registry} refusée pour {user}")
        raise ValueError(f"{registry} refuse ce jeton : {msg}")
    try:
        os.chmod(DOCKER_CFG, 0o600)
    except OSError:
        pass
    log("ok", "registre", f"identifiants enregistrés pour {registry} ({user})")


def registry_logout(registry):
    rc, out = run(["docker", "logout", _cfg_key(registry)], timeout=30)
    log("info", "registre", f"identifiants retirés pour {registry}")
    return rc == 0


def _ports(a):
    from . import gameports, kinds
    public = gameports.compose_ports(a["slug"]) if kinds.ports(a.get("kind")) else []
    if not kinds.http(a.get("kind")):   # sans page web : seulement ses ports publics (serveur de jeu, service)
        return public
    ports = [f"127.0.0.1:{a['host_port']}:{a['port']}"]
    wg = node_wg(a.get("node"))
    if wg and os.path.exists("/etc/wireguard/wg-hangar.conf"):
        ports.append(f"{wg}:{a['host_port']}:{a['port']}")
    return ports + public   # ports publics en plus de la page web (messagerie : 25, 465, 993)


def db_url(a, node=None):
    """DATABASE_URL vue d'un conteneur de l'appli sur `node` : PostgreSQL partagé du nœud, ou base dédiée (haute
    dispo) par son nom de conteneur sur le même nœud, par le réseau privé depuis un autre."""
    n = db_name(a["slug"])
    hn, hc = ha_db(a["slug"])
    if not hc:
        host = "postgres:5432"
    elif (hn or LOCAL) == (node or a.get("node") or LOCAL):
        host = f"{hc}:5432"
    else:
        from . import ha
        host = f"{node_wg(hn)}:{ha.get(a['slug'])['db_port']}"
    return f"postgresql://{n}:{a['db_password']}@{host}/{n}"


def compose_path(slug, node=None):
    """Fichier compose (sur la console) : celui du nœud principal, ou celui d'une instance supplémentaire."""
    d = app_dir(slug)
    return f"{d}/compose.yml" if node is None else f"{d}/inst-{node}/compose.yml"


def write_compose(a, version, instance=None, role=None):
    """Compose de l'appli sur son nœud (a['node']), ou d'une instance supplémentaire sur `instance`."""
    node = instance or a.get("node")
    a = {**a, "node": node}
    env, _ = parse_env(a["env"])
    if a["db"]:
        env["DATABASE_URL"] = db_url(a, node)
    from . import services
    extra, extra_env = services.compose_extra(a, f"hangar-{a['slug']}", f"{app_dir(a['slug'])}/data", instance)
    for k, v in extra_env.items():   # relais e-mail : une variable SMTP_… réglée par l'appli elle-même l'emporte
        if k.startswith(("SMTP_", "MAIL_")):
            env.setdefault(k, v)
        else:
            env[k] = v
    if a["source"] == "git":   # Django reconnu sans Dockerfile : adresses de l'appli, clé secrète (autobuild.py)
        from . import autobuild
        for k, v in autobuild.extra_env(a["slug"]).items():
            env.setdefault(k, v)
    from . import system
    tzs = system.tz_settings()
    if tzs["apps"] and tzs["tz"] and "TZ" not in env:   # heure locale dans l'appli (sauf TZ déjà choisie par elle)
        env["TZ"] = tzs["tz"]
    from . import preprod
    if preprod.prod_of(a["slug"]):   # à l'appli de couper e-mails, notifications, paiements… en préproduction
        env["HANGAR_ENVIRONMENT"] = "preprod"
    svc = {
        "image": image_ref(a, version),
        "restart": "unless-stopped",
        "ports": _ports(a),
        "networks": [f"hangar-{a['slug']}"],     # réseau propre à l'appli (segment.py)
        "volumes": [f"{app_dir(a['slug'])}/data:/data"],
        "environment": {k: v.replace("$", "$$") for k, v in env.items()},
        "mem_limit": f"{a['mem_mb']}m",
        # durcissement : pas d'élévation de privilèges, capacités rares retirées, nombre de processus borné
        "security_opt": ["no-new-privileges:true"],
        "cap_drop": ["NET_RAW", "MKNOD", "SYS_CHROOT", "SETFCAP", "AUDIT_WRITE"],
        "pids_limit": 1024,
        "labels": {"fr.hangar.app": a["slug"], "fr.hangar.version": version},
    }
    if tzs["apps"] and tzs["tz"]:   # images sans tzdata : le fichier de l'hôte suffit à la plupart
        svc["volumes"].append("/etc/localtime:/etc/localtime:ro")
    from . import limits
    if limits.cpus(a["slug"]):        # processeur borné : une appli qui s'emballe ne ralentit pas ses voisines
        svc["cpus"] = limits.cpus(a["slug"])
    from . import runopts
    runopts.apply(a["slug"], svc, f"{app_dir(a['slug'])}/data")   # point d'entrée, commande, santé, dossiers
    if role is None:
        from . import ha
        role = ha.role_of(a["slug"], instance)
    if role:   # haute dispo : l'arrêt de sécurité d'un nœud isolé vise ces conteneurs
        svc["labels"]["fr.hangar.ha-role"] = role
    if a["source"] == "git":
        from . import autobuild
        # copie du dépôt faite par Hangar sur cette machine (autobuild.checkout) : dépôts privés, sous-dossiers
        svc["build"] = {"context": autobuild.context(a["slug"])}
        df = autobuild.inline(a["slug"])
        if df:   # dépôt sans Dockerfile : celui que Hangar a choisi pour sa technologie (autobuild.py)
            svc["build"]["dockerfile_inline"] = df
    if "mysql" in extra:   # l'appli démarre quand la base répond (première initialisation, restauration d'un export)
        svc["depends_on"] = {"mysql": {"condition": "service_healthy"}}
    doc = {"name": f"app-{a['slug']}", "services": {"app": svc, **extra},
           "networks": {f"hangar-{a['slug']}": {"external": True}}}
    d = app_dir(a["slug"])
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    if is_local(node):
        os.makedirs(f"{d}/data", exist_ok=True)
    else:   # le dossier data/ vit sur le nœud (/srv/apps/<id>/data), le compose sur la console
        rc, out = nsh(node, f"install -d -m 0700 {d} && install -d {d}/data", timeout=60)
        if rc:
            raise RuntimeError(f"nœud {node} injoignable : " + tail(out, 2))
    path = compose_path(a["slug"], instance)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    # JSON est du YAML valide : aucune valeur saisie ne peut casser la structure du fichier
    write_private(path, "# Généré par Hangar. Ne pas éditer à la main.\n" + json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    return path


# ---------------------------------------------------------------- PostgreSQL

def ha_db(slug):
    """Base dédiée d'une appli en haute dispo : (nœud de la base primaire, conteneur), sinon (None, None)."""
    try:
        h = db.one("SELECT db_node FROM ha WHERE slug = ? AND db_node IS NOT NULL", (slug,))
    except Exception:
        h = None
    return (h["db_node"], f"appdb-{slug}") if h else (None, None)


def pg_where(slug):
    """(nœud, conteneur PostgreSQL) qui porte la base d'une appli : sa base dédiée en haute dispo, sinon le
    PostgreSQL partagé de son nœud. Le superutilisateur s'appelle « platform » dans les deux cas."""
    n, c = ha_db(slug)
    return (n, c) if c else (app_node(slug), PG)


def _psql(sql, node=None, container=PG):
    return dk(node, "exec", "-i", container, "psql", "-U", "platform", "-v", "ON_ERROR_STOP=1", "-qtA",
              input=sql, timeout=60)


def ensure_db(a, node=None, container=None):
    n, pw = db_name(a["slug"]), a["db_password"]
    if container is None:
        hn, hc = ha_db(a["slug"])
        node, container = (hn, hc) if hc else (a.get("node"), PG)
    rc, out = _psql(f"""
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{n}') THEN CREATE ROLE {n} LOGIN; END IF;
END $$;
ALTER ROLE {n} WITH LOGIN PASSWORD '{pw}';
SELECT 1 FROM pg_database WHERE datname = '{n}';
""", node, container)
    if rc:
        raise RuntimeError("création du rôle PostgreSQL impossible : " + tail(out, 2))
    if "1" not in out.split():
        rc, out = _psql(f"CREATE DATABASE {n} OWNER {n};", node, container)
        if rc:
            raise RuntimeError("création de la base impossible : " + tail(out, 2))
        log("ok", a["slug"], f"base PostgreSQL {n} créée" + ("" if is_local(node) else f" sur le nœud {node}"))
    # chaque appli n'ouvre que sa base (par défaut, PUBLIC peut se connecter à toutes)
    rc, out = _psql(f"REVOKE CONNECT, TEMPORARY ON DATABASE {n} FROM PUBLIC; REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;"
                    + (" REVOKE CONNECT ON DATABASE platform FROM PUBLIC;" if container == PG else ""), node, container)
    if rc:
        log("warn", a["slug"], "droits de connexion PostgreSQL non restreints : " + tail(out, 2))


def app_node(slug):
    a = db.app(slug)
    return a["node"] if a else LOCAL


def dump_db(slug, dest, node=None):
    n = db_name(slug)
    pn, pc = pg_where(slug)
    p = subprocess.run(["docker", "exec", pc, "pg_dump", "-U", "platform", n], capture_output=True, timeout=600,
                       env=denv(node or pn))
    if p.returncode:
        raise RuntimeError("dump impossible : " + p.stderr.decode(errors="replace")[-300:])
    with gzip.open(dest, "wb") as f:
        f.write(p.stdout)


def drop_db(slug, node=None):
    n = db_name(slug)
    pn, pc = pg_where(slug)
    _psql(f"DROP DATABASE IF EXISTS {n} WITH (FORCE); DROP ROLE IF EXISTS {n};", node or pn, pc if not node else PG)


# ---------------------------------------------------------------- état des conteneurs

_stats_cache = {"ts": 0, "data": {}}


def app_nodes():
    """Nœuds qui hébergent au moins une appli (le local toujours), instances de haute dispo comprises."""
    from . import ha
    return sorted({LOCAL} | {r["node"] for r in db.q("SELECT DISTINCT node FROM apps")} | ha.all_instance_nodes())


def _on_nodes(fn):
    """Exécute fn(node) sur chaque nœud hébergeant des applis, en parallèle (un nœud lent ne bloque pas les autres)."""
    ids = app_nodes()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(ids))) as ex:
        return dict(zip(ids, ex.map(fn, ids)))


def container_states():
    def one(node):
        rc, out = dk(node, "ps", "-a", "--filter", "label=fr.hangar.app",
                     "--format", '{{.Label "fr.hangar.app"}}\t{{.State}}\t{{.Status}}', timeout=15)
        res = {}
        for line in out.splitlines() if rc == 0 else []:
            parts = line.split("\t")
            if len(parts) == 3:
                res[parts[0]] = (parts[1], parts[2])
        return res if rc == 0 else None
    states = {}
    home = {r["slug"]: r["node"] for r in db.q("SELECT slug, node FROM apps")}
    for node, res in _on_nodes(one).items():
        if res is None:
            for slug, n in home.items():
                if n == node:
                    states[slug] = ("unknown", f"nœud {node} injoignable")
        else:   # instances multiples : l'état affiché est celui du nœud principal
            states.update({k: v for k, v in res.items() if home.get(k, node) == node})
    return states


def _to_mb(v):
    m = re.match(r"([\d.]+)\s*([KMG]i?B|B)", v.strip())
    if not m:
        return 0
    n, u = float(m.group(1)), m.group(2)
    return round(n * {"B": 1 / 1048576, "KiB": 1 / 1024, "KB": 1 / 1024, "MiB": 1, "MB": 1, "GiB": 1024, "GB": 1024}[u])


def container_details():
    """Par appli : redémarrages, heure de démarrage, tuée faute de mémoire (dernier arrêt)."""
    def one(node):
        rc, out = dk(node, "ps", "-a", "--filter", "label=fr.hangar.app", "--format", "{{.ID}}", timeout=20)
        ids = out.split() if rc == 0 else []
        if not ids:
            return ""
        return dk(node, "inspect", "-f", '{{index .Config.Labels "fr.hangar.app"}}\t{{.RestartCount}}\t'
                    '{{.State.StartedAt}}\t{{.State.OOMKilled}}', *ids, timeout=20)[1]
    res = {}
    for out in _on_nodes(one).values():
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) == 4:
                try:
                    ts = calendar.timegm(time.strptime(parts[2][:19], "%Y-%m-%dT%H:%M:%S"))   # Docker donne l'heure UTC
                except ValueError:
                    ts = None
                res[parts[0]] = {"restarts": int(parts[1] or 0), "started": ts, "oom": parts[3] == "true"}
    return res


def mem_usage():
    if time.time() - _stats_cache["ts"] < 15:
        return _stats_cache["data"]
    def one(node):
        return dk(node, "stats", "--no-stream", "--format", "{{.Name}}\t{{.MemUsage}}", timeout=30)
    out = "\n".join(o for rc, o in _on_nodes(one).values() if rc == 0)
    data = {}
    for line in out.splitlines():
        name, _, usage = line.partition("\t")
        m = re.match(r"app-(.+)-app-1$", name)
        if m:
            data[m.group(1)] = _to_mb(usage.split("/")[0])
        elif name == PG:
            data["__postgres"] = _to_mb(usage.split("/")[0])
    _stats_cache.update(ts=time.time(), data=data)
    return data


def display_status(a, cs):
    if a["state"] == "deploying":
        return "deploying"
    if a["desired"] == "stopped":
        return "stopped"
    from . import kinds, sites
    if kinds.static(a["kind"]):   # pas de conteneur : en ligne dès qu'une version est publiée
        return "running" if sites.healthy(a["slug"]) else "error"
    c = cs.get(a["slug"])
    if a["state"] != "error" and c and c[0] == "running":
        return "running"
    return "error"


def states():
    """État des conteneurs de toutes les applis, depuis le cache (20 s au plus, rafraîchi en arrière-plan)."""
    return cache.get("states", 20, container_states)


def apps_with_status():
    s, cs = db.settings(), states()
    mem = cache.get("mem", 20, mem_usage) if any(v[0] == "running" for v in cs.values()) else {}
    rows = []
    for a in db.apps():
        a = dict(a)
        a["status"] = display_status(a, cs)
        a["container"] = cs.get(a["slug"], ("absent", ""))[1]
        a["ram"] = mem.get(a["slug"], 0) if a["status"] == "running" else 0
        a["urls"] = urls(a, s)
        rows.append(a)
    return rows


# ---------------------------------------------------------------- déploiement

LOG_TS = re.compile(r"^\s*\[?\d{4}-\d{2}-\d{2}[T ][\d:.,]+(?:Z|[+-]\d{2}:?\d{2})?\]?\s*")


def _container_state(name, node=None):
    rc, st = dk(node, "inspect", "-f",
                "{{.State.Status}} {{.State.ExitCode}} {{.RestartCount}} {{.State.OOMKilled}} "
                "{{if .State.Health}}{{.State.Health.Status}}{{else}}-{{end}}", name, timeout=15)
    if rc:
        return None
    status, code, restarts, oom, health = (st.split() + ["", "0", "0", "false", "-"])[:5]
    return {"status": status, "code": code, "restarts": int(restarts or 0), "oom": oom == "true",
            "health": "" if health == "-" else health}


def container_report(name, lines=6, node=None):
    """État du conteneur et dernières lignes de ses logs, sans horodatage, répétitions regroupées."""
    st = _container_state(name, node)
    out = []
    if st is None:
        return "Conteneur introuvable."
    if st["oom"]:
        out.append("Le conteneur a été tué faute de mémoire : augmente « RAM max ».")
    elif st["status"] in ("exited", "dead", "restarting") and st["code"] not in ("", "0"):
        out.append(f"Le conteneur s'arrête avec le code {st['code']}"
                   + (f" ({st['restarts']} redémarrages)." if st["restarts"] else "."))
    rc, logs = dk(node, "logs", "--tail", "80", name, timeout=20)
    groups = []
    for l in logs.splitlines():
        l = LOG_TS.sub("", l).rstrip()
        if not l.strip():
            continue
        l = l if len(l) <= 300 else l[:297] + "…"
        if groups and groups[-1][0] == l:
            groups[-1][1] += 1
        else:
            groups.append([l, 1])
    if groups:
        out.append("Derniers logs :")
        out += [f"  {l}" + (f"  (×{n})" if n > 1 else "") for l, n in groups[-lines:]]
    else:
        out.append("Aucune ligne de log : l'appli n'a rien écrit sur sa sortie standard.")
    return "\n".join(out)


def _wait_running(a, settle=30, timeout=90):
    """Appli sans page web : saine si son conteneur tourne encore après `settle` secondes, sans redémarrer."""
    node, name = a.get("node"), f"app-{a['slug']}-app-1"
    st0 = _container_state(name, node)
    base = st0["restarts"] if st0 else 0
    for _ in range(max(1, min(settle, timeout) // 3)):
        time.sleep(3)
        st = _container_state(name, node)
        if not st or st["status"] in ("exited", "dead") or st["restarts"] > base:
            why = "absent" if not st else ("s'est arrêté" if st["status"] in ("exited", "dead") else "a redémarré")
            return False, f"le conteneur {why} (code {st['code'] if st else '?'}).\n{container_report(name, node=node)}"
    return True, f"conteneur en marche depuis {settle} s"


def _wait_healthy(a, timeout=150):
    """Appli avec une commande de santé : attend que Docker la déclare « healthy »."""
    node, name = a.get("node"), f"app-{a['slug']}-app-1"
    deadline, st = time.time() + timeout, None
    while time.time() < deadline:
        time.sleep(3)
        st = _container_state(name, node)
        if not st or st["status"] in ("exited", "dead"):
            why = "absent" if not st else "s'est arrêté"
            return False, f"le conteneur {why} (code {st['code'] if st else '?'}).\n{container_report(name, node=node)}"
        if st["health"] == "healthy":
            return True, "commande de santé réussie"
        if st["health"] == "unhealthy":
            break
    last = _health_log(name, node)
    return False, (f"commande de santé en échec ({st['health'] or 'pas de réponse'} après {timeout} s)"
                   + (f" : {last}" if last else "") + f"\n{container_report(name, node=node)}")


def _health_log(name, node):
    """Sortie du dernier passage de la commande de santé (pour comprendre un échec)."""
    rc, out = dk(node, "inspect", "-f", "{{if .State.Health}}{{json .State.Health.Log}}{{end}}", name, timeout=15)
    try:
        last = json.loads(out)[-1] if rc == 0 and out.strip() else None
    except (ValueError, IndexError, TypeError):
        last = None
    if not last:
        return ""
    msg = (last.get("Output") or "").strip()
    return f"code de sortie {last.get('ExitCode')}" + (f", « {msg[-300:]} »" if msg else "")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_probe_opener = urllib.request.build_opener(_NoRedirect)


def http_probe(url, timeout=3):
    """Code HTTP de `url`, sans suivre les redirections (une appli qui renvoie vers https est bien en marche).
    Lève une exception si rien ne répond."""
    try:
        with _probe_opener.open(url, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:   # 3xx (non suivie), 4xx, 5xx
        return e.code


def wait_health(a, timeout=90):
    from . import kinds, runopts
    if not kinds.http(a.get("kind")):
        if runopts.has_health(a["slug"]):
            return _wait_healthy(a)
        return _wait_running(a, timeout=timeout)
    node = a.get("node")
    url = f"http://{app_host(a)}:{a['host_port']}{a['health_path']}"
    name = f"app-{a['slug']}-app-1"
    deadline, last = time.time() + timeout, "pas de réponse"
    st0 = _container_state(name, node)
    base = st0["restarts"] if st0 else 0
    time.sleep(1)
    while time.time() < deadline:
        st = _container_state(name, node)
        if st and (st["status"] in ("exited", "dead") or st["restarts"] - base >= 3):
            why = "s'est arrêté" if st["status"] in ("exited", "dead") else "redémarre en boucle"
            return False, f"le conteneur {why}.\n{container_report(name, node=node)}"
        try:
            code = http_probe(url, timeout=3)
            if runopts.health_ok(a["slug"], code):
                return True, f"HTTP {code}"
            last = f"HTTP {code} (attendu : {runopts.HEALTH_MODES[runopts.health_mode(a['slug'])][0]})"
        except Exception as e:
            last = str(getattr(e, "reason", e))
        time.sleep(2)
    return False, f"{url} → {last} après {timeout} s.\n{container_report(name, node=node)}"


USER_RE = re.compile(r"^(\d{1,10})(?::(\d{1,10}))?$")


def image_user(a, version):
    """UID/GID qui doit posséder /data : réglage de l'appli, sinon l'utilisateur (USER) de l'image."""
    if a.get("data_user"):
        m = USER_RE.match(a["data_user"])
        if m:
            return int(m[1]), int(m[2] or m[1]), "réglé dans la console"
    ref, node = image_ref(a, version), a.get("node")
    rc, u = dk(node, "image", "inspect", "-f", "{{.Config.User}}", ref, timeout=30)
    u = u.strip() if rc == 0 else ""
    if u in ("", "root", "0", "0:0", "root:root"):
        return 0, 0, "image en root"
    m = USER_RE.match(u)
    if m:
        return int(m[1]), int(m[2] or m[1]), f"USER {u} de l'image"
    # USER donné par son nom : on demande l'UID à l'image elle-même
    ids = []
    for flag in ("-u", "-g"):
        rc, out = dk(node, "run", "--rm", "--pull", "never", "--network", "none",
                     "--entrypoint", "id", ref, flag, timeout=60)
        ids.append(out.strip() if rc == 0 and out.strip().isdigit() else None)
    if all(ids):
        return int(ids[0]), int(ids[1]), f"USER {u} de l'image"
    return None, None, u


def prepare_data(a, version):
    d = f"{app_dir(a['slug'])}/data"
    node = a.get("node")
    uid, gid, src = image_user(a, version)
    if uid is None:
        log("warn", a["slug"], f"UID de l'utilisateur « {src} » introuvable (pas de commande id dans l'image) : "
            "/data reste à root. Indique l'UID dans « Propriétaire de /data ».")
        return
    rc, cur = nsh(node, f"install -d {d} && stat -c '%u %g' {d}", timeout=60)
    if rc:
        raise RuntimeError(f"dossier {d} inaccessible : {tail(cur, 2)}")
    if cur.split()[-2:] != [str(uid), str(gid)]:
        rc, out = nsh(node, f"chown -R {uid}:{gid} {d}", timeout=600)
        if rc:
            raise RuntimeError(f"impossible d'attribuer /data à {uid}:{gid} : {tail(out, 2)}")
        log("info", a["slug"], f"/data attribué à {uid}:{gid} ({src})")
    from . import runopts
    subs = [sub for sub, _ in runopts.parse_mounts(runopts.of(a["slug"]).get("mounts") or "")]
    if subs:   # dossiers montés ailleurs (www:/var/www/html…) : créés avant Docker, au même propriétaire que /data
        cmd = " && ".join(f"install -d -o {uid} -g {gid} {d}/{x} && "
                          f"if [ \"$(stat -c %u {d}/{x})\" != {uid} ]; then chown -R {uid}:{gid} {d}/{x}; fi" for x in subs)
        rc, out = nsh(node, cmd, timeout=600)
        if rc:
            raise RuntimeError(f"dossiers de data/ ({', '.join(subs)}) : {tail(out, 2)}")
    db.update_app(a["slug"], data_owner=f"{uid}:{gid}")


_rebuild = set()   # applis Git à reconstruire au prochain déploiement, même si l'image existe


def request_rebuild(slug):
    _rebuild.add(slug)


def patched(a, version):
    """Image corrigée (patch.py) en place pour cette version, ou None."""
    from . import patch
    return patch.active(a, version)


def up_timeout(slug):
    """Délai d'un « compose up » : long avec une base MySQL/MariaDB, que l'appli attend (rechargement d'un export)."""
    from . import services
    return 1800 if services.mysql(slug) else 300


def _up(a, version):
    d, node = app_dir(a["slug"]), a.get("node")
    pa = patched(a, version)
    if pa and (a["slug"] in _rebuild or dk(node, "image", "inspect", pa["ref"], timeout=30)[0]):
        # nouvelle construction demandée, ou image corrigée absente de cette machine (appli déplacée…) : l'originale
        from . import patch
        patch.forget(a["slug"])
        log("warn", a["slug"], "image corrigée abandonnée : " + ("nouvelle construction" if a["slug"] in _rebuild
                                                                else "absente de cette machine") + ", image d'origine utilisée")
        pa = None
    write_compose(a, version)
    if a["source"] == "git" and not pa:
        rc, _ = dk(node, "image", "inspect", image_ref(a, version), timeout=30)
        if rc or a["slug"] in _rebuild:   # absente, ou reconstruction demandée (webhook : nouveaux commits)
            _rebuild.discard(a["slug"])
            from . import autobuild
            try:   # sans Dockerfile dans le dépôt : technologie reconnue à chaque construction
                ab = autobuild.refresh(a, version)
            except RuntimeError as e:
                return False, f"build impossible : {e}"
            try:
                autobuild.checkout(a, version)
            except RuntimeError as e:
                return False, f"build impossible : {e}"
            write_compose(a, version)
            log("info", a["slug"], f"build de {a['image']}#{version}" + (f" ({ab['sha'][:7]})" if ab.get("sha") else "")
                + ("" if ab.get("own") else f" sans Dockerfile : {ab['label']}, démarrage « {ab['start']} »"))
            rc, out = dk(node, "compose", "build", "--pull", cwd=d, timeout=1800)
            nsh(node, f"rm -rf {autobuild.src_dir(a['slug'])}", timeout=120)   # le code n'est plus utile après le build
            if rc:
                return False, "build impossible : " + tail(out)
    if a["source"] != "git" and not pa:
        rc, out = dk(node, "compose", "pull", "--quiet", cwd=d, timeout=900)
        if rc:
            rc2, _ = dk(node, "image", "inspect", image_ref(a, version), timeout=30)
            if rc2:
                hint = ""
                if re.search(r"unauthorized|denied|authentication required", out, re.I):
                    reg = registry_of(a["image"])
                    hint = (f" Image privée, ou absente sous ce nom ou ce tag. Vérifie qu'elle existe, puis renseigne "
                            f"un jeton de lecture pour {reg} dans la fiche de l'appli."
                            if reg not in registry_logins() else
                            f" Les identifiants enregistrés pour {reg} ne donnent pas accès à cette image "
                            f"(droit read:packages ? image sous ce nom et ce tag ?).")
                return False, f"téléchargement de {image_ref(a, version)} refusé.{hint}" if hint else \
                    f"téléchargement de {image_ref(a, version)} impossible : " + tail(out)
            log("warn", a["slug"], f"registre injoignable pour {image_ref(a, version)}, image déjà présente utilisée")
    prepare_data(a, version)
    rc, out = dk(node, "compose", "up", "-d", "--remove-orphans", "--no-build", cwd=d, timeout=up_timeout(a["slug"]))
    if rc:
        return False, "démarrage impossible : " + tail(out)
    ok, detail = wait_health(a)
    if not ok:
        from . import kinds
        what = f"healthcheck {a['health_path']}" if kinds.http(a.get("kind")) else "vérification de santé"
        return False, f"{what} en échec : {detail}"
    return True, detail


def deploy(slug, version, kind, previous=None):
    """kind : create | update | rollback | config. `previous` : ancienne config (kind=config)."""
    with op_lock:
        a = db.app(slug)
        if not a:
            return
        old = a["version"]
        db.update_app(slug, state="deploying")
        verb = {"create": "création", "update": "mise à jour", "rollback": "retour arrière", "config": "redéploiement"}[kind]
        log("info", slug, f"{verb} : {old} → {version}" if version != old else f"{verb} de {version}")
        try:
            if a["db"]:
                ensure_db(a)
            ok, detail = _up(a, version)
            if ok and a["desired"] != "stopped":   # vérifications après déploiement (en plus du healthcheck)
                from . import smoke
                u = urllib.parse.urlsplit(D.primary_url(slug) or "")
                sok, res = smoke.run(a, version, host=u.hostname)
                if res:
                    detail = f"{detail} ; {smoke.summary(res)}"
                    db.kv_set(f"smoke_last:{slug}", {"ts": time.time(), "version": version, "results": res})
                ok = sok
        except Exception as e:
            ok, detail = False, str(e)
        if ok:
            prev = old if version != old else a["prev_version"]
            db.update_app(slug, state="ok", desired="running", version=version, prev_version=prev, deployed_at=time.time())
            log("ok", slug, f"{version} en ligne ({detail})")
            upd = db.kv_get("image_updates") or {}
            if upd.pop(slug, None) is not None:   # image du tag tirée et en ligne : plus rien en attente
                db.kv_set("image_updates", upd)
            if a.get("latest_version"):
                from . import registry
                if registry.newest([a["latest_version"]], version) is None:   # plus rien de plus récent
                    db.update_app(slug, latest_version=None)
        else:
            log("error", slug, detail)
            state = "error"
            restore = None
            if kind in ("update", "rollback") and version != old and old:
                restore = (a, old, f"retour automatique à {old}")
            elif kind == "config" and previous:
                db.update_app(slug, **{k: previous[k] for k in ("port", "health_path", "mem_mb", "source", "image", "env", "db", "data_user")})
                if "_run" in previous:   # démarrage du conteneur (runopts) d'avant
                    from . import runopts
                    runopts.restore(slug, previous["_run"])
                restore = (db.app(slug), old, "configuration précédente restaurée")
            if restore:
                b, v, msg = restore
                try:
                    ok2, d2 = _up(b, v)
                except Exception as e:
                    ok2, d2 = False, str(e)
                if ok2:
                    state = "ok"
                    log("warn", slug, f"{msg}, {v} toujours en ligne")
                else:
                    log("error", slug, f"{msg} impossible : {d2}")
            db.update_app(slug, state=state)
            alerts.send_async(f"{a['name']} : {verb} de {version} en échec",
                              detail + ("" if state == "error" else f"\n{old} est resté en ligne."),
                              priority=4 if state == "ok" else 5, tags=["x"])
        from . import history
        history.record(slug, "Hangar (déploiement)")   # réglage remis par un retour automatique, ou première prise
        if ok:
            from . import ha, vulns
            ha.after_deploy(slug)
            vulns.after_deploy(slug)   # analyse de l'image en arrière-plan (si l'option est active)
        try:
            apply_routing()
        except RuntimeError:
            pass


def _static_toggle(slug, desired, verb):
    db.update_app(slug, desired=desired, state="ok")
    log("ok" if desired == "running" else "info", slug, verb)
    apply_routing()


def start(slug):
    from . import kinds
    if kinds.static(db.app(slug)["kind"]):
        return _static_toggle(slug, "running", "site remis en ligne")
    with op_lock:
        a = db.app(slug)
        db.update_app(slug, state="deploying", desired="running")
        rc, out = dk(a["node"], "compose", "up", "-d", "--no-build", cwd=app_dir(slug), timeout=300)
        ok, detail = (False, tail(out)) if rc else wait_health(a)
        db.update_app(slug, state="ok" if ok else "error")
        log("ok" if ok else "error", slug, "démarrée" if ok else f"démarrage en échec : {detail}")
    from . import ha
    ha.instances_do(slug, "start")
    apply_routing()


def stop(slug):
    from . import kinds
    if kinds.static(db.app(slug)["kind"]):
        return _static_toggle(slug, "stopped", "site arrêté (Caddy répond 503)")
    with op_lock:
        db.update_app(slug, desired="stopped")
        rc, out = dk(app_node(slug), "compose", "stop", cwd=app_dir(slug), timeout=120)
        db.update_app(slug, state="ok" if rc == 0 else "error")
        log("info" if rc == 0 else "error", slug, "arrêtée" if rc == 0 else "arrêt en échec : " + tail(out))
    from . import ha
    ha.instances_do(slug, "stop")
    apply_routing()


def restart(slug):
    from . import kinds
    if kinds.static(db.app(slug)["kind"]):
        return _static_toggle(slug, "running", "site rechargé")
    with op_lock:
        a = db.app(slug)
        db.update_app(slug, state="deploying", desired="running")
        rc, out = dk(a["node"], "compose", "restart", cwd=app_dir(slug), timeout=180)
        ok, detail = (False, tail(out)) if rc else wait_health(a)
        db.update_app(slug, state="ok" if ok else "error")
        log("ok" if ok else "error", slug, "redémarrée" if ok else f"redémarrage en échec : {detail}")
    from . import ha
    ha.instances_do(slug, "restart")
    apply_routing()


def delete(slug):
    with op_lock:
        a = db.app(slug)
        if not a:
            return
        stamp = time.strftime("%Y%m%d-%H%M%S")
        keep = f"{BACKUPS}/deleted/{slug}-{stamp}"
        os.makedirs(keep, exist_ok=True)
        os.chmod(keep, 0o700)
        d, node = app_dir(slug), a["node"]
        from . import gameports, ha, kinds, limits, preprod, services, sites
        if kinds.static(a["kind"]):   # site statique : versions gardées avec les copies des applis supprimées
            if os.path.isdir(f"{d}/site"):
                shutil.move(f"{d}/site", f"{keep}/site")
            shutil.rmtree(d, ignore_errors=True)
            sites.remove(slug)
            from . import hooks, perms, protect
            hooks.forget(slug)
            perms.forget_app(slug)
            protect.drop(slug)
            from . import history
            history.drop(slug)
            db.x("DELETE FROM apps WHERE slug = ?", (slug,))
            D.set_routes(slug, [])
            preprod.forget(slug)
            log("info", slug, f"site supprimé ; ses versions sont gardées dans {keep}")
            apply_routing()
            return
        try:   # MySQL / MariaDB : export à jour gardé avec les fichiers de l'appli supprimée
            services.fresh_dump(a, quiet=True)
        except RuntimeError as e:
            log("warn", slug, str(e))
        from . import mysqlrepl
        mysqlrepl.remove(slug)   # avant d'oublier les services : la réplique dit encore sur quel nœud elle est
        services.drop(slug)
        gameports.save(slug, [])
        restricted = gameports.save_sources(slug, [])
        from . import autobuild, mail, traffic
        traffic.forget(slug)
        autobuild.forget(slug)
        mail.forget(slug)   # ses enregistrements DNS de messagerie partent à la prochaine synchro Cloudflare
        limits.drop(slug)
        from . import runopts
        runopts.drop(slug)
        from . import hooks, perms, protect
        hooks.forget(slug)
        perms.forget_app(slug)
        protect.drop(slug)
        from . import diskuse, history, patch, vulns
        history.drop(slug)
        diskuse.forget(slug)
        vulns.drop(slug)
        patch.forget(slug)
        preprod.forget(slug)
        if ha.get(slug):   # haute dispo : base dédiée rapatriée dans le PostgreSQL partagé, secours et instances retirés
            ha.disable(slug, "suppression", locked=True)
            a = db.app(slug)
        if os.path.exists(f"{d}/compose.yml"):
            dk(node, "compose", "down", "--remove-orphans", cwd=d, timeout=180)
        from . import segment
        segment.drop(node, slug)
        if a["db"]:
            try:
                dump_db(slug, f"{keep}/{db_name(slug)}.sql.gz", node)
            except Exception as e:
                log("warn", slug, f"dump avant suppression impossible : {e}")
            drop_db(slug, node)
        if not is_local(node):   # rapatrie data/ du nœud avant de l'y effacer
            rc, out = run(["rsync", "-a", "-e", f"ssh -F {NODE_SSH}", f"root@{node_wg(node)}:{d}/data/",
                           f"{d}/data/"], timeout=3600)
            if rc:
                log("warn", slug, f"data/ non rapatrié depuis le nœud {node} (laissé sur place) : {tail(out, 2)}")
            else:
                nsh(node, f"rm -rf {d}", timeout=600)
        if os.path.isdir(d):
            shutil.move(d, f"{keep}/files")
        db.x("DELETE FROM apps WHERE slug = ?", (slug,))
        D.set_routes(slug, [])   # ses adresses partent avec elle (sinon elles bloquent le retrait d'un domaine)
        log("warn", slug, f"supprimée, fichiers et dump conservés dans {keep}")
    apply_routing()
    if restricted:   # règles de ses ports réservés retirées (le port pourra servir à une autre appli)
        from . import segment
        for e in segment.push_all():
            log("warn", slug, e)


def logs(slug, lines=300):
    d = app_dir(slug)
    if not os.path.exists(f"{d}/compose.yml"):
        return "Aucun conteneur pour l'instant."
    rc, out = dk(app_node(slug), "compose", "logs", "--no-color", "--no-log-prefix", "--timestamps", "--tail",
                 str(lines), cwd=d, timeout=40)
    return out or "Aucune ligne de log."


# ---------------------------------------------------------------- système

def system_info():
    def first(cmd):
        rc, out = run(cmd, timeout=15)
        return out.splitlines()[0].strip() if rc == 0 and out else "inconnu"
    try:
        debian = open("/etc/debian_version").read().strip()
    except OSError:
        debian = "?"
    mem = {}
    for line in open("/proc/meminfo"):
        k, v = line.split(":")
        mem[k] = int(v.split()[0]) // 1024
    du = shutil.disk_usage("/")
    return {
        "debian": f"Debian {debian}",
        "docker": first(["docker", "version", "--format", "{{.Server.Version}}"]),
        "compose": first(["docker", "compose", "version", "--short"]),
        "caddy": first(["caddy", "version"]).split()[0],
        "postgres": first(["docker", "exec", PG, "postgres", "--version"]).replace("postgres (PostgreSQL) ", ""),
        "mem_used": mem["MemTotal"] - mem["MemAvailable"], "mem_total": mem["MemTotal"],
        "disk_used": du.used // 2**30, "disk_total": du.total // 2**30,
    }


# Routage public (Caddy, noms publics, tunnel, entrée du trafic) : voir routing.py
from .routing import (  # noqa: E402,F401
    _doh,
    _ensure_access_log,
    _maint_lines,
    _resolve,
    _site_names,
    _tunnel_connected,
    _upstream,
    app_public_names,
    apply_routing,
    ingress_nodes,
    maintenance,
    manifests,
    parse_tunnel_token,
    public_names,
    public_pages,
    push_routing,
    rebind_local_apps,
    render_caddyfile,
    resolves,
    set_maintenance,
    set_tunnel_token,
    sync_all_tunnels,
    sync_tunnel,
    tunnel_id,
    tunnel_ready,
    tunnel_status,
    write_manifests,
)
