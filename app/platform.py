"""Opérations sur la plateforme : fichiers compose, Docker, Caddy, PostgreSQL."""
import base64
import concurrent.futures
import gzip
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request

from . import alerts, db

PLATFORM = "/srv/platform"
APPS_DIR = "/srv/apps"
BACKUPS = "/srv/backups"
CADDYFILE = f"{PLATFORM}/Caddyfile"
APPS_JSON = f"{PLATFORM}/public/.well-known/apps.json"
ENV_FILE = f"{PLATFORM}/.env"
ACCESS_LOG = "/var/log/caddy/access.log"
PG = "platform-postgres-1"
HOST_PORT_MIN = 18001

op_lock = threading.Lock()        # une seule opération Docker à la fois
routing_lock = threading.Lock()   # une seule régénération Caddy à la fois

LABELS = {"running": "En ligne", "stopped": "Arrêtée", "error": "En erreur", "deploying": "Déploiement"}
SECRET_KEY = re.compile(r"(SECRET|PASSWORD|PASSWD|TOKEN|KEY|PASS)$", re.I)
MASK = "••••••"


# ---------------------------------------------------------------- utilitaires

def run(cmd, cwd=None, timeout=600, input=None):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, input=input)
    except subprocess.TimeoutExpired:
        return 124, f"délai dépassé ({timeout} s) : {' '.join(cmd)}"
    return p.returncode, (p.stdout + p.stderr).strip()


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


def recover():
    """Au démarrage : un déploiement interrompu par un redémarrage passe en erreur."""
    for a in db.q("SELECT slug FROM apps WHERE state = 'deploying'"):
        db.update_app(a["slug"], state="error")
        log("warn", a["slug"], "déploiement interrompu par un redémarrage de la console")


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

def path_url(a, s):
    return f"https://{s['hub']}.{s['base_domain']}/{a['slug']}/"


def sub_url(a, s):
    return f"https://{a['sub']}.{s['base_domain']}/"


def urls(a, s):
    u = []
    if a["expose"] in ("path", "both"):
        u.append(("chemin", path_url(a, s)))
    if a["expose"] in ("sub", "both") and a.get("sub"):
        u.append(("sous-domaine", sub_url(a, s)))
    return u


def primary_url(a, s):
    return sub_url(a, s) if a["expose"] in ("sub", "both") and a.get("sub") else path_url(a, s)


def next_host_port():
    used = {r["host_port"] for r in db.q("SELECT host_port FROM apps")}
    p = HOST_PORT_MIN
    while p in used:
        p += 1
    return p


# ---------------------------------------------------------------- Caddy

def _upstream(a, prefix, ind):
    if a["desired"] == "stopped":
        return [f'{ind}respond "Service arrêté" 503']
    lines = [f"{ind}reverse_proxy 127.0.0.1:{a['host_port']} {{",
             f"{ind}\theader_up X-Real-IP {{client_ip}}"]
    if prefix:
        lines.append(f"{ind}\theader_up X-Forwarded-Prefix {prefix}")
    lines.append(f"{ind}}}")
    return lines


def render_caddyfile(s, apps):
    """Mode tunnel : HTTP en local derrière cloudflared, TLS terminé chez Cloudflare.
    Mode direct : Caddy écoute 80/443 et obtient lui-même les certificats Let's Encrypt."""
    domains = [s["base_domain"]] + [d for d in s["aliases"] if d != s["base_domain"]]
    tunnel = s.get("mode") == "tunnel"
    scheme = "http://" if tunnel else ""

    def names(prefix):
        return ", ".join(f"{scheme}{prefix}.{d}" for d in domains)

    L = [f"# Généré par Hangar le {time.strftime('%Y-%m-%d %H:%M:%S')}. Ne pas éditer à la main.",
         f"# Mode d'exposition : {'tunnel Cloudflare' if tunnel else 'direct (Let’s Encrypt)'}",
         "{", "\tadmin localhost:2019"]
    if tunnel:
        host, port = s["tunnel_bind"].rsplit(":", 1)
        L += ["\tauto_https off", f"\thttp_port {port}", f"\tdefault_bind {host}",
              "\tservers {",
              "\t\t# cloudflared est sur la même machine : on fait confiance à l'IP client qu'il transmet",
              "\t\ttrusted_proxies static 127.0.0.1/32 ::1",
              "\t\tclient_ip_headers Cf-Connecting-IP X-Forwarded-For",
              "\t}"]
    L += ["}", "",
          "# Journal des requêtes (JSON), lu par Hangar pour les statistiques",
          "(hangar_log) {", "\tlog {", f"\t\toutput file {ACCESS_LOG} {{", "\t\t\troll_size 20MiB",
          "\t\t\troll_keep 3", "\t\t}", "\t\tformat json", "\t}", "}", "",
          "# Routes par chemin",
          names(s["hub"]) + " {",
         "\timport hangar_log",
         "\tencode zstd gzip",
         "\thandle /.well-known/apps.json {",
         "\t\troot * /srv/platform/public",
         '\t\theader Cache-Control "public, max-age=300"',
         "\t\tfile_server",
         "\t}",
         "\thandle /health {",
         '\t\trespond "ok" 200',
         "\t}"]
    for a in apps:
        if a["expose"] not in ("path", "both"):
            continue
        slug = a["slug"]
        L += ["", f"\t# appli {slug}", f"\tredir /{slug} /{slug}/ 308", f"\thandle_path /{slug}/* {{",
              f"\t\tlog_append hangar_app {slug}"]
        L += _upstream(a, f"/{slug}", "\t\t")
        L.append("\t}")
    L += ["", "\thandle {", '\t\trespond "Not found" 404', "\t}", "}"]
    for a in apps:
        if a["expose"] in ("sub", "both") and a["sub"]:
            L += ["", f"# appli {a['slug']}", names(a["sub"]) + " {",
                  "\timport hangar_log", f"\tlog_append hangar_app {a['slug']}",
                  "\tencode zstd gzip"]
            L += _upstream(a, None, "\t")
            L.append("}")
    if tunnel:
        L += ["", "# Tout autre nom arrivant par le tunnel", "http:// {", '\trespond "Not found" 404', "}"]
    return "\n".join(L) + "\n"


def tunnel_status():
    rc, out = run(["systemctl", "is-active", "cloudflared"], timeout=10)
    installed = shutil.which("cloudflared") is not None
    return {"installed": installed, "active": out.strip() == "active",
            "state": out.strip() if installed else "non installé"}


# ---------------------------------------------------------------- noms publics et tunnel

TUNNEL_TOKEN = "/etc/cloudflared/token"
_dns_cache = {}
_dns_pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)


def _resolve(name):
    try:
        socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)
        return True
    except OSError:
        return False


def resolves(names, ttl=30):
    """{nom: True/False/None} ; None si la résolution n'a pas répondu à temps."""
    now, out, todo = time.time(), {}, {}
    for n in names:
        c = _dns_cache.get(n)
        if c and now - c[1] < ttl:
            out[n] = c[0]
        else:
            todo[n] = _dns_pool.submit(_resolve, n)
    for n, fut in todo.items():
        try:
            out[n] = fut.result(timeout=max(0.1, 3 - (time.time() - now)))
            _dns_cache[n] = (out[n], time.time())
        except concurrent.futures.TimeoutError:
            out[n] = None
    return out


def public_names(s, apps_list=None):
    """Chaque nom public que Cloudflare (ou le DNS) doit connaître, sans joker."""
    apps_list = db.apps() if apps_list is None else apps_list
    subs = [a for a in apps_list if a["expose"] != "path" and a["sub"]]
    names = []
    for d in [s["base_domain"]] + s["aliases"]:
        names.append({"name": f"{s['hub']}.{d}", "what": "routes par chemin", "slug": None, "alias": d != s["base_domain"]})
        for a in subs:
            names.append({"name": f"{a['sub']}.{d}", "what": a["name"], "slug": a["slug"], "alias": d != s["base_domain"]})
    st = resolves([n["name"] for n in names])
    for n in names:
        n["ok"] = st[n["name"]]
    return names


def app_public_names(a, s):
    if a["expose"] == "path" or not a.get("sub"):
        return []
    return [n for n in public_names(s, [a]) if n["slug"]]


def parse_tunnel_token(tok):
    """Un jeton de tunnel est du JSON {a: compte, t: id du tunnel, s: secret} encodé en base64."""
    tok = (tok or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]{60,4096}", tok):
        return None
    try:
        raw = base64.b64decode(tok + "=" * (-len(tok) % 4), altchars=b"-_" if "-" in tok or "_" in tok else None)
        d = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return None
    if not all(isinstance(d.get(k), str) and d[k] for k in ("a", "t", "s")):
        return None
    return {"tunnel_id": d["t"], "token": tok}


def tunnel_id():
    try:
        p = parse_tunnel_token(open(TUNNEL_TOKEN).read())
    except OSError:
        return None
    return p["tunnel_id"] if p else None


def _tunnel_connected(since, wait=25):
    end = time.time() + wait
    while time.time() < end:
        rc, out = run(["journalctl", "-u", "cloudflared", "--since", since, "--no-pager", "-o", "cat"], timeout=10)
        if "Registered tunnel connection" in out:
            return True, ""
        rc2, st = run(["systemctl", "is-active", "cloudflared"], timeout=10)
        if st.strip() in ("failed", "inactive"):
            break
        time.sleep(1)
    err = [l for l in out.splitlines() if " ERR " in l or "error" in l.lower()]
    return False, (err[-1] if err else "pas de connexion au bout de 25 s")[-300:]


def set_tunnel_token(tok):
    """Remplace le jeton, redémarre cloudflared, remet l'ancien si la connexion échoue."""
    p = parse_tunnel_token(tok)
    if not p:
        raise ValueError("Jeton invalide : copie la longue chaîne affichée après « cloudflared service install ».")
    rc, unit = run(["systemctl", "cat", "cloudflared"], timeout=10)
    if rc != 0 or "--token-file" not in unit:
        raise ValueError("Le service cloudflared n'utilise pas /etc/cloudflared/token. Installe-le d'abord (voir README).")
    try:
        old = open(TUNNEL_TOKEN).read()
    except OSError:
        old = None
    os.makedirs(os.path.dirname(TUNNEL_TOKEN), exist_ok=True)
    write_private(TUNNEL_TOKEN, p["token"] + "\n")
    since = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 1))
    run(["systemctl", "restart", "cloudflared"], timeout=30)
    ok, err = _tunnel_connected(since)
    if ok:
        log("ok", "tunnel", f"jeton du tunnel remplacé, tunnel {p['tunnel_id']} connecté")
        return p["tunnel_id"]
    if old is not None:
        write_private(TUNNEL_TOKEN, old)
        run(["systemctl", "restart", "cloudflared"], timeout=30)
    log("error", "tunnel", f"nouveau jeton refusé ({err}), ancien jeton remis")
    raise RuntimeError(f"cloudflared n'a pas pu se connecter avec ce jeton : {err}. L'ancien jeton est remis.")


def _sync_env_file(s):
    try:
        lines = open(ENV_FILE).read().splitlines()
    except FileNotFoundError:
        lines = []
    wanted = {"BASE_DOMAIN": s["base_domain"], "HUB": s["hub"]}
    out, seen = [], set()
    for line in lines:
        k = line.split("=", 1)[0]
        if k in wanted:
            out.append(f"{k}={wanted[k]}")
            seen.add(k)
        else:
            out.append(line)
    out += [f"{k}={v}" for k, v in wanted.items() if k not in seen]
    tmp = ENV_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(out) + "\n")
    shutil.copymode(ENV_FILE, tmp) if os.path.exists(ENV_FILE) else None
    try:
        shutil.chown(tmp, group="caddy")
    except (LookupError, PermissionError):
        pass
    os.replace(tmp, ENV_FILE)


def _ensure_access_log():
    """`caddy validate` tourne en root : sans ça il créerait le journal en root et Caddy ne pourrait plus y écrire."""
    import grp
    import pwd
    try:
        uid, gid = pwd.getpwnam("caddy").pw_uid, grp.getgrnam("caddy").gr_gid
    except KeyError:
        return
    os.makedirs(os.path.dirname(ACCESS_LOG), exist_ok=True)
    if not os.path.exists(ACCESS_LOG):
        open(ACCESS_LOG, "a").close()
    st = os.stat(ACCESS_LOG)
    if (st.st_uid, st.st_gid) != (uid, gid):
        os.chown(ACCESS_LOG, uid, gid)
    os.chmod(ACCESS_LOG, 0o640)


def apply_routing():
    """Régénère le Caddyfile et apps.json. Ne remplace rien si Caddy refuse la config."""
    with routing_lock:
        s, apps = db.settings(), db.apps()
        _ensure_access_log()
        new = CADDYFILE + ".new"
        with open(new, "w") as f:
            f.write(render_caddyfile(s, apps))
        rc, out = run(["caddy", "validate", "--config", new, "--adapter", "caddyfile"], timeout=60)
        if rc:
            os.remove(new)
            log("error", "caddy", "configuration refusée, l'ancienne est conservée : " + tail(out, 3))
            raise RuntimeError("Caddy a refusé la nouvelle configuration. Détail dans le journal.")
        if os.path.exists(CADDYFILE):
            shutil.copy2(CADDYFILE, CADDYFILE + ".prev")
        os.replace(new, CADDYFILE)
        rc, out = run(["systemctl", "reload", "caddy"], timeout=60)
        if rc:
            shutil.copy2(CADDYFILE + ".prev", CADDYFILE)
            run(["systemctl", "reload", "caddy"], timeout=60)
            log("error", "caddy", "rechargement impossible, ancienne configuration restaurée : " + tail(out, 3))
            raise RuntimeError("Caddy n'a pas pu recharger la configuration. Détail dans le journal.")
        manifest = {a["pkg"]: primary_url(a, s) for a in apps if a["pkg"]}
        tmp = APPS_JSON + ".tmp"
        with open(tmp, "w") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)
        os.chmod(tmp, 0o644)
        os.replace(tmp, APPS_JSON)
        _sync_env_file(s)


# ---------------------------------------------------------------- fichiers d'une appli

def app_dir(slug):
    return f"{APPS_DIR}/{slug}"


def db_name(slug):
    return "app_" + slug.replace("-", "_")


def safe_tag(ref):
    return re.sub(r"[^A-Za-z0-9_.-]", "-", ref)[:120]


def image_ref(a, version):
    if a["source"] == "git":
        return f"hangar/{a['slug']}:{safe_tag(version)}"
    return f"{a['image']}:{version}"


# ---------------------------------------------------------------- registres privés

DOCKER_CFG = "/root/.docker/config.json"
DOCKER_HUB = "https://index.docker.io/v1/"


def registry_of(image):
    """ghcr.io/jpiperault/x -> ghcr.io ; nginx ou user/x -> docker.io."""
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


def write_compose(a, version):
    env, _ = parse_env(a["env"])
    if a["db"]:
        n = db_name(a["slug"])
        env["DATABASE_URL"] = f"postgresql://{n}:{a['db_password']}@postgres:5432/{n}"
    svc = {
        "image": image_ref(a, version),
        "restart": "unless-stopped",
        "ports": [f"127.0.0.1:{a['host_port']}:{a['port']}"],
        "networks": ["platform"],
        "volumes": ["./data:/data"],
        "environment": {k: v.replace("$", "$$") for k, v in env.items()},
        "mem_limit": f"{a['mem_mb']}m",
        "labels": {"fr.hangar.app": a["slug"], "fr.hangar.version": version},
    }
    if a["source"] == "git":
        svc["build"] = {"context": f"{a['image']}#{version}"}
    doc = {"name": f"app-{a['slug']}", "services": {"app": svc},
           "networks": {"platform": {"external": True}}}
    d = app_dir(a["slug"])
    os.makedirs(f"{d}/data", exist_ok=True)
    os.chmod(d, 0o700)
    # JSON est du YAML valide : aucune valeur saisie ne peut casser la structure du fichier
    write_private(f"{d}/compose.yml",
                  "# Généré par Hangar. Ne pas éditer à la main.\n" + json.dumps(doc, indent=2, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------- PostgreSQL

def _psql(sql):
    return run(["docker", "exec", "-i", PG, "psql", "-U", "platform", "-v", "ON_ERROR_STOP=1", "-qtA"],
               input=sql, timeout=60)


def ensure_db(a):
    n, pw = db_name(a["slug"]), a["db_password"]
    rc, out = _psql(f"""
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{n}') THEN CREATE ROLE {n} LOGIN; END IF;
END $$;
ALTER ROLE {n} WITH LOGIN PASSWORD '{pw}';
SELECT 1 FROM pg_database WHERE datname = '{n}';
""")
    if rc:
        raise RuntimeError("création du rôle PostgreSQL impossible : " + tail(out, 2))
    if "1" not in out.split():
        rc, out = _psql(f"CREATE DATABASE {n} OWNER {n};")
        if rc:
            raise RuntimeError("création de la base impossible : " + tail(out, 2))
        log("ok", a["slug"], f"base PostgreSQL {n} créée")


def dump_db(slug, dest):
    n = db_name(slug)
    p = subprocess.run(["docker", "exec", PG, "pg_dump", "-U", "platform", n], capture_output=True, timeout=600)
    if p.returncode:
        raise RuntimeError("dump impossible : " + p.stderr.decode(errors="replace")[-300:])
    with gzip.open(dest, "wb") as f:
        f.write(p.stdout)


def drop_db(slug):
    n = db_name(slug)
    _psql(f"DROP DATABASE IF EXISTS {n} WITH (FORCE); DROP ROLE IF EXISTS {n};")


# ---------------------------------------------------------------- état des conteneurs

_stats_cache = {"ts": 0, "data": {}}


def container_states():
    rc, out = run(["docker", "ps", "-a", "--filter", "label=fr.hangar.app",
                   "--format", '{{.Label "fr.hangar.app"}}\t{{.State}}\t{{.Status}}'], timeout=20)
    states = {}
    for line in out.splitlines() if rc == 0 else []:
        parts = line.split("\t")
        if len(parts) == 3:
            states[parts[0]] = (parts[1], parts[2])
    return states


def _to_mb(v):
    m = re.match(r"([\d.]+)\s*([KMG]i?B|B)", v.strip())
    if not m:
        return 0
    n, u = float(m.group(1)), m.group(2)
    return round(n * {"B": 1 / 1048576, "KiB": 1 / 1024, "KB": 1 / 1024, "MiB": 1, "MB": 1, "GiB": 1024, "GB": 1024}[u])


def mem_usage():
    if time.time() - _stats_cache["ts"] < 15:
        return _stats_cache["data"]
    rc, out = run(["docker", "stats", "--no-stream", "--format", "{{.Name}}\t{{.MemUsage}}"], timeout=30)
    data = {}
    for line in out.splitlines() if rc == 0 else []:
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
    c = cs.get(a["slug"])
    if a["state"] != "error" and c and c[0] == "running":
        return "running"
    return "error"


def apps_with_status():
    s, cs = db.settings(), container_states()
    mem = mem_usage() if any(v[0] == "running" for v in cs.values()) else {}
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


def _container_state(name):
    rc, st = run(["docker", "inspect", "-f",
                  "{{.State.Status}} {{.State.ExitCode}} {{.RestartCount}} {{.State.OOMKilled}}", name], timeout=10)
    if rc:
        return None
    status, code, restarts, oom = (st.split() + ["", "0", "0", "false"])[:4]
    return {"status": status, "code": code, "restarts": int(restarts or 0), "oom": oom == "true"}


def container_report(name, lines=6):
    """État du conteneur et dernières lignes de ses logs, sans horodatage, répétitions regroupées."""
    st = _container_state(name)
    out = []
    if st is None:
        return "Conteneur introuvable."
    if st["oom"]:
        out.append("Le conteneur a été tué faute de mémoire : augmente « RAM max ».")
    elif st["status"] in ("exited", "dead", "restarting") and st["code"] not in ("", "0"):
        out.append(f"Le conteneur s'arrête avec le code {st['code']}"
                   + (f" ({st['restarts']} redémarrages)." if st["restarts"] else "."))
    rc, logs = run(["docker", "logs", "--tail", "80", name], timeout=15)
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


def wait_health(a, timeout=90):
    url = f"http://127.0.0.1:{a['host_port']}{a['health_path']}"
    name = f"app-{a['slug']}-app-1"
    deadline, last = time.time() + timeout, "pas de réponse"
    st0 = _container_state(name)
    base = st0["restarts"] if st0 else 0
    time.sleep(1)
    while time.time() < deadline:
        st = _container_state(name)
        if st and (st["status"] in ("exited", "dead") or st["restarts"] - base >= 3):
            why = "s'est arrêté" if st["status"] in ("exited", "dead") else "redémarre en boucle"
            return False, f"le conteneur {why}.\n{container_report(name)}"
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                return True, f"HTTP {r.status}"
        except urllib.error.HTTPError as e:
            if e.code < 500:
                return True, f"HTTP {e.code}"
            last = f"HTTP {e.code}"
        except Exception as e:
            last = str(getattr(e, "reason", e))
        time.sleep(2)
    return False, f"{url} → {last} après {timeout} s.\n{container_report(name)}"


USER_RE = re.compile(r"^(\d{1,10})(?::(\d{1,10}))?$")


def image_user(a, version):
    """UID/GID qui doit posséder /data : réglage de l'appli, sinon l'utilisateur (USER) de l'image."""
    if a.get("data_user"):
        m = USER_RE.match(a["data_user"])
        if m:
            return int(m[1]), int(m[2] or m[1]), "réglé dans la console"
    ref = image_ref(a, version)
    rc, u = run(["docker", "image", "inspect", "-f", "{{.Config.User}}", ref], timeout=20)
    u = u.strip() if rc == 0 else ""
    if u in ("", "root", "0", "0:0", "root:root"):
        return 0, 0, "image en root"
    m = USER_RE.match(u)
    if m:
        return int(m[1]), int(m[2] or m[1]), f"USER {u} de l'image"
    # USER donné par son nom : on demande l'UID à l'image elle-même
    ids = []
    for flag in ("-u", "-g"):
        rc, out = run(["docker", "run", "--rm", "--pull", "never", "--network", "none",
                       "--entrypoint", "id", ref, flag], timeout=60)
        ids.append(out.strip() if rc == 0 and out.strip().isdigit() else None)
    if all(ids):
        return int(ids[0]), int(ids[1]), f"USER {u} de l'image"
    return None, None, u


def prepare_data(a, version):
    d = f"{app_dir(a['slug'])}/data"
    os.makedirs(d, exist_ok=True)
    uid, gid, src = image_user(a, version)
    if uid is None:
        log("warn", a["slug"], f"UID de l'utilisateur « {src} » introuvable (pas de commande id dans l'image) : "
            "/data reste à root. Indique l'UID dans « Propriétaire de /data ».")
        return
    st = os.stat(d)
    if (st.st_uid, st.st_gid) != (uid, gid):
        rc, out = run(["chown", "-R", f"{uid}:{gid}", d], timeout=600)
        if rc:
            raise RuntimeError(f"impossible d'attribuer /data à {uid}:{gid} : {tail(out, 2)}")
        log("info", a["slug"], f"/data attribué à {uid}:{gid} ({src})")
    db.update_app(a["slug"], data_owner=f"{uid}:{gid}")


def _up(a, version):
    d = app_dir(a["slug"])
    write_compose(a, version)
    if a["source"] == "git":
        rc, _ = run(["docker", "image", "inspect", image_ref(a, version)], timeout=20)
        if rc:
            log("info", a["slug"], f"build de {a['image']}#{version}")
            rc, out = run(["docker", "compose", "build", "--pull"], cwd=d, timeout=1800)
            if rc:
                return False, "build impossible : " + tail(out)
    else:
        rc, out = run(["docker", "compose", "pull", "--quiet"], cwd=d, timeout=900)
        if rc:
            rc2, _ = run(["docker", "image", "inspect", image_ref(a, version)], timeout=20)
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
    rc, out = run(["docker", "compose", "up", "-d", "--remove-orphans", "--no-build"], cwd=d, timeout=300)
    if rc:
        return False, "démarrage impossible : " + tail(out)
    ok, detail = wait_health(a)
    if not ok:
        return False, f"healthcheck {a['health_path']} en échec : {detail}"
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
        except Exception as e:
            ok, detail = False, str(e)
        if ok:
            prev = old if version != old else a["prev_version"]
            db.update_app(slug, state="ok", desired="running", version=version, prev_version=prev, deployed_at=time.time())
            log("ok", slug, f"{version} en ligne ({detail})")
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
        try:
            apply_routing()
        except RuntimeError:
            pass


def start(slug):
    with op_lock:
        a = db.app(slug)
        db.update_app(slug, state="deploying", desired="running")
        rc, out = run(["docker", "compose", "up", "-d", "--no-build"], cwd=app_dir(slug), timeout=300)
        ok, detail = (False, tail(out)) if rc else wait_health(a)
        db.update_app(slug, state="ok" if ok else "error")
        log("ok" if ok else "error", slug, "démarrée" if ok else f"démarrage en échec : {detail}")
    apply_routing()


def stop(slug):
    with op_lock:
        db.update_app(slug, desired="stopped")
        rc, out = run(["docker", "compose", "stop"], cwd=app_dir(slug), timeout=120)
        db.update_app(slug, state="ok" if rc == 0 else "error")
        log("info" if rc == 0 else "error", slug, "arrêtée" if rc == 0 else "arrêt en échec : " + tail(out))
    apply_routing()


def restart(slug):
    with op_lock:
        a = db.app(slug)
        db.update_app(slug, state="deploying", desired="running")
        rc, out = run(["docker", "compose", "restart"], cwd=app_dir(slug), timeout=180)
        ok, detail = (False, tail(out)) if rc else wait_health(a)
        db.update_app(slug, state="ok" if ok else "error")
        log("ok" if ok else "error", slug, "redémarrée" if ok else f"redémarrage en échec : {detail}")
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
        d = app_dir(slug)
        if os.path.exists(f"{d}/compose.yml"):
            run(["docker", "compose", "down", "--remove-orphans"], cwd=d, timeout=180)
        if a["db"]:
            try:
                dump_db(slug, f"{keep}/{db_name(slug)}.sql.gz")
            except Exception as e:
                log("warn", slug, f"dump avant suppression impossible : {e}")
            drop_db(slug)
        if os.path.isdir(d):
            shutil.move(d, f"{keep}/files")
        db.x("DELETE FROM apps WHERE slug = ?", (slug,))
        log("warn", slug, f"supprimée, fichiers et dump conservés dans {keep}")
    apply_routing()


def logs(slug, lines=300):
    d = app_dir(slug)
    if not os.path.exists(f"{d}/compose.yml"):
        return "Aucun conteneur pour l'instant."
    rc, out = run(["docker", "compose", "logs", "--no-color", "--no-log-prefix", "--timestamps", "--tail", str(lines)],
                  cwd=d, timeout=30)
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
