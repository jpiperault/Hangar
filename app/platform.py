"""Opérations sur la plateforme : fichiers compose, Docker, Caddy, PostgreSQL."""
import base64
import calendar
import concurrent.futures
import gzip
import html
import json
import os
import re
import shutil
import socket
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
BACKUPS = "/srv/backups"
CADDYFILE = f"{PLATFORM}/Caddyfile"
PUBLIC = f"{PLATFORM}/public"
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


def maintenance(slug=None):
    """Appli(s) en maintenance : {slug: {on, auto, msg, since}}. Caddy y répond par une page 503."""
    m = db.kv_get("maintenance") or {}
    return m.get(slug) if slug else m


def set_maintenance(slug, on, auto=False, msg="", reroute=True):
    """auto : posée par une opération (restauration, import…) et retirée par elle, sans toucher à une maintenance
    posée à la main."""
    with routing_lock:
        m = db.kv_get("maintenance") or {}
        cur = m.get(slug)
        if on:
            if cur and not cur.get("auto") and auto:
                return False   # déjà en maintenance à la main : l'opération n'y touche pas
            m[slug] = {"on": True, "auto": auto, "msg": msg[:300], "since": time.time()}
        else:
            if not cur or (auto and not cur.get("auto")):
                return False
            m.pop(slug, None)
        db.kv_set("maintenance", m)
    if reroute:
        try:
            apply_routing()
        except RuntimeError as e:
            log("warn", slug, f"page de maintenance non appliquée : {e}")
    return True


def _maint_lines(a, ind):
    m = maintenance(a["slug"])
    msg = (m.get("msg") or "").strip() or "Le service revient dans quelques minutes. Merci de ta patience."
    body = MAINT_HTML.format(msg=html.escape(msg, quote=False), name=html.escape(a["name"], quote=False))
    body = body.replace("`", "'").replace("\n", " ")
    return [f"{ind}header Retry-After 120", f"{ind}header X-Hangar-Maintenance 1", f"{ind}header Cache-Control no-store",
            f'{ind}header Content-Type "text/html; charset=utf-8"', f"{ind}respond `{body}` 503"]


def _upstream(a, prefix, ind, here=LOCAL):
    if maintenance(a["slug"]):
        return _maint_lines(a, ind)
    if a["desired"] == "stopped":
        return [f'{ind}respond "Service arrêté" 503']
    from . import ha
    # appli sur ce nœud : en local ; sur un autre nœud : par le réseau privé WireGuard
    nodes = ha.instance_nodes(a)
    hosts = [f"{'127.0.0.1' if n == here else node_wg(n)}:{a['host_port']}" for n in nodes]
    lines = [f"{ind}reverse_proxy {' '.join(hosts)} {{",
             f"{ind}\theader_up X-Real-IP {{client_ip}}"]
    if len(hosts) > 1:   # instances multiples : répartition, et une instance qui ne répond plus est écartée
        from . import affinity
        lines += [f"{ind}\t{affinity.caddy_policy(a['slug'])}", f"{ind}\tlb_try_duration 5s",
                  f"{ind}\thealth_uri {a['health_path'] or '/'}", f"{ind}\thealth_interval 10s",
                  f"{ind}\thealth_timeout 3s", f"{ind}\thealth_status 2xx", f"{ind}\tfail_duration 30s"]
    if prefix:
        lines.append(f"{ind}\theader_up X-Forwarded-Prefix {prefix}")
    lines.append(f"{ind}}}")
    return lines


def _site_names(hosts, tunnel, port):
    return ", ".join(f"http://{h}:{port}" if tunnel else h for h in hosts)


def render_caddyfile(s, apps, here=LOCAL):
    """Un bloc par nom public, selon le mode de son domaine :
    - tunnel : HTTP sur l'adresse locale de cloudflared (TUNNEL_BIND), TLS terminé chez Cloudflare ; sur la console et
      sur chaque nœud qui reçoit le trafic du tunnel ;
    - direct : Caddy écoute en 80/443 et obtient les certificats Let's Encrypt ; seulement sur la machine d'entrée
      choisie pour ce domaine (celle vers qui pointe le DNS)."""
    doms = D.by_name()
    rts = D.all_routes()
    bind_host, port = s["tunnel_bind"].rsplit(":", 1)
    ingress = here == LOCAL or bool(db.one("SELECT 1 FROM nodes WHERE id = ? AND ingress = 1", (here,)))

    def served(d):
        return (ingress and tunnel_ready()) if d["mode"] == "tunnel" else (d["entry"] or LOCAL) == here
    live = {n: d for n, d in doms.items() if served(d)}
    any_tunnel = any(d["mode"] == "tunnel" for d in live.values())

    L = [f"# Généré par Hangar le {time.strftime('%Y-%m-%d %H:%M:%S')} pour {here}. Ne pas éditer à la main.",
         "{", "\tadmin localhost:2019"]
    if any_tunnel:
        L += [f"\tservers {s['tunnel_bind']} {{",
              "\t\t# cloudflared est sur la même machine : on fait confiance à l'IP client qu'il transmet",
              "\t\ttrusted_proxies static 127.0.0.1/32 ::1",
              "\t\tclient_ip_headers Cf-Connecting-IP X-Forwarded-For",
              "\t}"]
    L += ["}", "",
          "# Journal des requêtes (JSON), lu par Hangar pour les statistiques",
          "(hangar_log) {", "\tlog {", f"\t\toutput file {ACCESS_LOG} {{", "\t\t\troll_size 20MiB",
          "\t\t\troll_keep 3", "\t\t}", "\t\tformat json", "\t}", "}", "",
          "# Sites servis par le tunnel : HTTP local seulement",
          f"(tunnel) {{", f"\tbind {bind_host}", "}"]
    by_slug = {a["slug"]: a for a in apps}
    from . import statuspage
    sp = statuspage.settings()
    for name, d in sorted(live.items(), key=lambda x: (not x[1]["is_default"], x[0])):
        tunnel = d["mode"] == "tunnel"
        L += ["", f"# ---------------- {name} ({'tunnel Cloudflare' if tunnel else 'direct, Let’s Encrypt'})"]
        if statuspage.host(sp) and sp["domain"] == name:
            L += ["", "# page de statut publique", _site_names([statuspage.host(sp)], tunnel, port) + " {"]
            if tunnel:
                L.append("\timport tunnel")
            L += ["\tencode zstd gzip", f"\troot * {PUBLIC}/{statuspage.DIR}", '\theader Cache-Control "public, max-age=30"',
                  "\trewrite * /index.html", "\tfile_server", "}"]
        if d["hub"]:
            L += ["", f"# Routes par chemin sur {d['hub']}.{name}", _site_names([f"{d['hub']}.{name}"], tunnel, port) + " {"]
            if tunnel:
                L.append("\timport tunnel")
            L += ["\timport hangar_log", "\tencode zstd gzip",
                  "\t# configuration à distance des applis Android (remoteconfig.py)",
                  "\thandle /.well-known/apps/* {", f"\t\troot * {PUBLIC}/{name}",
                  '\t\theader Cache-Control "public, max-age=60"', "\t\tfile_server", "\t}",
                  "\t# rapports de plantage (crashes.py) : serveur interne de la console",
                  "\thandle /.well-known/hangar/crash/* {", "\t\trequest_body {", "\t\t\tmax_size 64KB", "\t\t}",
                  f"\t\treverse_proxy {'127.0.0.1' if here == LOCAL else node_wg(LOCAL)}:8099 {{",
                  "\t\t\theader_up X-Real-IP {client_ip}", "\t\t}", "\t}",
                  "\thandle /.well-known/apps.json {",
                  f"\t\troot * {PUBLIC}/{name}",
                  '\t\theader Cache-Control "public, max-age=300"',
                  "\t\tfile_server", "\t}",
                  "\thandle /health {", '\t\trespond "ok" 200', "\t}",
                  "\t# pages publiques : accueil et règles de confidentialité",
                  "\thandle / {", f"\t\troot * {PUBLIC}/{name}", "\t\trewrite * /index.html", "\t\tfile_server", "\t}",
                  "\thandle /confidentialite {", f"\t\troot * {PUBLIC}/{name}", "\t\trewrite * /confidentialite.html",
                  "\t\tfile_server", "\t}"]
            for slug, rs in rts.items():
                a = by_slug.get(slug)
                if not a or not any(r["kind"] == "path" and r["domain"] == name for r in rs):
                    continue
                L += ["", f"\t# appli {slug}", f"\tredir /{slug} /{slug}/ 308", f"\thandle_path /{slug}/* {{",
                      f"\t\tlog_append hangar_app {slug}"]
                L += _upstream(a, f"/{slug}", "\t\t", here)
                L.append("\t}")
            L += ["", "\thandle {", '\t\trespond "Not found" 404', "\t}", "}"]
        for slug, rs in rts.items():
            a = by_slug.get(slug)
            hosts = [D.host_of(r, doms) for r in rs if r["kind"] == "sub" and r["domain"] == name]
            if not a or not hosts:
                continue
            L += ["", f"# appli {slug}", _site_names(hosts, tunnel, port) + " {"]
            if tunnel:
                L.append("\timport tunnel")
            L += ["\timport hangar_log", f"\tlog_append hangar_app {slug}", "\tencode zstd gzip"]
            L += _upstream(a, None, "\t", here)
            L.append("}")
    if any_tunnel:
        L += ["", "# Tout autre nom arrivant par le tunnel", f"http://:{port} {{", "\timport tunnel",
              '\trespond "Not found" 404', "}"]
    return "\n".join(L) + "\n"


def tunnel_ready():
    """Le tunnel sert quelque chose : au moins un domaine en mode tunnel."""
    return D.has_mode("tunnel")


def manifests():
    """apps.json de chaque domaine qui a un hôte de routes par chemin : {pkg: adresse de l'appli sur ce domaine}.
    Une appli sans adresse sur ce domaine n'y figure pas."""
    doms = D.by_name()
    rts = D.all_routes()
    out = {}
    for name, d in doms.items():
        if not d["hub"]:
            continue
        m = {}
        for a in db.apps():
            if not a["pkg"]:
                continue
            u = D.primary_url(a["slug"], rts.get(a["slug"], []), doms, domain=name)
            if u:
                m[a["pkg"]] = u
        out[name] = m
    return out


def tunnel_status():
    rc, out = run(["systemctl", "is-active", "cloudflared"], timeout=10)
    installed = shutil.which("cloudflared") is not None
    return {"installed": installed, "active": out.strip() == "active",
            "state": out.strip() if installed else "non installé"}


# ---------------------------------------------------------------- noms publics et tunnel

TUNNEL_TOKEN = "/etc/cloudflared/token"
_dns_cache = {}
_dns_pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)


def _doh(name, rtype):
    """Réponse du résolveur public de Cloudflare (DNS sur HTTPS) : True/False, None s'il ne répond pas."""
    url = "https://cloudflare-dns.com/dns-query?" + urllib.parse.urlencode({"name": name, "type": rtype})
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept": "application/dns-json"}),
                                    timeout=2.5) as r:
            d = json.loads(r.read())
    except (OSError, ValueError):
        return None
    return d.get("Status") == 0 and any(a.get("type") in (1, 28) for a in d.get("Answer") or [])


def _resolve(name):
    """Le nom est-il visible d'Internet ? Demandé à un résolveur public, pas à celui de la machine (souvent la box,
    qui garde en cache un « inexistant » jusqu'à 30 minutes après la déclaration)."""
    ok = _doh(name, "A")
    if ok is False:
        ok = _doh(name, "AAAA")
    if ok is not None:
        return ok
    try:   # résolveur public injoignable : celui de la machine
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


def public_names(s=None, slug=None):
    """Chaque nom public que Cloudflare (ou le DNS) doit connaître, sans joker, avec son état DNS et Cloudflare."""
    names = D.public_names(slug)
    st = resolves([n["name"] for n in names])
    cf = db.kv_get("cf_status") or {}
    for n in names:
        n["ok"] = st[n["name"]]
        n["cf"] = (cf.get("names") or {}).get(n["name"])
    return names


def app_public_names(a, s=None):
    return [n for n in public_names(slug=a["slug"]) if n["slug"]]


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
        sync_all_tunnels()   # les connecteurs des nœuds suivent le même tunnel
        return p["tunnel_id"]
    if old is not None:
        write_private(TUNNEL_TOKEN, old)
        run(["systemctl", "restart", "cloudflared"], timeout=30)
    log("error", "tunnel", f"nouveau jeton refusé ({err}), ancien jeton remis")
    raise RuntimeError(f"cloudflared n'a pas pu se connecter avec ce jeton : {err}. L'ancien jeton est remis.")


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
        files = write_manifests()
        push_routing(s, apps, files)
    from . import cloudflare      # noms publics chez Cloudflare (si un jeton d'API est enregistré)
    spawn(cloudflare.sync_quiet)
    from . import security
    spawn(security.reconcile)   # pare-feu des nœuds : 80/443 suivent les machines d'entrée des domaines directs


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


def public_pages(host, contact):
    """Page d'accueil et règles de confidentialité du domaine (demandées par Google pour publier l'accès au Drive)."""
    esc = lambda t: html.escape(t, quote=True)
    who = (f'<a href="mailto:{esc(contact)}">{esc(contact)}</a>' if contact else "l'administrateur de ce serveur")
    home = PAGE.format(title=f"Hangar · {esc(host)}", host=esc(host), body=f"""<h1>Hangar</h1>
<p class="sub">{esc(host)}</p>
<p>Ce serveur héberge les services de {esc(host.split('.', 1)[-1])} avec Hangar, une console d'hébergement
auto-hébergée et open source : applications web, bases de données, sauvegardes et surveillance.</p>
<h2>Utilisation de Google Drive</h2>
<p>Hangar peut envoyer les sauvegardes chiffrées du serveur dans le Google Drive de son administrateur. Il n'accède
qu'aux fichiers qu'il a créés lui-même (autorisation <code>drive.file</code>) et ne lit aucun autre document.</p>
<p>Contact : {who}.</p>""")
    priv = PAGE.format(title=f"Règles de confidentialité · {esc(host)}", host=esc(host), body=f"""<h1>Règles de confidentialité</h1>
<p class="sub">Hangar sur {esc(host)}</p>
<h2>Données consultées</h2>
<p>Quand son administrateur connecte Google Drive, Hangar demande uniquement l'autorisation <code>drive.file</code> :
il voit et modifie seulement les fichiers qu'il a lui-même créés, dans un dossier dédié. Il ne lit ni ne liste aucun
autre fichier du Drive, et n'accède à aucune autre donnée du compte Google (contacts, e-mails, profil).</p>
<h2>Utilisation</h2>
<p>Ces fichiers sont les sauvegardes du serveur. Ils sont chiffrés sur le serveur avant leur envoi : Google ne
reçoit que des données illisibles. Ils servent uniquement à restaurer le serveur après une panne.</p>
<h2>Conservation et partage</h2>
<p>Les sauvegardes sont gardées selon la durée choisie dans la console, puis supprimées. Le jeton d'accès
Google reste sur le serveur. Aucune donnée n'est vendue, partagée avec des tiers ni utilisée à des fins publicitaires.
L'utilisation des données reçues des API Google respecte les
<a href="https://developers.google.com/terms/api-services-user-data-policy">règles relatives aux données utilisateur des services API Google</a>,
y compris les exigences d'utilisation limitée.</p>
<h2>Révocation</h2>
<p>L'accès peut être retiré à tout moment depuis la console (Sauvegardes, Déconnecter) ou sur
<a href="https://myaccount.google.com/permissions">myaccount.google.com/permissions</a>.</p>
<h2>Contact</h2>
<p>{who[0].upper() + who[1:] if not contact else who}.</p>""")
    return {"index.html": home, "confidentialite.html": priv}


def write_manifests():
    """Écrit public/<domaine>/.well-known/apps.json et les pages publiques (accueil, confidentialité) ;
    retourne {chemin relatif: contenu} pour les nœuds."""
    files = {}
    doms = D.by_name()
    contact = db.settings().get("public_contact") or ""
    from . import remoteconfig
    for name, m in manifests().items():
        files[f"{name}/.well-known/apps.json"] = json.dumps(m, indent=2, ensure_ascii=False)
        files.update(remoteconfig.files(name, f"{doms[name]['hub']}.{name}", m))
        for fname, content in public_pages(f"{doms[name]['hub']}.{name}", contact).items():
            files[f"{name}/{fname}"] = content
    from . import statuspage
    if statuspage.host():   # gardée dans l'envoi aux nœuds (qui remplace tout le dossier public)
        files[f"{statuspage.DIR}/index.html"] = statuspage.render()[0]
    for rel in files:
        path = f"{PUBLIC}/{rel}"
        os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write(files[rel])
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    keep = {rel.split("/", 1)[0] for rel in files}
    for name in os.listdir(PUBLIC) if os.path.isdir(PUBLIC) else []:
        if "." in name and not name.startswith(".") and name not in keep:   # domaine retiré ou sans préfixe
            shutil.rmtree(f"{PUBLIC}/{name}", ignore_errors=True)
    return files


# ---------------------------------------------------------------- entrée du trafic sur les nœuds

def ingress_nodes(s=None):
    """Nœuds distants qui reçoivent du trafic Internet : par le tunnel (option « reçoit le trafic ») ou comme
    machine d'entrée d'un domaine en mode direct."""
    direct = {d["entry"] for d in D.all_domains() if d["mode"] == "direct"}
    rows = db.q("SELECT * FROM nodes WHERE id != 'local' AND state IN ('ok', 'offline')")
    return [n for n in rows if (n["ingress"] and tunnel_ready()) or n["id"] in direct]


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


def push_routing(s, apps, files):
    """Envoie à chaque nœud d'entrée sa propre configuration Caddy et les apps.json (en parallèle, erreurs journalisées).
    Un nœud qui ne reçoit plus de trafic garde une configuration vide."""
    targets = ingress_nodes(s)
    ids = {n["id"] for n in targets}
    idle = [n for n in db.q("SELECT * FROM nodes WHERE id != 'local' AND state = 'ok'") if n["id"] not in ids]
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for rel, content in files.items():
            data = content.encode()
            ti = tarfile.TarInfo(rel)
            ti.size, ti.mode = len(data), 0o644
            tar.addfile(ti, io.BytesIO(data))
    blob = buf.getvalue()

    def one(n):
        rc, out = nsh(n["id"], PUSH_CADDY, timeout=60, input=render_caddyfile(s, apps, here=n["id"]))
        if rc:
            return f"{n['id']} : " + tail(out, 2)
        rc, out = nsh(n["id"], PUSH_PUBLIC, timeout=30, input=blob)
        return f"{n['id']} : " + tail(out, 2) if rc else None

    def empty(n):
        nsh(n["id"], PUSH_CADDY, timeout=60, input="# Généré par Hangar : ce nœud ne reçoit pas de trafic\n"
                                                  "{\n\tadmin localhost:2019\n}\n")
    if not targets and not idle:
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(targets) + len(idle)) as ex:
        errs = [e for e in ex.map(one, targets) if e]
        list(ex.map(empty, idle))
    for e in errs:
        log("warn", "caddy", f"routes non mises à jour sur le nœud {e}")


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


def sync_tunnel(node_id):
    """Connecteur cloudflared sur un nœud : même jeton que la console si le nœud reçoit le trafic, sinon arrêté."""
    n = node_row(node_id)
    if not n or is_local(node_id):
        return
    want = bool(n["ingress"]) and tunnel_ready() and os.path.exists(TUNNEL_TOKEN)
    if want:
        token = open(TUNNEL_TOKEN).read().strip()
        rc, out = nsh(node_id, "install -d -m 0755 /etc/cloudflared && umask 077 && cat > /etc/cloudflared/token.new && "
                               "mv /etc/cloudflared/token.new /etc/cloudflared/token", timeout=30, input=token + "\n")
        if rc == 0:
            rc, out = nsh(node_id, "cat > /etc/systemd/system/cloudflared.service && systemctl daemon-reload && "
                                   "systemctl enable cloudflared >/dev/null 2>&1 && systemctl restart cloudflared",
                          timeout=60, input=TUNNEL_UNIT)
        if rc:
            raise RuntimeError(f"connecteur du tunnel non démarré sur {node_id} : " + tail(out, 2))
        log("ok", f"nœud {node_id}", "connecteur du tunnel Cloudflare actif : ce nœud reçoit aussi le trafic Internet")
    else:
        nsh(node_id, "systemctl disable --now cloudflared >/dev/null 2>&1; true", timeout=30)


def sync_all_tunnels():
    for n in db.q("SELECT id FROM nodes WHERE id != 'local' AND state IN ('ok', 'offline')"):
        try:
            sync_tunnel(n["id"])
        except RuntimeError as e:
            log("warn", f"nœud {n['id']}", str(e))


def rebind_local_apps():
    """Après la création du réseau privé : republie les applis locales aussi sur 10.88.0.1, pour que les Caddy des
    autres nœuds les joignent. Recrée chaque conteneur (quelques secondes), une seule fois."""
    wg = node_wg(LOCAL)
    if not wg:
        return
    for a in db.apps():
        if not is_local(a["node"]) or a["desired"] != "running":
            continue
        d = app_dir(a["slug"])
        if not os.path.exists(f"{d}/compose.yml"):
            continue
        rc, ports = dk(LOCAL, "port", f"app-{a['slug']}-app-1", timeout=15)
        if rc or f"{wg}:{a['host_port']}" in ports:   # conteneur absent, ou déjà publié sur le réseau privé
            continue
        with op_lock:
            write_compose(a, a["version"])
            rc, out = dk(LOCAL, "compose", "up", "-d", "--no-build", cwd=d, timeout=300)
            ok, detail = (False, tail(out)) if rc else wait_health(a)
            log("ok" if ok else "error", a["slug"], "publiée aussi sur le réseau privé " + wg
                if ok else f"republication sur le réseau privé en échec : {detail}")


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
    src = e.get("source", "image")
    chk(src in ("image", "git"), "source")
    img = e.get("image")
    chk(isinstance(img, str) and (IMAGE if src == "image" else GIT).match(img), "image")
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


def _ports(a):
    ports = [f"127.0.0.1:{a['host_port']}:{a['port']}"]
    wg = node_wg(a.get("node"))
    if wg and os.path.exists("/etc/wireguard/wg-hangar.conf"):
        ports.append(f"{wg}:{a['host_port']}:{a['port']}")
    return ports


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
    env.update(extra_env)
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
    if role is None:
        from . import ha
        role = ha.role_of(a["slug"], instance)
    if role:   # haute dispo : l'arrêt de sécurité d'un nœud isolé vise ces conteneurs
        svc["labels"]["fr.hangar.ha-role"] = role
    if a["source"] == "git":
        svc["build"] = {"context": f"{a['image']}#{version}"}
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
                "{{.State.Status}} {{.State.ExitCode}} {{.RestartCount}} {{.State.OOMKilled}}", name, timeout=15)
    if rc:
        return None
    status, code, restarts, oom = (st.split() + ["", "0", "0", "false"])[:4]
    return {"status": status, "code": code, "restarts": int(restarts or 0), "oom": oom == "true"}


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


def wait_health(a, timeout=90):
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
            with urllib.request.urlopen(url, timeout=3) as r:
                return True, f"HTTP {r.status}"
        except urllib.error.HTTPError as e:
            if e.code < 500:
                return True, f"HTTP {e.code}"
            last = f"HTTP {e.code}"
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
    db.update_app(a["slug"], data_owner=f"{uid}:{gid}")


def _up(a, version):
    d, node = app_dir(a["slug"]), a.get("node")
    write_compose(a, version)
    if a["source"] == "git":
        rc, _ = dk(node, "image", "inspect", image_ref(a, version), timeout=30)
        if rc:
            log("info", a["slug"], f"build de {a['image']}#{version}")
            rc, out = dk(node, "compose", "build", "--pull", cwd=d, timeout=1800)
            if rc:
                return False, "build impossible : " + tail(out)
    else:
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
    rc, out = dk(node, "compose", "up", "-d", "--remove-orphans", "--no-build", cwd=d, timeout=300)
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
        if ok:
            from . import ha
            ha.after_deploy(slug)
        try:
            apply_routing()
        except RuntimeError:
            pass


def start(slug):
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
    with op_lock:
        db.update_app(slug, desired="stopped")
        rc, out = dk(app_node(slug), "compose", "stop", cwd=app_dir(slug), timeout=120)
        db.update_app(slug, state="ok" if rc == 0 else "error")
        log("info" if rc == 0 else "error", slug, "arrêtée" if rc == 0 else "arrêt en échec : " + tail(out))
    from . import ha
    ha.instances_do(slug, "stop")
    apply_routing()


def restart(slug):
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
        from . import ha, limits, preprod, services
        services.drop(slug)
        limits.drop(slug)
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
