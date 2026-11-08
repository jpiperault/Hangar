"""Nœuds : machines supplémentaires (VPS, serveurs dédiés, autres conteneurs) pilotées par la console.

- La console se connecte aux nœuds en SSH (root, clé dédiée /srv/platform/nodes/id_ed25519) : elle est l'initiatrice,
  elle peut donc rester derrière une box sans port ouvert.
- Réseau privé WireGuard « wg-hangar » 10.88.0.0/24 : la console est 10.88.0.1, chaque nœud 10.88.0.N.
  Maillage complet ; Endpoint connu pour les nœuds joignables, keepalive depuis la console.
- Docker à distance : `docker -H ssh://root@10.88.0.N` à travers WireGuard (multiplexage SSH).
"""
import ipaddress
import json
import os
import re
import shlex
import subprocess
import tarfile
import io
import threading
import time

from . import alerts, db
from . import platform as P

DIR = "/srv/platform/nodes"
KEY = f"{DIR}/id_ed25519"
KNOWN = f"{DIR}/known_hosts"
SSH_CONF = f"{DIR}/ssh_config"
WG_IF = "wg-hangar"
WG_NET = ipaddress.ip_network("10.88.0.0/24")
WG_LOCAL = "10.88.0.1"
WG_PORT = 51820
WG_KEY = "/etc/wireguard/hangar.key"
LOCAL = "local"
SRC = "/opt/hangar/deploy"


ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,22}[a-z0-9])?$")
_lock = threading.Lock()
_fails = {}




# ---------------------------------------------------------------- registre

def all_nodes():
    rows = db.q("SELECT * FROM nodes ORDER BY CASE id WHEN 'local' THEN 0 ELSE 1 END, created_at")
    for r in rows:
        r["info"] = json.loads(r["info"] or "{}")
    return rows


def get(node_id):
    r = db.one("SELECT * FROM nodes WHERE id = ?", (node_id,))
    if r:
        r["info"] = json.loads(r["info"] or "{}")
    return r


def _update(node_id, **f):
    if "info" in f and not isinstance(f["info"], str):
        f["info"] = json.dumps(f["info"])
    sets = ", ".join(f"{k} = ?" for k in f)
    db.x(f"UPDATE nodes SET {sets} WHERE id = ?", list(f.values()) + [node_id])


def _next_ip():
    used = {r["wg_ip"] for r in db.q("SELECT wg_ip FROM nodes")} | {WG_LOCAL}
    for h in WG_NET.hosts():
        if str(h) not in used:
            return str(h)
    raise RuntimeError("plus d'adresse libre dans 10.88.0.0/24")


def pubkey():
    return open(f"{KEY}.pub").read().strip()


def ensure_key():
    os.makedirs(DIR, mode=0o700, exist_ok=True)
    if not os.path.exists(KEY):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "hangar@console", "-f", KEY], check=True)
    _ssh_config()
    return pubkey()


def _ssh_config():
    conf = (f"# Généré par Hangar : accès SSH aux nœuds par le réseau privé\n"
            f"Host 10.88.0.*\n  User root\n  IdentityFile {KEY}\n  IdentitiesOnly yes\n"
            f"  UserKnownHostsFile {KNOWN}\n  StrictHostKeyChecking accept-new\n  BatchMode yes\n"
            f"  ControlMaster auto\n  ControlPath /run/hangar-ssh-%C\n  ControlPersist 120\n"
            f"  ServerAliveInterval 15\n  ConnectTimeout 8\n")
    P.write_private(SSH_CONF, conf)
    os.makedirs("/root/.ssh", mode=0o700, exist_ok=True)
    user = "/root/.ssh/config"
    cur = open(user).read() if os.path.exists(user) else ""
    line = f"Include {SSH_CONF}"
    if line not in cur:
        P.write_private(user, line + "\n" + cur)   # Include en tête : s'applique avant les autres blocs


def _ssh_args(n, via_wg=True):
    host = n["wg_ip"] if via_wg else n["address"]
    base = ["ssh", "-F", SSH_CONF] if via_wg else [
        "ssh", "-i", KEY, "-o", "IdentitiesOnly=yes", "-o", f"UserKnownHostsFile={KNOWN}",
        "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "-p", str(n["ssh_port"])]
    return base + [f"root@{host}"]


def ssh(n, cmd, timeout=60, input=None, via_wg=True):
    """Commande sur un nœud. via_wg=False : par son adresse publique (installation, avant le tunnel)."""
    try:
        p = subprocess.run(_ssh_args(n, via_wg) + [cmd], capture_output=True, timeout=timeout,
                           input=input, text=not isinstance(input, bytes))
    except subprocess.TimeoutExpired:
        return 124, f"délai dépassé ({timeout} s)"
    out = p.stdout + p.stderr
    return p.returncode, out if isinstance(out, str) else out.decode(errors="replace")


def docker_host(n):
    return None if n["id"] == LOCAL else f"ssh://root@{n['wg_ip']}"


def docker(n, *args, timeout=120):
    env = dict(os.environ)
    h = docker_host(n)
    if h:
        env["DOCKER_HOST"] = h
    try:
        p = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return 124, f"délai dépassé ({timeout} s)"
    return p.returncode, (p.stdout + p.stderr).strip()


# ---------------------------------------------------------------- WireGuard

def _local_key():
    os.makedirs("/etc/wireguard", mode=0o700, exist_ok=True)
    if not os.path.exists(WG_KEY):
        k = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True).stdout.strip()
        P.write_private(WG_KEY, k + "\n")
    priv = open(WG_KEY).read().strip()
    pub = subprocess.run(["wg", "pubkey"], input=priv, capture_output=True, text=True, check=True).stdout.strip()
    return priv, pub


DOCKER_AFTER_WG = (f"[Unit]\n# Les conteneurs publient leurs ports sur l'adresse WireGuard : elle doit exister avant eux.\n"
                   f"After=wg-quick@{WG_IF}.service\nWants=wg-quick@{WG_IF}.service\n")


def ensure_local():
    """Crée le nœud « local » (cette machine) et son interface WireGuard au premier nœud ajouté."""
    _, pub = _local_key()
    os.makedirs("/etc/systemd/system/docker.service.d", exist_ok=True)
    path = "/etc/systemd/system/docker.service.d/hangar-wg.conf"
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(DOCKER_AFTER_WG)
        subprocess.run(["systemctl", "daemon-reload"])
    if not get(LOCAL):
        s = db.settings()
        db.x("INSERT INTO nodes(id, name, address, wg_ip, wg_pubkey, state, created_at) VALUES(?, ?, ?, ?, ?, 'ok', ?)",
             (LOCAL, "Ce serveur (console)", s["admin_bind"].rsplit(":", 1)[0], WG_LOCAL, pub, time.time()))
    else:
        _update(LOCAL, wg_pubkey=pub)


def _conf_for(me, peers):
    """Configuration wg-quick d'un nœud. La clé privée reste sur chaque machine (insérée sur place)."""
    L = ["# Généré par Hangar. Ne pas modifier à la main.", "[Interface]",
         f"Address = {me['wg_ip']}/24", "PrivateKey = __HANGAR_KEY__"]
    if me["id"] != LOCAL:
        L.append(f"ListenPort = {WG_PORT}")
    for p in peers:
        if p["id"] == me["id"] or not p.get("wg_pubkey"):
            continue
        L += ["", f"# {p['name']} ({p['id']})", "[Peer]", f"PublicKey = {p['wg_pubkey']}", f"AllowedIPs = {p['wg_ip']}/32"]
        if p["id"] != LOCAL and p.get("address"):
            L.append(f"Endpoint = {p['address']}:{WG_PORT}")
        L.append("PersistentKeepalive = 25")
    return "\n".join(L) + "\n"


APPLY = (f"set -e; umask 077; mkdir -p /etc/wireguard; "
         f"sed \"s|__HANGAR_KEY__|$(cat {WG_KEY})|\" > /etc/wireguard/{WG_IF}.conf; "
         f"systemctl enable wg-quick@{WG_IF} >/dev/null 2>&1; "
         f"if ip link show {WG_IF} >/dev/null 2>&1; then wg syncconf {WG_IF} <(wg-quick strip {WG_IF}); "
         f"else systemctl start wg-quick@{WG_IF}; fi")


def apply_mesh():
    """Pousse la configuration WireGuard sur la console puis sur chaque nœud installé."""
    with _lock:
        peers = [n for n in all_nodes() if n["wg_pubkey"] and n["state"] in ("ok", "offline", "installing")]
        local = get(LOCAL)
        p = subprocess.run(["bash", "-c", APPLY], input=_conf_for(local, peers), capture_output=True, text=True)
        if p.returncode:
            raise RuntimeError("WireGuard local : " + P.tail(p.stderr))
        errs = []
        for n in peers:
            if n["id"] == LOCAL:
                continue
            via_wg = n["state"] == "ok" and _wg_alive(n)
            rc, out = ssh(n, f"bash -c {shlex.quote(APPLY)}", input=_conf_for(n, peers), timeout=60, via_wg=via_wg)
            if rc:
                errs.append(f"{n['id']} : {P.tail(out, 2)}")
        if errs:
            raise RuntimeError("WireGuard : " + " ; ".join(errs))


def _wg_alive(n, within=200):
    hs = handshakes()
    return time.time() - hs.get(n.get("wg_pubkey"), 0) < within


def handshakes():
    rc, out = P.run(["wg", "show", WG_IF, "latest-handshakes"], timeout=10)
    res = {}
    for line in out.splitlines() if rc == 0 else []:
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            res[parts[0]] = int(parts[1])
    return res


# ---------------------------------------------------------------- ajout d'un nœud

def add(node_id, name, address, ssh_port):
    node_id = (node_id or "").strip().lower()
    if not ID_RE.match(node_id) or node_id == LOCAL:
        raise ValueError("Identifiant : lettres minuscules, chiffres et tirets (par exemple vps-1).")
    if get(node_id):
        raise ValueError("Cet identifiant est déjà utilisé.")
    address = (address or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", address):
        raise ValueError("Adresse invalide : IP publique ou nom DNS du serveur.")
    if db.one("SELECT 1 FROM nodes WHERE address = ?", (address,)):
        raise ValueError("Ce serveur est déjà un nœud.")
    try:
        ssh_port = int(ssh_port or 22)
        assert 1 <= ssh_port <= 65535
    except (ValueError, AssertionError):
        raise ValueError("Port SSH invalide.")
    ensure_key()
    ensure_local()
    wg_ip = _next_ip()
    db.x("INSERT INTO nodes(id, name, address, ssh_port, wg_ip, state, created_at) VALUES(?, ?, ?, ?, ?, 'installing', ?)",
         (node_id, (name or node_id).strip()[:60], address, ssh_port, wg_ip, time.time()))
    P.spawn(install, node_id)


def _log(n, level, msg):
    P.log(level, f"nœud {n['id']}", msg)


def install(node_id):
    """Installation (ou réparation) d'un nœud : fichiers, bootstrap, WireGuard, vérification de Docker à distance."""
    n = get(node_id)
    _update(node_id, state="installing", error=None)
    _log(n, "info", f"installation sur {n['address']} (SSH port {n['ssh_port']})")
    try:
        rc, out = ssh(n, "cat /etc/os-release && nproc", timeout=30, via_wg=False)
        if rc:
            if re.search(r"Permission denied|publickey", out):
                raise RuntimeError("le serveur refuse la clé de Hangar : as-tu collé la ligne d'autorisation en root ?")
            raise RuntimeError("connexion SSH impossible : " + P.tail(out, 2))
        if "ID=debian" not in out:
            raise RuntimeError("Debian requis sur le nœud")
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for src, arc in ((f"{SRC}/node/bootstrap.sh", "bootstrap.sh"), (f"{SRC}/node/node.nft", "node.nft"),
                             (f"{SRC}/docker/daemon.json", "daemon.json"),
                             (f"{SRC}/docker/platform-compose.yml", "platform-compose.yml"),
                             (f"{SRC}/systemd/nftables-neutralise.conf", "nftables-neutralise.conf")):
                tar.add(src, arcname=arc)
        rc, out = ssh(n, "rm -rf /opt/hangar-node && mkdir -p /opt/hangar-node && tar -C /opt/hangar-node -xf -",
                      input=buf.getvalue(), timeout=60, via_wg=False)
        if rc:
            raise RuntimeError("copie des fichiers impossible : " + P.tail(out, 2))
        _log(n, "info", "préparation du nœud (Docker, PostgreSQL, pare-feu, WireGuard) : quelques minutes")
        rc, out = ssh(n, "bash /opt/hangar-node/bootstrap.sh", timeout=1800, via_wg=False)
        vals = dict(re.findall(r"^HANGAR_([A-Z_]+)=(.*)$", out, re.M))
        if rc or vals.get("DONE") != "1":
            raise RuntimeError(vals.get("ERROR") or f"étape « {vals.get('STEP', '?')} » en échec : " + P.tail(out, 3))
        _update(node_id, wg_pubkey=vals["WG_PUBKEY"], info={"docker": vals.get("DOCKER"), "os": vals.get("OS")})
        _log(n, "info", "configuration du réseau privé WireGuard")
        apply_mesh()
        n = get(node_id)
        for _ in range(20):
            # le ping prouve le lien ; l'échange de clés WireGuard, lui, n'est refait que toutes les ~2 minutes
            if subprocess.run(["ping", "-c1", "-W1", n["wg_ip"]], capture_output=True).returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError(f"le réseau privé ne s'établit pas (UDP {WG_PORT} bloqué vers {n['address']} ?)")
        rc, out = docker(n, "info", "--format", "{{.ServerVersion}}", timeout=60)
        if rc:
            raise RuntimeError("Docker à distance injoignable : " + P.tail(out, 2))
        _update(node_id, state="ok", last_seen=time.time())
        collect(get(node_id))
        _log(n, "ok", f"nœud prêt : réseau privé {n['wg_ip']}, Docker {out.strip()}")
        try:
            P.apply_routing()          # Caddy du nœud : routes de toutes les applis
            P.sync_tunnel(node_id)     # connecteur du tunnel si le nœud reçoit le trafic
        except RuntimeError as e:
            _log(n, "warn", str(e))
        P.spawn(P.rebind_local_apps)   # applis de la console joignables par le réseau privé
    except Exception as e:
        _update(node_id, state="error", error=str(e)[:500])
        _log(n, "error", f"installation en échec : {e}")


def set_ingress(node_id, on):
    n = get(node_id)
    if not n or node_id == LOCAL:
        raise ValueError("Nœud inconnu.")
    _update(node_id, ingress=1 if on else 0)
    P.sync_tunnel(node_id)
    P.apply_routing()
    _log(n, "info", "reçoit le trafic Internet" if on else "ne reçoit plus le trafic Internet (applis toujours joignables "
                                                            "par les autres nœuds)")


def remove(node_id):
    """Retire un nœud vide : il quitte le réseau privé. Rien n'est effacé sur la machine elle-même."""
    n = get(node_id)
    if not n or node_id == LOCAL:
        raise ValueError("Nœud inconnu.")
    if db.one("SELECT 1 FROM apps WHERE node = ?", (node_id,)):
        raise ValueError("Ce nœud héberge encore des applis : déplace-les ou supprime-les d'abord.")
    ssh(n, f"systemctl disable --now cloudflared >/dev/null 2>&1; systemctl disable --now wg-quick@{WG_IF} "
           f">/dev/null 2>&1; rm -f /etc/wireguard/{WG_IF}.conf", timeout=20, via_wg=False)
    db.x("DELETE FROM nodes WHERE id = ?", (node_id,))
    db.x("DELETE FROM stats_node WHERE node = ?", (node_id,))
    try:
        apply_mesh()
    except RuntimeError as e:
        P.log("warn", f"nœud {node_id}", str(e))
    P.log("info", f"nœud {node_id}", "nœud retiré (Docker, PostgreSQL et données restent sur la machine)")


# ---------------------------------------------------------------- mesures

PROBE = r"""python3 - <<'EOF'
import json, os, shutil, subprocess, time
def cg():
    # consommation propre de la machine ou du conteneur (cgroup v2) ; en LXC, /proc/stat reflète l'hôte
    try:
        return int([l for l in open('/sys/fs/cgroup/cpu.stat') if l.startswith('usage_usec')][0].split()[1])
    except Exception:
        return None
def cpu():
    v = [int(x) for x in open('/proc/stat').readline().split()[1:9]]
    return sum(v), v[3] + v[4]
c0, a, t0 = cg(), cpu(), time.time(); time.sleep(1); c1, b, t1 = cg(), cpu(), time.time()
m = {l.split(':')[0]: int(l.split()[1]) for l in open('/proc/meminfo')}
du = shutil.disk_usage('/')
def sh(c):
    try: return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception: return ''
print(json.dumps({
  'cpu': round(min(100, (c1 - c0) / ((t1 - t0) * 1e6 * os.cpu_count()) * 100), 1) if c0 is not None and c1 is not None
         else round((1 - (b[1]-a[1]) / max(1, b[0]-a[0])) * 100, 1), 'cores': os.cpu_count(),
  'mem': (m['MemTotal'] - m['MemAvailable']) / 1024, 'mem_total': m['MemTotal'] / 1024,
  'disk': du.used / 1e9, 'disk_total': du.total / 1e9,
  'load': [float(x) for x in open('/proc/loadavg').read().split()[:3]],
  'uptime': float(open('/proc/uptime').read().split()[0]),
  'docker': sh("docker version --format '{{.Server.Version}}'"),
  'containers': int(sh('docker ps -q | wc -l') or 0),
  'pg': sh("docker inspect -f '{{.State.Health.Status}}' platform-postgres-1"),
  'os': sh('. /etc/os-release; echo $PRETTY_NAME')}))
EOF"""


def collect(n):
    """Mesures d'un nœud distant (via le réseau privé). Retourne le dict ou None."""
    t0 = time.time()
    rc, out = ssh(n, PROBE, timeout=25)
    if rc:
        return None
    try:
        info = json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return None
    p = subprocess.run(["ping", "-c1", "-W2", n["wg_ip"]], capture_output=True, text=True)
    m = re.search(r"time=([\d.]+) ms", p.stdout)
    info["latency_ms"] = round(float(m.group(1)), 1) if m else None   # aller-retour par le réseau privé
    _update(n["id"], info=info, last_seen=time.time(), state="ok" if n["state"] in ("ok", "offline") else n["state"])
    db.x("INSERT OR REPLACE INTO stats_node(node, t, cpu, mem, mem_total, disk, disk_total, load1) "
         "VALUES(?, ?, ?, ?, ?, ?, ?, ?)", (n["id"], int(time.time() // 60 * 60), info["cpu"], info["mem"],
                                            info["mem_total"], info["disk"], info["disk_total"], info["load"][0]))
    return info


def check_all():
    """Chaque minute (fil de surveillance) : mesures et disponibilité des nœuds distants."""
    for n in all_nodes():
        if n["id"] == LOCAL or n["state"] not in ("ok", "offline"):
            continue
        info = collect(n)
        if info:
            if _fails.get(n["id"], 0) >= 2:
                P.log("ok", f"nœud {n['id']}", "nœud à nouveau joignable")
                alerts.send(f"Nœud {n['name']} rétabli", "Le nœud répond à nouveau.", priority=3, tags=["white_check_mark"])
            _fails[n["id"]] = 0
            continue
        _fails[n["id"]] = _fails.get(n["id"], 0) + 1
        if _fails[n["id"]] == 2:
            _update(n["id"], state="offline")
            P.log("error", f"nœud {n['id']}", "nœud injoignable depuis 2 minutes")
            alerts.send(f"Nœud {n['name']} injoignable", f"{n['address']} ne répond plus par le réseau privé.",
                        priority=5, tags=["rotating_light"])


def local_info():
    from . import stats
    h = stats.host_now()
    rc, out = P.run(["docker", "ps", "-q"], timeout=10)
    return {**h, "load": h["load"], "containers": len(out.split()), "latency_ms": 0,
            "docker": P.run(["docker", "version", "--format", "{{.Server.Version}}"], timeout=10)[1].strip(),
            "os": open("/etc/os-release").read().split('PRETTY_NAME="')[1].split('"')[0]}


def series(node_id, rng="24h"):
    from . import stats
    if node_id == LOCAL:
        return stats.host_series(rng)
    span, step = stats.RANGES.get(rng, stats.RANGES["24h"])
    now = int(time.time())
    start = (now - span) // step * step + step
    slots = list(range(start, now // step * step + step, step))
    idx = {t: i for i, t in enumerate(slots)}
    out = {k: [None] * len(slots) for k in ("cpu", "mem", "load1")}
    for r in db.q(f"SELECT (t / {step}) * {step} AS s, avg(cpu) cpu, max(mem) mem, avg(load1) load1 FROM stats_node "
                  "WHERE node = ? AND t >= ? GROUP BY s", (node_id, start)):
        i = idx.get(r["s"])
        if i is not None:
            for k in out:
                out[k][i] = round(r[k], 2) if r[k] is not None else None
    out.update(t=slots, step=step, range=rng)
    return out


def purge():
    db.x("DELETE FROM stats_node WHERE t < ?", (time.time() - 8 * 86400,))
