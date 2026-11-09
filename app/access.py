"""Accès à la console : adresse d'écoute, port et réseaux autorisés, réglables depuis la console elle-même.

Un changement s'applique tout de suite (pare-feu, certificat si l'adresse change, redémarrage de la console) et revient
tout seul à l'ancien réglage au bout de DELAY secondes, sauf s'il est confirmé depuis la nouvelle adresse. Une erreur
de saisie ne peut donc pas fermer la console pour de bon.
"""
import ipaddress
import os
import re
import shutil
import time

from . import db
from . import platform as P

ENV = "/srv/platform/.env"
NFT = "/etc/nftables.d/platform.nft"
TLS = "/srv/platform/tls"
PREV = "/srv/platform/access.prev"
UNIT = "hangar-acces-retour"
DELAY = 180
# ports déjà pris par la plateforme ou ses services
TAKEN = {22, 80, 443, 2019, 5432, 8080, 51820}


def _env():
    out = {}
    try:
        for line in open(ENV).read().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def parse_nets(text):
    nets = []
    for x in re.split(r"[\s,;]+", text or ""):
        if x:
            nets.append(ipaddress.ip_network(x, strict=False))
    return nets


def current():
    e = _env()
    ip, port = (e.get("ADMIN_BIND") or "127.0.0.1:8443").rsplit(":", 1)
    return {"ip": ip, "port": int(port), "nets": [str(n) for n in parse_nets(e.get("LAN_CIDR", ""))]}


def local_ips():
    rc, out = P.run(["ip", "-4", "-o", "addr"], timeout=10)
    res = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and not re.match(r"^(lo|docker\d*|br-|veth|wg-)", parts[1]):
            res.append({"ip": parts[3].split("/")[0], "iface": parts[1], "net": str(ipaddress.ip_network(parts[3], strict=False))})
    return res


def validate(ip, port, nets_text, client_ip):
    e = {}
    if ip not in {x["ip"] for x in local_ips()}:
        e["ip"] = "Choisis une adresse de cette machine."
    try:
        port = int(port)
        if not 1024 <= port <= 65535 or port in TAKEN:
            raise ValueError
        if port != current()["port"]:
            rc, out = P.run(["ss", "-Hltn", f"sport = :{port}"], timeout=10)
            if out.strip():
                e["port"] = f"Le port {port} est déjà utilisé sur cette machine."
        if port >= P.HOST_PORT_MIN and port < P.HOST_PORT_MIN + 1000:
            e["port"] = f"Les ports à partir de {P.HOST_PORT_MIN} sont réservés aux applis."
    except (TypeError, ValueError):
        e["port"] = "Port entre 1024 et 65535, hors 2019, 5432, 8080 et 51820."
    try:
        nets = parse_nets(nets_text)
        if not nets:
            raise ValueError("vide")
        if any(n.version != 4 for n in nets):
            e["nets"] = "Réseaux IPv4 seulement, par exemple 192.168.1.0/24."
        elif any(n.prefixlen < 8 for n in nets):
            e["nets"] = "Réseau trop large (au moins /8)."
        elif any(not n.is_private for n in nets):
            e["nets"] = "Réseaux privés seulement : la console ne doit jamais être ouverte sur Internet."
        elif client_ip and not any(ipaddress.ip_address(client_ip) in n for n in nets):
            e["nets"] = f"Ton adresse actuelle ({client_ip}) n'est pas dans ces réseaux : tu perdrais l'accès."
    except ValueError:
        e["nets"] = "Un réseau par ligne, par exemple 192.168.1.0/24."
        nets = []
    return e, {"ip": ip, "port": port, "nets": [str(n) for n in nets]}


def render_nft(text, nets, port):
    text = re.sub(r"(set lan \{[^}]*elements = \{)[^}]*(\})", lambda m: f"{m.group(1)} {', '.join(nets)} {m.group(2)}", text)
    return re.sub(r"(ip saddr @lan tcp dport \{ 22, )\d+( \})", lambda m: f"{m.group(1)}{port}{m.group(2)}", text)


def _write_env(updates):
    lines = open(ENV).read().splitlines()
    seen = set()
    for i, line in enumerate(lines):
        k = line.split("=", 1)[0].strip()
        if k in updates:
            lines[i] = f"{k}={updates[k]}"
            seen.add(k)
    lines += [f"{k}={v}" for k, v in updates.items() if k not in seen]
    tmp = ENV + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(lines) + "\n")
    shutil.copymode(ENV, tmp)
    st = os.stat(ENV)
    os.chown(tmp, st.st_uid, st.st_gid)
    os.replace(tmp, ENV)


def pending():
    p = db.kv_get("access_pending")
    if not p:
        return None
    rc, out = P.run(["systemctl", "is-active", f"{UNIT}.timer"], timeout=10)
    if out.strip() != "active":
        return None
    p["left"] = max(0, int(p["deadline"] - time.time()))
    return p


def apply(new, by):
    """Applique le nouveau réglage et programme le retour automatique. La console redémarre 2 s plus tard."""
    old = current()
    if pending():
        raise ValueError("Un changement attend déjà sa confirmation.")
    shutil.rmtree(PREV, ignore_errors=True)
    os.makedirs(PREV, mode=0o700)
    for f in (ENV, NFT, f"{TLS}/hangar.crt", f"{TLS}/hangar.key"):
        if os.path.exists(f):
            shutil.copy2(f, f"{PREV}/{os.path.basename(f)}")
    nft = render_nft(open(NFT).read(), new["nets"], new["port"])
    tmp = NFT + ".new"
    with open(tmp, "w") as f:
        f.write(nft)
    rc, out = P.run(["nft", "-c", "-f", tmp], timeout=20)
    if rc:
        os.remove(tmp)
        raise RuntimeError("règles de pare-feu refusées : " + P.tail(out, 2))
    os.replace(tmp, NFT)
    rc, out = P.run(["nft", "-f", NFT], timeout=20)
    if rc:
        shutil.copy2(f"{PREV}/platform.nft", NFT)
        P.run(["nft", "-f", NFT], timeout=20)
        raise RuntimeError("pare-feu non appliqué : " + P.tail(out, 2))
    if new["ip"] != old["ip"]:
        P.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
               "-days", "3650", "-subj", "/CN=Hangar", "-addext", f"subjectAltName=IP:{new['ip']}",
               "-keyout", f"{TLS}/hangar.key", "-out", f"{TLS}/hangar.crt"], timeout=30)
        os.chmod(f"{TLS}/hangar.key", 0o600)
    _write_env({"ADMIN_BIND": f"{new['ip']}:{new['port']}", "LAN_CIDR": ",".join(new["nets"])})
    P.run(["systemctl", "reset-failed", f"{UNIT}.timer", f"{UNIT}.service"], timeout=10)
    rc, out = P.run(["systemd-run", f"--unit={UNIT}", f"--on-active={DELAY}", "--timer-property=AccuracySec=1s",
                     "/usr/local/bin/hangar", "access-revert"], timeout=20)
    if rc:
        revert(restart=False)
        raise RuntimeError("retour automatique impossible à programmer, rien n'est changé : " + P.tail(out, 2))
    url = f"https://{new['ip']}:{new['port']}/"
    db.kv_set("access_pending", {"old": old, "new": new, "url": url, "deadline": time.time() + DELAY, "by": by})
    P.log("warn", "console", f"accès changé par {by} : {url}, réseaux {', '.join(new['nets'])}. Retour à l'ancien "
                             f"réglage dans {DELAY // 60} min sans confirmation.")
    P.run(["systemd-run", "--on-active=2", "systemctl", "restart", "hangar"], timeout=20)
    return url


def confirm(by):
    P.run(["systemctl", "stop", f"{UNIT}.timer"], timeout=20)
    shutil.rmtree(PREV, ignore_errors=True)
    p = db.kv_get("access_pending") or {}
    db.kv_set("access_pending", None)
    P.log("ok", "console", f"nouvel accès confirmé par {by} : {p.get('url', '?')}")


def revert(restart=True):
    """Remet l'ancien réglage (appelé par le minuteur, ou en cas d'échec). Redémarre la console."""
    if not os.path.isdir(PREV):
        return False
    for name, dest in (("platform.nft", NFT), (".env", ENV), ("hangar.crt", f"{TLS}/hangar.crt"),
                       ("hangar.key", f"{TLS}/hangar.key")):
        if os.path.exists(f"{PREV}/{name}"):
            shutil.copy2(f"{PREV}/{name}", dest)
    P.run(["nft", "-f", NFT], timeout=20)
    shutil.rmtree(PREV, ignore_errors=True)
    db.kv_set("access_pending", None)
    P.run(["systemctl", "stop", f"{UNIT}.timer"], timeout=20)
    P.log("warn", "console", "nouvel accès non confirmé : ancien réglage remis")
    if restart:
        P.run(["systemctl", "restart", "hangar"], timeout=60)
    return True
