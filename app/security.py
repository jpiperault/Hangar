"""Sécurité des nœuds exposés sur Internet, réglée depuis la console.

Une politique générale (kv « security »), que chaque nœud suit ou remplace par la sienne (colonne nodes.security).
La console en déduit, nœud par nœud, les fichiers à poser :
- pare-feu nftables : tout est fermé sauf le réseau privé WireGuard, SSH selon le réglage (ouvert, restreint à des
  adresses, ou fermé), 80/443 seulement sur les machines d'entrée d'un domaine en mode direct, et les ports ajoutés à
  la main ; les adresses privées (10.88.0.x, 127.x) ne sont acceptées que par leurs interfaces ;
- sshd : mots de passe ou clés seulement, root interdit par l'adresse publique (sauf compte d'installation root),
  essais limités ; root reste permis par clé depuis la console sur le réseau privé ;
- fail2ban : bannissement des adresses qui échouent à se connecter en SSH, durée croissante en cas de récidive ;
- mises à jour de sécurité automatiques, redémarrage automatique facultatif ;
- clés SSH d'administration ajoutées au compte d'installation ; réglages réseau du noyau.

Application sans risque : le nœud programme lui-même le retour à l'ancien réglage (RETOUR secondes) avant de
changer quoi que ce soit, puis la console ouvre une nouvelle connexion par le réseau privé et confirme. Si elle ne
passe plus, rien n'est confirmé et l'ancien réglage revient tout seul.
"""
import hashlib
import io
import ipaddress
import json
import re
import shlex
import subprocess
import tarfile
import threading
import time
import urllib.request

from . import alerts, db
from . import domains as D
from . import nodes as N
from . import platform as P

RETOUR = 120
_lock = threading.Lock()
RESERVED = {80, 443, 2019, 5432, 8080, N.WG_PORT}
KEY_RE = re.compile(r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|"
                    r"sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/]+={0,3}( [^\n]{0,200})?$")
EXTRA_RE = re.compile(r"^(tcp|udp)\s+(\d{1,5})(?:-(\d{1,5}))?(?:\s+(?:depuis\s+|from\s+)?(\S+))?$", re.I)

DEFAULT = {
    "ssh_mode": "open",        # open : tout Internet · restricted : seulement ssh_sources · closed : réseau privé seul
    "ssh_sources": [],
    "ssh_port": None,          # None : le port SSH de chaque nœud (celui de son installation)
    "ssh_passwords": True,     # False : clés seulement
    "ssh_root": False,         # root par clé sur l'adresse publique (toujours permis si c'est le compte d'installation)
    "admin_keys": [],
    "f2b": True, "f2b_maxretry": 5, "f2b_findtime": 10, "f2b_bantime": 60, "f2b_increment": True,
    "updates": True, "reboot": "",   # "" : jamais de redémarrage automatique, sinon "HH:MM"
    "extra": [],               # ouvertures supplémentaires : {"proto", "from", "to", "src": [..]}
}


# ---------------------------------------------------------------- politique

def policy():
    p = dict(DEFAULT)
    p.update(db.kv_get("security") or {})
    return p


def node_policy(n):
    """(politique effective du nœud, réglages propres ?). Le port vide devient celui du nœud."""
    own = (n or {}).get("security")
    if own:
        p = dict(DEFAULT)
        p.update(json.loads(own) if isinstance(own, str) else own)
    else:
        p = policy()
    p["ssh_port"] = p.get("ssh_port") or state(n).get("base_port") or (n or {}).get("ssh_port") or 22
    return p, bool(own)


def parse_form(f):
    """Formulaire → (politique, erreurs). Les erreurs portent le nom du champ."""
    e = {}
    p = dict(DEFAULT)
    p["ssh_mode"] = f.get("ssh_mode") if f.get("ssh_mode") in ("open", "restricted", "closed") else "open"
    srcs = []
    for x in re.split(r"[\s,;]+", f.get("ssh_sources") or ""):
        if not x:
            continue
        try:
            net = ipaddress.ip_network(x, strict=False)
            if net.prefixlen < (8 if net.version == 4 else 16):
                e["ssh_sources"] = f"{x} : réseau trop large."
            srcs.append(str(net))
        except ValueError:
            e["ssh_sources"] = f"{x} : adresse ou réseau invalide (par exemple 203.0.113.7 ou 203.0.113.0/24)."
    p["ssh_sources"] = srcs
    if p["ssh_mode"] == "restricted" and not srcs and "ssh_sources" not in e:
        e["ssh_sources"] = "Indique au moins une adresse autorisée, ou choisis un autre mode."
    try:
        p["ssh_port"] = int(f["ssh_port"]) if (f.get("ssh_port") or "").strip() else None
        if p["ssh_port"] is not None and (not 1 <= p["ssh_port"] <= 65535 or p["ssh_port"] in RESERVED):
            raise ValueError
    except ValueError:
        e["ssh_port"] = "Port entre 1 et 65535, hors 80, 443, 2019, 5432, 8080 et 51820, ou vide."
        p["ssh_port"] = None
    p["ssh_passwords"] = f.get("ssh_auth") != "keys"
    p["ssh_root"] = f.get("ssh_root") == "key"
    keys = []
    for line in (f.get("admin_keys") or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not KEY_RE.match(line):
            e["admin_keys"] = f"Clé publique invalide : « {line[:40]}… ». Une ligne par clé, par exemple ssh-ed25519 AAAA… moi@pc."
        keys.append(line)
    p["admin_keys"] = keys
    if not p["ssh_passwords"] and p["ssh_mode"] != "closed" and not keys and not f.get("keys_ok"):
        e["ssh_auth"] = ("Sans mot de passe, ta propre connexion se fait par clé : ajoute ta clé publique ci-dessous, "
                         "ou coche la case si elle est déjà en place sur les nœuds.")
    p["f2b"] = bool(f.get("f2b"))
    for k, lo, hi, label in (("f2b_maxretry", 2, 20, "Essais"), ("f2b_findtime", 1, 1440, "Fenêtre"),
                             ("f2b_bantime", 1, 43200, "Durée")):
        try:
            p[k] = int(f.get(k) or DEFAULT[k])
            if not lo <= p[k] <= hi:
                raise ValueError
        except ValueError:
            e[k] = f"{label} : entre {lo} et {hi}."
            p[k] = DEFAULT[k]
    p["f2b_increment"] = bool(f.get("f2b_increment"))
    p["updates"] = bool(f.get("updates"))
    r = (f.get("reboot") or "").strip()
    if r and not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", r):
        e["reboot"] = "Heure au format HH:MM, ou vide pour ne jamais redémarrer tout seul."
    p["reboot"] = r if f.get("reboot_on") else ""
    extra = []
    for line in (f.get("extra") or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = EXTRA_RE.match(line)
        try:
            if not m:
                raise ValueError
            lo, hi = int(m.group(2)), int(m.group(3) or m.group(2))
            if not 1 <= lo <= hi <= 65535:
                raise ValueError
            src = [str(ipaddress.ip_network(x, strict=False)) for x in (m.group(4) or "").split(",") if x]
            extra.append({"proto": m.group(1).lower(), "from": lo, "to": hi, "src": src})
        except ValueError:
            e["extra"] = f"« {line} » : une ouverture par ligne, par exemple « tcp 25565 » ou « udp 27015-27020 depuis 203.0.113.0/24 »."
    p["extra"] = extra
    return p, e


def to_form(p):
    """Politique (enregistrée, port vide possible) → valeurs de formulaire (textes)."""
    ex = []
    for x in p["extra"]:
        s = f"{x['proto']} {x['from']}" + (f"-{x['to']}" if x["to"] != x["from"] else "")
        ex.append(s + (f" depuis {','.join(x['src'])}" if x["src"] else ""))
    return {**p, "ssh_port": p.get("ssh_port") or "", "ssh_sources": "\n".join(p["ssh_sources"]), "admin_keys": "\n".join(p["admin_keys"]),
            "extra": "\n".join(ex)}


def save_global(p, by):
    db.kv_set("security", p)
    P.log("info", "sécurité", f"politique générale modifiée par {by}")


def own_raw(n):
    """Réglages propres d'un nœud tels qu'enregistrés (port vide possible), ou None."""
    own = (n or {}).get("security")
    if not own:
        return None
    p = dict(DEFAULT)
    p.update(json.loads(own) if isinstance(own, str) else own)
    return p


def save_node(node_id, p, by):
    N._update(node_id, security=json.dumps(p) if p else None)
    P.log("info", f"nœud {node_id}", f"sécurité : {'réglages propres' if p else 'suit la politique générale'} ({by})")


def summary(p):
    """Résumé lisible d'une politique : [(libellé, valeur)]. Port vide : celui de chaque nœud."""
    port = f"port {p['ssh_port']}" if p.get("ssh_port") else "port de chaque nœud"
    src = p["ssh_sources"]
    mode = {"open": "ouvert à tout Internet",
            "restricted": "restreint à " + ", ".join(src[:2]) + (f" (+{len(src) - 2})" if len(src) > 2 else ""),
            "closed": "fermé, réseau privé seulement"}[p["ssh_mode"]]
    if p["f2b"]:
        f2b = (f"{p['f2b_maxretry']} échecs en {p['f2b_findtime']} min → banni {p['f2b_bantime']} min"
               + (", doublé si récidive" if p["f2b_increment"] else ""))
    else:
        f2b = "désactivé"
    if not p["updates"]:
        upd = "automatiques désactivées"
    else:
        upd = "sécurité chaque jour, " + (f"redémarrage auto à {p['reboot']}" if p["reboot"] else "sans redémarrage auto")
    extra = []
    for x in p["extra"]:
        rng = f"{x['from']}" + (f"-{x['to']}" if x["to"] != x["from"] else "")
        extra.append(f"{x['proto']} {rng}" + (" (filtré)" if x["src"] else ""))
    n = len(p["admin_keys"])
    return [("SSH public", f"{mode} · {port}"),
            ("Connexion", ("clés seulement" if not p["ssh_passwords"] else "clés et mots de passe")
             + (", root par clé" if p["ssh_root"] else ", root interdit")),
            ("Clés d'admin", f"{n} clé{'s' if n > 1 else ''}" if n else "aucune"),
            ("Fail2ban", f2b), ("Mises à jour", upd), ("Ports en plus", ", ".join(extra) or "aucun")]


def level(cs):
    """Bilan d'une liste de contrôle : (niveau le plus grave, nombre de points non OK)."""
    bad = [c for c in cs if c["level"] in ("warn", "error")]
    lv = "error" if any(c["level"] == "error" for c in bad) else "warn" if bad else "ok"
    return lv, len(bad)


def reboot(node_id, by):
    n = N.get(node_id)
    if not n or node_id == N.LOCAL or n["state"] != "ok":
        raise ValueError("Nœud injoignable.")
    rc, out = N.ssh(n, "systemd-run --on-active=5 --quiet systemctl reboot", timeout=20)
    if rc:
        raise RuntimeError(P.tail(out, 2))
    N._fails[node_id] = -3    # pas d'alerte « injoignable » pendant le redémarrage (environ 4 min de marge)
    P.log("warn", f"nœud {node_id}", f"redémarrage demandé par {by}")

    def later():
        time.sleep(150)
        collect(node_id)
    P.spawn(later)


# ---------------------------------------------------------------- rendu des fichiers d'un nœud

def web_needed(node_id):
    """Le nœud reçoit-il le trafic web en direct (machine d'entrée d'un domaine en mode direct) ?"""
    return [d["name"] for d in D.all_domains() if d["mode"] == "direct" and (d.get("entry") or N.LOCAL) == node_id]


def _split(nets):
    v4 = [x for x in nets if ipaddress.ip_network(x).version == 4]
    return v4, [x for x in nets if x not in v4]


def render_nft(p, web):
    port = p["ssh_port"]
    L = ["# Pare-feu du nœud Hangar, généré par la console (Sécurité). Ne pas modifier à la main.",
         "# Table dédiée : ne touche ni aux règles de Docker ni à celles de fail2ban.",
         "table inet hangarnode", "delete table inet hangarnode", "table inet hangarnode {",
         "\tcounter refused {}"]
    v4, v6 = _split(p["ssh_sources"]) if p["ssh_mode"] == "restricted" else ([], [])
    if v4:
        L.append(f"\tset ssh4 {{ type ipv4_addr; flags interval; elements = {{ {', '.join(v4)} }} }}")
    if v6:
        L.append(f"\tset ssh6 {{ type ipv6_addr; flags interval; elements = {{ {', '.join(v6)} }} }}")
    if p["ssh_mode"] == "open":
        L += ["\tset flood4 { type ipv4_addr; flags dynamic, timeout; timeout 2m; size 65536; }",
              "\tset flood6 { type ipv6_addr; flags dynamic, timeout; timeout 2m; size 65536; }"]
    L += ["",
          "\tchain pre {",
          "\t\ttype filter hook prerouting priority raw; policy accept;",
          "\t\t# les adresses du réseau privé et de la boucle locale ne s'atteignent que par leurs interfaces",
          f"\t\tiifname != {{ \"lo\", \"{N.WG_IF}\", \"docker0\", \"br-*\" }} fib daddr type local "
          f"ip daddr {{ {N.WG_NET}, 127.0.0.0/8 }} counter drop",
          "\t}", "",
          "\tchain input {",
          "\t\ttype filter hook input priority 0; policy drop;",
          "\t\tiif lo accept",
          "\t\tct state established,related accept",
          "\t\tct state invalid drop",
          "\t\tmeta l4proto { icmp, ipv6-icmp } accept",
          "\t\tiifname { \"docker0\", \"br-*\" } accept",
          "\t\t# réseau privé des nœuds (console et autres nœuds) : de confiance",
          f"\t\tiifname \"{N.WG_IF}\" accept",
          f"\t\tudp dport {N.WG_PORT} accept"]
    if p["ssh_mode"] == "open":
        L += [f"\t\t# SSH ouvert : au-delà de 10 nouvelles connexions par minute, une adresse est freinée",
              f"\t\ttcp dport {port} ct state new add @flood4 {{ ip saddr limit rate over 10/minute burst 10 packets }} drop",
              f"\t\ttcp dport {port} ct state new add @flood6 {{ ip6 saddr limit rate over 10/minute burst 10 packets }} drop",
              f"\t\ttcp dport {port} accept"]
    elif p["ssh_mode"] == "restricted":
        L.append("\t\t# SSH seulement depuis les adresses autorisées")
        if v4:
            L.append(f"\t\tip saddr @ssh4 tcp dport {port} accept")
        if v6:
            L.append(f"\t\tip6 saddr @ssh6 tcp dport {port} accept")
    else:
        L.append("\t\t# SSH fermé sur l'adresse publique : seulement par le réseau privé")
    if web:
        L += [f"\t\t# web direct ({', '.join(web)})", "\t\ttcp dport { 80, 443 } accept", "\t\tudp dport 443 accept"]
    for x in p["extra"]:
        rng = f"{x['from']}" + (f"-{x['to']}" if x["to"] != x["from"] else "")
        s4, s6 = _split(x["src"])
        if not x["src"]:
            L.append(f"\t\t{x['proto']} dport {rng} accept")
        if s4:
            L.append(f"\t\tip saddr {{ {', '.join(s4)} }} {x['proto']} dport {rng} accept")
        if s6:
            L.append(f"\t\tip6 saddr {{ {', '.join(s6)} }} {x['proto']} dport {rng} accept")
    L += ["\t\tcounter name refused", "\t}", "}"]
    return "\n".join(L) + "\n"


def render_sshd(p, n):
    root = p["ssh_root"] or (n.get("ssh_user") or "root") == "root"
    L = ["# Généré par la console Hangar (Sécurité). Ne pas modifier à la main.",
         "# Lu avant sshd_config : ces valeurs l'emportent sur celles de l'hébergeur."]
    if not p["ssh_passwords"]:
        L += ["PasswordAuthentication no", "KbdInteractiveAuthentication no"]
    L += [f"PermitRootLogin {'prohibit-password' if root else 'no'}",
          "PermitEmptyPasswords no", "MaxAuthTries 3", "LoginGraceTime 30", "X11Forwarding no",
          "AllowAgentForwarding no", "ClientAliveInterval 300",
          "# root par clé depuis la console, sur le réseau privé (DOCKER_HOST, maintenance)",
          f"Match Address {N.WG_LOCAL}", "    PermitRootLogin prohibit-password"]
    return "\n".join(L) + "\n"


def render_f2b(p):
    ign = ["127.0.0.1/8", "::1", str(N.WG_NET)] + (p["ssh_sources"] if p["ssh_mode"] == "restricted" else [])
    L = ["# Généré par la console Hangar (Sécurité). Ne pas modifier à la main.", "[DEFAULT]",
         "banaction = nftables", "banaction_allports = nftables[type=allports]",
         f"ignoreip = {' '.join(ign)}", f"bantime = {p['f2b_bantime']}m", f"findtime = {p['f2b_findtime']}m",
         f"maxretry = {p['f2b_maxretry']}"]
    if p["f2b_increment"]:
        L += ["bantime.increment = true", "bantime.factor = 2", "bantime.maxtime = 4w"]
    L += ["", "[sshd]", f"enabled = {'true' if p['f2b'] else 'false'}", "backend = systemd",
          # Debian 13 : SSH lancé par socket, journal sous ssh.service ou sshd-session
          "journalmatch = _COMM=sshd + _COMM=sshd-session", f"port = {p['ssh_port']}", "mode = normal"]
    return "\n".join(L) + "\n"


def render_apt(p):
    L = ["// Généré par la console Hangar (Sécurité). Lu après 20auto-upgrades et 52platform-unattended.",
         f'APT::Periodic::Update-Package-Lists "1";',
         f'APT::Periodic::Unattended-Upgrade "{1 if p["updates"] else 0}";']
    if p["reboot"]:
        L += ['Unattended-Upgrade::Automatic-Reboot "true";', f'Unattended-Upgrade::Automatic-Reboot-Time "{p["reboot"]}";']
    else:
        L.append('Unattended-Upgrade::Automatic-Reboot "false";')
    return "\n".join(L) + "\n"


SYSCTL = """# Généré par la console Hangar (Sécurité) : réglages réseau prudents pour une machine exposée
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.icmp_echo_ignore_broadcasts = 1
kernel.dmesg_restrict = 1
"""


def render(n):
    """Fichiers du nœud {nom: contenu} et paramètres du script, d'après sa politique."""
    p, own = node_policy(n)
    files = {"hangar-node.nft": render_nft(p, web_needed(n["id"])), "sshd.conf": render_sshd(p, n),
             "jail.local": render_f2b(p), "apt.conf": render_apt(p), "sysctl.conf": SYSCTL,
             "admin_keys": "".join(k + "\n" for k in p["admin_keys"])}
    env = {"SSH_PORT": str(p["ssh_port"]), "F2B": "1" if p["f2b"] else "0", "ADMIN_USER": n.get("ssh_user") or "root"}
    return files, env, p, own


def digest(files, env):
    h = hashlib.sha256()
    for k in sorted(files):
        h.update(k.encode() + b"\0" + files[k].encode() + b"\0")
    h.update(json.dumps(env, sort_keys=True).encode())
    return h.hexdigest()[:16]


def state(n):
    n = n or {}
    return json.loads(n.get("sec") or "{}") if isinstance(n.get("sec"), str) else (n.get("sec") or {})


def _set_state(node_id, **kw):
    st = state(N.get(node_id))
    st.update(kw)
    N._update(node_id, sec=json.dumps(st))
    return st


# ---------------------------------------------------------------- application

def _fresh_ssh(n, cmd, timeout=15):
    """Nouvelle connexion par le réseau privé (sans la connexion partagée) : prouve que l'accès tient encore."""
    try:
        p = subprocess.run(["ssh", "-F", N.SSH_CONF, "-o", "ControlMaster=no", "-o", "ControlPath=none",
                            f"root@{n['wg_ip']}", cmd], capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return 124, "délai dépassé"


def apply(node_id, by="console"):
    """Applique la politique au nœud. Retourne (ok, message). Un nœud à la fois."""
    n = N.get(node_id)
    if not n or node_id == N.LOCAL:
        raise ValueError("Nœud inconnu.")
    _set_state(node_id, applying=time.time())
    try:
        with _lock:
            return _apply(node_id, by)
    finally:
        _set_state(node_id, applying=None)


def applying(n):
    t = state(n).get("applying")
    return bool(t and time.time() - t < 1200)


def _apply(node_id, by):
    n = N.get(node_id)
    if not n or node_id == N.LOCAL:
        raise ValueError("Nœud inconnu.")
    if n["state"] not in ("ok", "installing") or not N._wg_alive(n):
        msg = "nœud injoignable par le réseau privé : réglage appliqué à son retour (Appliquer)"
        _set_state(node_id, error=msg, ts=time.time())
        return False, msg
    files, env, p, own = render(n)
    want = digest(files, env)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, src in (("apply.sh", f"{N.SRC}/node/security-apply.sh"), ("revert.sh", f"{N.SRC}/node/security-revert.sh")):
            tar.add(src, arcname=name)
        for name, body in list(files.items()) + [("env", "".join(f"{k}={shlex.quote(v)}\n" for k, v in env.items()))]:
            data = body.encode()
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode = len(data), 0o600
            tar.addfile(ti, io.BytesIO(data))
    P.log("info", f"nœud {node_id}", f"sécurité : application en cours ({by})")
    rc, out = N.ssh(n, "rm -rf /opt/hangar-node/sec && mkdir -p -m 700 /opt/hangar-node/sec && "
                       "tar -C /opt/hangar-node/sec -xf - && "
                       "systemctl reset-failed hangar-sec-apply >/dev/null 2>&1; "
                       "systemd-run --unit=hangar-sec-apply --collect --quiet "
                       "bash -c 'bash /opt/hangar-node/sec/apply.sh > /opt/hangar-node/sec/apply.log 2>&1'",
                    input=buf.getvalue(), timeout=60)
    if rc:
        return _fail(n, "envoi impossible : " + P.tail(out, 2))
    # le script tourne sur le nœud, détaché : une coupure de la connexion ne l'interrompt pas
    vals, deadline = {}, time.time() + 900
    while time.time() < deadline:
        time.sleep(3)
        rc, out = _fresh_ssh(n, "cat /opt/hangar-node/sec/apply.log 2>/dev/null; echo; "
                                "echo HANGAR_UNIT=$(systemctl is-active hangar-sec-apply 2>/dev/null)", timeout=20)
        if rc:
            # plus d'accès par le réseau privé : le nœud remettra l'ancien réglage tout seul
            time.sleep(5)
            rc, out = _fresh_ssh(n, "true")
            if rc:
                return _fail(n, f"le nœud ne répond plus après le changement : il remet l'ancien réglage de lui-même "
                                f"dans {RETOUR // 60} min au plus")
            continue
        vals = dict(re.findall(r"^HANGAR_([A-Z_]+)=(.*)$", out, re.M))
        if vals.get("DONE") == "1" or vals.get("ERROR") or vals.get("UNIT") not in ("active", "activating"):
            break
    if vals.get("DONE") != "1":
        return _fail(n, vals.get("ERROR") or f"étape « {vals.get('STEP', '?')} » en échec, ancien réglage remis")
    # nouvelle connexion, comme la console en ouvrira ensuite : si elle passe, on confirme
    for _ in range(3):
        rc, out = _fresh_ssh(n, "systemctl stop hangar-sec-retour.timer 2>/dev/null; rm -rf /var/lib/hangar-sec/prev; "
                                "echo HANGAR_OK=1")
        if "HANGAR_OK=1" in out:
            break
        time.sleep(3)
    else:
        return _fail(n, "nouvelle connexion refusée après le changement : ancien réglage remis par le nœud")
    if n["ssh_port"] != p["ssh_port"]:
        if not state(n).get("base_port"):
            _set_state(node_id, base_port=n["ssh_port"])   # port d'installation : celui d'un port laissé vide
        N._update(node_id, ssh_port=p["ssh_port"])
    warn = vals.get("WARN")
    _set_state(node_id, applied=want, ts=time.time(), error=None, warn=warn or None, by=by)
    P.log("ok", f"nœud {node_id}", "sécurité appliquée" + (f" ({'réglages propres' if own else 'politique générale'})")
          + (f" : {warn}" if warn else ""))
    P.spawn(collect, node_id)
    return True, "Sécurité appliquée" + (f" : {warn}" if warn else ".")


def _fail(n, msg):
    _set_state(n["id"], error=msg[:400], ts=time.time())
    P.log("error", f"nœud {n['id']}", f"sécurité : {msg}")
    return False, msg


def apply_all(by="console"):
    res = {}
    for n in N.all_nodes():
        if n["id"] != N.LOCAL and n["state"] in ("ok", "offline"):
            res[n["id"]] = apply(n["id"], by)
    return res


def pending(n):
    """La politique voulue diffère-t-elle de celle appliquée ?"""
    files, env, _, _ = render(n)
    return state(n).get("applied") != digest(files, env)


def reconcile():
    """Après un changement de routage (machine d'entrée d'un domaine direct…) : réapplique là où le pare-feu doit
    changer. Seulement sur les nœuds dont la sécurité est déjà gérée par la console."""
    for n in N.all_nodes():
        if n["id"] != N.LOCAL and n["state"] == "ok" and state(n).get("applied") and pending(n):
            try:
                apply(n["id"], "routage")
            except Exception as e:
                P.log("error", f"nœud {n['id']}", f"sécurité : {e}")


# ---------------------------------------------------------------- état observé

PROBE = r"""python3 - "$1" <<'EOF'
import json, os, re, subprocess, sys, time
user = sys.argv[1]
def sh(c, t=20):
    try: return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t).stdout
    except Exception: return ''
o = {}
o['nft'] = 'table inet hangarnode' in sh('nft list tables')
m = re.search(r'packets (\d+)', sh('nft list counter inet hangarnode refused'))
o['refused'] = int(m.group(1)) if m else None
t = sh(f'install -d -m 0755 /run/sshd; sshd -T -C user={user},host=x,addr=203.0.113.9')
cfg = dict(l.split(' ', 1) for l in t.splitlines() if ' ' in l)
o['ssh'] = {k: cfg.get(k) for k in ('passwordauthentication', 'kbdinteractiveauthentication', 'permitrootlogin', 'maxauthtries')}
o['ssh_ports'] = sorted({int(l.split()[1]) for l in t.splitlines() if l.startswith('port ')})
o['f2b'] = sh('systemctl is-active fail2ban').strip()
s = sh('fail2ban-client status sshd 2>/dev/null')
g = lambda k: (re.search(k + r':\s*(.*)', s) or [None, ''])[1].strip()
o['banned'] = g('Banned IP list').split() if s else []
o['failed_total'] = int(g('Total failed') or 0) if s else None
o['banned_total'] = int(g('Total banned') or 0) if s else None
up = sh('apt list --upgradable 2>/dev/null', 60).splitlines()[1:]
o['upgradable'] = len(up)
o['security_updates'] = sum('-security' in l for l in up)
o['reboot'] = os.path.exists('/var/run/reboot-required')
try: o['uu_last'] = os.path.getmtime('/var/log/unattended-upgrades/unattended-upgrades.log')
except OSError: o['uu_last'] = None
listen = []
for l in sh('ss -Hltnup').splitlines():
    p = l.split()
    if len(p) < 5: continue
    addr = p[4].rsplit(':', 1)[0].strip('[]')
    if addr.startswith('127.') or addr in ('::1',) or addr.startswith('10.88.0.') or '%lo' in addr: continue
    proc = (re.search(r'\(\("([^"]+)"', l) or [None, '?'])[1]
    listen.append({'proto': p[0], 'port': int(p[4].rsplit(':', 1)[1]), 'proc': proc})
o['listen'] = sorted({(x['proto'], x['port'], x['proc']) for x in listen})
pub = []
for l in sh("docker ps --format '{{.Names}} {{.Ports}}'").splitlines():
    name, _, ports = l.partition(' ')
    for x in re.findall(r'(0\.0\.0\.0|\[::\]|::):(\d+)->', ports):
        pub.append(f'{name}:{x[1]}')
o['docker_public'] = sorted(set(pub))
o['ts'] = time.time()
print(json.dumps(o))
EOF"""


def collect(node_id):
    n = N.get(node_id)
    if not n or n["state"] not in ("ok",):
        return None
    rc, out = N.ssh(n, f"bash -s {shlex.quote(n.get('ssh_user') or 'root')}", input=PROBE, timeout=90)
    try:
        obs = json.loads(out.strip().splitlines()[-1]) if rc == 0 else None
    except (ValueError, IndexError):
        obs = None
    if obs is None:
        return None
    before = {c["key"] for c in checks(n, obs) if c["level"] == "error"}
    _set_state(node_id, obs=obs)
    after = [c for c in checks(N.get(node_id), obs) if c["level"] == "error" and c["key"] not in before]
    for c in after:
        if c["key"] in ("nft", "docker"):
            alerts.send(f"Sécurité du nœud {n['name']}", c["msg"], priority=4, tags=["warning"])
    return obs


def collect_all():
    for n in N.all_nodes():
        if n["id"] != N.LOCAL and n["state"] == "ok":
            try:
                collect(n["id"])
            except Exception as e:
                P.log("warn", f"nœud {n['id']}", f"état de sécurité illisible : {e}")


def checks(n, obs=None):
    """Points de contrôle d'un nœud : [{key, level ok|warn|error|info, label, msg}]."""
    st = state(n)
    obs = obs if obs is not None else st.get("obs")
    p, own = node_policy(n)
    out = []

    def add(key, level, label, msg):
        out.append({"key": key, "level": level, "label": label, "msg": msg})

    if not st.get("applied"):
        add("applied", "warn", "Politique", "jamais appliquée par la console : clique sur Appliquer")
    elif pending(n):
        add("applied", "warn", "Politique", "modifiée depuis la dernière application : clique sur Appliquer")
    elif st.get("error"):
        add("applied", "error", "Politique", st["error"])
    else:
        add("applied", "ok", "Politique", f"appliquée {('(réglages propres)' if own else '(politique générale)')}")
    if not obs:
        add("obs", "info", "État", "pas encore relevé")
        return out
    add("nft", "ok" if obs.get("nft") else "error", "Pare-feu",
        (f"actif, {obs['refused']} paquets refusés" if obs.get("refused") is not None else "actif") if obs.get("nft")
        else "table hangarnode absente : la machine est ouverte")
    mode = {"open": "ouvert à tout Internet (freiné, fail2ban)", "restricted": f"restreint à {', '.join(p['ssh_sources'])}",
            "closed": "fermé (réseau privé seulement)"}[p["ssh_mode"]]
    add("ssh_mode", "warn" if p["ssh_mode"] == "open" and p["ssh_passwords"] else "ok",
        "SSH public", f"{mode}, port {p['ssh_port']}")
    s = obs.get("ssh") or {}
    pw = s.get("passwordauthentication") == "yes" or s.get("kbdinteractiveauthentication") == "yes"
    if p["ssh_mode"] != "closed":
        add("ssh_pw", "warn" if pw else "ok", "Mots de passe SSH",
            "acceptés : préfère les clés seulement" if pw else "refusés, clés seulement")
    root = s.get("permitrootlogin")
    add("ssh_root", "warn" if root == "yes" else "ok", "Root par l'adresse publique",
        {"yes": "permis avec mot de passe", "no": "interdit", "prohibit-password": "par clé seulement",
         "without-password": "par clé seulement"}.get(root, root or "?"))
    if p["f2b"]:
        ok = obs.get("f2b") == "active"
        add("f2b", "ok" if ok else "error", "Anti-force brute",
            f"{len(obs.get('banned') or [])} adresse(s) bannie(s), {obs.get('banned_total') or 0} bannissement(s), "
            f"{obs.get('failed_total') or 0} échec(s) depuis le démarrage" if ok else "fail2ban arrêté")
    elif p["ssh_mode"] == "open":
        add("f2b", "warn", "Anti-force brute", "désactivé alors que SSH est ouvert à tout Internet")
    sec = obs.get("security_updates") or 0
    add("updates", "warn" if sec or not p["updates"] else "ok", "Mises à jour",
        (f"{sec} de sécurité en attente" if sec else "système à jour") + f", {obs.get('upgradable', 0)} au total"
        + ("" if p["updates"] else " ; mises à jour automatiques désactivées"))
    if obs.get("reboot"):
        add("reboot", "warn", "Redémarrage", "requis pour finir une mise à jour (noyau…)" +
            (f" : prévu à {p['reboot']}" if p["reboot"] else ""))
    if obs.get("docker_public"):
        add("docker", "error", "Docker", "ports publiés sur toutes les adresses, hors pare-feu : " + ", ".join(obs["docker_public"]))
    allowed = {p["ssh_port"]} if p["ssh_mode"] != "closed" else set()
    allowed |= {80, 443} if web_needed(n["id"]) else set()
    for x in p["extra"]:
        allowed |= set(range(x["from"], x["to"] + 1))
    hidden = [f"{x[0]} {x[1]} ({x[2]})" for x in obs.get("listen") or []
              if x[1] not in allowed and x[1] != N.WG_PORT and x[0] == "tcp"]
    if hidden:
        add("listen", "info", "Services bloqués", "écoutent sur toutes les adresses mais le pare-feu les ferme : "
            + ", ".join(hidden[:8]))
    return out


def unban(node_id, ip):
    ipaddress.ip_address(ip)
    n = N.get(node_id)
    rc, out = N.ssh(n, f"fail2ban-client set sshd unbanip {shlex.quote(ip)}", timeout=30)
    if rc:
        raise RuntimeError(P.tail(out, 2))
    P.log("info", f"nœud {node_id}", f"adresse {ip} débannie")
    P.spawn(collect, node_id)


def public_ip():
    """Adresse publique de la console vue d'Internet (pour l'autoriser en SSH)."""
    try:
        with urllib.request.urlopen("https://cloudflare.com/cdn-cgi/trace", timeout=8) as r:
            m = re.search(r"^ip=(\S+)$", r.read().decode(), re.M)
            return m.group(1) if m else None
    except OSError:
        return None
