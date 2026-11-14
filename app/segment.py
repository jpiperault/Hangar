"""Cloisonnement des applis : une appli compromise ne doit atteindre ni les autres applis, ni son nœud, ni le réseau
local, ni les autres nœuds.

- Chaque appli a son propre réseau Docker « hangar-<slug> » (interface pont hg-<empreinte>). Son conteneur, et sa base
  dédiée en haute dispo, y sont seuls. Le PostgreSQL partagé du nœud y est branché sous le nom « postgres » seulement
  si l'appli a une base sur lui.
- Table nftables « inet hangarapps », identique sur la console et chaque nœud (/etc/nftables.d/hangar-apps.nft,
  rechargée au démarrage avec le pare-feu de la machine) :
    * aucun trafic d'un réseau d'appli vers un autre, même par un port publié sur l'adresse de l'hôte ;
    * aucun trafic entre un réseau d'appli et les réseaux Docker historiques (docker0, platform) ;
    * vers le réseau privé 10.88.0.0/24 : seulement le port de sa propre base dédiée (haute dispo) ;
    * ports publics réservés à certaines adresses (gameports.sources) : le reste est jeté, en IPv4 après la
      redirection de Docker (port d'origine retrouvé par conntrack), en IPv6 à l'entrée de la machine (Docker y passe
      par son proxy, sans redirection).
  Le reste (réseau local, adresses internes, services de l'hôte) est bloqué par le pare-feu de chaque machine.
"""
import hashlib
import json
import os

from . import db
from . import platform as P

NFT = "/etc/nftables.d/hangar-apps.nft"
PREFIX = "hangar-"


def net_name(slug):
    return f"{PREFIX}{slug}"


def bridge(slug):
    """Nom de l'interface pont (15 caractères au plus)."""
    return "hg-" + hashlib.sha1(slug.encode()).hexdigest()[:10]


def _slugs():
    s = {a["slug"] for a in db.apps()}
    try:
        s |= {h["slug"] for h in db.q("SELECT slug FROM ha")}
    except Exception:
        pass
    return sorted(s)


def _dbports():
    """Ports privés ouverts à une appli seulement : sa base dédiée (haute dispo) et son Redis partagé (instances)."""
    try:
        out = [(r["slug"], int(r["db_port"])) for r in db.q("SELECT slug, db_port FROM ha WHERE db_port IS NOT NULL")]
    except Exception:
        return []
    from . import mysqlrepl, services
    for slug in {s for s, _ in out} | {r["slug"] for r in db.q("SELECT slug FROM ha")}:
        p = services.shared_port(slug)
        if p:
            out.append((slug, p))
        p = mysqlrepl.ports(slug)   # base MySQL/MariaDB principale, pour sa réplique sur le secours
        if p:
            out.append((slug, p))
    return out


def _restrict_rules(node):
    """Règles des ports publics réservés : (lignes de la chaîne forward, lignes de la chaîne input de ce nœud)."""
    from . import gameports
    fwd, inp = [], []
    for slug, where, ports, nets in gameports.restricted():
        v4 = [n for n in nets if ":" not in n]
        v6 = [n for n in nets if ":" in n]
        for proto in ("tcp", "udp"):
            ps = sorted({p["port"] for p in ports if p["proto"] == proto})
            if not ps:
                continue
            pl = "{ " + ", ".join(map(str, ps)) + " }"
            c4 = f"ip saddr != {{ {', '.join(v4)} }} " if v4 else ""
            c6 = f"ip6 saddr != {{ {', '.join(v6)} }} " if v6 else ""
            fwd.append(f'\t\toifname "{bridge(slug)}" ct state new meta nfproto ipv4 meta l4proto {proto} '
                       f"ct original proto-dst {pl} {c4}counter drop")
            fwd.append(f'\t\toifname "{bridge(slug)}" ct state new meta nfproto ipv6 meta l4proto {proto} '
                       f"ct original proto-dst {pl} {c6}counter drop")
            if where == (node or P.LOCAL):
                inp.append(f"\t\tmeta nfproto ipv6 {proto} dport {pl} {c6}counter drop")
    return fwd, inp


def render(node=None):
    br = [bridge(s) for s in _slugs()]
    fwd, inp = _restrict_rules(node)
    dbp = [(bridge(s), p) for s, p in _dbports()]
    wg = "10.88.0.0/24"
    L = ["# Cloisonnement des applis, généré par la console Hangar. Ne pas modifier à la main.",
         "table inet hangarapps", "delete table inet hangarapps", "table inet hangarapps {",
         "\tset same {", "\t\ttypeof iifname . oifname"]
    if br:
        L.append("\t\telements = { " + ", ".join(f'"{b}" . "{b}"' for b in br) + " }")
    L += ["\t}", "\tset dbports {", "\t\ttypeof iifname . tcp dport"]
    if dbp:
        L.append("\t\telements = { " + ", ".join(f'"{b}" . {p}' for b, p in dbp) + " }")
    L += ["\t}", "",
          "\tchain forward {",
          "\t\ttype filter hook forward priority -2; policy accept;",
          "\t\t# d'une appli à une autre : jamais (y compris par un port publié sur l'adresse de l'hôte)",
          "\t\tiifname \"hg-*\" oifname \"hg-*\" iifname . oifname != @same counter drop",
          "\t\tiifname \"hg-*\" oifname { \"docker0\", \"br-*\" } counter drop",
          "\t\tiifname { \"docker0\", \"br-*\" } oifname \"hg-*\" ct state new counter drop",
          "\t\t# réseau privé des nœuds : seulement le port de sa propre base dédiée",
          f"\t\tiifname \"hg-*\" ct state new ip daddr {wg} meta l4proto != tcp counter drop",
          f"\t\tiifname \"hg-*\" ct state new ip daddr {wg} iifname . tcp dport != @dbports counter drop"]
    if fwd:
        L += ["\t\t# ports publics réservés à certaines adresses"] + fwd
    L += ["\t}"]
    if inp:
        L += ["", "\tchain input {", "\t\ttype filter hook input priority -2; policy accept;",
              "\t\t# ports publics réservés, en IPv6 (proxy de Docker sur la machine)"] + inp + ["\t}"]
    L += ["}"]
    return "\n".join(L) + "\n"


def push(node):
    """Écrit et charge la table de cloisonnement sur un nœud (la console : node None ou 'local')."""
    txt = render(node)
    cmd = (f"set -e; install -d /etc/nftables.d; cat > {NFT}.new; nft -c -f {NFT}.new; "
           f"mv {NFT}.new {NFT}; nft -f {NFT}")
    rc, out = P.nsh(node, cmd, timeout=60, input=txt)
    if rc:
        raise RuntimeError(f"cloisonnement des applis sur {node or P.LOCAL} : " + P.tail(out, 2))


def push_all():
    """Sur la console et chaque nœud joignable. Retourne les erreurs."""
    errs = []
    for n in db.q("SELECT id, state FROM nodes"):
        if n["id"] != P.LOCAL and n["state"] != "ok":
            continue
        try:
            push(n["id"])
        except RuntimeError as e:
            errs.append(str(e))
    return errs


def _pg_wanted(slug):
    a = db.app(slug)
    return bool(a and a["db"] and not P.ha_db(slug)[1])


def ensure(node, slug):
    """Réseau de l'appli présent sur le nœud (avant tout « compose up »), PostgreSQL partagé branché ou non."""
    name = net_name(slug)
    rc, _ = P.dk(node, "network", "inspect", name, timeout=30)
    if rc:
        push(node)   # la règle « même réseau » doit exister avant le premier paquet
        rc, out = P.dk(node, "network", "create", "--driver", "bridge",
                       "--opt", f"com.docker.network.bridge.name={bridge(slug)}",
                       "--label", f"fr.hangar.app={slug}", name, timeout=60)
        if rc and "already exists" not in out:
            raise RuntimeError(f"réseau {name} sur {node or P.LOCAL} : " + P.tail(out, 2))
    rc, out = P.dk(node, "inspect", "-f", "{{json .NetworkSettings.Networks}}", P.PG, timeout=30)
    if rc:
        return
    on = name in (json.loads(out or "{}") or {})
    want = _pg_wanted(slug)
    if want and not on:
        rc, out = P.dk(node, "network", "connect", "--alias", "postgres", name, P.PG, timeout=60)
        if rc:
            raise RuntimeError(f"PostgreSQL sur le réseau {name} : " + P.tail(out, 2))
    elif on and not want:
        P.dk(node, "network", "disconnect", "-f", name, P.PG, timeout=60)


def drop(node, slug):
    """Après l'arrêt définitif de l'appli sur ce nœud : réseau retiré (au mieux)."""
    name = net_name(slug)
    P.dk(node, "network", "disconnect", "-f", name, P.PG, timeout=60)
    P.dk(node, "network", "rm", name, timeout=60)


def before_up(node, args, cwd):
    """Appelé par platform.dk avant un « compose up » : prépare les réseaux d'appli que le compose utilise."""
    path = None
    if "-f" in args:
        i = args.index("-f")
        path = args[i + 1] if i + 1 < len(args) else None
    elif cwd:
        path = os.path.join(cwd, "compose.yml")
    if not path or not os.path.exists(path):
        return
    try:
        doc = json.loads("".join(l for l in open(path) if not l.startswith("#")))
    except (OSError, ValueError):
        return
    for name, spec in (doc.get("networks") or {}).items():
        if isinstance(spec, dict) and spec.get("external") and name.startswith(PREFIX):
            ensure(node, name[len(PREFIX):])


# ---------------------------------------------------------------- mise en place sur une installation existante

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "deploy")
NODE_UNIT = """[Unit]
Description=Pare-feu nftables du nœud Hangar
After=network-pre.target
Before=network-online.target docker.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/nftables.d/hangar-node.nft
ExecStart=-/bin/sh -c '[ ! -f /etc/nftables.d/hangar-apps.nft ] || /usr/sbin/nft -f /etc/nftables.d/hangar-apps.nft'
ExecStop=/usr/sbin/nft delete table inet hangarnode
ExecStop=-/usr/sbin/nft delete table inet hangarapps
[Install]
WantedBy=multi-user.target
"""


def prepare_host(node):
    """Pare-feu rechargé au démarrage avec la table de cloisonnement, et plage d'adresses Docker dédiée
    (172.20.0.0/14, jamais celles du réseau local). Docker redémarre si besoin : live-restore garde les conteneurs."""
    if P.is_local(node):
        unit = open(f"{SRC}/systemd/platform-firewall.service").read()
        cmd = "cat > /etc/systemd/system/platform-firewall.service"
    else:
        unit, cmd = NODE_UNIT, "cat > /etc/systemd/system/hangar-node-firewall.service"
    rc, out = P.nsh(node, f"set -e; {cmd}; systemctl daemon-reload", input=unit, timeout=60)
    if rc:
        raise RuntimeError(f"service de pare-feu sur {node} : " + P.tail(out, 2))
    daemon = open(f"{SRC}/docker/daemon.json").read()
    rc, out = P.nsh(node, "set -e; cat > /tmp/hangar-daemon.json; "
                          "if ! cmp -s /tmp/hangar-daemon.json /etc/docker/daemon.json; then "
                          "install -m 0644 /tmp/hangar-daemon.json /etc/docker/daemon.json; systemctl restart docker; "
                          "for i in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 2; done; fi; "
                          "rm -f /tmp/hangar-daemon.json; docker info >/dev/null",
                    input=daemon, timeout=180)
    if rc:
        raise RuntimeError(f"Docker sur {node} : " + P.tail(out, 2))
    push(node)


def _compose_files(slug, main_node):
    d = P.app_dir(slug)
    if os.path.exists(f"{d}/compose.yml"):
        yield f"{d}/compose.yml", main_node
    for e in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        for pre in ("inst-", "db-"):
            if e.startswith(pre) and os.path.exists(f"{d}/{e}/compose.yml"):
                yield f"{d}/{e}/compose.yml", e[len(pre):]


def migrate(log=print):
    """Passe les applis existantes du réseau commun « platform » à leur réseau propre. Chaque conteneur en marche est
    recréé (quelques secondes de coupure par appli)."""
    ok_all = True
    nodes = []
    for n in [r["id"] for r in db.q("SELECT id, state FROM nodes") if r["id"] == P.LOCAL or r["state"] == "ok"]:
        try:
            prepare_host(n)
            nodes.append(n)
            log(f"{n} : pare-feu de cloisonnement et plage d'adresses Docker en place")
        except (RuntimeError, OSError) as e:
            ok_all = False
            log(f"{n} : ÉCHEC, {e}")
    for a in db.apps():
        slug = a["slug"]
        for path, node in _compose_files(slug, a["node"]):
            if node not in nodes:
                log(f"{slug} : {node} injoignable, {path} laissé tel quel")
                ok_all = False
                continue
            head = "".join(l for l in open(path) if l.startswith("#"))
            doc = json.loads("".join(l for l in open(path) if not l.startswith("#")))
            if "platform" not in (doc.get("networks") or {}):
                continue
            net = net_name(slug)
            for svc in doc["services"].values():
                svc["networks"] = [net if x == "platform" else x for x in svc.get("networks", [])]
            doc["networks"] = {net: {"external": True}}
            P.write_private(path, head + json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
            proj = doc["name"]
            rc, ids = P.dk(node, "compose", "-f", path, "-p", proj, "ps", "-q", timeout=60)
            if rc or not ids.strip():
                ensure(node, slug)
                log(f"{slug} : {proj} sur {node} (arrêté) passera par son réseau au prochain démarrage")
                continue
            with P.op_lock:
                rc, out = P.dk(node, "compose", "-f", path, "-p", proj, "up", "-d", "--no-build", timeout=300)
            if rc:
                log(f"{slug} : {proj} sur {node} ÉCHEC : {P.tail(out, 2)}")
                ok_all = False
                P.log("error", slug, f"passage sur son réseau isolé en échec ({node}) : {P.tail(out, 2)}")
                continue
            log(f"{slug} : {proj} sur {node} recréé sur le réseau {net}")
            P.log("ok", slug, f"isolée sur son propre réseau ({node})")
        if a["desired"] == "running":
            ok, detail = P.wait_health(a)
            log(f"{slug} : {'en ligne' if ok else 'HEALTHCHECK EN ÉCHEC : ' + str(detail)}")
    return ok_all
