"""Ports publics TCP/UDP d'une appli (type « serveur de jeu ») : publiés par Docker sur toutes les adresses de sa
machine, donc joignables sur son adresse publique (pas par le tunnel Cloudflare, qui ne transporte que le web).
Réglage kv « public_ports » : {slug: [{"proto": "tcp", "port": 25565, "cport": 25565}]} (port public, port du conteneur).
Saisie : « tcp 25565 » (même port des deux côtés) ou « tcp 8081:8080 » (public:conteneur).
Sources autorisées (kv « public_ports_from » : {slug: ["203.0.113.4/32", "2001:db8::/48"]}) : si la liste n'est pas
vide, seuls ces réseaux atteignent les ports publics de l'appli (filtré par segment.py, sur la console et les nœuds).
"""
import ipaddress
import re

from . import db

RESERVED = {22, 80, 443, 51820, 2019, 8099, 8443}


def _internal():
    """Ports déjà pris par Hangar sur les machines : Caddy (tunnel), port local de chaque appli, base dédiée
    (+10000) et Redis partagé (+20000)."""
    out = set()
    try:
        out.add(int((db.settings().get("tunnel_bind") or "127.0.0.1:8080").rsplit(":", 1)[1]))
    except (ValueError, IndexError):
        out.add(8080)
    for a in db.apps():
        out |= {a["host_port"], a["host_port"] + 10000, a["host_port"] + 20000}
    return out


def of(slug):
    return (db.kv_get("public_ports") or {}).get(slug) or []


def text(slug):
    return ", ".join(f"{p['proto']} {p['port']}" + (f":{p['cport']}" if p.get("cport", p["port"]) != p["port"] else "")
                     for p in of(slug))


def parse(raw, slug, node):
    """« tcp 25565, udp 19132 » → liste ; ValueError si invalide, réservé, ou déjà pris sur cette machine."""
    out = []
    for item in [x.strip() for x in re.split(r"[,;\n]", raw or "") if x.strip()]:
        m = re.fullmatch(r"(?i)(tcp|udp)?\s*(\d{1,5})(?:\s*:\s*(\d{1,5}))?", item)
        if not m:
            raise ValueError(f"« {item} » : il faut « tcp 25565 », « udp 19132 » ou « tcp 8081:8080 »")
        proto, port = (m.group(1) or "tcp").lower(), int(m.group(2))
        cport = int(m.group(3) or port)
        if not (1 <= port <= 65535 and 1 <= cport <= 65535):
            raise ValueError(f"port {port} hors limites")
        if port in RESERVED or port in _internal():
            raise ValueError(f"port {port} réservé à Hangar (SSH, web, réseau privé, ports internes des applis)")
        if not any(p["proto"] == proto and p["port"] == port for p in out):
            out.append({"proto": proto, "port": port, "cport": cport})
    if len(out) > 20:
        raise ValueError("20 ports au plus")
    for other, ports in (db.kv_get("public_ports") or {}).items():
        a = db.app(other)
        if other == slug or not a or (a["node"] or "local") != (node or "local"):
            continue
        clash = [p for p in out if any(p["proto"] == q["proto"] and p["port"] == q["port"] for q in ports)]
        if clash:
            raise ValueError(f"{clash[0]['proto']} {clash[0]['port']} est déjà ouvert pour {a['name']} sur cette machine")
    return out


def busy(node, ports):
    """Ports demandés déjà écoutés sur la machine, par un programme ou un autre conteneur : ["tcp 25 (master)"].
    Un MTA local (postfix sur 127.0.0.1:25, courant sur Debian) suffit à empêcher Docker de publier 0.0.0.0:25."""
    from . import platform as P
    if not ports:
        return []
    rc, out = P.nsh(node, "ss -Hlntup", timeout=30)
    if rc != 0:
        return []   # machine injoignable : le déploiement dira pourquoi
    seen = {}
    for line in out.splitlines():
        f = line.split()
        if len(f) < 5 or f[0] not in ("tcp", "udp"):
            continue
        try:
            port = int(f[4].rsplit(":", 1)[1])
        except (ValueError, IndexError):
            continue
        m = re.search(r'\(\("([^"]+)"', line)
        seen.setdefault((f[0], port), m.group(1) if m else "?")
    return [f"{p['proto']} {p['port']} ({seen[(p['proto'], p['port'])]})" for p in ports if (p["proto"], p["port"]) in seen]


def save(slug, ports):
    allv = db.kv_get("public_ports") or {}
    if ports:
        allv[slug] = ports
    else:
        allv.pop(slug, None)
    db.kv_set("public_ports", allv)


def compose_ports(slug):
    return [f"{p['port']}:{p.get('cport', p['port'])}/{p['proto']}" for p in of(slug)]


def expected(node):
    """{(conteneur, port)} publiés volontairement sur cette machine (le contrôle de sécurité ne les signale pas)."""
    out = set()
    for slug, ports in (db.kv_get("public_ports") or {}).items():
        a = db.app(slug)
        if a and (a["node"] or "local") == (node or "local"):
            out |= {(f"app-{slug}-app-1", p["port"]) for p in ports}
    return out


def sources(slug):
    return (db.kv_get("public_ports_from") or {}).get(slug) or []


def parse_sources(raw):
    """« 203.0.113.4, 198.51.100.0/24, 2001:db8::/48 » → liste normalisée ; ValueError si invalide."""
    out = []
    for item in [x.strip() for x in re.split(r"[,;\s]+", raw or "") if x.strip()]:
        try:
            n = ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise ValueError(f"« {item[:60]} » : une adresse IP ou un réseau, par exemple 203.0.113.4 ou 198.51.100.0/24")
        if n.prefixlen == 0:
            raise ValueError("0.0.0.0/0 ou ::/0 : laisse le champ vide pour ouvrir à tous")
        if str(n) not in out:
            out.append(str(n))
    if len(out) > 50:
        raise ValueError("50 adresses ou réseaux au plus")
    return out


def save_sources(slug, nets):
    allv = db.kv_get("public_ports_from") or {}
    if (allv.get(slug) or []) == (nets or []):
        return False
    if nets:
        allv[slug] = nets
    else:
        allv.pop(slug, None)
    db.kv_set("public_ports_from", allv)
    return True


def restricted():
    """[(appli, nœud, ports, sources)] des applis dont les ports publics sont réservés à certaines adresses."""
    out = []
    for slug, nets in sorted((db.kv_get("public_ports_from") or {}).items()):
        a, ports = db.app(slug), of(slug)
        if a and nets and ports:
            out.append((slug, a["node"] or "local", ports, nets))
    return out
