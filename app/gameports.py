"""Ports publics TCP/UDP d'une appli (type « serveur de jeu ») : publiés par Docker sur toutes les adresses de sa
machine, donc joignables sur son adresse publique (pas par le tunnel Cloudflare, qui ne transporte que le web).
Réglage kv « public_ports » : {slug: [{"proto": "tcp", "port": 25565, "cport": 25565}]} (port public, port du conteneur).
Saisie : « tcp 25565 » (même port des deux côtés) ou « tcp 8081:8080 » (public:conteneur).
"""
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
