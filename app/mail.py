"""Messagerie : les enregistrements DNS d'un serveur mail installé dans Hangar (Stalwart, du catalogue).

Réglage kv « mail_dns » : {slug: {"host": "mail.exemple.fr", "domain": "exemple.fr"}}.
- host : nom du serveur (SMTP, IMAP) ; enregistrement A/AAAA vers l'adresse publique de sa machine, jamais proxifié
  (le proxy et le tunnel de Cloudflare ne transportent que le web) ;
- domain : domaine des adresses (x@exemple.fr) : MX → host, SPF « v=spf1 mx -all », DMARC « p=none ».
La clé DKIM est créée par le serveur mail lui-même : à publier depuis son administration.
cloudflare.sync() crée ces enregistrements quand un jeton d'API est enregistré ; sinon la fiche de l'appli les liste
pour une déclaration à la main.
"""
import ipaddress
import re

from . import db

HOST_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
SPF = "v=spf1 mx -all"
DMARC = "v=DMARC1; p=none"


def of(slug):
    return (db.kv_get("mail_dns") or {}).get(slug)


def save(slug, host, domain):
    allv = db.kv_get("mail_dns") or {}
    allv[slug] = {"host": host, "domain": domain}
    db.kv_set("mail_dns", allv)


def forget(slug):
    allv = db.kv_get("mail_dns") or {}
    if allv.pop(slug, None) is not None:
        db.kv_set("mail_dns", allv)


def check(host, domain, slug=None, web_host=None):
    """Erreur (texte) si le nom du serveur ou le domaine ne conviennent pas, sinon None."""
    from . import domains as D
    if not HOST_RE.match(host or ""):
        return "Nom du serveur mail invalide : par exemple mail.exemple.fr."
    if not HOST_RE.match(domain or ""):
        return "Domaine des adresses invalide : par exemple exemple.fr."
    if host == domain:
        return "Le serveur mail a besoin de son propre nom (mail.exemple.fr), distinct du domaine des adresses."
    if host == web_host or any(n["name"] == host for n in D.public_names()):
        return f"{host} est déjà l'adresse web d'une appli : choisis un autre nom pour le serveur mail."
    for other, m in (db.kv_get("mail_dns") or {}).items():
        if other != slug and db.app(other) and m.get("domain") == domain:
            return f"{domain} reçoit déjà son courrier par l'appli {other}."
    return None


def public_ip(slug):
    """Adresse publique de la machine de l'appli, ou None si elle n'en a pas (réseau local, nom DNS)."""
    from . import nodes
    from . import platform as P
    a = db.app(slug)
    if not a:
        return None
    if P.is_local(a["node"]):
        from . import access
        addr = access.current().get("ip") or ""
    else:
        addr = (nodes.get(a["node"]) or {}).get("address") or ""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return None
    return str(ip) if ip.is_global else None


def records(slug):
    """Enregistrements voulus : [{type, name, content, priority?}] ; l'A/AAAA manque si la machine n'a pas d'IP publique."""
    m = of(slug)
    if not m:
        return []
    out = []
    ip = public_ip(slug)
    if ip:
        out.append({"type": "AAAA" if ":" in ip else "A", "name": m["host"], "content": ip})
    out += [{"type": "MX", "name": m["domain"], "content": m["host"], "priority": 10},
            {"type": "TXT", "name": m["domain"], "content": SPF},
            {"type": "TXT", "name": f"_dmarc.{m['domain']}", "content": DMARC}]
    return out


def wanted():
    """Tous les enregistrements de messagerie à tenir, avec l'appli concernée."""
    out = []
    for slug in sorted(db.kv_get("mail_dns") or {}):
        if db.app(slug):
            out += [{**r, "slug": slug} for r in records(slug)]
    return out


def kind_of(r):
    """Famille d'un enregistrement, pour savoir s'il en remplace un autre du même nom."""
    if r["type"] in ("A", "AAAA", "CNAME"):
        return "addr"
    if r["type"] == "MX":
        return "mx"
    c = _txt(r.get("content"))
    if r["type"] == "TXT" and c.lower().startswith("v=spf1"):
        return "spf"
    if r["type"] == "TXT" and c.lower().startswith("v=dmarc1"):
        return "dmarc"
    return None


def _txt(c):
    c = (c or "").strip()
    return c[1:-1] if len(c) >= 2 and c[0] == c[-1] == '"' else c


def same(r, have):
    """Même enregistrement (Cloudflare renvoie les TXT entre guillemets, les noms en minuscules)."""
    if r["type"] != have.get("type"):
        return False
    a, b = r["content"], have.get("content") or ""
    if r["type"] == "TXT":
        return _txt(a) == _txt(b)
    if r["type"] == "MX":
        return a.lower().rstrip(".") == b.lower().rstrip(".") and int(have.get("priority") or 0) == r["priority"]
    return a == b
