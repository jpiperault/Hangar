"""Messagerie : les enregistrements DNS d'un serveur mail installé dans Hangar (Stalwart, du catalogue).

Réglage kv « mail_dns » : {slug: {"host": "mail.exemple.fr", "domain": "exemple.fr"}}.
- host : nom du serveur (SMTP, IMAP) ; enregistrement A/AAAA vers l'adresse publique de sa machine, jamais proxifié
  (le proxy et le tunnel de Cloudflare ne transportent que le web) ;
- domain : domaine des adresses (x@exemple.fr) : MX → host, SPF « v=spf1 mx -all », DMARC « p=none ».
La clé DKIM est créée par le serveur mail lui-même : à publier depuis son administration.
cloudflare.sync() crée ces enregistrements quand un jeton d'API est enregistré ; sinon la fiche de l'appli les liste
pour une déclaration à la main.

Stalwart (catalogue) démarre en mode « premier démarrage » : seul un assistant web en HTTP simple répond, et il refuse
l'interface servie en HTTPS par Hangar. setup() fait cet assistant par l'API (JMAP x:Bootstrap) depuis la console, par
le réseau privé : nom du serveur, domaine, RocksDB, journaux sur la console, clés DKIM ; avec un jeton Cloudflare donné
à l'installation, Stalwart gère aussi son certificat (DNS-01) et ses enregistrements (DKIM, DMARC, SRV…), et Hangar ne
tient plus que l'A, le MX et le SPF (« stalwart_dns »). Le compte admin permanent qu'il crée est gardé dans kv
« mail_admin » jusqu'à ce qu'un admin l'oublie ; la variable du compte temporaire est retirée, puis l'appli redémarre.
"""
import base64
import ipaddress
import json
import re
import time
import urllib.error
import urllib.request

from . import db

RECOVERY = "STALWART_RECOVERY_ADMIN"

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
    for key in ("mail_dns", "mail_admin"):
        allv = db.kv_get(key) or {}
        if allv.pop(slug, None) is not None:
            db.kv_set(key, allv)


def _set_flag(slug, **kv):
    allv = db.kv_get("mail_dns") or {}
    if slug in allv:
        allv[slug].update(kv)
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
            {"type": "TXT", "name": m["domain"], "content": SPF}]
    if not m.get("stalwart_dns"):   # sinon Stalwart publie lui-même DMARC, DKIM, SRV…
        out.append({"type": "TXT", "name": f"_dmarc.{m['domain']}", "content": DMARC})
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


# ---------------------------------------------------------------- Stalwart : configuration par l'API

def admin_of(slug):
    return (db.kv_get("mail_admin") or {}).get(slug)


def forget_admin(slug):
    allv = db.kv_get("mail_admin") or {}
    if allv.pop(slug, None) is not None:
        db.kv_set("mail_admin", allv)


def needs_setup(slug):
    """Appli Stalwart du catalogue encore en mode « premier démarrage » (variable du compte temporaire présente)."""
    from . import platform as P
    a, m = db.app(slug), of(slug)
    if not a or not m or m.get("setup"):
        return False
    env, _ = P.parse_env(a["env"])
    return bool(env.get(RECOVERY))


def _base(a):
    from . import platform as P
    host = "127.0.0.1" if P.is_local(a["node"]) else P.node_wg(a["node"])
    return f"http://{host}:{a['host_port']}"


def _call(base, cred, path, body=None, timeout=30):
    req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "Basic " + base64.b64encode(cred.encode()).decode(),
                                          "Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise RuntimeError("Stalwart refuse le compte temporaire (déjà configuré, ou variable modifiée)")
        raise RuntimeError(f"Stalwart répond HTTP {e.code} sur {path}")
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise RuntimeError(f"Stalwart injoignable ({e})")


def bootstrap_body(host, domain, cf_token=""):
    """Réponses de l'assistant de Stalwart (objet x:Bootstrap)."""
    body = {"defaultHostname": host, "defaultDomain": domain, "generateDkimKeys": True,
            "requestTlsCertificate": bool(cf_token),   # sans DNS automatique : ACME par le port 443, pris par Caddy
            "tracer": {"@type": "Stdout", "ansi": False, "enable": True, "level": "info", "multiline": False,
                       "lossy": False, "buffered": True, "events": {}, "eventsPolicy": "exclude"},
            "dnsServer": {"@type": "Manual"}}
    if cf_token:
        body["dnsServer"] = {"@type": "Cloudflare", "description": "Cloudflare (Hangar)",
                             "secret": {"@type": "Value", "secret": cf_token}}
    return body


def setup(slug, cf_token="", by="hangar"):
    """Fait l'assistant de Stalwart par son API, puis retire le compte temporaire et redémarre l'appli."""
    from . import platform as P
    a, m = db.app(slug), of(slug)
    if not a or not m:
        return
    env, _ = P.parse_env(a["env"])
    cred = env.get(RECOVERY)
    try:
        if not cred:
            raise RuntimeError(f"variable {RECOVERY} absente : configure Stalwart depuis son interface")
        base = _base(a)
        sess = _call(base, cred, "/jmap/session")
        acct = (sess.get("primaryAccounts") or {}).get("urn:stalwart:jmap")
        if not acct:
            raise RuntimeError("API d'administration de Stalwart introuvable")
        req = {"using": ["urn:ietf:params:jmap:core", "urn:stalwart:jmap"],
               "methodCalls": [["x:Bootstrap/set", {"accountId": acct, "update": {
                   "singleton": bootstrap_body(m["host"], m["domain"], cf_token.strip())}}, "0"]]}
        res = _call(base, cred, "/jmap/", req, timeout=120)
        name, out = (res.get("methodResponses") or [[None, {}]])[0][:2]
        done = (out.get("updated") or {}).get("singleton") if name == "x:Bootstrap/set" else None
        if not done:
            err = (out.get("notUpdated") or {}).get("singleton") or out
            detail = err.get("description") or ", ".join(
                f"{v.get('property')} ({v.get('type')})" for v in err.get("validationErrors") or []) or err.get("type")
            raise RuntimeError(f"configuration refusée par Stalwart : {detail}")
    except RuntimeError as e:
        P.log("error", slug, f"configuration automatique de Stalwart impossible : {e}")
        return False
    if done.get("username") and done.get("secret"):
        allv = db.kv_get("mail_admin") or {}
        allv[slug] = {"user": done["username"], "secret": done["secret"], "ts": time.time()}
        db.kv_set("mail_admin", allv)
    _set_flag(slug, setup=time.time(), stalwart_dns=bool(cf_token.strip()))
    lines = [l for l in (a["env"] or "").splitlines() if not re.match(rf"\s*{RECOVERY}\s*=", l)]
    db.update_app(slug, env="\n".join(lines))
    P.log("ok", slug, f"Stalwart configuré ({m['host']}, adresses @{m['domain']}"
                      + (", certificat et DNS par Cloudflare" if cf_token.strip() else "") + f") par {by} ; "
                      "compte temporaire retiré, redémarrage")
    P.deploy(slug, a["version"], "config")
    P.apply_routing()   # enregistrements DNS à jour (DMARC laissé à Stalwart s'il a un jeton)
    return True


def install(slug, version, cf_token=""):
    """Après l'installation depuis le catalogue : déploiement, puis configuration automatique si l'appli répond."""
    from . import platform as P
    P.deploy(slug, version, "create")
    a = db.app(slug)
    if a and a["state"] == "ok" and needs_setup(slug):
        setup(slug, cf_token)
