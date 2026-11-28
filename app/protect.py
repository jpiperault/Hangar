"""Protéger une appli web : mot de passe (authentification HTTP de base) et/ou adresses IP autorisées, appliqués par Caddy
devant l'appli, sur toutes ses adresses (sous-domaines et chemins), sur la console et les nœuds d'entrée.

- Mot de passe : un ou plusieurs comptes ; seule l'empreinte bcrypt est gardée (calculée par « caddy hash-password »).
- Adresses : IP ou réseaux ; l'IP vue est celle du visiteur (Cloudflare la transmet par le tunnel).
- Les chemins techniques de Hangar (/.well-known/hangar/… : webhooks, rapports de plantage, configuration des clients)
  restent ouverts : ils ont leur propre clé ou signature.
Réglage kv « app_protect » : {slug: {"users": [{"name", "hash"}], "ips": ["203.0.113.4/32", …]}}.

Adresses bloquées (le contraire : tout le monde sauf elles), kv « ip_deny » : {slug ou "*": [{ip, until, why, ts}]} ;
"*" vaut pour toutes les applis. Un blocage peut expirer (until) : expire() les retire, chaque heure. Posé depuis le
journal d'accès (traffic.py), y compris sur une alerte « comportement suspect ».
"""
import ipaddress
import re
import subprocess
import time

from . import db

USER_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
OPEN = "/.well-known/hangar/*"


def of(slug):
    return (db.kv_get("app_protect") or {}).get(slug) or {}


def _save(slug, cfg):
    allv = db.kv_get("app_protect") or {}
    if cfg.get("users") or cfg.get("ips"):
        allv[slug] = cfg
    else:
        allv.pop(slug, None)
    db.kv_set("app_protect", allv)


def hash_password(pw):
    r = subprocess.run(["caddy", "hash-password", "--plaintext", pw], capture_output=True, text=True, timeout=60)
    h = r.stdout.strip()
    if r.returncode or not h.startswith("$2"):
        raise RuntimeError("empreinte du mot de passe impossible : " + (r.stderr or r.stdout)[-200:])
    return h


def add_user(slug, name, pw):
    name = (name or "").strip()
    if not USER_RE.match(name):
        raise ValueError("identifiant : lettres, chiffres, . _ @ -")
    if len(pw or "") < 8:
        raise ValueError("mot de passe : 8 caractères au moins")
    cfg = of(slug)
    users = [u for u in cfg.get("users", []) if u["name"] != name] + [{"name": name, "hash": hash_password(pw)}]
    if len(users) > 20:
        raise ValueError("20 comptes au plus")
    _save(slug, {**cfg, "users": users})


def remove_user(slug, name):
    cfg = of(slug)
    _save(slug, {**cfg, "users": [u for u in cfg.get("users", []) if u["name"] != name]})


def parse_ips(raw):
    out = []
    for item in [x for x in re.split(r"[,;\s]+", raw or "") if x]:
        try:
            n = ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise ValueError(f"« {item[:60]} » : une adresse IP ou un réseau (203.0.113.4, 198.51.100.0/24)")
        if n.prefixlen == 0:
            raise ValueError("0.0.0.0/0 ou ::/0 : laisse le champ vide pour ouvrir à tous")
        if str(n) not in out:
            out.append(str(n))
    if len(out) > 100:
        raise ValueError("100 adresses ou réseaux au plus")
    return out


def set_ips(slug, ips):
    _save(slug, {**of(slug), "ips": ips})


def drop(slug):
    _save(slug, {})


ALL = "*"
DENY_MAX = 500


def _deny_all():
    return db.kv_get("ip_deny") or {}


def denied(slug, now=None):
    """Blocages en cours pour cette appli (les siens et ceux de toutes les applis)."""
    now = now or time.time()
    d = _deny_all()
    return [e for key in (slug, ALL) for e in d.get(key, []) if not e.get("until") or e["until"] > now]


def deny_ips(slug, now=None):
    out = []
    for e in denied(slug, now):
        if e["ip"] not in out:
            out.append(e["ip"])
    return out


def block(target, ip, hours=None, why=""):
    """Bloque une adresse (ou un réseau) pour une appli, ou pour toutes (target « * »). hours None : sans fin."""
    n = ipaddress.ip_network(ip, strict=False)
    if n.prefixlen == 0:
        raise ValueError("bloquer tout Internet : non")
    if (n.version == 4 and n.prefixlen < 16) or (n.version == 6 and n.prefixlen < 32):
        raise ValueError("réseau trop large (au plus /16 en IPv4, /32 en IPv6)")
    if n.is_private or n.is_loopback:
        raise ValueError("adresse privée ou locale : elle ne vient pas d'Internet")
    d = _deny_all()
    cur = [e for e in d.get(target, []) if e["ip"] != str(n)]
    if len(cur) >= DENY_MAX:
        raise ValueError(f"{DENY_MAX} blocages au plus")
    cur.append({"ip": str(n), "until": time.time() + hours * 3600 if hours else None, "why": (why or "")[:200], "ts": time.time()})
    d[target] = cur
    db.kv_set("ip_deny", d)
    return str(n)


def unblock(target, ip):
    d = _deny_all()
    cur = [e for e in d.get(target, []) if e["ip"] != ip]
    changed = len(cur) != len(d.get(target, []))
    if cur:
        d[target] = cur
    else:
        d.pop(target, None)
    if changed:
        db.kv_set("ip_deny", d)
    return changed


def blocked_list():
    """Tous les blocages, pour l'affichage : [{target, ip, until, why, ts}]."""
    now = time.time()
    return sorted([{**e, "target": t} for t, li in _deny_all().items() for e in li if not e.get("until") or e["until"] > now],
                  key=lambda e: -e["ts"])


def expire(now=None):
    """Retire les blocages échus ; True si quelque chose a changé (routes Caddy à refaire)."""
    now = now or time.time()
    d = _deny_all()
    new = {t: [e for e in li if not e.get("until") or e["until"] > now] for t, li in d.items()}
    new = {t: li for t, li in new.items() if li}
    if new != d:
        db.kv_set("ip_deny", new)
        return True
    return False


def caddy_lines(slug, ind, site=True):
    """Directives Caddy, à placer avant l'appli (dans son bloc de site, ou dans son handle_path)."""
    cfg = of(slug)
    m = re.sub(r"[^a-z0-9]", "_", slug)
    L = []
    deny = deny_ips(slug)
    if deny:   # adresses bloquées : refusées partout, chemins techniques compris
        L += [f"{ind}@hp_deny_{m} client_ip {' '.join(deny)}", f"{ind}route @hp_deny_{m} {{",
              f'{ind}\trespond "Accès refusé" 403', f"{ind}}}"]
    if not cfg:
        return L
    if cfg.get("ips"):
        L += [f"{ind}@hp_ip_{m} {{", f"{ind}\tnot client_ip {' '.join(cfg['ips'])}"]
        if site:
            L.append(f"{ind}\tnot path {OPEN}")
        L += [f"{ind}}}", f"{ind}route @hp_ip_{m} {{", f'{ind}\trespond "Accès refusé" 403', f"{ind}}}"]
    if cfg.get("users"):
        if site:
            L += [f"{ind}@hp_auth_{m} not path {OPEN}", f"{ind}basic_auth @hp_auth_{m} {{"]
        else:
            L.append(f"{ind}basic_auth {{")
        L += [f"{ind}\t{u['name']} {u['hash']}" for u in cfg["users"]] + [f"{ind}}}"]
    return L
