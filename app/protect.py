"""Protéger une appli web : mot de passe (authentification HTTP de base) et/ou adresses IP autorisées, appliqués par Caddy
devant l'appli, sur toutes ses adresses (sous-domaines et chemins), sur la console et les nœuds d'entrée.

- Mot de passe : un ou plusieurs comptes ; seule l'empreinte bcrypt est gardée (calculée par « caddy hash-password »).
- Adresses : IP ou réseaux ; l'IP vue est celle du visiteur (Cloudflare la transmet par le tunnel).
- Les chemins techniques de Hangar (/.well-known/hangar/… : webhooks, rapports de plantage, configuration des clients)
  restent ouverts : ils ont leur propre clé ou signature.
Réglage kv « app_protect » : {slug: {"users": [{"name", "hash"}], "ips": ["203.0.113.4/32", …]}}.
"""
import ipaddress
import re
import subprocess

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


def caddy_lines(slug, ind, site=True):
    """Directives Caddy, à placer avant l'appli (dans son bloc de site, ou dans son handle_path)."""
    cfg = of(slug)
    if not cfg:
        return []
    m = re.sub(r"[^a-z0-9]", "_", slug)
    L = []
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
