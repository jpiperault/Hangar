"""Domaines servis par Hangar et adresses publiques des applis.

Un domaine a son propre mode d'exposition :
- tunnel : Cloudflare reçoit le trafic et l'envoie par cloudflared à Caddy (HTTP local, aucun port ouvert) ;
- direct : Caddy écoute en 80/443 sur la machine d'entrée choisie et obtient ses certificats Let's Encrypt.
Le préfixe « hub » (apps, par exemple) donne l'hôte des routes par chemin : apps.<domaine>/<appli>/. Vide : pas de
routes par chemin sur ce domaine.

Une appli a une liste d'adresses (table routes), dans l'ordre : la première est l'adresse principale.
- kind 'sub'  : <sub>.<domaine>, ou le domaine nu si sub est vide ;
- kind 'path' : <hub>.<domaine>/<slug>/.
"""
import re
import time

from . import db

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
RESERVED_SUBS = {"www"}


# ---------------------------------------------------------------- domaines

def all_domains():
    return db.q("SELECT * FROM domains ORDER BY is_default DESC, name")


def get(name):
    return db.one("SELECT * FROM domains WHERE name = ?", (name,))


def default():
    return db.one("SELECT * FROM domains ORDER BY is_default DESC, created_at LIMIT 1")


def by_name():
    return {d["name"]: d for d in all_domains()}


def zone_hint(name):
    """Domaine enregistrable le plus probable (deux derniers labels) : sert seulement d'indication."""
    return ".".join(name.split(".")[-2:])


def save(name, mode, hub, entry="local", ip="", make_default=False, old=None):
    """Crée ou modifie un domaine. Retourne les erreurs (dict champ → message)."""
    e = {}
    name = (name or "").strip().lower().rstrip(".")
    hub = (hub or "").strip().lower()
    ip = (ip or "").strip()
    if not DOMAIN_RE.match(name):
        e["name"] = "Nom de domaine invalide, par exemple exemple.fr"
    elif not old and get(name):
        e["name"] = "Ce domaine existe déjà."
    elif old and name != old["name"]:
        e["name"] = "Le nom d'un domaine ne change pas : ajoute le nouveau, puis retire l'ancien."
    if mode not in ("tunnel", "direct"):
        e["mode"] = "Mode inconnu."
    if hub and not LABEL_RE.match(hub):
        e["hub"] = "Lettres minuscules, chiffres et tirets, par exemple apps."
    elif hub and db.one("SELECT 1 FROM routes WHERE kind = 'sub' AND domain = ? AND sub = ?", (name, hub)):
        e["hub"] = f"{hub}.{name} est déjà l'adresse d'une appli."
    if ip:
        import ipaddress
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            e["ip"] = "Adresse IP invalide."
    if mode == "direct" and not db.one("SELECT 1 FROM nodes WHERE id = ? AND (id = 'local' OR state IN ('ok', 'offline'))",
                                       (entry,)) and entry != "local":
        e["entry"] = "Machine d'entrée inconnue."
    if not hub and old and old["hub"] and db.one("SELECT 1 FROM routes WHERE kind = 'path' AND domain = ?", (name,)):
        e["hub"] = "Des applis ont une route par chemin sur ce domaine : retire-les d'abord, ou garde un préfixe."
    if e:
        return e
    if mode != "direct":
        entry, ip = "local", ""
    if old:
        db.x("UPDATE domains SET mode = ?, hub = ?, entry = ?, ip = ? WHERE name = ?", (mode, hub, entry, ip, name))
    else:
        db.x("INSERT INTO domains(name, mode, hub, entry, ip, is_default, created_at) VALUES(?, ?, ?, ?, ?, 0, ?)",
             (name, mode, hub, entry, ip, time.time()))
    if make_default or not db.one("SELECT 1 FROM domains WHERE is_default = 1"):
        set_default(name)
    return {}


def set_default(name):
    with db.lock:
        db.x("UPDATE domains SET is_default = CASE WHEN name = ? THEN 1 ELSE 0 END", (name,))


def remove(name):
    d = get(name)
    if not d:
        raise ValueError("Domaine inconnu.")
    users = db.q("SELECT DISTINCT slug FROM routes WHERE domain = ?", (name,))
    if users:
        raise ValueError("Des applis utilisent encore ce domaine : " + ", ".join(u["slug"] for u in users) +
                         ". Retire leurs adresses sur ce domaine d'abord.")
    if db.one("SELECT COUNT(*) AS n FROM domains")["n"] <= 1:
        raise ValueError("Il faut garder au moins un domaine.")
    db.x("DELETE FROM domains WHERE name = ?", (name,))
    if d["is_default"]:
        set_default(default()["name"])


def has_mode(mode):
    return bool(db.one("SELECT 1 FROM domains WHERE mode = ?", (mode,)))


# ---------------------------------------------------------------- adresses des applis

def host_of(r, doms=None):
    if r["kind"] == "path":
        d = (doms or {}).get(r["domain"]) or get(r["domain"])
        return f"{d['hub']}.{r['domain']}" if d and d["hub"] else None
    return f"{r['sub']}.{r['domain']}" if r["sub"] else r["domain"]


def url_of(r, slug, doms=None):
    h = host_of(r, doms)
    if not h:
        return None
    return f"https://{h}/{slug}/" if r["kind"] == "path" else f"https://{h}/"


def routes(slug):
    return db.q("SELECT * FROM routes WHERE slug = ? ORDER BY pos, id", (slug,))


def all_routes():
    out = {}
    for r in db.q("SELECT * FROM routes ORDER BY slug, pos, id"):
        out.setdefault(r["slug"], []).append(r)
    return out


def urls(slug, rts=None, doms=None):
    """[(libellé, url)] dans l'ordre des adresses ; la première est l'adresse principale."""
    doms = doms or by_name()
    out = []
    for r in (routes(slug) if rts is None else rts):
        u = url_of(r, slug, doms)
        if u:
            out.append(("chemin" if r["kind"] == "path" else "adresse", u))
    return out


def primary_url(slug, rts=None, doms=None, domain=None):
    """Adresse principale ; avec domain, la première adresse de l'appli sur ce domaine."""
    doms = doms or by_name()
    for r in (routes(slug) if rts is None else rts):
        if domain and r["domain"] != domain:
            continue
        u = url_of(r, slug, doms)
        if u:
            return u
    return None


def set_routes(slug, items):
    """items : [{kind, domain, sub}], dans l'ordre. Remplace toutes les adresses de l'appli."""
    with db.lock:
        db.x("BEGIN")
        try:
            db.x("DELETE FROM routes WHERE slug = ?", (slug,))
            for i, r in enumerate(items):
                db.x("INSERT INTO routes(slug, domain, kind, sub, pos) VALUES(?, ?, ?, ?, ?)",
                     (slug, r["domain"], r["kind"], r.get("sub") or "", i))
            db.x("COMMIT")
        except Exception:
            db.x("ROLLBACK")
            raise


def parse_routes(form, slug):
    """Lit les adresses du formulaire d'une appli : champs r_kind, r_domain, r_sub répétés, dans l'ordre.
    Retourne (items, erreur)."""
    kinds, doms_in, subs = form.getlist("r_kind"), form.getlist("r_domain"), form.getlist("r_sub")
    doms = by_name()
    raw = [{"kind": k if k in ("sub", "path") else "sub", "domain": (d or "").strip().lower(),
            "sub": (x or "").strip().lower()} for k, d, x in zip(kinds, doms_in, subs)]
    items, err = _check_routes(raw, slug, doms)
    return (raw, err) if err else (items, None)


def _check_routes(raw, slug, doms):
    items, seen = [], set()
    for r in raw:
        kind, dom, sub = r["kind"], r["domain"], r["sub"]
        if kind == "sub" and not sub and not dom:
            continue                      # ligne vide
        d = doms.get(dom)
        if not d:
            return items, f"Domaine inconnu : {dom or '(vide)'}."
        if kind == "path":
            if not d["hub"]:
                return items, f"{dom} n'a pas d'hôte pour les routes par chemin (préfixe vide dans Domaines)."
            sub = ""
            key = ("path", dom)
            label = f"{d['hub']}.{dom}/{slug}/"
        else:
            if sub == "@":
                sub = ""
            if sub and not LABEL_RE.match(sub):
                return items, f"Sous-domaine invalide : {sub}. Lettres minuscules, chiffres et tirets."
            if sub in RESERVED_SUBS:
                return items, f"{sub}.{dom} est réservé."
            if d["hub"] and sub == d["hub"]:
                return items, f"{sub}.{dom} sert aux routes par chemin."
            other = db.one("SELECT slug FROM routes WHERE kind = 'sub' AND domain = ? AND sub = ? AND slug != ?",
                           (dom, sub, slug))
            label = f"{sub + '.' if sub else ''}{dom}"
            if other:
                return items, f"{label} est déjà l'adresse de l'appli {other['slug']}."
            key = ("sub", dom, sub)
        if key in seen:
            return items, f"{label} est en double."
        seen.add(key)
        items.append({"kind": kind, "domain": dom, "sub": sub})
    if not items:
        return items, "Donne au moins une adresse à l'appli."
    return items, None


# ---------------------------------------------------------------- noms publics

def public_names(slug=None):
    """Chaque nom public à déclarer (DNS ou tunnel) : [{name, domain, mode, what, slug}]."""
    doms = by_name()
    names, seen = [], set()

    def add(name, d, what, s):
        if name not in seen:
            seen.add(name)
            names.append({"name": name, "domain": d["name"], "mode": d["mode"], "what": what, "slug": s,
                          "entry": d["entry"], "ip": d["ip"]})
    apps = {a["slug"]: a["name"] for a in db.apps()}
    if slug is None:
        for d in doms.values():
            if d["hub"]:
                add(f"{d['hub']}.{d['name']}", d, "routes par chemin", None)
    for s, rts in all_routes().items():
        if slug is not None and s != slug:
            continue
        for r in rts:
            d = doms.get(r["domain"])
            if not d:
                continue
            if r["kind"] == "path":
                if slug is not None and d["hub"]:
                    add(f"{d['hub']}.{d['name']}", d, "routes par chemin", None)
                continue
            add(host_of(r, doms), d, apps.get(s, s), s)
    return names


# ---------------------------------------------------------------- reprise de l'ancien modèle (un domaine + alias)

def migrate_from_settings():
    """Ancien modèle : base_domain + alias servis à l'identique, un mode global, apps.expose/sub.
    Chaque alias devient un domaine, et chaque appli garde exactement les mêmes noms."""
    if db.one("SELECT 1 FROM domains"):
        return False
    s = {r["key"]: r["value"] for r in db.q("SELECT key, value FROM settings")}
    import json
    base = s.get("base_domain") or "piperault.fr"
    aliases = [a for a in json.loads(s.get("aliases") or "[]") if a and a != base]
    mode = s.get("mode") or "tunnel"
    hub = s.get("hub") or "apps"
    now = time.time()
    for i, name in enumerate([base] + aliases):
        db.x("INSERT OR IGNORE INTO domains(name, mode, hub, entry, ip, is_default, created_at) VALUES(?, ?, ?, 'local', '', ?, ?)",
             (name, mode, hub, 1 if i == 0 else 0, now + i))
    for a in db.q("SELECT slug, expose, sub FROM apps"):
        items = []
        for name in [base] + aliases:
            if a["expose"] in ("sub", "both") and a["sub"]:
                items.append({"kind": "sub", "domain": name, "sub": a["sub"]})
        for name in [base] + aliases:
            if a["expose"] in ("path", "both") or not a["sub"]:
                items.append({"kind": "path", "domain": name, "sub": ""})
        set_routes(a["slug"], items)
    return True


# ---------------------------------------------------------------- archives

def export():
    """Domaines et adresses pour une archive (format 2)."""
    return [{k: d[k] for k in ("name", "mode", "hub", "entry", "ip", "is_default")} for d in all_domains()]


def export_routes(slug):
    return [{k: r[k] for k in ("kind", "domain", "sub")} for r in routes(slug)]


def legacy_domains(st):
    """Réglages d'une archive d'avant le multi-domaine : base_domain + alias, même mode et même préfixe."""
    st = st or {}
    if st.get("domains"):
        return st["domains"]
    base = st.get("base_domain")
    if not base:
        return []
    names = [base] + [a for a in (st.get("aliases") or []) if a and a != base]
    return [{"name": n, "mode": st.get("mode") or "tunnel", "hub": st.get("hub") or "apps", "entry": "local",
             "ip": "", "is_default": 1 if i == 0 else 0} for i, n in enumerate(names)]


def legacy_routes(a, doms):
    """Adresses d'une appli d'avant le multi-domaine (expose/sub), servies sur chaque domaine de l'archive."""
    if a.get("routes"):
        return a["routes"]
    names = [d["name"] for d in doms]
    out = []
    if a.get("expose") in ("sub", "both") and a.get("sub"):
        out += [{"kind": "sub", "domain": n, "sub": a["sub"]} for n in names]
    if a.get("expose") in ("path", "both") or not a.get("sub"):
        out += [{"kind": "path", "domain": n, "sub": ""} for n in names]
    return out


def import_domains(items):
    """Ajoute ou met à jour les domaines d'une archive ; ceux d'ici qui n'y sont pas restent."""
    for d in items:
        if not DOMAIN_RE.match(d.get("name") or ""):
            continue
        entry = d.get("entry") or "local"
        if entry != "local" and not db.one("SELECT 1 FROM nodes WHERE id = ?", (entry,)):
            entry = "local"
        mode = d.get("mode") if d.get("mode") in ("tunnel", "direct") else "tunnel"
        hub = d.get("hub") or ""
        if get(d["name"]):
            db.x("UPDATE domains SET mode = ?, hub = ?, entry = ?, ip = ? WHERE name = ?",
                 (mode, hub, entry, d.get("ip") or "", d["name"]))
        else:
            db.x("INSERT INTO domains(name, mode, hub, entry, ip, is_default, created_at) VALUES(?, ?, ?, ?, ?, 0, ?)",
                 (d["name"], mode, hub, entry, d.get("ip") or "", time.time()))
    dft = next((d["name"] for d in items if d.get("is_default")), None)
    if dft and get(dft):
        set_default(dft)


def usable_routes(slug, wanted):
    """Garde les adresses d'une archive possibles ici (domaine connu, nom libre). Retourne (adresses, écartées)."""
    doms = by_name()
    ok, dropped, seen = [], [], set()
    for r in wanted or []:
        d = doms.get(r.get("domain"))
        label = f"{r.get('sub') + '.' if r.get('sub') else ''}{r.get('domain')}" if r.get("kind") == "sub" \
            else f"chemin sur {r.get('domain')}"
        if not d:
            dropped.append(label + " (domaine absent)")
            continue
        if r.get("kind") == "path":
            if not d["hub"]:
                dropped.append(label + " (pas de préfixe)")
                continue
            key = ("path", d["name"])
        else:
            sub = r.get("sub") or ""
            if (sub and not LABEL_RE.match(sub)) or (d["hub"] and sub == d["hub"]) or db.one(
                    "SELECT 1 FROM routes WHERE kind = 'sub' AND domain = ? AND sub = ? AND slug != ?",
                    (d["name"], sub, slug)):
                dropped.append(label + " (déjà pris)")
                continue
            key = ("sub", d["name"], sub)
        if key not in seen:
            seen.add(key)
            ok.append({"kind": r["kind"], "domain": d["name"], "sub": r.get("sub") or ""})
    if not ok:
        d = default()
        if d and d["hub"]:
            ok = [{"kind": "path", "domain": d["name"], "sub": ""}]
    return ok, dropped
