"""Configuration à distance des applis Android, servie par Caddy à côté de apps.json :
    https://<hôte des routes>.<domaine>/.well-known/apps/<package>.json
L'appli la lit au démarrage (comme apps.json) :
- version minimale (versionCode) : en dessous, l'appli demande de se mettre à jour, et ne s'utilise plus ;
- version conseillée : en dessous, elle le propose sans bloquer ;
- interrupteurs de fonctionnalités (« cle = valeur ») ;
- message d'annonce (info ou avertissement), avec une date de fin ;
- adresse et clé d'envoi des rapports de plantage (crashes.py).
Réglage kv « remote_config » : {slug: {min_code, rec_code, flags, message, level, until}}.
"""
import json
import re
import time

from . import db

KEY = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")


def of(slug):
    return {"min_code": None, "rec_code": None, "flags": "", "message": "", "level": "info", "until": "",
            **((db.kv_get("remote_config") or {}).get(slug) or {})}


def parse_flags(text):
    """« cle = valeur » par ligne → dict typé (true/false, nombres, texte). ValueError avec la ligne fautive."""
    out = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        k, sep, v = line.partition("=")
        k, v = k.strip(), v.strip()
        if not sep or not KEY.match(k):
            raise ValueError(f"ligne « {line[:50]} » : il faut « cle = valeur » (clé en minuscules, chiffres, . _ -)")
        if len(v) > 500:
            raise ValueError(f"valeur de {k} trop longue (500 caractères au plus)")
        low = v.lower()
        if low in ("true", "vrai", "oui", "on"):
            out[k] = True
        elif low in ("false", "faux", "non", "off"):
            out[k] = False
        elif re.fullmatch(r"-?\d{1,15}", v):
            out[k] = int(v)
        elif re.fullmatch(r"-?\d{1,12}\.\d{1,6}", v):
            out[k] = float(v)
        else:
            out[k] = v.strip('"')
    if len(out) > 100:
        raise ValueError("100 interrupteurs au plus")
    return out


def save(slug, f):
    def code(name):
        v = (f.get(name) or "").strip()
        if not v:
            return None
        if not re.fullmatch(r"\d{1,10}", v) or int(v) > 2_100_000_000:
            raise ValueError("versionCode : un nombre entier (celui de build.gradle)")
        return int(v)
    c = {"min_code": code("min_code"), "rec_code": code("rec_code"), "flags": (f.get("flags") or "").strip(),
         "message": (f.get("message") or "").strip()[:500], "level": "warn" if f.get("level") == "warn" else "info",
         "until": (f.get("until") or "").strip()}
    parse_flags(c["flags"])
    if c["until"] and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", c["until"]):
        raise ValueError("date de fin au format AAAA-MM-JJ")
    if c["min_code"] and c["rec_code"] and c["rec_code"] < c["min_code"]:
        raise ValueError("la version conseillée ne peut pas être plus ancienne que la version minimale")
    allv = db.kv_get("remote_config") or {}
    allv[slug] = c
    db.kv_set("remote_config", allv)


def build(a, url, hub):
    """Contenu du fichier public d'une appli."""
    from . import crashes
    c = of(a["slug"])
    msg = None
    if c["message"] and (not c["until"] or c["until"] >= time.strftime("%Y-%m-%d")):
        msg = {"text": c["message"], "level": c["level"], "until": c["until"] or None}
    return {
        "package": a["pkg"], "url": url,
        "min_version_code": c["min_code"], "recommended_version_code": c["rec_code"],
        "store_url": f"https://play.google.com/store/apps/details?id={a['pkg']}",
        "flags": parse_flags(c["flags"]), "message": msg,
        "crash_url": f"https://{hub}/.well-known/hangar/crash/{a['pkg']}", "crash_key": crashes.key(a["slug"]),
        "updated": int(time.time()),
    }


def files(name, hub, manifest):
    """{chemin relatif dans public/: contenu} pour un domaine : un fichier par appli de son apps.json."""
    by_pkg = {a["pkg"]: a for a in db.apps() if a["pkg"]}
    out = {}
    for pkg, url in manifest.items():
        a = by_pkg.get(pkg)
        if a:
            out[f"{name}/.well-known/apps/{pkg}.json"] = json.dumps(build(a, url, hub), indent=1, ensure_ascii=False)
    return out
