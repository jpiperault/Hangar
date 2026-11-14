"""Analyse des vulnérabilités des images des applis, avec Trivy.

Sur la machine de l'appli, un conteneur Trivy jetable lit l'image locale (par le socket Docker) et liste les
failles connues (HIGH et CRITICAL), avec la version qui les corrige. Sa base de failles est gardée dans le volume
Docker « hangar-trivy-cache » de la machine (téléchargée une fois, mise à jour à chaque passage).
Quand : chaque semaine (jour réglable) et, en option, après chaque déploiement. Alerte quand une image en ligne a une
faille CRITICAL qu'elle n'avait pas au passage précédent (pas à la toute première analyse : rien à comparer).
Réglage kv « vuln_scan » : {"on", "day", "after_deploy"} ; résultats kv « vulns » : {slug: {ts, image, digest,
counts, items, error}}.
"""
import json
import time

from . import alerts, db
from . import platform as P

TRIVY = "aquasec/trivy:0.75.0"
DEFAULT = {"on": True, "day": 0, "after_deploy": True}
HOUR = 5
MAX_ITEMS = 200
_busy = set()


def settings():
    return {**DEFAULT, **(db.kv_get("vuln_scan") or {})}


def save(on, day, after_deploy):
    db.kv_set("vuln_scan", {"on": bool(on), "day": max(0, min(6, int(day))), "after_deploy": bool(after_deploy)})


def results():
    return db.kv_get("vulns") or {}


def of(slug):
    return results().get(slug)


def parse(report):
    """Rapport JSON de Trivy → (compte par gravité, failles triées : les plus graves et corrigeables d'abord)."""
    items, counts = [], {"CRITICAL": 0, "HIGH": 0}
    for res in report.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            sev = v.get("Severity", "UNKNOWN")
            if sev not in counts:
                continue
            counts[sev] += 1
            items.append({"id": v.get("VulnerabilityID"), "sev": sev, "pkg": v.get("PkgName"),
                          "installed": v.get("InstalledVersion"), "fixed": v.get("FixedVersion") or "",
                          "title": (v.get("Title") or "")[:160], "target": res.get("Target", "")[:120],
                          "class": "os" if res.get("Class") == "os-pkgs" else "lang", "type": res.get("Type") or ""})
    seen, uniq = set(), []
    for it in sorted(items, key=lambda x: (x["sev"] != "CRITICAL", not x["fixed"], x["id"] or "")):
        k = (it["id"], it["pkg"], it["installed"])
        if k not in seen:
            seen.add(k)
            uniq.append(it)
    return counts, uniq[:MAX_ITEMS]


def scan(slug):
    """Analyse l'image en ligne de l'appli. Retourne le résultat enregistré."""
    a = db.app(slug)
    if not a or a["kind"] == "static" or slug in _busy:
        return None
    _busy.add(slug)
    try:
        ref = P.image_ref(a, a["version"])
        node = a["node"]
        rc, dig = P.dk(node, "image", "inspect", "-f", "{{.Id}}", ref, timeout=30)
        if rc:
            return _store(slug, {"ts": time.time(), "image": ref, "error": "image absente de la machine"})
        rc, out = P.dk(node, "run", "--rm", "-v", "/var/run/docker.sock:/var/run/docker.sock:ro",
                       "-v", "hangar-trivy-cache:/root/.cache", "--memory", "1g", TRIVY,
                       "image", "--quiet", "--format", "json", "--severity", "HIGH,CRITICAL", "--scanners", "vuln",
                       "--timeout", "15m", ref, timeout=1200)
        start = out.find("{")
        if rc or start < 0:
            return _store(slug, {"ts": time.time(), "image": ref, "error": P.tail(out, 3)[:300] or f"code {rc}"})
        counts, items = parse(json.JSONDecoder().raw_decode(out[start:])[0])   # messages de Trivy après le JSON
        prev = of(slug) or {}
        res = {"ts": time.time(), "image": ref, "digest": dig.strip(), "counts": counts, "items": items, "error": None}
        _store(slug, res)
        new_crit = {i["id"] for i in items if i["sev"] == "CRITICAL"} - {i["id"] for i in prev.get("items") or []
                                                                         if i["sev"] == "CRITICAL"}
        # première analyse réussie : on note, sans alerter (la liste est dans la fiche) ; ensuite, les nouvelles seulement
        if new_crit and a["desired"] == "running" and prev.get("counts") is not None:
            fixable = [i for i in items if i["id"] in new_crit and i["fixed"]]
            alerts.send(f"{a['name']} : {len(new_crit)} faille(s) critique(s)",
                        f"Image {ref} : {', '.join(sorted(new_crit)[:5])}" + ("…" if len(new_crit) > 5 else "") +
                        (f". {len(fixable)} corrigée(s) dans une version plus récente des paquets : reconstruis ou mets "
                         "à jour l'image." if fixable else ". Pas encore de correctif publié."),
                        priority=4, tags=["warning", "lock"], key=f"vuln:{slug}", cooldown=86400)
        P.log("warn" if counts["CRITICAL"] else "info", slug,
              f"analyse de {ref} : {counts['CRITICAL']} critique(s), {counts['HIGH']} élevée(s)")
        from . import patch
        patch.maybe_auto(slug, res)   # correction automatique des paquets système, si réglée
        return res
    except Exception as e:
        return _store(slug, {"ts": time.time(), "error": str(e)[:300]})
    finally:
        _busy.discard(slug)


def _store(slug, res):
    allv = results()
    allv[slug] = res
    db.kv_set("vulns", allv)
    return res


def busy(slug):
    return slug in _busy


def after_deploy(slug):
    if settings()["on"] and settings()["after_deploy"]:
        P.spawn(scan, slug)


def drop(slug):
    allv = results()
    if allv.pop(slug, None) is not None:
        db.kv_set("vulns", allv)


def tick(now=None):
    """Toutes les heures : un passage par semaine, la nuit du jour choisi, appli par appli."""
    s = settings()
    if not s["on"]:
        return
    t = time.localtime(now or time.time())
    last = db.kv_get("vuln_scan_week")
    week = time.strftime("%G-W%V", t)
    if t.tm_wday != s["day"] or t.tm_hour < HOUR or last == week:
        return
    db.kv_set("vuln_scan_week", week)
    for a in db.apps():
        if a["kind"] != "static" and a["desired"] == "running":
            scan(a["slug"])


def groups(items):
    """Failles regroupées par paquet, en trois familles : système corrigeable, dépendances de l'appli, sans correctif.
    Chaque groupe : {pkg, installed, fixed, sev (la pire), ids, titles, type, target}."""
    fam = {"os": {}, "lang": {}, "nofix": {}}
    for i in items:
        key = "nofix" if not i["fixed"] else i.get("class") or ("os" if "(" in i.get("target", "") else "lang")
        g = fam[key].setdefault((i["pkg"], i["installed"]), {"pkg": i["pkg"], "installed": i["installed"], "fixed": set(),
                                                              "sev": "HIGH", "ids": [], "titles": [], "type": i.get("type", ""),
                                                              "target": i.get("target", "")})
        if i["fixed"]:
            g["fixed"] |= {x.strip() for x in i["fixed"].split(",") if x.strip()}
        if i["sev"] == "CRITICAL":
            g["sev"] = "CRITICAL"
        g["ids"].append(i["id"])
        if i["title"] and len(g["titles"]) < 3:
            g["titles"].append(i["title"])
    out = {}
    for k, d in fam.items():
        lst = [{**g, "fixed": ", ".join(sorted(g["fixed"]))} for g in d.values()]
        out[k] = sorted(lst, key=lambda g: (g["sev"] != "CRITICAL", -len(g["ids"]), g["pkg"] or ""))
    return out


def prompt(a, res):
    """Prompt à donner à l'assistant de code du projet pour corriger les dépendances vulnérables de l'appli."""
    g = groups(res.get("items") or [])["lang"]
    if not g:
        return ""
    lines = [f"# Corriger les dépendances vulnérables de {a['name']}", "",
             f"L'image en ligne ({res.get('image')}) contient des dépendances avec des failles connues, déjà corrigées "
             "dans des versions plus récentes. Mets-les à jour dans le projet (fichier de dépendances, verrou), "
             "reconstruis, et vérifie que tout marche encore.", "",
             "| Paquet | Installé | Corrigé en | Gravité | Failles |", "|---|---|---|---|---|"]
    for x in g:
        lines.append(f"| {x['pkg']} | {x['installed']} | {x['fixed']} | {'critique' if x['sev'] == 'CRITICAL' else 'élevée'} | "
                     f"{', '.join(x['ids'][:6])}{'…' if len(x['ids']) > 6 else ''} |")
    lines += ["", "À faire :",
              "1. Monte chaque paquet au moins à la version « Corrigé en » (la plus basse qui corrige, si plusieurs : "
              "reste dans la même version majeure quand c'est possible).",
              "2. Si un paquet n'est qu'une dépendance indirecte, monte le paquet qui l'amène, ou fixe sa version.",
              "3. Lis les notes de version des montées de version majeures et adapte le code si besoin.",
              "4. Lance les tests, puis construis l'image et vérifie qu'elle démarre et que /health répond.",
              "5. Publie une nouvelle version (tag) : Hangar la déploie et la réanalyse."]
    return "\n".join(lines)
