"""Nettoyage des images Docker : les anciennes versions des applis s'accumulent sur chaque machine.

Sur chaque machine (console et nœuds en ligne), pour chaque appli :
- si elle tourne là (ou peut y tourner : secours, instance) : on garde la version en ligne, la précédente (retour
  arrière) et les `keep` plus récentes ; les autres versions de son image sont supprimées ;
- si elle n'est plus là (déplacée sur un autre nœud) : ses images y sont supprimées.
Jamais touchées : une image utilisée par un conteneur (même arrêté), et les images qui ne sont pas celles d'une appli
(PostgreSQL, Valkey, MySQL…), sauf les images orphelines sans nom. En option, le cache de construction (docker builder).
Réglage kv « image_cleanup » : {"on", "keep", "day" (0 = lundi … 6 = dimanche), "build_cache"} ;
dernier passage : kv « image_cleanup_last » {ts, freed, removed, errors}.
"""
import time

from . import db
from . import platform as P

DEFAULT = {"on": False, "keep": 3, "day": 6, "build_cache": True}
HOUR = 4   # passage la nuit du jour choisi, après les sauvegardes


def settings():
    return {**DEFAULT, **(db.kv_get("image_cleanup") or {})}


def save(on, keep, day, build_cache):
    keep = max(1, min(20, int(keep)))
    day = max(0, min(6, int(day)))
    db.kv_set("image_cleanup", {"on": bool(on), "keep": keep, "day": day, "build_cache": bool(build_cache)})


def _repo(a):
    return f"hangar/{a['slug']}" if a["source"] == "git" else a["image"]


def _homes(a):
    from . import ha
    h = ha.get(a["slug"])
    return {a["node"] or P.LOCAL} | set(h["nodes"] if h else [])


def _images(node):
    """[{ref, repo, tag, id, created, size}] des images nommées de la machine, et la liste des orphelines."""
    rc, out = P.dk(node, "image", "ls", "--no-trunc", "--format",
                   "{{.Repository}}|{{.Tag}}|{{.ID}}|{{.CreatedAt}}", timeout=60)
    if rc:
        raise RuntimeError(P.tail(out, 2))
    named, dangling = [], []
    for line in out.splitlines():
        parts = line.split("|")
        if len(parts) != 4:
            continue
        repo, tag, iid, created = parts
        if repo == "<none>" or tag == "<none>":
            dangling.append(iid)
        else:
            named.append({"ref": f"{repo}:{tag}", "repo": repo, "tag": tag, "id": iid, "created": created})
    return named, dangling


def _used_ids(node):
    rc, out = P.dk(node, "ps", "-a", "--no-trunc", "--format", "{{.ID}}", timeout=60)
    ids = out.split() if rc == 0 else []
    if not ids:
        return set()
    rc, out = P.dk(node, "inspect", "-f", "{{.Image}}", *ids, timeout=60)
    if rc:
        raise RuntimeError("conteneurs illisibles : " + P.tail(out, 2))
    return set(out.split())


def plan(node, keep=None):
    """Images à supprimer sur cette machine : [{ref, id, why}] (rien n'est supprimé)."""
    keep = keep or settings()["keep"]
    named, _ = _images(node)
    used = _used_ids(node)
    apps = db.apps()
    by_repo = {}
    for a in apps:
        if a["source"] in ("image", "git"):
            by_repo.setdefault(_repo(a), []).append(a)
            by_repo.setdefault(f"hangar-patch/{a['slug']}", []).append(a)   # images corrigées (patch.py)
    out = []
    for repo, owners in by_repo.items():
        imgs = sorted([i for i in named if i["repo"] == repo], key=lambda i: i["created"], reverse=True)
        here = [a for a in owners if node in _homes(a)]
        if not here:
            out += [{**i, "why": "appli plus sur cette machine"} for i in imgs if i["id"] not in used]
            continue
        protect = set()
        for a in here:
            for v in (a["version"], a["prev_version"]):
                if v:
                    protect.add(P.image_ref(a, v))
                    protect.add(P.base_ref(a, v))   # l'originale reste : base de la correction, et repli
        recent = [i["ref"] for i in imgs][:keep]
        for i in imgs:
            if i["id"] in used or i["ref"] in protect or i["ref"] in recent:
                continue
            out.append({**i, "why": "ancienne version"})
    return out


def _size(node, ids):
    if not ids:
        return 0
    rc, out = P.dk(node, "image", "inspect", "-f", "{{.Size}}", *ids, timeout=60)
    return sum(int(x) for x in out.split() if x.isdigit()) if rc == 0 else 0


def preview():
    """Ce qu'un passage supprimerait maintenant : {nœud: {"images": [...], "bytes": n}} ; erreurs par nœud."""
    res = {}
    for n in _nodes():
        try:
            p = plan(n)
            res[n] = {"images": p, "bytes": _size(n, sorted({i["id"] for i in p}))}
        except Exception as e:
            res[n] = {"error": str(e)[:200]}
    return res


def _nodes():
    return [r["id"] for r in db.q("SELECT id, state FROM nodes") if r["id"] == P.LOCAL or r["state"] == "ok"]


def run(trigger="planifié"):
    """Un passage sur chaque machine. Retourne le résumé (aussi gardé dans kv « image_cleanup_last »)."""
    s = settings()
    freed, removed, errors = 0, 0, []
    for n in _nodes():
        try:
            p = plan(n, s["keep"])
            ids = sorted({i["id"] for i in p})
            size = _size(n, ids)
            for i in p:
                rc, out = P.dk(n, "image", "rm", i["ref"], timeout=120)
                if rc == 0:
                    removed += 1
                elif "conflict" not in out and "being used" not in out:
                    errors.append(f"{n} : {i['ref']} : {P.tail(out, 1)[:120]}")
            freed += size
            rc, out = P.dk(n, "image", "prune", "-f", timeout=300)       # orphelines sans nom
            freed += _reclaimed(out)
            if s["build_cache"]:
                rc, out = P.dk(n, "builder", "prune", "-f", "--filter", "until=168h", timeout=600)
                freed += _reclaimed(out)
        except Exception as e:
            errors.append(f"{n} : {str(e)[:200]}")
    last = {"ts": time.time(), "freed": freed, "removed": removed, "errors": errors, "trigger": trigger}
    db.kv_set("image_cleanup_last", last)
    from .backup import human
    P.log("warn" if errors else "ok", "système", f"nettoyage des images ({trigger}) : {removed} supprimée(s), "
          f"{human(freed)} libérés" + (f" ; erreurs : {' ; '.join(errors)[:400]}" if errors else ""))
    return last


def _reclaimed(out):
    """« Total reclaimed space: 1.2GB » → octets."""
    import re
    m = re.search(r"reclaimed space:\s*([\d.]+)\s*([kMGT]?B)", out or "", re.I)
    if not m:
        return 0
    mult = {"B": 1, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12}[m.group(2).upper()]
    return int(float(m.group(1)) * mult)


def tick(now=None):
    """Appelée toutes les heures par la supervision : passe une fois, la nuit du jour choisi."""
    s = settings()
    if not s["on"]:
        return
    t = time.localtime(now or time.time())
    last = (db.kv_get("image_cleanup_last") or {}).get("ts") or 0
    if t.tm_wday == s["day"] and t.tm_hour >= HOUR and (now or time.time()) - last > 20 * 3600:
        from . import backup
        if backup.running():
            return
        run()
