"""Correction des failles des paquets système d'une image : Hangar construit, sur la machine de l'appli, une image dérivée
de celle en ligne dont les paquets du système (Alpine apk, Debian/Ubuntu apt, Fedora/RHEL dnf ou microdnf) sont mis à
jour, puis la déploie. Si l'appli ne répond plus, l'image d'origine revient tout de suite.

- Image dérivée : hangar-patch/<appli>:<version>-<date>, construite depuis l'image locale (rien n'est envoyé ailleurs),
  sur chaque machine où l'appli tourne ou peut tourner (secours, instances). Utilisateur, commande et point d'entrée de
  l'image d'origine sont gardés.
- Elle ne vaut que pour la version en ligne : déployer une autre version repart de l'image d'origine (et le mode
  automatique la corrige de nouveau). Une appli déplacée sur une machine sans l'image dérivée repart de l'originale.
- Les dépendances de l'appli elle-même (paquets Python, npm, Java…) ne sont pas touchées : il faut les monter dans son
  projet (prompt de correction dans l'onglet Vulnérabilités).
- Automatique : après une analyse qui trouve des failles système corrigeables, au plus un essai par jour et par version.
Réglages : kv « vuln_fix » {"auto": bool} (général) et « vuln_fix_apps » {slug: "auto" | "manuel"} (par appli) ;
état : kv « image_patches » {slug: {version, ref, base, ts, nodes}} et « image_patch_tries » {slug: {version, ts, ok, msg}}.
"""
import json
import time

from . import alerts, db
from . import platform as P

UPGRADE = ("set -e; if command -v apk >/dev/null 2>&1; then apk upgrade --no-cache; "
           "elif command -v apt-get >/dev/null 2>&1; then apt-get update; "
           "DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends -o Dpkg::Options::=--force-confold upgrade; "
           "apt-get clean; rm -rf /var/lib/apt/lists/*; "
           "elif command -v dnf >/dev/null 2>&1; then dnf -y upgrade --refresh; dnf clean all; "
           "elif command -v microdnf >/dev/null 2>&1; then microdnf -y upgrade; microdnf clean all; "
           "else echo 'HANGAR: aucun gestionnaire de paquets dans cette image (distroless ?)'; exit 3; fi")
_busy = set()


def of(slug):
    return (db.kv_get("image_patches") or {}).get(slug)


def active(a, version):
    p = of(a["slug"])
    return p if p and p.get("version") == version and a["source"] in ("image", "git") else None


def _set(slug, val):
    allv = db.kv_get("image_patches") or {}
    if val:
        allv[slug] = val
    else:
        allv.pop(slug, None)
    db.kv_set("image_patches", allv)


def forget(slug):
    _set(slug, None)


def busy(slug):
    return slug in _busy


def auto_default():
    return bool((db.kv_get("vuln_fix") or {}).get("auto"))


def set_auto_default(on):
    db.kv_set("vuln_fix", {"auto": bool(on)})


def mode(slug):
    return (db.kv_get("vuln_fix_apps") or {}).get(slug) or ""


def set_mode(slug, m):
    allv = db.kv_get("vuln_fix_apps") or {}
    if m in ("auto", "manuel"):
        allv[slug] = m
    else:
        allv.pop(slug, None)
    db.kv_set("vuln_fix_apps", allv)


def auto(slug):
    m = mode(slug)
    return m == "auto" if m else auto_default()


def last_try(slug):
    return (db.kv_get("image_patch_tries") or {}).get(slug)


def _try(slug, version, ok, msg):
    allv = db.kv_get("image_patch_tries") or {}
    allv[slug] = {"version": version, "ts": time.time(), "ok": ok, "msg": msg[:400]}
    db.kv_set("image_patch_tries", allv)


def _homes(a):
    from . import ha
    h = ha.get(a["slug"])
    return [a["node"] or P.LOCAL] + [n for n in (h["nodes"] if h else []) if n != (a["node"] or P.LOCAL)]


def _dockerfile(base, user):
    lines = [f"FROM {base}", "USER root", f"RUN {UPGRADE}"]
    if user and user not in ("root", "0", "0:0"):
        lines.append(f"USER {user}")
    lines.append(f'LABEL fr.hangar.patched-from="{base}"')
    return "\n".join(lines) + "\n"


def build(a):
    """Construit l'image dérivée sur chaque machine de l'appli. Retourne son nom. RuntimeError si impossible."""
    base = P.base_ref(a, a["version"])
    node = a["node"] or P.LOCAL
    rc, out = P.dk(node, "image", "inspect", "-f", "{{json .Config.User}}|{{json .RepoDigests}}", base, timeout=30)
    if rc:
        raise RuntimeError(f"image {base} absente de la machine")
    user_json, _, dig_json = out.strip().partition("|")
    user = json.loads(user_json or '""') or ""
    try:
        base_digests = [d.split("@", 1)[1] for d in json.loads(dig_json or "[]") if "@" in d]
    except ValueError:
        base_digests = []
    ref = f"hangar-patch/{a['slug']}:{P.safe_tag(a['version'])}-{time.strftime('%Y%m%d%H%M')}"
    df = _dockerfile(base, user)
    for n in _homes(a):
        if n != node:   # secours, instances : l'image d'origine doit y être aussi
            P.dk(n, "pull", "--quiet", base, timeout=900)
        rc, out = P.dk(n, "build", "--label", f"fr.hangar.app={a['slug']}", "-t", ref, "-",
                       input=df, timeout=1800)
        if rc:
            if "HANGAR: aucun gestionnaire" in out:
                raise RuntimeError("cette image n'a pas de gestionnaire de paquets (image « distroless ») : seule une "
                                   "nouvelle version de l'image peut corriger ses failles")
            raise RuntimeError(f"construction sur {n} impossible : {P.tail(out, 3)}")
    return ref, base, base_digests


def ensure_on(a, node):
    """Image corrigée présente sur cette machine (secours ou instance ajoutés après la correction) ; la construit sinon.
    Retourne True si elle y est (ou s'il n'y a pas de correction en place)."""
    p = active(a, a["version"])
    if not p:
        return True
    if P.dk(node, "image", "inspect", p["ref"], timeout=30)[0] == 0:
        return True
    base = p.get("base") or P.base_ref(a, a["version"])
    P.dk(node, "pull", "--quiet", base, timeout=900)
    rc, out = P.dk(node, "image", "inspect", "-f", "{{json .Config.User}}", base, timeout=30)
    user = json.loads(out or '""') if rc == 0 else ""
    rc, out = P.dk(node, "build", "--label", f"fr.hangar.app={a['slug']}", "-t", p["ref"], "-",
                   input=_dockerfile(base, user), timeout=1800)
    if rc:
        P.log("warn", a["slug"], f"image corrigée non construite sur {node} ({P.tail(out, 2)}) : une bascule y "
              "repartirait de l'image d'origine")
        return False
    allv = db.kv_get("image_patches") or {}
    if a["slug"] in allv:
        allv[a["slug"]]["nodes"] = sorted(set(allv[a["slug"]].get("nodes") or []) | {node})
        db.kv_set("image_patches", allv)
    P.log("info", a["slug"], f"image corrigée construite aussi sur {node}")
    return True


def apply(slug, by="Hangar"):
    """Construit et déploie l'image corrigée ; revient à l'originale si l'appli ne répond plus. Retourne (ok, message)."""
    a = db.app(slug)
    if not a or a["kind"] == "static" or slug in _busy:
        return False, "rien à faire"
    if a["state"] == "deploying":
        return False, "un déploiement est en cours"
    _busy.add(slug)
    version = a["version"]
    try:
        from . import vulns
        before = (vulns.of(slug) or {}).get("counts") or {}
        P.log("info", slug, f"correction des paquets système de l'image ({by}) : construction")
        try:
            ref, base, digests = build(a)
        except RuntimeError as e:
            _try(slug, version, False, str(e))
            P.log("error", slug, f"correction des paquets système impossible : {e}")
            return False, str(e)
        old = of(slug)
        _set(slug, {"version": version, "ref": ref, "base": base, "base_digests": digests, "ts": time.time(),
                    "nodes": _homes(a), "by": by})
        P.deploy(slug, version, "update")
        if db.app(slug)["state"] != "ok":
            _set(slug, old if old and old.get("version") == version else None)
            P.deploy(slug, version, "update")   # image d'avant (originale, ou correction précédente)
            msg = "l'appli ne répond plus avec l'image corrigée : image d'avant remise"
            _try(slug, version, False, msg)
            P.log("error", slug, f"correction des paquets système : {msg}")
            alerts.send(f"{a['name']} : correction des failles en échec", msg, priority=4, tags=["warning"])
            return False, msg
        t0 = time.time()
        while vulns.busy(slug) and time.time() - t0 < 1500:   # l'analyse lancée après le déploiement : on l'attend
            time.sleep(3)
        res = vulns.of(slug) or {}
        if res.get("ts", 0) < (of(slug) or {}).get("ts", 0):
            res = vulns.scan(slug) or {}
        after = res.get("counts") or {}
        msg = (f"image corrigée en ligne ({ref}) : critiques {before.get('CRITICAL', '?')} → {after.get('CRITICAL', '?')}, "
               f"élevées {before.get('HIGH', '?')} → {after.get('HIGH', '?')}")
        _try(slug, version, True, msg)
        P.log("ok", slug, msg)
        for n in (old or {}).get("nodes") or []:   # correction précédente : plus utilisée
            if old.get("ref") and old["ref"] != ref:
                P.dk(n, "image", "rm", old["ref"], timeout=120)
        return True, msg
    finally:
        _busy.discard(slug)


def maybe_auto(slug, res):
    """Après une analyse : correction automatique si réglée, s'il reste des failles système corrigeables, au plus une
    fois par jour et par version."""
    from . import vulns
    a = db.app(slug)
    if not a or not auto(slug) or a["desired"] != "running" or slug in _busy:
        return
    if not vulns.groups(res.get("items") or [])["os"]:
        return
    t = last_try(slug)
    if t and t["version"] == a["version"] and time.time() - t["ts"] < 86400:
        return
    P.spawn(apply, slug, "automatique")
