"""Vérifications après déploiement : en plus du healthcheck, quelques adresses de l'appli doivent répondre comme
prévu avant que la nouvelle version soit gardée. Sinon, le déploiement échoue et la version précédente revient.

Réglage kv « smoke » : {slug: "une vérification par ligne"}. Format d'une ligne :
    /chemin [code attendu] [texte attendu dans la réponse]
Code par défaut : 200. Dans le texte, {version} est remplacé par la version déployée.
Exemples :  /    ·    /api/v1/version 200 {version}    ·    /admin 302
"""
import re
import time
import urllib.error
import urllib.request

from . import db

MAX = 10
LINE = re.compile(r"^(/\S*)(?:\s+(\d{3}))?(?:\s+(.+))?$")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None   # une redirection est un résultat à vérifier, pas à suivre


def parse(text):
    """[{path, status, contains}] ; ValueError avec la ligne fautive."""
    out = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = LINE.match(line)
        if not m or len(line) > 300:
            raise ValueError(f"ligne illisible « {line[:60]} » (format : /chemin [code] [texte attendu])")
        st = int(m.group(2) or 200)
        if not 100 <= st <= 599:
            raise ValueError(f"code HTTP invalide : {st}")
        out.append({"path": m.group(1), "status": st, "contains": (m.group(3) or "").strip()})
    if len(out) > MAX:
        raise ValueError(f"{MAX} vérifications au plus")
    return out


def text_of(slug):
    return (db.kv_get("smoke") or {}).get(slug, "")


def save(slug, text):
    parse(text)
    allv = db.kv_get("smoke") or {}
    if text.strip():
        allv[slug] = "\n".join(l.rstrip() for l in text.strip().splitlines())
    else:
        allv.pop(slug, None)
    db.kv_set("smoke", allv)


def run(a, version, host=None, tries=3):
    """(ok, résultats) : chaque vérification sur l'instance qui vient de démarrer (port local de l'appli)."""
    from . import platform as P
    checks = parse(text_of(a["slug"]))
    if not checks:
        return True, []
    base = f"http://{P.app_host(a)}:{a['host_port']}"
    opener = urllib.request.build_opener(_NoRedirect)
    results = []
    for c in checks:
        want = c["contains"].replace("{version}", version)
        got, why = None, ""
        for i in range(tries):
            req = urllib.request.Request(base + c["path"], headers={"X-Forwarded-Proto": "https",
                                                                    "User-Agent": "Hangar-verification"})
            if host:
                req.add_header("Host", host)
            try:
                with opener.open(req, timeout=10) as r:
                    got, body = r.status, r.read(512 * 1024).decode(errors="replace")
            except urllib.error.HTTPError as e:
                got, body = e.code, e.read(512 * 1024).decode(errors="replace") if e.fp else ""
            except Exception as e:
                got, body, why = None, "", str(getattr(e, "reason", e))[:120]
            ok = got == c["status"] and (not want or want in body)
            if ok:
                break
            if got is not None and got != c["status"]:
                why = f"code {got} au lieu de {c['status']}"
            elif got is not None:
                why = f"« {want[:60]} » absent de la réponse"
            if i < tries - 1:
                time.sleep(2)
        results.append({**c, "ok": ok, "got": got, "why": "" if ok else why})
    return all(r["ok"] for r in results), results


def summary(results):
    bad = [r for r in results if not r["ok"]]
    if not bad:
        return f"{len(results)} vérification(s) réussie(s)"
    return "vérification en échec : " + " ; ".join(f"{r['path']} ({r['why']})" for r in bad)
