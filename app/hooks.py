"""Publication automatique par webhook (GitHub, et tout outil compatible : Gitea, Forgejo, GitLab, un script de CI).

Adresse publique (Caddy → serveur interne de la console, port 8099, comme les rapports de plantage) :
  https://<adresse de l'appli>/.well-known/hangar/hook            (appli avec un sous-domaine)
  https://<hub>.<domaine>/.well-known/hangar/hook/<appli>         (toujours possible si le domaine a un hub)

Authentification : en-tête X-Hub-Signature-256 (HMAC-SHA256 du corps avec le secret de l'appli : GitHub, Gitea,
Forgejo), ou X-Gitlab-Token égal au secret. Chaque livraison (X-GitHub-Delivery…) n'est acceptée qu'une fois.

Ce que fait un envoi valide :
- site statique construit depuis Git : un push sur sa branche → construction et publication ;
- appli en image : « package / registry_package » publié (tag) → déploiement de ce tag s'il est plus récent, ou
  redéploiement si c'est le tag en ligne (latest, main…) ; « workflow_run » réussi → déploiement de la version la plus
  récente du registre (ou nouveau tirage du tag en ligne) ; corps {"version": "1.4.0"} (script de CI) → ce tag ;
  un push seul est ignoré (l'image n'est pas encore construite).
Réglage kv « hooks » : {slug: {"secret": "...", "seen": [ids], "last": {ts, event, result, ok}}}.
"""
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import urllib.parse

from . import db
from . import domains as D
from . import platform as P

MAX_BODY = 1024 ** 2
PATH = "/.well-known/hangar/hook"
_lock = threading.Lock()


def _all():
    return db.kv_get("hooks") or {}


def of(slug):
    return _all().get(slug)


def enable(slug):
    with _lock:
        h = _all()
        h[slug] = {"secret": secrets.token_hex(24), "seen": [], "last": None}
        db.kv_set("hooks", h)
    return h[slug]


def disable(slug):
    with _lock:
        h = _all()
        if h.pop(slug, None) is not None:
            db.kv_set("hooks", h)


def has_sub(slug):
    return any(r["kind"] == "sub" for r in D.routes(slug))


def url(slug):
    """Adresse à donner à GitHub (None si l'appli n'a aucune adresse publique utilisable)."""
    doms = D.by_name()
    for r in D.routes(slug):
        if r["kind"] == "sub":
            return f"https://{D.host_of(r, doms)}{PATH}"
    for r in D.routes(slug):
        h = D.host_of(r, doms)
        if h:
            return f"https://{h}{PATH}/{slug}"
    hub = next((d for d in D.all_domains() if d["hub"]), None)
    return f"https://{hub['hub']}.{hub['name']}{PATH}/{slug}" if hub else None


def _record(slug, event, result, ok, delivery=None):
    with _lock:
        h = _all()
        if slug not in h:
            return
        if delivery:
            h[slug]["seen"] = ([delivery] + (h[slug].get("seen") or []))[:100]
        h[slug]["last"] = {"ts": time.time(), "event": event, "result": result[:300], "ok": ok}
        db.kv_set("hooks", h)


def _signed(cfg, headers, body):
    sig = headers.get("X-Hub-Signature-256") or ""
    if sig:
        want = "sha256=" + hmac.new(cfg["secret"].encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig.strip(), want)
    tok = headers.get("X-Gitlab-Token") or ""
    return bool(tok) and hmac.compare_digest(tok.strip(), cfg["secret"])


def _payload(headers, body):
    ctype = (headers.get("Content-Type") or "").split(";")[0].strip().lower()
    raw = body.decode("utf-8", "replace")
    if ctype == "application/x-www-form-urlencoded":   # GitHub, si « Content type » est resté sur form
        raw = (urllib.parse.parse_qs(raw).get("payload") or ["{}"])[0]
    data = json.loads(raw or "{}")
    if not isinstance(data, dict):
        raise ValueError
    return data


TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _event(headers, data):
    ev = (headers.get("X-GitHub-Event") or headers.get("X-Gitea-Event") or headers.get("X-Forgejo-Event")
          or headers.get("X-Gitlab-Event") or "").strip().lower()
    if ev in ("push hook", "tag push hook"):
        return "push"
    if ev == "pipeline hook":
        return "workflow_run"
    if not ev and "version" in data:
        return "deploy"
    return ev or "inconnu"


def _package_tag(data):
    pkg = data.get("package") or data.get("registry_package") or {}
    pv = pkg.get("package_version") or {}
    tag = ((pv.get("container_metadata") or {}).get("tag") or {}).get("name") or pv.get("version") or ""
    return pkg.get("name") or "", tag


def _deploy_image(a, tag, why):
    """Déploie `tag` (plus récent) ou redéploie s'il est en ligne. Retourne (code, texte)."""
    from . import registry
    if not TAG_RE.match(tag or "") or tag.startswith("sha256"):
        return 200, f"tag « {tag[:60]} » ignoré"
    cur = a["version"]
    if tag != cur:
        if registry.semver(cur) and registry.semver(tag) and registry.newest([tag], cur) is None:
            return 200, f"{tag} n'est pas plus récent que {cur} : rien à faire"
        if not registry.semver(tag) and registry.semver(cur):
            return 200, f"tag « {tag} » non numéroté, l'appli suit des versions x.y.z : ignoré"
    P.spawn(P.deploy, a["slug"], tag, "update")
    P.log("info", a["slug"], f"webhook ({why}) : déploiement de {tag}" if tag != cur else
          f"webhook ({why}) : nouveau tirage de {tag}")
    return 202, f"déploiement de {tag} lancé"


def handle(slug, headers, body, ip=""):
    """Traite un envoi. Retourne (code HTTP, texte)."""
    a, cfg = db.app(slug), of(slug)
    if not a or not cfg:
        return 404, "webhook inconnu"
    if not _signed(cfg, headers, body):
        return 403, "signature refusée"
    delivery = (headers.get("X-GitHub-Delivery") or headers.get("X-Gitea-Delivery")
                or headers.get("X-Gitlab-Event-UUID") or "")[:80]
    if delivery and delivery in (cfg.get("seen") or []):
        return 200, "déjà reçu"
    try:
        data = _payload(headers, body)
    except ValueError:
        return 400, "JSON attendu"
    ev = _event(headers, data)
    try:
        code, text = _dispatch(a, ev, data)
    except Exception as e:
        code, text = 500, f"erreur : {str(e)[:200]}"
    _record(slug, ev, text, code < 300, delivery)
    if code >= 300 or code == 202:
        P.log("info" if code < 300 else "warn", slug, f"webhook {ev} : {text}")
    return code, text


def _dispatch(a, ev, data):
    from . import kinds, monitor, registry, sites
    slug = a["slug"]
    if ev == "ping":
        return 200, "pong"
    if a["state"] == "deploying" or (kinds.static(a["kind"]) and sites.busy(slug)):
        return 409, "déploiement déjà en cours, renvoie plus tard"
    if kinds.static(a["kind"]):
        g = sites.meta(slug)["git"]
        if not g:
            return 409, "site sans dépôt Git réglé dans sa fiche"
        if ev != "push":
            return 200, f"événement {ev} ignoré (un push suffit)"
        ref = data.get("ref") or ""
        if ref != f"refs/heads/{g['branch']}":
            return 200, f"{ref or 'référence inconnue'} ignoré (branche suivie : {g['branch']})"
        if data.get("deleted"):
            return 200, "branche supprimée : rien à publier"
        P.spawn(sites.build_git, slug)
        sha = (data.get("after") or "")[:7]
        return 202, f"construction de {g['branch']}{'@' + sha if sha else ''} lancée"
    if a["source"] != "image":
        return 409, "seules les applis en image et les sites statiques se publient par webhook"
    if ev == "deploy":
        return _deploy_image(a, str(data.get("version") or ""), "script")
    if ev in ("package", "registry_package"):
        if (data.get("action") or "published") not in ("published", "updated", "create"):
            return 200, f"action {data.get('action')} ignorée"
        name, tag = _package_tag(data)
        repo = registry.split(a["image"])[1].lower()
        if name and repo != name.lower() and not repo.endswith("/" + name.lower()):
            return 200, f"paquet {name} ignoré (l'appli utilise {a['image']})"
        return _deploy_image(a, tag, "paquet publié")
    if ev == "workflow_run":
        run = data.get("workflow_run") or data.get("object_attributes") or {}
        if (data.get("action") or "completed") != "completed" or (run.get("conclusion") or run.get("status")) not in ("success",):
            return 200, "workflow pas (encore) réussi : rien à faire"
        if registry.semver(a["version"]):
            monitor.check_versions(slug)
            latest = (db.app(slug) or {}).get("latest_version")
            if not latest:
                return 200, f"{a['version']} est déjà la version la plus récente du registre"
            return _deploy_image(a, latest, "workflow réussi")
        return _deploy_image(a, a["version"], "workflow réussi")
    if ev == "push":
        return 200, "push ignoré pour une appli en image : abonne le webhook à « Workflow runs » ou « Packages »"
    return 200, f"événement {ev} ignoré"


def caddy_hub_lines(coll):
    return ["\t# webhooks de publication (hooks.py) : serveur interne de la console",
            f"\thandle {PATH}/* {{", "\t\trequest_body {", "\t\t\tmax_size 1MB", "\t\t}",
            f"\t\treverse_proxy {coll} {{", "\t\t\theader_up X-Real-IP {client_ip}", "\t\t}", "\t}"]


def caddy_app_lines(slug, coll):
    if not of(slug):
        return []
    return [f"\thandle {PATH} {{", "\t\trequest_body {", "\t\t\tmax_size 1MB", "\t\t}",
            f"\t\trewrite * {PATH}/{slug}",
            f"\t\treverse_proxy {coll} {{", "\t\t\theader_up X-Real-IP {client_ip}", "\t\t}", "\t}"]


def forget(slug):
    disable(slug)
