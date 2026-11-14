"""Droits par appli : un compte « appli » ne voit que les applis qu'on lui donne, chacune en lecture (« voir ») ou avec
le droit de la redéployer (« deployer » : démarrer, arrêter, redémarrer, déployer une version, revenir en arrière).
Il garde son mot de passe et sa double authentification. Le reste de la console lui est fermé.
Réglage kv « user_apps » : {compte: {appli: "voir" | "deployer"}}.
"""
import re

from . import db

ROLE = "appli"
ROLES = {"admin": "administrateur", "lecture": "lecture seule", ROLE: "applis choisies"}
LEVELS = {"voir": "voir", "deployer": "voir et redéployer"}
DEPLOY = ("start", "restart", "stop", "version", "rollback")
APP_RE = re.compile(r"^/apps/([a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?)(/.*)?$")
ACT_RE = re.compile(r"^/apps/([a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?)/(" + "|".join(DEPLOY) + ")$")


def scopes(username):
    return (db.kv_get("user_apps") or {}).get(username) or {}


def set_scopes(username, sc):
    allv = db.kv_get("user_apps") or {}
    sc = {k: v for k, v in (sc or {}).items() if v in LEVELS}
    if sc:
        allv[username] = sc
    else:
        allv.pop(username, None)
    db.kv_set("user_apps", allv)


def forget_user(username):
    set_scopes(username, {})


def forget_app(slug):
    allv = db.kv_get("user_apps") or {}
    for u in list(allv):
        allv[u].pop(slug, None)
    db.kv_set("user_apps", {u: v for u, v in allv.items() if v})


def can_deploy(role, username, slug):
    if role == "admin":
        return True
    return role == ROLE and scopes(username).get(slug) == "deployer"


def visible(role, username, slug):
    return role != ROLE or slug in scopes(username)


def refused(method, path, username):
    """Message de refus pour un compte « appli », sinon None."""
    if path == "/logout" or path == f"/users/{username}/password" or path.startswith(f"/users/{username}/2fa/"):
        return None
    sc = scopes(username)
    if method in ("GET", "HEAD", "OPTIONS"):
        if path in ("/", "/compte"):
            return None
        m = APP_RE.match(path)
        if m and m.group(1) in sc and not path.endswith(("/download", "/db/export")):
            return None
        return "Ce compte n'a pas accès à cette page."
    m = ACT_RE.match(path)
    if m and sc.get(m.group(1)) == "deployer":
        return None
    return "Ce compte n'a pas le droit de faire cette action."
