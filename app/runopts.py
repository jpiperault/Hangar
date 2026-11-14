"""Démarrage du conteneur d'une appli : point d'entrée et commande à la place de ceux de l'image, et santé par
commande (pour un service sans page web : « redis-cli ping », « pg_isready », un script maison…).

Réglage kv « app_run » : {slug: {"entrypoint": "...", "command": "...", "health_cmd": "..."}}.
- entrypoint et command : découpés comme dans un shell (guillemets compris), puis passés en liste à Docker :
  aucune interprétation par un shell, rien ne peut casser le fichier compose.
- health_cmd : lancée dans le conteneur par Docker (CMD-SHELL) toutes les 15 s ; 3 échecs → « unhealthy ».
  Pour une appli sans page web, le déploiement attend « healthy » et la supervision alerte sur « unhealthy ».
"""
import shlex

from . import db

KEY = "app_run"
MAX = 1000
FIELDS = ("entrypoint", "command", "health_cmd")
HEALTH = {"interval": "15s", "timeout": "10s", "retries": 3, "start_period": "60s"}


def of(slug):
    return (db.kv_get(KEY) or {}).get(slug) or {}


def _check(name, v):
    if len(v) > MAX:
        raise ValueError(f"{name} : {MAX} caractères au plus")
    if any(c in v for c in "\0\r\n"):
        raise ValueError(f"{name} : une seule ligne")
    return v


def split(name, v):
    try:
        return shlex.split(v)
    except ValueError as e:
        raise ValueError(f"{name} : {e} (guillemet non fermé ?)")


def save(slug, f):
    """f : formulaire (entrypoint, command, health_cmd). ValueError si invalide. Retourne True si changé."""
    new = {}
    labels = {"entrypoint": "point d'entrée", "command": "commande", "health_cmd": "commande de santé"}
    for k in FIELDS:
        v = _check(labels[k], (f.get(k) or "").strip())
        if v:
            if k != "health_cmd":
                split(labels[k], v)
            new[k] = v
    allv = db.kv_get(KEY) or {}
    if allv.get(slug, {}) == new:
        return False
    if new:
        allv[slug] = new
    else:
        allv.pop(slug, None)
    db.kv_set(KEY, allv)
    return True


def restore(slug, old):
    """Remet un réglage d'avant (retour automatique après un déploiement en échec)."""
    allv = db.kv_get(KEY) or {}
    if old:
        allv[slug] = old
    else:
        allv.pop(slug, None)
    db.kv_set(KEY, allv)


def drop(slug):
    allv = db.kv_get(KEY) or {}
    if allv.pop(slug, None) is not None:
        db.kv_set(KEY, allv)


def apply(slug, svc):
    """Ajoute entrypoint, command et healthcheck au service compose."""
    o = of(slug)

    def esc(x):   # compose remplace $VAR lui-même : $$ laisse passer un $ tel quel jusqu'au conteneur
        return x.replace("$", "$$")
    if o.get("entrypoint"):
        svc["entrypoint"] = [esc(x) for x in split("point d'entrée", o["entrypoint"])]
    if o.get("command"):
        svc["command"] = [esc(x) for x in split("commande", o["command"])]
    if o.get("health_cmd"):
        svc["healthcheck"] = {"test": ["CMD-SHELL", esc(o["health_cmd"])], **HEALTH}
    return svc


def has_health(slug):
    return bool(of(slug).get("health_cmd"))
