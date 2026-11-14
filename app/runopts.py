"""Démarrage du conteneur d'une appli : point d'entrée et commande à la place de ceux de l'image, et santé par
commande (pour un service sans page web : « redis-cli ping », « pg_isready », un script maison…).

Dossiers persistants ailleurs que /data (« mounts ») : « www:/var/www/html » monte data/www sur /var/www/html,
pour les images qui gardent leurs données ailleurs (WordPress…). Sauvegardés, restaurés et déplacés avec data/.
Réglage kv « app_run » : {slug: {"entrypoint": "...", "command": "...", "health_cmd": "...", "mounts": "..."}}.
- entrypoint et command : découpés comme dans un shell (guillemets compris), puis passés en liste à Docker :
  aucune interprétation par un shell, rien ne peut casser le fichier compose.
- health_cmd : lancée dans le conteneur par Docker (CMD-SHELL) toutes les 15 s ; 3 échecs → « unhealthy ».
  Pour une appli sans page web, le déploiement attend « healthy » et la supervision alerte sur « unhealthy ».
"""
import re
import shlex

from . import db

KEY = "app_run"
MAX = 1000
FIELDS = ("entrypoint", "command", "health_cmd", "mounts")
SUB_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,30}$")
PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]{1,200}$")
FORBIDDEN = ("/", "/data", "/proc", "/sys", "/dev", "/etc", "/bin", "/sbin", "/usr", "/lib", "/run", "/tmp")


def parse_mounts(v):
    """« www:/var/www/html, conf:/etc/app » → [(sous-dossier de data/, chemin dans le conteneur)]."""
    out = []
    for item in [x.strip() for x in re.split(r"[,\s]+", v or "") if x.strip()]:
        sub, _, path = item.partition(":")
        path = path.rstrip("/") or "/"
        if not SUB_RE.match(sub) or sub.startswith(".hangar"):
            raise ValueError(f"dossiers : « {item[:60]} » : il faut sous-dossier:chemin, par exemple www:/var/www/html")
        if not PATH_RE.match(path) or ".." in path.split("/") or path in FORBIDDEN:
            raise ValueError(f"dossiers : chemin « {path[:60]} » refusé")
        if any(p == path for _, p in out):
            raise ValueError(f"dossiers : {path} donné deux fois")
        out.append((sub, path))
    if len(out) > 10:
        raise ValueError("dossiers : 10 au plus")
    return out
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
    labels = {"entrypoint": "point d'entrée", "command": "commande", "health_cmd": "commande de santé",
              "mounts": "dossiers"}
    for k in FIELDS:
        v = _check(labels[k], (f.get(k) or "").strip())
        if v:
            if k == "mounts":
                v = ", ".join(f"{a}:{b}" for a, b in parse_mounts(v))
            elif k != "health_cmd":
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


def apply(slug, svc, data_dir=None):
    """Ajoute entrypoint, command, healthcheck et dossiers persistants au service compose."""
    o = of(slug)
    if o.get("mounts") and data_dir:
        svc["volumes"] += [f"{data_dir}/{sub}:{path}" for sub, path in parse_mounts(o["mounts"])]

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
