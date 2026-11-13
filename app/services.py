"""Services ajoutés à une appli, dans son propre compose et sur son réseau cloisonné.

Redis (image Valkey, compatible Redis) : persistant (AOF + instantanés) dans data/.hangar-redis, donc sauvegardé,
restauré, déplacé et copié vers un secours avec data/. Mot de passe aléatoire ; l'appli reçoit REDIS_URL.
Réglage kv « app_services » : {slug: {"redis": {"mem": Mo, "password": "..."}}}.
"""
import secrets

from . import db

REDIS_IMAGE = "valkey/valkey:8-alpine"
REDIS_DIR = ".hangar-redis"


def of(slug):
    return (db.kv_get("app_services") or {}).get(slug) or {}


def _save(slug, svc):
    allv = db.kv_get("app_services") or {}
    if svc:
        allv[slug] = svc
    else:
        allv.pop(slug, None)
    db.kv_set("app_services", allv)


def redis(slug):
    return of(slug).get("redis")


def enable_redis(slug, mem):
    mem = int(mem)
    if not 32 <= mem <= 4096:
        raise ValueError("mémoire de Redis : entre 32 et 4096 Mo")
    from . import ha
    if ha.get(slug):
        raise ValueError("Redis n'est pas encore possible avec la haute disponibilité (chaque instance aurait le sien)")
    svc = of(slug)
    cur = svc.get("redis") or {}
    svc["redis"] = {"mem": mem, "password": cur.get("password") or secrets.token_hex(24)}
    _save(slug, svc)


def disable_redis(slug):
    svc = of(slug)
    svc.pop("redis", None)
    _save(slug, svc)


def drop(slug):
    _save(slug, {})


def compose_extra(a, net, data_dir):
    """(services à ajouter au compose, variables à donner à l'appli)."""
    r = redis(a["slug"])
    if not r:
        return {}, {}
    mem = int(r["mem"])
    svc = {
        "image": REDIS_IMAGE,
        "restart": "unless-stopped",
        # le point d'entrée de l'image donne le dossier à l'utilisateur valkey puis abandonne root
        "command": ["valkey-server", "--dir", "/data", "--appendonly", "yes", "--save", "300 10",
                    "--requirepass", r["password"], "--maxmemory", f"{max(16, mem - 16)}mb",
                    "--maxmemory-policy", "noeviction", "--protected-mode", "no"],
        "networks": [net],
        "volumes": [f"{data_dir}/{REDIS_DIR}:/data"],
        "mem_limit": f"{mem}m",
        "security_opt": ["no-new-privileges:true"],
        "cap_drop": ["NET_RAW", "MKNOD", "SYS_CHROOT", "SETFCAP", "AUDIT_WRITE"],
        "pids_limit": 256,
        "labels": {"fr.hangar.service": "redis", "fr.hangar.of": a["slug"]},
    }
    return {"redis": svc}, {"REDIS_URL": f"redis://:{r['password']}@redis:6379/0"}
