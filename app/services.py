"""Services ajoutés à une appli, dans son propre compose et sur son réseau cloisonné.

Redis (image Valkey, compatible Redis) : persistant (AOF + instantanés) dans data/.hangar-redis, donc sauvegardé,
restauré, déplacé et copié vers un secours avec data/. Mot de passe aléatoire ; l'appli reçoit REDIS_URL.

Haute dispo :
- secours à chaud : Redis suit l'appli ; sa copie part avec data/ vers le secours (toutes les quelques minutes) et
  redémarre avec l'appli en cas de bascule (on perd au plus les dernières minutes d'écritures) ;
- instances multiples : un seul Redis, sur le nœud principal, publié sur son adresse du réseau privé (port de l'appli
  + 20000) ; les instances des autres nœuds s'y connectent (port ouvert à cette appli seulement, segment.py). Si le
  nœud principal tombe, la bascule le recrée sur le nouveau nœud principal, vide.
Réglage kv « app_services » : {slug: {"redis": {"mem": Mo, "password": "..."}}}.
"""
import secrets

from . import db

REDIS_IMAGE = "valkey/valkey:8-alpine"
REDIS_DIR = ".hangar-redis"
PORT_OFFSET = 20000   # Redis partagé des instances multiples : port de l'appli + 20000 (base dédiée : + 10000)


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
    svc = of(slug)
    cur = svc.get("redis") or {}
    svc["redis"] = {"mem": mem, "password": cur.get("password") or secrets.token_hex(24)}
    _save(slug, svc)
    _seg_push(slug)


def disable_redis(slug):
    svc = of(slug)
    svc.pop("redis", None)
    _save(slug, svc)
    _seg_push(slug)


def shared_port(slug):
    """Port du Redis partagé (instances multiples), sur l'adresse privée du nœud principal ; sinon None."""
    from . import ha
    h, a = ha.get(slug), db.app(slug)
    if not redis(slug) or not h or h["mode"] != "replicas" or not a:
        return None
    return a["host_port"] + PORT_OFFSET


def _seg_push(slug):
    from . import ha
    h = ha.get(slug)
    if h and h["mode"] == "replicas":   # port du Redis partagé ouvert (ou refermé) pour cette appli
        from . import segment
        for e in segment.push_all():
            from . import platform as P
            P.log("warn", slug, e)


def drop(slug):
    _save(slug, {})


def compose_extra(a, net, data_dir, instance=None):
    """(services à ajouter au compose, variables à donner à l'appli). `instance` : compose d'une instance
    supplémentaire (haute dispo) ; elle utilise le Redis du nœud principal."""
    r = redis(a["slug"])
    if not r:
        return {}, {}
    from . import platform as P
    port = shared_port(a["slug"])
    if instance is not None:
        main = db.app(a["slug"])["node"]
        if not port:   # secours à chaud : pas d'instance qui tourne en même temps
            return {}, {}
        return {}, {"REDIS_URL": f"redis://:{r['password']}@{P.node_wg(main)}:{port}/0"}
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
    if port:   # partagé avec les instances des autres nœuds : publié sur le réseau privé seulement
        svc["ports"] = [f"{P.node_wg(a['node'])}:{port}:6379"]
    return {"redis": svc}, {"REDIS_URL": f"redis://:{r['password']}@redis:6379/0"}
