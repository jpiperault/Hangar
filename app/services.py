"""Services ajoutés à une appli, dans son propre compose et sur son réseau cloisonné.

Redis (image Valkey, compatible Redis) : persistant (AOF + instantanés) dans data/.hangar-redis, donc sauvegardé,
restauré, déplacé et copié vers un secours avec data/. Mot de passe aléatoire ; l'appli reçoit REDIS_URL.

Haute dispo :
- secours à chaud : Redis suit l'appli ; sa copie part avec data/ vers le secours (toutes les quelques minutes) et
  redémarre avec l'appli en cas de bascule (on perd au plus les dernières minutes d'écritures) ;
- instances multiples : un seul Redis, sur le nœud principal, publié sur son adresse du réseau privé (port de l'appli
  + 20000) ; les instances des autres nœuds s'y connectent (port ouvert à cette appli seulement, segment.py). Si le
  nœud principal tombe, la bascule le recrée sur le nouveau nœud principal, vide.
MySQL / MariaDB (au choix) : une base propre à l'appli, hôte « mysql », port 3306, base et utilisateur « app ».
- Ses fichiers bruts vivent hors de data/ (/srv/apps/<appli>/mysql) : jamais sauvegardés, car incohérents copiés
  pendant qu'elle tourne. À la place, un export cohérent (mariadb-dump / mysqldump --single-transaction) est écrit dans
  data/.hangar-mysql/dump.sql.gz avant chaque sauvegarde, archive, point de restauration, copie vers la préprod ou
  déplacement (fresh_dump).
- Ce dossier est aussi le dossier d'initialisation de l'image : quand data/ est remplacé (restauration, import,
  déplacement), les fichiers bruts sont effacés (reset) et la base repart de l'export, toute seule, au démarrage.
- Pas de haute dispo pour l'instant (la copie vers un secours se fait fichier par fichier).
Réglage kv « app_services » : {slug: {"redis": {"mem": Mo, "password": "..."},
                                       "mysql": {"engine": "mariadb"|"mysql", "mem": Mo, "password", "root"}}}.
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
    svcs, env = _redis_extra(a, net, data_dir, instance)
    env.update(mail_env(a["slug"]))   # relais e-mail : sur chaque instance
    if mysql(a["slug"]) and instance is None:
        svcs["mysql"] = _mysql_service(a, net, data_dir)
        env.update(mysql_env(a["slug"]))
    return svcs, env


def _redis_extra(a, net, data_dir, instance=None):
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


# ---------------------------------------------------------------- MySQL / MariaDB

ENGINES = {"mariadb": {"name": "MariaDB 11.4", "image": "mariadb:11.4", "dump": "mariadb-dump",
                       "health": ["CMD", "healthcheck.sh", "--connect", "--innodb_initialized"]},
           "mysql": {"name": "MySQL 8.4", "image": "mysql:8.4", "dump": "mysqldump",
                     "health": ["CMD-SHELL", "mysqladmin ping -h 127.0.0.1 -uroot -p\"$$MYSQL_ROOT_PASSWORD\" --silent"]}}
MYSQL_DIR = ".hangar-mysql"     # dans data/ : l'export, et le dossier d'initialisation de l'image
DUMP = f"{MYSQL_DIR}/dump.sql.gz"


def mysql(slug):
    return of(slug).get("mysql")


def mysql_raw(slug):
    from . import platform as P
    return f"{P.app_dir(slug)}/mysql"


def enable_mysql(slug, engine, mem):
    mem = int(mem)
    if engine not in ENGINES:
        raise ValueError("moteur inconnu")
    if not 128 <= mem <= 8192:
        raise ValueError("mémoire de la base : entre 128 et 8192 Mo")
    from . import ha
    if ha.get(slug):
        raise ValueError("MySQL / MariaDB n'est pas encore compatible avec la haute dispo : retire-la d'abord")
    svc = of(slug)
    cur = svc.get("mysql") or {}
    if cur and cur["engine"] != engine:
        raise ValueError("changer de moteur ferait perdre la base : retire-la d'abord (son export reste dans data/)")
    svc["mysql"] = {"engine": engine, "mem": mem, "password": cur.get("password") or secrets.token_hex(20),
                    "root": cur.get("root") or secrets.token_hex(20)}
    _save(slug, svc)


def disable_mysql(slug):
    svc = of(slug)
    svc.pop("mysql", None)
    _save(slug, svc)


def mysql_env(slug):
    m = mysql(slug)
    if not m:
        return {}
    return {"MYSQL_HOST": "mysql", "MYSQL_PORT": "3306", "MYSQL_DATABASE": "app", "MYSQL_USER": "app",
            "MYSQL_PASSWORD": m["password"], "MYSQL_URL": f"mysql://app:{m['password']}@mysql:3306/app"}


def _mysql_service(a, net, data_dir):
    m = mysql(a["slug"])
    e = ENGINES[m["engine"]]
    mem = int(m["mem"])
    pool = max(32, mem // 2)
    return {
        "image": e["image"],
        "restart": "unless-stopped",
        "command": [f"--innodb-buffer-pool-size={pool}M", "--skip-name-resolve", "--character-set-server=utf8mb4",
                    "--collation-server=utf8mb4_unicode_ci", "--max-connections=100"],
        "environment": {"MYSQL_ROOT_PASSWORD": m["root"], "MYSQL_DATABASE": "app", "MYSQL_USER": "app",
                        "MYSQL_PASSWORD": m["password"]},
        "networks": [net],
        "volumes": [f"{mysql_raw(a['slug'])}:/var/lib/mysql", f"{data_dir}/{MYSQL_DIR}:/docker-entrypoint-initdb.d:ro"],
        "mem_limit": f"{mem}m",
        "security_opt": ["no-new-privileges:true"],
        "cap_drop": ["NET_RAW", "MKNOD", "SYS_CHROOT", "SETFCAP", "AUDIT_WRITE"],
        "pids_limit": 512,
        # start_period long : un gros export peut mettre longtemps à se recharger ; « healthy » dès qu'elle répond
        "healthcheck": {"test": e["health"], "interval": "5s", "timeout": "5s", "retries": 6, "start_period": "1500s",
                        "start_interval": "3s"},
        "labels": {"fr.hangar.service": "mysql", "fr.hangar.of": a["slug"]},
    }


def fresh_dump(a, quiet=False):
    """Export cohérent de la base MySQL/MariaDB de l'appli dans data/.hangar-mysql/dump.sql.gz, sur son nœud.
    Sans effet si l'appli n'en a pas, ou si la base ne tourne pas (l'export précédent reste). RuntimeError si l'export
    échoue."""
    m = mysql(a["slug"])
    if not m:
        return False
    from . import platform as P
    name = f"app-{a['slug']}-mysql-1"
    rc, st = P.dk(a["node"], "inspect", "-f", "{{.State.Status}}", name, timeout=20)
    if rc or st.strip() != "running":
        if not quiet:
            P.log("warn", a["slug"], "base MySQL/MariaDB arrêtée : l'export précédent est gardé")
        return False
    d = f"{P.app_dir(a['slug'])}/data/{MYSQL_DIR}"
    tool = ENGINES[m["engine"]]["dump"]
    extra = " --set-gtid-purged=OFF" if m["engine"] == "mysql" else ""
    cmd = (f"set -o pipefail; install -d -m 0755 {d} && docker exec {name} sh -c 'MYSQL_PWD=\"$MYSQL_ROOT_PASSWORD\" "
           f"{tool} -uroot --single-transaction --routines --events --triggers --hex-blob{extra} --databases app' "
           f"| gzip > {d}/.dump.tmp && chmod 0644 {d}/.dump.tmp && mv {d}/.dump.tmp {d}/dump.sql.gz")
    rc, out = P.nsh(a["node"], f"bash -c {_q(cmd)}", timeout=3600)
    if rc:
        P.nsh(a["node"], f"rm -f {d}/.dump.tmp", timeout=30)
        raise RuntimeError(f"export de la base MySQL/MariaDB de {a['slug']} impossible : " + P.tail(out, 2))
    return True


def _q(s):
    import shlex
    return shlex.quote(s)


def reset_mysql(a, node=None):
    """Efface les fichiers bruts : au prochain démarrage, la base repart de data/.hangar-mysql (export)."""
    if not mysql(a["slug"]):
        return
    from . import platform as P
    P.nsh(node or a["node"], f"rm -rf {mysql_raw(a['slug'])}", timeout=300)


def mysql_state(a):
    m = mysql(a["slug"])
    if not m:
        return None
    from . import platform as P
    name = f"app-{a['slug']}-mysql-1"
    rc, st = P.dk(a["node"], "inspect", "-f", "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}",
                  name, timeout=20)
    if rc:
        return {"state": "absent"}
    parts = st.split()
    out = {"state": parts[0], "health": parts[1] if len(parts) > 1 else ""}
    rc, dump = P.nsh(a["node"], f"stat -c '%s %Y' {P.app_dir(a['slug'])}/data/{DUMP} 2>/dev/null", timeout=20)
    if rc == 0 and dump.strip():
        size, ts = dump.split()[:2]
        out.update(dump_size=int(size), dump_ts=float(ts))
    return out


# ---------------------------------------------------------------- relais e-mail

def relay():
    """Compte SMTP partagé par les applis qui envoient des e-mails (kv « mail_relay »), ou None s'il n'est pas réglé."""
    r = db.kv_get("mail_relay") or {}
    return r if r.get("host") else None


def save_relay(cfg):
    db.kv_set("mail_relay", cfg or None)


def mail(slug):
    return of(slug).get("mail")


def enable_mail(slug, sender):
    from . import alerts
    if not relay():
        raise ValueError("règle d'abord le relais e-mail (Système et alertes)")
    sender = (sender or "").strip()
    if not alerts.MAIL_RE.match(sender):
        raise ValueError("adresse d'expéditeur invalide, par exemple noreply@exemple.fr")
    svc = of(slug)
    svc["mail"] = {"from": sender}
    _save(slug, svc)


def disable_mail(slug):
    svc = of(slug)
    svc.pop("mail", None)
    _save(slug, svc)


def mail_env(slug):
    m, r = mail(slug), relay()
    if not m or not r:
        return {}
    sec = r.get("security") or "starttls"
    return {"SMTP_HOST": r["host"], "SMTP_PORT": str(r.get("port") or 587), "SMTP_USER": r.get("user") or "",
            "SMTP_USERNAME": r.get("user") or "", "SMTP_PASSWORD": r.get("password") or "", "SMTP_SECURE": sec,
            "SMTP_TLS": "true" if sec == "ssl" else "false", "SMTP_STARTTLS": "true" if sec == "starttls" else "false",
            "SMTP_FROM": m["from"], "MAIL_FROM": m["from"]}


def mail_users():
    return [slug for slug, v in (db.kv_get("app_services") or {}).items() if v.get("mail")]
