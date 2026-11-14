"""Réplication MySQL / MariaDB vers le secours à chaud (haute dispo « secours »).

- Base principale (service « mysql » de l'appli) : journal binaire avec GTID, identifiant de serveur 1, publiée sur
  l'adresse privée de son nœud (port de l'appli + 30000), ouverte à cette appli seulement (segment.py), et un utilisateur
  de réplication.
- Secours : conteneur « myrepl-<appli> » (même image), sur le réseau de l'appli, données dans /srv/apps/<appli>/mysql (le
  même dossier que la base de l'appli utiliserait là), en lecture seule, qui suit la base principale (base « app »
  seulement). Il est amorcé par un export cohérent pris sans arrêt (position GTID comprise).
- Bascule programmée : l'appli s'arrête, la réplique rattrape (attente de la position GTID), la base principale
  s'arrête, la réplique est promue ; l'appli repart sur ses données, sans rechargement. Panne : la réplique est promue
  telle quelle (les dernières secondes non répliquées sont perdues). L'ancien principal, à son retour, redevient la
  réplique (amorcée de nouveau).
- Si la réplique n'est pas là ou ne suit pas, Hangar revient à la méthode par export (services.fresh_dump /
  reset_mysql).
État dans le réglage du service (services.mysql(slug)) : "repl" (mot de passe de réplication), "replica" {node, ts}.
"""
import json
import re
import secrets
import shlex
import subprocess
import time

from . import db
from . import platform as P

PORT_OFFSET = 30000
GTID = {"mariadb": "@@gtid_binlog_pos", "mysql": "@@GLOBAL.gtid_executed"}


def name(slug):
    return f"myrepl-{slug}"


def port(a):
    return a["host_port"] + PORT_OFFSET


def _svc():
    from . import services
    return services


def active(slug):
    """Réplication en place : (nœud de la réplique) ou None."""
    m = _svc().mysql(slug) or {}
    r = m.get("replica")
    return r["node"] if r else None


def wanted(slug):
    """Le service MySQL de l'appli doit-il écrire un journal binaire et être publié (secours à chaud) ?"""
    from . import ha
    h = ha.get(slug)
    return bool(_svc().mysql(slug) and h and h["mode"] == "standby")


def primary_args(slug, engine):
    """Options de la base principale quand la réplication est voulue."""
    if not wanted(slug):
        return []
    common = ["--server-id=1", "--log-bin=mysql-bin", "--binlog-format=ROW", "--binlog-expire-logs-seconds=172800"]
    if engine == "mariadb":
        return common + ["--gtid-strict-mode=ON"]
    return common + ["--gtid-mode=ON", "--enforce-gtid-consistency=ON"]


def _set(slug, **kw):
    from . import services
    allv = db.kv_get("app_services") or {}
    m = (allv.get(slug) or {}).get("mysql")
    if not m:
        return
    for k, v in kw.items():
        if v is None:
            m.pop(k, None)
        else:
            m[k] = v
    db.kv_set("app_services", allv)
    services.mysql(slug)   # (relu au besoin)


def _sql(node, container, sql, engine, timeout=60, user="root", pw=None):
    """SQL dans le conteneur ; mot de passe root du conteneur par défaut (pw="" : sans mot de passe)."""
    tool = "mariadb" if engine == "mariadb" else "mysql"
    pwd = '"$MYSQL_ROOT_PASSWORD"' if pw is None else shlex.quote(pw)
    cmd = f"MYSQL_PWD={pwd} {tool} -u{user} -N -B -e {shlex.quote(sql)}"
    return P.dk(node, "exec", container, "sh", "-c", cmd, timeout=timeout)


def _wait_up(node, container, engine, timeout=300, pw=None):
    t0 = time.time()
    while time.time() - t0 < timeout:
        rc, _ = _sql(node, container, "SELECT 1", engine, timeout=20, pw=pw)
        if rc == 0:
            return True
        time.sleep(3)
    return False


def _primary(a):
    return a["node"], f"app-{a['slug']}-mysql-1"


def build(slug, node):
    """Amorce (ou ré-amorce) la réplique sur `node` à partir de la base principale. RuntimeError si impossible."""
    from . import segment
    svc = _svc()
    a = db.app(slug)
    m = svc.mysql(slug)
    if not a or not m:
        raise RuntimeError("pas de base MySQL/MariaDB")
    eng = m["engine"]
    pnode, pcont = _primary(a)
    if (node or P.LOCAL) == (pnode or P.LOCAL):   # jamais sur la machine de la base principale : ses données y sont
        raise RuntimeError(f"{node} porte la base principale : pas de réplique sur la même machine")
    if not _wait_up(pnode, pcont, eng):
        raise RuntimeError("la base principale ne répond pas")
    repl = m.get("repl") or secrets.token_hex(20)
    _set(slug, repl=repl)
    auth = "" if eng == "mariadb" else " WITH caching_sha2_password"
    rc, out = _sql(pnode, pcont, f"CREATE USER IF NOT EXISTS 'repl'@'%' IDENTIFIED{auth} BY '{repl}'; "
                   f"ALTER USER 'repl'@'%' IDENTIFIED{auth} BY '{repl}'; "
                   "GRANT REPLICATION SLAVE ON *.* TO 'repl'@'%';", eng)
    if rc:
        raise RuntimeError("utilisateur de réplication : " + P.tail(out, 2))
    segment.ensure(node, slug)
    mem = int(m["mem"])
    args = ["run", "-d", "--name", name(slug), "--restart", "unless-stopped", "--network", segment.net_name(slug),
            "--memory", f"{mem}m", "--security-opt", "no-new-privileges:true", "--label", f"fr.hangar.of={slug}",
            "--label", "fr.hangar.service=mysql-replica",
            "-v", f"{svc.mysql_raw(slug)}:/var/lib/mysql",
            "-e", f"MYSQL_ROOT_PASSWORD={m['root']}", "-e", "MYSQL_DATABASE=app", "-e", "MYSQL_USER=app",
            "-e", f"MYSQL_PASSWORD={m['password']}", "-e", "MARIADB_INITDB_SKIP_TZINFO=1", "-e", "MYSQL_INITDB_SKIP_TZINFO=1",
            svc.ENGINES[eng]["image"], "--innodb-log-file-size=32M",
            f"--innodb-buffer-pool-size={max(32, mem // 2)}M", "--server-id=2", "--read-only=ON",
            "--replicate-do-db=app", "--relay-log=relay-bin", "--skip-name-resolve",
            "--character-set-server=utf8mb4", "--collation-server=utf8mb4_unicode_ci"]
    if eng == "mysql":
        args += ["--gtid-mode=ON", "--enforce-gtid-consistency=ON"]   # repart tout seul après un redémarrage
    # dossier préparé par Hangar (pas par le point d'entrée de l'image, qui n'attend que 30 s son serveur
    # d'initialisation et peut abandonner à mi-chemin sur un disque lent), puis serveur, puis comptes
    raw = svc.mysql_raw(slug)
    image = svc.ENGINES[eng]["image"]
    init = ("mariadb-install-db --user=mysql --datadir=/var/lib/mysql --auth-root-authentication-method=normal "
            "--skip-test-db >/dev/null" if eng == "mariadb" else
            "mysqld --initialize-insecure --user=mysql --datadir=/var/lib/mysql")
    P.dk(node, "rm", "-f", name(slug), timeout=60)
    P.nsh(node, f"rm -rf {raw} && install -d -m 0755 {raw}", timeout=300)
    rc, out = P.dk(node, "run", "--rm", "-v", f"{raw}:/var/lib/mysql", "--entrypoint", "sh", image, "-c",
                   f"chown mysql:mysql /var/lib/mysql && {init}", timeout=900)
    if rc:
        raise RuntimeError("préparation des données de la réplique : " + P.tail(out, 2))
    rc, out = P.dk(node, *args, timeout=600)
    if rc:
        raise RuntimeError("conteneur de réplique : " + P.tail(out, 2))
    if not _wait_up(node, name(slug), eng, timeout=600, pw=""):
        raise RuntimeError("la réplique ne démarre pas : " + P.tail(P.dk(node, "logs", "--tail", "5", name(slug), timeout=30)[1], 3))
    rc, out = _sql(node, name(slug), f"ALTER USER 'root'@'localhost' IDENTIFIED BY '{m['root']}'; "
                   "CREATE DATABASE IF NOT EXISTS app CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; "
                   f"CREATE USER IF NOT EXISTS 'app'@'%' IDENTIFIED BY '{m['password']}'; "
                   "GRANT ALL PRIVILEGES ON app.* TO 'app'@'%'; FLUSH PRIVILEGES;", eng, pw="")
    if rc:
        raise RuntimeError("comptes de la réplique : " + P.tail(out, 2))
    # export cohérent avec sa position GTID, chargé directement dans la réplique
    if eng == "mariadb":
        dump = "mariadb-dump --single-transaction --gtid --master-data=1 --routines --events --triggers --databases app"
        load_pre = "STOP SLAVE; RESET SLAVE ALL; RESET MASTER;"
    else:
        dump = ("mysqldump --single-transaction --set-gtid-purged=ON --source-data=2 --routines --events --triggers "
                "--databases app")
        load_pre = "STOP REPLICA; RESET REPLICA ALL; RESET BINARY LOGS AND GTIDS;"
    _sql(node, name(slug), load_pre, eng)
    tool = "mariadb" if eng == "mariadb" else "mysql"
    src = subprocess.Popen(["docker", "exec", pcont, "sh", "-c", f'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" {dump} -uroot'],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=P.denv(pnode))
    dst = subprocess.run(["docker", "exec", "-i", name(slug), "sh", "-c", f'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" {tool} -uroot'],
                         stdin=src.stdout, capture_output=True, env=P.denv(node), timeout=3600)
    src.stdout.close()
    err = src.stderr.read().decode(errors="replace")
    src.wait(timeout=60)
    if src.returncode or dst.returncode:
        raise RuntimeError("amorçage de la réplique : " + (err + dst.stderr.decode(errors="replace"))[-300:])
    host = P.node_wg(a["node"])
    if eng == "mariadb":
        sql = (f"CHANGE MASTER TO MASTER_HOST='{host}', MASTER_PORT={port(a)}, MASTER_USER='repl', "
               f"MASTER_PASSWORD='{repl}', MASTER_USE_GTID=slave_pos, MASTER_CONNECT_RETRY=10; START SLAVE;")
    else:
        sql = (f"CHANGE REPLICATION SOURCE TO SOURCE_HOST='{host}', SOURCE_PORT={port(a)}, SOURCE_USER='repl', "
               f"SOURCE_PASSWORD='{repl}', SOURCE_AUTO_POSITION=1, GET_SOURCE_PUBLIC_KEY=1, SOURCE_CONNECT_RETRY=10; "
               "START REPLICA;")
    rc, out = _sql(node, name(slug), sql, eng)
    if rc:
        raise RuntimeError("démarrage de la réplication : " + P.tail(out, 2))
    _set(slug, replica={"node": node, "ts": time.time()})
    for _ in range(20):
        st = status(slug)
        if st and st.get("running"):
            P.log("ok", slug, f"réplique MySQL/MariaDB en place sur {node} (retard : {st.get('lag', '?')} s)")
            return st
        time.sleep(3)
    raise RuntimeError("la réplique ne suit pas : " + ((status(slug) or {}).get("error") or "?"))


def status(slug):
    """{running, lag, error} de la réplique, ou None s'il n'y en a pas."""
    node = active(slug)
    m = _svc().mysql(slug)
    if not node or not m:
        return None
    q = "SHOW SLAVE STATUS\\G" if m["engine"] == "mariadb" else "SHOW REPLICA STATUS\\G"
    tool = "mariadb" if m["engine"] == "mariadb" else "mysql"
    rc, out = P.dk(node, "exec", name(slug), "sh", "-c", f'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" {tool} -uroot -e "{q}"',
                   timeout=30)
    if rc:
        return {"running": False, "lag": None, "error": P.tail(out, 2)}
    f = dict(re.findall(r"^\s*(\w+): ?(.*)$", out, re.M))
    io = f.get("Slave_IO_Running") or f.get("Replica_IO_Running")
    sqlr = f.get("Slave_SQL_Running") or f.get("Replica_SQL_Running")
    lag = f.get("Seconds_Behind_Master") or f.get("Seconds_Behind_Source")
    err = f.get("Last_IO_Error") or f.get("Last_SQL_Error") or ""
    return {"running": io == "Yes" and sqlr == "Yes", "lag": int(lag) if lag and lag.isdigit() else None,
            "error": err.strip()}


def caught_up(slug, timeout=60):
    """Attend que la réplique ait rejoué tout ce que la base principale a écrit (appli déjà arrêtée)."""
    a, m = db.app(slug), _svc().mysql(slug)
    node = active(slug)
    pnode, pcont = _primary(a)
    rc, pos = _sql(pnode, pcont, f"SELECT {GTID[m['engine']]}", m["engine"])
    if rc:
        return False
    pos = pos.strip().replace("\n", "")
    if m["engine"] == "mariadb":
        sql = f"SELECT MASTER_GTID_WAIT('{pos}', {timeout})"
    else:
        sql = f"SELECT WAIT_FOR_EXECUTED_GTID_SET('{pos}', {timeout})"
    rc, out = _sql(node, name(slug), sql, m["engine"], timeout=timeout + 20)
    return rc == 0 and out.strip() == "0"


def promote(slug):
    """La réplique devient la base de l'appli sur son nœud : réplication arrêtée, conteneur retiré, données gardées
    (le service « mysql » de l'appli repart dessus). Retourne le nœud."""
    m = _svc().mysql(slug)
    node = active(slug)
    stop = "STOP SLAVE; RESET SLAVE ALL;" if m["engine"] == "mariadb" else "STOP REPLICA; RESET REPLICA ALL;"
    _sql(node, name(slug), stop + " SET GLOBAL read_only = OFF;", m["engine"], timeout=60)
    P.dk(node, "stop", "-t", "60", name(slug), timeout=120)
    P.dk(node, "rm", "-f", name(slug), timeout=60)
    _set(slug, replica=None)
    P.log("ok", slug, f"réplique MySQL/MariaDB promue sur {node}")
    return node


def remove(slug, node=None):
    node = node or active(slug)
    if node:
        P.dk(node, "rm", "-f", name(slug), timeout=60)
    _set(slug, replica=None)


def ports(slug):
    """Port publié de la base principale (pour segment.py) quand la réplication est voulue, sinon None."""
    a = db.app(slug)
    return port(a) if a and wanted(slug) else None


def info_json(slug):
    return json.dumps(status(slug) or {})
