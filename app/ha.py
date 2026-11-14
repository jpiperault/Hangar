"""Haute disponibilité des applis, au choix pour chacune (fiche de l'appli) :

- secours à chaud (« standby ») : l'appli tourne sur son nœud principal ; un nœud de secours garde une réplique de sa
  base (réplication PostgreSQL en continu) et une copie de data/ (toutes les quelques minutes, relayée par la console).
  Si le nœud principal tombe, la console promeut la réplique, démarre l'appli sur le secours et bascule les routes.
- instances multiples (« replicas ») : l'appli tourne en même temps sur plusieurs nœuds, Caddy répartit les requêtes
  et écarte une instance qui ne répond plus. Pour les applis qui ne gardent rien d'important dans data/ (chaque
  instance a le sien). La base a aussi une réplique, sur le premier autre nœud.

Une appli en haute dispo avec une base a sa propre instance PostgreSQL (conteneur appdb-<appli>, même image que le
PostgreSQL partagé, superutilisateur « platform »), publiée seulement sur le réseau privé : c'est ce qui permet de la
répliquer seule et de la promouvoir sans toucher aux autres applis.

Bascule automatique, seulement si on est sûr que le nœud est tombé et pas seulement coupé de la console :
- la console a Internet ;
- aucun autre nœud ne joint le nœud par le réseau privé ;
- et, si l'arrêt de sécurité n'est pas actif sur ce nœud : il ne répond pas sur son adresse publique, et (avec un jeton
  d'API Cloudflare) son connecteur de tunnel n'est plus connecté.
Arrêt de sécurité (« fencing ») : un nœud qui ne voit plus aucun pair du réseau privé pendant `fence_after` secondes
arrête lui-même ses applis en haute dispo et son connecteur de tunnel, pour ne jamais servir en double avec le secours.
À son retour, la console le reconstruit en secours (ou redémarre ses applis si rien n'a basculé).
"""
import json
import os
import secrets
import shlex
import socket
import threading
import time
import urllib.request

from . import alerts, db
from . import nodes as N
from . import platform as P

PG_IMAGE = "postgres:17"          # même version que le PostgreSQL partagé
DB_PORT_OFFSET = 10000            # port privé de la base dédiée : port de l'appli + 10000
SAFE = f"{P.BACKUPS}/avant-haute-dispo"
FENCE_MARK = "/var/lib/hangar/fenced"
SRC = "/opt/hangar/deploy/node"

INIT = """#!/bin/bash
# Généré par Hangar : compte de réplication de la base dédiée (exécuté une seule fois, à la création)
set -e
echo "host replication replicator all scram-sha-256" >> "$PGDATA/pg_hba.conf"
psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d postgres -c "CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD '$REPL_PASSWORD'"
"""

_busy = set()            # applis en cours d'opération de haute dispo
_blocked = {}            # nœud → raison d'une bascule refusée (signalée une fois par panne)
_last = {}               # tâches périodiques : clé → horodatage
_tl = threading.Lock()


# ---------------------------------------------------------------- registre

def get(slug):
    try:
        r = db.one("SELECT * FROM ha WHERE slug = ?", (slug,))
    except Exception:
        return None
    if r:
        r["nodes"] = json.loads(r["nodes"] or "[]")
        r["info"] = json.loads(r["info"] or "{}")
    return r


def all_ha():
    out = []
    for r in db.q("SELECT * FROM ha"):
        r["nodes"] = json.loads(r["nodes"] or "[]")
        r["info"] = json.loads(r["info"] or "{}")
        out.append(r)
    return out


def _save(slug, **f):
    for k in ("nodes", "info"):
        if k in f and not isinstance(f[k], str):
            f[k] = json.dumps(f[k])
    f["updated_at"] = time.time()
    db.x(f"UPDATE ha SET {', '.join(f'{k} = ?' for k in f)} WHERE slug = ?", list(f.values()) + [slug])


def _info(slug, **kw):
    h = get(slug)
    info = h["info"]
    info.update(kw)
    _save(slug, info=info)
    return info


def settings():
    s = {"fence": "auto", "fence_after": 180}
    s.update(db.kv_get("ha") or {})
    return s


def save_settings(fence, fence_after, by):
    if fence not in ("auto", "always", "never"):
        raise ValueError("Réglage d'arrêt de sécurité inconnu.")
    fence_after = int(fence_after)
    if not 90 <= fence_after <= 1800:
        raise ValueError("Délai d'arrêt de sécurité : entre 90 et 1800 secondes.")
    db.kv_set("ha", {"fence": fence, "fence_after": fence_after})
    P.log("info", "haute dispo", f"arrêt de sécurité : {fence}, après {fence_after} s ({by})")
    push_fence_all()


def stale(h):
    return h["info"].get("stale") or []


def instance_nodes(a):
    """Nœuds où l'appli tourne (Caddy les met en répartition) : le principal, plus les instances en mode replicas."""
    h = get(a["slug"])
    if h and h["mode"] == "replicas":
        return [a["node"] or N.LOCAL] + [n for n in h["nodes"] if n not in stale(h) and n != a["node"]]
    return [a["node"] or N.LOCAL]


def all_instance_nodes():
    try:
        return {n for h in all_ha() if h["mode"] == "replicas" for n in h["nodes"]}
    except Exception:
        return set()


def role_of(slug, instance=None):
    """Étiquette des conteneurs de l'appli pour l'arrêt de sécurité (None : pas de haute dispo)."""
    if not get(slug):
        return None
    return "instance" if instance else "primary"


def participants():
    """Nœuds distants concernés par la haute dispo (principal, secours, instances)."""
    out = set()
    for h in all_ha():
        a = db.app(h["slug"])
        if a:
            out |= {a["node"]} | set(h["nodes"])
    return {n for n in out if n and n != N.LOCAL}


def _ok(node_id):
    if node_id == N.LOCAL:
        return True
    n = N.get(node_id)
    return bool(n and n["state"] == "ok")


# ---------------------------------------------------------------- base dédiée

def _seg_push():
    from . import segment
    for e in segment.push_all():
        P.log("warn", "nœud local", e)


def _d(slug):
    return P.app_dir(slug)


def _db_compose(slug, node, role, h):
    path = f"{_d(slug)}/db-{node}/compose.yml"
    doc = {"name": f"appdb-{slug}", "services": {"db": {
        "image": PG_IMAGE, "container_name": f"appdb-{slug}", "restart": "unless-stopped",
        "environment": {"POSTGRES_USER": "platform", "POSTGRES_PASSWORD": h["db_admin"],
                        "REPL_PASSWORD": h["repl_password"]},
        "command": ["postgres", "-c", "wal_level=replica", "-c", "max_wal_senders=10", "-c", "wal_keep_size=1024",
                    "-c", "hot_standby=on"],
        "volumes": [f"{_d(slug)}/pgdata:/var/lib/postgresql/data", f"{_d(slug)}/pginit:/docker-entrypoint-initdb.d:ro"],
        "ports": [f"{P.node_wg(node)}:{h['db_port']}:5432"],     # réseau privé seulement
        "networks": [f"hangar-{slug}"], "shm_size": "128mb",
        "labels": {"fr.hangar.ha-db": slug, "fr.hangar.ha-dbrole": role},
        "healthcheck": {"test": ["CMD-SHELL", "pg_isready -U platform"], "interval": "10s", "timeout": "5s",
                        "retries": 5}}},
        "networks": {f"hangar-{slug}": {"external": True}}}
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    P.write_private(path, "# Généré par Hangar (haute dispo). Ne pas éditer à la main.\n" + json.dumps(doc, indent=2) + "\n")
    return path


def _dbc(slug, node, *args, timeout=300):
    path = f"{_d(slug)}/db-{node}/compose.yml"
    if os.path.exists(path):
        return P.dk(node, "compose", "-f", path, "-p", f"appdb-{slug}", *args, timeout=timeout)
    return P.dk(node, "compose", "-p", f"appdb-{slug}", *args, timeout=timeout)


def _db_sql(node, slug, sql, dbname="postgres", timeout=60):
    return P.dk(node, "exec", "-i", f"appdb-{slug}", "psql", "-U", "platform", "-d", dbname, "-qtA",
                "-v", "ON_ERROR_STOP=1", input=sql, timeout=timeout)


def _db_wait(node, slug, timeout=120):
    end = time.time() + timeout
    while time.time() < end:
        rc, _ = P.dk(node, "exec", f"appdb-{slug}", "pg_isready", "-U", "platform", timeout=15)
        if rc == 0:
            return True
        time.sleep(2)
    return False


def _prep_dirs(slug, node, owner=None):
    d = _d(slug)
    own = f" -o {owner} -g {owner}" if owner else ""
    rc, out = P.nsh(node, f"install -d -m 0700 {d} && rm -rf {d}/pgdata && install -d -m 0700{own} {d}/pgdata && "
                          f"install -d -m 0755 {d}/pginit && cat > {d}/pginit/10-hangar-replication.sh && "
                          f"chmod 755 {d}/pginit/10-hangar-replication.sh", input=INIT, timeout=120)
    if rc:
        raise RuntimeError(f"dossiers de la base sur {node} : " + P.tail(out, 2))


def _db_primary_create(slug, node, h):
    _dbc(slug, node, "down", timeout=120)
    _prep_dirs(slug, node)
    _db_compose(slug, node, "primary", h)
    rc, out = _dbc(slug, node, "up", "-d", "--quiet-pull", timeout=600)
    if rc or not _db_wait(node, slug):
        raise RuntimeError(f"base dédiée sur {node} : " + P.tail(out, 2))


def _db_standby_build(slug, node, primary, h):
    """Réplique de la base sur `node`, copiée de la base primaire (pg_basebackup) puis tenue à jour en continu."""
    _dbc(slug, node, "down", timeout=120)
    _prep_dirs(slug, node, owner=999)   # 999 : utilisateur postgres de l'image officielle
    P.dk(node, "pull", "--quiet", PG_IMAGE, timeout=600)
    rc, out = P.dk(node, "run", "--rm", "--network", "host", "--user", "999:999",
                   "-e", f"PGPASSWORD={h['repl_password']}", "-v", f"{_d(slug)}/pgdata:/var/lib/postgresql/data",
                   PG_IMAGE, "pg_basebackup", "-h", P.node_wg(primary), "-p", str(h["db_port"]), "-U", "replicator",
                   "-D", "/var/lib/postgresql/data", "-R", "-X", "stream", "-c", "fast", timeout=6 * 3600)
    if rc:
        raise RuntimeError(f"copie de la base vers {node} impossible : " + P.tail(out, 3))
    _db_compose(slug, node, "standby", h)
    rc, out = _dbc(slug, node, "up", "-d", timeout=300)
    if rc or not _db_wait(node, slug):
        raise RuntimeError(f"réplique sur {node} : " + P.tail(out, 2))
    _info(slug, db_standby=node, db_rebuilt=time.time())
    P.log("ok", slug, f"réplique de la base en place sur {node}")


def _db_promote(slug, node):
    rc, out = _db_sql(node, slug, "SELECT pg_promote(true, 60);", timeout=90)
    if rc or "t" not in out.split():
        rc2, out2 = _db_sql(node, slug, "SELECT pg_is_in_recovery();")
        if not (rc2 == 0 and out2.strip() == "f"):
            raise RuntimeError(f"promotion de la réplique sur {node} impossible : " + P.tail(out, 2))
    _db_compose(slug, node, "primary", get(slug))   # étiquette à jour au prochain démarrage du conteneur


def _db_remove(slug, node):
    _dbc(slug, node, "down", "--remove-orphans", timeout=180)
    P.nsh(node, f"rm -rf {_d(slug)}/pgdata {_d(slug)}/pginit", timeout=300)
    path = f"{_d(slug)}/db-{node}"
    if os.path.isdir(path):
        import shutil
        shutil.rmtree(path, ignore_errors=True)


def _pg_dump(node, container, slug, path):
    import subprocess
    with open(path, "wb") as f:
        p = subprocess.run(["docker", "exec", container, "pg_dump", "-U", "platform", "-Fc", P.db_name(slug)],
                           stdout=f, stderr=subprocess.PIPE, timeout=3600, env=P.denv(node))
    if p.returncode:
        raise RuntimeError("export de la base impossible : " + p.stderr.decode(errors="replace")[-300:])


def _pg_restore(node, container, slug, path):
    import subprocess
    name = P.db_name(slug)
    with open(path, "rb") as f:
        p = subprocess.run(["docker", "exec", "-i", container, "pg_restore", "-U", "platform", "--no-owner", "--no-acl",
                            f"--role={name}", "-d", name], stdin=f, capture_output=True, timeout=3600,
                           env=P.denv(node))
    errs = [l for l in p.stderr.decode(errors="replace").splitlines() if "error" in l.lower()]
    if p.returncode and errs:
        raise RuntimeError("restauration de la base : " + " | ".join(errs[-3:]))


def replication(slug):
    """État de la réplication vu de la base primaire : [{client, state, lag}] ; None si illisible."""
    h = get(slug)
    if not h or not h["db_node"]:
        return None
    rc, out = _db_sql(h["db_node"], slug, "SELECT client_addr, state, COALESCE(EXTRACT(EPOCH FROM replay_lag), 0) "
                                          "FROM pg_stat_replication;", timeout=20)
    if rc:
        return None
    res = []
    for line in out.splitlines():
        p = line.split("|")
        if len(p) == 3:
            res.append({"client": p[0], "state": p[1], "lag": round(float(p[2] or 0), 1)})
    return res


# ---------------------------------------------------------------- data/ et instances

def sync_data(slug):
    """Copie data/ du nœud principal vers le secours (mode secours), relayée par la console si besoin."""
    from . import backup
    h, a = get(slug), db.app(slug)
    if not h or h["mode"] != "standby" or not a:
        return
    src, dst = a["node"], h["nodes"][0]
    if dst in stale(h) or not _ok(src) or not _ok(dst) or N._fails.get(src, 0) > 0 or N._fails.get(dst, 0) > 0:
        return   # un des deux ne répond pas en ce moment : la copie attendra
    d = f"{_d(slug)}/data"
    from . import services
    try:   # MySQL/MariaDB : export à jour, qui part avec data/ (le secours repart de lui)
        services.fresh_dump(a, quiet=True)
    except RuntimeError as e:
        P.log("warn", slug, f"{e} : le secours garde l'export précédent")
    try:
        if P.is_local(src):
            P.push_dir(dst, d, d)
        elif P.is_local(dst):
            P.pull_dir(src, d, d)
        else:   # relais : le miroir des sauvegardes sert aussi de copie intermédiaire
            relay = f"{backup.MIRROR}/{slug}/data"
            P.pull_dir(src, d, relay)
            P.push_dir(dst, relay, d)
        _info(slug, last_sync=time.time(), sync_error=None)
    except RuntimeError as e:
        _info(slug, sync_error=str(e)[:300])
        P.log("warn", slug, f"copie de data/ vers le secours {dst} : {e}")


def _prepull(a, node):
    """Image de l'appli présente d'avance sur un nœud (la bascule n'attend pas un téléchargement)."""
    if a["source"] == "git":
        P.dk(node, "compose", "-f", P.compose_path(a["slug"]), "-p", f"app-{a['slug']}", "build", timeout=1800)
    else:
        P.dk(node, "pull", "--quiet", P.image_ref(a, a["version"]), timeout=900)
    from . import services
    m = services.mysql(a["slug"])
    if m:   # sa base MySQL/MariaDB aussi
        P.dk(node, "pull", "--quiet", services.ENGINES[m["engine"]]["image"], timeout=900)


def _instance_up(a, node):
    path = P.write_compose(a, a["version"], instance=node, role="instance")
    b = {**a, "node": node}
    proj = ["compose", "-f", path, "-p", f"app-{a['slug']}"]
    if a["source"] == "git":
        rc, out = P.dk(node, *proj, "build", timeout=1800)
    else:
        rc, out = P.dk(node, *proj, "pull", "--quiet", timeout=900)
    if rc:
        rc2, _ = P.dk(node, "image", "inspect", P.image_ref(a, a["version"]), timeout=30)
        if rc2:
            raise RuntimeError(f"image indisponible sur {node} : " + P.tail(out, 2))
    P.prepare_data(b, a["version"])
    if a["desired"] == "stopped":
        return True, "appli arrêtée"
    rc, out = P.dk(node, *proj, "up", "-d", "--remove-orphans", "--no-build", timeout=300)
    if rc:
        raise RuntimeError(f"démarrage sur {node} : " + P.tail(out, 2))
    return P.wait_health(b)


def _instance_down(slug, node):
    P.dk(node, "compose", "-p", f"app-{slug}", "down", "--remove-orphans", timeout=180)
    path = os.path.dirname(P.compose_path(slug, node))
    if os.path.isdir(path):
        import shutil
        shutil.rmtree(path, ignore_errors=True)


def after_deploy(slug):
    """Après un déploiement réussi sur le nœud principal (appelé sous op_lock)."""
    h, a = get(slug), db.app(slug)
    if not h or not a:
        return
    if h["mode"] == "standby":
        for n in h["nodes"]:
            if _ok(n) and n not in stale(h):
                P.spawn(_prepull, dict(a), n)
        return
    for n in h["nodes"]:      # instances : l'une après l'autre
        if n in stale(h) or not _ok(n):
            continue
        try:
            ok, detail = _instance_up(a, n)
            P.log("ok" if ok else "error", slug, f"instance sur {n} : {a['version']} " + ("en ligne" if ok else f"en échec : {detail}"))
        except Exception as e:
            P.log("error", slug, f"instance sur {n} : {e}")
            alerts.send_async(f"{a['name']} : instance sur {n} en échec", str(e)[:400], priority=4, tags=["warning"])


def instances_do(slug, action):
    """Démarrer, arrêter ou redémarrer les instances supplémentaires avec l'appli."""
    h = get(slug)
    if not h or h["mode"] != "replicas":
        return
    for n in h["nodes"]:
        if n in stale(h) or not _ok(n):
            continue
        path = P.compose_path(slug, n)
        if not os.path.exists(path):
            continue
        args = {"start": ["up", "-d", "--no-build"], "stop": ["stop"], "restart": ["restart"]}[action]
        rc, out = P.dk(n, "compose", "-f", path, "-p", f"app-{slug}", *args, timeout=300)
        if rc:
            P.log("error", slug, f"instance sur {n} : {action} en échec : " + P.tail(out, 2))


# ---------------------------------------------------------------- activer, retirer

def validate(a, mode, nodes_, ack):
    if mode not in ("standby", "replicas"):
        return "Mode inconnu."
    from . import services
    if services.mysql(a["slug"]) and mode == "replicas":
        return ("Cette appli a une base MySQL/MariaDB : choisis le secours à chaud (les instances multiples demandent "
                "une base partagée en direct).")
    nodes_ = [n for n in dict.fromkeys(nodes_) if n and n != a["node"]]
    if not nodes_:
        return "Choisis au moins un autre nœud."
    if mode == "standby" and len(nodes_) != 1:
        return "Le secours à chaud se fait sur un seul nœud."
    if N.LOCAL in nodes_ and not N.console_hosts("standby" if mode == "standby" else "app"):
        return "La console est en « gestion seulement » : choisis un autre nœud (page Nœuds pour changer)."
    for n in nodes_:
        if n != N.LOCAL and not _ok(n):
            return f"Le nœud {n} n'est pas en ligne."
    if not P.node_wg(a["node"]) or not all(P.node_wg(n) for n in nodes_):
        return "Le réseau privé entre les nœuds n'est pas en place."
    if mode == "replicas" and not ack:
        return "Les instances multiples ne partagent pas data/ : confirme que l'appli n'y garde rien d'important."
    return None


def enable(slug, mode, nodes_, auto, delay, sync_min, by):
    a = db.app(slug)
    nodes_ = [n for n in dict.fromkeys(nodes_) if n and n != a["node"]]
    with P.op_lock:
        _busy.add(slug)
        try:
            _enable(a, mode, nodes_, auto, delay, sync_min, by)
        finally:
            _busy.discard(slug)
    push_fence_all()
    P.apply_routing()


def _enable(a, mode, nodes_, auto, delay, sync_min, by):
    slug = a["slug"]
    db.x("INSERT OR REPLACE INTO ha(slug, mode, nodes, auto, delay, sync_min, db_port, db_admin, repl_password, "
         "state, info, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 'setup', '{}', ?)",
         (slug, mode, json.dumps(nodes_), 1 if auto else 0, delay, sync_min, a["host_port"] + DB_PORT_OFFSET,
          secrets.token_hex(16), secrets.token_hex(16), time.time()))
    h = get(slug)
    _seg_push()   # port de la base dédiée ouvert à cette appli seulement, sur chaque nœud
    label = "secours à chaud" if mode == "standby" else "instances multiples"
    P.log("info", slug, f"haute dispo ({label} sur {', '.join(nodes_)}) : mise en place par {by}")
    node, d = a["node"], P.app_dir(slug)
    try:
        if a["db"]:
            # la base passe du PostgreSQL partagé à une base dédiée, réplicable : courte coupure
            os.makedirs(SAFE, mode=0o700, exist_ok=True)
            dump = f"{SAFE}/{slug}-{time.strftime('%Y%m%d-%H%M%S')}.dump"
            P.dk(node, "compose", "stop", cwd=d, timeout=120)
            _pg_dump(node, P.PG, slug, dump)
            os.chmod(dump, 0o600)
            _db_primary_create(slug, node, h)
            P.ensure_db(a, node, f"appdb-{slug}")
            _pg_restore(node, f"appdb-{slug}", slug, dump)
            _save(slug, db_node=node)
        ok, detail = P._up(a, a["version"])   # compose réécrit : DATABASE_URL, étiquette de rôle
        if not ok and a["desired"] == "running":
            raise RuntimeError(f"l'appli ne répond pas avec sa base dédiée : {detail}")
        if a["desired"] == "stopped":
            P.dk(node, "compose", "stop", cwd=d, timeout=120)
        if a["db"]:
            P._psql(f"DROP DATABASE IF EXISTS {P.db_name(slug)} WITH (FORCE);", node)   # copie : {dump}
            _db_standby_build(slug, nodes_[0], node, get(slug))
        a = db.app(slug)
        if mode == "standby":
            _prepull(a, nodes_[0])
            sync_data(slug)
        else:
            for n in nodes_:
                ok, detail = _instance_up(a, n)
                if not ok:
                    raise RuntimeError(f"instance sur {n} : {detail}")
        _save(slug, state="ok")
        P.log("ok", slug, f"haute dispo en place : {label} sur {', '.join(nodes_)}")
    except Exception as e:
        P.log("error", slug, f"haute dispo : mise en place en échec, retour à l'état d'avant : {e}")
        _rollback_enable(slug, a, nodes_)
        raise


def _rollback_enable(slug, a, nodes_):
    h = get(slug)
    node = a["node"]
    try:
        for n in nodes_:
            _instance_down(slug, n)
            _db_remove(slug, n)
        if h and h["db_node"]:
            # la base dédiée a pu recevoir des écritures : on la recopie dans le PostgreSQL partagé
            dump = f"{SAFE}/{slug}-retour-{time.strftime('%Y%m%d-%H%M%S')}.dump"
            _pg_dump(node, f"appdb-{slug}", slug, dump)
            db.x("DELETE FROM ha WHERE slug = ?", (slug,))
            P.ensure_db(a, node, P.PG)
            P._psql(f"DROP DATABASE IF EXISTS {P.db_name(slug)} WITH (FORCE); "
                    f"CREATE DATABASE {P.db_name(slug)} OWNER {P.db_name(slug)};", node)
            _pg_restore(node, P.PG, slug, dump)
        db.x("DELETE FROM ha WHERE slug = ?", (slug,))
        _seg_push()
        _db_remove(slug, node)
        ok, detail = P._up(db.app(slug), a["version"])
        P.log("warn" if ok else "error", slug, "appli remise comme avant" + ("" if ok else f", mais ne répond pas : {detail}"))
    except Exception as e:
        db.x("DELETE FROM ha WHERE slug = ?", (slug,))
        P.log("error", slug, f"retour à l'état d'avant incomplet : {e}")


def disable(slug, by, locked=False):
    """Retire la haute dispo : base remise dans le PostgreSQL partagé du nœud principal, secours et instances retirés."""
    if not locked:
        with P.op_lock:
            _busy.add(slug)
            try:
                return _disable(slug, by)
            finally:
                _busy.discard(slug)
                push_fence_all()
                P.apply_routing()
    return _disable(slug, by)


def _disable(slug, by):
    h, a = get(slug), db.app(slug)
    if not h:
        return
    node, d = a["node"], P.app_dir(slug)
    for n in h["nodes"]:
        if h["mode"] == "replicas":
            _instance_down(slug, n)
        elif _ok(n):
            P.dk(n, "compose", "-p", f"app-{slug}", "down", "--remove-orphans", timeout=180)
    if h["db_node"]:
        os.makedirs(SAFE, mode=0o700, exist_ok=True)
        dump = f"{SAFE}/{slug}-retrait-{time.strftime('%Y%m%d-%H%M%S')}.dump"
        P.dk(node, "compose", "stop", cwd=d, timeout=120)
        _pg_dump(h["db_node"], f"appdb-{slug}", slug, dump)
        os.chmod(dump, 0o600)
        P.ensure_db(a, node, P.PG)
        _pg_restore(node, P.PG, slug, dump)
    db.x("DELETE FROM ha WHERE slug = ?", (slug,))
    _seg_push()
    for n in set(h["nodes"]) | {node}:
        if _ok(n):
            _db_remove(slug, n)
        if n != node and _ok(n):   # copie de data/ du secours, ou data/ d'une instance
            from . import segment
            segment.drop(n, slug)    # son réseau Docker n'y sert plus
            if P.is_local(n):
                import shutil
                shutil.rmtree(f"{d}/data", ignore_errors=True)   # le dossier de l'appli garde ses compose
            else:
                P.nsh(n, f"rm -rf {d}", timeout=600)
    if a["desired"] == "running":
        ok, detail = P._up(a, a["version"])
        P.log("ok" if ok else "error", slug, "haute dispo retirée" + ("" if ok else f", mais l'appli ne répond pas : {detail}"))
    else:
        P.write_compose(a, a["version"])
        P.log("info", slug, f"haute dispo retirée ({by})")


def update_options(slug, auto, delay, sync_min, by):
    _save(slug, auto=1 if auto else 0, delay=delay, sync_min=sync_min)
    P.log("info", slug, f"haute dispo : bascule {'automatique' if auto else 'manuelle'}, après {delay} min ; "
                        f"copie de data/ toutes les {sync_min} min ({by})")


# ---------------------------------------------------------------- bascule

def failover(slug, dead, reason):
    """Bascule d'urgence : le nœud `dead` est tombé."""
    with P.op_lock:
        _busy.add(slug)
        try:
            _failover(slug, dead, reason)
        finally:
            _busy.discard(slug)
    P.apply_routing()


def _failover(slug, dead, reason):
    h, a = get(slug), db.app(slug)
    if not h or not a:
        return
    if h["mode"] == "replicas" and dead != a["node"]:
        # une instance est tombée : Caddy l'écarte déjà ; on la reconstruira à son retour
        _info(slug, stale=sorted(set(stale(h)) | {dead}))
        _save(slug, state="degraded")
        P.log("warn", slug, f"instance sur {dead} perdue ({reason}) : les autres instances servent")
        return
    cands = [n for n in h["nodes"] if n not in stale(h) and _ok(n)]
    if a["db"]:   # seule la réplique de la base peut reprendre
        sb = h["info"].get("db_standby")
        target = sb if sb in cands else None
    else:
        target = cands[0] if cands else None
    if not target:
        P.log("error", slug, f"bascule impossible : aucun nœud de secours en ligne ({reason})")
        alerts.send(f"{a['name']} : bascule impossible", f"{dead} est tombé et aucun secours n'est en ligne.",
                    priority=5, tags=["rotating_light"])
        return
    P.log("warn", slug, f"bascule de {dead} vers {target} : {reason}")
    t0 = time.time()
    try:
        if a["db"]:
            _db_promote(slug, target)
            _save(slug, db_node=target)
        db.update_app(slug, node=target, state="deploying")
        b = db.app(slug)
        if h["mode"] == "replicas":
            _instance_down_file(slug, target)
        from . import services
        services.reset_mysql(b, target)   # MySQL/MariaDB : repart de l'export de la dernière copie de data/
        ok, detail = P._up(b, b["version"])
        if not ok and b["desired"] == "running":
            raise RuntimeError(detail)
        if b["desired"] == "stopped":
            P.dk(target, "compose", "stop", cwd=P.app_dir(slug), timeout=120)
        rest = [n for n in h["nodes"] if n != target]
        _save(slug, nodes=rest + [dead], state="degraded")
        _info(slug, stale=sorted(set(stale(h)) | {dead}), db_standby=None,
              last_failover={"ts": time.time(), "from": dead, "to": target, "reason": reason})
        if h["mode"] == "replicas":   # les autres instances suivent la base promue
            for n in rest:
                if _ok(n) and n not in stale(h):
                    try:
                        _instance_up(b, n)
                    except Exception as e:
                        P.log("error", slug, f"instance sur {n} après bascule : {e}")
        db.update_app(slug, state="ok")
        P.log("ok", slug, f"basculée sur {target} en {time.time() - t0:.0f} s")
        alerts.send(f"{a['name']} basculée sur {target}", f"{dead} ne répond plus ({reason}). L'appli tourne sur "
                    f"{target}. {dead} sera reconstruit en secours à son retour.", priority=4, tags=["arrows_counterclockwise"])
    except Exception as e:
        db.update_app(slug, state="error")
        _save(slug, state="error")
        P.log("error", slug, f"bascule vers {target} en échec : {e}")
        alerts.send(f"{a['name']} : bascule en échec", f"Vers {target} : {e}", priority=5, tags=["rotating_light"])


def _instance_down_file(slug, node):
    """Le nœud d'une instance devient le principal : son compose d'instance disparaît (même projet Docker)."""
    path = os.path.dirname(P.compose_path(slug, node))
    if os.path.isdir(path):
        import shutil
        shutil.rmtree(path, ignore_errors=True)


def switchover(slug, by):
    """Bascule programmée vers le secours (ou la première autre instance), sans perte : maintenance, retour."""
    with P.op_lock:
        _busy.add(slug)
        try:
            _switchover(slug, by)
        finally:
            _busy.discard(slug)
    P.apply_routing()


def _switchover(slug, by):
    h, a = get(slug), db.app(slug)
    old, d = a["node"], P.app_dir(slug)
    target = h["info"].get("db_standby") if a["db"] else next((n for n in h["nodes"] if n not in stale(h)), None)
    if not target or target in stale(h) or not _ok(target) or not _ok(old):
        raise RuntimeError("bascule impossible : il faut le nœud principal et le secours en ligne, et à jour")
    P.log("info", slug, f"bascule programmée de {old} vers {target} ({by})")
    t0 = time.time()
    db.update_app(slug, state="deploying")   # la supervision ne signale pas la courte coupure voulue
    from . import services
    if services.mysql(slug):   # l'appli d'abord, puis l'export de sa base à l'arrêt des écritures
        P.dk(old, "compose", "stop", "app", cwd=d, timeout=120)
        services.fresh_dump(a)
    P.dk(old, "compose", "stop", cwd=d, timeout=120)   # plus aucune écriture
    try:
        if h["mode"] == "standby":
            sync_data(slug)
            if get(slug)["info"].get("sync_error"):
                raise RuntimeError("dernière copie de data/ en échec")
        if a["db"]:
            rc, lsn = _db_sql(old, slug, "SELECT pg_current_wal_lsn();")
            if rc:
                raise RuntimeError("position de la base illisible")
            lsn = lsn.strip()
            for _ in range(60):   # la réplique a tout rejoué ?
                rc, out = _db_sql(target, slug, f"SELECT pg_last_wal_replay_lsn() >= '{lsn}'::pg_lsn;")
                if rc == 0 and out.strip() == "t":
                    break
                time.sleep(1)
            else:
                raise RuntimeError("la réplique n'a pas rattrapé la base principale en 60 s")
            _dbc(slug, old, "stop", timeout=120)
            _db_promote(slug, target)
            _save(slug, db_node=target)
        db.update_app(slug, node=target)
        b = db.app(slug)
        if h["mode"] == "replicas":
            _instance_down_file(slug, target)
            P.dk(old, "compose", "-p", f"app-{slug}", "down", timeout=120)
        services.reset_mysql(b, target)
        ok, detail = P._up(b, b["version"])
        if not ok:
            raise RuntimeError(f"l'appli ne répond pas sur {target} : {detail}")
    except Exception as e:
        P.log("error", slug, f"bascule programmée en échec : {e} ; retour sur {old}")
        h2 = get(slug)
        if a["db"] and h2["db_node"] == target:
            # la réplique a été promue : l'ancienne base (arrêtée à jour) redevient principale, la réplique sera refaite
            _dbc(slug, target, "down", timeout=120)
            _dbc(slug, old, "up", "-d", timeout=300)
            _db_wait(old, slug)
            _save(slug, db_node=old)
        db.update_app(slug, node=a["node"])
        ok_back, _ = P._up(db.app(slug), a["version"])
        db.update_app(slug, state="ok" if ok_back else "error")
        if a["db"]:
            P.spawn(_rebuild_standby, slug, target)
        raise
    rest = [n for n in h["nodes"] if n != target]
    _save(slug, nodes=[old] + rest, state="ok")
    _info(slug, last_switchover={"ts": time.time(), "from": old, "to": target})
    if a["db"]:
        _db_standby_build(slug, old, target, get(slug))
    if h["mode"] == "replicas":
        b = db.app(slug)
        for n in [old] + rest:
            if _ok(n) and n not in stale(h):
                try:
                    _instance_up(b, n)
                except Exception as e:
                    P.log("error", slug, f"instance sur {n} : {e}")
    else:
        P.dk(old, "compose", "-p", f"app-{slug}", "down", timeout=120)
        _prepull(db.app(slug), old)
        sync_data(slug)
    db.update_app(slug, state="ok")
    P.log("ok", slug, f"basculée sur {target} en {time.time() - t0:.0f} s ; " + (
        f"{old} est maintenant le secours" if h["mode"] == "standby" else
        f"base principale sur {target}, {old} reste une instance" + (" avec la réplique" if a["db"] else "")))


def _rebuild_standby(slug, node):
    try:
        h = get(slug)
        _db_standby_build(slug, node, h["db_node"], h)
    except Exception as e:
        P.log("error", slug, f"réplique sur {node} : {e}")


def resync(slug, by):
    """Refait le secours de zéro : réplique de la base et copie complète de data/ (ou instances)."""
    with P.op_lock:
        _busy.add(slug)
        try:
            h, a = get(slug), db.app(slug)
            P.log("info", slug, f"haute dispo : resynchronisation ({by})")
            _rebuild(slug, h, a, h["nodes"])
            _save(slug, state="ok")
        finally:
            _busy.discard(slug)
    P.apply_routing()


def _rebuild(slug, h, a, targets):
    """Reconstruit `targets` comme secours ou instances de l'appli (base répliquée, data/, image)."""
    for n in targets:
        if not _ok(n):
            continue
        if h["mode"] == "standby" or n != a["node"]:
            P.dk(n, "compose", "-p", f"app-{slug}", "down", "--remove-orphans", timeout=180)
    if a["db"]:   # réplique de la base : là où elle était, sinon sur le premier nœud reconstruit
        sb = h["info"].get("db_standby")
        dbn = sb if sb and _ok(sb) and sb not in targets else next((n for n in targets if _ok(n)), None)
        if dbn and (dbn in targets or not sb):
            _db_standby_build(slug, dbn, h["db_node"], get(slug))
    a = db.app(slug)
    if h["mode"] == "standby":
        _prepull(a, h["nodes"][0])
        sync_data(slug)
    else:
        for n in targets:
            if _ok(n) and n != a["node"]:
                _instance_up(a, n)
    _info(slug, stale=[n for n in stale(get(slug)) if n not in targets])


# ---------------------------------------------------------------- retour d'un nœud, arrêt de sécurité

def on_node_back(node_id):
    """Un nœud répond de nouveau : il redevient secours (si ses applis ont basculé) ou les redémarre (sinon)."""
    if node_id == N.LOCAL:
        return
    _blocked.pop(node_id, None)
    rc, out = P.nsh(node_id, f"cat {FENCE_MARK} 2>/dev/null; true", timeout=30)
    fenced = rc == 0 and out.strip() != ""
    touched = False
    for h in all_ha():
        a = db.app(h["slug"])
        if not a:
            continue
        slug = a["slug"]
        if node_id in stale(h):
            touched = True
            with P.op_lock:
                _busy.add(slug)
                try:
                    P.log("info", slug, f"{node_id} est revenu : reconstruit en secours")
                    P.dk(node_id, "compose", "-p", f"app-{slug}", "down", "--remove-orphans", timeout=180)
                    if a["db"]:
                        _dbc(slug, node_id, "down", timeout=120)
                    _rebuild(slug, get(slug), a, [node_id])
                    h2 = get(slug)
                    _save(slug, state="ok" if not stale(h2) else "degraded")
                    alerts.send_async(f"{a['name']} : secours rétabli", f"{node_id} est revenu et sert de nouveau de secours.",
                                      priority=3, tags=["white_check_mark"])
                except Exception as e:
                    _save(slug, state="error")
                    P.log("error", slug, f"reconstruction du secours sur {node_id} en échec : {e}")
                finally:
                    _busy.discard(slug)
        elif fenced and (a["node"] == node_id or (h["mode"] == "replicas" and node_id in h["nodes"])) \
                and a["desired"] == "running":
            touched = True   # arrêt de sécurité sans bascule : on relance
            if a["node"] == node_id:
                P.dk(node_id, "compose", "up", "-d", "--no-build", cwd=P.app_dir(slug), timeout=300)
            else:
                path = P.compose_path(slug, node_id)
                if os.path.exists(path):
                    P.dk(node_id, "compose", "-f", path, "-p", f"app-{slug}", "up", "-d", "--no-build", timeout=300)
            P.log("ok", slug, f"redémarrée sur {node_id} après son arrêt de sécurité")
    if fenced:
        P.nsh(node_id, f"rm -f {FENCE_MARK}", timeout=30)
        P.log("info", f"nœud {node_id}", "fin de l'arrêt de sécurité")
        try:
            P.sync_tunnel(node_id)
        except Exception as e:
            P.log("warn", f"nœud {node_id}", f"connecteur du tunnel : {e}")
    if touched or fenced:
        P.apply_routing()


def fence_enabled(node_id):
    s = settings()
    if s["fence"] == "never":
        return False
    if s["fence"] == "always":
        return True
    # auto : un nœud isolé distingue « je suis coupé » de « la console est éteinte » s'il a au moins un autre pair
    return len([n for n in N.all_nodes() if n["id"] != N.LOCAL]) >= 2


def push_fence(node_id):
    s = settings()
    conf = f"# Généré par la console Hangar (haute dispo)\nENABLED={1 if fence_enabled(node_id) else 0}\nAFTER={s['fence_after']}\n"
    script = open(f"{SRC}/hangar-fence.sh").read()
    cmd = ("install -d -m 0755 /etc/hangar /var/lib/hangar && cat > /etc/hangar/fence.conf.new && "
           "mv /etc/hangar/fence.conf.new /etc/hangar/fence.conf && "
           f"echo {shlex.quote(script)} > /usr/local/sbin/hangar-fence && chmod 755 /usr/local/sbin/hangar-fence && "
           "printf '[Unit]\\nDescription=Hangar : arrêt de sécurité d un nœud isolé\\n[Service]\\nType=oneshot\\n"
           "ExecStart=/usr/local/sbin/hangar-fence\\n' > /etc/systemd/system/hangar-fence.service && "
           "printf '[Unit]\\nDescription=Hangar : vérifie toutes les 30 s que le nœud n est pas isolé\\n[Timer]\\n"
           "OnBootSec=60\\nOnUnitActiveSec=30\\nAccuracySec=5\\n[Install]\\nWantedBy=timers.target\\n' "
           "> /etc/systemd/system/hangar-fence.timer && systemctl daemon-reload && "
           "systemctl enable --now hangar-fence.timer >/dev/null 2>&1")
    rc, out = P.nsh(node_id, cmd, input=conf, timeout=60)
    if rc:
        P.log("warn", f"nœud {node_id}", "arrêt de sécurité non configuré : " + P.tail(out, 2))


def push_fence_all():
    for n in N.all_nodes():
        if n["id"] != N.LOCAL and n["state"] == "ok":
            push_fence(n["id"])


# ---------------------------------------------------------------- surveillance (chaque minute)

def _internet():
    try:
        with urllib.request.urlopen("https://cloudflare.com/cdn-cgi/trace", timeout=6):
            return True
    except OSError:
        return False


def _cf_connected(node):
    """Le connecteur de tunnel du nœud est-il encore connecté chez Cloudflare ? None si on ne peut pas savoir."""
    from . import cloudflare
    if not cloudflare.token():
        return None
    t = cloudflare.tunnel_info()
    if not t:
        return None
    try:
        ip = socket.gethostbyname(node["address"])
        res, _ = cloudflare._api("GET", f"/accounts/{t[0]}/cfd_tunnel/{t[1]}/connections")
        return any(c.get("origin_ip") == ip for x in res or [] for c in x.get("conns") or [])
    except Exception:
        return None


def really_down(node_id):
    """(sûr ?, raison) : le nœud est-il vraiment tombé, et pas seulement coupé de la console ?"""
    n = N.get(node_id)
    if not _internet():
        return False, "la console n'a plus accès à Internet : c'est peut-être elle qui est coupée"
    for w in N.all_nodes():
        if w["id"] in (N.LOCAL, node_id) or w["state"] != "ok":
            continue
        rc, _ = P.nsh(w["id"], f"ping -c2 -W2 {n['wg_ip']}", timeout=15)
        if rc == 0:
            return False, f"{w['id']} joint encore {node_id} par le réseau privé"
    if not fence_enabled(node_id):
        try:
            socket.create_connection((n["address"], n["ssh_port"]), timeout=4).close()
            return False, f"{node_id} répond encore sur son adresse publique (arrêt de sécurité inactif : bascule évitée)"
        except OSError:
            pass
        if _cf_connected(n):
            return False, f"le connecteur de tunnel de {node_id} est encore connecté chez Cloudflare"
    return True, "injoignable par le réseau privé, sans réponse des autres nœuds"


def _every(key, seconds):
    with _tl:
        if time.time() - _last.get(key, 0) < seconds:
            return False
        _last[key] = time.time()
        return True


def tick():
    """Appelé chaque minute par la surveillance, après le relevé des nœuds."""
    hs = all_ha()
    if not hs:
        return
    down = {nid: m for nid, m in N._fails.items() if m > 0}
    for h in hs:
        a = db.app(h["slug"])
        if not a or h["slug"] in _busy or h["state"] == "setup":
            continue
        slug = a["slug"]
        # 1. panne d'un nœud de l'appli
        involved = [a["node"]] + (h["nodes"] if h["mode"] == "replicas" else [])
        for nid in involved:
            if nid in stale(h) or down.get(nid, 0) < h["delay"]:
                continue
            if not h["auto"] and nid == a["node"]:
                if _every(f"manual-{slug}-{nid}", 3600):
                    alerts.send(f"{a['name']} : nœud {nid} tombé", "Bascule automatique désactivée : bascule à la main "
                                "depuis la fiche de l'appli si besoin.", priority=5, tags=["rotating_light"])
                continue
            sure, why = really_down(nid)
            if not sure:
                if _blocked.get(nid) != why:
                    _blocked[nid] = why
                    P.log("warn", slug, f"bascule suspendue : {why}")
                    alerts.send_async(f"{a['name']} : bascule suspendue", why, priority=4, tags=["warning"])
                continue
            P.spawn(failover, slug, nid, f"{nid} injoignable depuis {down[nid]} min ; {why}")
            break
        # 2. copie de data/ vers le secours
        if h["mode"] == "standby" and h["state"] in ("ok",) and \
                time.time() - h["info"].get("last_sync", 0) >= h["sync_min"] * 60 and _every(f"sync-{slug}", 50):
            P.spawn(_guarded, slug, sync_data)
        # 3. réplication de la base : reconstruite si elle ne suit plus
        if a["db"] and h["state"] == "ok" and _every(f"repl-{slug}", 300):
            P.spawn(_guarded, slug, _check_replication)
    # 4. nœuds en arrêt de sécurité alors que la console les joint (console revenue, coupure courte…)
    if _every("fence-scan", 300):
        P.spawn(_scan_fenced)


def _guarded(slug, fn):
    if slug in _busy:
        return
    _busy.add(slug)
    try:
        fn(slug)
    finally:
        _busy.discard(slug)


def _check_replication(slug):
    h = get(slug)
    sb = h["info"].get("db_standby")
    if not sb or not _ok(sb) or not _ok(h["db_node"]):
        return
    rep = replication(slug)
    if rep is None:
        return
    if any(r["state"] == "streaming" for r in rep):
        _info(slug, repl_lag=max(r["lag"] for r in rep), repl_ok=time.time())
        return
    if time.time() - h["info"].get("repl_ok", time.time()) > 600 and time.time() - h["info"].get("db_rebuilt", 0) > 1800:
        P.log("warn", slug, f"la réplique sur {sb} ne suit plus : reconstruction")
        try:
            _db_standby_build(slug, sb, h["db_node"], h)
        except Exception as e:
            P.log("error", slug, f"réplique sur {sb} : {e}")


def _scan_fenced():
    for nid in participants():
        if _ok(nid):
            rc, out = P.nsh(nid, f"cat {FENCE_MARK} 2>/dev/null; true", timeout=20)
            if rc == 0 and out.strip():
                on_node_back(nid)


# ---------------------------------------------------------------- affichage

def status(slug):
    """Vue d'ensemble pour la fiche de l'appli."""
    h, a = get(slug), db.app(slug)
    if not h or not a:
        return None
    rows = []
    sb = h["info"].get("db_standby")
    for n in [a["node"]] + [x for x in h["nodes"] if x != a["node"]]:
        node = N.get(n) or {"state": "ok"}
        if n in stale(h):
            role = "à reconstruire (était le principal)" if h["mode"] == "standby" else "instance à reconstruire"
        elif n == a["node"]:
            role = "principal" if h["mode"] == "standby" else "instance principale"
        else:
            role = "secours" if h["mode"] == "standby" else "instance"
        bits = []
        if a["db"] and n == h["db_node"]:
            bits.append("base principale")
        if a["db"] and n == sb:
            bits.append("réplique de la base")
        rows.append({"node": n, "role": role, "db": ", ".join(bits), "state": node["state"] if n != N.LOCAL else "ok"})
    rep = replication(slug) if a["db"] and _ok(h["db_node"] or a["node"]) else None
    return {"h": h, "rows": rows, "rep": rep, "busy": slug in _busy}
