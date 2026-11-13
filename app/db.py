"""Registre SQLite de la plateforme : réglages, applis, journal, comptes."""
import json
import os
import sqlite3
import threading

DB_PATH = os.environ.get("HANGAR_DB", "/srv/platform/platform.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS apps (
    slug TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    pkg TEXT NOT NULL DEFAULT '',
    expose TEXT NOT NULL DEFAULT 'path',      -- path | sub | both
    sub TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'image',     -- image | git
    image TEXT NOT NULL,
    version TEXT NOT NULL,
    prev_version TEXT,
    port INTEGER NOT NULL,
    host_port INTEGER NOT NULL UNIQUE,
    health_path TEXT NOT NULL DEFAULT '/',
    mem_mb INTEGER NOT NULL DEFAULT 256,
    env TEXT NOT NULL DEFAULT '',
    db INTEGER NOT NULL DEFAULT 0,
    db_password TEXT,
    state TEXT NOT NULL DEFAULT 'ok',         -- ok | deploying | error
    desired TEXT NOT NULL DEFAULT 'running',  -- running | stopped
    deployed_at REAL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL, level TEXT NOT NULL, app TEXT NOT NULL, msg TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (             -- sessions ouvertes : révocables (déconnexion, mot de passe changé)
    id TEXT PRIMARY KEY, username TEXT NOT NULL, created REAL NOT NULL, seen REAL NOT NULL, ip TEXT
);
CREATE TABLE IF NOT EXISTS backups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL, duration REAL, ok INTEGER NOT NULL, remote INTEGER NOT NULL DEFAULT 0,
    added INTEGER, total INTEGER, snapshot TEXT, trigger TEXT, msg TEXT
);
CREATE TABLE IF NOT EXISTS stats_req (           -- une ligne par appli et par minute
    app TEXT NOT NULL, t INTEGER NOT NULL, n INTEGER NOT NULL, e4 INTEGER NOT NULL, e5 INTEGER NOT NULL,
    dur_sum REAL NOT NULL, p95 REAL NOT NULL, bytes INTEGER NOT NULL, PRIMARY KEY (app, t)
);
CREATE TABLE IF NOT EXISTS stats_res (           -- échantillon CPU / RAM par minute
    app TEXT NOT NULL, t INTEGER NOT NULL, cpu REAL NOT NULL, mem REAL NOT NULL, PRIMARY KEY (app, t)
);
CREATE TABLE IF NOT EXISTS stats_host (          -- serveur, par minute
    t INTEGER PRIMARY KEY, cpu REAL, mem REAL, mem_total REAL, swap REAL, disk REAL, disk_total REAL,
    load1 REAL, rx REAL, tx REAL
);
CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, address TEXT, ssh_port INTEGER NOT NULL DEFAULT 22,
    wg_ip TEXT NOT NULL UNIQUE, wg_pubkey TEXT, state TEXT NOT NULL DEFAULT 'installing',
    info TEXT NOT NULL DEFAULT '{}', last_seen REAL, created_at REAL NOT NULL, error TEXT
);
CREATE TABLE IF NOT EXISTS ha (                  -- haute dispo d'une appli (absente : pas de haute dispo)
    slug TEXT PRIMARY KEY,
    mode TEXT NOT NULL,                           -- standby : secours à chaud · replicas : instances multiples
    nodes TEXT NOT NULL DEFAULT '[]',             -- autres nœuds (secours, ou instances), par ordre de priorité
    auto INTEGER NOT NULL DEFAULT 1,              -- bascule automatique si le nœud principal tombe
    delay INTEGER NOT NULL DEFAULT 4,             -- minutes d'indisponibilité avant de basculer
    sync_min INTEGER NOT NULL DEFAULT 5,          -- copie de data/ vers le secours (minutes)
    db_node TEXT, db_port INTEGER,                -- base dédiée : nœud de la base primaire, port privé
    db_admin TEXT, repl_password TEXT,
    state TEXT NOT NULL DEFAULT 'setup',          -- setup | ok | degraded | error
    info TEXT NOT NULL DEFAULT '{}',              -- relevés : copies, réplication, nœuds à reconstruire
    updated_at REAL
);
CREATE TABLE IF NOT EXISTS stats_node (
    node TEXT NOT NULL, t INTEGER NOT NULL, cpu REAL, mem REAL, mem_total REAL, disk REAL, disk_total REAL,
    load1 REAL, PRIMARY KEY (node, t)
);
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, ts REAL NOT NULL);
CREATE TABLE IF NOT EXISTS domains (              -- voir domains.py
    name TEXT PRIMARY KEY, mode TEXT NOT NULL DEFAULT 'tunnel', hub TEXT NOT NULL DEFAULT '',
    entry TEXT NOT NULL DEFAULT 'local', ip TEXT NOT NULL DEFAULT '', is_default INTEGER NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS routes (               -- adresses publiques des applis, dans l'ordre (pos)
    id INTEGER PRIMARY KEY AUTOINCREMENT, slug TEXT NOT NULL, domain TEXT NOT NULL,
    kind TEXT NOT NULL, sub TEXT NOT NULL DEFAULT '', pos INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS routes_host ON routes(domain, sub) WHERE kind = 'sub';
CREATE UNIQUE INDEX IF NOT EXISTS routes_path ON routes(slug, domain) WHERE kind = 'path';
CREATE TABLE IF NOT EXISTS uptime (               -- healthchecks de la console : réussis / faits, par appli et par jour
    app TEXT NOT NULL, day TEXT NOT NULL, ok INTEGER NOT NULL, total INTEGER NOT NULL, PRIMARY KEY (app, day)
);
"""

_lock = threading.RLock()
lock = _lock
_c = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
_c.row_factory = sqlite3.Row
_c.execute("PRAGMA journal_mode=WAL")
_c.execute("PRAGMA busy_timeout=5000")
os.chmod(DB_PATH, 0o600)


def q(sql, args=()):
    with _lock:
        return [dict(r) for r in _c.execute(sql, args).fetchall()]


def one(sql, args=()):
    rows = q(sql, args)
    return rows[0] if rows else None


def x(sql, args=()):
    with _lock:
        return _c.execute(sql, args)


def init():
    with _lock:
        _c.executescript(SCHEMA)
        cols = {r["name"] for r in _c.execute("PRAGMA table_info(apps)").fetchall()}
        if "data_user" not in cols:   # '' = utilisateur de l'image, sinon "uid" ou "uid:gid"
            _c.execute("ALTER TABLE apps ADD COLUMN data_user TEXT NOT NULL DEFAULT ''")
        if "data_owner" not in cols:  # propriétaire effectivement appliqué à /data
            _c.execute("ALTER TABLE apps ADD COLUMN data_owner TEXT")
        bcols = {r["name"] for r in _c.execute("PRAGMA table_info(backups)").fetchall()}
        if "dest" not in bcols:   # destination de la sauvegarde : gdrive, nas… (NULL = locale)
            _c.execute("ALTER TABLE backups ADD COLUMN dest TEXT")
            _c.execute("UPDATE backups SET dest = 'gdrive' WHERE remote = 1")
        ncols = {r["name"] for r in _c.execute("PRAGMA table_info(nodes)").fetchall()}
        if "ingress" not in ncols:   # 1 : le nœud reçoit le trafic Internet (Caddy + connecteur du tunnel)
            _c.execute("ALTER TABLE nodes ADD COLUMN ingress INTEGER NOT NULL DEFAULT 1")
        if "security" not in ncols:  # sécurité propre au nœud (JSON) ; NULL = politique générale
            _c.execute("ALTER TABLE nodes ADD COLUMN security TEXT")
        if "sec" not in ncols:       # sécurité appliquée et observée (JSON)
            _c.execute("ALTER TABLE nodes ADD COLUMN sec TEXT")
        if "ssh_user" not in ncols:  # compte SSH de l'installation (root, ou un compte avec sudo)
            _c.execute("ALTER TABLE nodes ADD COLUMN ssh_user TEXT NOT NULL DEFAULT 'root'")
        if "node" not in cols:   # nœud qui héberge l'appli ('local' = la machine de la console)
            _c.execute("ALTER TABLE apps ADD COLUMN node TEXT NOT NULL DEFAULT 'local'")
        if "latest_version" not in cols:  # dernière version trouvée sur le registre
            _c.execute("ALTER TABLE apps ADD COLUMN latest_version TEXT")
            _c.execute("ALTER TABLE apps ADD COLUMN latest_checked REAL")
            _c.execute("ALTER TABLE apps ADD COLUMN latest_error TEXT")
    defaults = {
        "base_domain": os.environ.get("BASE_DOMAIN", "piperault.fr"),
        "hub": os.environ.get("HUB", "apps"),
        "aliases": "[]",
        "mode": os.environ.get("EXPOSURE_MODE", "tunnel"),   # tunnel | direct
        "ntfy_server": "https://ntfy.sh",
        "ntfy_topic": "hangar-" + os.urandom(9).hex(),
        "ntfy_token": "",
        "alerts_on": "1",
        "backup_keep": json.dumps({"daily": 7, "weekly": 4, "monthly": 12}),
    }
    for k, v in defaults.items():
        x("INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)", (k, v))
    from . import domains   # base_domain / alias / mode global → table domains (une seule fois)
    domains.migrate_from_settings()


def settings():
    s = {r["key"]: r["value"] for r in q("SELECT key, value FROM settings")}
    s["aliases"] = json.loads(s.get("aliases") or "[]")
    s["lan_cidr"] = os.environ.get("LAN_CIDR", "192.168.91.0/24")
    s["admin_bind"] = os.environ.get("ADMIN_BIND", "192.168.91.93:8443")
    s["tunnel_bind"] = os.environ.get("TUNNEL_BIND", "127.0.0.1:8080")
    d = one("SELECT name, hub FROM domains ORDER BY is_default DESC, created_at LIMIT 1")
    s["domain"] = d["name"] if d else ""
    s["home"] = (f"{d['hub']}.{d['name']}" if d["hub"] else d["name"]) if d else ""
    return s


def set_setting(key, value):
    if isinstance(value, (list, dict)):
        value = json.dumps(value)
    x("INSERT INTO settings(key, value) VALUES(?, ?) "
      "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))


def apps():
    return q("SELECT * FROM apps ORDER BY name COLLATE NOCASE")


def app(slug):
    return one("SELECT * FROM apps WHERE slug = ?", (slug,))


APP_FIELDS = ["name", "pkg", "expose", "sub", "source", "image", "version", "prev_version",
              "port", "host_port", "health_path", "mem_mb", "env", "db", "db_password",
              "state", "desired", "deployed_at", "created_at", "data_user", "data_owner",
              "latest_version", "latest_checked", "latest_error", "node"]


def insert_app(slug, data):
    cols = ["slug"] + [k for k in APP_FIELDS if k in data]
    x(f"INSERT INTO apps({', '.join(cols)}) VALUES({', '.join('?' * len(cols))})",
      [slug] + [data[k] for k in cols[1:]])


def update_app(slug, **fields):
    bad = set(fields) - set(APP_FIELDS)
    if bad:
        raise ValueError(f"champs inconnus : {bad}")
    if fields:
        sets = ", ".join(f"{k} = ?" for k in fields)
        x(f"UPDATE apps SET {sets} WHERE slug = ?", list(fields.values()) + [slug])


def kv_get(key, default=None):
    r = one("SELECT value, ts FROM kv WHERE key = ?", (key,))
    if not r:
        return default
    return json.loads(r["value"])


def kv_ts(key):
    r = one("SELECT ts FROM kv WHERE key = ?", (key,))
    return r["ts"] if r else None


def kv_set(key, value):
    import time
    x("INSERT INTO kv(key, value, ts) VALUES(?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
      "ts = excluded.ts", (key, json.dumps(value), time.time()))
