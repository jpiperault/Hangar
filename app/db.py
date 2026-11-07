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
"""

_lock = threading.RLock()
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
    defaults = {
        "base_domain": os.environ.get("BASE_DOMAIN", "piperault.fr"),
        "hub": os.environ.get("HUB", "apps"),
        "aliases": "[]",
        "mode": os.environ.get("EXPOSURE_MODE", "tunnel"),   # tunnel | direct
    }
    for k, v in defaults.items():
        x("INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)", (k, v))


def settings():
    s = {r["key"]: r["value"] for r in q("SELECT key, value FROM settings")}
    s["aliases"] = json.loads(s.get("aliases") or "[]")
    s["lan_cidr"] = os.environ.get("LAN_CIDR", "192.168.91.0/24")
    s["admin_bind"] = os.environ.get("ADMIN_BIND", "192.168.91.93:8443")
    s["tunnel_bind"] = os.environ.get("TUNNEL_BIND", "127.0.0.1:8080")
    s.setdefault("mode", "tunnel")
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
              "state", "desired", "deployed_at", "created_at", "data_user", "data_owner"]


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
