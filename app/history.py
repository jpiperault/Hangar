"""Historique des réglages d'une appli : après chaque action sur une appli dans la console, un instantané de ses réglages
est pris ; s'il diffère du dernier, il est gardé (qui, quand). On peut revoir ce qui a changé et revenir à un réglage.

Réglages suivis : nom, type, image (ou dépôt), port, adresse de santé, mémoire, base, propriétaire de /data, variables,
processeur max, ports publics, démarrage (commande, santé, dossiers). Pas la version déployée (elle a son propre retour
arrière) ni les données.
Table app_history(id, slug, ts, username, snap JSON) ; 50 instantanés gardés par appli.
"""
import json
import time

from . import db

KEEP = 50
FIELDS = ("name", "kind", "source", "image", "port", "health_path", "mem_mb", "db", "data_user", "env")
LABELS = {"name": "nom", "kind": "type", "source": "source", "image": "image", "port": "port",
          "health_path": "adresse de santé", "mem_mb": "mémoire", "db": "base PostgreSQL", "data_user": "propriétaire de /data",
          "env": "variables", "cpus": "processeur max", "ports": "ports publics", "run": "démarrage et santé"}


def init():
    db.x("CREATE TABLE IF NOT EXISTS app_history (id INTEGER PRIMARY KEY AUTOINCREMENT, slug TEXT NOT NULL, "
         "ts REAL NOT NULL, username TEXT, snap TEXT NOT NULL)")
    db.x("CREATE INDEX IF NOT EXISTS app_history_slug ON app_history(slug, id)")


def snapshot(slug):
    from . import gameports, limits, runopts
    a = db.app(slug)
    if not a:
        return None
    s = {k: a[k] for k in FIELDS}
    s.update(cpus=limits.cpus(slug), ports=gameports.of(slug), run=runopts.of(slug))
    return s


def last(slug):
    r = db.one("SELECT * FROM app_history WHERE slug = ? ORDER BY id DESC LIMIT 1", (slug,))
    return json.loads(r["snap"]) if r else None


def record(slug, username):
    """Garde l'instantané s'il a changé. Retourne True si un nouveau réglage a été noté."""
    try:
        init()
        s = snapshot(slug)
        if s is None or s == last(slug):
            return False
        db.x("INSERT INTO app_history(slug, ts, username, snap) VALUES(?, ?, ?, ?)",
             (slug, time.time(), username, json.dumps(s, ensure_ascii=False)))
        old = db.q("SELECT id FROM app_history WHERE slug = ? ORDER BY id DESC LIMIT -1 OFFSET ?", (slug, KEEP))
        if old:
            db.x("DELETE FROM app_history WHERE slug = ? AND id <= ?", (slug, old[0]["id"]))
        return True
    except Exception:
        return False


def _env_changes(old, new):
    from . import platform as P
    a, _ = P.parse_env(old or "")
    b, _ = P.parse_env(new or "")
    out = []
    for k in sorted(set(a) | set(b)):
        if k not in a:
            out.append(f"+ {k}")
        elif k not in b:
            out.append(f"− {k}")
        elif a[k] != b[k]:
            out.append(f"~ {k}")
    return out


def changes(old, new):
    """[(libellé, avant, après)] lisibles ; les valeurs des variables ne sont jamais montrées."""
    if old is None:
        return [("création du suivi", "", "")]
    out = []
    for k in list(FIELDS) + ["cpus", "ports", "run"]:
        if old.get(k) == new.get(k):
            continue
        if k == "env":
            out.append((LABELS[k], "", ", ".join(_env_changes(old.get(k), new.get(k)))))
        elif k == "ports":
            fmt = lambda v: ", ".join(f"{p['proto']} {p['port']}" for p in v or []) or "aucun"
            out.append((LABELS[k], fmt(old.get(k)), fmt(new.get(k))))
        elif k == "run":
            keys = sorted(set(old.get(k) or {}) | set(new.get(k) or {}))
            out.append((LABELS[k], "", ", ".join(x for x in keys if (old.get(k) or {}).get(x) != (new.get(k) or {}).get(x))))
        else:
            out.append((LABELS[k], str(old.get(k) if old.get(k) not in (None, "") else "—"),
                        str(new.get(k) if new.get(k) not in (None, "") else "—")))
    return out


def entries(slug, limit=20):
    init()
    rows = db.q("SELECT * FROM app_history WHERE slug = ? ORDER BY id DESC LIMIT ?", (slug, limit + 1))
    out = []
    for i, r in enumerate(rows[:limit]):
        snap = json.loads(r["snap"])
        prev = json.loads(rows[i + 1]["snap"]) if i + 1 < len(rows) else None
        out.append({"id": r["id"], "ts": r["ts"], "user": r["username"], "changes": changes(prev, snap), "current": i == 0})
    return out


def get(slug, hid):
    init()
    r = db.one("SELECT * FROM app_history WHERE slug = ? AND id = ?", (slug, hid))
    return json.loads(r["snap"]) if r else None


def restore(slug, snap):
    """Remet un réglage d'avant (registre, processeur, ports publics, démarrage). L'appelant redéploie."""
    from . import gameports, limits, runopts
    db.update_app(slug, **{k: snap[k] for k in FIELDS if k in snap})
    limits.save(slug, str(snap.get("cpus") or ""))
    gameports.save(slug, snap.get("ports") or [])
    runopts.restore(slug, snap.get("run") or {})


def drop(slug):
    init()
    db.x("DELETE FROM app_history WHERE slug = ?", (slug,))
