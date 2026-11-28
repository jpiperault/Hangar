"""Jetons d'API : piloter Hangar sans la console web (scripts, CI, serveur MCP pour Claude).

Un jeton appartient à un compte et n'a jamais plus de droits que lui (rôle, applis choisies). Sa portée le restreint
encore : « read » (lire : applis, état, journal, logs, trafic) ou « deploy » (lire, puis déployer une version,
démarrer, arrêter, redémarrer). Rien d'autre n'est possible par l'API : ni suppression, ni réglages, ni secrets.

Le jeton (« hgr_… », 256 bits) n'est affiché qu'une fois, à sa création ; seule son empreinte SHA-256 est gardée,
dans kv « api_tokens » : [{id, name, user, scope, hash, created, last_used, last_ip}]. L'API, comme la console,
ne répond que sur le réseau local.
"""
import hashlib
import hmac
import re
import secrets
import time

from . import db

PREFIX = "hgr_"
SCOPES = {"read": "lecture", "deploy": "lecture et déploiement"}
NAME_RE = re.compile(r"^[\w .@-]{1,60}$")
MAX = 50


def _all():
    return db.kv_get("api_tokens") or []


def _hash(tok):
    return hashlib.sha256(tok.encode()).hexdigest()


def create(user, name, scope):
    """Nouveau jeton ; retourne (id, jeton en clair : à montrer une seule fois)."""
    name = (name or "").strip()
    if not NAME_RE.match(name):
        raise ValueError("nom : lettres, chiffres, espaces, . @ - (60 au plus), par exemple « Claude » ou « CI GitHub »")
    if scope not in SCOPES:
        raise ValueError("portée inconnue")
    if not db.one("SELECT 1 FROM users WHERE username = ?", (user,)):
        raise ValueError("compte inconnu")
    items = _all()
    if len(items) >= MAX:
        raise ValueError(f"{MAX} jetons au plus")
    tok = PREFIX + secrets.token_urlsafe(32)
    tid = secrets.token_hex(4)
    items.append({"id": tid, "name": name, "user": user, "scope": scope, "hash": _hash(tok), "created": time.time(),
                  "last_used": None, "last_ip": None})
    db.kv_set("api_tokens", items)
    return tid, tok


def of_user(user=None):
    """Jetons visibles (sans empreinte), d'un compte ou de tous."""
    return [{k: v for k, v in t.items() if k != "hash"} for t in _all() if user is None or t["user"] == user]


def revoke(tid, user=None):
    """Retire un jeton (user : seulement s'il lui appartient). True s'il existait."""
    items = _all()
    keep = [t for t in items if not (t["id"] == tid and (user is None or t["user"] == user))]
    if len(keep) != len(items):
        db.kv_set("api_tokens", keep)
        return True
    return False


def forget_user(user):
    items = _all()
    keep = [t for t in items if t["user"] != user]
    if len(keep) != len(items):
        db.kv_set("api_tokens", keep)


def check(header, ip=""):
    """En-tête Authorization → jeton valide {id, name, user, scope, role}, ou None."""
    m = re.fullmatch(r"Bearer\s+(hgr_[A-Za-z0-9_-]{20,100})", (header or "").strip())
    if not m:
        return None
    h = _hash(m.group(1))
    items = _all()
    for t in items:
        if hmac.compare_digest(t["hash"], h):
            row = db.one("SELECT role FROM users WHERE username = ?", (t["user"],))
            if not row:
                return None
            if not t.get("last_used") or time.time() - t["last_used"] > 60:
                t["last_used"], t["last_ip"] = time.time(), ip
                db.kv_set("api_tokens", items)
            return {"id": t["id"], "name": t["name"], "user": t["user"], "scope": t["scope"], "role": row["role"]}
    return None
