"""Alertes par ntfy : une notification push sur le téléphone, abonné à un sujet secret."""
import json
import threading
import time
import urllib.request

from . import db

_last = {}          # clé -> horodatage du dernier envoi (anti-rafale)
_lock = threading.Lock()


def _post(s, title, msg, priority, tags):
    # publication JSON : titre et message en UTF-8 sans passer par les en-têtes HTTP
    body = json.dumps({"topic": s["ntfy_topic"], "title": title, "message": msg[:3900],
                       "priority": priority, "tags": tags}).encode()
    req = urllib.request.Request(s["ntfy_server"].rstrip("/") + "/", data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    if s.get("ntfy_token"):
        req.add_header("Authorization", f"Bearer {s['ntfy_token']}")
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status


def send(title, msg, priority=3, tags=None, key=None, cooldown=0, force=False):
    """Envoie une alerte. `key` + `cooldown` évitent de répéter la même alerte trop souvent.
    Retourne (envoyé, erreur)."""
    s = db.settings()
    if not force and s.get("alerts_on") != "1":
        return False, "alertes désactivées"
    if not s.get("ntfy_topic"):
        return False, "aucun sujet ntfy"
    if key and cooldown:
        with _lock:
            if time.time() - _last.get(key, 0) < cooldown:
                return False, "déjà envoyée récemment"
            _last[key] = time.time()
    try:
        _post(s, title, msg, priority, tags or [])
        return True, ""
    except Exception as e:  # le réseau ne doit jamais faire échouer l'opération qui alerte
        err = str(getattr(e, "reason", e))
        db.x("INSERT INTO events(ts, level, app, msg) VALUES(?, ?, ?, ?)",
             (time.time(), "warn", "alertes", f"notification non envoyée ({title}) : {err}"[:500]))
        return False, err


def send_async(*args, **kw):
    threading.Thread(target=send, args=args, kwargs=kw, daemon=True).start()
