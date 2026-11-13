"""Rapports de plantage des applis Android, sans service extérieur.

Point d'envoi public : POST https://<hôte des routes>.<domaine>/.well-known/hangar/crash/<package>
Caddy le transmet à un petit serveur interne de la console (127.0.0.1:8099 ; les nœuds qui reçoivent le trafic
passent par le réseau privé, 10.88.0.1:8099). En-tête X-Hangar-Key (clé de l'appli, donnée par sa configuration
à distance) ; corps JSON : {version_name, version_code, os, device, exception, message, stacktrace}.
Rien de personnel n'est demandé ni gardé (pas d'adresse IP).

Les plantages sont regroupés par empreinte (type d'exception + premières lignes du code de l'appli). Alerte à la
première apparition d'un groupe, et quand un groupe marqué « corrigé » revient dans une version plus récente.
Limites : 64 Ko par rapport, 30 par minute et par adresse, 600 par heure et par appli ; 90 jours, 5000 par appli.
"""
import hashlib
import http.server
import json
import re
import secrets
import threading
import time

from . import alerts, db
from . import platform as P

PORT = 8099
MAX_BODY = 64 * 1024
_rate = {}            # clé -> [début de fenêtre, compte]
_rl = threading.Lock()
_started = False
FRAMEWORK = ("java.", "javax.", "kotlin.", "kotlinx.", "android.", "androidx.", "com.android.", "dalvik.", "sun.",
             "libcore.", "com.google.android.", "okhttp3.", "retrofit2.")


def key(slug):
    """Clé d'envoi de l'appli (créée au premier besoin). Elle est publique (dans l'appli) : elle trie, ne protège pas."""
    keys = db.kv_get("crash_keys") or {}
    if slug not in keys:
        keys[slug] = secrets.token_urlsafe(18)
        db.kv_set("crash_keys", keys)
    return keys[slug]


def _limited(k, limit, window):
    now = time.time()
    with _rl:
        start, n = _rate.get(k, (now, 0))
        if now - start > window:
            start, n = now, 0
        n += 1
        _rate[k] = (start, n)
        if len(_rate) > 20000:
            _rate.clear()
        return n > limit


def fingerprint(exc, trace, pkg):
    """Empreinte stable d'un plantage : type d'exception + 3 premières lignes « at » du code de l'appli
    (sinon les 3 premières tout court), sans numéros de ligne."""
    frames = [l.strip()[3:] for l in (trace or "").splitlines() if l.strip().startswith("at ")]
    root = pkg.rsplit(".", 1)[0] if pkg.count(".") >= 2 else pkg
    mine = [f for f in frames if f.startswith(root) or not f.startswith(FRAMEWORK)]
    top = [re.sub(r"\(.*?\)", "", f) for f in (mine or frames)[:3]]
    return hashlib.sha1(("|".join([exc or "?"] + top)).encode()).hexdigest()[:12], (top[0] if top else "")


def record(slug, pkg, data, now=None):
    """Enregistre un rapport ; alerte si c'est un nouveau groupe ou une régression. Retourne l'empreinte."""
    now = now or time.time()
    s = lambda k, n: str(data.get(k) or "")[:n]   # noqa: E731
    exc, msg, trace = s("exception", 300), s("message", 1000), s("stacktrace", 16000)
    try:
        vcode = int(data.get("version_code") or 0)
    except (TypeError, ValueError):
        vcode = 0
    fp, top = fingerprint(exc, trace, pkg)
    db.x("INSERT INTO crashes(slug, ts, fp, vname, vcode, os, device, exc, msg, trace) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
         (slug, now, fp, s("version_name", 40), vcode, s("os", 60), s("device", 80), exc, msg, trace))
    g = db.one("SELECT * FROM crash_groups WHERE slug = ? AND fp = ?", (slug, fp))
    a = db.app(slug)
    name = a["name"] if a else slug
    if not g:
        db.x("INSERT INTO crash_groups(slug, fp, first, last, count, status, exc, msg, top, vmax) "
             "VALUES(?, ?, ?, ?, 1, 'open', ?, ?, ?, ?)", (slug, fp, now, now, exc, msg[:300], top, vcode))
        P.log("error", slug, f"nouveau plantage Android : {exc or '?'} {('à ' + top) if top else ''}"[:300])
        alerts.send(f"{name} : nouveau plantage Android", f"{exc}: {msg[:200]}\n{top}\nVersion {s('version_name', 40)} "
                    f"({vcode}), {s('device', 80)}", priority=4, tags=["boom"], key=f"crash:{slug}:{fp}", cooldown=3600)
        return fp
    reopen = g["status"] == "resolved" and vcode > (g["resolved_code"] or 0)
    db.x("UPDATE crash_groups SET last = ?, count = count + 1, vmax = max(vmax, ?), status = ? WHERE slug = ? AND fp = ?",
         (now, vcode, "open" if reopen else g["status"], slug, fp))
    if reopen:
        P.log("error", slug, f"plantage Android revenu après correction : {exc} (version {vcode})")
        alerts.send(f"{name} : un plantage corrigé revient", f"{exc}: {msg[:200]}\n{top}\nVersion {s('version_name', 40)} "
                    f"({vcode}), marqué corrigé en {g['resolved_code']}.", priority=4, tags=["boom"],
                    key=f"crash:{slug}:{fp}", cooldown=3600)
    return fp


def groups(slug):
    return db.q("SELECT * FROM crash_groups WHERE slug = ? ORDER BY status = 'resolved', last DESC LIMIT 100", (slug,))


def latest(slug, fp, n=1):
    return db.q("SELECT * FROM crashes WHERE slug = ? AND fp = ? ORDER BY id DESC LIMIT ?", (slug, fp, n))


def versions(slug, fp):
    return db.q("SELECT vname, vcode, count(*) n FROM crashes WHERE slug = ? AND fp = ? GROUP BY vname, vcode "
                "ORDER BY vcode DESC LIMIT 8", (slug, fp))


def set_status(slug, fp, status):
    a = db.app(slug)
    vmax = db.one("SELECT vmax FROM crash_groups WHERE slug = ? AND fp = ?", (slug, fp))
    if status == "delete":
        db.x("DELETE FROM crashes WHERE slug = ? AND fp = ?", (slug, fp))
        db.x("DELETE FROM crash_groups WHERE slug = ? AND fp = ?", (slug, fp))
    elif vmax:
        db.x("UPDATE crash_groups SET status = ?, resolved_code = ? WHERE slug = ? AND fp = ?",
             (status, vmax["vmax"] if status == "resolved" else None, slug, fp))
    return a


def purge(now=None):
    now = now or time.time()
    db.x("DELETE FROM crashes WHERE ts < ?", (now - 90 * 86400,))
    db.x("DELETE FROM crash_groups WHERE last < ?", (now - 90 * 86400,))
    for r in db.q("SELECT slug, count(*) n FROM crashes GROUP BY slug HAVING n > 5000"):
        db.x("DELETE FROM crashes WHERE slug = ? AND id NOT IN (SELECT id FROM crashes WHERE slug = ? "
             "ORDER BY id DESC LIMIT 5000)", (r["slug"], r["slug"]))


# ---------------------------------------------------------------- point d'envoi (serveur interne)

class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "hangar-crash"

    def _out(self, code, text=""):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        m = re.fullmatch(r"/\.well-known/hangar/crash/([A-Za-z0-9_.]{3,150})", self.path.split("?")[0])
        if not m:
            return self._out(404, "inconnu")
        pkg = m.group(1)
        a = db.one("SELECT * FROM apps WHERE pkg = ?", (pkg,))
        if not a:
            return self._out(404, "appli inconnue")
        ip = (self.headers.get("X-Real-IP") or self.client_address[0])[:64]
        if _limited(f"ip:{ip}", 30, 60) or _limited(f"app:{a['slug']}", 600, 3600):
            return self._out(429, "trop de rapports")
        if self.headers.get("X-Hangar-Key") != key(a["slug"]):
            return self._out(403, "clé refusée")
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if not 0 < n <= MAX_BODY:
            return self._out(413, "rapport trop gros")
        try:
            data = json.loads(self.rfile.read(n).decode("utf-8", "replace"))
            if not isinstance(data, dict):
                raise ValueError
        except ValueError:
            return self._out(400, "JSON attendu")
        record(a["slug"], pkg, data)
        return self._out(204)

    def log_message(self, *a):
        pass


def _serve(host):
    try:
        srv = http.server.ThreadingHTTPServer((host, PORT), _Handler)
    except OSError as e:
        P.log("warn", "console", f"point d'envoi des plantages indisponible sur {host}:{PORT} : {e}")
        return
    srv.daemon_threads = True
    srv.serve_forever()


def start():
    """Écoute sur 127.0.0.1 (Caddy de la console) et sur l'adresse privée de la console (Caddy des nœuds)."""
    global _started
    if _started:
        return
    _started = True
    for host in ("127.0.0.1", P.node_wg(P.LOCAL)):
        if host:
            threading.Thread(target=_serve, args=(host,), daemon=True, name=f"crash-{host}").start()
