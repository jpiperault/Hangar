"""Console Hangar : application web (démarrage, protections communes). Les routes sont dans app/routes/."""
import asyncio  # noqa: F401  (utilisé par les essais : main.asyncio.sleep)
import ipaddress
import os
import secrets
import time
import urllib.parse

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from . import access, cache, crashes, db, monitor
from . import platform as P
from .routes.common import HERE, SESSION_IDLE

LAN = access.parse_nets(os.environ.get("LAN_CIDR", "192.168.91.0/24"))

db.init()
P.recover()
monitor.start()
crashes.start()   # point d'envoi des rapports de plantage (Caddy → 127.0.0.1:8099 / 10.88.0.1:8099)
# mesures lentes gardées au chaud : les pages ne font jamais attendre un nœud
cache.keep_warm("states", 20, P.container_states)
cache.keep_warm("mem", 20, P.mem_usage)


def _secret():
    path = os.environ.get("HANGAR_SECRET_FILE", "/srv/platform/hangar.secret")
    if not os.path.exists(path):
        P.write_private(path, secrets.token_hex(32))
    return open(path).read().strip()


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=f"{HERE}/static"), name="static")


AUDIT_GET = ("/download", "/db/export")   # lectures qui sortent des données : tracées aussi
READONLY_OK = ("/logout",)


def _readonly_refused(request, user):
    """Message de refus si un compte en lecture seule tente une action (ou une lecture de secrets), sinon None."""
    if getattr(request.state, "role", "admin") != "lecture":
        return None
    p = request.url.path
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return "Compte en lecture seule : téléchargement réservé aux administrateurs." if p.endswith(AUDIT_GET) else None
    if p in READONLY_OK or p == f"/users/{user}/password":
        return None
    return "Compte en lecture seule : cette action est réservée aux administrateurs."


def _audit(request, user, ip, status, detail=None):
    try:
        db.x("INSERT INTO audit(ts, username, ip, method, path, status, detail) VALUES(?, ?, ?, ?, ?, ?, ?)",
             (time.time(), user, ip, request.method, request.url.path[:300], status, detail))
    except Exception:
        pass


@app.middleware("http")
async def guard(request: Request, call_next):
    ip = request.client.host if request.client else ""
    try:
        addr = ipaddress.ip_address(ip)
        allowed = any(addr in n for n in LAN) or addr.is_loopback
    except ValueError:
        allowed = False
    if not allowed:
        return PlainTextResponse("Console réservée au réseau local.", status_code=403)
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        # formulaires : refusés s'ils viennent d'un autre site (en plus du cookie SameSite=Strict)
        # Sec-Fetch-Site d'abord (envoyé par tous les navigateurs récents) ; sinon l'en-tête Origin.
        # Avec Referrer-Policy no-referrer, Chrome envoie « Origin: null » même pour la page elle-même.
        sfs, origin = request.headers.get("sec-fetch-site"), request.headers.get("origin")
        if (sfs and sfs not in ("same-origin", "none")) or (
                not sfs and origin not in (None, "null", f"{request.url.scheme}://{request.url.netloc}")):
            return PlainTextResponse("Requête d'un autre site refusée.", status_code=403)
    request.state.nonce = secrets.token_urlsafe(16)
    if not request.url.path.startswith(("/login", "/static")):
        u, sid = request.session.get("user"), request.session.get("sid")
        row = db.one("SELECT s.seen, u.role FROM sessions s JOIN users u ON u.username = s.username "
                     "WHERE s.id = ? AND s.username = ?", (sid or "", u or "")) if u and sid else None
        now = time.time()
        if not row or now - row["seen"] > SESSION_IDLE:   # déconnectée, compte supprimé ou inactive trop longtemps
            if sid:
                db.x("DELETE FROM sessions WHERE id = ?", (sid,))
            request.session.clear()
            return RedirectResponse("/login", status_code=303)
        if now - row["seen"] > 60:
            db.x("UPDATE sessions SET seen = ? WHERE id = ?", (now, sid))
        request.state.role = row["role"]
        refused = _readonly_refused(request, u)
        if refused:
            _audit(request, u, ip, 403, "refusé : compte en lecture seule")
            request.session["flash"] = {"msg": refused, "kind": "error"}
            back = request.headers.get("referer") or "/"
            path = urllib.parse.urlsplit(back).path if back.startswith(("http", "/")) else "/"
            return RedirectResponse(path if path.startswith("/") and not path.startswith("//") else "/", status_code=303)
    response = await call_next(request)
    if request.method not in ("GET", "HEAD", "OPTIONS") or request.url.path.endswith(AUDIT_GET):
        _audit(request, request.session.get("user") or (request.url.path == "/login" and "(connexion)") or None, ip,
               response.status_code)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        f"default-src 'self'; script-src 'self' 'nonce-{request.state.nonce}'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'")
    return response


app.add_middleware(SessionMiddleware, secret_key=_secret(), session_cookie="hangar",
                   max_age=8 * 3600, same_site="strict", https_only=True)


class _Gzip:
    """Pages et fichiers statiques compressés ; jamais les téléchargements en flux (archives, exports)."""
    SKIP = ("/download", "/db/export")

    def __init__(self, app):
        from starlette.middleware.gzip import GZipMiddleware
        self.app, self.gz = app, GZipMiddleware(app, minimum_size=1024, compresslevel=5)

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and not scope["path"].endswith(self.SKIP):
            return await self.gz(scope, receive, send)
        return await self.app(scope, receive, send)


app.add_middleware(_Gzip)


# routes, dans l'ordre (les plus précises avant /apps/{slug}/{action})
from .routes import (appdata, apps, auth, backups, domains, features, ha, monitoring, nodes,  # noqa: E402
                     pages, settings, sitepub, system)
from .routes.auth import LOGIN_MAX_IP, _fails  # noqa: E402,F401  (pour les essais)

for _r in (auth, ha, features, sitepub, apps, domains, settings, pages, backups, system, appdata, monitoring, nodes):
    app.include_router(_r.router)
