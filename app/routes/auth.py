"""Connexion et déconnexion."""
import asyncio
import secrets
import time

from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import APIRouter, Request

from .. import alerts, db
from .. import platform as P
from .common import SESSION_IDLE, flash, go, ph, render

router = APIRouter()


# ---------------------------------------------------------------- connexion

@router.get("/login")
async def login_page(request: Request):
    if request.session.get("user"):
        return go("/")
    return render(request, "login.html", title="Connexion")
LOGIN_WINDOW = 15 * 60            # fenêtre de comptage des échecs
LOGIN_MAX_IP, LOGIN_MAX_USER = 5, 20
_fails = {}                       # ("ip"|"user", valeur) -> [horodatages d'échec]
_verify_gate = asyncio.Semaphore(2)
_DUMMY = ph.hash(secrets.token_hex(16))   # vérifié pour un compte inconnu : même temps de réponse


def _recent(key, now):
    lst = [t for t in _fails.get(key, []) if now - t < LOGIN_WINDOW]
    if lst:
        _fails[key] = lst
    else:
        _fails.pop(key, None)
    return lst


def _new_session(request, username):
    request.session.clear()
    sid = secrets.token_urlsafe(32)
    now = time.time()
    db.x("INSERT INTO sessions(id, username, created, seen, ip) VALUES(?, ?, ?, ?, ?)",
         (sid, username, now, now, request.client.host if request.client else ""))
    db.x("DELETE FROM sessions WHERE seen < ?", (now - SESSION_IDLE,))
    request.session.update(user=username, sid=sid)


@router.post("/login")
async def login(request: Request):
    f = await request.form()
    name = (f.get("username") or "").strip()[:64]
    ip = request.client.host if request.client else "?"
    now = time.time()
    by_ip, by_user = _recent(("ip", ip), now), _recent(("user", name.lower()), now)
    if len(by_ip) >= LOGIN_MAX_IP or len(by_user) >= LOGIN_MAX_USER:
        await asyncio.sleep(1.5)
        wait = int(LOGIN_WINDOW - (now - min(by_ip if len(by_ip) >= LOGIN_MAX_IP else by_user))) // 60 + 1
        flash(request, f"Trop d'essais. Réessaie dans {wait} min.", "error")
        return go("/login")
    user = db.one("SELECT * FROM users WHERE username = ?", (name,))
    async with _verify_gate:   # vérifications Argon2 en série : pas de force brute en parallèle
        try:
            ok = await asyncio.to_thread(ph.verify, user["hash"] if user else _DUMMY, f.get("password") or "")
            ok = ok and bool(user)
        except (VerifyMismatchError, InvalidHashError):
            ok = False
    if not ok:
        for k in (("ip", ip), ("user", name.lower())):
            _fails.setdefault(k, []).append(now)
        n = len(_fails[("ip", ip)])
        if n <= LOGIN_MAX_IP:
            P.log("warn", "console", f"échec de connexion pour « {name[:32]} » depuis {ip}"
                  + (" : adresse bloquée 15 min" if n == LOGIN_MAX_IP else ""))
        if n == LOGIN_MAX_IP or len(_fails[("user", name.lower())]) == LOGIN_MAX_USER:
            P.spawn(alerts.send, "Hangar : tentatives de connexion", f"{n} échecs depuis {ip} (compte « {name[:32]} »), "
                    "connexion bloquée 15 min.", 4, ["warning"], f"login-{ip}", 900)
        await asyncio.sleep(1.5)
        flash(request, "Identifiant ou mot de passe incorrect.", "error")
        return go("/login")
    _fails.pop(("ip", ip), None)
    _new_session(request, user["username"])
    P.log("info", "console", f"connexion de {user['username']} depuis {ip}")
    return go("/")


@router.post("/logout")
async def logout(request: Request):
    if request.session.get("sid"):
        db.x("DELETE FROM sessions WHERE id = ?", (request.session["sid"],))
    request.session.clear()
    return go("/login")
