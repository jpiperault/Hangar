"""Connexion et déconnexion."""
import asyncio
import secrets
import time

from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import APIRouter, Request

from .. import alerts, db, totp
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
    if user["totp_secret"]:   # double authentification : le code avant d'ouvrir la session
        request.session.clear()
        request.session["pending"] = {"u": user["username"], "ts": now}
        return go("/login/code")
    _new_session(request, user["username"])
    P.log("info", "console", f"connexion de {user['username']} depuis {ip}")
    return _with_lang(go("/"), user["username"])


def _with_lang(resp, username):
    """La page de connexion parlera la langue du dernier compte connecté depuis ce navigateur."""
    u = db.one("SELECT lang FROM users WHERE username = ?", (username,))
    resp.set_cookie("hangar_lang", (u and u["lang"]) or "fr", max_age=365 * 86400, secure=True, httponly=True,
                    samesite="strict")
    return resp


PENDING_MAX = 5 * 60   # le code doit suivre le mot de passe dans les 5 minutes


def _pending(request):
    p = request.session.get("pending") or {}
    if not p.get("u") or time.time() - p.get("ts", 0) > PENDING_MAX:
        request.session.pop("pending", None)
        return None
    return p["u"]


@router.get("/login/code")
async def login_code_page(request: Request):
    name = _pending(request)
    if not name:
        return go("/login")
    return render(request, "login_code.html", title="Connexion", pending_user=name)


@router.post("/login/code")
async def login_code(request: Request):
    name = _pending(request)
    if not name:
        flash(request, "Délai dépassé : reconnecte-toi.", "error")
        return go("/login")
    ip = request.client.host if request.client else "?"
    now = time.time()
    by_ip, by_user = _recent(("ip", ip), now), _recent(("user", name.lower()), now)
    if len(by_ip) >= LOGIN_MAX_IP or len(by_user) >= LOGIN_MAX_IP:
        request.session.clear()
        flash(request, "Trop d'essais. Réessaie dans 15 min.", "error")
        return go("/login")
    how = await asyncio.to_thread(totp.verify_login, name, (await request.form()).get("code") or "")
    if not how:
        for k in (("ip", ip), ("user", name.lower())):
            _fails.setdefault(k, []).append(now)
        P.log("warn", "console", f"code de double authentification refusé pour « {name} » depuis {ip}")
        await asyncio.sleep(1)
        flash(request, "Code incorrect ou déjà utilisé.", "error")
        return go("/login/code")
    _fails.pop(("ip", ip), None)
    _new_session(request, name)
    left = totp.recovery_left(name)
    P.log("info", "console", f"connexion de {name} depuis {ip} (double authentification"
          + (f", code de secours : {left} restant(s))" if how == "secours" else ")"))
    if how == "secours":
        flash(request, f"Connecté avec un code de secours : il en reste {left}. Pense à en générer de nouveaux "
              "(Accès et comptes).", "error" if left < 3 else "ok")
    return _with_lang(go("/"), name)


@router.post("/logout")
async def logout(request: Request):
    if request.session.get("sid"):
        db.x("DELETE FROM sessions WHERE id = ?", (request.session["sid"],))
    request.session.clear()
    return go("/login")
