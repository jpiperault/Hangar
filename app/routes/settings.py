"""Réglages : accès, comptes, registres, journal d'audit."""
import asyncio
import re

from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse

from .. import access, db
from .. import platform as P
from .common import flash, go, ph, render

router = APIRouter()


# ---------------------------------------------------------------- réglages : accès, comptes, registres

@router.get("/settings")
async def settings_page(request: Request):
    return render(request, "settings.html", title="Réglages", nav="settings", acc=access.current(),
                  ips=access.local_ips(), pending=access.pending(), client=request.client.host,
                  users=db.q("SELECT username, role FROM users ORDER BY username"), registries=P.registry_logins(),
                  audit=db.q("SELECT * FROM audit ORDER BY id DESC LIMIT 15"),
                  aform=request.session.pop("aform", None), aerr=request.session.pop("aerr", None))


@router.post("/settings/access")
async def settings_access(request: Request):
    f = await request.form()
    errs, new = access.validate(f.get("ip"), f.get("port"), f.get("nets"), request.client.host)
    cur = access.current()
    if not errs and new["ip"] == cur["ip"] and new["port"] == cur["port"] and new["nets"] == cur["nets"]:
        flash(request, "Rien n'a changé.")
        return go("/settings#acces")
    if errs:
        request.session["aform"] = {"ip": f.get("ip"), "port": f.get("port"), "nets": f.get("nets")}
        request.session["aerr"] = errs
        flash(request, " ".join(errs.values()), "error")
        return go("/settings#acces")
    try:
        url = await asyncio.to_thread(access.apply, new, request.session.get("user"))
    except (ValueError, RuntimeError) as e:
        flash(request, str(e), "error")
        return go("/settings#acces")
    return render(request, "access_moved.html", title="Accès modifié", nav="settings", url=url, delay=access.DELAY)


@router.post("/settings/access/confirm")
async def settings_access_confirm(request: Request):
    await asyncio.to_thread(access.confirm, request.session.get("user"))
    flash(request, "Nouvel accès confirmé : il est gardé.")
    return go("/settings#acces")


@router.post("/settings/access/revert")
async def settings_access_revert(request: Request):
    P.spawn(access.revert)
    return PlainTextResponse("Ancien réglage remis : la console redémarre sur son ancienne adresse.")


@router.post("/settings/registry/remove")
async def remove_registry(request: Request):
    reg = ((await request.form()).get("registry") or "").strip()
    if reg in P.registry_logins():
        await asyncio.to_thread(P.registry_logout, reg)
        flash(request, f"Identifiants retirés pour {reg}. Les images déjà téléchargées restent utilisables.")
    return go("/settings")


USER_RE = re.compile(r"^[a-z][a-z0-9._-]{1,31}$")


def _check_pw(f):
    pw = f.get("password") or ""
    if len(pw) < 10:
        return None, "Mot de passe : 10 caractères au moins."
    if pw != (f.get("password2") or ""):
        return None, "Les deux saisies du mot de passe diffèrent."
    return pw, None


@router.post("/users/add")
async def users_add(request: Request):
    f = await request.form()
    name = (f.get("username") or "").strip().lower()
    pw, err = _check_pw(f)
    if not USER_RE.match(name):
        err = "Identifiant : lettres minuscules, chiffres, . _ -, 2 à 32 caractères."
    elif db.one("SELECT 1 FROM users WHERE username = ?", (name,)):
        err = "Ce compte existe déjà."
    if err:
        flash(request, err, "error")
        return go("/settings#comptes")
    role = "lecture" if f.get("role") == "lecture" else "admin"
    db.x("INSERT INTO users(username, hash, role) VALUES(?, ?, ?)", (name, ph.hash(pw), role))
    P.log("ok", "console", f"compte {name} ({'lecture seule' if role == 'lecture' else 'administrateur'}) créé par "
          f"{request.session.get('user')}")
    flash(request, f"Compte {name} créé.")
    return go("/settings#comptes")


@router.post("/users/{name}/password")
async def users_password(request: Request, name: str):
    f = await request.form()
    me = request.session.get("user")
    u = db.one("SELECT * FROM users WHERE username = ?", (name,))
    if not u:
        return go("/settings#comptes")
    if name == me:
        try:
            ok = ph.verify(u["hash"], f.get("current") or "")
        except (VerifyMismatchError, InvalidHashError):
            ok = False
        if not ok:
            await asyncio.sleep(1)
            flash(request, "Mot de passe actuel incorrect.", "error")
            return go("/settings#comptes")
    pw, err = _check_pw(f)
    if err:
        flash(request, err, "error")
        return go("/settings#comptes")
    db.x("UPDATE users SET hash = ? WHERE username = ?", (ph.hash(pw), name))
    db.x("DELETE FROM sessions WHERE username = ? AND id != ?", (name, request.session.get("sid") or ""))
    P.log("ok", "console", f"mot de passe de {name} changé par {me} (ses autres sessions sont fermées)")
    flash(request, f"Mot de passe de {name} changé.")
    return go("/settings#comptes")


@router.post("/users/{name}/remove")
async def users_remove(request: Request, name: str):
    me = request.session.get("user")
    if name == me:
        flash(request, "Tu ne peux pas supprimer ton propre compte.", "error")
    elif db.one("SELECT COUNT(*) AS n FROM users")["n"] <= 1:
        flash(request, "Il faut garder au moins un compte.", "error")
    elif _last_admin(name):
        flash(request, "Il faut garder au moins un compte administrateur.", "error")
    else:
        db.x("DELETE FROM users WHERE username = ?", (name,))
        db.x("DELETE FROM sessions WHERE username = ?", (name,))
        P.log("info", "console", f"compte {name} supprimé par {me}")
        flash(request, f"Compte {name} supprimé, ses sessions sont fermées.")
    return go("/settings#comptes")


def _last_admin(name):
    u = db.one("SELECT role FROM users WHERE username = ?", (name,))
    return bool(u and u["role"] == "admin" and db.one("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'")["n"] <= 1)


@router.post("/users/{name}/role")
async def users_role(request: Request, name: str):
    f = await request.form()
    role = "lecture" if f.get("role") == "lecture" else "admin"
    if not db.one("SELECT 1 FROM users WHERE username = ?", (name,)):
        return go("/settings#comptes")
    if role == "lecture" and _last_admin(name):
        flash(request, "Il faut garder au moins un compte administrateur.", "error")
        return go("/settings#comptes")
    db.x("UPDATE users SET role = ? WHERE username = ?", (role, name))
    P.log("info", "console", f"compte {name} : {'lecture seule' if role == 'lecture' else 'administrateur'} "
          f"(par {request.session.get('user')})")
    flash(request, f"Compte {name} : {'lecture seule' if role == 'lecture' else 'administrateur'}.")
    return go("/settings#comptes")


@router.get("/settings/audit")
async def audit_page(request: Request):
    who = request.query_params.get("u") or ""
    rows = db.q("SELECT * FROM audit WHERE (? = '' OR username = ?) ORDER BY id DESC LIMIT 500", (who, who))
    return render(request, "audit.html", title="Journal des actions", nav="settings", rows=rows, who=who,
                  users=[r["username"] for r in db.q("SELECT DISTINCT username FROM audit WHERE username IS NOT NULL")])
