"""Réglages : accès, comptes, registres, journal d'audit."""
import asyncio
import re

from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse

from .. import access, db, perms, totp
from .. import platform as P
from .common import flash, go, ph, render

router = APIRouter()


# ---------------------------------------------------------------- réglages : accès, comptes, registres

@router.get("/settings")
async def settings_page(request: Request):
    return render(request, "settings.html", title="Réglages", nav="settings", acc=access.current(),
                  ips=access.local_ips(), pending=access.pending(), client=request.client.host,
                  users=db.q("SELECT username, role, totp_secret IS NOT NULL AS totp FROM users ORDER BY username"),
                  registries=P.registry_logins(), totp_setup=_setup_ctx(request), totp_codes=request.session.pop("totp_codes", None),
                  totp_left=totp.recovery_left(request.session.get("user") or ""), roles=perms.ROLES, levels=perms.LEVELS,
                  scopes=db.kv_get("user_apps") or {}, all_apps=db.q("SELECT slug, name FROM apps ORDER BY name"),
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
    role = f.get("role") if f.get("role") in perms.ROLES else "admin"
    db.x("INSERT INTO users(username, hash, role) VALUES(?, ?, ?)", (name, ph.hash(pw), role))
    P.log("ok", "console", f"compte {name} ({perms.ROLES[role]}) créé par "
          f"{request.session.get('user')}")
    flash(request, f"Compte {name} créé.")
    return go("/settings#comptes")


@router.post("/users/{name}/password")
async def users_password(request: Request, name: str):
    f = await request.form()
    me = request.session.get("user")
    u = db.one("SELECT * FROM users WHERE username = ?", (name,))
    if not u:
        return go(_mine(request) + "#comptes")
    if name == me:
        try:
            ok = ph.verify(u["hash"], f.get("current") or "")
        except (VerifyMismatchError, InvalidHashError):
            ok = False
        if not ok:
            await asyncio.sleep(1)
            flash(request, "Mot de passe actuel incorrect.", "error")
            return go(_mine(request) + "#comptes")
    pw, err = _check_pw(f)
    if err:
        flash(request, err, "error")
        return go(_mine(request) + "#comptes")
    db.x("UPDATE users SET hash = ? WHERE username = ?", (ph.hash(pw), name))
    db.x("DELETE FROM sessions WHERE username = ? AND id != ?", (name, request.session.get("sid") or ""))
    P.log("ok", "console", f"mot de passe de {name} changé par {me} (ses autres sessions sont fermées)")
    flash(request, f"Mot de passe de {name} changé.")
    return go(_mine(request) + "#comptes")


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
        perms.forget_user(name)
        db.x("DELETE FROM sessions WHERE username = ?", (name,))
        P.log("info", "console", f"compte {name} supprimé par {me}")
        flash(request, f"Compte {name} supprimé, ses sessions sont fermées.")
    return go("/settings#comptes")


def _mine(request):
    """Page où un compte gère son mot de passe et sa double authentification."""
    return "/compte" if getattr(request.state, "role", "admin") == perms.ROLE else "/settings"


@router.get("/compte")
async def my_account(request: Request):
    if getattr(request.state, "role", "admin") != perms.ROLE:
        return go("/settings#2fa")
    me = request.session.get("user")
    return render(request, "compte.html", title="Mon compte", nav="compte", my_scopes=perms.scopes(me),
                  names={a["slug"]: a["name"] for a in db.apps()}, levels=perms.LEVELS,
                  users=db.q("SELECT username, role, totp_secret IS NOT NULL AS totp FROM users WHERE username = ?", (me,)),
                  totp_setup=_setup_ctx(request), totp_codes=request.session.pop("totp_codes", None),
                  totp_left=totp.recovery_left(me))


def _setup_ctx(request):
    """Mise en place en cours de la double authentification (secret gardé dans la session signée)."""
    sec = request.session.get("totp_setup")
    if not sec:
        return None
    u = request.session.get("user")
    link = totp.uri(sec, u, db.settings().get("home") or "")
    return {"secret": " ".join(sec[i:i + 4] for i in range(0, len(sec), 4)), "qr": totp.qr_svg(link), "uri": link}


@router.post("/users/{name}/lang")
async def users_lang(request: Request, name: str):
    from .. import i18n
    me = request.session.get("user")
    lang = (await request.form()).get("lang")
    if name != me or lang not in i18n.LANGS:
        return go(_mine(request))
    db.x("UPDATE users SET lang = ? WHERE username = ?", (lang, me))
    r = go(_mine(request) + "#langue")
    r.set_cookie("hangar_lang", lang, max_age=365 * 86400, secure=True, httponly=True, samesite="strict")
    return r


@router.post("/users/{name}/2fa/{op}")
async def users_2fa(request: Request, name: str, op: str):
    me = request.session.get("user")
    back = go(_mine(request) + "#2fa")
    if not db.one("SELECT 1 FROM users WHERE username = ?", (name,)):
        return go("/settings")
    f = await request.form()
    if name != me:   # un administrateur ne peut que retirer celle d'un autre compte (téléphone perdu)
        if op == "disable" and getattr(request.state, "role", "admin") == "admin":
            totp.disable(name)
            db.x("DELETE FROM sessions WHERE username = ?", (name,))
            P.log("warn", "console", f"double authentification de {name} retirée par {me}")
            flash(request, f"Double authentification de {name} retirée : il se reconnectera avec son mot de passe seul.")
        return go("/settings#comptes")
    if op == "start":
        request.session["totp_setup"] = totp.new_secret()
        return back
    if op == "cancel":
        request.session.pop("totp_setup", None)
        return back
    if op == "confirm":
        sec = request.session.get("totp_setup")
        if not sec or totp.check(sec, f.get("code")) is None:
            flash(request, "Code incorrect : vérifie l'heure du téléphone, puis tape le code affiché maintenant.", "error")
            return back
        codes, hashes = totp.new_recovery()
        totp.enable(me, sec, hashes)
        request.session.pop("totp_setup", None)
        request.session["totp_codes"] = codes
        db.x("DELETE FROM sessions WHERE username = ? AND id != ?", (me, request.session.get("sid") or ""))
        P.log("ok", "console", f"double authentification activée pour {me}")
        flash(request, "Double authentification activée. Range les codes de secours ci-dessous : ils ne s'affichent qu'une fois.")
        return back
    if op in ("disable", "recovery"):
        if not totp.enabled(me) or not await asyncio.to_thread(totp.verify_login, me, f.get("code") or ""):
            flash(request, "Code incorrect.", "error")
            return back
        if op == "disable":
            totp.disable(me)
            P.log("warn", "console", f"double authentification retirée par {me}")
            flash(request, "Double authentification retirée.")
        else:
            codes, hashes = totp.new_recovery()
            u = totp.user(me)
            totp.enable(me, u["totp_secret"], hashes)
            db.x("UPDATE users SET totp_last = ? WHERE username = ?", (u["totp_last"], me))
            request.session["totp_codes"] = codes
            P.log("info", "console", f"nouveaux codes de secours pour {me}")
            flash(request, "Nouveaux codes de secours : les anciens ne marchent plus.")
        return back
    return back


def _last_admin(name):
    u = db.one("SELECT role FROM users WHERE username = ?", (name,))
    return bool(u and u["role"] == "admin" and db.one("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'")["n"] <= 1)


@router.post("/users/{name}/role")
async def users_role(request: Request, name: str):
    f = await request.form()
    role = f.get("role") if f.get("role") in perms.ROLES else "admin"
    if not db.one("SELECT 1 FROM users WHERE username = ?", (name,)):
        return go("/settings#comptes")
    if role != "admin" and _last_admin(name):
        flash(request, "Il faut garder au moins un compte administrateur.", "error")
        return go("/settings#comptes")
    db.x("UPDATE users SET role = ? WHERE username = ?", (role, name))
    sc = {k[4:]: v for k, v in f.items() if k.startswith("app_") and v in perms.LEVELS and db.app(k[4:])}
    perms.set_scopes(name, sc if role == perms.ROLE else {})
    db.x("DELETE FROM sessions WHERE username = ? AND id != ?", (name, request.session.get("sid") or ""))
    detail = f" : {', '.join(f'{k} ({perms.LEVELS[v]})' for k, v in sc.items()) or 'aucune appli'}" if role == perms.ROLE else ""
    P.log("info", "console", f"compte {name} : {perms.ROLES[role]}{detail} (par {request.session.get('user')})")
    flash(request, f"Compte {name} : {perms.ROLES[role]}{detail}.")
    return go("/settings#comptes")


@router.get("/settings/audit")
async def audit_page(request: Request):
    who = request.query_params.get("u") or ""
    rows = db.q("SELECT * FROM audit WHERE (? = '' OR username = ?) ORDER BY id DESC LIMIT 500", (who, who))
    return render(request, "audit.html", title="Journal des actions", nav="settings", rows=rows, who=who,
                  users=[r["username"] for r in db.q("SELECT DISTINCT username FROM audit WHERE username IS NOT NULL")])
