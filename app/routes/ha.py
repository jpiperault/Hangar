"""Haute disponibilité d'une appli et réglages de la console comme nœud."""
import asyncio

from fastapi import APIRouter, Request

from .. import affinity, ha, nodes
from .. import platform as P
from .common import _int, flash, get_app_or_404, go

router = APIRouter()


@router.post("/apps/{slug}/ha/enable")
async def ha_enable(request: Request, slug: str):
    a = get_app_or_404(slug)
    f = await request.form()
    mode = f.get("mode")
    chosen = [f.get("standby")] if mode == "standby" else f.getlist("inst")
    err = await asyncio.to_thread(ha.validate, a, mode, chosen, bool(f.get("ack")))
    if not err and (ha.get(slug) or a["state"] == "deploying"):
        err = "Une opération est déjà en cours sur cette appli."
    if err:
        flash(request, err, "error")
        return go(f"/apps/{slug}#hautedispo")
    P.spawn(ha.enable, slug, mode, chosen, bool(f.get("auto")), _int(f.get("delay"), 4, 60, 4),
            _int(f.get("sync_min"), 1, 1440, 5), request.session.get("user"))
    flash(request, "Mise en place de la haute dispo lancée : suis l'avancement dans les événements.")
    return go(f"/apps/{slug}#hautedispo")


@router.post("/apps/{slug}/ha/options")
async def ha_options(request: Request, slug: str):
    get_app_or_404(slug)
    f = await request.form()
    if ha.get(slug):
        ha.update_options(slug, bool(f.get("auto")), _int(f.get("delay"), 4, 60, 4), _int(f.get("sync_min"), 1, 1440, 5),
                          request.session.get("user"))
        flash(request, "Réglages de la bascule enregistrés.")
    return go(f"/apps/{slug}#hautedispo")


def _ha_job(fn, slug, user, what):
    try:
        fn(slug, user)
    except Exception as e:
        P.log("error", slug, f"{what} : {e}")


@router.post("/apps/{slug}/ha/affinity")
async def ha_affinity(request: Request, slug: str):
    get_app_or_404(slug)
    f = await request.form()
    try:
        affinity.save(slug, f.get("mode") or "", f.get("name") or "")
        await asyncio.to_thread(P.apply_routing)
        a = affinity.of(slug)
        P.log("info", slug, "affinité des instances : " + (f"{affinity.MODES[a['mode']]} {a['name']}".strip()
                                                          if a["mode"] else "aucune"))
        flash(request, "Affinité enregistrée : Caddy l'applique tout de suite.")
    except (ValueError, RuntimeError) as e:
        flash(request, f"Affinité refusée : {e}", "error")
    return go(f"/apps/{slug}#affinite")


@router.post("/apps/{slug}/ha/{action}")
async def ha_action(request: Request, slug: str, action: str):
    get_app_or_404(slug)
    fns = {"switch": (ha.switchover, "bascule programmée", "Bascule lancée."),
           "resync": (ha.resync, "resynchronisation", "Resynchronisation lancée."),
           "disable": (ha.disable, "retrait de la haute dispo", "Retrait de la haute dispo lancé.")}
    if action in fns and ha.get(slug):
        fn, what, msg = fns[action]
        P.spawn(_ha_job, fn, slug, request.session.get("user"), what)
        flash(request, msg + " Suis l'avancement dans les événements.")
    return go(f"/apps/{slug}#hautedispo")


@router.post("/nodes/console")
async def console_settings(request: Request):
    f = await request.form()
    await asyncio.to_thread(nodes.save_console_role, f.get("role") == "manage", f.get("standby") == "on",
                            request.session.get("user"))
    flash(request, "Rôle de la console enregistré.")
    return go("/nodes#console")


@router.post("/ha/settings")
async def ha_settings(request: Request):
    f = await request.form()
    try:
        await asyncio.to_thread(ha.save_settings, f.get("fence"), f.get("fence_after") or 180, request.session.get("user"))
        flash(request, "Réglages de haute dispo enregistrés et envoyés aux nœuds.")
    except (ValueError, TypeError) as e:
        flash(request, str(e), "error")
    return go("/nodes#hautedispo")
