"""Système : mises à jour, fuseau horaire, rapport, alertes."""
import asyncio
import re

from fastapi import APIRouter, Request

from .. import alerts, cache, db, report, system
from .. import platform as P
from .common import flash, go, render

router = APIRouter()


# ---------------------------------------------------------------- système, mises à jour, alertes

@router.get("/system")
async def system_page(request: Request):
    chk = db.kv_get("sys_check")
    busy = await asyncio.to_thread(system.running)
    info = await asyncio.to_thread(cache.get, "sysinfo", 600, P.system_info)
    events = db.q("SELECT * FROM events WHERE app IN ('système', 'alertes') ORDER BY id DESC LIMIT 12")
    mach = [{"id": n, "name": name, "chk": (chk or {}) if n == P.LOCAL else ((chk or {}).get("nodes") or {}).get(n)}
            for n, name in system.machines()]
    return render(request, "system.html", title="Système", nav="system", chk=chk, chk_ts=db.kv_ts("sys_check"),
                  busy=busy, comps=system.COMPONENTS, info=info, events=events, refresh=bool(busy), machines=mach,
                  since=db.kv_get("sys_pending_since") or {}, auto=system.auto_settings(),
                  tzs=system.tz_settings(), tz_common=system.TZ_COMMON, tz_all=system.timezones(),
                  tz_now=await asyncio.to_thread(cache.get, "tz_now", 600, _tz_now))


def _tz_now():
    import concurrent.futures
    ms = system.machines()
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(ms)) as ex:
        found = list(ex.map(lambda m: system.tz_of(m[0]), ms))
    return [(name, tz) for (_n, name), tz in zip(ms, found)]


@router.post("/system/timezone")
async def system_timezone(request: Request):
    f = await request.form()
    try:
        errs = await asyncio.to_thread(system.apply_tz, (f.get("tz") or "").strip(), f.get("apps") == "on")
        msg = f"Fuseau horaire {f.get('tz')} appliqué. La console redémarre : recharge la page dans quelques secondes."
        if f.get("apps") == "on":
            msg += " Les applis l'auront à leur prochain déploiement ou redémarrage."
        flash(request, msg + (" Problèmes : " + " ; ".join(errs) if errs else ""), "error" if errs else "ok")
    except ValueError as e:
        flash(request, str(e), "error")
    return go("/system#fuseau")


@router.post("/system/auto")
async def system_auto(request: Request):
    f = await request.form()
    try:
        system.save_auto(f.get("on") == "on", f.getlist("comps"), f.get("start") or 3, f.get("end") or 5)
        a = system.auto_settings()
        P.log("info", "système", "mises à jour automatiques de nuit " + (
            f"activées ({', '.join(system.COMPONENTS[c]['name'] for c in a['comps']) or 'aucun composant'}, "
            f"{a['start']} h – {a['end']} h)" if a["on"] else "désactivées"))
        flash(request, "Mises à jour automatiques enregistrées.")
    except (ValueError, TypeError) as e:
        flash(request, f"Réglage refusé : {e}", "error")
    return go("/system#auto")


@router.post("/system/check")
async def system_check(request: Request):
    try:
        await asyncio.to_thread(system.check)
        flash(request, "Vérification terminée.")
    except Exception as e:
        flash(request, f"Vérification impossible : {e}", "error")
    return go("/system")


@router.post("/system/update/{cid}")
async def system_update(request: Request, cid: str):
    f = await request.form()
    node = (f.get("node") or P.LOCAL).strip()
    try:
        await asyncio.to_thread(system.launch, cid, node)
        msg = f"Mise à jour de {system.COMPONENTS[cid]['name']} lancée ({system._who(node)})."
        if cid == "docker" and P.is_local(node):
            msg += " La console va redémarrer : recharge la page dans une minute."
        flash(request, msg)
    except (ValueError, RuntimeError) as e:
        flash(request, str(e), "error")
    return go(f"/system#maj-{node}" if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,30}", node) else "/system")


@router.post("/system/report")
async def system_report(request: Request):
    sent, err = await asyncio.to_thread(report.send, None, True)
    flash(request, "Rapport envoyé sur ntfy." if sent else f"Rapport non envoyé : {err}", "ok" if sent else "error")
    return go("/system#alertes")


@router.post("/system/alerts")
async def alerts_save(request: Request):
    f = await request.form()
    server = (f.get("ntfy_server") or "").strip().rstrip("/")
    topic = (f.get("ntfy_topic") or "").strip()
    token = (f.get("ntfy_token") or "").strip()
    if not re.fullmatch(r"https://[A-Za-z0-9.-]+(:\d+)?(/[A-Za-z0-9._~/-]*)?", server):
        flash(request, "Serveur ntfy invalide (https://…).", "error")
    elif not re.fullmatch(r"[A-Za-z0-9_-]{6,64}", topic):
        flash(request, "Sujet invalide : 6 à 64 lettres, chiffres, - ou _.", "error")
    else:
        db.set_setting("ntfy_server", server)
        db.set_setting("ntfy_topic", topic)
        if token != P.MASK:
            db.set_setting("ntfy_token", token)
        db.set_setting("alerts_on", "1" if f.get("alerts_on") == "on" else "0")
        flash(request, "Alertes enregistrées.")
    return go("/system#alertes")


@router.post("/system/alerts/test")
async def alerts_test(request: Request):
    ok, err = await asyncio.to_thread(alerts.send, "Test Hangar", "Si tu lis ceci, les alertes arrivent bien sur ton téléphone.",
                                      3, ["bell"], None, 0, True)
    flash(request, "Notification de test envoyée." if ok else f"Envoi impossible : {err}", "ok" if ok else "error")
    return go("/system#alertes")
