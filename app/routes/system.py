"""Système : mises à jour, fuseau horaire, rapport, alertes."""
import asyncio
import re

from fastapi import APIRouter, Request

from .. import alerts, cache, db, images, report, runopts, system
from .. import platform as P
from .common import _int, flash, go, render, tpl

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
                  tz_now=await asyncio.to_thread(cache.get, "tz_now", 600, _tz_now), chans=alerts.channels(),
                  img=images.settings(), img_last=db.kv_get("image_cleanup_last"),
                  health_modes=runopts.HEALTH_MODES, health_default=db.kv_get("health_mode") or "lenient",
                  levels=[(1, "toutes, même discrètes"), (3, "normales et plus"), (4, "importantes et urgentes"), (5, "urgentes seulement")])


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


@router.post("/system/images")
async def system_images(request: Request):
    f = await request.form()
    images.save(f.get("on") == "on", _int(f.get("keep"), 1, 20, 3), _int(f.get("day"), 0, 6, 6), f.get("build_cache") == "on")
    s = images.settings()
    P.log("info", "console", "nettoyage des images " + (f"activé (garde {s['keep']} versions)" if s["on"] else "désactivé"))
    flash(request, "Nettoyage des images enregistré.")
    return go("/system#images")


@router.post("/system/images/run")
async def system_images_run(request: Request):
    P.spawn(images.run, "à la main")
    flash(request, "Nettoyage des images lancé : le résultat arrive dans le journal dans un instant.")
    return go("/system#images")


@router.get("/system/images/preview")
async def system_images_preview(request: Request):
    pv = await asyncio.to_thread(images.preview)
    return tpl.TemplateResponse(request, "_images_preview.html", {"pv": pv})


@router.post("/system/health")
async def system_health(request: Request):
    m = (await request.form()).get("mode")
    if m in runopts.HEALTH_MODES:
        db.kv_set("health_mode", m)
        P.log("info", "console", f"contrôle de santé par défaut : {runopts.HEALTH_MODES[m][0]}")
        flash(request, f"Contrôle de santé par défaut : {runopts.HEALTH_MODES[m][0]}.")
    return go("/system#sante")


@router.post("/system/alerts")
async def alerts_save(request: Request):
    f = await request.form()
    server = (f.get("ntfy_server") or "").strip().rstrip("/")
    topic = (f.get("ntfy_topic") or "").strip()
    token = (f.get("ntfy_token") or "").strip()
    if not re.fullmatch(r"https://[A-Za-z0-9.-]+(:\d+)?(/[A-Za-z0-9._~/-]*)?", server):
        flash(request, "Serveur ntfy invalide (https://…).", "error")
    elif topic and not re.fullmatch(r"[A-Za-z0-9_-]{6,64}", topic):
        flash(request, "Sujet invalide : 6 à 64 lettres, chiffres, - ou _ (vide : pas de ntfy).", "error")
    else:
        db.set_setting("ntfy_server", server)
        db.set_setting("ntfy_topic", topic)
        if token != P.MASK:
            db.set_setting("ntfy_token", token)
        db.set_setting("ntfy_min", str(_int(f.get("ntfy_min"), 1, 5, 1)))
        db.set_setting("alerts_on", "1" if f.get("alerts_on") == "on" else "0")
        flash(request, "Alertes enregistrées.")
    return go("/system#alertes")


def _channel_form(ch, f, detect=False):
    """Réglage d'un canal depuis son formulaire. ValueError si invalide. Les secrets masqués sont gardés."""
    old = alerts.channels().get(ch) or {}
    keep = lambda k: old.get(k, "") if (f.get(k) or "") == P.MASK else (f.get(k) or "").strip()
    c = {"on": f.get("on") == "on", "min": _int(f.get("min"), 1, 5, alerts.DEFAULT_MIN[ch])}
    if ch == "email":
        c.update(host=(f.get("host") or "").strip(), port=_int(f.get("port"), 1, 65535, 587),
                 security=f.get("security") if f.get("security") in ("starttls", "ssl", "none") else "starttls",
                 user=(f.get("user") or "").strip()[:200], password=keep("password")[:300],
                 **{"from": (f.get("from") or "").strip()[:200]},
                 to=[x.strip() for x in re.split(r"[,;\s]+", f.get("to") or "") if x.strip()][:5])
        if not alerts.HOST_RE.match(c["host"]):
            raise ValueError("serveur SMTP invalide, par exemple smtp.fastmail.com")
        if not c["to"] or not all(alerts.MAIL_RE.match(x) for x in c["to"]):
            raise ValueError("destinataires : une à cinq adresses e-mail, séparées par des virgules")
        if not (c["from"] or c["user"]) or (c["from"] and not alerts.MAIL_RE.match(c["from"])):
            raise ValueError("expéditeur : une adresse e-mail (sinon, l'identifiant SMTP doit en être une)")
        if c["security"] == "none" and c["user"]:
            raise ValueError("connexion sans chiffrement : le mot de passe passerait en clair, choisis STARTTLS ou SSL")
    elif ch == "discord":
        c["url"] = keep("url")
        if not alerts.DISCORD_RE.match(c["url"]):
            raise ValueError("adresse du webhook Discord invalide (https://discord.com/api/webhooks/…)")
    elif ch == "telegram":
        c.update(token=keep("token"), chat_id=(f.get("chat_id") or "").strip())
        if not alerts.TG_TOKEN_RE.match(c["token"]):
            raise ValueError("jeton du bot invalide (donné par @BotFather, de la forme 123456:ABC…)")
        if c["chat_id"] and not alerts.TG_CHAT_RE.match(c["chat_id"]):
            raise ValueError("chat_id invalide (un nombre, ou @nom_du_canal)")
        if c["on"] and not c["chat_id"] and not detect:
            raise ValueError("chat_id manquant : écris un message au bot, puis « Trouver ma conversation »")
    return c


@router.post("/system/alerts/channel/{ch}")
async def alerts_channel(request: Request, ch: str):
    if ch not in alerts.SENDERS:
        return go("/system#alertes")
    f = await request.form()
    detect = ch == "telegram" and request.query_params.get("detect") == "1"
    try:
        c = _channel_form(ch, f, detect)
    except ValueError as e:
        flash(request, f"{alerts.CHANNELS[ch]} : {e}", "error")
        return go(f"/system#canal-{ch}")
    if detect:
        try:
            found = await asyncio.to_thread(alerts.telegram_detect, c["token"])
        except Exception as e:
            flash(request, f"Telegram injoignable ou jeton refusé : {str(getattr(e, 'reason', e))[:200]}", "error")
            return go("/system#canal-telegram")
        if not found:
            flash(request, "Aucun message reçu par le bot : écris-lui (ou ajoute-le à un groupe et écris-y), puis réessaie.", "error")
            return go("/system#canal-telegram")
        c["chat_id"] = found[0]
        flash(request, f"Conversation trouvée : {found[1] or found[0]}. Envoie un test pour vérifier.")
    else:
        flash(request, f"{alerts.CHANNELS[ch]} enregistré" + (" et activé." if c["on"] else " (désactivé)."))
    alerts.save_channel(ch, c)
    P.log("info", "alertes", f"canal {alerts.CHANNELS[ch]} " + ("activé" if c["on"] else "désactivé"))
    return go(f"/system#canal-{ch}")


@router.post("/system/alerts/channel/{ch}/test")
async def alerts_channel_test(request: Request, ch: str):
    if ch not in alerts.CHANNELS:
        return go("/system#alertes")
    if ch in alerts.SENDERS:   # le test part avec ce qui est saisi : enregistré d'abord
        try:
            alerts.save_channel(ch, _channel_form(ch, await request.form()))
        except ValueError as e:
            flash(request, f"{alerts.CHANNELS[ch]} : {e}", "error")
            return go(f"/system#canal-{ch}")
    ok, err = await asyncio.to_thread(alerts.send, "Test Hangar", f"Si tu lis ceci, les alertes arrivent bien par {alerts.CHANNELS[ch]}.",
                                      4, ["bell"], None, 0, True, ch)
    flash(request, f"Test envoyé par {alerts.CHANNELS[ch]}." if ok else f"Envoi impossible : {err or 'canal non réglé'}",
          "ok" if ok else "error")
    return go(f"/system#canal-{ch}" if ch != "ntfy" else "/system#alertes")


@router.post("/system/alerts/test")
async def alerts_test(request: Request):
    ok, err = await asyncio.to_thread(alerts.send, "Test Hangar", "Si tu lis ceci, les alertes arrivent bien.",
                                      3, ["bell"], None, 0, True)
    flash(request, ("Test envoyé sur chaque canal réglé." + (f" Échecs : {err}" if err else "")) if ok else
          f"Envoi impossible : {err}", "ok" if ok and not err else "error")
    return go("/system#alertes")
