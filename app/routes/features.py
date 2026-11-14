"""Fonctions d'une appli : tâches planifiées, Redis, préprod, configuration à distance, plantages, limites, essais."""
import asyncio
import time
import urllib.parse

from fastapi import APIRouter, Request

from .. import crashes, db, hooks, jobs, limits, runopts, preprod, remoteconfig, services, smoke
from .. import domains as D
from .. import platform as P
from .common import flash, get_app_or_404, go, render

router = APIRouter()


@router.post("/apps/{slug}/jobs")
async def app_job_add(request: Request, slug: str):
    if not db.app(slug):
        return go("/")
    f = await request.form()
    try:
        jobs.add(slug, jobs.validate(f))
        P.log("info", slug, f"tâche planifiée « {(f.get('name') or '').strip()[:80]} » ajoutée")
        flash(request, "Tâche ajoutée.")
    except ValueError as e:
        flash(request, f"Tâche refusée : {e}", "error")
    return go(f"/apps/{slug}#taches")


@router.post("/apps/{slug}/jobs/{jid}/{op}")
async def app_job_op(request: Request, slug: str, jid: str, op: str):
    a = db.app(slug)
    j = next((x for x in jobs.of(slug) if x["id"] == jid), None) if a else None
    if not j:
        return go(f"/apps/{slug}#taches" if a else "/")
    if op == "run":
        P.spawn(jobs.run, slug, jid, True)
        flash(request, f"Tâche « {j['name']} » lancée : son résultat s'affiche ici à la fin.")
    elif op == "toggle":
        jobs.toggle(slug, jid)
        flash(request, f"Tâche « {j['name']} » {'désactivée' if j.get('on', True) else 'réactivée'}.")
    elif op == "delete":
        jobs.remove(slug, jid)
        P.log("info", slug, f"tâche planifiée « {j['name']} » supprimée")
        flash(request, f"Tâche « {j['name']} » supprimée.")
    return go(f"/apps/{slug}#taches")


@router.post("/apps/{slug}/services/redis")
async def app_redis(request: Request, slug: str):
    a = db.app(slug)
    if not a:
        return go("/")
    f = await request.form()
    if a["state"] == "deploying":
        flash(request, "Une opération est en cours sur cette appli : réessaie dans un instant.", "error")
        return go(f"/apps/{slug}#redis")
    try:
        if f.get("on") == "1" and request.query_params.get("off") != "1":
            services.enable_redis(slug, f.get("mem") or 128)
            msg = "Redis activé : l'appli est redéployée avec REDIS_URL."
        else:
            services.disable_redis(slug)
            msg = "Redis retiré : l'appli est redéployée sans lui. Ses données restent dans data/.hangar-redis."
    except ValueError as e:
        flash(request, str(e), "error")
        return go(f"/apps/{slug}#redis")
    P.log("info", slug, msg.split(" :")[0])
    P.spawn(P.deploy, slug, a["version"], "config", dict(a))
    flash(request, msg)
    return go(f"/apps/{slug}#redis")


@router.post("/apps/{slug}/services/mail")
async def app_mail(request: Request, slug: str):
    a = get_app_or_404(slug)
    f = await request.form()
    try:
        if request.query_params.get("off") == "1":
            services.disable_mail(slug)
            msg = "E-mails coupés : l'appli est redéployée sans les variables SMTP_…."
        else:
            had = services.mail(slug)
            services.enable_mail(slug, f.get("sender"))
            msg = ("Expéditeur changé" if had else "E-mails activés") + " : l'appli est redéployée avec SMTP_HOST, SMTP_PORT, " \
                  "SMTP_USER, SMTP_PASSWORD, SMTP_SECURE et SMTP_FROM."
    except ValueError as e:
        flash(request, str(e), "error")
        return go(f"/apps/{slug}#mail")
    P.log("info", slug, msg.split(" :")[0])
    if a["state"] != "deploying" and a["version"]:
        P.spawn(P.deploy, slug, a["version"], "config", dict(a))
    flash(request, msg)
    return go(f"/apps/{slug}#mail")


@router.post("/apps/{slug}/services/mysql")
async def app_mysql(request: Request, slug: str):
    a = get_app_or_404(slug)
    f = await request.form()
    if a["state"] == "deploying":
        flash(request, "Une opération est en cours sur cette appli : réessaie dans un instant.", "error")
        return go(f"/apps/{slug}#mysql")
    try:
        if request.query_params.get("off") == "1":
            await asyncio.to_thread(services.fresh_dump, a, True)
            services.disable_mysql(slug)
            msg = ("Base MySQL/MariaDB retirée : l'appli est redéployée sans elle. Son dernier export reste dans "
                   "data/.hangar-mysql.")
        else:
            had = services.mysql(slug)
            services.enable_mysql(slug, f.get("engine") or "mariadb", f.get("mem") or 256)
            msg = ("Mémoire de la base changée : l'appli est redéployée." if had else
                   f"{services.ENGINES[services.mysql(slug)['engine']]['name']} ajoutée : l'appli est redéployée avec "
                   "MYSQL_HOST, MYSQL_DATABASE, MYSQL_USER, MYSQL_PASSWORD et MYSQL_URL.")
    except (ValueError, RuntimeError) as e:
        flash(request, str(e), "error")
        return go(f"/apps/{slug}#mysql")
    P.log("info", slug, msg.split(" :")[0])
    P.spawn(P.deploy, slug, a["version"], "config", dict(a))
    flash(request, msg)
    return go(f"/apps/{slug}#mysql")


@router.post("/apps/{slug}/preprod")
async def app_preprod(request: Request, slug: str):
    a = db.app(slug)
    if not a:
        return go("/")
    f = await request.form()
    op = request.query_params.get("op") or "create"
    try:
        if op == "create":
            pre = preprod.check(slug)
            version = (f.get("version") or "").strip() or a["version"]
            if not P.VERSION.match(version):
                raise ValueError("version invalide")
            P.spawn(preprod.create, slug, version)
            flash(request, f"Préproduction « {pre} » en cours de création : déploiement de {version}, puis copie de la base "
                  "et de data/ de la production.")
            return go(f"/apps/{slug}#preprod")
        pre = slug if preprod.prod_of(slug) else preprod.of(slug)
        if not pre:
            raise ValueError("pas de préproduction")
        if op == "refresh":
            if db.app(pre)["state"] == "deploying":
                raise ValueError("la préproduction est occupée")
            P.spawn(preprod.refresh, pre)
            flash(request, "Copie des données de la production lancée : la préproduction est arrêtée quelques instants. "
                  "Son état d'avant est mis de côté.")
        elif op == "promote":
            prod = db.app(preprod.prod_of(pre))
            if prod["state"] == "deploying":
                raise ValueError("la production est occupée")
            P.spawn(preprod.promote, pre)
            flash(request, f"Déploiement de {db.app(pre)['version']} en production lancé ({prod['name']}). "
                  "En cas d'échec du healthcheck, la version actuelle reste en ligne.")
            return go(f"/apps/{prod['slug']}")
    except ValueError as e:
        flash(request, f"Préproduction : {e}", "error")
    return go(f"/apps/{slug}#preprod")


@router.post("/apps/{slug}/remote-config")
async def app_remote_config(request: Request, slug: str):
    get_app_or_404(slug)
    f = await request.form()
    try:
        remoteconfig.save(slug, f)
        await asyncio.to_thread(P.apply_routing)   # fichiers publics réécrits et envoyés aux nœuds
        P.log("info", slug, "configuration à distance de l'appli Android mise à jour")
        flash(request, "Configuration publiée : les applis la lisent à leur prochain démarrage (cache d'une minute).")
    except (ValueError, RuntimeError) as e:
        flash(request, f"Configuration refusée : {e}", "error")
    return go(f"/apps/{slug}#mobile")


@router.get("/apps/{slug}/crashes/{fp}")
async def app_crash(request: Request, slug: str, fp: str):
    a = get_app_or_404(slug)
    g = db.one("SELECT * FROM crash_groups WHERE slug = ? AND fp = ?", (slug, fp))
    if not g:
        return go(f"/apps/{slug}#mobile")
    return render(request, "crash.html", title=f"Plantage · {a['name']}", nav="apps", a=a, g=g,
                  items=crashes.latest(slug, fp, 20), versions=crashes.versions(slug, fp))


@router.post("/apps/{slug}/crashes/{fp}/{op}")
async def app_crash_op(request: Request, slug: str, fp: str, op: str):
    get_app_or_404(slug)
    if op in ("resolved", "open", "delete"):
        crashes.set_status(slug, fp, op)
        flash(request, {"resolved": "Marqué corrigé : une alerte partira s'il revient dans une version plus récente.",
                        "open": "Rouvert.", "delete": "Groupe supprimé."}[op])
    return go(f"/apps/{slug}#mobile")


@router.post("/apps/{slug}/history/{hid}/restore")
async def app_history_restore(request: Request, slug: str, hid: int):
    from .. import history
    a = get_app_or_404(slug)
    snap = history.get(slug, hid)
    if not snap:
        return go(f"/apps/{slug}#historique")
    if a["state"] == "deploying":
        flash(request, "Un déploiement est en cours : réessaie dans un instant.", "error")
        return go(f"/apps/{slug}#historique")
    when = time.strftime("%d/%m %H:%M", time.localtime(db.one("SELECT ts FROM app_history WHERE id = ?", (hid,))["ts"]))
    previous = {**dict(a), "_run": runopts.of(slug)}
    history.restore(slug, snap)
    P.log("info", slug, f"réglages du {when} remis")
    if a["version"]:
        P.spawn(P.deploy, slug, a["version"], "config", previous)
        flash(request, f"Réglages du {when} remis : l'appli est redéployée (si elle ne démarre pas, les réglages d'avant reviennent).")
    else:
        flash(request, f"Réglages du {when} remis.")
    return go(f"/apps/{slug}#historique")


@router.post("/apps/{slug}/protect/{op}")
async def app_protect(request: Request, slug: str, op: str):
    from .. import protect
    get_app_or_404(slug)
    f = await request.form()
    try:
        if op == "adduser":
            await asyncio.to_thread(protect.add_user, slug, f.get("name"), f.get("password") or "")
            msg = f"Compte {f.get('name')} ajouté : l'appli demande maintenant un mot de passe."
        elif op == "deluser":
            protect.remove_user(slug, f.get("name") or "")
            msg = f"Compte {f.get('name')} retiré."
        elif op == "ips":
            protect.set_ips(slug, protect.parse_ips(f.get("ips")))
            ips = protect.of(slug).get("ips")
            msg = f"Adresses autorisées : {', '.join(ips)}." if ips else "Plus de restriction par adresse."
        else:
            return go(f"/apps/{slug}")
    except (ValueError, RuntimeError) as e:
        flash(request, str(e), "error")
        return go(f"/apps/{slug}#protection")
    await asyncio.to_thread(P.apply_routing)
    P.log("info", slug, "protection : " + msg)
    flash(request, msg)
    return go(f"/apps/{slug}#protection")


@router.post("/apps/{slug}/hook/{op}")
async def app_hook(request: Request, slug: str, op: str):
    a = get_app_or_404(slug)
    back = f"/apps/{slug}#{'site' if a['kind'] == 'static' else 'reglages'}"
    if op in ("enable", "renew"):
        if a["kind"] != "static" and a["source"] not in ("image", "git"):
            flash(request, "Publication par webhook : applis en image, construites depuis Git, et sites statiques.", "error")
            return go(back)
        hooks.enable(slug)
        P.log("info", slug, "webhook de publication " + ("activé" if op == "enable" else "renouvelé (nouveau secret)"))
        flash(request, "Webhook activé : copie l'adresse et le secret dans GitHub." if op == "enable" else
              "Nouveau secret : remplace-le dans GitHub (l'ancien est refusé dès maintenant).")
    elif op == "options":
        f = await request.form()
        hooks.set_options(slug, f.get("rebuild") == "on", f.get("tags") == "on")
        flash(request, "Réglages du webhook enregistrés.")
        return go(back)
    elif op == "disable":
        hooks.disable(slug)
        P.log("info", slug, "webhook de publication retiré")
        flash(request, "Webhook retiré : les envois sont refusés.")
    else:
        return go(back)
    await asyncio.to_thread(P.apply_routing)
    return go(back)


@router.post("/apps/{slug}/run")
async def app_run(request: Request, slug: str):
    a = get_app_or_404(slug)
    f = await request.form()
    before = runopts.of(slug)
    try:
        changed = runopts.save(slug, f)
    except ValueError as e:
        flash(request, str(e), "error")
        return go(f"/apps/{slug}#demarrage")
    if changed:
        o = runopts.of(slug)
        P.log("info", slug, "démarrage du conteneur : " + (", ".join(
            f"{n} « {o[k]} »" for k, n in (("entrypoint", "point d'entrée"), ("command", "commande")) if o.get(k)) or "celui de l'image")
              + (" ; santé par commande" if o.get("health_cmd") else ""))
        if a["state"] != "deploying" and a["version"]:
            P.spawn(P.deploy, slug, a["version"], "config", {**dict(a), "_run": before})
            flash(request, "Démarrage enregistré : l'appli est redéployée (en cas d'échec, l'ancien réglage revient).")
        else:
            flash(request, "Démarrage enregistré : pris en compte au prochain déploiement.")
    return go(f"/apps/{slug}#demarrage")


@router.post("/apps/{slug}/limits")
async def app_limits(request: Request, slug: str):
    a = db.app(slug)
    if not a:
        return go("/")
    f = await request.form()
    before = limits.cpus(slug)
    try:
        limits.save(slug, f.get("cpus"))
    except ValueError as e:
        flash(request, str(e), "error")
        return go(f"/apps/{slug}#limites")
    after = limits.cpus(slug)
    if after != before:
        P.log("info", slug, f"processeur max : {after} cœur(s)" if after else "processeur : sans limite")
        if a["state"] != "deploying":
            P.spawn(P.deploy, slug, a["version"], "config", dict(a))
        flash(request, ("Limite de processeur enregistrée" if after else "Limite de processeur retirée") + " : l'appli est redéployée.")
    return go(f"/apps/{slug}#limites")


@router.post("/apps/{slug}/smoke")
async def app_smoke(request: Request, slug: str):
    a = db.app(slug)
    if not a:
        return go("/")
    f = await request.form()
    try:
        smoke.save(slug, f.get("checks") or "")
    except ValueError as e:
        flash(request, f"Vérifications refusées : {e}", "error")
        return go(f"/apps/{slug}#verifs")
    if request.query_params.get("test") == "1" and smoke.text_of(slug):
        u = urllib.parse.urlsplit(D.primary_url(slug) or "")
        ok, res = await asyncio.to_thread(smoke.run, a, a["version"], u.hostname, 1)
        db.kv_set(f"smoke_last:{slug}", {"ts": time.time(), "version": a["version"], "results": res, "manual": True})
        flash(request, ("Toutes les vérifications passent : " if ok else "Des vérifications échouent : ") + smoke.summary(res),
              "ok" if ok else "error")
    else:
        P.log("info", slug, "vérifications après déploiement : " + (f"{len(smoke.parse(smoke.text_of(slug)))} adresse(s)"
                                                                   if smoke.text_of(slug) else "aucune"))
        flash(request, "Vérifications enregistrées : elles s'appliquent au prochain déploiement.")
    return go(f"/apps/{slug}#verifs")
