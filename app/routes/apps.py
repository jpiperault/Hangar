"""Applications : liste, catalogue, création, fiche, actions courantes."""
import asyncio
import secrets
import time

from fastapi import APIRouter, Request

from .. import affinity, diskuse, mail, history, mysqlrepl, patch, vulns, hooks, monitor, onboarding, perms, protect, runopts, segment, applogs, backup, cache, catalog, cloudflare, crashes, db, dbadmin, gameports, ha, jobs, kinds, limits, nodes, preprod, remoteconfig, services, sites, smoke, stats, traffic
from .. import domains as D
from .. import platform as P
from .common import RESERVED, SLUG, VERSION, _client_names, _public_addr, _rc_url, _redis_state, apply_registry, flash, get_app_or_404, go, node_choices, render, tpl_for, validate

router = APIRouter()


# ---------------------------------------------------------------- applications

@router.get("/")
async def home(request: Request):
    rows = await asyncio.to_thread(P.apps_with_status)
    role, me = getattr(request.state, "role", "admin"), request.session.get("user")
    rows = [r for r in rows if perms.visible(role, me, r["slug"])]
    todo = [] if onboarding.hidden() or role != "admin" else await asyncio.to_thread(onboarding.pending)
    return render(request, "apps.html", title="Applications", nav="apps", apps=rows, req24=stats.requests_24h(), todo=todo,
                  kind_list=kinds.choices(), kind_names={k: v["short"] for k, v in kinds.KINDS.items()},
                  ports={a["slug"]: gameports.text(a["slug"]) for a in rows},
                  refresh=any(r["status"] == "deploying" for r in rows), img_updates=db.kv_get("image_updates") or {},
                  ram_total=sum(r["ram"] for r in rows))


@router.get("/catalogue")
async def catalogue_page(request: Request):
    ch = node_choices()
    if not ch:
        flash(request, "Aucune machine ne peut héberger d'appli : ajoute un nœud.", "error")
        return go("/nodes")
    cur = catalog.get(request.query_params.get("app") or "") or catalog.items()[0]
    used = {a["image"] for a in db.apps()}
    return render(request, "catalogue.html", title="Installer une appli prête", nav="apps", items=catalog.items(),
                  cats=catalog.CATS, cur=cur, used=used, domains=D.all_domains(), dft=D.default(), node_choices=ch,
                  best=max(ch, key=lambda c: c["free"])["id"], form=request.session.pop("cform", None))


@router.post("/apps/{slug}/template")
async def app_template(request: Request, slug: str):
    a = get_app_or_404(slug)
    f = await request.form()
    if a["source"] != "image":
        flash(request, "Seules les applis en image peuvent devenir un modèle.", "error")
        return go(f"/apps/{slug}#modele")
    t = catalog.from_app(a, (f.get("name") or "").strip(), (f.get("desc") or "").strip())
    catalog.save_custom(t)
    P.log("info", slug, f"enregistrée comme modèle « {t['name']} » dans le catalogue")
    flash(request, f"Modèle « {t['name']} » ajouté au catalogue (Mes modèles).")
    return go(f"/catalogue?app={t['id']}")


@router.post("/catalogue/{cid}/delete")
async def catalogue_delete(request: Request, cid: str):
    if any(c["id"] == cid for c in catalog.custom()):
        catalog.delete_custom(cid)
        flash(request, "Modèle retiré du catalogue (les applis déjà installées ne changent pas).")
    return go("/catalogue")


@router.post("/catalogue/install")
async def catalogue_install(request: Request):
    f = await request.form()
    c = catalog.get(f.get("app") or "")
    if not c:
        return go("/catalogue")
    back = go(f"/catalogue?app={c['id']}")
    slug = (f.get("slug") or "").strip().lower()
    name = (f.get("name") or c["name"]).strip()[:80] or c["name"]
    node = f.get("node") or "local"
    err = None
    if not SLUG.match(slug) or slug in RESERVED:
        err = "Identifiant : lettres minuscules, chiffres et tirets, 32 caractères au plus."
    elif db.app(slug):
        err = "Cet identifiant est déjà utilisé."
    elif node not in {x["id"] for x in node_choices()}:
        err = "Machine indisponible."
    rts = []
    if not err:
        rts, err = D._check_routes([{"kind": "sub", "domain": (f.get("domain") or "").strip().lower(),
                                     "sub": (f.get("sub") or "").strip().lower()}], slug, D.by_name())
    pports, mhost, mdom = [], "", ""
    if not err and c.get("mail"):   # serveur de messagerie : son nom, son domaine et ses ports publics
        mhost = (f.get("mail_host") or "").strip().lower().rstrip(".")
        mdom = (f.get("mail_domain") or "").strip().lower().rstrip(".")
        err = mail.check(mhost, mdom, slug, D.host_of(rts[0]) if rts else None)
    if not err and c.get("ports"):
        try:
            pports = gameports.parse(c["ports"], slug, node)
        except ValueError as x:
            err = f"Ports publics : {x}"
        taken = [] if err else await asyncio.to_thread(gameports.busy, node, pports)
        if taken:
            err = (f"Ports déjà utilisés sur cette machine : {', '.join(taken)}. Arrête ce programme (un serveur mail "
                   "local, souvent postfix : systemctl disable --now postfix) ou choisis une autre machine.")
    if err:
        request.session["cform"] = {k: f.get(k) for k in ("slug", "name", "sub", "domain", "node", "mail_host", "mail_domain")}
        flash(request, err, "error")
        return back
    host = D.host_of(rts[0]) if rts else ""
    pw = secrets.token_hex(16) if c["db"] else None
    a = {"slug": slug, "node": node, "db_password": pw}
    my_pw = None
    if c.get("mysql"):   # base MySQL/MariaDB : son mot de passe va dans les variables de l'appli
        services.enable_mysql(slug, c["mysql"], c.get("mysql_mem", 256))
        my_pw = services.mysql(slug)["password"]
    vals = {"url": f"https://{host}/", "url_noslash": f"https://{host}", "host": host, "db_host": "postgres",
            "db_port": 5432, "db_name": P.db_name(slug), "db_user": P.db_name(slug), "db_password": pw or "",
            "mysql_password": my_pw or "", "mail_host": mhost}
    if c["db"]:
        vals["db_url"] = P.db_url({**a, "db": 1}, node)
    d = {"name": name, "kind": c.get("kind", "tool"), "pkg": "", "source": "image", "image": c["image"], "version": c["version"],
         "port": c["port"], "health_path": c["health"], "mem_mb": c["mem"], "env": catalog.render_env(c["env"], vals),
         "db": 1 if c["db"] else 0, "db_password": pw, "data_user": c.get("data_user", ""), "node": node,
         "host_port": P.next_host_port(), "state": "deploying", "desired": "running", "created_at": time.time()}
    db.insert_app(slug, d)
    D.set_routes(slug, rts)
    if c.get("mounts") or c.get("run"):
        runopts.save(slug, {**(c.get("run") or {}), "mounts": c.get("mounts") or ""})
    if pports:
        gameports.save(slug, pports)
    if mhost:
        mail.save(slug, mhost, mdom)
    P.log("info", slug, f"installée depuis le catalogue ({c['name']}, {c['image']}:{c['version']})")
    if c.get("setup") == "stalwart":   # puis son assistant par l'API (le jeton Cloudflare ne fait que passer)
        P.spawn(mail.install, slug, c["version"], (f.get("mail_cf_token") or "").strip())
    else:
        P.spawn(P.deploy, slug, c["version"], "create")
    flash(request, f"{c['name']} en cours d'installation sur https://{host}/. {c['after']}")
    return go(f"/apps/{slug}")


@router.get("/apps/new")
async def new_app(request: Request):
    ch = node_choices()
    if not ch:
        flash(request, "La console est en « gestion seulement » et aucun nœud n'est en ligne : ajoute un nœud "
                       "ou réautorise les applis sur la console.", "error")
        return go("/nodes#console")
    best = max(ch, key=lambda c: c["free"])["id"]
    dft = D.default()
    blank = {"name": "", "pkg": "", "slug": "", "port": 8080, "kind": kinds.DEFAULT,
             "routes": [{"kind": "sub", "domain": dft["name"] if dft else "", "sub": ""}],
             "health_path": "/health", "mem_mb": 256, "source": "image", "image": "", "version": "", "env": "", "db": 1,
             "data_user": "", "node": best}
    return render(request, "app_form.html", title="Nouvelle application", nav="apps", a=blank, new=True, errors={},
                  registries=P.registry_logins(), node_choices=ch, best=best, domains=D.all_domains(),
                  kinds=kinds.choices())


@router.post("/apps/new")
async def create_app(request: Request):
    f = await request.form()
    d, errors = validate(f)
    if not errors:
        _, errors = await apply_registry(f, d)
    if errors:
        return render(request, "app_form.html", 400, title="Nouvelle application", nav="apps", a=d, new=True,
                      errors=errors, registries=P.registry_logins(), reg_user=f.get("reg_user") or "",
                      node_choices=node_choices(), best=None, domains=D.all_domains(), kinds=kinds.choices(),
                      gports=f.get("gports") or "", gfrom=f.get("gfrom") or "")
    slug = d.pop("slug")
    rts = d.pop("routes")
    gameports.save(slug, d.pop("_ports") or [])
    if gameports.save_sources(slug, d.pop("_from") or []):
        P.spawn(segment.push_all)
    static = kinds.static(d["kind"])
    d.update(host_port=P.next_host_port(), state="ok" if static else "deploying", desired="running",
             created_at=time.time(), db_password=secrets.token_hex(16) if d["db"] else None)
    db.insert_app(slug, d)
    D.set_routes(slug, rts)
    if static:
        P.log("info", slug, "site statique créé : publie une première version (zip ou dépôt Git)")
        await asyncio.to_thread(P.apply_routing)
        flash(request, f"{d['name']} créé. Publie maintenant une première version : un zip du dossier construit, ou un dépôt Git.")
        return go(f"/apps/{slug}#site")
    P.log("info", slug, f"appli créée, port local {d['host_port']}")
    P.spawn(P.deploy, slug, d["version"], "create")
    flash(request, f"{d['name']} créée. Déploiement de {d['version']} en cours.")
    return go(f"/apps/{slug}")


async def _app_ctx(request, slug):
    """Contexte complet de la fiche d'une appli (affichage, ou réaffichage après une erreur de saisie)."""
    rows = await asyncio.to_thread(P.apps_with_status)
    a = next(r for r in rows if r["slug"] == slug)
    events = db.q("SELECT * FROM events WHERE app = ? ORDER BY id DESC LIMIT 8", (slug,))
    names = await asyncio.to_thread(P.app_public_names, a, db.settings())
    rng = request.query_params.get("r") if request.query_params.get("r") in stats.RANGES else "24h"
    st = stats.app_charts(stats.series(slug, rng), a["mem_mb"], limits.cpus(slug))
    dbi = dbadmin.cached_info(slug) if a["db"] and a["status"] != "deploying" else None   # sinon chargée après
    others = [c for c in node_choices() if c["id"] != a["node"]]
    dsize = await asyncio.to_thread(cache.get, f"dsize:{slug}", 300, P.dir_size, a["node"], f"{P.app_dir(slug)}/data") \
        if others else None
    a["routes"] = D.routes(slug)
    dser = diskuse.series(slug)
    disk = dict(disk=diskuse.app_view(slug), dpath=stats.spark_path([x["total"] for x in dser]) if len(dser) > 1 else "",
                dgrowth=diskuse.growth(slug), dbusy=diskuse.busy())
    mrec = []
    if mail.of(slug):   # serveur de messagerie : ses enregistrements DNS, et leur état chez Cloudflare
        cfm = {(r["type"], r["name"]): r for r in ((cloudflare.status().get("mail") or {}).get(slug) or [])}
        mrec = [{**r, **{k: v for k, v in (cfm.get((r["type"], r["name"])) or {}).items() if k in ("ok", "msg")}}
                for r in mail.records(slug)]
    disk.update(mailcfg=mail.of(slug), mailrec=mrec, mailip=mail.public_ip(slug) if mail.of(slug) else None,
                mailsetup=mail.needs_setup(slug), mailadmin=mail.admin_of(slug))
    hst = await asyncio.to_thread(ha.status, slug)
    busy = (hst and (hst["busy"] or hst["h"]["state"] == "setup"))
    all_tabs = request.session.get("user") in (db.kv_get("ui_all_tabs") or [])
    return dict(title=a["name"], nav="apps", a=a, new=False, errors={}, events=events, names=names, ha=hst, **disk, all_tabs=all_tabs,
                kinds=kinds.choices(), kind=kinds.get(a["kind"]), gports=gameports.text(slug), gfrom=", ".join(gameports.sources(slug)),
                site_meta=sites.meta(slug), site_busy=sites.busy(slug),
                public_addr=_public_addr(a),
                console_only=nodes.console_role()["manage_only"],
                ha_nodes=[c for c in node_choices("standby") if c["id"] != a["node"]],
                ha_inst=[c for c in others if c["id"] != a["node"]],
                refresh=a["status"] == "deploying" or bool(busy) or sites.busy(slug), registries=P.registry_logins(), st=st, dbi=dbi,
                ranges=list(stats.RANGES), others=others, dsize=dsize, domains=D.all_domains(), cf=cloudflare.status(),
                safety=backup.safety_copies(slug), maint=P.maintenance(slug),
                jobs=[{**j, "desc": jobs.describe(j), "busy": jobs.is_running(slug, j["id"])} for j in jobs.of(slug)],
                job_days=jobs.DAYS, cpus=limits.cpus(slug), run=runopts.of(slug), can_deploy=perms.can_deploy(getattr(request.state, 'role', 'admin'), request.session.get('user'), slug), health_modes=runopts.HEALTH_MODES, health_default=runopts.default_health_mode(), hook=hooks.of(slug), prot=protect.of(slug), hist=history.entries(slug), vul=vulns.of(slug), vul_busy=vulns.busy(slug), vul_groups=vulns.groups((vulns.of(slug) or {}).get('items') or []), vul_prompt=vulns.prompt(a, vulns.of(slug) or {}, getattr(request.state, 'lang', 'fr')), patch_on=patch.active(a, a['version']), patch_busy=patch.busy(slug), patch_mode=patch.mode(slug), patch_auto=patch.auto(slug), patch_default=patch.auto_default(), patch_try=patch.last_try(slug), hook_opts=hooks.options(slug), hook_url=hooks.url(slug), rc=remoteconfig.of(slug),
                rc_urls={"android": _rc_url(a, a["pkg"]), "ios": _rc_url(a, a["ios_bundle"])},
                has_clients=bool(a["pkg"] or a["ios_bundle"] or a["web_client"]), client_names=_client_names(a),
                crash_groups=crashes.groups(slug) if (a["pkg"] or a["ios_bundle"] or a["web_client"]) else [], aff=affinity.of(slug), aff_modes=affinity.MODES,
                aff_default=affinity.DEFAULT_NAME, smoke_text=smoke.text_of(slug), smoke_last=db.kv_get(f"smoke_last:{slug}"), redis=services.redis(slug), mysql=services.mysql(slug), mysql_repl=(cache.get(f'myrepl:{slug}', 30, mysqlrepl.status, slug, wait=False) if services.mysql(slug) and ha.get(slug) else None), mail=services.mail(slug), relay=services.relay(), mysql_engines=services.ENGINES, img_update=monitor.image_update(slug), pre=db.app(preprod.of(slug) or ""),
                prod=db.app(preprod.prod_of(slug) or ""),
                redis_st=(cache.get(f"redis:{slug}", 20, _redis_state, a, wait=False) or {"state": "…"})
                if services.redis(slug) else None,
                mysql_st=(cache.get(f"mysql:{slug}", 20, services.mysql_state, a, wait=False) or {"state": "…"})
                if services.mysql(slug) else None)


@router.get("/apps/{slug}")
async def show_app(request: Request, slug: str):
    get_app_or_404(slug)
    return render(request, "app_form.html", **await _app_ctx(request, slug))


@router.post("/apps/{slug}")
async def save_app(request: Request, slug: str):
    cur = get_app_or_404(slug)
    if cur["state"] == "deploying":
        flash(request, "Un déploiement est en cours. Réessaie quand il sera terminé.", "error")
        return go(f"/apps/{slug}")
    f = await request.form()
    d, errors = validate(f, cur)
    logged = False
    if not errors:
        logged, errors = await apply_registry(f, d)
    if errors:
        ctx = await _app_ctx(request, slug)
        ctx["a"].update(d)          # saisie conservée, adresses comprises
        ctx.update(errors=errors, refresh=False, reg_user=f.get("reg_user") or "", gports=f.get("gports") or "", gfrom=f.get("gfrom") or "")
        return render(request, "app_form.html", 400, **ctx)
    d.pop("slug")
    rts = d.pop("routes")
    D.set_routes(slug, rts)
    if kinds.static(cur["kind"]) or kinds.static(d["kind"]):   # site statique : nom et adresses seulement
        if kinds.static(cur["kind"]) != kinds.static(d["kind"]):
            flash(request, "Un site statique ne peut pas devenir une appli en conteneur (ni l'inverse) : crée une nouvelle appli.", "error")
            return go(f"/apps/{slug}#reglages")
        d.pop("_ports", None)
        d.pop("_from", None)
        db.update_app(slug, name=d["name"])
        await asyncio.to_thread(P.apply_routing)
        flash(request, "Enregistré. Adresses publiques mises à jour.")
        return go(f"/apps/{slug}#reglages")
    new_ports = d.pop("_ports") or []
    ports_changed = new_ports != gameports.of(slug)
    gameports.save(slug, new_ports)
    from_changed = gameports.save_sources(slug, d.pop("_from") or [])
    if from_changed or (ports_changed and gameports.sources(slug)):   # pare-feu des ports réservés à jour
        errs = await asyncio.to_thread(segment.push_all)
        if errs:
            flash(request, "Pare-feu des ports publics pas mis à jour partout : " + " ; ".join(errs)[:300], "error")
            return go(f"/apps/{slug}#reglages")
        if from_changed and not ports_changed:
            P.log("info", slug, "ports publics ouverts à : " + (", ".join(gameports.sources(slug)) or "tous"))
    runtime = ("port", "health_path", "mem_mb", "source", "image", "env", "db", "data_user", "kind")
    changed = [k for k in runtime if str(d[k]) != str(cur[k])] + (["ports publics"] if ports_changed else [])
    if logged and cur["state"] == "error":
        changed.append("identifiants du registre")  # le téléchargement avait échoué : on retente
    if d["db"] and not cur["db_password"]:
        d["db_password"] = secrets.token_hex(16)
    db.update_app(slug, **d)
    if changed and cur["desired"] == "running":
        db.update_app(slug, state="deploying")
        P.spawn(P.deploy, slug, cur["version"], "config", cur)
        flash(request, "Enregistré. Redéploiement en cours, l'ancienne configuration revient si le healthcheck échoue.")
    else:
        try:
            await asyncio.to_thread(P.apply_routing)
            flash(request, "Enregistré. Adresses publiques mises à jour.")
        except RuntimeError as e:
            flash(request, str(e), "error")
    P.log("info", slug, "configuration modifiée" + (f" ({', '.join(changed)})" if changed else ""))
    return go(f"/apps/{slug}")


@router.post("/apps/{slug}/version")
async def deploy_version(request: Request, slug: str):
    a = get_app_or_404(slug)
    v = ((await request.form()).get("version") or "").strip()
    if a["state"] == "deploying":
        flash(request, "Un déploiement est déjà en cours.", "error")
    elif not VERSION.match(v):
        flash(request, "Version invalide : lettres, chiffres, . _ - /", "error")
    else:
        db.update_app(slug, state="deploying")
        P.spawn(P.deploy, slug, v, "update")
        flash(request, f"Déploiement de {v} en cours. Si le healthcheck échoue, {a['version']} reste en ligne.")
    return go(f"/apps/{slug}")


@router.post("/apps/{slug}/rollback")
async def rollback(request: Request, slug: str):
    a = get_app_or_404(slug)
    if a["state"] == "deploying" or not a["prev_version"]:
        flash(request, "Retour arrière impossible pour l'instant.", "error")
    else:
        db.update_app(slug, state="deploying")
        P.spawn(P.deploy, slug, a["prev_version"], "rollback")
        flash(request, f"Retour à {a['prev_version']} en cours.")
    return go(f"/apps/{slug}")


@router.post("/apps/{slug}/revert")
async def app_revert(request: Request, slug: str):
    a = db.app(slug)
    if not a:
        return go("/")
    f = await request.form()
    c = backup.safety_copy(f.get("copy") or "")
    if not c or c["slug"] != slug:
        flash(request, "Copie de sécurité introuvable.", "error")
        return go(f"/apps/{slug}#securite")
    parts = [p for p, has in (("db", c["has_db"] and a["db"]), ("data", c["has_data"])) if has and f.get(p) == "on"]
    if not parts:
        flash(request, "Coche la base et/ou les fichiers à remettre.", "error")
        return go(f"/apps/{slug}#securite")
    if a["state"] == "deploying" or backup.running():
        flash(request, f"{a['name']} : une opération ou une sauvegarde est en cours, réessaie plus tard.", "error")
        return go(f"/apps/{slug}#securite")
    prev = a["state"]
    db.update_app(slug, state="deploying")
    P.spawn(backup.revert, slug, c["name"], parts, prev)
    flash(request, f"Retour arrière lancé pour {a['name']}. Son état actuel est d'abord mis de côté : "
          "tu pourras y revenir de la même façon.")
    return go(f"/apps/{slug}")


@router.post("/apps/{slug}/restore-point")
async def app_restore_point(request: Request, slug: str):
    a = db.app(slug)
    if not a:
        return go("/")
    f = await request.form()
    try:
        await asyncio.to_thread(backup.restore_point, slug, f.get("note") or "")
        flash(request, "Point de restauration créé : tu peux y revenir depuis cette liste.")
    except Exception as e:
        flash(request, f"Point de restauration impossible : {str(e)[:300]}", "error")
    return go(f"/apps/{slug}#securite")


@router.post("/apps/{slug}/maintenance")
async def app_maintenance(request: Request, slug: str):
    a = db.app(slug)
    if not a:
        return go("/")
    f = await request.form()
    on = f.get("on") == "1"
    await asyncio.to_thread(P.set_maintenance, slug, on, False, (f.get("msg") or "").strip())
    P.log("info", slug, "mode maintenance " + ("activé : les visiteurs voient la page de maintenance (503)" if on else "désactivé"))
    flash(request, "Mode maintenance activé." if on else "Mode maintenance désactivé : l'appli est de nouveau servie.")
    return go(f"/apps/{slug}#maintenance")


@router.post("/apps/{slug}/{action}")
async def app_action(request: Request, slug: str, action: str):
    a = get_app_or_404(slug)
    back = (await request.form()).get("back") or f"/apps/{slug}"
    back = back if back.startswith("/") and not back.startswith("//") else "/"
    if a["state"] == "deploying":
        flash(request, "Un déploiement est en cours.", "error")
        return go(back)
    if action in ("start", "restart"):
        db.update_app(slug, state="deploying")
        P.spawn(P.start if action == "start" else P.restart, slug)
        flash(request, f"{a['name']} : {'démarrage' if action == 'start' else 'redémarrage'} en cours.")
    elif action == "stop":
        await asyncio.to_thread(P.stop, slug)
        flash(request, f"{a['name']} arrêtée. Ses adresses répondent 503.")
    elif action == "delete":
        f = await request.form()
        if (f.get("confirm") or "").strip() != slug:
            flash(request, f"Tape {slug} pour confirmer la suppression.", "error")
            return go(f"/apps/{slug}#supprimer")
        db.update_app(slug, state="deploying")
        P.spawn(P.delete, slug)
        flash(request, f"{a['name']} en cours de suppression. Fichiers et dump conservés dans /srv/backups/deleted.")
        return go("/")
    else:
        flash(request, "Action inconnue.", "error")
    return go(back)


@router.get("/apps/{slug}/db/panel")
async def app_db_panel(request: Request, slug: str):
    """Bloc Base de données, chargé après la page quand le cache est vide (lecture sur le nœud)."""
    a = get_app_or_404(slug)
    dbi = await asyncio.to_thread(dbadmin.cached_info, slug, True) if a["db"] else None
    return tpl_for(request).TemplateResponse(request, "_dbpanel.html", {"a": a, "dbi": dbi})


@router.get("/apps/{slug}/logs")
async def app_logs(request: Request, slug: str):
    a = get_app_or_404(slug)
    qp = request.query_params
    period = qp.get("p") if qp.get("p") in applogs.PERIODS else ""
    q, err = (qp.get("q") or "")[:200], qp.get("e") == "1"
    lines, total, cut = await asyncio.to_thread(applogs.read, slug, period, q, err)
    return render(request, "logs.html", title=f"Logs · {a['name']}", nav="apps", a=a, lines=lines, total=total,
                  cut=cut, period=period, q=q, err=err, periods=applogs.PERIODS, la=applogs.settings(slug))


@router.get("/apps/{slug}/trafic")
async def app_traffic(request: Request, slug: str):
    """Trafic : vue d'ensemble (visiteurs, pages, origines…) ou journal d'accès (vue=journal)."""
    a = get_app_or_404(slug)
    qp = request.query_params
    ctx = dict(title=f"Trafic · {a['name']}", nav="apps", a=a, ts=traffic.settings(),
               is_admin=getattr(request.state, "role", "admin") == "admin")
    if qp.get("vue") == "journal":
        period = qp.get("p") if qp.get("p") in traffic.JOURNAL_PERIODS else "24h"
        search, status = (qp.get("q") or "")[:200], qp.get("s") or ""
        bots, live, ip = qp.get("bots") != "0", qp.get("live") == "1", (qp.get("ip") or "")[:64]
        rows, total = await asyncio.to_thread(traffic.journal, slug, period, search, status, bots)
        det = await asyncio.to_thread(traffic.ip_detail, slug, ip) if ip else None
        return render(request, "traffic.html", vue="journal", rows=rows, total=total, period=period, periods=traffic.JOURNAL_PERIODS,
                      search=search, status=status, bots=bots, live=live, ip=ip, det=det, auto_refresh=10 if live else None, **ctx)
    rng = qp.get("r") if qp.get("r") in traffic.RANGES else "24h"
    bots = qp.get("bots") == "1"
    ov = await asyncio.to_thread(cache.get, f"traffic:{slug}:{rng}:{int(bots)}", 60, traffic.overview, slug, rng, bots)
    return render(request, "traffic.html", vue="apercu", ov=ov, st=traffic.charts(ov), ranges=list(traffic.RANGES), **ctx)


@router.post("/apps/{slug}/trafic/reglages")
async def app_traffic_settings(request: Request, slug: str):
    get_app_or_404(slug)
    if getattr(request.state, "role", "admin") != "admin":
        flash(request, "Réglage réservé aux administrateurs.", "error")
        return go(f"/apps/{slug}/trafic")
    f = await request.form()
    try:
        traffic.save_settings(f.get("days") or 0, f.get("ip_days") or 0, f.get("max_rows") or 0)
        s = traffic.settings()
        P.log("info", "système", f"journal d'accès : {s['days']} jours, adresses complètes {s['ip_days']} jours, "
                                 f"{s['max_rows']} lignes max par appli")
        flash(request, "Conservation du journal d'accès enregistrée (toutes les applis).")
    except (TypeError, ValueError) as e:
        flash(request, f"Refusé : {e}", "error")
    return go(f"/apps/{slug}/trafic?vue=journal#conservation")


@router.post("/apps/{slug}/logs/alerts")
async def app_log_alerts(request: Request, slug: str):
    get_app_or_404(slug)
    f = await request.form()
    try:
        applogs.save(slug, f.get("on") == "on", f.get("patterns") or "")
        s = applogs.settings(slug)
        P.log("info", slug, "alertes sur les logs " + (f"actives ({len(s['patterns'].splitlines())} motif(s))" if s["on"] else "coupées"))
        flash(request, "Alertes sur les logs enregistrées.")
    except ValueError as e:
        flash(request, f"Refusé : {e}", "error")
    return go(f"/apps/{slug}/logs#alertes")


@router.post("/apps/{slug}/mail/setup")
async def mail_setup(request: Request, slug: str):
    a = get_app_or_404(slug)
    f = await request.form()
    if not mail.needs_setup(slug):
        flash(request, "Stalwart est déjà configuré.", "error")
    elif a["state"] == "deploying":
        flash(request, "Une opération est en cours sur cette appli.", "error")
    else:
        P.spawn(mail.setup, slug, (f.get("mail_cf_token") or "").strip(), request.session.get("user") or "?")
        flash(request, "Configuration de Stalwart lancée : suis l'avancement dans les événements.")
    return go(f"/apps/{slug}#messagerie")


@router.post("/apps/{slug}/mail/admin/forget")
async def mail_admin_forget(request: Request, slug: str):
    get_app_or_404(slug)
    if getattr(request.state, "role", "admin") == "admin":
        mail.forget_admin(slug)
        P.log("info", slug, f"mot de passe de l'admin Stalwart oublié par la console ({request.session.get('user')})")
        flash(request, "Mot de passe oublié par Hangar : il n'est plus que dans Stalwart.")
    return go(f"/apps/{slug}#messagerie")
