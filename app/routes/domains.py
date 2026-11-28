"""Domaines, Cloudflare et tunnel."""
import asyncio

from fastapi import APIRouter, Request

from .. import cloudflare, db, nodes
from .. import domains as D
from .. import platform as P
from .common import flash, go, render

router = APIRouter()


# ---------------------------------------------------------------- domaines

def _entry_choices():
    out = [{"id": "local", "name": "Ce serveur (console)"}]
    out += [{"id": n["id"], "name": n["name"], "address": n["address"]} for n in nodes.all_nodes()
            if n["id"] != "local" and n["state"] in ("ok", "offline")]
    return out


@router.get("/domains")
async def domains_page(request: Request):
    names = await asyncio.to_thread(P.public_names)
    doms = D.all_domains()
    usage = {d["name"]: db.one("SELECT COUNT(DISTINCT slug) AS n FROM routes WHERE domain = ?", (d["name"],))["n"]
             for d in doms}
    by = {}
    for r in db.q("SELECT DISTINCT r.domain, a.slug, a.name FROM routes r JOIN apps a ON a.slug = r.slug ORDER BY a.name"):
        by.setdefault(r["domain"], []).append(r)
    return render(request, "domains.html", title="Domaines", nav="domains", doms=doms, usage=usage, names=names,
                  users_of=by,
                  missing=[n for n in names if n["ok"] is False], cf=cloudflare.status(), entries=_entry_choices(),
                  tunnel_id=P.tunnel_id(), tunnel=P.tunnel_status(), form=request.session.pop("dform", None))


async def _after_domains(request, tunnel_before):
    try:
        await asyncio.to_thread(P.apply_routing)
    except RuntimeError as e:
        flash(request, str(e), "error")
        return False
    if P.tunnel_ready() != tunnel_before:
        P.spawn(P.sync_all_tunnels)   # connecteurs des nœuds : actifs seulement s'il y a un domaine en tunnel
    return True


@router.post("/domains/add")
async def domains_add(request: Request):
    f = await request.form()
    before = P.tunnel_ready()
    errs = D.save(f.get("name"), f.get("mode"), f.get("hub"), f.get("entry") or "local", f.get("ip"),
                  make_default=f.get("default") == "on")
    if errs:
        request.session["dform"] = {k: f.get(k) or "" for k in ("name", "mode", "hub", "entry", "ip")}
        flash(request, " ".join(errs.values()), "error")
        return go("/domains#ajouter")
    name = f.get("name").strip().lower().rstrip(".")
    if await _after_domains(request, before):
        P.log("ok", "caddy", f"domaine {name} ajouté ({f.get('mode')})")
        flash(request, f"{name} ajouté. Les applis peuvent maintenant y avoir une adresse.")
    return go("/domains")


@router.post("/domains/{name}")
async def domains_edit(request: Request, name: str):
    old = D.get(name)
    if not old:
        return go("/domains")
    f = await request.form()
    before = P.tunnel_ready()
    errs = D.save(name, f.get("mode"), f.get("hub"), f.get("entry") or "local", f.get("ip"),
                  make_default=f.get("default") == "on", old=old)
    if errs:
        flash(request, " ".join(errs.values()), "error")
        return go(f"/domains#d-{name}")
    if not await _after_domains(request, before):
        D.save(name, old["mode"], old["hub"], old["entry"], old["ip"], old=old)   # retour à l'ancien réglage
        await asyncio.to_thread(P.apply_routing)
        return go("/domains")
    P.log("ok", "caddy", f"domaine {name} modifié : {f.get('mode')}, préfixe {f.get('hub') or 'aucun'}")
    msg = f"{name} enregistré, Caddy rechargé."
    if f.get("mode") != old["mode"]:
        msg += (" Ses noms passent maintenant par le tunnel Cloudflare." if f.get("mode") == "tunnel"
                else " Les ports 80 et 443 doivent arriver jusqu'à la machine d'entrée choisie.")
    flash(request, msg)
    return go("/domains")


@router.post("/domains/{name}/remove")
async def domains_remove(request: Request, name: str):
    before = P.tunnel_ready()
    try:
        D.remove(name)
    except ValueError as e:
        flash(request, str(e), "error")
        return go("/domains")
    if await _after_domains(request, before):
        P.log("info", "caddy", f"domaine {name} retiré")
        flash(request, f"{name} retiré.")
    return go("/domains")


@router.post("/cloudflare/token")
async def cf_token(request: Request):
    f = await request.form()
    try:
        zones = await asyncio.to_thread(cloudflare.set_token, f.get("token"))
    except ValueError as e:
        flash(request, str(e), "error")
        return go("/domains#cloudflare")
    await asyncio.to_thread(cloudflare.sync_quiet)
    err = cloudflare.status().get("error")
    flash(request, f"Jeton accepté (zones : {', '.join(zones) or 'aucune'}). " +
          (f"Synchronisation en échec : {err}" if err else "Noms publics synchronisés."), "error" if err else "ok")
    return go("/domains#cloudflare")


@router.post("/cloudflare/remove")
async def cf_remove(request: Request):
    await asyncio.to_thread(cloudflare.remove_token)
    flash(request, "Jeton d'API retiré. Ce qui existe chez Cloudflare reste en place.")
    return go("/domains#cloudflare")


@router.post("/cloudflare/sync")
async def cf_sync(request: Request):
    await asyncio.to_thread(cloudflare.sync_quiet)
    st = cloudflare.status()
    flash(request, f"Synchronisation en échec : {st['error']}" if st.get("error") else
          "Cloudflare est à jour." + (" " + " ; ".join(st.get("changes") or []) if st.get("changes") else ""),
          "error" if st.get("error") else "ok")
    return go("/domains")


@router.post("/settings/tunnel")
async def save_tunnel_token(request: Request):
    f = await request.form()
    try:
        tid = await asyncio.to_thread(P.set_tunnel_token, f.get("token") or "")
    except (ValueError, RuntimeError) as e:
        flash(request, str(e), "error")
        return go("/domains#tunnel")
    P.spawn(cloudflare.sync_quiet)
    flash(request, f"Jeton enregistré. cloudflared est connecté au tunnel {tid}.")
    return go("/domains#tunnel")


# ---------------------------------------------------------------- démarrage rapide

@router.get("/demarrage")
async def quickstart_page(request: Request):
    from .. import catalog, quickstart
    st = await asyncio.to_thread(quickstart.state)
    example = catalog.get("it-tools")
    app_url = D.primary_url(st["app"]["slug"]) if st["app"] else None
    return render(request, "quickstart.html", title="Démarrage rapide", nav="apps", st=st, example=example, app_url=app_url,
                  form=request.session.pop("qsform", {}))


@router.post("/demarrage/domaine")
async def quickstart_connect(request: Request):
    from .. import quickstart
    if getattr(request.state, "role", "admin") != "admin":
        flash(request, "Réservé aux administrateurs.", "error")
        return go("/demarrage")
    f = await request.form()
    try:
        name = await asyncio.to_thread(quickstart.connect, f.get("domain"), f.get("token"))
    except (ValueError, RuntimeError) as e:
        request.session["qsform"] = {"domain": f.get("domain") or ""}
        flash(request, str(e), "error")
        return go("/demarrage#domaine")
    flash(request, f"{name} est relié : le tunnel Cloudflare est connecté et Hangar gère ses noms publics.")
    return go("/demarrage#appli")
