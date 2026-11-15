"""Nœuds et sécurité des nœuds."""
import asyncio
import time

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .. import access, db, diskuse, ha, nodes, security, stats
from .. import platform as P
from .common import flash, go, render

router = APIRouter()


# ---------------------------------------------------------------- nœuds

@router.get("/nodes")
async def nodes_page(request: Request):
    rows = nodes.all_nodes()
    if not nodes.get(nodes.LOCAL):
        rows.insert(0, {"id": nodes.LOCAL, "name": "Ce serveur (console)", "address": db.settings()["admin_bind"].rsplit(":", 1)[0],
                        "wg_ip": "—", "state": "ok", "info": {}, "created_at": 0})
    hs = await asyncio.to_thread(nodes.handshakes)
    loc = await asyncio.to_thread(nodes.local_info)
    apps_by = {}
    for a in db.apps():
        apps_by.setdefault(a["node"], []).append(a)
    for n in rows:
        if n["id"] == nodes.LOCAL:
            n["info"] = loc
        n["hs"] = hs.get(n.get("wg_pubkey") or "")
        n["apps"] = apps_by.get(n["id"], [])
        n["reserved"] = sum(a["mem_mb"] for a in n["apps"] if a["desired"] == "running")
    key = await asyncio.to_thread(nodes.ensure_key)
    busy = any(n["state"] == "installing" for n in rows)
    hrows = []
    for h in ha.all_ha():
        ap = db.app(h["slug"])
        if ap:
            hrows.append({"a": ap, "h": h})
    return render(request, "nodes.html", title="Nœuds", nav="nodes", rows=rows, key=key, now=time.time(),
                  has=ha.settings(), hrows=hrows, crole=nodes.console_role(), on_console=apps_by.get(nodes.LOCAL, []),
                  fence_auto=len([n for n in nodes.all_nodes() if n["id"] != nodes.LOCAL]) >= 2,
                  refresh=busy, auto_refresh=None if busy else 60)


@router.post("/nodes/add")
async def nodes_add(request: Request):
    f = await request.form()
    try:
        await asyncio.to_thread(nodes.add, f.get("id"), f.get("name"), f.get("address"), f.get("ssh_port"),
                                f.get("ssh_user"), f.get("sudo_password") or "")
        flash(request, "Installation du nœud lancée : quelques minutes. Cette page se met à jour toute seule.")
    except (ValueError, RuntimeError) as e:
        flash(request, str(e), "error")
    return go("/nodes")


@router.post("/nodes/{node_id}/retry")
async def nodes_retry(request: Request, node_id: str):
    f = await request.form()
    n = nodes.get(node_id)
    if n and node_id != nodes.LOCAL and n["state"] != "installing":
        P.spawn(nodes.install, node_id, f.get("sudo_password") or "")
        flash(request, f"Réinstallation de {n['name']} lancée. Rien n'est effacé : le script reprend là où il en était.")
    return go("/nodes")


@router.post("/nodes/{node_id}/remove")
async def nodes_remove(request: Request, node_id: str):
    f = await request.form()
    if (f.get("confirm") or "").strip() != node_id:
        flash(request, f"Tape {node_id} pour confirmer.", "error")
        return go(f"/nodes/{node_id}")
    try:
        await asyncio.to_thread(nodes.remove, node_id)
        flash(request, f"Nœud {node_id} retiré du réseau privé.")
    except ValueError as e:
        flash(request, str(e), "error")
        return go(f"/nodes/{node_id}")
    return go("/nodes")


# ---------------------------------------------------------------- sécurité des nœuds

def _sec_values(p, f=None):
    """Valeurs du formulaire de sécurité : la politique, ou ce qui a été tapé (en cas d'erreur)."""
    v = security.to_form(p)
    if f is not None:
        for k in ("ssh_sources", "admin_keys", "extra", "ssh_port", "reboot"):
            v[k] = f.get(k) or ""
    return v


def _sec_row(n):
    st = security.state(n)
    obs = st.get("obs") or {}
    cs = security.checks(n)
    lv, count = security.level(cs)
    return {"n": n, "st": st, "own": bool(n.get("security")), "applying": security.applying(n),
            "checks": cs, "level": lv, "count": count, "banned": obs.get("banned") or [],
            "web": security.web_needed(n["id"]), "pending": security.pending(n),
            "summary": security.summary(security.node_policy(n)[0])}


JOURNAL_CATS = [("all", "Tout"), ("sec", "Sécurité"), ("install", "Installation"), ("route", "Tunnel et routage"),
                ("other", "Autres")]


def _event_cat(msg):
    m = msg.lower()
    if m.startswith("sécurité") or "bannie" in m or "redémarrage" in m:
        return "sec"
    if any(w in m for w in ("installation", "réparation", "préparation", "nœud prêt", "réseau privé", "wireguard")):
        return "install"
    if any(w in m for w in ("tunnel", "caddy", "trafic", "route")):
        return "route"
    return "other"


@router.get("/security")
async def security_page(request: Request):
    return await _security_render(request)


async def _security_render(request, f=None, err=None):
    rows = [await asyncio.to_thread(_sec_row, n) for n in nodes.all_nodes() if n["id"] != nodes.LOCAL]
    busy = any(r["applying"] for r in rows)
    return render(request, "security.html", title="Sécurité", nav="security", rows=rows,
                  f=f or _sec_values(security.policy()), err=err, lan=", ".join(access.current()["nets"]),
                  gsum=security.summary(security.policy()), cssh=await asyncio.to_thread(security.console_ssh),
                  refresh=busy, status_code=400 if err else 200)


@router.post("/security/console-ssh")
async def console_ssh(request: Request):
    f = await request.form()
    err = await asyncio.to_thread(security.console_ssh_apply, f.get("keys_only") == "on", f.get("f2b") == "on",
                                  f.get("keys"), request.session.get("user"))
    flash(request, err or "SSH de la console réglé.", "error" if err else "ok")
    return go("/security#console")


@router.post("/security")
async def security_save(request: Request):
    f = await request.form()
    p, err = security.parse_form(f)
    if err:
        flash(request, "Rien n'est appliqué : corrige les champs en rouge.", "error")
        return await _security_render(request, f=_sec_values(p, f), err=err)
    security.save_global(p, request.session.get("user"))
    targets = [n["id"] for n in nodes.all_nodes() if n["id"] != nodes.LOCAL and not n.get("security")
               and n["state"] == "ok"]
    for nid in targets:
        P.spawn(security.apply, nid, request.session.get("user"))
    flash(request, "Politique enregistrée" + (f" : application sur {len(targets)} nœud(s), une à la fois." if targets
                                               else ". Elle s'appliquera à chaque nœud installé."))
    return go("/security")


@router.post("/security/{node_id}/apply")
async def security_apply(request: Request, node_id: str):
    n = nodes.get(node_id)
    if n and node_id != nodes.LOCAL:
        P.spawn(security.apply, node_id, request.session.get("user"))
        flash(request, f"Application sur {n['name']} lancée.")
    return go("/security")


@router.post("/security/{node_id}/collect")
async def security_collect(request: Request, node_id: str):
    n = nodes.get(node_id)
    if n and node_id != nodes.LOCAL:
        obs = await asyncio.to_thread(security.collect, node_id)
        flash(request, "État relevé." if obs else "Nœud injoignable : état non relevé.", "ok" if obs else "error")
    back = request.headers.get("referer") or "/security"
    return go("/security" if back.split("#")[0].rstrip("/").endswith("/security") else f"/nodes/{node_id}#securite")


@router.post("/disk/refresh")
async def disk_refresh(request: Request):
    """Mesure de l'espace disque de toutes les machines, en tâche de fond (20 s environ)."""
    if not diskuse.busy():
        diskuse.collect_async()
    flash(request, "Mesure de l'espace disque lancée : recharge la page dans une demi-minute.")
    from urllib.parse import urlparse
    back = urlparse(request.headers.get("referer") or "").path   # chemin seul : pas de redirection ailleurs
    return go((back if back.startswith(("/apps/", "/nodes")) else "/nodes") + "#disque")


@router.get("/security/myip")
async def security_myip(request: Request):
    return JSONResponse({"ip": await asyncio.to_thread(security.public_ip)})


@router.post("/nodes/{node_id}/security")
async def node_security(request: Request, node_id: str):
    n = nodes.get(node_id)
    if not n or node_id == nodes.LOCAL:
        return go("/nodes")
    f = await request.form()
    user = request.session.get("user")
    if f.get("which") == "own":
        p, err = security.parse_form(f)
        if err:
            flash(request, "Rien n'est appliqué : corrige les champs en rouge.", "error")
            return await _node_render(request, node_id, sec_f=_sec_values(p, f), sec_err=err)
        security.save_node(node_id, p, user)
    else:
        security.save_node(node_id, None, user)
    if n["state"] == "ok":
        P.spawn(security.apply, node_id, user)
        flash(request, "Réglage enregistré, application en cours.")
    else:
        flash(request, "Réglage enregistré : il s'appliquera quand le nœud répondra.")
    return go(f"/nodes/{node_id}#securite")


@router.post("/nodes/{node_id}/reboot")
async def node_reboot(request: Request, node_id: str):
    try:
        lxc = await asyncio.to_thread(security.reboot, node_id, request.session.get("user"))
        flash(request, "Redémarrage lancé : le nœud et ses applis reviennent en une à deux minutes." + (
            " C'est un conteneur LXC : selon sa configuration, Proxmox peut le laisser arrêté. "
            "S'il ne revient pas, démarre-le depuis Proxmox." if lxc else ""))
    except (ValueError, RuntimeError) as e:
        flash(request, f"Redémarrage impossible : {e}", "error")
    return go(f"/nodes/{node_id}#securite")


@router.post("/nodes/{node_id}/unban")
async def node_unban(request: Request, node_id: str):
    f = await request.form()
    try:
        await asyncio.to_thread(security.unban, node_id, (f.get("ip") or "").strip())
        flash(request, f"{f.get('ip')} débannie.")
    except (ValueError, RuntimeError) as e:
        flash(request, f"Débannissement impossible : {e}", "error")
    return go(f.get("back") if f.get("back") == "/security" else f"/nodes/{node_id}#securite")


@router.get("/nodes/{node_id}")
async def node_page(request: Request, node_id: str):
    return await _node_render(request, node_id)


async def _node_render(request, node_id, sec_f=None, sec_err=None):
    n = nodes.get(node_id)
    if not n:
        return go("/nodes")
    rng = request.query_params.get("r") if request.query_params.get("r") in stats.RANGES else "24h"
    if node_id == nodes.LOCAL:
        n["info"] = await asyncio.to_thread(nodes.local_info)
    se = nodes.series(node_id, rng)
    mem_total = (n["info"] or {}).get("mem_total") or 0
    se["charts"] = [
        {"title": "Processeur", "sub": "moyenne (% des cœurs)", "unit": "%", "kind": "line", "values": se["cpu"],
         "limit": 100, "limitLabel": "100 %", "extra": [{"label": "charge", "values": se["load1"], "unit": ""}]},
        {"title": "Mémoire utilisée", "sub": "max sur l'intervalle (Mo)", "unit": "Mo", "kind": "line", "values": se["mem"],
         "limit": round(mem_total) or None, "limitLabel": f"total {mem_total:.0f} Mo"},
    ]
    events = db.q("SELECT * FROM events WHERE app = ? ORDER BY id DESC LIMIT 150", (f"nœud {node_id}",))
    for e in events:
        e["cat"] = _event_cat(e["msg"])
    hs = (await asyncio.to_thread(nodes.handshakes)).get(n.get("wg_pubkey") or "")
    sec = None
    if node_id != nodes.LOCAL:
        sec = await asyncio.to_thread(_sec_row, n)
        sec["f"] = sec_f or _sec_values(security.own_raw(n) or security.policy())
        sec["err"] = sec_err
        if sec_err:
            sec["own"] = True
    return render(request, "node.html", title=n["name"], nav="nodes", n=n, se=se, rng=rng, ranges=list(stats.RANGES),
                  events=events, hs=hs, now=time.time(), apps=[a for a in db.apps() if a["node"] == node_id],
                  sec=sec, cats=JOURNAL_CATS, du=diskuse.node_view(node_id), du_busy=diskuse.busy(), refresh=n["state"] == "installing" or bool(sec and sec["applying"]),
                  status_code=400 if sec_err else 200)
