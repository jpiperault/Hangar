"""API à jetons (/api/v1/…) : lire l'état des applis, leurs logs et leur trafic ; déployer, démarrer, arrêter.

Authentification : en-tête « Authorization: Bearer hgr_… » (apitokens.py), contrôlée par le middleware de main.py, qui
pose request.state.api. Réponses en JSON. Un compte « applis choisies » ne voit que ses applis ; déployer demande un
jeton « deploy » et le droit de déployer cette appli.
"""
import asyncio
import time

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .. import applogs, db, kinds, perms, traffic
from .. import domains as D
from .. import platform as P

router = APIRouter(prefix="/api/v1")


def _err(status, msg):
    return JSONResponse({"error": msg}, status_code=status)


def _tok(request):
    return request.state.api


def _app(request, slug):
    t = _tok(request)
    a = db.app(slug)
    if not a or not perms.visible(t["role"], t["user"], slug):
        return None
    return a


def _summary(r, statuses=None):
    st = (statuses or {}).get(r["slug"])
    return {"slug": r["slug"], "name": r["name"], "kind": r["kind"], "source": r["source"], "version": r["version"],
            "previous_version": r["prev_version"], "node": r["node"], "state": r["state"], "desired": r["desired"],
            "status": st, "url": D.primary_url(r["slug"])}


@router.get("")
async def api_root(request: Request):
    t = _tok(request)
    return {"hangar": "api v1", "token": {"name": t["name"], "user": t["user"], "scope": t["scope"], "role": t["role"]},
            "endpoints": ["GET /api/v1/apps", "GET /api/v1/apps/{slug}", "GET /api/v1/apps/{slug}/events",
                          "GET /api/v1/apps/{slug}/logs?period=1h&q=&errors=1", "GET /api/v1/apps/{slug}/traffic?range=24h",
                          "POST /api/v1/apps/{slug}/deploy {\"version\": \"…\"}", "POST /api/v1/apps/{slug}/start",
                          "POST /api/v1/apps/{slug}/stop", "POST /api/v1/apps/{slug}/restart"]}


@router.get("/apps")
async def api_apps(request: Request):
    t = _tok(request)
    rows = await asyncio.to_thread(P.apps_with_status)
    return {"apps": [_summary(r, {x["slug"]: x["status"] for x in rows}) for r in rows
                     if perms.visible(t["role"], t["user"], r["slug"])]}


@router.get("/apps/{slug}")
async def api_app(request: Request, slug: str):
    a = _app(request, slug)
    if not a:
        return _err(404, "appli inconnue")
    rows = await asyncio.to_thread(P.apps_with_status)
    st = {x["slug"]: x["status"] for x in rows}
    out = _summary(a, st)
    out.update(port=a["port"], health_path=a["health_path"], memory_mb=a["mem_mb"], database=bool(a["db"]),
               http=kinds.http(a["kind"]), urls=[u for u in (D.url_of(r, slug) for r in D.routes(slug)) if u],
               image=a["image"] if a["source"] != "static" else None)
    if a["source"] == "git":
        from .. import autobuild
        ab = autobuild.of(slug) or {}
        out["build"] = {"dockerfile": "repository" if ab.get("own") else ("hangar" if ab else None),
                        "stack": ab.get("label"), "start": ab.get("start"), "commit": ab.get("sha")}
    return out


@router.get("/apps/{slug}/events")
async def api_events(request: Request, slug: str):
    if not _app(request, slug):
        return _err(404, "appli inconnue")
    n = max(1, min(200, int(request.query_params.get("limit") or 30)))
    rows = db.q("SELECT ts, level, msg FROM events WHERE app = ? ORDER BY id DESC LIMIT ?", (slug, n))
    return {"events": [{"time": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(r["ts"])), "level": r["level"],
                        "message": r["msg"]} for r in rows]}


@router.get("/apps/{slug}/logs")
async def api_logs(request: Request, slug: str):
    if not _app(request, slug):
        return _err(404, "appli inconnue")
    qp = request.query_params
    period = qp.get("period") if qp.get("period") in applogs.PERIODS else ""
    lines, total, cut = await asyncio.to_thread(applogs.read, slug, period, (qp.get("q") or "")[:200], qp.get("errors") == "1",
                                                min(2000, max(1, int(qp.get("limit") or 300))))
    return {"lines": lines, "matched": total, "truncated": bool(cut)}


@router.get("/apps/{slug}/traffic")
async def api_traffic(request: Request, slug: str):
    if not _app(request, slug):
        return _err(404, "appli inconnue")
    rng = request.query_params.get("range") if request.query_params.get("range") in traffic.RANGES else "24h"
    ov = await asyncio.to_thread(traffic.overview, slug, rng, request.query_params.get("bots") == "1")
    pick = lambda rows: [{"key": r["key"], "label": r["label"], "count": r["n"]} for r in rows]  # noqa: E731
    return {"range": rng, "visitors": ov["visitors"], "page_views": ov["pages"], "requests": ov["req"]["requests"],
            "server_errors": ov["req"]["e5"], "p95_ms": ov["req"]["p95"], "bytes": ov["req"]["bytes"],
            "top_pages": pick(ov["top_pages"]), "referrers": pick(ov["top_refs"]), "countries": pick(ov["top_cc"]),
            "status": [{"class": c["label"], "count": c["n"]} for c in ov["codes"]],
            "suspects": [{k: x[k] for k in ("ip", "kind", "what")} for x in ov["suspects"]]}


async def _act(request, slug, what):
    t = _tok(request)
    a = _app(request, slug)
    if not a:
        return _err(404, "appli inconnue")
    if t["scope"] != "deploy" or not perms.can_deploy(t["role"], t["user"], slug):
        return _err(403, "ce jeton ne peut pas déployer cette appli")
    if a["state"] == "deploying":
        return _err(409, "un déploiement est déjà en cours")
    who = f"API ({t['name']}, {t['user']})"
    if what == "deploy":
        try:
            body = await request.json()
        except ValueError:
            body = {}
        v = str((body or {}).get("version") or "").strip() or a["version"]
        if not P.VERSION.match(v):
            return _err(400, "version invalide : lettres, chiffres, . _ - /")
        if a["source"] == "git":
            P.request_rebuild(slug)   # même branche : nouvelle construction depuis le dernier commit
        db.update_app(slug, state="deploying")
        P.log("info", slug, f"déploiement de {v} demandé par {who}")
        P.spawn(P.deploy, slug, v, "update")
        return JSONResponse({"accepted": True, "action": "deploy", "version": v}, status_code=202)
    if what == "stop":
        P.log("info", slug, f"arrêt demandé par {who}")
        await asyncio.to_thread(P.stop, slug)
        return {"accepted": True, "action": "stop"}
    db.update_app(slug, state="deploying")
    P.log("info", slug, f"{'démarrage' if what == 'start' else 'redémarrage'} demandé par {who}")
    P.spawn(P.start if what == "start" else P.restart, slug)
    return JSONResponse({"accepted": True, "action": what}, status_code=202)


@router.post("/apps/{slug}/deploy")
async def api_deploy(request: Request, slug: str):
    return await _act(request, slug, "deploy")


@router.post("/apps/{slug}/start")
async def api_start(request: Request, slug: str):
    return await _act(request, slug, "start")


@router.post("/apps/{slug}/stop")
async def api_stop(request: Request, slug: str):
    return await _act(request, slug, "stop")


@router.post("/apps/{slug}/restart")
async def api_restart(request: Request, slug: str):
    return await _act(request, slug, "restart")
