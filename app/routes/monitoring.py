"""Supervision et page de statut."""
import asyncio
import time

from fastapi import APIRouter, Request

from .. import backup, cache, db, external, monitor, nodes, stats, statuspage
from .. import domains as D
from .. import platform as P
from .common import _ago, _int, flash, go, render

router = APIRouter()


# ---------------------------------------------------------------- supervision

def _services():
    def active(u):
        return P.run(["systemctl", "is-active", u], timeout=10)[1].strip()
    s = db.settings()
    out = []
    caddy = active("caddy")
    out.append({"name": "Serveur web (Caddy)", "ok": caddy == "active", "state": "en ligne" if caddy == "active" else caddy})
    if P.tunnel_ready():
        t = P.tunnel_status()
        out.append({"name": "Tunnel Cloudflare", "ok": t["active"], "state": "connecté" if t["active"] else t["state"]})
    dk = active("docker")
    out.append({"name": "Docker", "ok": dk == "active", "state": "en ligne" if dk == "active" else dk})
    pg = P.run(["docker", "inspect", "-f", "{{.State.Health.Status}}", P.PG], timeout=10)[1].strip()
    out.append({"name": "PostgreSQL", "ok": pg == "healthy", "state": {"healthy": "en ligne"}.get(pg, pg or "absent")})
    fw = P.run(["nft", "list", "table", "inet", "platform"], timeout=10)[0] == 0
    out.append({"name": "Pare-feu", "ok": fw, "state": "actif" if fw else "règles absentes"})
    last = backup.last_ok()
    if backup.configured():
        fresh = bool(last and time.time() - last["ts"] < 36 * 3600)
        out.append({"name": "Sauvegardes", "ok": fresh, "state": ("dernière " + _ago(last["ts"])) if last else "aucune réussie"})
    else:
        out.append({"name": "Sauvegardes", "ok": None, "state": "Drive non connecté"})
    out.append({"name": "Alertes", "ok": True if s.get("alerts_on") == "1" else None,
                "state": "actives" if s.get("alerts_on") == "1" else "désactivées"})
    return out


def _postgres():
    q = ("SELECT datname, pg_database_size(datname) FROM pg_database WHERE datname NOT IN ('template0','template1') "
         "ORDER BY 2 DESC;")
    rc, out = P._psql(q)
    dbs = [{"name": l.split("|")[0], "size": int(l.split("|")[1])} for l in out.splitlines() if "|" in l] if rc == 0 else []
    rc, conn = P._psql("SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'client backend';")
    rc2, mx = P._psql("SHOW max_connections;")
    return {"dbs": dbs, "total": sum(d["size"] for d in dbs), "conn": conn.strip() if rc == 0 else "?",
            "max": mx.strip() if rc2 == 0 else "?"}


cache.keep_warm("mon_containers", 30, P.container_details)
cache.keep_warm("mon_pg", 60, _postgres)


@router.post("/monitoring/external")
async def external_save(request: Request):

    f = await request.form()
    node = f.get("node") or ""
    if node and not db.one("SELECT 1 FROM nodes WHERE id = ?", (node,)):
        node = ""
    external.save(f.get("on") == "on" and bool(node), node, _int(f.get("every"), 1, 60, 5), _int(f.get("fails"), 1, 10, 2))
    s = external.settings()
    P.log("info", "supervision", "surveillance de l'extérieur " + (f"depuis {node}, toutes les {s['every']} min" if s["on"] else "coupée"))
    if s["on"] and (request.query_params.get("now") == "1" or not external.results()):
        try:
            await asyncio.to_thread(external.run)
            flash(request, "Enregistré, et premier passage fait.")
        except Exception as e:
            flash(request, f"Enregistré, mais la sonde ne répond pas : {str(e)[:200]}", "error")
    else:
        flash(request, "Surveillance de l'extérieur enregistrée.")
    return go("/monitoring#exterieur")


@router.get("/monitoring")
async def monitoring(request: Request):
    rng = request.query_params.get("r") if request.query_params.get("r") in stats.RANGES else "24h"
    host = stats.host_now()
    hs = stats.host_charts(stats.host_series(rng), host["mem_total"])
    rows = await asyncio.to_thread(P.apps_with_status)
    req, spark, res24 = stats.apps_overview()
    cont = await asyncio.to_thread(cache.get, "mon_containers", 30, P.container_details)
    svc = await asyncio.to_thread(cache.get, "mon_services", 15, _services)
    pg = await asyncio.to_thread(cache.get, "mon_pg", 60, _postgres)
    for a in rows:
        a["h"] = monitor.health.get(a["slug"])
        a["r"] = req.get(a["slug"])
        a["c"] = cont.get(a["slug"], {})
        a["cpu24"] = (res24.get(a["slug"]) or {}).get("cpu")
        a["spark"] = stats.spark_path(spark.get(a["slug"], [0] * 24))
        a["spark_max"] = max(spark.get(a["slug"], [0]))
    incidents = db.q("SELECT * FROM events WHERE level IN ('error', 'warn') AND ts > ? ORDER BY id DESC LIMIT 15",
                     (time.time() - 86400,))
    return render(request, "monitoring.html", title="Supervision", nav="monitoring", host=host, hs=hs, rng=rng,
                  ranges=list(stats.RANGES), rows=rows, svc=svc, pg=pg, incidents=incidents, auto_refresh=60,
                  now=time.time(), machines=_machines(host, svc, rows), sp=statuspage.settings(),
                  sp_host=statuspage.host(), sp_dns=(await asyncio.to_thread(P.resolves, [statuspage.host()]))
                  .get(statuspage.host()) if statuspage.host() else None, doms=D.all_domains(),
                  ext=external.settings(), ext_res=external.results(),
                  ext_err=db.kv_get("external_error"), probe_nodes=db.q("SELECT id, state FROM nodes ORDER BY id"),
                  app_names={a["slug"]: a["name"] for a in rows})


@router.post("/monitoring/status")
async def status_page_save(request: Request):
    f = await request.form()
    try:
        statuspage.save(f.get("on") == "on", f.get("domain") or "", f.get("sub") or "", f.get("title") or "",
                        f.getlist("apps"))
        await asyncio.to_thread(P.apply_routing)
        await asyncio.to_thread(statuspage.write)
        h = statuspage.host()
        P.log("info", "système", f"page de statut publique : {h}" if h else "page de statut publique coupée")
        flash(request, f"Page de statut en ligne sur https://{h}/ (si le nom est déclaré)." if h else "Page de statut coupée.")
    except (ValueError, RuntimeError) as e:
        flash(request, f"Page de statut : {e}", "error")
    return go("/monitoring#statut")


def _machines(host, svc, rows):
    """Une ligne par machine pour la supervision : la console (mesures locales), puis chaque nœud (dernier relevé)."""
    napps = {}
    for a in rows:
        napps[a["node"] or P.LOCAL] = napps.get(a["node"] or P.LOCAL, 0) + 1
    keep = {"Serveur web (Caddy)": "Caddy", "Tunnel Cloudflare": "Tunnel", "Docker": "Docker", "PostgreSQL": "PostgreSQL",
            "Pare-feu": "Pare-feu"}
    out = [{"id": P.LOCAL, "name": "Console", "state": "ok", "info": host, "apps": napps.get(P.LOCAL, 0), "latency": None,
            "checks": [{"name": keep[x["name"]], "ok": x["ok"], "state": x["state"]} for x in svc if x["name"] in keep]}]
    for n in nodes.all_nodes():
        if n["id"] == P.LOCAL:
            continue
        i = n["info"] or {}
        stale = not n["last_seen"] or time.time() - n["last_seen"] > 180
        state = n["state"] if n["state"] != "ok" else ("stale" if stale else "ok")
        out.append({"id": n["id"], "name": n["name"], "state": state, "seen": n["last_seen"], "info": i,
                    "apps": napps.get(n["id"], 0), "latency": i.get("latency_ms"),
                    "checks": [] if state != "ok" else monitor.node_checks(n, i)})
    return out
