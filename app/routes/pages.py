"""Prompts de déploiement et de migration, journal des événements, premier démarrage."""
import asyncio
import os
import re

from fastapi import APIRouter, Request

from .. import db, onboarding
from .. import domains as D
from .common import HERE, flash, go, render

router = APIRouter()


# ---------------------------------------------------------------- prompt de déploiement

@router.get("/prompt")
async def prompt_page(request: Request):
    a = db.app(request.query_params.get("app") or "")
    dft = D.default()
    hangar = {"platform": {"base": dft["name"], "hub": dft["hub"], "mode": dft["mode"],
                           "domains": [{"name": d["name"], "hub": d["hub"], "mode": d["mode"]} for d in D.all_domains()]}}
    if a:
        m = re.match(r"^ghcr\.io/([^/]+)/", a["image"]) if a["source"] == "image" else None
        r0 = (D.routes(a["slug"]) or [{"kind": "path", "domain": dft["name"], "sub": ""}])[0]
        dom = D.get(r0["domain"]) or dft
        hangar["platform"].update(base=dom["name"], hub=dom["hub"], mode=dom["mode"])
        hangar["app"] = {"name": a["name"], "slug": a["slug"], "pkg": a["pkg"], "kind": a["kind"],
                         "expose": "path" if r0["kind"] == "path" else "sub",
                         "sub": r0["sub"], "port": a["port"], "mem": a["mem_mb"], "db": bool(a["db"]),
                         "gh": m.group(1) if m else None, "url": D.primary_url(a["slug"])}
    return render(request, "prompt.html", title="Préparer un projet", nav="prompt", app=a,
                  apps=db.apps(), hangar=hangar)


@router.get("/prompt/migration")
async def prompt_migration_page(request: Request):
    """Générateur du prompt de migration : docs/prompt-migration.md, rempli avec la fiche de l'appli et la source."""
    txt = open(os.path.join(os.path.dirname(HERE), "docs", "prompt-migration.md")).read()
    txt = re.sub(r"^<!--.*?-->\s*", "", txt, flags=re.S)
    a = db.app(request.query_params.get("app") or "")
    apps = []
    for x in db.apps():
        m = re.match(r"^ghcr\.io/([^/]+)/", x["image"] or "") if x["source"] == "image" else None
        apps.append({"slug": x["slug"], "name": x["name"], "image": x["image"] if x["source"] == "image" else "",
                     "gh": m.group(1) if m else "", "version": x["version"], "port": x["port"], "db": bool(x["db"])})
    return render(request, "prompt_migration.html", title="Prompt de migration", nav="prompt", app=a, apps=apps,
                  tpl=txt)


# ---------------------------------------------------------------- journal

@router.get("/journal")
async def journal(request: Request):
    app_filter = request.query_params.get("app") or ""
    if app_filter:
        events = db.q("SELECT * FROM events WHERE app = ? ORDER BY id DESC LIMIT 300", (app_filter,))
    else:
        events = db.q("SELECT * FROM events ORDER BY id DESC LIMIT 300")
    names = [r["app"] for r in db.q("SELECT DISTINCT app FROM events ORDER BY app")]
    return render(request, "journal.html", title="Journal", nav="journal", events=events, names=names, app_filter=app_filter)


# ---------------------------------------------------------------- logs de toutes les applis

@router.get("/logs")
async def all_logs(request: Request):
    from .. import applogs, perms
    qp = request.query_params
    role, me = getattr(request.state, "role", "admin"), request.session.get("user")
    mine = [a for a in db.apps() if a["kind"] != "static" and perms.visible(role, me, a["slug"])]
    period = qp.get("p") if qp.get("p") in ("1h", "24h", "168h") else "24h"
    q, err, app = (qp.get("q") or "")[:200], qp.get("e") == "1", qp.get("app") or ""
    slugs = [app] if app in {a["slug"] for a in mine} else [a["slug"] for a in mine]
    found, errs, cut, asked = [], {}, False, bool(q or err)
    if asked:
        found, errs, cut = await asyncio.to_thread(applogs.search, q, period, err, slugs)
    return render(request, "all_logs.html", title="Logs des applis", nav="logs", found=found, errs=errs, cut=cut,
                  asked=asked, q=q, err=err, period=period, app=app, apps=mine,
                  periods={k: v for k, v in applogs.PERIODS.items() if k})


# ---------------------------------------------------------------- premier démarrage

@router.get("/bienvenue")
async def welcome(request: Request):
    st = await asyncio.to_thread(onboarding.steps)
    return render(request, "welcome.html", title="Bien démarrer", nav="apps", steps=st,
                  left=[x for x in st if x["essential"] and not x["done"]], hidden=onboarding.hidden())


@router.post("/bienvenue/{op}")
async def welcome_toggle(request: Request, op: str):
    onboarding.set_hidden(op == "masquer")
    flash(request, "Liste de démarrage masquée : elle reste dans Accès et comptes → Bien démarrer." if op == "masquer" else
          "Liste de démarrage affichée sur l'accueil.")
    return go("/" if op == "masquer" else "/bienvenue")
