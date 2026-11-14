"""Prompts de déploiement et de migration, journal des événements."""
import os
import re

from fastapi import APIRouter, Request

from .. import db
from .. import domains as D
from .common import HERE, render

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
