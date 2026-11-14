"""Versions, déplacement et base de données d'une appli."""
import asyncio
import os
import secrets
import time
import urllib.parse

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from .. import db, dbadmin, monitor, move
from .. import platform as P
from .common import _confirmed, flash, get_app_or_404, go, node_choices, render

router = APIRouter()


# ---------------------------------------------------------------- versions, base, statistiques d'une appli

@router.post("/apps/{slug}/versions/check")
async def versions_check(request: Request, slug: str):
    get_app_or_404(slug)
    await asyncio.to_thread(monitor.check_versions, slug)
    a = db.app(slug)
    if a["latest_error"]:
        flash(request, f"Vérification impossible : {a['latest_error']}", "error")
    elif a["latest_version"]:
        flash(request, f"Version {a['latest_version']} disponible.")
    elif monitor.image_update(slug):
        flash(request, f"Une image plus récente est publiée sous le tag {a['version']} : « Mettre à jour » la déploie.")
    else:
        flash(request, f"{a['version']} est la version la plus récente.")
    return go(f"/apps/{slug}")


@router.get("/apps/{slug}/sql")
async def sql_page(request: Request, slug: str):
    from .. import sqlquery
    a = get_app_or_404(slug)
    eng = sqlquery.engines(slug)
    return render(request, "sql.html", title=f"SQL · {a['name']}", nav="apps", a=a, engines=eng,
                  engine=request.query_params.get("e") or (eng[0] if eng else ""), q="", res=None, err=None)


@router.post("/apps/{slug}/sql")
async def sql_run(request: Request, slug: str):
    from .. import sqlquery
    a = get_app_or_404(slug)
    f = await request.form()
    q, engine = (f.get("q") or "")[:20000], f.get("engine") or ""
    res, err = None, None
    try:
        cols, rows, cut = await asyncio.to_thread(sqlquery.run, slug, engine, q)
        res = {"cols": cols, "rows": rows, "cut": cut}
        P.log("info", slug, f"requête SQL en lecture seule par {request.session.get('user')} : {' '.join(q.split())[:200]}")
    except (ValueError, RuntimeError) as e:
        err = str(e)[:1000]
    return render(request, "sql.html", title=f"SQL · {a['name']}", nav="apps", a=a, engines=sqlquery.engines(slug),
                  engine=engine, q=q, res=res, err=err)


@router.get("/apps/{slug}/files")
async def files_page(request: Request, slug: str):
    from .. import backup, datafiles
    a = get_app_or_404(slug)
    try:
        rel = datafiles.clean(request.query_params.get("p") or "")
        items, cut = await asyncio.to_thread(datafiles.listdir, slug, rel)
        err = None
    except ValueError as e:
        rel, items, cut, err = datafiles.clean(request.query_params.get("p") or ""), [], False, str(e)
    crumbs, acc = [], []
    for part in [x for x in rel.split("/") if x]:
        acc.append(part)
        crumbs.append((part, "/".join(acc)))
    return render(request, "files.html", title=f"data/ · {a['name']}", nav="apps", a=a, rel=rel, items=items, cut=cut,
                  err=err, crumbs=crumbs, internal=datafiles.internal(rel), dests=backup.dests())


@router.get("/apps/{slug}/files/download")
async def files_download(request: Request, slug: str):
    from .. import datafiles
    get_app_or_404(slug)
    rel = request.query_params.get("p") or ""
    try:
        gen = await asyncio.to_thread(datafiles.stream, slug, rel)
    except ValueError as e:
        flash(request, str(e), "error")
        return go(f"/apps/{slug}/files")
    name = os.path.basename(datafiles.clean(rel)) or "fichier"
    P.log("info", slug, f"data/{datafiles.clean(rel)} téléchargé par {request.session.get('user')}")
    return StreamingResponse(gen, media_type="application/octet-stream",
                             headers={"Content-Disposition": f"attachment; filename*=UTF-8''{urllib.parse.quote(name)}"})


@router.post("/apps/{slug}/files/upload")
async def files_upload(request: Request, slug: str):
    from .. import datafiles
    get_app_or_404(slug)
    f = await request.form()
    up = f.get("file")
    folder = datafiles.clean(f.get("p") or "")
    back = go(f"/apps/{slug}/files?p={urllib.parse.quote(folder)}")
    if not up or not getattr(up, "filename", ""):
        flash(request, "Choisis un fichier.", "error")
        return back
    name = datafiles.clean(f.get("name") or os.path.basename(up.filename))
    rel = f"{folder}/{name}" if folder else name
    os.makedirs(P.WORK_TMP, mode=0o700, exist_ok=True)
    tmp = f"{P.WORK_TMP}/envoi-{slug}-{secrets.token_hex(6)}"
    size = 0
    try:
        with open(tmp, "wb") as out:
            while chunk := await up.read(1024 * 1024):
                size += len(chunk)
                if size > datafiles.MAX_UPLOAD:
                    raise ValueError("fichier trop gros (200 Mo au plus)")
                out.write(chunk)
        prev = await asyncio.to_thread(datafiles.write, slug, rel, tmp)
        P.log("info", slug, f"data/{rel} remplacé par {request.session.get('user')}"
              + (f" (ancienne version : {prev})" if prev else " (nouveau fichier)"))
        flash(request, f"data/{rel} enregistré." + (f" L'ancienne version est gardée dans {prev}." if prev else ""))
    except (ValueError, RuntimeError) as e:
        flash(request, str(e), "error")
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return back


@router.post("/apps/{slug}/files/restore")
async def files_restore(request: Request, slug: str):
    from .. import datafiles
    get_app_or_404(slug)
    f = await request.form()
    rel = datafiles.clean(f.get("p") or "")
    folder = os.path.dirname(rel)
    try:
        snap, prev = await asyncio.to_thread(datafiles.restore_file, slug, rel, f.get("dest") or "gdrive")
        when = time.strftime("%d/%m %H:%M", time.localtime(snap["ts"]))
        P.log("ok", slug, f"data/{rel} remis depuis la sauvegarde du {when} par {request.session.get('user')}")
        flash(request, f"data/{rel} remis tel qu'il était le {when}." + (f" La version d'avant est gardée dans {prev}." if prev else ""))
    except (ValueError, RuntimeError) as e:
        flash(request, str(e), "error")
    return go(f"/apps/{slug}/files?p={urllib.parse.quote(folder)}")


@router.get("/apps/{slug}/terminal")
async def terminal_page(request: Request, slug: str):
    from .. import terminal
    a = get_app_or_404(slug)
    return render(request, "terminal.html", title=f"Terminal · {a['name']}", nav="apps", a=a,
                  containers=terminal.containers(slug))


@router.post("/apps/{slug}/terminal/run")
async def terminal_run(request: Request, slug: str):
    from fastapi.responses import JSONResponse
    from .. import terminal
    get_app_or_404(slug)
    f = await request.form()
    try:
        out, rc, cwd = await asyncio.to_thread(terminal.run, slug, f.get("which") or "app", f.get("cmd") or "",
                                               f.get("cwd") or "", f.get("root") == "1", request.session.get("user"))
        return JSONResponse({"out": out, "rc": rc, "cwd": cwd})
    except ValueError as e:
        return JSONResponse({"out": str(e), "rc": -1, "cwd": f.get("cwd") or ""}, status_code=400)


@router.post("/apps/{slug}/node/move")
async def app_move(request: Request, slug: str):
    a = get_app_or_404(slug)
    target = (await request.form()).get("target") or ""
    if a["state"] == "deploying":
        flash(request, "Une opération est en cours sur cette appli.", "error")
    elif target == a["node"] or target not in {c["id"] for c in node_choices()}:
        flash(request, "Choisis un autre nœud, en ligne.", "error")
    else:
        db.update_app(slug, state="deploying")
        P.spawn(move.move, slug, target)
        flash(request, f"Déplacement vers {target} lancé. L'appli reste en ligne pendant la copie, puis est coupée "
                       "quelques secondes ; si la cible ne répond pas, elle redémarre sur son nœud actuel.")
    return go(f"/apps/{slug}")


@router.get("/apps/{slug}/db/export")
async def db_export(request: Request, slug: str):
    a = get_app_or_404(slug)
    if not a["db"]:
        return go(f"/apps/{slug}")
    name = f"{slug}-{time.strftime('%Y%m%d-%H%M')}.sql.gz"
    return StreamingResponse(dbadmin.export_stream(slug), media_type="application/gzip",
                             headers={"Content-Disposition": f'attachment; filename="{name}"'})


IMPORT_DIR = f"{P.BACKUPS}/import-tmp"
IMPORT_MAX = 2 * 1024 ** 3


@router.post("/apps/{slug}/db/import")
async def db_import(request: Request, slug: str):
    a = get_app_or_404(slug)
    f = await request.form()
    up = f.get("file")
    if not a["db"] or a["state"] == "deploying":
        flash(request, "Import impossible pour l'instant.", "error")
        return go(f"/apps/{slug}#base")
    if not _confirmed(f, slug):
        flash(request, f"Tape {slug} pour confirmer l'import : il remplace tout le contenu de la base.", "error")
        return go(f"/apps/{slug}#base")
    if not up or not getattr(up, "filename", ""):
        flash(request, "Choisis un fichier .sql, .sql.gz ou .dump.", "error")
        return go(f"/apps/{slug}#base")
    os.makedirs(IMPORT_DIR, mode=0o700, exist_ok=True)
    path = f"{IMPORT_DIR}/{slug}-{secrets.token_hex(4)}"
    size, head = 0, b""
    with open(path, "wb") as out:
        while chunk := await up.read(1024 * 1024):
            if not head:
                head = chunk[:8]
            size += len(chunk)
            if size > IMPORT_MAX:
                out.close()
                os.remove(path)
                flash(request, "Fichier trop gros (2 Go maximum).", "error")
                return go(f"/apps/{slug}#base")
            out.write(chunk)
    kind = "dump" if head.startswith(b"PGDMP") else "sqlgz" if head.startswith(b"\x1f\x8b") else "sql"
    if kind == "sql" and b"\x00" in head:
        os.remove(path)
        flash(request, "Format non reconnu : attendu un export SQL (.sql, .sql.gz) ou pg_dump -Fc (.dump).", "error")
        return go(f"/apps/{slug}#base")
    db.update_app(slug, state="deploying")
    P.spawn(dbadmin.import_file, slug, path, kind)
    flash(request, f"Import de {up.filename} en cours. Une copie de la base actuelle est faite avant.")
    return go(f"/apps/{slug}")


@router.post("/apps/{slug}/db/reset")
async def db_reset(request: Request, slug: str):
    a = get_app_or_404(slug)
    f = await request.form()
    if not a["db"] or a["state"] == "deploying":
        flash(request, "Remise à zéro impossible pour l'instant.", "error")
    elif not _confirmed(f, slug):
        flash(request, f"Tape {slug} pour confirmer la remise à zéro.", "error")
    else:
        db.update_app(slug, state="deploying")
        P.spawn(dbadmin.reset, slug)
        flash(request, "Remise à zéro en cours. Une copie de la base actuelle est faite avant.")
        return go(f"/apps/{slug}")
    return go(f"/apps/{slug}#base")
