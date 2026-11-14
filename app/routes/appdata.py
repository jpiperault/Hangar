"""Versions, déplacement et base de données d'une appli."""
import asyncio
import os
import secrets
import time

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from .. import db, dbadmin, monitor, move
from .. import platform as P
from .common import _confirmed, flash, get_app_or_404, go, node_choices

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


IMPORT_DIR = "/srv/backups/import-tmp"
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
