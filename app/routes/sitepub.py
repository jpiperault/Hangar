"""Sites statiques : publication (zip, dépôt Git), versions, réglages."""
import asyncio
import os
import secrets
import zipfile

from fastapi import APIRouter, Request

from .. import kinds, sites
from .. import platform as P
from .common import flash, get_app_or_404, go

router = APIRouter()


@router.post("/apps/{slug}/site/upload")
async def site_upload(request: Request, slug: str):
    a = get_app_or_404(slug)
    if not kinds.static(a["kind"]):
        return go(f"/apps/{slug}")
    f = await request.form()
    up = f.get("file")
    if not up or not getattr(up, "filename", ""):
        flash(request, "Choisis le zip du dossier construit.", "error")
        return go(f"/apps/{slug}#site")
    os.makedirs("/srv/backups/restore-tmp", mode=0o700, exist_ok=True)
    part = f"/srv/backups/restore-tmp/site-{slug}-{secrets.token_hex(6)}.zip"
    size = 0
    try:
        with open(part, "wb") as out:
            while chunk := await up.read(4 * 1024 * 1024):
                size += len(chunk)
                if size > sites.MAX_ZIP:
                    raise ValueError("zip trop gros (200 Mo au plus)")
                out.write(chunk)
        n = await asyncio.to_thread(sites.publish_zip, slug, part, os.path.basename(up.filename)[:80])
        flash(request, f"Version #{n} en ligne.")
    except (ValueError, OSError, zipfile.BadZipFile) as e:
        P.log("error", slug, f"publication refusée : {e}")
        flash(request, f"Publication refusée : {e}", "error")
    finally:
        if os.path.exists(part):
            os.remove(part)
    return go(f"/apps/{slug}#site")


@router.post("/apps/{slug}/site/git")
async def site_git(request: Request, slug: str):
    a = get_app_or_404(slug)
    if not kinds.static(a["kind"]):
        return go(f"/apps/{slug}")
    f = await request.form()
    try:
        sites.save_git(slug, f)
    except ValueError as e:
        flash(request, str(e), "error")
        return go(f"/apps/{slug}#site")
    if sites.busy(slug):
        flash(request, "Une construction est déjà en cours.", "error")
    else:
        P.spawn(sites.build_git, slug)
        flash(request, "Construction lancée : clonage, build dans un conteneur jetable, puis publication.")
    return go(f"/apps/{slug}#site")


@router.post("/apps/{slug}/site/activate/{n}")
async def site_activate(request: Request, slug: str, n: int):
    get_app_or_404(slug)
    try:
        await asyncio.to_thread(sites.activate, slug, n)
        flash(request, f"Version #{n} remise en ligne.")
    except ValueError as e:
        flash(request, str(e), "error")
    return go(f"/apps/{slug}#site")


@router.post("/apps/{slug}/site/settings")
async def site_settings(request: Request, slug: str):
    get_app_or_404(slug)
    f = await request.form()
    sites.set_spa(slug, f.get("spa") == "on")
    await asyncio.to_thread(P.apply_routing)
    flash(request, "Réglages du site enregistrés.")
    return go(f"/apps/{slug}#site")
