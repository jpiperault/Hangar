"""Sauvegardes, archives, import de données, copies de sécurité."""
import asyncio
import json
import os
import re
import secrets

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from .. import backup, crypt, dataimport, db
from .. import domains as D
from .. import platform as P
from .common import _confirmed, flash, go, render

router = APIRouter()


@router.get("/backups")
async def backups_page(request: Request):
    ds = backup.dests()
    cur = request.query_params.get("d") or (ds[0]["id"] if ds else "")
    if not backup.dest(cur):
        cur = ds[0]["id"] if ds else ""
    snaps, snap_err = (await asyncio.to_thread(backup.snapshots, cur)) if cur else ([], None)
    snap_busy = backup.snapshots_refreshing(cur)
    keep = json.loads(db.settings().get("backup_keep") or "{}")
    nxt = P.run(["systemctl", "show", "platform-backup.timer", "-p", "NextElapseUSecRealtime", "--value"], timeout=10)[1]
    m = re.search(r"(\d{4})-(\d{2})-(\d{2}) (\d{2}:\d{2})", nxt)
    nxt = f"{m.group(3)}/{m.group(2)} à {m.group(4)}" if m else nxt
    busy = backup.running()
    arch_busy = backup.archive_running()
    for d in ds:
        d["last"] = backup.last_ok(d["id"])
    return render(request, "backups.html", title="Sauvegardes", nav="backups", drive_conf=backup.drive_configured(),
                  dests=ds, cur=cur, runs=backup.last_runs(12), last_ok=backup.last_ok(), busy=busy or arch_busy,
                  arch_busy=arch_busy, snaps=snaps, snap_err=snap_err, nas=backup.nas_info(),
                  pending=backup.auth_pending(), google_url=backup._auth.get("google_url"),
                  pw=backup.password() if getattr(request.state, "role", "admin") == "admin" else None, keep=keep, next_run=nxt.strip(), apps=db.apps(), refresh=busy or arch_busy,
                  folder=backup.FOLDER, own_client=backup.client_id(), archives=backup.archives(),
                  snap_busy=snap_busy, restore_tests=backup.restore_tests(), imports=dataimport.pending(), safety=backup.safety_copies(),
                  app_names={a['slug']: a['name'] for a in db.apps()})


@router.post("/backups/public-contact")
async def public_contact(request: Request):
    f = await request.form()
    c = (f.get("contact") or "").strip()
    if c and not re.fullmatch(r"[^@\s<>\"']{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,63}", c):
        flash(request, "Adresse e-mail invalide.", "error")
        return go("/backups#drive")
    db.set_setting("public_contact", c)
    try:
        await asyncio.to_thread(P.apply_routing)
        flash(request, "Contact enregistré sur la page d'accueil et les règles de confidentialité." if c
              else "Contact retiré des pages publiques.")
    except RuntimeError as e:
        flash(request, f"Contact enregistré, mais les pages n'ont pas été republiées : {e}", "error")
    return go("/backups#drive")


@router.post("/backups/password")
async def backup_password(request: Request):
    f = await request.form()
    try:
        backup.set_password(f.get("password") or "")
        flash(request, "Mot de passe enregistré. Connecte maintenant Drive ou le NAS : les sauvegardes existantes seront reprises.")
    except ValueError as e:
        flash(request, str(e), "error")
    return go("/backups")


@router.post("/backups/full-restore")
async def backup_full_restore(request: Request):
    f = await request.form()
    dest_id, snap = f.get("dest") or "", (f.get("snap") or "").strip()
    if not backup.dest(dest_id) or not re.fullmatch(r"[0-9a-f]{8,64}", snap):
        flash(request, "Choisis une sauvegarde.", "error")
    else:
        P.spawn(backup.snapshot_to_archive, dest_id, snap)
        flash(request, "Préparation de la reprise : la sauvegarde est téléchargée puis convertie en archive. "
                       "Elle apparaîtra dans « Archives » (importée) ; ouvre-la pour lancer la restauration.")
    return go("/backups#archives")


@router.post("/backups/nas/connect")
async def nas_connect(request: Request):
    f = await request.form()
    try:
        await asyncio.to_thread(backup.nas_connect, f.get("kind"), (f.get("host") or "").strip(), f.get("port"),
                                (f.get("user") or "").strip(), f.get("password") or "", (f.get("share") or "").strip(),
                                (f.get("path") or "").strip())
        flash(request, "NAS connecté. Les prochaines sauvegardes y seront aussi envoyées.")
    except (ValueError, RuntimeError) as e:
        flash(request, str(e), "error")
    return go("/backups#nas")


@router.post("/backups/nas/disconnect")
async def nas_disconnect(request: Request):
    await asyncio.to_thread(backup.nas_disconnect)
    flash(request, "NAS déconnecté. Les sauvegardes déjà envoyées restent sur le NAS.")
    return go("/backups")


@router.post("/backups/archive/create")
async def archive_create(request: Request):
    if backup.running() or backup.archive_running():
        flash(request, "Une sauvegarde ou une archive est déjà en cours.", "error")
    else:
        try:
            await asyncio.to_thread(backup.start_archive)
            flash(request, "Création de l'archive lancée. Elle apparaîtra dans la liste une fois prête.")
        except RuntimeError as e:
            flash(request, str(e), "error")
    return go("/backups#archives")


@router.get("/backups/archive/{name}/download")
async def archive_download(request: Request, name: str):
    path = backup.archive_path(name)
    if not path:
        return go("/backups#archives")
    backup._ensure_password()
    P.log("info", "sauvegarde", f"archive {name} téléchargée (chiffrée)")
    return StreamingResponse(crypt.encrypt_stream(path, backup.password()), media_type="application/pgp-encrypted",
                             headers={"Content-Disposition": f'attachment; filename="{name}{crypt.SUFFIX}"'})


@router.post("/backups/archive/{name}/delete")
async def archive_delete(request: Request, name: str):
    path = backup.archive_path(name)
    if path:
        os.remove(path)
        P.log("info", "sauvegarde", f"archive {name} supprimée")
        flash(request, f"Archive {name} supprimée.")
    return go("/backups#archives")


ARCHIVE_MAX = 20 * 1024 ** 3


@router.post("/backups/archive/upload")
async def archive_upload(request: Request):
    f = await request.form()
    up = f.get("file")
    if not up or not getattr(up, "filename", ""):
        flash(request, "Choisis une archive .tar.gz créée par Hangar.", "error")
        return go("/backups#archives")
    os.makedirs(backup.ARCHIVES, mode=0o700, exist_ok=True)
    name = backup.save_upload_name()
    part = f"{backup.ARCHIVES}/.{name}.part"
    size = 0
    with open(part, "wb") as out:
        os.chmod(part, 0o600)
        while chunk := await up.read(4 * 1024 * 1024):
            size += len(chunk)
            if size > ARCHIVE_MAX:
                break
            out.write(chunk)
    if size > ARCHIVE_MAX:
        os.remove(part)
        flash(request, "Archive trop grosse (20 Go maximum).", "error")
        return go("/backups#archives")
    try:
        if crypt.is_encrypted(part):   # archive téléchargée (chiffrée) : mot de passe saisi, sinon celui d'ici
            clear = part + ".clair"
            try:
                await asyncio.to_thread(crypt.decrypt_file, part, clear, [f.get("password") or "", backup.password() or ""])
            finally:
                os.remove(part)
            os.replace(clear, part)
        await asyncio.to_thread(backup.read_manifest, part)
    except ValueError as e:
        for x in (part, part + ".clair"):
            if os.path.exists(x):
                os.remove(x)
        flash(request, f"{up.filename} : {e}", "error")
        return go("/backups#archives")
    os.replace(part, f"{backup.ARCHIVES}/{name}")
    P.log("info", "sauvegarde", f"archive {up.filename} importée ({backup.human(size)}) sous le nom {name}")
    return go(f"/backups/archive/{name}")


# ---------------------------------------------------------------- import de données dans une appli existante

@router.post("/backups/import/upload")
async def import_upload(request: Request):
    f = await request.form()
    up = f.get("file")
    if not up or not getattr(up, "filename", ""):
        flash(request, "Choisis un fichier .tar.gz (db.dump et/ou data/).", "error")
        return go("/backups#import")
    os.makedirs(dataimport.IMPORTS, mode=0o700, exist_ok=True)
    part = f"{dataimport.IMPORTS}/.{secrets.token_hex(8)}.part"
    size = 0
    try:
        with open(part, "wb") as out:
            os.chmod(part, 0o600)
            while chunk := await up.read(4 * 1024 * 1024):
                size += len(chunk)
                if size > dataimport.MAX:
                    break
                out.write(chunk)
        if size > dataimport.MAX:
            raise ValueError("fichier trop gros (20 Go maximum)")
        name = await asyncio.to_thread(dataimport.receive, part, up.filename, size)
    except ValueError as e:
        flash(request, f"{up.filename} : {e}", "error")
        return go("/backups#import")
    finally:
        if os.path.exists(part):
            os.remove(part)
    return go(f"/backups/import/{name}")


@router.get("/backups/import/{name}")
async def import_page(request: Request, name: str):
    i = dataimport.info(name)
    if not i:
        return go("/backups#import")
    apps = [{**dict(a), "can": dataimport.parts_for(i, a)} for a in db.apps()]
    return render(request, "import.html", title="Importer des données", nav="backups", iname=name, i=i, apps=apps,
                  pick=request.query_params.get("app") or (i.get("src_slug") if db.app(i.get("src_slug") or "") else ""))


@router.post("/backups/import/{name}/run")
async def import_run(request: Request, name: str):
    i = dataimport.info(name)
    if not i:
        return go("/backups#import")
    f = await request.form()
    slug = (f.get("app") or "").strip()
    a = db.app(slug)
    back = go(f"/backups/import/{name}?app={slug}")
    if not a:
        flash(request, "Choisis l'appli qui reçoit les données.", "error")
        return go(f"/backups/import/{name}")
    if (f.get("confirm") or "").strip().lower() != slug:
        flash(request, f"Tape « {slug} » pour confirmer.", "error")
        return back
    parts = [p for p in dataimport.parts_for(i, a) if f.get(p) == "on"]
    if not parts:
        flash(request, "Coche la base et/ou les fichiers à importer." if dataimport.parts_for(i, a)
              else f"{a['name']} n'a pas de base PostgreSQL : rien à importer de ce fichier.", "error")
        return back
    if a["state"] == "deploying" or backup.running():
        flash(request, f"{a['name']} : une opération ou une sauvegarde est en cours, réessaie plus tard.", "error")
        return back
    prev = a["state"]
    db.update_app(slug, state="deploying")
    P.spawn(dataimport.run, name, slug, parts, prev)
    flash(request, f"Import lancé dans {a['name']} : l'appli est arrêtée quelques instants, puis redémarrée. "
          "Son état d'avant est gardé dans /srv/backups/avant-restauration.")
    return go(f"/apps/{slug}")


@router.post("/backups/safety/{name}/delete")
async def safety_delete(request: Request, name: str):
    c = backup.safety_copy(name)
    if c:
        await asyncio.to_thread(backup.delete_safety, name)
        P.log("info", c["slug"], f"copie de sécurité {name} supprimée")
        flash(request, "Copie de sécurité supprimée.")
    f = await request.form()
    return go(f"/apps/{c['slug']}#securite" if c and f.get("back") == "app" else "/backups#securite")


@router.post("/backups/import/{name}/delete")
async def import_delete(request: Request, name: str):
    if dataimport.info(name):
        dataimport.remove(name)
        flash(request, "Fichier d'import supprimé.")
    return go("/backups#import")


@router.get("/backups/archive/{name}")
async def archive_page(request: Request, name: str):
    path = backup.archive_path(name)
    if not path:
        return go("/backups#archives")
    try:
        man = await asyncio.to_thread(backup.read_manifest, path)
    except ValueError as e:
        flash(request, str(e), "error")
        return go("/backups#archives")
    return render(request, "archive.html", title="Restaurer une archive", nav="backups", aname=name, man=man, s_domains=[d["name"] for d in D.all_domains()],
                  size=os.path.getsize(path))


@router.post("/backups/archive/{name}/restore")
async def archive_restore(request: Request, name: str):
    path = backup.archive_path(name)
    if not path:
        return go("/backups#archives")
    f = await request.form()
    if (f.get("confirm") or "").strip().lower() != "restaurer":
        flash(request, "Tape « restaurer » pour confirmer.", "error")
        return go(f"/backups/archive/{name}")
    man = await asyncio.to_thread(backup.read_manifest, path)
    choices = {}
    for a in man["apps"]:
        slug = a["slug"]
        if f.get(f"app_{slug}") != "on":
            continue
        cur = db.app(slug)
        if cur and cur["state"] == "deploying":
            flash(request, f"{slug} : une opération est en cours, réessaie plus tard.", "error")
            return go(f"/backups/archive/{name}")
        parts = [p for p in ("data", "db") if f.get(f"{p}_{slug}") == "on" and a.get(f"has_{p}")]
        if cur and not parts:
            continue
        choices[slug] = parts
    with_settings = f.get("settings") == "on" and man.get("settings")
    if not choices and not with_settings:
        flash(request, "Coche au moins une appli et ce qu'il faut restaurer.", "error")
        return go(f"/backups/archive/{name}")
    if with_settings:
        try:
            await asyncio.to_thread(backup.apply_settings, man["settings"])
        except RuntimeError as e:
            flash(request, f"Réglages non repris : {e}", "error")
            return go(f"/backups/archive/{name}")
    if not choices:
        flash(request, "Domaines repris de l'archive.")
        return go("/domains")
    for slug in choices:
        if db.app(slug):
            db.update_app(slug, state="deploying")
    backup.start_archive_restore(name, choices)
    flash(request, f"Restauration lancée pour {', '.join(choices)}. Suis l'avancement dans la liste des applis.")
    return go("/")


@router.post("/backups/drive/start")
async def drive_start(request: Request):
    f = await request.form()
    cid, csec = (f.get("client_id") or "").strip(), (f.get("client_secret") or "").strip()
    if cid and not re.fullmatch(r"[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com", cid):
        flash(request, "Client ID invalide : il se termine par .apps.googleusercontent.com", "error")
        return go("/backups#drive")
    if cid and not re.fullmatch(r"[A-Za-z0-9_-]{10,100}", csec):
        flash(request, "Indique aussi le code secret du client (Client secret).", "error")
        return go("/backups#drive")
    try:
        url = await asyncio.to_thread(backup.auth_start, cid, csec)
        backup._auth["google_url"] = url
    except RuntimeError as e:
        flash(request, str(e), "error")
    return go("/backups#drive")


@router.post("/backups/drive/finish")
async def drive_finish(request: Request):
    f = await request.form()
    try:
        await asyncio.to_thread(backup.auth_finish, f.get("url") or "")
        flash(request, "Google Drive connecté. Note le mot de passe des sauvegardes ci-dessous, puis lance une première sauvegarde.")
    except (ValueError, RuntimeError) as e:
        flash(request, str(e), "error")
    return go("/backups#drive")


@router.post("/backups/drive/cancel")
async def drive_cancel(request: Request):
    backup.auth_cancel()
    return go("/backups")


@router.post("/backups/drive/disconnect")
async def drive_disconnect(request: Request):
    await asyncio.to_thread(backup.disconnect)
    flash(request, "Google Drive déconnecté. Les sauvegardes déjà envoyées restent dans ton Drive.")
    return go("/backups")


@router.post("/backups/verify")
async def backup_verify(request: Request):
    if backup.running():
        flash(request, "Une sauvegarde ou un test est déjà en cours.", "error")
    else:
        try:
            await asyncio.to_thread(backup.start_verify)
            flash(request, "Test de restauration lancé : résultat dans une à quelques minutes.")
        except RuntimeError as e:
            flash(request, str(e), "error")
    return go("/backups#verif")


@router.post("/backups/run")
async def backup_run(request: Request):
    if backup.running():
        flash(request, "Une sauvegarde est déjà en cours.", "error")
    else:
        try:
            await asyncio.to_thread(backup.start_now)
            flash(request, "Sauvegarde lancée. Cette page se met à jour toute seule.")
        except RuntimeError as e:
            flash(request, str(e), "error")
    return go("/backups")


@router.post("/backups/keep")
async def backup_keep(request: Request):
    f = await request.form()
    try:
        keep = {k: int(f.get(k)) for k in ("daily", "weekly", "monthly")}
        if not all(0 <= v <= 365 for v in keep.values()) or not any(keep.values()):
            raise ValueError
    except (TypeError, ValueError):
        flash(request, "Indique des nombres entre 0 et 365, dont au moins un non nul.", "error")
        return go("/backups")
    db.set_setting("backup_keep", keep)
    flash(request, "Rétention enregistrée. Elle s'applique à la prochaine sauvegarde.")
    return go("/backups")


@router.post("/backups/restore")
async def backup_restore(request: Request):
    f = await request.form()
    slug, snap, dest_id = f.get("slug") or "", (f.get("snap") or "").strip(), f.get("dest") or ""
    parts = [p for p in ("data", "db") if f.get(p) == "on"]
    a = db.app(slug)
    if not backup.dest(dest_id):
        flash(request, "Destination inconnue.", "error")
    elif not a or not re.fullmatch(r"[0-9a-f]{8,64}", snap):
        flash(request, "Choisis une appli et une sauvegarde.", "error")
    elif not parts:
        flash(request, "Coche au moins « fichiers » ou « base ».", "error")
    elif "db" in parts and not a["db"]:
        flash(request, f"{a['name']} n'a pas de base.", "error")
    elif not _confirmed(f, slug):
        flash(request, f"Tape {slug} pour confirmer la restauration.", "error")
    elif a["state"] == "deploying":
        flash(request, "Une opération est déjà en cours sur cette appli.", "error")
    else:
        db.update_app(slug, state="deploying")
        P.spawn(backup.restore_app, slug, dest_id, snap, parts)
        flash(request, f"Restauration de {a['name']} en cours. L'état actuel est mis de côté avant d'être remplacé.")
        return go(f"/apps/{slug}")
    return go("/backups#restaurer")
