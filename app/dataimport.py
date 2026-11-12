"""Import de données dans une appli existante : migration depuis une instance hébergée hors de Hangar, ou reprise
d'une seule appli d'une archive d'un autre serveur, sous un autre identifiant.

Fichier accepté : un .tar.gz qui contient
- format simple (kit de migration) : `db.dump` (pg_dump -Fc, client 17 au plus) et/ou `data/…` ;
- ou une archive Hangar d'une seule appli : `db/<appli>.dump` et/ou `apps/<appli>/data/…` (manifest.json ignoré).
Rien d'autre : pas de lien, pas de chemin absolu ni de « .. ». L'appli cible choisit ce qu'elle reprend (base, data/) ;
son état d'avant est mis de côté dans /srv/backups/avant-restauration, comme pour une restauration.
"""
import json
import os
import re
import shutil
import subprocess
import tarfile
import time

from . import backup, db
from . import platform as P

IMPORTS = os.environ.get("HANGAR_IMPORTS", "/srv/backups/imports")
TMP = os.environ.get("HANGAR_IMPORTS_TMP", "/srv/backups/restore-tmp")
MAX = 20 * 1024 ** 3
NAME_RE = re.compile(r"^import-[0-9]{8}-[0-9]{6}\.tar\.gz$")
SLUG = r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?"


def new_name():
    return f"import-{time.strftime('%Y%m%d-%H%M%S')}.tar.gz"


def path(name):
    if not NAME_RE.match(name or ""):
        return None
    p = f"{IMPORTS}/{name}"
    return p if os.path.exists(p) else None


def info(name):
    p = path(name)
    try:
        return json.load(open(p + ".json")) if p else None
    except (OSError, ValueError):
        return None


def pending():
    if not os.path.isdir(IMPORTS):
        return []
    out = []
    for f in sorted(os.listdir(IMPORTS), reverse=True):
        i = info(f) if NAME_RE.match(f) else None
        if i:
            out.append({**i, "name": f})
    return out


def _norm(name):
    n = name[2:] if name.startswith("./") else name
    return n.rstrip("/")


def inspect(p):
    """Contenu d'un fichier d'import. ValueError si le format n'est pas reconnu ou si un membre est dangereux."""
    dump, data, slugs = None, None, set()
    files = data_size = db_size = 0
    try:
        with tarfile.open(p, "r:gz") as tar:
            for m in tar:
                n = _norm(m.name)
                if n in ("", "."):
                    continue
                if n.startswith("/") or ".." in n.split("/"):
                    raise ValueError(f"chemin refusé dans l'archive : {n[:120]}")
                if not (m.isfile() or m.isdir()):
                    raise ValueError(f"lien ou fichier spécial refusé : {n[:120]} (seuls les fichiers et dossiers sont acceptés)")
                if n == "manifest.json" or n in ("db", "apps") and m.isdir():
                    continue
                mh = re.fullmatch(rf"db/({SLUG})\.dump", n)
                ma = re.fullmatch(rf"apps/({SLUG})(?:/(data)(/.*)?)?", n)
                if n == "db.dump" and m.isfile():
                    dump, db_size = n, m.size
                elif mh and m.isfile():
                    slugs.add(mh.group(1))
                    dump, db_size = n, m.size
                elif n == "data" or n.startswith("data/"):
                    data = "data"
                elif ma and (ma.group(2) or m.isdir()):
                    slugs.add(ma.group(1))
                    if ma.group(2):
                        data = f"apps/{ma.group(1)}/data"
                else:
                    raise ValueError(f"fichier inattendu dans l'archive : {n[:120]} (attendu : db.dump et/ou data/…)")
                if m.isfile() and (n.startswith("data/") or "/data/" in n):
                    files += 1
                    data_size += m.size
    except (tarfile.TarError, OSError, EOFError) as e:
        raise ValueError(f"archive illisible : {e}")
    if len(slugs) > 1:
        raise ValueError(f"cette archive contient plusieurs applis ({', '.join(sorted(slugs))}) : "
                         "utilise « Envoyer une archive pour la restaurer »")
    if data and data.startswith("apps/") and dump == "db.dump" or dump and dump.startswith("db/") and data == "data":
        raise ValueError("archive mêlant les deux formats (db.dump/data et db/…/apps/…)")
    if not dump and not data:
        raise ValueError("ni base (db.dump) ni fichiers (data/) dans cette archive")
    return {"dump": dump, "data": data, "src_slug": next(iter(slugs), ""), "files": files,
            "data_size": data_size, "db_size": db_size}


def check_dump(p, member):
    """Le fichier est-il un export que le PostgreSQL de Hangar sait relire ? Retourne les versions qu'il annonce."""
    work = f"{TMP}/check-{os.getpid()}-{time.time_ns()}"
    os.makedirs(work, mode=0o700)
    try:
        with tarfile.open(p, "r:gz") as tar:
            tar.extract(tar.getmember(member if member in tar.getnames() else "./" + member), work, filter="data")
        f = f"{work}/{_norm(member)}"
        with open(f, "rb") as fh:
            magic = fh.read(5)
        if magic != b"PGDMP":
            raise ValueError("db.dump n'est pas un export PostgreSQL au format personnalisé (pg_dump -Fc)")
        with open(f, "rb") as fh:   # descripteur neuf : la lecture tamponnée ci-dessus a déplacé sa position réelle
            r = subprocess.run(["docker", "exec", "-i", P.PG, "pg_restore", "-l"], stdin=fh, capture_output=True,
                               timeout=600)
        if r.returncode:
            raise ValueError("export refusé par pg_restore 17 : " + P.tail(r.stderr.decode(errors="replace"), 2)
                             + " (refais l'export avec l'image postgres:17)")
        toc = r.stdout.decode(errors="replace")
        ver = lambda k: (re.search(rf";\s+{k}:\s*(.+)", toc) or [None, ""])[1].strip()   # noqa: E731
        return {"pg_from": ver("Dumped from database version"), "pg_dump": ver("Dumped by pg_dump version"),
                "objects": sum(1 for line in toc.splitlines() if line and not line.startswith(";"))}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def receive(part, filename, size):
    """Fichier envoyé (déjà écrit dans `part`) : vérifié, puis rangé avec sa fiche. Retourne son nom."""
    i = inspect(part)
    if i["dump"]:
        i.update(check_dump(part, i["dump"]))
    name = new_name()
    while os.path.exists(f"{IMPORTS}/{name}"):
        time.sleep(1)
        name = new_name()
    i.update(filename=os.path.basename(filename or "")[:120], size=size, ts=time.time())
    fd = os.open(f"{IMPORTS}/{name}.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(i, f)
    os.replace(part, f"{IMPORTS}/{name}")
    P.log("info", "sauvegarde", f"données à importer reçues : {i['filename'] or name} ({backup._h(size)})")
    return name


def remove(name):
    p = path(name)
    if p:
        for f in (p, p + ".json"):
            if os.path.exists(f):
                os.remove(f)


def parts_for(i, a):
    """Ce que l'appli `a` peut reprendre de l'import décrit par `i`."""
    out = []
    if i.get("data"):
        out.append("data")
    if i.get("dump") and a["db"]:
        out.append("db")
    return out


def run(name, slug, parts, prev="ok"):
    """Applique l'import à l'appli (thread de la console). L'appelant a mis l'appli en « deploying »."""
    p, i = path(name), info(name)
    work = f"{TMP}/import-{time.strftime('%Y%m%d-%H%M%S')}"
    started = False
    try:
        if not p or not i:
            raise RuntimeError("fichier d'import introuvable")
        need = (i.get("data_size") or 0) + (i.get("db_size") or 0) + 512 * 1024 ** 2
        os.makedirs(TMP, mode=0o700, exist_ok=True)
        if shutil.disk_usage(TMP).free < need:
            raise RuntimeError(f"place insuffisante sur le serveur ({backup._h(need)} nécessaires)")
        os.makedirs(work, mode=0o700)
        want = [m for m, k in ((i.get("dump"), "db"), (i.get("data"), "data")) if m and k in parts]
        with tarfile.open(p, "r:gz") as tar:
            for m in tar:
                n = _norm(m.name)
                if any(n == w or n.startswith(w + "/") for w in want):
                    m.name = n
                    tar.extract(m, work, filter="data")
        src_dump = f"{work}/{i['dump']}" if i.get("dump") else None
        src_data = f"{work}/{i['data']}" if i.get("data") else None
        if src_data and "data" in parts:
            os.makedirs(src_data, exist_ok=True)   # data/ vide : un dossier sans fichier est un import valide
        label = f"l'import {i.get('filename') or name}"
        P.log("info", slug, f"import de données lancé depuis {i.get('filename') or name} ({', '.join(parts)})")
        with P.op_lock:
            started = True
            backup._apply(db.app(slug), src_data, src_dump, parts, label)
        remove(name)
    except Exception as e:
        P.log("error", slug, f"import de données impossible : {str(e)[:600]}")
        backup.after_failure(slug, started, prev)
    finally:
        shutil.rmtree(work, ignore_errors=True)
