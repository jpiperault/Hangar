"""Sites statiques : pas de conteneur, Caddy sert directement des fichiers.

- Chaque version publiée est gardée sur la console : /srv/apps/<appli>/site/releases/<n>/ (les 10 dernières, dans
  les sauvegardes avec /srv/apps).
- La version en ligne est copiée dans /srv/platform/sites/<appli>/, servi par Caddy, et envoyée aux nœuds qui
  reçoivent le trafic (même chemin) ; revenir à une version = la recopier.
- Publication : un zip (dossier construit), ou un dépôt Git construit dans un conteneur jetable (image et commande
  au choix), dont on garde le dossier produit.
Réglage kv « static_sites » : {slug: {current, next, spa, releases: [{n, ts, source, size, files}], git: {...}}}.
"""
import os
import re
import shutil
import threading
import time
import zipfile

from . import db
from . import platform as P

SITES = "/srv/platform/sites"
KEEP = 10
MAX_ZIP = 200 * 1024 ** 2
MAX_FILES_BYTES = 500 * 1024 ** 2
BUILD_IMAGE = "node:22-alpine"
_busy = set()
_lock = threading.Lock()


def releases_dir(slug):
    return f"{P.app_dir(slug)}/site/releases"


def meta(slug):
    m = (db.kv_get("static_sites") or {}).get(slug) or {}
    return {"current": None, "next": 1, "spa": True, "releases": [], "git": {}, **m}


def _save(slug, m):
    with _lock:
        allm = db.kv_get("static_sites") or {}
        allm[slug] = m
        db.kv_set("static_sites", allm)


def busy(slug):
    return slug in _busy


def _dsize(d):
    n = files = 0
    for root, _dirs, fs in os.walk(d):
        for f in fs:
            files += 1
            try:
                n += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
    return n, files


def _check_tree(d):
    """Arborescence publiable : pas de lien, index.html à la racine, taille raisonnable. ValueError sinon."""
    for root, dirs, fs in os.walk(d):
        for x in dirs + fs:
            if os.path.islink(os.path.join(root, x)):
                raise ValueError(f"lien refusé dans le site : {os.path.relpath(os.path.join(root, x), d)}")
    if not os.path.isfile(os.path.join(d, "index.html")):
        raise ValueError("pas de index.html à la racine du site")
    size, files = _dsize(d)
    if size > MAX_FILES_BYTES:
        raise ValueError("site trop gros (500 Mo au plus)")
    return size, files


def extract_zip(path, dest):
    """Zip → dossier, sans chemin absolu, « .. », ni lien ; un seul dossier en tête est pris comme racine."""
    os.makedirs(dest, mode=0o755)
    total = 0
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            name = info.filename
            if name.startswith("/") or ".." in name.split("/") or "\\" in name:
                raise ValueError(f"chemin refusé dans le zip : {name[:100]}")
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError(f"lien refusé dans le zip : {name[:100]}")
            total += info.file_size
            if total > MAX_FILES_BYTES:
                raise ValueError("contenu du zip trop gros (500 Mo au plus une fois décompressé)")
        z.extractall(dest)
    entries = [e for e in os.listdir(dest) if e not in ("__MACOSX", ".DS_Store")]
    if len(entries) == 1 and os.path.isdir(os.path.join(dest, entries[0])) and \
            not os.path.isfile(os.path.join(dest, "index.html")):
        return os.path.join(dest, entries[0])
    return dest


def _new_release(slug, src, source):
    """Copie un dossier prêt comme nouvelle version (pas encore en ligne). Retourne son numéro."""
    size, files = _check_tree(src)
    m = meta(slug)
    n = m["next"]
    dest = f"{releases_dir(slug)}/{n}"
    os.makedirs(os.path.dirname(dest), mode=0o755, exist_ok=True)
    shutil.copytree(src, dest)
    for root, dirs, fs in os.walk(dest):      # lisibles par Caddy
        os.chmod(root, 0o755)
        for f in fs:
            os.chmod(os.path.join(root, f), 0o644)
    m["releases"] = [{"n": n, "ts": time.time(), "source": source[:200], "size": size, "files": files}] + m["releases"]
    m["next"] = n + 1
    for old in m["releases"][KEEP:]:
        if old["n"] != m["current"]:
            shutil.rmtree(f"{releases_dir(slug)}/{old['n']}", ignore_errors=True)
    m["releases"] = m["releases"][:KEEP] + [r for r in m["releases"][KEEP:] if r["n"] == m["current"]]
    _save(slug, m)
    return n


def _sync_nodes(slug):
    """Copie le dossier servi vers les nœuds qui reçoivent le trafic (erreurs journalisées, sans bloquer)."""
    src = f"{SITES}/{slug}"
    for n in P.ingress_nodes():
        try:
            P.nsh(n["id"], f"install -d -m 0755 {SITES}", timeout=30)
            P.push_dir(n["id"], src, src)
        except Exception as e:
            P.log("warn", slug, f"site non copié sur le nœud {n['id']} : {e}")


def activate(slug, n):
    """Met la version n en ligne (copie atomique dans le dossier servi, puis nœuds, puis routes)."""
    m = meta(slug)
    if not any(r["n"] == n for r in m["releases"]):
        raise ValueError("version inconnue")
    src = f"{releases_dir(slug)}/{n}"
    live, tmp = f"{SITES}/{slug}", f"{SITES}/.{slug}.new"
    os.makedirs(SITES, mode=0o755, exist_ok=True)
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.copytree(src, tmp)
    old = f"{SITES}/.{slug}.old"
    shutil.rmtree(old, ignore_errors=True)
    if os.path.exists(live):
        os.rename(live, old)
    os.rename(tmp, live)
    shutil.rmtree(old, ignore_errors=True)
    first = m["current"] is None
    m["current"] = n
    _save(slug, m)
    db.update_app(slug, version=f"#{n}", state="ok", desired="running", deployed_at=time.time())
    _sync_nodes(slug)
    if first:
        P.apply_routing()
    P.log("ok", slug, f"version #{n} du site en ligne")


def publish_zip(slug, path, label):
    work = f"{P.WORK_TMP}/site-{slug}-{time.time_ns()}"
    try:
        root = extract_zip(path, work)
        n = _new_release(slug, root, f"zip · {label}")
        activate(slug, n)
        return n
    finally:
        shutil.rmtree(work, ignore_errors=True)


GIT_RE = re.compile(r"^(https://[A-Za-z0-9.-]+/[A-Za-z0-9._/-]+?)(\.git)?$")
BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,100}$")
DIR_RE = re.compile(r"^[A-Za-z0-9._-][A-Za-z0-9._/-]{0,100}$")
IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9._-]+)?$")


def save_git(slug, f):
    g = {"repo": (f.get("repo") or "").strip(), "branch": (f.get("branch") or "main").strip(),
         "cmd": (f.get("cmd") or "").strip()[:500], "out": (f.get("out") or "dist").strip().strip("/"),
         "image": (f.get("image") or BUILD_IMAGE).strip()}
    if not GIT_RE.match(g["repo"]):
        raise ValueError("dépôt : une adresse https://…, par exemple https://github.com/moi/site")
    if not BRANCH_RE.match(g["branch"]):
        raise ValueError("branche invalide")
    g["out"] = g["out"] or "."
    if g["out"] != "." and (not DIR_RE.match(g["out"]) or ".." in g["out"].split("/")):
        raise ValueError("dossier produit invalide")
    if not IMAGE_RE.match(g["image"]):
        raise ValueError("image de build invalide")
    m = meta(slug)
    m["git"] = g
    _save(slug, m)
    return g


def build_git(slug):
    """Thread : clone, build dans un conteneur jetable, publie le dossier produit. Journalise le résultat."""
    if slug in _busy:
        return
    _busy.add(slug)
    g = meta(slug)["git"]
    work = f"{P.WORK_TMP}/build-{slug}-{time.time_ns()}"
    try:
        os.makedirs(work, mode=0o755)
        P.log("info", slug, f"construction du site depuis {g['repo']} ({g['branch']})")
        rc, out = P.run(["git", "clone", "--depth", "1", "--branch", g["branch"], g["repo"], f"{work}/src"], timeout=600)
        if rc:
            raise RuntimeError("clonage impossible : " + P.tail(out, 2))
        rc, sha = P.run(["git", "-C", f"{work}/src", "rev-parse", "--short", "HEAD"], timeout=30)
        if g["cmd"]:
            rc, out = P.run(["docker", "pull", "-q", g["image"]], timeout=900)   # à part : le journal du build reste lisible
            if rc and P.run(["docker", "image", "inspect", g["image"]], timeout=30)[0]:
                raise RuntimeError(f"image de build {g['image']} introuvable : " + P.tail(out, 2))
            cpus = str(min(2, os.cpu_count() or 1))   # Docker refuse plus de cœurs que la machine n'en a
            rc, out = P.run(["docker", "run", "--rm", "--memory", "1g", "--cpus", cpus, "--pids-limit", "512",
                             "--security-opt", "no-new-privileges", "-v", f"{work}/src:/src", "-w", "/src",
                             "-e", "CI=1", g["image"], "sh", "-c", g["cmd"]], timeout=1800)
            if rc:
                raise RuntimeError("build en échec : " + P.tail(out, 6))
        src = os.path.realpath(f"{work}/src")
        outdir = src if g["out"] == "." else os.path.realpath(f"{work}/src/{g['out']}")
        if not (outdir == src or outdir.startswith(src + "/")) or not os.path.isdir(outdir):
            raise RuntimeError(f"dossier produit « {g['out']} » introuvable après le build")
        shutil.rmtree(os.path.join(outdir, ".git"), ignore_errors=True)   # jamais publié
        n = _new_release(slug, outdir, f"git · {g['branch']}@{sha.strip()}")
        activate(slug, n)
    except Exception as e:
        P.log("error", slug, f"publication du site impossible : {str(e)[:800]}")
        from . import alerts
        a = db.app(slug)
        alerts.send(f"{a['name'] if a else slug} : publication du site en échec", str(e)[:400], priority=4, tags=["warning"])
    finally:
        shutil.rmtree(work, ignore_errors=True)
        _busy.discard(slug)


def set_spa(slug, on):
    m = meta(slug)
    m["spa"] = bool(on)
    _save(slug, m)


def remove(slug):
    shutil.rmtree(f"{SITES}/{slug}", ignore_errors=True)
    allm = db.kv_get("static_sites") or {}
    allm.pop(slug, None)
    db.kv_set("static_sites", allm)
    for n in P.ingress_nodes():
        P.nsh(n["id"], f"rm -rf {SITES}/{slug}", timeout=60)


def healthy(slug):
    return os.path.isfile(f"{SITES}/{slug}/index.html")


def caddy_lines(a, ind):
    """Bloc Caddy qui sert le site (dans un bloc de site ou un handle_path)."""
    slug = a["slug"]
    if P.maintenance(slug):
        return P._maint_lines(a, ind)
    if a["desired"] == "stopped" or not meta(slug)["current"]:
        return [f'{ind}respond "Site pas encore publié" 503'] if not meta(slug)["current"] else [f'{ind}respond "Service arrêté" 503']
    L = [f"{ind}root * {SITES}/{slug}",
         f"{ind}@hashed path_regexp [.-][0-9a-zA-Z_-]{{8,}}\\.(js|mjs|css|woff2?|png|jpe?g|webp|avif|svg|gif|ico)$",
         f'{ind}header @hashed Cache-Control "public, max-age=31536000, immutable"',
         f'{ind}header /index.html Cache-Control "no-cache"']
    if meta(slug)["spa"]:
        L.append(f"{ind}try_files {{path}} {{path}}/ /index.html")
    L.append(f"{ind}file_server")
    return L
