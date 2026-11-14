"""Explorateur du dossier data/ d'une appli (sur sa machine) : parcourir, télécharger, remplacer un fichier, et remettre
un seul fichier depuis une sauvegarde.

- Chemins relatifs à data/ seulement ; « .. » refusé ; un fichier n'est lu ou écrit que si son chemin réel (liens
  suivis) reste dans data/ (un lien vers /etc/shadow du nœud ne sort donc rien).
- Dossiers internes de Hangar (.hangar-mysql, .hangar-redis) : visibles, jamais modifiés.
- Remplacer : l'ancien fichier est d'abord copié sur la console (BACKUPS/avant-remplacement/<appli>-<date>/…),
  le nouveau prend le propriétaire et les droits de l'ancien (ou du dossier).
- Depuis une sauvegarde : « restic dump » du fichier dans l'instantané choisi (data/ de la console, ou miroir des nœuds
  pour une appli distante), puis même chemin que remplacer.
"""
import os
import shlex
import subprocess
import time

from . import db
from . import platform as P

MAX_LIST = 1000
MAX_UPLOAD = 200 * 1024 ** 2
SAFE = f"{P.BACKUPS}/avant-remplacement"


def root(slug):
    return f"{P.app_dir(slug)}/data"


def clean(rel):
    parts = [p for p in (rel or "").replace("\\", "/").split("/") if p not in ("", ".")]
    if any(p == ".." or "\0" in p for p in parts):
        raise ValueError("chemin refusé")
    return "/".join(parts)


def internal(rel):
    return (rel or "").split("/", 1)[0].startswith(".hangar-")


def _node(slug):
    a = db.app(slug)
    if not a:
        raise ValueError("appli inconnue")
    return a["node"]


def _inside(slug, rel, want="f"):
    """Commande shell qui met dans $p le chemin réel de rel s'il est dans data/ (fichier ou dossier), sinon sort 3."""
    r = shlex.quote(root(slug))
    target = shlex.quote(f"{root(slug)}/{rel}" if rel else root(slug))
    test = "-f" if want == "f" else "-d"
    return (f"p=$(realpath -e -- {target} 2>/dev/null) || exit 4; R=$(realpath -e -- {r}) || exit 4; "
            f'case "$p/" in "$R"/*) ;; *) exit 3;; esac; [ {test} "$p" ] || exit 5; ')


def listdir(slug, rel=""):
    """[{name, type ('d'|'f'|'l'), size, mtime}] trié dossiers d'abord ; ValueError si absent ou refusé."""
    rel = clean(rel)
    cmd = _inside(slug, rel, "d") + (f'cd "$p" && find . -mindepth 1 -maxdepth 1 -printf "%y\\t%s\\t%T@\\t%f\\0" '
                                      f"| head -z -n {MAX_LIST + 1}")
    rc, out = P.nsh(_node(slug), cmd, timeout=60)
    if rc:
        raise ValueError({3: "chemin hors de data/", 4: "dossier introuvable", 5: "pas un dossier"}.get(rc, P.tail(out, 2)))
    items = []
    for rec in out.split("\0"):
        parts = rec.split("\t", 3)
        if len(parts) != 4:
            continue
        typ, size, mt, name = parts
        items.append({"name": name, "type": typ if typ in ("d", "f", "l") else "f", "size": int(size or 0),
                      "mtime": float(mt or 0)})
    items.sort(key=lambda x: (x["type"] != "d", x["name"].lower()))
    return items[:MAX_LIST], len(items) > MAX_LIST


def _cmd(slug, shell):
    node = _node(slug)
    if P.is_local(node):
        return ["bash", "-c", shell]
    return ["ssh", "-F", P.NODE_SSH, f"root@{P.node_wg(node)}", shell]


def stream(slug, rel):
    """Générateur du contenu d'un fichier de data/ (ValueError avant le premier octet si refusé)."""
    rel = clean(rel)
    rc, out = P.nsh(_node(slug), _inside(slug, rel, "f") + "true", timeout=30)
    if rc:
        raise ValueError("fichier introuvable ou hors de data/")
    proc = subprocess.Popen(_cmd(slug, _inside(slug, rel, "f") + 'cat -- "$p"'), stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)

    def gen():
        try:
            while True:
                chunk = proc.stdout.read(256 * 1024)
                if not chunk:
                    break
                yield chunk
        finally:
            proc.stdout.close()
            proc.wait(timeout=60)
    return gen()


def _save_previous(slug, rel):
    """Copie l'ancien fichier (s'il existe) sur la console avant de l'écraser. Retourne son chemin, ou None."""
    dest = f"{SAFE}/{slug}-{time.strftime('%Y%m%d-%H%M%S')}/{rel}"
    os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
    try:
        with open(dest, "wb") as f:
            for chunk in stream(slug, rel):
                f.write(chunk)
        os.chmod(dest, 0o600)
        return dest
    except ValueError:
        os.remove(dest)
        return None


def write(slug, rel, src_path):
    """Remplace (ou crée) data/<rel> par le fichier local src_path. Retourne l'emplacement de l'ancienne version."""
    rel = clean(rel)
    if not rel or internal(rel):
        raise ValueError("dossier interne de Hangar : non modifiable ici")
    parent = os.path.dirname(rel)
    rc, out = P.nsh(_node(slug), _inside(slug, parent, "d") + "true", timeout=30)
    if rc:
        raise ValueError("dossier de destination introuvable ou hors de data/")
    prev = _save_previous(slug, rel)
    target = shlex.quote(f"{root(slug)}/{rel}")
    tmp = shlex.quote(f"{root(slug)}/{rel}.hangar-tmp")
    ref = target if prev else shlex.quote(f"{root(slug)}/{parent}" if parent else root(slug))
    # même propriétaire et mêmes droits que l'ancien fichier (ou que le dossier, pour un nouveau fichier)
    shell = (f"set -e; [ ! -L {target} ] || {{ echo 'lien refusé'; exit 6; }}; cat > {tmp}; "
             f"chown --reference={ref} {tmp}; " + (f"chmod --reference={target} {tmp}; " if prev else "chmod 0644 " + tmp + "; ")
             + f"mv -f {tmp} {target}")
    with open(src_path, "rb") as f:
        p = subprocess.run(_cmd(slug, shell), stdin=f, capture_output=True, timeout=1800)
    if p.returncode:
        raise RuntimeError("écriture impossible : " + (p.stdout + p.stderr).decode(errors="replace")[-300:])
    return prev


def restore_file(slug, rel, dest_id="gdrive"):
    """Remet data/<rel> tel qu'il était dans la dernière sauvegarde de cette destination. Retourne (instantané, ancien)."""
    from . import backup
    rel = clean(rel)
    a = db.app(slug)
    d = backup.dest(dest_id)
    if not d:
        raise ValueError("destination de sauvegarde inconnue")
    snaps, err = backup.snapshots(dest_id, wait=True)
    if not snaps:
        raise RuntimeError(err or "aucune sauvegarde sur cette destination")
    snap = snaps[0]
    inside = f"{P.app_dir(slug)}/data/{rel}" if P.is_local(a["node"]) else f"{backup.MIRROR}/{slug}/data/{rel}"
    rc, out, err = backup.restic("ls", "--json", snap["id"], inside, timeout=600, d=d)
    import json
    kinds = [json.loads(line).get("type") for line in out.splitlines()
             if line.startswith("{") and json.loads(line).get("path") == inside]
    if not kinds:
        raise RuntimeError(f"{rel} absent de la dernière sauvegarde de {d['name']}")
    if kinds[0] != "file":
        raise ValueError("seul un fichier peut être remis de cette façon (pour un dossier : Sauvegardes → Restaurer)")
    tmp = f"{P.WORK_TMP}/fichier-{slug}-{time.time_ns()}"
    os.makedirs(P.WORK_TMP, mode=0o700, exist_ok=True)
    try:
        with open(tmp, "wb") as f:
            p = subprocess.run(["restic", "-o", "rclone.program=rclone", "dump", snap["id"], inside], stdout=f,
                               stderr=subprocess.PIPE, timeout=3600, env=backup._env(d))
        if p.returncode:
            raise RuntimeError("fichier absent de la dernière sauvegarde, ou dépôt illisible : "
                               + p.stderr.decode(errors="replace")[-200:])
        prev = write(slug, rel, tmp)
        return snap, prev
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
