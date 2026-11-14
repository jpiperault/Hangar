"""Commandes dans le conteneur d'une appli (ou de son Redis, de sa base MySQL/MariaDB), depuis la console.

Une commande à la fois (pas de programme plein écran) : « docker exec » sur sa machine, avec sh, 60 s au plus,
256 Ko de sortie au plus. Le dossier courant est gardé d'une commande à l'autre (« cd » marche). Chaque commande est
notée au journal de l'appli. Réservé aux administrateurs (le contrôle d'accès de la console refuse les autres).
"""
import re

from . import db
from . import platform as P

TIMEOUT = 60
MAX_OUT = 256 * 1024
MARK = "@@HANGAR-PWD@@"   # pas de caractère de contrôle : la sortie est nettoyée de ses blancs
CWD_RE = re.compile(r"^/[^\x00\n]{0,500}$")


def containers(slug):
    from . import services
    out = [("app", f"app-{slug}-app-1", "l'appli")]
    if services.redis(slug):
        out.append(("redis", f"app-{slug}-redis-1", "Redis"))
    if services.mysql(slug):
        out.append(("mysql", f"app-{slug}-mysql-1", "MySQL / MariaDB"))
    return out


def run(slug, which, command, cwd="", as_root=False, user=None):
    """(sortie, code de sortie, nouveau dossier courant)."""
    a = db.app(slug)
    if not a:
        raise ValueError("appli inconnue")
    command = (command or "").strip()
    if not command:
        raise ValueError("commande vide")
    if len(command) > 4000 or "\x00" in command:
        raise ValueError("commande trop longue")
    name = dict((k, c) for k, c, _ in containers(slug)).get(which)
    if not name:
        raise ValueError("conteneur inconnu")
    cwd = cwd if CWD_RE.match(cwd or "") else ""
    # erreurs dans la même sortie, dans l'ordre ; le dossier courant à la toute fin
    script = ('[ -n "$1" ] && cd "$1" 2>/dev/null; exec 2>&1; ' + command + '\nrc=$?; printf "\\n' + MARK + '%s" "$PWD"; exit $rc')
    args = ["exec", "-i"] + (["-u", "0"] if as_root else []) + [name, "timeout", str(TIMEOUT), "sh", "-c", script, "sh", cwd]
    rc, out = P.dk(a["node"], *args, timeout=TIMEOUT + 15)
    new_cwd = cwd
    if MARK in out:
        out, _, tail = out.rpartition(MARK)
        new_cwd = tail.strip() if CWD_RE.match(tail.strip()) else cwd
        out = out[:-1] if out.endswith("\n") else out
    elif "timeout" in out and "not found" in out:   # image sans « timeout » : on relance sans lui
        args = ["exec", "-i"] + (["-u", "0"] if as_root else []) + [name, "sh", "-c", script, "sh", cwd]
        rc, out = P.dk(a["node"], *args, timeout=TIMEOUT + 15)
        if MARK in out:
            out, _, tail = out.rpartition(MARK)
            new_cwd = tail.strip() if CWD_RE.match(tail.strip()) else cwd
    if rc in (124, 143) and not out.strip():   # « timeout » de coreutils (124) ou de busybox (143, SIGTERM)
        out = f"[arrêtée au bout de {TIMEOUT} s]"
    elif rc in (124, 143):
        out += f"\n[arrêtée au bout de {TIMEOUT} s]"
    if len(out) > MAX_OUT:
        out = out[:MAX_OUT] + "\n[sortie tronquée]"
    P.log("info", slug, f"commande dans {which}{' (root)' if as_root else ''} par {user or '?'} : "
          f"{' '.join(command.split())[:200]} (code {rc})")
    return out, rc, new_cwd

