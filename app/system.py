"""Mises à jour des composants système, avec retour à la version précédente si le service ne repart pas.

Les mises à jour tournent dans une unité systemd transitoire (`hangar sysupdate <composant>`) :
mettre Docker à jour redémarre aussi la console (dépendance systemd), l'opération doit lui survivre.
"""
import os
import re
import subprocess
import time

from . import alerts, db, registry
from . import platform as P

COMPONENTS = {
    "debian": {"name": "Paquets Debian", "pkgs": None,
               "note": "Système et bibliothèques. Les correctifs de sécurité s'installent déjà seuls chaque nuit."},
    "docker": {"name": "Docker", "pkgs": ["docker-ce", "docker-ce-cli", "containerd.io", "docker-compose-plugin",
                                          "docker-buildx-plugin"],
               "note": "Le démon redémarre ; les conteneurs continuent de tourner (live-restore). La console redémarre."},
    "caddy": {"name": "Caddy", "pkgs": ["caddy"], "note": "Coupure de moins d'une seconde."},
    "cloudflared": {"name": "cloudflared", "pkgs": ["cloudflared"], "note": "Le tunnel se reconnecte en quelques secondes."},
    "postgres": {"name": "PostgreSQL", "pkgs": None,
                 "note": "Mise à jour mineure de l'image (même version majeure). Bases indisponibles une dizaine de secondes ; "
                         "un dump complet est fait avant."},
}
PG_IMAGE = "postgres:17"
APT_ENV = {**os.environ, "DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "a"}
APT_OPTS = ["-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"]


def _apt(*args, timeout=1800):
    p = subprocess.run(["apt-get", "-q", "-y", *APT_OPTS, *args], capture_output=True, text=True, env=APT_ENV,
                       timeout=timeout)
    return p.returncode, (p.stdout + p.stderr).strip()


def installed(pkg):
    rc, out = P.run(["dpkg-query", "-W", "-f", "${Version}", pkg], timeout=20)
    return out.strip() if rc == 0 else None


def _upgradable():
    rc, out = P.run(["apt", "list", "--upgradable"], timeout=120)
    res = {}
    for line in out.splitlines():
        m = re.match(r"^([^/\s]+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from: ([^\]]+)\]", line)
        if m:
            res[m.group(1)] = {"new": m.group(2), "old": m.group(3)}
    return res


def _pg_local_digest():
    rc, out = P.run(["docker", "image", "inspect", PG_IMAGE, "--format", "{{join .RepoDigests \" \"}}"], timeout=20)
    m = re.search(r"@(sha256:[0-9a-f]+)", out)
    return m.group(1) if rc == 0 and m else None


def _pg_version():
    rc, out = P.run(["docker", "exec", P.PG, "postgres", "--version"], timeout=20)
    m = re.search(r"(\d+\.\d+)", out)
    return m.group(1) if m else "?"


def check(refresh_apt=True):
    """Recense les mises à jour disponibles. Résultat gardé dans kv 'sys_check'."""
    if refresh_apt:
        _apt("update", timeout=600)
    up = _upgradable()
    comps = {}
    owned = set()
    for cid, c in COMPONENTS.items():
        if c["pkgs"]:
            owned.update(c["pkgs"])
            pk = [p for p in c["pkgs"] if installed(p)]
            main = pk[0] if pk else c["pkgs"][0]
            ups = {p: up[p] for p in pk if p in up}
            comps[cid] = {"current": installed(main) or "absent",
                          "available": ups[main]["new"] if main in ups else (next(iter(ups.values()))["new"] if ups else None),
                          "packages": sorted(ups)}
    deb = sorted(p for p in up if p not in owned)
    comps["debian"] = {"current": open("/etc/debian_version").read().strip(),
                       "available": f"{len(deb)} paquet{'s' if len(deb) > 1 else ''}" if deb else None, "packages": deb}
    pg = {"current": _pg_version(), "available": None, "packages": []}
    try:
        remote, local = registry.digest("postgres", "17"), _pg_local_digest()
        if remote and local and remote != local:
            pg["available"] = "nouvelle image 17.x"
    except Exception as e:
        pg["error"] = str(e)[:200]
    comps["postgres"] = pg
    res = {"ts": time.time(), "components": comps, "reboot": os.path.exists("/var/run/reboot-required"),
           "hangar": hangar_status()}
    db.kv_set("sys_check", res)
    return res


def hangar_status():
    rc, _ = P.run(["git", "-C", "/opt/hangar", "fetch", "-q", "origin"], timeout=60)
    rc2, out = P.run(["git", "-C", "/opt/hangar", "rev-list", "--left-right", "--count", "HEAD...origin/main"], timeout=20)
    rc3, head = P.run(["git", "-C", "/opt/hangar", "log", "-1", "--format=%h %cs"], timeout=20)
    rc4, dirty = P.run(["git", "-C", "/opt/hangar", "status", "--porcelain"], timeout=20)
    try:
        ahead, behind = (int(x) for x in out.split())
    except ValueError:
        ahead = behind = None
    return {"head": head.strip(), "ahead": ahead, "behind": behind, "dirty": bool(dirty.strip()), "fetch_ok": rc == 0}


# ---------------------------------------------------------------- mise à jour (unité transitoire)

def unit(cid):
    return f"hangar-maj-{cid}"


def running(cid=None):
    ids = [cid] if cid else list(COMPONENTS)
    for c in ids:
        rc, out = P.run(["systemctl", "is-active", unit(c)], timeout=10)
        if out.strip() in ("active", "activating"):
            return c
    return None


def launch(cid):
    if cid not in COMPONENTS:
        raise ValueError("composant inconnu")
    busy = running()
    if busy:
        raise RuntimeError(f"Une mise à jour est déjà en cours ({COMPONENTS[busy]['name']}).")
    if cid == "docker" and db.one("SELECT 1 FROM apps WHERE state = 'deploying'"):
        raise RuntimeError("Un déploiement est en cours : attends qu'il se termine.")
    P.run(["systemctl", "reset-failed", unit(cid)], timeout=10)
    rc, out = P.run(["systemd-run", f"--unit={unit(cid)}", "--collect", "--quiet",
                     "--property=EnvironmentFile=/srv/platform/.env", "--working-directory=/opt/hangar",
                     "/opt/hangar/venv/bin/python", "-m", "app", "sysupdate", cid], timeout=30)
    if rc:
        raise RuntimeError("Lancement impossible : " + P.tail(out))


def _wait(fn, seconds):
    end = time.time() + seconds
    while time.time() < end:
        if fn():
            return True
        time.sleep(2)
    return False


def _active(svc):
    return P.run(["systemctl", "is-active", svc], timeout=10)[1].strip() == "active"


def _verify(cid, since):
    if cid == "caddy":
        ok = _wait(lambda: _active("caddy") and P.run(["curl", "-sf", "-o", "/dev/null", "http://localhost:2019/config/"],
                                                     timeout=10)[0] == 0, 30)
        return ok, "Caddy ne répond plus"
    if cid == "cloudflared":
        ok, err = P._tunnel_connected(since, wait=40)
        return ok, f"le tunnel ne se reconnecte pas ({err})"
    if cid == "docker":
        def apps_up():
            if P.run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=20)[0]:
                return False
            states = P.container_states()
            want = [a["slug"] for a in db.apps() if a["desired"] == "running"]
            pg = P.run(["docker", "inspect", "-f", "{{.State.Running}}", P.PG], timeout=10)[1].strip() == "true"
            return pg and all(states.get(w, ("",))[0] == "running" for w in want)
        return _wait(apps_up, 120), "Docker ou les conteneurs ne sont pas repartis"
    return True, ""


def _pg_ready():
    return P.run(["docker", "exec", P.PG, "pg_isready", "-U", "platform"], timeout=10)[0] == 0


def run_update(cid):
    """Exécutée par l'unité transitoire. Journalise sous l'appli « système »."""
    c = COMPONENTS[cid]
    name = c["name"]
    P.log("info", "système", f"mise à jour de {name} lancée")
    since = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 1))
    try:
        if cid == "postgres":
            from . import backup
            backup._dump_all_local()
            rc, old_id = P.run(["docker", "image", "inspect", PG_IMAGE, "--format", "{{.Id}}"], timeout=20)
            old_v = _pg_version()
            rc, out = P.run(["docker", "compose", "pull", "--quiet"], cwd=P.PLATFORM, timeout=900)
            if rc:
                raise RuntimeError("téléchargement de l'image impossible : " + P.tail(out))
            P.run(["docker", "compose", "up", "-d"], cwd=P.PLATFORM, timeout=300)
            if not _wait(_pg_ready, 90):
                P.log("error", "système", "PostgreSQL ne redémarre pas avec la nouvelle image : retour à l'ancienne")
                P.run(["docker", "tag", old_id.strip(), PG_IMAGE], timeout=30)
                P.run(["docker", "compose", "up", "-d"], cwd=P.PLATFORM, timeout=300)
                ok = _wait(_pg_ready, 90)
                raise RuntimeError("nouvelle image refusée, ancienne remise " + ("(PostgreSQL en ligne)" if ok else "MAIS PostgreSQL ne répond pas"))
            P.log("ok", "système", f"PostgreSQL mis à jour : {old_v} → {_pg_version()}")
        else:
            owned = {p for x in COMPONENTS.values() for p in (x["pkgs"] or [])}

            def wanted(up):
                return [p for p in c["pkgs"] if p in up] if c["pkgs"] else sorted(p for p in up if p not in owned)
            pkgs = wanted(_upgradable())
            if not pkgs:
                _apt("update", timeout=600)
                pkgs = wanted(_upgradable())
            if not pkgs:
                P.log("ok", "système", f"{name} : déjà à jour")
                return 0
            old = {p: installed(p) for p in pkgs}
            rc, out = _apt("install", "--only-upgrade", *pkgs, timeout=3600)
            if rc:
                raise RuntimeError("apt : " + P.tail(out, 4))
            ok, why = _verify(cid, since)
            if not ok:
                P.log("error", "système", f"{name} : {why} après la mise à jour, retour aux versions précédentes")
                rc2, out2 = _apt("install", "--allow-downgrades", *[f"{p}={v}" for p, v in old.items() if v], timeout=3600)
                if cid in ("caddy", "cloudflared"):
                    P.run(["systemctl", "restart", cid], timeout=60)
                ok2, _ = _verify(cid, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 1)))
                raise RuntimeError(f"{why} ; versions précédentes " +
                                   ("remises, service rétabli" if rc2 == 0 and ok2 else "NON rétablies : intervention nécessaire"))
            new = {p: installed(p) for p in pkgs}
            if c["pkgs"]:
                main = pkgs[0]
                P.log("ok", "système", f"{name} mis à jour : {old[main]} → {new[main]}")
            else:
                P.log("ok", "système", f"{len(pkgs)} paquet{'s' if len(pkgs) > 1 else ''} Debian mis à jour : "
                      + ", ".join(pkgs[:12]) + ("…" if len(pkgs) > 12 else ""))
        check(refresh_apt=False)
        return 0
    except Exception as e:
        P.log("error", "système", f"mise à jour de {name} en échec : {e}")
        alerts.send(f"Mise à jour de {name} en échec", str(e), priority=4, tags=["warning"])
        try:
            check(refresh_apt=False)
        except Exception:
            pass
        return 1
