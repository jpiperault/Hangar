"""Mises à jour des composants système de la console et de chaque nœud, avec retour à la version précédente si le
service ne repart pas.

Les mises à jour tournent dans une unité systemd transitoire de la console (`hangar sysupdate <composant> [--node X]`) :
mettre Docker à jour sur la console redémarre aussi la console (dépendance systemd), l'opération doit lui survivre.
Sur un nœud, les commandes passent par SSH sur le réseau privé ; une seule mise à jour à la fois, toutes machines
confondues.
"""
import os
import re
import shlex
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
APT_ENV = {"DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_MODE": "a"}   # ajoutées à l'environnement
APT_OPTS = ["-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"]


# ---------------------------------------------------------------- commandes sur une machine (console ou nœud)

def _x(node, argv, timeout=120, env=None):
    """Commande sur la console (node None/'local') ou sur un nœud (SSH). `env` : variables ajoutées."""
    if P.is_local(node):
        return P.run(argv, timeout=timeout, env={**os.environ, **env} if env else None)
    pre = " ".join(f"{k}={shlex.quote(v)}" for k, v in (env or {}).items())
    return P.nsh(node, (pre + " " if pre else "") + shlex.join(argv), timeout=timeout)


def _apt(node, *args, timeout=1800):
    return _x(node, ["apt-get", "-q", "-y", *APT_OPTS, *args], timeout=timeout, env=APT_ENV)


def installed(node, pkg):
    rc, out = _x(node, ["dpkg-query", "-W", "-f", "${Version}", pkg], timeout=20)
    return out.strip() if rc == 0 and out.strip() and "no packages" not in out else None


def _upgradable(node):
    rc, out = _x(node, ["apt", "list", "--upgradable"], timeout=120)
    res = {}
    for line in out.splitlines():
        m = re.match(r"^([^/\s]+)/\S+\s+(\S+)\s+\S+\s+\[upgradable from: ([^\]]+)\]", line)
        if m:
            res[m.group(1)] = {"new": m.group(2), "old": m.group(3)}
    return res


def _pg_local_digest(node):
    rc, out = _x(node, ["docker", "image", "inspect", PG_IMAGE, "--format", "{{join .RepoDigests \" \"}}"], timeout=20)
    m = re.search(r"@(sha256:[0-9a-f]+)", out)
    return m.group(1) if rc == 0 and m else None


def _pg_version(node):
    rc, out = _x(node, ["docker", "exec", P.PG, "postgres", "--version"], timeout=20)
    m = re.search(r"(\d+\.\d+)", out)
    return m.group(1) if rc == 0 and m else "?"


def machines():
    """La console, puis chaque nœud installé et joignable : [(id, nom)]."""
    out = [(P.LOCAL, "Console")]
    for n in db.q("SELECT id, name, state FROM nodes WHERE id != ? ORDER BY name", (P.LOCAL,)):
        if n["state"] == "ok":
            out.append((n["id"], n["name"]))
    return out


def _who(node):
    if P.is_local(node):
        return "console"
    r = P.node_row(node)
    return f"nœud {r['name'] if r else node}"


# ---------------------------------------------------------------- recensement

def check_machine(node, pg_remote=None, refresh_apt=True):
    """Mises à jour disponibles sur une machine."""
    if refresh_apt:
        rc, out = _apt(node, "update", timeout=600)
        if rc:
            raise RuntimeError("apt update : " + P.tail(out, 2))
    up = _upgradable(node)
    comps = {}
    owned = set()
    for cid, c in COMPONENTS.items():
        if c["pkgs"]:
            owned.update(c["pkgs"])
            pk = [p for p in c["pkgs"] if installed(node, p)]
            main = pk[0] if pk else c["pkgs"][0]
            ups = {p: up[p] for p in pk if p in up}
            comps[cid] = {"current": installed(node, main) or "absent",
                          "available": ups[main]["new"] if main in ups else
                          (f"{next(iter(ups))} {next(iter(ups.values()))['new']}" if ups else None),
                          "packages": sorted(ups)}
    deb = sorted(p for p in up if p not in owned)
    rc, ver = _x(node, ["cat", "/etc/debian_version"], timeout=20)
    comps["debian"] = {"current": ver.strip() if rc == 0 else "?",
                       "available": f"{len(deb)} paquet{'s' if len(deb) > 1 else ''}" if deb else None, "packages": deb}
    pg = {"current": _pg_version(node), "available": None, "packages": []}
    local = _pg_local_digest(node)
    if pg_remote and local and pg_remote != local:
        pg["available"] = "nouvelle image 17.x"
    comps["postgres"] = pg
    rb = _x(node, ["test", "-e", "/var/run/reboot-required"], timeout=20)[0] == 0
    return {"ts": time.time(), "components": comps, "reboot": rb}


def check(refresh_apt=True, only=None):
    """Recense les mises à jour de la console et de chaque nœud. Résultat gardé dans kv 'sys_check' :
    components/reboot (console, comme avant) et nodes[id] pour chaque nœud. `only` : une seule machine."""
    prev = db.kv_get("sys_check") or {}
    try:
        pg_remote, pg_err = registry.digest("postgres", "17"), None
    except Exception as e:
        pg_remote, pg_err = None, str(e)[:200]
    nodes = {} if only is None else dict(prev.get("nodes") or {})
    res = {**prev, "ts": time.time(), "nodes": nodes}
    for node, _name in machines():
        if only is not None and node != only:
            continue
        try:
            m = check_machine(node, pg_remote, refresh_apt)
            if pg_err:
                m["components"]["postgres"]["error"] = pg_err
        except Exception as e:
            m = {"ts": time.time(), "components": {}, "reboot": False, "error": str(e)[:300]}
        if P.is_local(node):
            res.update(components=m["components"], reboot=m["reboot"], error=m.get("error"))
        else:
            nodes[node] = m
    for gone in [n for n in nodes if not P.node_row(n)]:   # nœud retiré
        nodes.pop(gone)
    if only is None or P.is_local(only):
        res["hangar"] = hangar_status()
    db.kv_set("sys_check", res)
    return res


def pending(res=None):
    """[(machine, cid)] des mises à jour en attente (hors paquets Debian ordinaires)."""
    res = res or db.kv_get("sys_check") or {}
    out = [(P.LOCAL, k) for k, v in (res.get("components") or {}).items() if v.get("available") and k != "debian"]
    for n, m in (res.get("nodes") or {}).items():
        out += [(n, k) for k, v in (m.get("components") or {}).items() if v.get("available") and k != "debian"]
    return out


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

def unit(cid, node=None):
    return f"hangar-maj-{cid}" if P.is_local(node) else f"hangar-maj-{node}-{cid}"


def running(cid=None, node=None):
    """(machine, composant) de la mise à jour en cours, sinon None. Avec cid/node : seulement celle-là."""
    for n, _name in machines():
        if node is not None and (n or P.LOCAL) != (node or P.LOCAL):
            continue
        for c in [cid] if cid else list(COMPONENTS):
            rc, out = P.run(["systemctl", "is-active", unit(c, n)], timeout=10)
            if out.strip() in ("active", "activating"):
                return (n, c)
    return None


def launch(cid, node=None):
    node = node or P.LOCAL
    if cid not in COMPONENTS:
        raise ValueError("composant inconnu")
    if node not in [m for m, _ in machines()]:
        raise ValueError("machine inconnue ou injoignable")
    busy = running()
    if busy:
        raise RuntimeError(f"Une mise à jour est déjà en cours ({COMPONENTS[busy[1]]['name']}, {_who(busy[0])}).")
    if cid == "docker" and db.one("SELECT 1 FROM apps WHERE state = 'deploying'"):
        raise RuntimeError("Un déploiement est en cours : attends qu'il se termine.")
    P.run(["systemctl", "reset-failed", unit(cid, node)], timeout=10)
    argv = ["/opt/hangar/venv/bin/python", "-m", "app", "sysupdate", cid] + ([] if P.is_local(node) else ["--node", node])
    rc, out = P.run(["systemd-run", f"--unit={unit(cid, node)}", "--collect", "--quiet",
                     "--property=EnvironmentFile=/srv/platform/.env", "--working-directory=/opt/hangar", *argv], timeout=30)
    if rc:
        raise RuntimeError("Lancement impossible : " + P.tail(out))


def _wait(fn, seconds):
    end = time.time() + seconds
    while time.time() < end:
        if fn():
            return True
        time.sleep(2)
    return False


def _active(node, svc):
    return _x(node, ["systemctl", "is-active", svc], timeout=20)[1].strip() == "active"


def _verify(node, cid, since, was_active):
    if cid == "caddy":
        if not was_active:
            return True, ""
        ok = _wait(lambda: _active(node, "caddy") and _x(node, ["curl", "-sf", "-o", "/dev/null",
                                                               "http://localhost:2019/config/"], timeout=20)[0] == 0, 30)
        return ok, "Caddy ne répond plus"
    if cid == "cloudflared":
        if not was_active:
            return True, ""
        if P.is_local(node):
            ok, err = P._tunnel_connected(since, wait=40)
            return ok, f"le tunnel ne se reconnecte pas ({err})"
        return _wait(lambda: _active(node, "cloudflared"), 40), "cloudflared ne redémarre pas"
    if cid == "docker":
        def apps_up():
            if _x(node, ["docker", "info", "--format", "{{.ServerVersion}}"], timeout=20)[0]:
                return False
            states = P.container_states()
            want = [a["slug"] for a in db.apps() if a["desired"] == "running" and (a["node"] or P.LOCAL) == node]
            pg = _x(node, ["docker", "inspect", "-f", "{{.State.Running}}", P.PG], timeout=20)[1].strip() == "true"
            return pg and all(states.get(w, ("",))[0] == "running" for w in want)
        return _wait(apps_up, 120), "Docker ou les conteneurs ne sont pas repartis"
    return True, ""


def _pg_ready(node):
    return _x(node, ["docker", "exec", P.PG, "pg_isready", "-U", "platform"], timeout=20)[0] == 0


def _pg_dump_before(node):
    """Dump complet du PostgreSQL de la machine avant de changer son image."""
    if P.is_local(node):
        from . import backup
        backup._dump_all_local()
        return
    f = f"/srv/backups/avant-maj-postgres-{time.strftime('%Y%m%d-%H%M%S')}.sql.gz"
    rc, out = P.nsh(node, f"set -o pipefail; umask 077; install -d -m 0700 /srv/backups; "
                          f"docker exec {P.PG} pg_dumpall -U platform | gzip > {f}.tmp && mv {f}.tmp {f}; "
                          f"ls -1t /srv/backups/avant-maj-postgres-*.sql.gz | tail -n +4 | xargs -r rm -f", timeout=3600)
    if rc:
        raise RuntimeError("dump avant mise à jour impossible : " + P.tail(out, 2))


def _compose(node, *args, timeout=900):
    if P.is_local(node):
        return P.run(["docker", "compose", *args], cwd=P.PLATFORM, timeout=timeout)
    return P.nsh(node, f"cd {P.PLATFORM} && docker compose {shlex.join(args)}", timeout=timeout)


def run_update(cid, node=None):
    """Exécutée par l'unité transitoire. Journalise sous l'appli « système »."""
    node = node or P.LOCAL
    c = COMPONENTS[cid]
    who = _who(node)
    name = c["name"]
    P.log("info", "système", f"{who} : mise à jour de {name} lancée")
    since = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 1))
    try:
        if cid == "postgres":
            _pg_dump_before(node)
            rc, old_id = _x(node, ["docker", "image", "inspect", PG_IMAGE, "--format", "{{.Id}}"], timeout=20)
            old_v = _pg_version(node)
            rc, out = _compose(node, "pull", "--quiet")
            if rc:
                raise RuntimeError("téléchargement de l'image impossible : " + P.tail(out))
            _compose(node, "up", "-d", timeout=300)
            if not _wait(lambda: _pg_ready(node), 90):
                P.log("error", "système", f"{who} : PostgreSQL ne redémarre pas avec la nouvelle image : retour à l'ancienne")
                _x(node, ["docker", "tag", old_id.strip(), PG_IMAGE], timeout=30)
                _compose(node, "up", "-d", timeout=300)
                ok = _wait(lambda: _pg_ready(node), 90)
                raise RuntimeError("nouvelle image refusée, ancienne remise " + ("(PostgreSQL en ligne)" if ok else "MAIS PostgreSQL ne répond pas"))
            P.log("ok", "système", f"{who} : PostgreSQL mis à jour : {old_v} → {_pg_version(node)}")
        else:
            owned = {p for x in COMPONENTS.values() for p in (x["pkgs"] or [])}

            def wanted(up):
                return [p for p in c["pkgs"] if p in up] if c["pkgs"] else sorted(p for p in up if p not in owned)
            pkgs = wanted(_upgradable(node))
            if not pkgs:
                _apt(node, "update", timeout=600)
                pkgs = wanted(_upgradable(node))
            if not pkgs:
                P.log("ok", "système", f"{who} : {name} déjà à jour")
                check(refresh_apt=False, only=node)
                return 0
            was_active = cid not in ("caddy", "cloudflared") or _active(node, cid)
            old = {p: installed(node, p) for p in pkgs}
            rc, out = _apt(node, "install", "--only-upgrade", *pkgs, timeout=3600)
            if rc:
                raise RuntimeError("apt : " + P.tail(out, 4))
            ok, why = _verify(node, cid, since, was_active)
            if not ok:
                P.log("error", "système", f"{who} : {name} : {why} après la mise à jour, retour aux versions précédentes")
                rc2, out2 = _apt(node, "install", "--allow-downgrades", *[f"{p}={v}" for p, v in old.items() if v], timeout=3600)
                if cid in ("caddy", "cloudflared"):
                    _x(node, ["systemctl", "restart", cid], timeout=60)
                ok2, _ = _verify(node, cid, time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 1)), was_active)
                raise RuntimeError(f"{why} ; versions précédentes " +
                                   ("remises, service rétabli" if rc2 == 0 and ok2 else "NON rétablies : intervention nécessaire"))
            new = {p: installed(node, p) for p in pkgs}
            if c["pkgs"]:
                main = pkgs[0]
                what = "" if main == c["pkgs"][0] else f" ({main})"
                P.log("ok", "système", f"{who} : {name} mis à jour{what} : {old[main]} → {new[main]}")
            else:
                P.log("ok", "système", f"{who} : {len(pkgs)} paquet{'s' if len(pkgs) > 1 else ''} Debian mis à jour : "
                      + ", ".join(pkgs[:12]) + ("…" if len(pkgs) > 12 else ""))
        check(refresh_apt=False, only=node)
        return 0
    except Exception as e:
        P.log("error", "système", f"{who} : mise à jour de {name} en échec : {e}")
        alerts.send(f"Mise à jour de {name} en échec ({who})", str(e), priority=4, tags=["warning"])
        try:
            check(refresh_apt=False, only=node)
        except Exception:
            pass
        return 1


# ---------------------------------------------------------------- mises à jour automatiques la nuit (option)

AUTO_DEFAULT = {"on": False, "comps": ["cloudflared", "caddy", "postgres"], "start": 3, "end": 5}
AUTO_RETRY_DAYS = 7   # une mise à jour tentée et toujours en attente (échec, ancienne version remise) : pas avant 7 jours


def auto_settings():
    s = {**AUTO_DEFAULT, **(db.kv_get("sys_auto") or {})}
    s["comps"] = [c for c in s["comps"] if c in COMPONENTS]
    return s


def save_auto(on, comps, start, end):
    start, end = int(start) % 24, int(end) % 24
    if start == end:
        raise ValueError("la plage horaire doit durer au moins une heure")
    db.kv_set("sys_auto", {"on": bool(on), "comps": [c for c in comps if c in COMPONENTS], "start": start, "end": end})


def in_window(hour, start, end):
    return start <= hour < end if start < end else (hour >= start or hour < end)


def auto_pick(res, settings, tried, now):
    """Prochaine (machine, composant) à mettre à jour automatiquement, sinon None. Fonction pure (testée).
    tried : {"machine:composant": {"ts", "available"}} des tentatives précédentes."""
    if not settings["on"] or not in_window(time.localtime(now).tm_hour, settings["start"], settings["end"]):
        return None
    cands = []
    for node, cid in pending(res) + [(n, "debian") for n, k in _debian_pending(res)]:
        if cid not in settings["comps"]:
            continue
        m = res if node == P.LOCAL else (res.get("nodes") or {}).get(node) or {}
        avail = ((m.get("components") or {}).get(cid) or {}).get("available")
        t = tried.get(f"{node}:{cid}")
        if t and t.get("available") == avail and now - t["ts"] < AUTO_RETRY_DAYS * 86400:
            continue
        cands.append((node, cid))
    # nœuds d'abord, la console en dernier (Docker de la console la redémarre) ; Docker après le reste
    cands.sort(key=lambda x: (x[0] == P.LOCAL, x[1] == "docker"))
    return cands[0] if cands else None


def _debian_pending(res):
    out = [(P.LOCAL, "debian")] if ((res.get("components") or {}).get("debian") or {}).get("available") else []
    for n, m in (res.get("nodes") or {}).items():
        if ((m.get("components") or {}).get("debian") or {}).get("available"):
            out.append((n, "debian"))
    return out


def auto_tick(now=None):
    """Appelée régulièrement par la surveillance : lance au plus une mise à jour à la fois, dans la plage de nuit."""
    now = now or time.time()
    s = auto_settings()
    if not s["on"] or running() or db.one("SELECT 1 FROM apps WHERE state = 'deploying'"):
        return None
    from . import backup
    if backup.running() or backup.archive_running():   # pas de changement de PostgreSQL ou de Docker sous une sauvegarde
        return None
    res = db.kv_get("sys_check") or {}
    tried = db.kv_get("sys_auto_tried") or {}
    pick = auto_pick(res, s, tried, now)
    if not pick:
        return None
    node, cid = pick
    m = res if node == P.LOCAL else (res.get("nodes") or {}).get(node) or {}
    tried[f"{node}:{cid}"] = {"ts": now, "available": ((m.get("components") or {}).get(cid) or {}).get("available")}
    db.kv_set("sys_auto_tried", {k: v for k, v in tried.items() if now - v["ts"] < 30 * 86400})
    P.log("info", "système", f"{_who(node)} : mise à jour automatique de nuit de {COMPONENTS[cid]['name']}")
    try:
        launch(cid, node)
    except (ValueError, RuntimeError) as e:
        P.log("warn", "système", f"{_who(node)} : mise à jour automatique de {COMPONENTS[cid]['name']} non lancée : {e}")
    return pick
