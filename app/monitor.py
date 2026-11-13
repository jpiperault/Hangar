"""Surveillance en tâche de fond (un fil dans la console) :
- chaque minute : statistiques, santé des applis, disque, mémoire, PostgreSQL, tunnel, et pour chaque nœud : disque,
  mémoire, Docker, PostgreSQL, Caddy (s'il reçoit le web en direct), pare-feu ;
- toutes les 6 h : nouvelles versions des images ;
- chaque jour : mises à jour système disponibles, fraîcheur des sauvegardes.
"""
import shutil
import threading
import time
import urllib.error
import urllib.request

from . import alerts, applogs, backup, db, ha, jobs, nodes, registry, report, security, stats, statuspage, system
from . import platform as P

_fails = {}            # slug -> échecs consécutifs
health = {}            # slug -> dernier healthcheck : ok, ms, ts, why
_down = set()          # applis signalées hors ligne
_flags = {}            # alertes d'état système déjà envoyées (disque, mémoire…)
_started = False


def _probe(a):
    url = f"http://{P.app_host(a)}:{a['host_port']}{a['health_path']}"
    try:
        with urllib.request.urlopen(url, timeout=5):
            return True, ""
    except urllib.error.HTTPError as e:
        return e.code < 500, f"HTTP {e.code}"
    except Exception as e:
        return False, str(getattr(e, "reason", e))


def check_apps():
    for a in db.apps():
        slug = a["slug"]
        if a["desired"] != "running" or a["state"] == "deploying":
            _fails.pop(slug, None)
            continue
        t0 = time.time()
        ok, why = _probe(a)
        health[slug] = {"ok": ok, "ms": (time.time() - t0) * 1000, "ts": time.time(), "why": why}
        if not P.maintenance(slug):   # disponibilité (rapport, page de statut) : une maintenance voulue ne compte pas
            db.x("INSERT INTO uptime(app, day, ok, total) VALUES(?, ?, ?, 1) ON CONFLICT(app, day) DO UPDATE SET "
                 "ok = ok + excluded.ok, total = total + 1", (slug, time.strftime("%Y-%m-%d"), 1 if ok else 0))
        if ok:
            _fails[slug] = 0
            if slug in _down:
                _down.discard(slug)
                P.log("ok", slug, "répond à nouveau")
                alerts.send(f"{a['name']} répond à nouveau", "L'appli est de nouveau en ligne.", priority=3,
                            tags=["white_check_mark"])
            continue
        _fails[slug] = _fails.get(slug, 0) + 1
        if _fails[slug] == 2 and slug not in _down:
            _down.add(slug)
            report = P.container_report(f"app-{slug}-app-1", lines=4, node=a["node"])
            P.log("error", slug, f"ne répond plus depuis 2 minutes ({why})\n{report}")
            alerts.send(f"{a['name']} ne répond plus", f"{a['health_path']} : {why}\n{report}", priority=5,
                        tags=["rotating_light"])


def _flag(key, bad, title, msg, ok_msg, priority=4):
    """Alerte sur front montant, message de retour à la normale sur front descendant."""
    if bad and not _flags.get(key):
        _flags[key] = True
        P.log("warn", "système", f"{title} : {msg}")
        alerts.send(title, msg, priority=priority, tags=["warning"])
    elif not bad and _flags.get(key):
        _flags[key] = False
        P.log("ok", "système", ok_msg)
        alerts.send(ok_msg, ok_msg, priority=2, tags=["white_check_mark"])


def check_system():
    du = shutil.disk_usage("/")
    pct = du.used / du.total * 100
    _flag("disk", pct > 85, "Disque presque plein", f"{pct:.0f} % utilisés, {du.free / 1e9:.1f} Go libres",
          "Espace disque revenu à la normale")
    try:
        mem = {l.split(":")[0]: int(l.split()[1]) for l in open("/proc/meminfo")}
        avail = mem["MemAvailable"] / mem["MemTotal"] * 100
        _flag("mem", avail < 8, "Mémoire presque saturée",
              f"{mem['MemAvailable'] // 1024} Mo disponibles sur {mem['MemTotal'] // 1024} Mo",
              "Mémoire revenue à la normale")
    except (OSError, KeyError, ValueError):
        pass
    pg = P.run(["docker", "inspect", "-f", "{{.State.Running}}", P.PG], timeout=10)[1].strip() == "true"
    _flag("pg", not pg, "PostgreSQL arrêté", "Le conteneur des bases ne tourne plus : les applis avec base sont en panne.",
          "PostgreSQL à nouveau en ligne", priority=5)
    if P.tunnel_ready() and P.tunnel_status()["installed"]:
        _flag("tunnel", not P.tunnel_status()["active"], "Tunnel Cloudflare coupé",
              "cloudflared ne tourne plus : les applis ne sont plus joignables depuis Internet.",
              "Tunnel Cloudflare rétabli", priority=5)


def node_checks(n, info=None):
    """État des services d'un nœud distant, d'après son dernier relevé : [{key, name, ok, state}].
    ok None : sans objet ou pas encore relevé."""
    info = info if info is not None else (n["info"] if isinstance(n["info"], dict) else {})
    svc = info.get("svc") or {}
    web = security.web_needed(n["id"])
    has_apps = bool(db.one("SELECT 1 FROM apps WHERE node = ?", (n["id"],)))
    out = []
    if "docker" in svc:
        out.append({"key": "docker", "name": "Docker", "ok": svc["docker"] == "active",
                    "state": "en ligne" if svc["docker"] == "active" else (svc["docker"] or "?")})
    pg = info.get("pg")
    if pg is not None:
        out.append({"key": "pg", "name": "PostgreSQL", "ok": pg == "healthy",
                    "state": {"healthy": "en ligne", "": "absent"}.get(pg, pg), "apps": has_apps})
    if "caddy" in svc:
        out.append({"key": "caddy", "name": "Caddy", "ok": (svc["caddy"] == "active") if web else None,
                    "state": ("en ligne" if svc["caddy"] == "active" else svc["caddy"] or "?") if web
                    else "inutile (pas d'entrée web directe)"})
    if "fw" in svc:
        out.append({"key": "fw", "name": "Pare-feu", "ok": svc["fw"] == "ok", "state": "actif" if svc["fw"] == "ok" else "règles absentes"})
    return out


def check_nodes():
    """Chaque minute, après le relevé des nœuds : disque, mémoire, Docker, PostgreSQL, Caddy, pare-feu de chaque nœud.
    (Injoignable : déjà signalé par nodes.check_all.)"""
    for n in nodes.all_nodes():
        if n["id"] == P.LOCAL or n["state"] != "ok" or not n["last_seen"] or time.time() - n["last_seen"] > 180:
            continue
        i, k, nm = n["info"] or {}, n["id"], n["name"]
        if i.get("disk_total"):
            pct = i["disk"] / i["disk_total"] * 100
            _flag(f"disk:{k}", pct > 85, f"Nœud {nm} : disque presque plein",
                  f"{pct:.0f} % utilisés, {i['disk_total'] - i['disk']:.1f} Go libres", f"Nœud {nm} : espace disque revenu à la normale")
        if i.get("mem_total"):
            avail = (i["mem_total"] - i["mem"]) / i["mem_total"] * 100
            _flag(f"mem:{k}", avail < 8, f"Nœud {nm} : mémoire presque saturée",
                  f"{i['mem_total'] - i['mem']:.0f} Mo disponibles sur {i['mem_total']:.0f} Mo",
                  f"Nœud {nm} : mémoire revenue à la normale")
        for c in node_checks(n, i):
            if c["ok"] is None:
                continue
            if c["key"] == "pg":
                _flag(f"pg:{k}", not c["ok"], f"Nœud {nm} : PostgreSQL arrêté",
                      f"État : {c['state']}." + (" Les applis du nœud avec base sont en panne." if c.get("apps") else ""),
                      f"Nœud {nm} : PostgreSQL à nouveau en ligne", priority=5 if c.get("apps") else 4)
            elif c["key"] == "docker":
                _flag(f"docker:{k}", not c["ok"], f"Nœud {nm} : Docker arrêté", f"État : {c['state']}. Ses applis sont en panne.",
                      f"Nœud {nm} : Docker à nouveau en ligne", priority=5)
            elif c["key"] == "caddy":
                _flag(f"caddy:{k}", not c["ok"], f"Nœud {nm} : Caddy arrêté",
                      f"État : {c['state']}. Les domaines en mode direct qui entrent par ce nœud ne répondent plus.",
                      f"Nœud {nm} : Caddy à nouveau en ligne", priority=5)
            elif c["key"] == "fw":
                _flag(f"fw:{k}", not c["ok"], f"Nœud {nm} : pare-feu absent",
                      "La table nftables hangarnode n'est plus chargée : le nœud est exposé. Clique sur Appliquer (page Sécurité).",
                      f"Nœud {nm} : pare-feu de nouveau en place", priority=5)


def check_versions(slug=None):
    """Cherche une version plus récente pour les applis en image. Retourne le nombre de nouveautés."""
    found = 0
    for a in ([db.app(slug)] if slug else db.apps()):
        if not a or a["source"] != "image":
            continue
        try:
            latest = registry.newest(registry.tags(a["image"]), a["version"])
            err = None if registry.semver(a["version"]) else \
                f"version actuelle « {a['version']} » non numérotée (x.y.z) : comparaison impossible"
        except Exception as e:
            latest, err = None, str(e)[:300]
        if latest and latest != a["latest_version"]:
            found += 1
            P.log("info", a["slug"], f"version {latest} disponible (en ligne : {a['version']})")
            alerts.send(f"{a['name']} : version {latest} disponible",
                        f"En ligne : {a['version']}. À déployer depuis la console.", priority=2, tags=["package"])
        db.update_app(a["slug"], latest_version=latest, latest_checked=time.time(), latest_error=err)
    return found


PENDING_DAYS = 14   # au-delà, rappel : une mise à jour attend depuis longtemps


def check_updates():
    prev = db.kv_get("sys_check") or {}
    res = system.check()

    def avail(r, n):
        m = r if n == P.LOCAL else (r.get("nodes") or {}).get(n) or {}
        return {k: v.get("available") for k, v in (m.get("components") or {}).items()}
    names = dict(system.machines())
    new = []
    for n, k in system.pending(res):
        if avail(res, n).get(k) != avail(prev, n).get(k):
            new.append(f"{system.COMPONENTS[k]['name']} ({'console' if n == P.LOCAL else names.get(n, n)})")
    if new:
        alerts.send("Mises à jour système disponibles", ", ".join(new) + ". À lancer depuis la page Système.",
                    priority=2, tags=["arrow_up"])
    # depuis quand chaque mise à jour attend ; rappel une fois au-delà de 14 jours
    since = db.kv_get("sys_pending_since") or {}
    now = time.time()
    cur = {f"{n}:{k}" for n, k in system.pending(res)}
    since = {key: v for key, v in since.items() if key in cur}
    late = []
    for key in cur:
        e = since.setdefault(key, {"ts": now, "reminded": False})
        if not e["reminded"] and now - e["ts"] > PENDING_DAYS * 86400:
            e["reminded"] = True
            n, k = key.split(":", 1)
            late.append(f"{system.COMPONENTS[k]['name']} ({'console' if n == P.LOCAL else names.get(n, n)})")
    db.kv_set("sys_pending_since", since)
    if late:
        alerts.send("Mises à jour en attente depuis plus de 14 jours", ", ".join(sorted(late))
                    + ". À lancer depuis la page Système.", priority=3, tags=["hourglass"])


def check_backup_age():
    if not backup.configured():
        return
    last = backup.last_ok()
    age = (time.time() - last["ts"]) / 3600 if last else None
    _flag("backup", age is None or age > 36, "Aucune sauvegarde récente",
          "Pas de sauvegarde réussie sur Google Drive depuis plus de 36 h." if last else
          "Aucune sauvegarde n'a encore réussi sur Google Drive.", "Sauvegardes à nouveau à jour")


def _every(key, seconds, fn):
    last = db.kv_ts(f"tick_{key}") or 0
    if time.time() - last >= seconds:
        db.kv_set(f"tick_{key}", True)
        try:
            fn()
        except Exception as e:
            P.log("warn", "système", f"tâche {key} en échec : {e}")


def _loop():
    time.sleep(20)
    while True:
        t0 = time.time()
        for name, fn in (("stats", stats.collect_requests), ("res", stats.collect_resources), ("host", stats.collect_host),
                         ("apps", check_apps), ("sys", check_system),
                         ("nodes", nodes.check_all), ("nodes_health", check_nodes), ("ha", ha.tick),
                         ("jobs", jobs.tick), ("logs", applogs.tick),
                         ("status", statuspage.tick)):
            try:
                fn()
            except Exception as e:
                P.log("warn", "système", f"surveillance {name} : {e}")
        _every("purge", 3600, stats.purge)
        _every("purge_nodes", 3600, nodes.purge)
        _every("security", 1800, security.collect_all)
        _every("versions", 6 * 3600, check_versions)
        _every("updates", 24 * 3600, check_updates)
        _every("auto_updates", 300, system.auto_tick)   # sans effet hors de la plage de nuit, ou si l'option est coupée
        _every("backup_age", 3600, check_backup_age)
        _every("weekly_report", 600, report.maybe_send)
        _every("purge_uptime", 86400, report.purge)
        time.sleep(max(5, 60 - (time.time() - t0)))


def start():
    global _started
    if not _started:
        _started = True
        threading.Thread(target=_loop, name="hangar-monitor", daemon=True).start()
