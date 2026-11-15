"""Espace disque occupé, par appli et par conteneur, sur chaque machine (console et nœuds).

Relevé chaque heure (et à la demande), une commande par machine :
- conteneurs : couche modifiable (fichiers écrits hors des volumes), journaux Docker, image utilisée ;
- volumes Docker (nommés ou anonymes), rattachés à l'appli dont un conteneur les monte ;
- dossier de l'appli /srv/apps/<appli> : data/ (dont Redis et l'export MySQL), fichiers bruts MySQL, base dédiée
  PostgreSQL de la haute dispo ;
- base de l'appli dans le PostgreSQL partagé du nœud (pg_database_size) ;
- le reste de la machine : images Docker (dont inutilisées), cache de build, cache de Trivy, volumes orphelins,
  PostgreSQL partagé hors bases d'applis, sauvegardes locales, système.

Le dernier relevé de chaque machine est gardé en entier (kv « diskuse:<machine> ») ; l'historique (total et data/
par appli et par machine) dans la table stats_disk, 90 jours. Les images sont partagées entre applis (couches
communes) : elles comptent dans le tableau de la machine, pas dans le total d'une appli.
"""
import json
import threading
import time

from . import db
from . import platform as P

KEEP_DAYS = 90
_lock = threading.Lock()

PROBE = r"""python3 - <<'EOF'
import json, os, shutil, subprocess
def sh(c, t=120):
    try: return subprocess.run(c, shell=True, capture_output=True, text=True, timeout=t).stdout
    except Exception: return ''
def du(p):
    if not os.path.exists(p): return None
    try: return int(sh(f"du -sbx '{p}' 2>/dev/null | cut -f1", 600).split()[0])
    except Exception: return None
out = {'containers': [], 'volumes': {}, 'dirs': {}, 'images': {}, 'pg': {}}
du0 = shutil.disk_usage('/'); out['disk'] = {'used': du0.used, 'total': du0.total, 'free': du0.free}
ids = sh('docker ps -aq --no-trunc').split()
if ids:
    for line in sh('docker inspect --size -f ' + "'{{json .}}' " + ' '.join(ids), 300).splitlines():
        try: c = json.loads(line)
        except ValueError: continue
        lp = c.get('LogPath') or ''
        labels = (c.get('Config') or {}).get('Labels') or {}
        out['containers'].append({
            'name': c['Name'].lstrip('/'), 'state': (c.get('State') or {}).get('Status'),
            'app': labels.get('fr.hangar.app') or labels.get('fr.hangar.ha-db') or '',
            'project': labels.get('com.docker.compose.project') or '', 'image': c.get('Image'),
            'image_name': (c.get('Config') or {}).get('Image'),
            'rw': c.get('SizeRw') or 0, 'log': os.path.getsize(lp) + sum(os.path.getsize(lp + f'.{i}') for i in range(1, 10) if os.path.exists(lp + f'.{i}')) if lp and os.path.exists(lp) else 0,
            'mounts': [{'t': m.get('Type'), 'name': m.get('Name') or '', 'src': m.get('Source') or '', 'dst': m.get('Destination') or ''}
                       for m in c.get('Mounts') or []]})
for v in sh('docker volume ls -q').split():
    out['volumes'][v] = du(f'/var/lib/docker/volumes/{v}/_data') or 0
for line in sh("docker image ls -a --no-trunc --format '{{.ID}}\t{{.Repository}}:{{.Tag}}'").splitlines():
    p = line.split('\t')
    if len(p) == 2: out['images'].setdefault(p[0], {'tags': [], 'size': 0})['tags'].append(p[1])
if out['images']:
    for line in sh("docker image inspect -f '{{.Id}} {{.Size}}' " + ' '.join(out['images']), 120).splitlines():
        p = line.split()
        if len(p) == 2 and p[0] in out['images']: out['images'][p[0]]['size'] = int(p[1])
out['df'] = {}
for line in sh("docker system df --format '{{.Type}}\t{{.Size}}\t{{.Reclaimable}}'").splitlines():
    p = line.split('\t')
    if len(p) == 3: out['df'][p[0]] = [p[1], p[2].split(' ')[0]]
if os.path.isdir('/srv/apps'):
    for slug in os.listdir('/srv/apps'):
        d = f'/srv/apps/{slug}'
        if not os.path.isdir(d): continue
        r = {'total': du(d)}
        for sub in ('data', 'mysql', 'pgdata', 'site', 'data/.hangar-redis', 'data/.hangar-mysql'):
            s = du(f'{d}/{sub}')
            if s is not None: r[sub] = s
        out['dirs'][slug] = r
out['backups'] = du('/srv/backups')
out['pg_dir'] = du('/srv/platform/postgres')
pg = sh("docker exec platform-postgres-1 psql -U platform -qtA -F ' ' -c 'SELECT datname, pg_database_size(datname) FROM pg_database' 2>/dev/null", 60)
for line in pg.splitlines():
    p = line.split()
    if len(p) == 2 and p[1].isdigit(): out['pg'][p[0]] = int(p[1])
print('@@HANGAR-DU@@' + json.dumps(out))
EOF"""

UNITS = {"B": 1, "kB": 1e3, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12}


def _human(text):
    """« 340.3MB » -> octets (sortie de docker system df)."""
    t = (text or "").strip()
    for u in sorted(UNITS, key=len, reverse=True):
        if t.endswith(u):
            try:
                return int(float(t[:-len(u)]) * UNITS[u])
            except ValueError:
                return 0
    return 0


def probe(node):
    rc, out = P.nsh(node, PROBE, timeout=900)
    if rc:
        return None
    for line in reversed(out.splitlines()):
        if line.startswith("@@HANGAR-DU@@"):
            try:
                return json.loads(line[len("@@HANGAR-DU@@"):])
            except ValueError:
                return None
    return None


def _owner(c, slugs):
    """Appli d'un conteneur : étiquette Hangar, projet compose « app-<appli> », ou nom (appdb-, myrepl-)."""
    if c.get("app") in slugs:
        return c["app"]
    proj = c.get("project") or ""
    if proj.startswith("app-") and proj[4:] in slugs:
        return proj[4:]
    for pre in ("appdb-", "myrepl-"):
        if c["name"].startswith(pre) and c["name"][len(pre):] in slugs:
            return c["name"][len(pre):]
    return None


SVC = {"app": "appli", "redis": "Redis", "mysql": "MySQL / MariaDB"}


def _role(c, slug):
    n = c["name"]
    if n.startswith("appdb-"):
        return "PostgreSQL dédié"
    if n.startswith("myrepl-"):
        return "réplique MySQL"
    for k, label in SVC.items():
        if n.startswith(f"app-{slug}-{k}-"):
            return label
    return n


def analyse(raw, slugs):
    """Relevé brut d'une machine -> {apps: {appli: détail}, machine: [(libellé, octets, note)], disk}."""
    apps = {}
    vol_owner = {}

    def app(s):
        return apps.setdefault(s, {"containers": [], "volumes": [], "parts": [], "total": 0, "data": 0})

    images = raw.get("images") or {}
    for c in raw.get("containers") or []:
        s = _owner(c, slugs)
        for m in c.get("mounts") or []:
            if m["t"] == "volume" and m["name"] and s:
                vol_owner.setdefault(m["name"], (s, m["dst"]))
        if not s:
            continue
        img = images.get(c.get("image")) or {}
        app(s)["containers"].append({"name": c["name"], "role": _role(c, s), "state": c.get("state"),
                                     "rw": c.get("rw") or 0, "log": c.get("log") or 0,
                                     "image": c.get("image_name"), "image_size": img.get("size") or 0})
    vols = raw.get("volumes") or {}
    orphans = 0
    attached = {m["name"] for c in raw.get("containers") or [] for m in c.get("mounts") or [] if m["t"] == "volume"}
    for v, size in vols.items():
        if v in vol_owner:
            s, dst = vol_owner[v]
            app(s)["volumes"].append({"name": v, "dst": dst, "size": size})
        elif v not in attached and v != "hangar-trivy-cache":
            orphans += size
    pg = raw.get("pg") or {}
    dirs = raw.get("dirs") or {}
    for s in slugs:
        d = dirs.get(s) or {}
        dbsize = pg.get(P.db_name(s))
        # la console garde une copie des réglages de chaque appli : sans conteneur, données ni base, rien à montrer
        if s not in apps and dbsize is None and not any(k in d for k in ("data", "mysql", "pgdata", "site")):
            continue
        a = app(s)
        data = d.get("data") or 0
        redis, mexp = d.get("data/.hangar-redis") or 0, d.get("data/.hangar-mysql") or 0
        parts = []
        if "data" in d:
            parts.append(("data", "Données (data/)", data - redis - mexp))
        if redis:
            parts.append(("redis", "Redis (data/.hangar-redis)", redis))
        if mexp:
            parts.append(("mysql_export", "Export MySQL (data/.hangar-mysql)", mexp))
        if d.get("mysql"):
            parts.append(("mysql", "Fichiers MySQL / MariaDB", d["mysql"]))
        if d.get("pgdata"):
            parts.append(("pgdata", "PostgreSQL dédié (haute dispo)", d["pgdata"]))
        if d.get("site"):
            parts.append(("site", "Site statique", d["site"]))
        known = sum(d.get(k) or 0 for k in ("data", "mysql", "pgdata", "site"))
        if d.get("total") and d["total"] - known > 0:
            parts.append(("other", "Réglages et fichiers de Hangar", d["total"] - known))
        if dbsize is not None:
            parts.append(("db", "Base PostgreSQL (partagée)", dbsize))
        a["parts"] = [{"key": k, "label": l, "size": v} for k, l, v in parts]
        a["data"] = data
    for s, a in apps.items():
        a["total"] = (sum(p["size"] for p in a["parts"]) + sum(v["size"] for v in a["volumes"])
                      + sum(c["rw"] + c["log"] for c in a["containers"]))
    disk = raw.get("disk") or {}
    df = raw.get("df") or {}
    img_total, img_unused = (_human(x) for x in (df.get("Images") or ["", ""]))   # couches communes comptées une fois
    apps_total = sum(a["total"] for a in apps.values())
    app_db = sum(pg.get(P.db_name(s)) or 0 for s in slugs)
    other_c = sum((c.get("rw") or 0) + (c.get("log") or 0) for c in raw.get("containers") or [] if not _owner(c, slugs))
    machine = [   # (libellé, octets, note, récupérable)
        ("Images Docker", img_total, "", img_unused),
        ("Cache de build Docker", _human((df.get("Build Cache") or [""])[0]), "", 0),
        ("Cache de l'analyse des vulnérabilités", vols.get("hangar-trivy-cache") or 0, "", 0),
        ("Volumes Docker orphelins", orphans, "Montés par aucun conteneur.", 0),
        ("PostgreSQL partagé (hors bases d'applis)", max(0, (raw.get("pg_dir") or 0) - app_db), "", 0),
        ("Conteneurs hors applis", other_c, "PostgreSQL, Caddy…", 0),
        ("Sauvegardes locales", raw.get("backups") or 0, "/srv/backups", 0),
    ]
    known = apps_total + sum(m[1] for m in machine)
    machine.append(("Système et autres fichiers", max(0, (disk.get("used") or 0) - known), "", 0))
    rows = [{"label": l, "size": v, "note": n, "reclaim": r} for l, v, n, r in machine if v]
    return {"apps": apps, "machine": rows, "disk": disk, "apps_total": apps_total}


def _fmt(b):
    for u, m in (("Go", 1e9), ("Mo", 1e6), ("ko", 1e3)):
        if b >= m:
            return f"{b / m:.1f} {u}".replace(".", ",")
    return f"{b} o"


def _machines():
    from . import nodes
    ids = set(P.app_nodes())
    ids |= {n["id"] for n in nodes.all_nodes() if n["state"] in ("ok", "offline", "degraded")}
    return sorted(ids)


def collect(only=None):
    """Relève toutes les machines (ou une seule), en parallèle. Retourne {machine: analyse ou None}."""
    if not _lock.acquire(blocking=False):
        return {}
    try:
        import concurrent.futures
        ids = [only] if only else _machines()
        slugs = {r["slug"] for r in db.q("SELECT slug FROM apps")}
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(ids))) as ex:
            raws = dict(zip(ids, ex.map(probe, ids)))
        t = int(time.time() // 3600 * 3600)
        res = {}
        for node, raw in raws.items():
            if raw is None:
                res[node] = None
                continue
            an = analyse(raw, slugs)
            an["t"] = time.time()
            db.kv_set(f"diskuse:{node}", an)
            for s, a in an["apps"].items():
                db.x("INSERT OR REPLACE INTO stats_disk(app, node, t, total, data) VALUES(?, ?, ?, ?, ?)",
                     (s, node, t, a["total"], a["data"]))
            res[node] = an
        return res
    finally:
        _lock.release()


def busy():
    return _lock.locked()


def collect_async(only=None):
    threading.Thread(target=collect, args=(only,), daemon=True).start()


def of_node(node):
    return db.kv_get(f"diskuse:{node}")


def node_view(node):
    """Tableau « qui occupe le disque » d'une machine : applis puis le reste, du plus gros au plus petit."""
    an = of_node(node)
    if not an:
        return None
    names = {r["slug"]: r["name"] for r in db.q("SELECT slug, name FROM apps")}
    rows = [{"label": names.get(s, s), "slug": s, "size": a["total"], "note": "", "reclaim": 0}
            for s, a in an["apps"].items()]
    rows += an["machine"]
    rows.sort(key=lambda r: -r["size"])
    used = (an.get("disk") or {}).get("used") or sum(r["size"] for r in rows) or 1
    for r in rows:
        r["pct"] = r["size"] / used * 100
    return {"t": an["t"], "disk": an.get("disk") or {}, "rows": rows}


def app_view(slug):
    """Détail d'une appli sur chaque machine où elle a des fichiers (principale, secours, instances)."""
    out = []
    from . import nodes
    nm = {n["id"]: n["name"] for n in nodes.all_nodes()}
    a = db.app(slug) or {}
    for node in _machines():
        an = of_node(node)
        d = (an or {}).get("apps", {}).get(slug)
        if d and d["total"]:
            out.append({"node": node, "name": nm.get(node, node if node != P.LOCAL else "console"),
                        "main": node == (a.get("node") or P.LOCAL), "t": an["t"], **d})
    out.sort(key=lambda x: not x["main"])
    return out


def series(slug, days=30):
    """Total occupé par l'appli sur sa machine principale, un point par jour (max du jour), en Go."""
    a = db.app(slug) or {}
    node = a.get("node") or P.LOCAL
    since = time.time() - days * 86400
    rows = db.q("SELECT (t / 86400) * 86400 d, max(total) tot, max(data) dat FROM stats_disk "
                "WHERE app = ? AND node = ? AND t >= ? GROUP BY d ORDER BY d", (slug, node, since))
    return [{"t": r["d"], "total": r["tot"], "data": r["dat"]} for r in rows]


def growth(slug, days=7):
    """Croissance moyenne par jour sur la période (octets), ou None sans assez de mesures."""
    s = series(slug, days + 1)
    if len(s) < 2:
        return None
    return (s[-1]["total"] - s[0]["total"]) / max(1, (s[-1]["t"] - s[0]["t"]) / 86400)


def purge():
    db.x("DELETE FROM stats_disk WHERE t < ?", (time.time() - KEEP_DAYS * 86400,))


def forget(slug):
    db.x("DELETE FROM stats_disk WHERE app = ?", (slug,))
