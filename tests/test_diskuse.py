"""Espace disque par appli et par conteneur : rattachement des conteneurs et volumes, tableau de la machine."""
import time

from app import db, diskuse

RAW = {
    "disk": {"used": 10_000_000_000, "total": 50_000_000_000, "free": 40_000_000_000},
    "containers": [
        {"name": "app-blog-app-1", "state": "running", "app": "blog", "project": "app-blog", "image": "sha256:a",
         "image_name": "ghost:5", "rw": 5_000_000, "log": 1_000_000,
         "mounts": [{"t": "bind", "name": "", "src": "/srv/apps/blog/data", "dst": "/data"},
                    {"t": "volume", "name": "app-blog_www", "src": "/var/lib/docker/volumes/app-blog_www/_data",
                     "dst": "/var/www/html"}]},
        {"name": "app-blog-mysql-1", "state": "running", "app": "", "project": "app-blog", "image": "sha256:b",
         "image_name": "mariadb:11", "rw": 1000, "log": 2000, "mounts": []},
        {"name": "myrepl-blog", "state": "exited", "app": "", "project": "", "image": "sha256:b",
         "image_name": "mariadb:11", "rw": 0, "log": 0, "mounts": []},
        {"name": "platform-postgres-1", "state": "running", "app": "", "project": "platform", "image": "sha256:c",
         "image_name": "postgres:17", "rw": 300, "log": 700, "mounts": []},
    ],
    "volumes": {"app-blog_www": 200_000_000, "orphelin123": 50_000_000, "hangar-trivy-cache": 1_000_000_000},
    "dirs": {"blog": {"total": 120_001_000, "data": 100_000_000, "mysql": 20_000_000,
                      "data/.hangar-mysql": 4_000_000},
             "ancienne": {"total": 900}},              # copie des réglages seulement (console) : ignorée
    "images": {"sha256:a": {"size": 500_000_000, "tags": ["ghost:5"]},
               "sha256:b": {"size": 300_000_000, "tags": ["mariadb:11"]}},
    "df": {"Images": ["2GB", "1.2GB"], "Build Cache": ["300MB", "300MB"]},
    "pg": {"app_blog": 7_000_000, "postgres": 8_000_000},
    "pg_dir": 40_000_000,
    "backups": 4096,
}


def test_rattachement_par_appli():
    an = diskuse.analyse(RAW, {"blog", "ancienne"})
    assert set(an["apps"]) == {"blog"}
    b = an["apps"]["blog"]
    roles = {c["name"]: c["role"] for c in b["containers"]}
    assert roles == {"app-blog-app-1": "appli", "app-blog-mysql-1": "MySQL / MariaDB", "myrepl-blog": "réplique MySQL"}
    assert b["volumes"] == [{"name": "app-blog_www", "dst": "/var/www/html", "size": 200_000_000}]
    parts = {p["key"]: p["size"] for p in b["parts"]}
    # data/ sans l'export MySQL, qui a sa propre ligne ; la base dans le PostgreSQL partagé comptée à part
    assert parts["data"] == 96_000_000 and parts["mysql_export"] == 4_000_000 and parts["mysql"] == 20_000_000
    assert parts["db"] == 7_000_000 and parts["other"] == 1000
    assert b["total"] == 120_001_000 + 7_000_000 + 200_000_000 + 5_000_000 + 1_000_000 + 3000
    assert b["data"] == 100_000_000


def test_tableau_de_la_machine():
    an = diskuse.analyse(RAW, {"blog"})
    m = {r["label"]: r for r in an["machine"]}
    assert m["Images Docker"]["size"] == 2_000_000_000 and m["Images Docker"]["reclaim"] == 1_200_000_000
    assert m["Cache de build Docker"]["size"] == 300_000_000
    assert m["Cache de l'analyse des vulnérabilités"]["size"] == 1_000_000_000
    assert m["Volumes Docker orphelins"]["size"] == 50_000_000            # monté par aucun conteneur
    assert m["PostgreSQL partagé (hors bases d'applis)"]["size"] == 33_000_000
    assert m["Conteneurs hors applis"]["size"] == 1000
    known = an["apps_total"] + sum(r["size"] for r in an["machine"] if r["label"] != "Système et autres fichiers")
    assert m["Système et autres fichiers"]["size"] == 10_000_000_000 - known


def test_human():
    assert diskuse._human("340.3MB") == 340_300_000
    assert diskuse._human("1.5GB") == 1_500_000_000
    assert diskuse._human("0B") == 0 and diskuse._human("") == 0


def test_historique_croissance_et_oubli(monkeypatch, app_row):
    slug = app_row["slug"]
    node = app_row.get("node") or "local"
    now = time.time()
    for i, total in enumerate((1_000_000_000, 1_100_000_000, 1_300_000_000)):
        t = int((now - (2 - i) * 86400) // 3600 * 3600)
        db.x("INSERT OR REPLACE INTO stats_disk(app, node, t, total, data) VALUES(?, ?, ?, ?, ?)",
             (slug, node, t, total, total // 2))
    s = diskuse.series(slug)
    assert [x["total"] for x in s][-1] == 1_300_000_000
    g = diskuse.growth(slug)
    assert 140_000_000 < g < 160_000_000          # +300 Mo en deux jours
    diskuse.forget(slug)
    assert diskuse.series(slug) == []


def test_vue_appli_et_noeud(monkeypatch, app_row):
    slug = app_row["slug"]
    raw = {**RAW, "containers": [{**c, "app": slug if c["app"] == "blog" else c["app"],
                                  "project": c["project"].replace("blog", slug),
                                  "name": c["name"].replace("blog", slug)} for c in RAW["containers"]],
           "dirs": {slug: RAW["dirs"]["blog"]}, "pg": {}}
    an = diskuse.analyse(raw, {slug})
    an["t"] = time.time()
    node = app_row.get("node") or "local"
    monkeypatch.setattr(diskuse, "_machines", lambda: [node])
    db.kv_set(f"diskuse:{node}", an)
    try:
        v = diskuse.app_view(slug)
        assert v and v[0]["main"] and v[0]["total"] == an["apps"][slug]["total"]
        nv = diskuse.node_view(node)
        assert nv["rows"] == sorted(nv["rows"], key=lambda r: -r["size"])
        assert any(r.get("slug") == slug for r in nv["rows"])
    finally:
        db.x("DELETE FROM kv WHERE key = ?", (f"diskuse:{node}",))
