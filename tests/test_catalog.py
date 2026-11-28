"""Catalogue d'applis prêtes : modèles valides, variables remplies, installation par la console."""
import re

import pytest

from app import catalog, db, kinds
from app import platform as P


def test_modeles_valides():
    ids = set()
    for c in catalog.CATALOG:
        assert c["id"] not in ids and P.SLUG.match(c["id"]) and c["cat"] in catalog.CATS
        ids.add(c["id"])
        e = {"slug": c["id"], "name": c["name"], "source": "image", "image": c["image"], "version": c["version"],
             "port": c["port"], "mem_mb": c["mem"], "health_path": c["health"], "env": catalog.render_env(c["env"], {}),
             "db": 1 if c["db"] else 0, "kind": "tool"}
        assert P.check_app_entry(e) == [], (c["id"], P.check_app_entry(e))
        allowed = {"secret", "url", "url_noslash", "host", "db_url", "db_host", "db_port", "db_name", "db_user",
                   "db_password", "mysql_password", "mail_host"}
        assert set(re.findall(r"\{([a-z_]+)\}", c["env"])) <= allowed, c["id"]
    assert kinds.get("tool")["http"]


def test_variables():
    out = catalog.render_env("A={secret}\nB={secret}\nC={url}\nD={inconnue}", {"url": "https://x/"})
    a, b, c, d = [l.split("=", 1)[1] for l in out.splitlines()]
    assert len(a) == 64 and a != b and c == "https://x/" and d == "{inconnue}"


@pytest.mark.parametrize("cid", ["it-tools", "gitea"])
def test_installation(cid, monkeypatch):
    from argon2 import PasswordHasher
    from fastapi.testclient import TestClient
    from app import main
    from app.routes import apps as routes_apps
    db.x("INSERT OR IGNORE INTO domains(name, mode, hub, created_at) VALUES('exemple.fr', 'tunnel', 'apps', 0)")
    db.x("DELETE FROM apps WHERE slug = ?", (cid,))
    db.x("DELETE FROM routes WHERE slug = ?", (cid,))
    monkeypatch.setattr(routes_apps, "node_choices", lambda purpose="app": [{"id": "local", "name": "Console", "free": 2000}])
    spawned = []
    monkeypatch.setattr(main.P, "spawn", lambda fn, *a: spawned.append(a))
    db.x("INSERT OR REPLACE INTO users(username, hash) VALUES(?, ?)", ("cat", PasswordHasher().hash("mot-de-passe-cat")))
    c = TestClient(main.app, base_url="https://hangar.test", client=("127.0.0.1", 50041))
    main._fails.clear()
    same = {"sec-fetch-site": "same-origin"}
    c.post("/login", data={"username": "cat", "password": "mot-de-passe-cat"}, headers=same)
    assert c.get(f"/catalogue?app={cid}").status_code == 200
    r = c.post("/catalogue/install", data={"app": cid, "slug": cid, "name": "", "sub": cid, "domain": "exemple.fr",
                                           "node": "local"}, headers=same, follow_redirects=False)
    assert r.headers["location"] == f"/apps/{cid}", r.headers["location"]
    a = db.app(cid)
    assert a["kind"] == "tool" and a["image"] == catalog.get(cid)["image"] and spawned
    if cid == "gitea":
        assert f"GITEA__database__PASSWD={a['db_password']}" in a["env"] and "GITEA__server__ROOT_URL=https://gitea.exemple.fr/" in a["env"]
        assert "{" not in a["env"]
    r = c.post("/catalogue/install", data={"app": cid, "slug": cid, "sub": cid, "domain": "exemple.fr", "node": "local"},
               headers=same, follow_redirects=False)
    assert "catalogue" in r.headers["location"]                     # identifiant déjà pris : refusé
    db.x("DELETE FROM apps WHERE slug = ?", (cid,))
    db.x("DELETE FROM routes WHERE slug = ?", (cid,))


def test_modele_perso(app_row, monkeypatch):
    from app import domains as D
    from app import runopts
    db.kv_set("custom_catalog", None)
    a = {**app_row, "env": "JWT_SECRET=abc\nAPI_TOKEN=xyz\nPUBLIC_URL=https://jeu.exemple.fr/\nHOST=jeu.exemple.fr\nPRIX=10",
         "kind": "api", "data_user": ""}
    monkeypatch.setattr(D, "primary_url", lambda slug, *x, **k: "https://jeu.exemple.fr/")
    monkeypatch.setattr(runopts, "of", lambda slug: {"mounts": "www:/var/www/html", "command": "serve --port 8080"})
    t = catalog.from_app(a, "Mon modèle", "")
    assert t["env"] == "JWT_SECRET={secret}\nAPI_TOKEN={secret}\nPUBLIC_URL={url}\nHOST={host}\nPRIX=10"
    assert t["kind"] == "api" and t["run"] == {"command": "serve --port 8080"} and t["mounts"] == "www:/var/www/html"
    catalog.save_custom(t)
    assert catalog.get("perso-mon-jeu")["name"] == "Mon modèle" and catalog.items()[0]["custom"]
    out = catalog.render_env(t["env"], {"url": "https://autre.exemple.fr/", "host": "autre.exemple.fr"})
    assert "JWT_SECRET=abc" not in out and "PUBLIC_URL=https://autre.exemple.fr/" in out   # secret régénéré
    catalog.delete_custom("perso-mon-jeu")
    assert catalog.get("perso-mon-jeu") is None


def test_dossiers_du_catalogue():
    from app import runopts
    for c in catalog.CATALOG:
        runopts.parse_mounts(c.get("mounts", ""))
