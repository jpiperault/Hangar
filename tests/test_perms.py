"""Droits par appli : ce qu'un compte « applis choisies » voit et peut faire."""
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

from app import db, perms
from app import platform as P

SAME = {"sec-fetch-site": "same-origin"}


def test_regles():
    perms.set_scopes("ana", {"jeu": "deployer", "site": "voir", "x": "n'importe quoi"})
    assert perms.scopes("ana") == {"jeu": "deployer", "site": "voir"}
    ok = lambda m, p: perms.refused(m, p, "ana") is None
    assert ok("GET", "/") and ok("GET", "/apps/jeu") and ok("GET", "/apps/site/logs") and ok("GET", "/compte")
    assert not ok("GET", "/apps/autre") and not ok("GET", "/settings") and not ok("GET", "/apps/jeu/db/export")
    assert ok("POST", "/apps/jeu/restart") and ok("POST", "/apps/jeu/version") and not ok("POST", "/apps/jeu/delete")
    assert not ok("POST", "/apps/site/restart") and not ok("POST", "/apps/jeu")          # « voir » ; réglages
    assert ok("POST", "/users/ana/password") and not ok("POST", "/users/bob/password") and ok("POST", "/logout")
    perms.forget_app("jeu")
    assert perms.scopes("ana") == {"site": "voir"}
    perms.forget_user("ana")
    assert perms.scopes("ana") == {}


@pytest.fixture
def client(app_row, monkeypatch):
    from app import main
    main._fails.clear()
    for s in ("mon-jeu", "autre"):
        db.x("DELETE FROM apps WHERE slug = ?", (s,))
    db.insert_app("mon-jeu", {**app_row, "state": "ok", "created_at": 0})
    db.insert_app("autre", {**app_row, "pkg": "", "name": "Autre appli", "state": "ok", "created_at": 0, "host_port": 18903})
    db.x("DELETE FROM users WHERE username = 'ana'")
    db.x("INSERT INTO users(username, hash, role) VALUES('ana', ?, 'appli')", (PasswordHasher().hash("mot-de-passe-ana"),))
    perms.set_scopes("ana", {"mon-jeu": "deployer"})
    spawned = []
    monkeypatch.setattr(P, "spawn", lambda fn, *a: spawned.append((fn.__name__, a)))
    monkeypatch.setattr(P, "apps_with_status", lambda: [{**a, "status": "running", "ram": 0, "urls": []} for a in db.apps()])
    c = TestClient(main.app, base_url="https://hangar.test", client=("127.0.0.1", 50030))
    c.post("/login", data={"username": "ana", "password": "mot-de-passe-ana"}, headers=SAME)
    yield c, spawned
    db.x("DELETE FROM sessions WHERE username = 'ana'")
    db.x("DELETE FROM users WHERE username = 'ana'")
    perms.forget_user("ana")
    for s in ("mon-jeu", "autre"):
        db.x("DELETE FROM apps WHERE slug = ?", (s,))


def test_parcours(client):
    c, spawned = client
    home = c.get("/").text
    assert "Mon jeu" in home and "Autre appli" not in home and 'href="/compte"' in home and 'href="/backups"' not in home
    assert c.get("/settings", follow_redirects=False).headers["location"] == "/"
    assert c.get("/apps/autre", follow_redirects=False).headers["location"] == "/"
    assert c.get("/compte").status_code == 200
    c.post("/apps/mon-jeu/restart", headers=SAME)
    assert spawned and spawned[-1][1] == ("mon-jeu",)
    c.post("/apps/autre/restart", headers=SAME)
    c.post("/apps/mon-jeu/delete", data={"confirm": "mon-jeu"}, headers=SAME)
    assert len(spawned) == 1 and db.app("mon-jeu") and db.app("autre")["state"] == "ok"
