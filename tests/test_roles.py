"""Comptes en lecture seule et journal des actions."""
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

from app import db, main

SAME = {"sec-fetch-site": "same-origin"}


def _client(name, role, port):
    db.x("INSERT OR REPLACE INTO users(username, hash, role) VALUES(?, ?, ?)", (name, PasswordHasher().hash("mot-de-passe-" + name), role))
    c = TestClient(main.app, base_url="https://hangar.test", client=("127.0.0.1", port))
    main._fails.clear()
    assert c.post("/login", data={"username": name, "password": "mot-de-passe-" + name}, headers=SAME,
                  follow_redirects=False).headers["location"] == "/"
    return c


@pytest.fixture
def lecteur():
    db.x("DELETE FROM audit")
    return _client("lecteur", "lecture", 50021)


def test_lecture_seule_refuse_les_actions(lecteur):
    r = lecteur.get("/settings")
    assert r.status_code == 200 and "lecture seule" in r.text
    r = lecteur.post("/system/check", headers={**SAME, "referer": "https://hangar.test/system"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/system"
    assert "réservée aux administrateurs" in lecteur.get("/system").text
    r = lecteur.get("/backups/archive/hangar-20260101-000000.tar.gz/download", follow_redirects=False)
    assert r.status_code == 303                                   # pas d'archive (secrets) pour un lecteur
    rows = db.q("SELECT * FROM audit WHERE username = 'lecteur' AND status = 403")
    assert {r["path"] for r in rows} >= {"/system/check", "/backups/archive/hangar-20260101-000000.tar.gz/download"}


def test_lecteur_change_son_mot_de_passe_mais_pas_les_droits(lecteur):
    r = lecteur.post("/users/lecteur/password", data={"current": "mot-de-passe-lecteur", "password": "nouveau-mdp-123",
                                                       "password2": "nouveau-mdp-123"}, headers=SAME, follow_redirects=False)
    assert r.headers["location"] == "/settings#comptes"
    assert "changé" in lecteur.get("/settings").text
    lecteur.post("/users/lecteur/role", data={"role": "admin"}, headers=SAME)
    assert db.one("SELECT role FROM users WHERE username = 'lecteur'")["role"] == "lecture"


def test_admin_trace_et_dernier_admin():
    db.x("DELETE FROM users WHERE role = 'admin' AND username != 'chef'")
    c = _client("chef", "admin", 50022)
    c.post("/users/chef/role", data={"role": "lecture"}, headers=SAME)
    assert db.one("SELECT role FROM users WHERE username = 'chef'")["role"] == "admin"   # dernier administrateur
    assert db.one("SELECT 1 FROM audit WHERE username = 'chef' AND path = '/users/chef/role'")
    assert "Journal des actions" in c.get("/settings/audit").text
