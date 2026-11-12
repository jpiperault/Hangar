"""Copies de sécurité : liste, purge (30 jours, 3 gardées), retour arrière depuis la fiche."""
import gzip
import os
import time

import pytest

from app import backup


@pytest.fixture
def safety(tmp_path, monkeypatch):
    monkeypatch.setattr(backup, "SAFETY", str(tmp_path))
    monkeypatch.setattr(backup.P, "log", lambda *a, **k: None)

    def make(slug, days_ago, db=True, data=True):
        name = f"{slug}-{time.strftime('%Y%m%d-%H%M%S', time.localtime(time.time() - days_ago * 86400))}"
        d = tmp_path / name
        d.mkdir()
        if db:
            with gzip.open(d / "base-avant.sql.gz", "wb") as f:
                f.write(b"SELECT 1;\n")
        if data:
            (d / "data").mkdir()
            (d / "data" / "a.txt").write_bytes(b"12345")
        return name
    return make


def test_liste(safety):
    a, b = safety("mon-jeu", 2), safety("autre", 1, db=False)
    cs = backup.safety_copies()
    assert [c["name"] for c in cs] == [b, a]
    assert cs[0]["has_db"] is False and cs[0]["has_data"] and cs[0]["size"] == 5
    assert [c["name"] for c in backup.safety_copies("mon-jeu")] == [a]
    assert backup.safety_copy(a)["slug"] == "mon-jeu"
    assert backup.safety_copy("../etc") is None and backup.safety_copy("mon-jeu-x") is None


def test_purge_garde_les_trois_dernieres(safety):
    vieux = [safety("mon-jeu", d) for d in (40, 50, 60, 70)]
    recent = safety("mon-jeu", 1)
    seul = safety("autre", 90)   # unique copie d'une appli : gardée même très vieille
    backup.purge_safety()
    reste = {c["name"] for c in backup.safety_copies()}
    assert reste == {recent, vieux[0], vieux[1], seul}


def test_suppression(safety):
    n = safety("mon-jeu", 1)
    backup.delete_safety("../" + n)
    assert backup.safety_copy(n)
    backup.delete_safety(n)
    assert backup.safety_copy(n) is None


def test_retour_arriere_web(safety, app_row, monkeypatch):
    from argon2 import PasswordHasher
    from fastapi.testclient import TestClient
    from app import db, main
    same = {"sec-fetch-site": "same-origin"}
    db.x("INSERT OR REPLACE INTO users(username, hash) VALUES(?, ?)", ("saf", PasswordHasher().hash("mot-de-passe-saf")))
    if not db.app(app_row["slug"]):
        db.insert_app(app_row["slug"], {**app_row, "state": "ok", "created_at": 0})
    db.update_app(app_row["slug"], state="ok")
    n = safety("mon-jeu", 1)
    c = TestClient(main.app, base_url="https://hangar.test", client=("127.0.0.1", 50002))
    main._fails.clear()
    c.post("/login", data={"username": "saf", "password": "mot-de-passe-saf"}, headers=same)
    seen = []
    monkeypatch.setattr(main.P, "spawn", lambda fn, *a: seen.append((fn.__name__, a)))
    r = c.post("/apps/mon-jeu/revert", data={"copy": n}, headers=same, follow_redirects=False)
    assert r.headers["location"] == "/apps/mon-jeu#securite" and not seen   # rien de coché
    r = c.post("/apps/mon-jeu/revert", data={"copy": "autre-20260101-000000", "db": "on"}, headers=same,
               follow_redirects=False)
    assert not seen
    r = c.post("/apps/mon-jeu/revert", data={"copy": n, "db": "on", "data": "on"}, headers=same, follow_redirects=False)
    assert r.headers["location"] == "/apps/mon-jeu"
    assert seen == [("revert", ("mon-jeu", n, ["db", "data"], "ok"))] and db.app("mon-jeu")["state"] == "deploying"
    db.update_app("mon-jeu", state="ok")
    r = c.post(f"/backups/safety/{n}/delete", data={"back": "app"}, headers=same, follow_redirects=False)
    assert r.headers["location"] == "/apps/mon-jeu#securite" and not os.path.exists(os.path.join(backup.SAFETY, n))
