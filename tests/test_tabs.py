"""Fiche d'une appli : onglets essentiels, onglets en service affichés d'office, le reste dans « Plus »."""
import time

import pytest

from app import db


@pytest.fixture
def client(monkeypatch):
    from argon2 import PasswordHasher
    from fastapi.testclient import TestClient
    from app import main
    db.x("DELETE FROM apps WHERE slug = 'onglets'")
    db.insert_app("onglets", {"name": "Onglets", "pkg": "", "expose": "path", "sub": "", "source": "image",
                              "image": "ghcr.io/exemple/app", "version": "1.0.0", "port": 8080, "host_port": 18078,
                              "health_path": "/", "mem_mb": 256, "env": "", "db": 0, "db_password": "", "state": "ok",
                              "desired": "running", "created_at": time.time(), "node": "local", "kind": "web"})
    db.x("INSERT OR REPLACE INTO users(username, hash) VALUES(?, ?)", ("ong", PasswordHasher().hash("mot-de-passe-ong")))
    db.kv_set("ui_all_tabs", [])
    c = TestClient(main.app, base_url="https://hangar.test", client=("127.0.0.1", 50043))
    main._fails.clear()
    c.post("/login", data={"username": "ong", "password": "mot-de-passe-ong"}, headers={"sec-fetch-site": "same-origin"},
           follow_redirects=False)
    yield c
    db.x("DELETE FROM apps WHERE slug = 'onglets'")
    db.kv_set("jobs", {})


def bars(html):
    bar, rest = html.split('<details class="tabmore">', 1)
    return bar.split('<div class="tabbar">', 1)[1], rest.split("</details>", 1)[0]


def test_essentiel_puis_plus(client):
    bar, more = bars(client.get("/apps/onglets").text)
    for t in ("apercu", "reglages"):
        assert f'data-tab="{t}"' in bar
    assert "/apps/onglets/trafic" in bar and "/apps/onglets/logs" in bar
    for t in ("base", "hautedispo", "taches", "avance", "restauration", "acces", "vulns"):
        assert f'data-tab="{t}"' in more and f'data-tab="{t}"' not in bar, t
    assert 'data-tab="mobile"' not in more                                   # pas de client : pas d'onglet du tout


def test_onglet_en_service_affiche(client):
    db.update_app("onglets", db=1)
    db.kv_set("jobs", {"onglets": [{"id": "j1", "name": "essai", "cmd": "echo", "kind": "minutes", "every": 60, "at": "03:00", "dow": 0}]})
    bar, more = bars(client.get("/apps/onglets").text)
    assert 'data-tab="base"' in bar and 'data-tab="taches"' in bar and 'data-tab="base"' not in more
    db.kv_set("jobs", {})


def test_tous_les_onglets(client):
    r = client.post("/users/ong/onglets", data={"back": "/apps/onglets"}, headers={"sec-fetch-site": "same-origin"},
                    follow_redirects=False)
    assert r.headers["location"] == "/apps/onglets"
    bar, more = bars(client.get("/apps/onglets").text)
    assert 'data-tab="avance"' in bar and "data-tab" not in more and "seulement l&#39;essentiel" in more
    r = client.post("/users/ong/onglets", data={"back": "https://ailleurs.example/"}, headers={"sec-fetch-site": "same-origin"},
                    follow_redirects=False)
    assert r.headers["location"] == "/"                                        # retour seulement vers une fiche
    assert db.kv_get("ui_all_tabs") == []
