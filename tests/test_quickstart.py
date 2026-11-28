"""Démarrage rapide : un domaine et un jeton Cloudflare → tunnel créé et relié, domaine ajouté."""
import pytest

from app import cloudflare as CF
from app import db, quickstart
from app import domains as D
from app import platform as P


@pytest.fixture
def cf(monkeypatch, tmp_path):
    calls = []
    state = {"tunnels": []}

    def api(method, path, body=None, tok=None, params=None):
        calls.append((method, path, body, params))
        if path == "/zones":
            return [{"id": "z1", "account": {"id": "acc1"}}], {}
        if path.endswith("/cfd_tunnel") and method == "GET":
            return list(state["tunnels"]), {}
        if path.endswith("/cfd_tunnel") and method == "POST":
            state["tunnels"].append({"id": "tun1", "name": body["name"]})
            return {"id": "tun1"}, {}
        if path.endswith("/token"):
            return "eyJhIjoiYWNjMSIsInQiOiJ0dW4xIiwicyI6InNlY3JldCJ9", {}
        raise AssertionError(path)
    monkeypatch.setattr(CF, "_api", api)
    monkeypatch.setattr(CF, "verify", lambda tok: ["exemple.fr"] if tok == "bon-jeton" else (_ for _ in ()).throw(CF.CFError("refusé")))
    saved = {}
    monkeypatch.setattr(CF, "set_token", lambda tok: saved.setdefault("api", tok))
    monkeypatch.setattr(P, "TUNNEL_TOKEN", str(tmp_path / "token"))
    monkeypatch.setattr(P, "set_tunnel_token", lambda tok: saved.setdefault("tunnel", tok) and "tun1")
    monkeypatch.setattr(quickstart, "ensure_unit", lambda: saved.setdefault("unit", True))
    monkeypatch.setattr(P, "apply_routing", lambda: None)
    monkeypatch.setattr(P, "spawn", lambda fn, *a: None)
    db.x("DELETE FROM domains")
    yield calls, state, saved
    db.x("DELETE FROM domains")


def test_relier_un_domaine(cf):
    calls, state, saved = cf
    assert quickstart.connect("Blog.Exemple.fr.", "bon-jeton") == "blog.exemple.fr"   # sous-domaine d'une zone
    assert state["tunnels"][0]["name"] == quickstart.tunnel_name()
    assert saved == {"tunnel": "eyJhIjoiYWNjMSIsInQiOiJ0dW4xIiwicyI6InNlY3JldCJ9", "unit": True, "api": "bon-jeton"}
    d = D.get("blog.exemple.fr")
    assert d["mode"] == "tunnel" and d["hub"] == "apps" and d["is_default"]


def test_tunnel_existant_repris(cf):
    calls, state, saved = cf
    state["tunnels"].append({"id": "deja", "name": quickstart.tunnel_name()})
    quickstart.connect("exemple.fr", "bon-jeton")
    assert not any(m == "POST" for m, *_ in calls) and any("/cfd_tunnel/deja/token" in p for _, p, *_ in calls)


def test_refus(cf):
    with pytest.raises(ValueError, match="refuse"):
        quickstart.connect("exemple.fr", "mauvais")
    with pytest.raises(ValueError, match="zones visibles"):
        quickstart.connect("autre.com", "bon-jeton")
    with pytest.raises(ValueError, match="invalide"):
        quickstart.connect("pas un domaine", "bon-jeton")
    assert not D.all_domains()


def test_page(cf, monkeypatch):
    from argon2 import PasswordHasher
    from fastapi.testclient import TestClient
    from app import main
    db.x("INSERT OR REPLACE INTO users(username, hash) VALUES(?, ?)", ("qs", PasswordHasher().hash("mot-de-passe-qs")))
    c = TestClient(main.app, base_url="https://hangar.test", client=("127.0.0.1", 50046))
    main._fails.clear()
    same = {"sec-fetch-site": "same-origin"}
    c.post("/login", data={"username": "qs", "password": "mot-de-passe-qs"}, headers=same, follow_redirects=False)
    r = c.get("/demarrage")
    assert r.status_code == 200 and "Jeton d'API Cloudflare" in r.text and quickstart.tunnel_name() in r.text
    r = c.post("/demarrage/domaine", data={"domain": "exemple.fr", "token": "bon-jeton"}, headers=same, follow_redirects=False)
    assert r.headers["location"] == "/demarrage#appli"
    r = c.get("/demarrage")
    assert "Publier l&#39;exemple" in r.text or "Publier l'exemple" in r.text
