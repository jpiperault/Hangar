"""Console web : en-têtes de sécurité, requêtes d'un autre site, connexion et limite d'essais."""
import re

import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

from app import db
from app import main

SAME = {"sec-fetch-site": "same-origin"}


@pytest.fixture(scope="module")
def client():
    db.x("INSERT OR REPLACE INTO users(username, hash) VALUES(?, ?)", ("admin", PasswordHasher().hash("bon-mot-de-passe")))
    return TestClient(main.app, base_url="https://hangar.test", client=("127.0.0.1", 50000))


def test_reserve_au_reseau_local():
    dehors = TestClient(main.app, base_url="https://hangar.test", client=("203.0.113.9", 50000))
    r = dehors.get("/login")
    assert r.status_code == 403 and "réseau local" in r.text


@pytest.fixture(autouse=True)
def rapide(monkeypatch):
    async def nosleep(*_a, **_k):
        return None
    monkeypatch.setattr(main.asyncio, "sleep", nosleep)
    main._fails.clear()


def test_entetes(client):
    r = client.get("/login")
    assert r.status_code == 200
    csp = r.headers["content-security-policy"]
    nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
    assert "unsafe-inline" not in csp.split("script-src")[1].split(";")[0]
    assert "frame-ancestors 'none'" in csp
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "same-origin"
    for tag in re.findall(r"<script[^>]*>", r.text):
        assert f'nonce="{nonce}"' in tag, tag
    assert not re.search(r"\son[a-z]+=", r.text), "gestionnaire d'événement en ligne (bloqué par la CSP)"


def test_pages_protegees(client):
    for url in ("/", "/apps", "/nodes", "/security", "/backups", "/settings"):
        r = client.get(url, follow_redirects=False)
        assert r.status_code in (302, 303) and r.headers["location"].endswith("/login"), url


@pytest.mark.parametrize("headers", [{"sec-fetch-site": "cross-site"}, {"sec-fetch-site": "same-site"},
                                     {"origin": "https://evil.example"}])
def test_requete_d_un_autre_site_refusee(client, headers):
    r = client.post("/login", data={"username": "admin", "password": "bon-mot-de-passe"}, headers=headers,
                    follow_redirects=False)
    assert r.status_code == 403


@pytest.mark.parametrize("headers", [SAME, {"sec-fetch-site": "none"}, {"origin": "https://hangar.test"}, {}])
def test_requete_du_meme_site_acceptee(client, headers):
    r = client.post("/login", data={"username": "admin", "password": "faux"}, headers=headers, follow_redirects=False)
    assert r.status_code == 303


def test_connexion_puis_deconnexion(client):
    r = client.post("/login", data={"username": "admin", "password": "bon-mot-de-passe"}, headers=SAME,
                    follow_redirects=False)
    assert r.headers["location"] == "/"
    assert client.get("/", follow_redirects=False).status_code == 200
    cookie = client.cookies.get("hangar")
    client.post("/logout", headers=SAME)
    client.cookies.set("hangar", cookie)   # vieux cookie rejoué : la session a été supprimée côté serveur
    assert client.get("/", follow_redirects=False).status_code in (302, 303)
    client.cookies.clear()


def test_limite_d_essais(client):
    for _ in range(main.LOGIN_MAX_IP):
        client.post("/login", data={"username": "admin", "password": "faux"}, headers=SAME)
    r = client.post("/login", data={"username": "admin", "password": "bon-mot-de-passe"}, headers=SAME,
                    follow_redirects=False)
    assert r.headers["location"].endswith("/login"), "le bon mot de passe ne doit plus passer après 5 échecs"
    client.cookies.clear()


def test_prompt_de_migration(client):
    client.post("/login", data={"username": "admin", "password": "bon-mot-de-passe"}, headers=SAME)
    r = client.get("/prompt/migration")
    assert r.status_code == 200 and "Kit de migration" in r.text and "&lt;!--" not in r.text
    assert '"<slug>"' in r.text or "&lt;slug&gt;" in r.text or "\\u003cslug\\u003e" in r.text
    client.cookies.clear()


def test_adresses_orphelines(app_row):
    from app import domains as D
    from app import platform as P
    D.set_routes("disparue", [{"kind": "sub", "domain": "exemple.fr", "sub": "disparue"}])
    assert "disparue" in P.drop_orphan_routes() and not D.routes("disparue")
