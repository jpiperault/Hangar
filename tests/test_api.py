"""API à jetons et serveur MCP : authentification, portées, droits du compte, actions, journal."""
import importlib.machinery
import importlib.util
import json
import os
import time

import pytest

from app import apitokens, db, perms
from app import platform as P

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _app(slug, port):
    db.x("DELETE FROM apps WHERE slug = ?", (slug,))
    db.insert_app(slug, {"name": slug.title(), "pkg": "", "expose": "path", "sub": "", "source": "image", "image": "x/y",
                         "version": "1.0.0", "port": 8080, "host_port": port, "health_path": "/", "mem_mb": 256, "env": "SECRET=s",
                         "db": 0, "db_password": "", "state": "ok", "desired": "running", "created_at": time.time(),
                         "node": "local", "kind": "web"})


@pytest.fixture
def api(monkeypatch):
    from argon2 import PasswordHasher
    from fastapi.testclient import TestClient
    from app import main
    for u, role in (("apiadm", "admin"), ("apilec", "lecture"), ("apiapp", perms.ROLE)):
        db.x("INSERT OR REPLACE INTO users(username, hash, role) VALUES(?, ?, ?)", (u, PasswordHasher().hash("x" * 12), role))
    _app("api-a", 18061)
    _app("api-b", 18062)
    db.kv_set("user_apps", {"apiapp": {"api-a": "deployer"}})
    db.kv_set("api_tokens", [])
    monkeypatch.setattr(P, "apps_with_status", lambda: [{**dict(r), "status": "running"} for r in db.q("SELECT * FROM apps")])
    spawned = []
    monkeypatch.setattr(P, "spawn", lambda fn, *a: spawned.append((fn.__name__, a)))
    c = TestClient(main.app, base_url="https://hangar.test", client=("127.0.0.1", 50049))
    yield c, spawned
    for s in ("api-a", "api-b"):
        db.x("DELETE FROM apps WHERE slug = ?", (s,))
    db.kv_set("user_apps", {})
    db.kv_set("api_tokens", [])


def h(tok):
    return {"Authorization": f"Bearer {tok}"}


def test_jetons():
    db.x("INSERT OR REPLACE INTO users(username, hash, role) VALUES('jt', 'x', 'admin')")
    db.kv_set("api_tokens", [])
    tid, tok = apitokens.create("jt", "Claude", "deploy")
    assert tok.startswith("hgr_") and len(tok) > 40
    stored = json.dumps(db.kv_get("api_tokens"))
    assert tok not in stored                                                   # empreinte seulement
    assert apitokens.check(f"Bearer {tok}", "192.168.1.5")["scope"] == "deploy"
    assert apitokens.of_user("jt")[0]["last_ip"] == "192.168.1.5" and "hash" not in apitokens.of_user("jt")[0]
    assert apitokens.check("Bearer hgr_" + "x" * 43) is None and apitokens.check(tok) is None
    for bad in (("", "read"), ("ok", "admin"), ("a" * 61, "read")):
        with pytest.raises(ValueError):
            apitokens.create("jt", *bad)
    assert apitokens.revoke(tid, "autre") is False and apitokens.revoke(tid, "jt")
    assert apitokens.check(f"Bearer {tok}") is None
    db.x("DELETE FROM users WHERE username = 'jt'")


def test_authentification(api):
    c, _ = api
    assert c.get("/api/v1/apps").status_code == 401
    assert c.get("/api/v1/apps", headers=h("hgr_" + "a" * 43)).status_code == 401
    _, tok = apitokens.create("apiadm", "lecture", "read")
    r = c.get("/api/v1", headers=h(tok))
    assert r.status_code == 200 and r.json()["token"]["scope"] == "read"
    assert {a["slug"] for a in c.get("/api/v1/apps", headers=h(tok)).json()["apps"]} >= {"api-a", "api-b"}
    d = c.get("/api/v1/apps/api-a", headers=h(tok)).json()
    assert d["version"] == "1.0.0" and "env" not in d and "SECRET" not in json.dumps(d)   # jamais de secrets
    r = c.post("/api/v1/apps/api-a/deploy", headers=h(tok), json={"version": "2.0.0"})
    assert r.status_code == 403                                                # portée lecture
    lan = __import__("fastapi.testclient", fromlist=["TestClient"]).TestClient(c.app, base_url="https://hangar.test",
                                                                                client=("8.8.8.8", 5000))
    assert lan.get("/api/v1/apps", headers=h(tok)).status_code == 403          # réseau local seulement


def test_deploiement_et_droits(api):
    c, spawned = api
    _, tok = apitokens.create("apiadm", "ci", "deploy")
    r = c.post("/api/v1/apps/api-a/deploy", headers=h(tok), json={"version": "2.0.0"})
    assert r.status_code == 202 and spawned[-1] == ("deploy", ("api-a", "2.0.0", "update"))
    assert db.app("api-a")["state"] == "deploying"
    assert c.post("/api/v1/apps/api-a/restart", headers=h(tok)).status_code == 409   # déjà en cours
    assert c.post("/api/v1/apps/api-a/deploy", headers=h(tok), json={"version": "x y"}).status_code in (400, 409)
    audit = db.q("SELECT username, path, status FROM audit WHERE username LIKE 'api:%' ORDER BY id DESC LIMIT 3")
    assert audit[0]["username"] == "api:apiadm/ci"
    # compte « applis choisies » : ne voit que ses applis ; déploie seulement là où il en a le droit
    db.update_app("api-a", state="ok")
    _, t2 = apitokens.create("apiapp", "x", "deploy")
    assert [a["slug"] for a in c.get("/api/v1/apps", headers=h(t2)).json()["apps"]] == ["api-a"]
    assert c.get("/api/v1/apps/api-b", headers=h(t2)).status_code == 404
    assert c.post("/api/v1/apps/api-b/start", headers=h(t2)).status_code == 404
    assert c.post("/api/v1/apps/api-a/start", headers=h(t2)).status_code == 202
    # compte en lecture seule : même un jeton « deploy » ne change rien
    db.update_app("api-a", state="ok")
    _, t3 = apitokens.create("apilec", "x", "deploy")
    assert c.post("/api/v1/apps/api-a/start", headers=h(t3)).status_code == 403


def test_logs_et_trafic(api, monkeypatch):
    from app import applogs
    c, _ = api
    _, tok = apitokens.create("apiadm", "l", "read")
    monkeypatch.setattr(applogs, "read", lambda slug, period, q, err, limit=2000: (["ligne 1", "erreur 2"], 2, False))
    r = c.get("/api/v1/apps/api-a/logs?period=1h&q=err", headers=h(tok)).json()
    assert r == {"lines": ["ligne 1", "erreur 2"], "matched": 2, "truncated": False}
    t = c.get("/api/v1/apps/api-a/traffic?range=24h", headers=h(tok)).json()
    assert t["range"] == "24h" and "visitors" in t and isinstance(t["suspects"], list)
    assert c.get("/api/v1/apps/api-a/events", headers=h(tok)).status_code == 200


def test_page_jetons(api):
    from argon2 import PasswordHasher
    from fastapi.testclient import TestClient
    from app import main
    db.x("UPDATE users SET hash = ? WHERE username = 'apiadm'", (PasswordHasher().hash("mot-de-passe-adm"),))
    c = TestClient(main.app, base_url="https://hangar.test", client=("127.0.0.1", 50050))
    main._fails.clear()
    same = {"sec-fetch-site": "same-origin"}
    c.post("/login", data={"username": "apiadm", "password": "mot-de-passe-adm"}, headers=same, follow_redirects=False)
    r = c.post("/users/apiadm/api", data={"name": "Claude", "scope": "deploy"}, headers=same, follow_redirects=False)
    assert r.headers["location"].endswith("#api")
    page = c.get("/settings").text
    tok = page.split('class="mono" aria-label="Nouveau jeton"')[0].rsplit('value="', 1)[1].split('"')[0]
    assert tok.startswith("hgr_") and tok not in c.get("/settings").text      # affiché une seule fois
    assert "claude mcp add hangar" in page
    assert c.get("/outils/hangar-mcp").text.startswith("#!/usr/bin/env python3")
    tid = apitokens.of_user("apiadm")[0]["id"]
    c.post(f"/users/apiadm/api/{tid}/revoke", headers=same)
    assert not apitokens.of_user("apiadm")


def _mcp():
    path = os.path.join(ROOT, "deploy", "bin", "hangar-mcp")
    loader = importlib.machinery.SourceFileLoader("hangar_mcp", path)
    spec = importlib.util.spec_from_loader("hangar_mcp", loader)
    m = importlib.util.module_from_spec(spec)
    loader.exec_module(m)
    return m


def test_serveur_mcp(monkeypatch):
    m = _mcp()
    init = m.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})
    assert init["serverInfo"]["name"] == "hangar" and "tools" in init["capabilities"]
    assert m.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    names = {t["name"] for t in m.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["tools"]}
    assert names == {"list_apps", "app_status", "app_logs", "app_traffic", "deploy_app", "app_action"}
    calls = []
    monkeypatch.setattr(m, "api", lambda method, path, body=None: calls.append((method, path, body)) or {"events": [], "ok": 1})
    r = m.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "deploy_app", "arguments": {"slug": "blog", "version": "2.0"}}})
    assert not r["isError"] and calls[-1] == ("POST", "/apps/blog/deploy", {"version": "2.0"})
    m.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "app_logs", "arguments": {"slug": "blog", "errors_only": True}}})
    assert calls[-1][1].startswith("/apps/blog/logs?") and "errors=1" in calls[-1][1]
    r = m.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "app_status", "arguments": {"slug": "../x"}}})
    assert r["isError"] and "invalide" in r["content"][0]["text"]
    monkeypatch.delenv("HANGAR_TOKEN", raising=False)
    m2 = _mcp()
    with pytest.raises(m2.HangarError, match="HANGAR_TOKEN"):
        m2.api("GET", "/apps")
