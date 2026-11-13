"""Applis Android : configuration à distance et rapports de plantage."""
import http.server
import json
import threading
import urllib.error
import urllib.request

import pytest

from app import crashes, db, remoteconfig

TRACE = """java.lang.IllegalStateException: partie introuvable
\tat fr.exemple.jeu.GameRepo.load(GameRepo.kt:42)
\tat fr.exemple.jeu.GameScreen.onStart(GameScreen.kt:17)
\tat android.app.Activity.performStart(Activity.java:8000)"""


@pytest.fixture
def appli(app_row, monkeypatch):
    if not db.app("mon-jeu"):
        db.insert_app("mon-jeu", {**app_row, "state": "ok", "created_at": 0})
    db.update_app("mon-jeu", pkg="fr.exemple.jeu")
    db.x("DELETE FROM crashes"), db.x("DELETE FROM crash_groups")
    db.kv_set("remote_config", {})
    sent = []
    monkeypatch.setattr(crashes.alerts, "send", lambda title, *a, **k: sent.append(title))
    monkeypatch.setattr(crashes.P, "log", lambda *a, **k: None)
    yield sent


def test_interrupteurs():
    assert remoteconfig.parse_flags("a = true\nb=8\nc = 1.5\nd = hiver\n# x\ne = non") == \
        {"a": True, "b": 8, "c": 1.5, "d": "hiver", "e": False}
    for bad in ("Majuscule = 1", "sans egal", "x = " + "y" * 600):
        with pytest.raises(ValueError):
            remoteconfig.parse_flags(bad)


def test_configuration(appli):
    with pytest.raises(ValueError, match="plus ancienne"):
        remoteconfig.save("mon-jeu", {"min_code": "20", "rec_code": "10"})
    remoteconfig.save("mon-jeu", {"min_code": "12", "rec_code": "15", "flags": "nouveau_menu = true",
                                  "message": "Maintenance dimanche", "level": "warn", "until": "2099-01-01"})
    c = remoteconfig.build(db.app("mon-jeu"), "https://jeu.exemple.fr/", "apps.exemple.fr")
    assert c["min_version_code"] == 12 and c["recommended_version_code"] == 15 and c["flags"] == {"nouveau_menu": True}
    assert c["message"] == {"text": "Maintenance dimanche", "level": "warn", "until": "2099-01-01"}
    assert c["crash_url"] == "https://apps.exemple.fr/.well-known/hangar/crash/fr.exemple.jeu" and c["crash_key"]
    remoteconfig.save("mon-jeu", {"message": "vieux", "until": "2000-01-01"})
    assert remoteconfig.build(db.app("mon-jeu"), "u", "h")["message"] is None   # annonce terminée
    files = remoteconfig.files("exemple.fr", "apps.exemple.fr", {"fr.exemple.jeu": "https://jeu.exemple.fr/"})
    assert list(files) == ["exemple.fr/.well-known/apps/fr.exemple.jeu.json"]


def test_regroupement_et_regression(appli):
    data = {"exception": "java.lang.IllegalStateException", "message": "partie 3 introuvable", "stacktrace": TRACE,
            "version_code": 12, "version_name": "1.2"}
    fp1 = crashes.record("mon-jeu", "fr.exemple.jeu", data)
    fp2 = crashes.record("mon-jeu", "fr.exemple.jeu", {**data, "message": "partie 9 introuvable",
                                                       "stacktrace": TRACE.replace(":42", ":43")})
    assert fp1 == fp2 and appli == ["Mon jeu : nouveau plantage Android"]          # même groupe, une alerte
    g = crashes.groups("mon-jeu")[0]
    assert g["count"] == 2 and g["top"] == "fr.exemple.jeu.GameRepo.load"
    crashes.set_status("mon-jeu", fp1, "resolved")
    crashes.record("mon-jeu", "fr.exemple.jeu", data)                              # même version : pas une régression
    assert crashes.groups("mon-jeu")[0]["status"] == "resolved"
    crashes.record("mon-jeu", "fr.exemple.jeu", {**data, "version_code": 13})
    assert crashes.groups("mon-jeu")[0]["status"] == "open" and appli[-1] == "Mon jeu : un plantage corrigé revient"


def test_point_d_envoi(appli):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), crashes._Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}/.well-known/hangar/crash/"

    def post(pkg, body, key):
        req = urllib.request.Request(base + pkg, data=body, method="POST",
                                     headers={"Content-Type": "application/json", "X-Hangar-Key": key})
        try:
            return urllib.request.urlopen(req, timeout=5).status
        except urllib.error.HTTPError as e:
            return e.code
    k = crashes.key("mon-jeu")
    ok = json.dumps({"exception": "E", "stacktrace": TRACE}).encode()
    assert post("fr.exemple.jeu", ok, k) == 204
    assert post("fr.exemple.jeu", ok, "mauvaise") == 403
    assert post("fr.inconnu.app", ok, k) == 404
    assert post("fr.exemple.jeu", b"pas du json", k) == 400
    assert post("fr.exemple.jeu", b"x" * (crashes.MAX_BODY + 1), k) == 413
    crashes._rate.clear()
    srv.shutdown()
    assert db.one("SELECT count(*) n FROM crashes")["n"] == 1


def test_ios_et_web(appli):
    db.update_app("mon-jeu", ios_bundle="fr.exemple.jeu.ios", web_client=1)
    remoteconfig.save("mon-jeu", {"min_code": "12", "ios_min": "300", "ios_rec": "310",
                                  "ios_store": "https://apps.apple.com/app/id1"})
    a = db.app("mon-jeu")
    ios = remoteconfig.build(a, "https://jeu.exemple.fr/", "apps.exemple.fr", "ios")
    assert ios["min_version_code"] == 300 and ios["store_url"].startswith("https://apps.apple.com")
    assert ios["crash_url"].endswith("/crash/fr.exemple.jeu.ios")
    web = json.loads(remoteconfig.web_files()["_clients/mon-jeu.json"])
    assert web["platform"] == "web" and web["crash_url"] == "/.well-known/hangar/crash" and "min_version_code" not in web
    assert "hangar-client.js" in "".join(remoteconfig.web_files())
    with pytest.raises(ValueError):
        remoteconfig.save("mon-jeu", {"ios_store": "http://ailleurs"})
    db.update_app("mon-jeu", ios_bundle="", web_client=0)


def test_empreintes_web_et_ios():
    js1 = "TypeError: x is null\n    at score (https://jeu.exemple.fr/assets/index-3f9a2b7c.js:42:17)\n    at onClick (https://jeu.exemple.fr/assets/index-3f9a2b7c.js:10:3)"
    js2 = js1.replace("3f9a2b7c", "aa11bb22").replace(":42:17", ":44:2")                  # nouveau build
    ff = "score@https://jeu.exemple.fr/assets/index-3f9a2b7c.js:42:17\nonClick@https://jeu.exemple.fr/assets/index-3f9a2b7c.js:10:3"
    f1, top = crashes.fingerprint("TypeError", js1, "mon-jeu", "web")
    assert f1 == crashes.fingerprint("TypeError", js2, "mon-jeu", "web")[0] and "score" in top
    assert crashes.fingerprint("TypeError", ff, "mon-jeu", "web")[0] != f1                # autre navigateur : autre groupe
    ios = "0   CoreFoundation 0x1a2b __exceptionPreprocess + 164\n3   Jeu 0x10045 Jeu.GameVC.load() + 88"
    assert crashes.fingerprint("NSRangeException", ios, "fr.exemple.jeu", "ios")[1]


def test_point_d_envoi_ios_et_web(appli):
    db.update_app("mon-jeu", ios_bundle="fr.exemple.jeu.ios", web_client=1)
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), crashes._Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}/.well-known/hangar/crash/"
    k = crashes.key("mon-jeu")
    body = json.dumps({"exception": "TypeError", "stacktrace": "at f (https://x/a.js:1:1)"}).encode()
    for path in ("fr.exemple.jeu.ios", "web/mon-jeu"):
        req = urllib.request.Request(base + path, data=body, method="POST",
                                     headers={"Content-Type": "application/json", "X-Hangar-Key": k})
        assert urllib.request.urlopen(req, timeout=5).status == 204
    srv.shutdown()
    crashes._rate.clear()
    assert sorted(r["platform"] for r in db.q("SELECT platform FROM crashes")) == ["ios", "web"]
    db.update_app("mon-jeu", ios_bundle="", web_client=0)


def test_caddy_client_web(app_row, monkeypatch):
    import shutil
    import subprocess
    from app import domains as D
    from app import platform as P
    if not shutil.which("caddy"):
        pytest.skip("caddy absent")
    db.x("INSERT OR IGNORE INTO domains(name, mode, hub, created_at) VALUES('exemple.fr', 'tunnel', 'apps', 0)")
    if not db.app("mon-jeu"):
        db.insert_app("mon-jeu", {**app_row, "state": "ok", "created_at": 0})
    db.update_app("mon-jeu", web_client=1)
    D.set_routes("mon-jeu", [{"kind": "sub", "domain": "exemple.fr", "sub": "jeu"}])
    conf = P.render_caddyfile({**db.settings(), "tunnel_bind": "127.0.0.1:8080"}, db.apps())
    assert "rewrite * /.well-known/hangar/crash/web/mon-jeu" in conf and "rewrite * /mon-jeu.json" in conf
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".caddy", delete=False) as fh:
        fh.write(conf)
    r = subprocess.run(["caddy", "validate", "--config", fh.name, "--adapter", "caddyfile"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-400:]
    db.update_app("mon-jeu", web_client=0)
    D.set_routes("mon-jeu", [])
