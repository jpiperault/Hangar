"""Vérifications après déploiement : lecture des lignes, passage contre un petit serveur HTTP."""
import http.server
import threading

import pytest

from app import db, smoke
from app import platform as P


def test_lecture():
    assert smoke.parse("/\n\n# commentaire\n/api/v1/version 200 {version}\n/admin 302") == [
        {"path": "/", "status": 200, "contains": ""}, {"path": "/api/v1/version", "status": 200, "contains": "{version}"},
        {"path": "/admin", "status": 302, "contains": ""}]
    for bad in ("api sans barre", "/x 999", "\n".join(f"/{i}" for i in range(11))):
        with pytest.raises(ValueError):
            smoke.parse(bad)


@pytest.fixture
def serveur(monkeypatch):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            routes = {"/": (200, b"accueil"), "/api/v1/version": (200, b'{"version":"1.4.0"}'),
                      "/admin": (302, b""), "/host": (200, self.headers.get("Host", "").encode())}
            code, body = routes.get(self.path, (404, b"non"))
            self.send_response(code)
            if code == 302:
                self.send_header("Location", "/login")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setattr(P, "app_host", lambda a: "127.0.0.1")
    yield {"slug": "verif", "host_port": srv.server_address[1], "node": "local"}
    srv.shutdown()
    db.kv_set("smoke", {})


def test_passage(serveur):
    smoke.save("verif", "/\n/api/v1/version 200 {version}\n/admin 302\n/host 200 jeu.exemple.fr")
    ok, res = smoke.run(serveur, "1.4.0", host="jeu.exemple.fr", tries=1)
    assert ok and len(res) == 4 and smoke.summary(res) == "4 vérification(s) réussie(s)"
    ok, res = smoke.run(serveur, "1.5.0", host="jeu.exemple.fr", tries=1)          # mauvaise version servie
    assert not ok and "/api/v1/version" in smoke.summary(res) and "absent" in smoke.summary(res)
    smoke.save("verif", "/absente")
    ok, res = smoke.run(serveur, "1.4.0", tries=1)
    assert not ok and res[0]["why"] == "code 404 au lieu de 200"
    smoke.save("verif", "")
    assert smoke.run(serveur, "1.4.0") == (True, [])
