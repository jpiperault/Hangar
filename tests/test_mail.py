"""Messagerie (Stalwart du catalogue) : nom du serveur, ports publics, enregistrements DNS tenus chez Cloudflare."""
import base64
import json

import pytest

from app import cloudflare, db, gameports, mail
from app import platform as P


@pytest.fixture
def serveur(app_row):
    for t in ("apps", "routes", "domains"):
        db.x(f"DELETE FROM {t}")
    db.x("DELETE FROM nodes WHERE id = 'vps-m'")
    db.x("INSERT INTO nodes(id, name, address, ssh_port, ssh_user, wg_ip, state, created_at) "
         "VALUES('vps-m', 'VPS', '51.15.10.7', 22, 'root', '10.88.0.7', 'ok', 0)")
    db.insert_app("courrier", {**app_row, "kind": "tool", "state": "ok", "created_at": 0, "host_port": 18601,
                               "pkg": "", "node": "vps-m"})
    for k in ("mail_dns", "cf_mail_managed", "public_ports"):
        db.kv_set(k, {} if k != "cf_mail_managed" else [])
    mail.save("courrier", "mail.exemple.fr", "exemple.fr")
    yield
    db.x("DELETE FROM apps WHERE slug = 'courrier'")
    db.x("DELETE FROM nodes WHERE id = 'vps-m'")


def test_enregistrements_voulus(serveur):
    r = mail.records("courrier")
    assert r[0] == {"type": "A", "name": "mail.exemple.fr", "content": "51.15.10.7"}
    assert {"type": "MX", "name": "exemple.fr", "content": "mail.exemple.fr", "priority": 10} in r
    assert {"type": "TXT", "name": "_dmarc.exemple.fr", "content": mail.DMARC} in r
    db.x("UPDATE nodes SET address = '192.168.1.50' WHERE id = 'vps-m'")     # réseau local : pas d'A automatique
    assert [x["type"] for x in mail.records("courrier")] == ["MX", "TXT", "TXT"]


def test_controle_des_noms(serveur):
    assert "invalide" in mail.check("mail", "exemple.fr")
    assert "propre nom" in mail.check("exemple.fr", "exemple.fr")
    assert "déjà son courrier" in mail.check("mx.exemple.fr", "exemple.fr", "autre")
    assert mail.check("mail.exemple.fr", "exemple.fr", "courrier") is None
    assert mail.check("mail.autre.fr", "autre.fr", "autre") is None


def test_ports_publics_en_plus_du_web(serveur):
    ports = gameports.parse("tcp 25, tcp 465, tcp 587, tcp 993", "courrier", "vps-m")
    gameports.save("courrier", ports)
    assert P._ports(db.app("courrier"))[-4:] == ["25:25/tcp", "465:465/tcp", "587:587/tcp", "993:993/tcp"]
    with pytest.raises(ValueError, match="déjà ouvert"):         # un second serveur mail sur la même machine
        db.insert_app("courrier2", {**dict(db.app("courrier")), "host_port": 18602, "name": "Autre"})
        try:
            gameports.parse("tcp 25", "courrier2", "vps-m")
        finally:
            db.x("DELETE FROM apps WHERE slug = 'courrier2'")


class FakeCF:
    def __init__(self, recs):
        self.recs, self.calls, self.n = recs, [], 0

    def api(self, method, path, body=None, tok=None, params=None):
        self.calls.append((method, path, body))
        if method == "GET" and path == "/zones":
            return ([{"id": "z1", "name": "exemple.fr"}] if params["name"] == "exemple.fr" else []), {}
        if method == "GET":
            return list(self.recs), {"total_pages": 1}
        if method == "POST":
            self.n += 1
            self.recs.append({**body, "id": f"n{self.n}"})
        if method == "DELETE":
            self.recs[:] = [r for r in self.recs if r["id"] != path.rsplit("/", 1)[1]]
        if method == "PUT":
            rid = path.rsplit("/", 1)[1]
            self.recs[:] = [({**body, "id": rid} if r["id"] == rid else r) for r in self.recs]
        return {}, {}


def test_synchro_cloudflare(serveur, monkeypatch):
    cf = FakeCF([{"id": "w", "type": "A", "name": "exemple.fr", "content": "198.51.100.1", "comment": ""},
                 {"id": "s", "type": "TXT", "name": "exemple.fr", "content": '"v=spf1 include:_spf.google.com ~all"',
                  "comment": ""}])
    monkeypatch.setattr(cloudflare, "_api", cf.api)
    changes = []
    out = cloudflare._sync_mail({}, changes)["courrier"]
    st = {(r["type"], r["name"]): r for r in out}
    assert st[("A", "mail.exemple.fr")]["ok"] and st[("MX", "exemple.fr")]["ok"]
    assert st[("TXT", "exemple.fr")]["ok"] is False and "SPF existe déjà" in st[("TXT", "exemple.fr")]["msg"]
    a = next(r for r in cf.recs if r["name"] == "mail.exemple.fr")
    assert a["proxied"] is False and a["comment"] == cloudflare.MAIL_COMMENT
    assert any(r["id"] == "s" for r in cf.recs) and any(r["id"] == "w" for r in cf.recs)   # rien d'étranger touché
    # deuxième passage : rien à refaire
    cf.calls.clear()
    cloudflare._sync_mail({}, [])
    assert not [c for c in cf.calls if c[0] != "GET"]
    # la machine change d'adresse : l'A de Hangar suit
    db.x("UPDATE nodes SET address = '51.15.10.8' WHERE id = 'vps-m'")
    cloudflare._sync_mail({}, [])
    assert next(r for r in cf.recs if r["name"] == "mail.exemple.fr")["content"] == "51.15.10.8"
    # appli supprimée : seuls les enregistrements de Hangar partent
    mail.forget("courrier")
    cloudflare._sync_mail({}, [])
    assert sorted(r["id"] for r in cf.recs) == ["s", "w"] and db.kv_get("cf_mail_managed") == []


def test_mx_etranger_pas_ecrase(serveur, monkeypatch):
    cf = FakeCF([{"id": "m", "type": "MX", "name": "exemple.fr", "content": "mx.ovh.net", "priority": 5, "comment": ""}])
    monkeypatch.setattr(cloudflare, "_api", cf.api)
    out = {(r["type"], r["name"]): r for r in cloudflare._sync_mail({}, [])["courrier"]}
    assert out[("MX", "exemple.fr")]["ok"] is False and "ailleurs" in out[("MX", "exemple.fr")]["msg"]
    assert [r["content"] for r in cf.recs if r["type"] == "MX"] == ["mx.ovh.net"]


def test_installation_depuis_le_catalogue(monkeypatch):
    from argon2 import PasswordHasher
    from fastapi.testclient import TestClient
    from app import main
    from app.routes import apps as routes_apps
    db.x("INSERT OR IGNORE INTO domains(name, mode, hub, created_at) VALUES('exemple.fr', 'tunnel', 'apps', 0)")
    for t in ("apps", "routes"):
        db.x(f"DELETE FROM {t} WHERE slug IN ('stalwart', 'stalwart2')")
    db.kv_set("mail_dns", {})
    db.kv_set("public_ports", {})
    monkeypatch.setattr(routes_apps, "node_choices", lambda purpose="app": [{"id": "local", "name": "Console", "free": 2000}])
    spawned = []
    monkeypatch.setattr(main.P, "spawn", lambda fn, *a: spawned.append((fn, a)))
    monkeypatch.setattr(gameports, "busy", lambda node, ports: [])
    db.x("INSERT OR REPLACE INTO users(username, hash) VALUES(?, ?)", ("mel", PasswordHasher().hash("mot-de-passe-mel")))
    c = TestClient(main.app, base_url="https://hangar.test", client=("127.0.0.1", 50042))
    main._fails.clear()
    same = {"sec-fetch-site": "same-origin"}
    c.post("/login", data={"username": "mel", "password": "mot-de-passe-mel"}, headers=same)
    try:
        _installe(c, same, spawned)
    finally:
        for t in ("apps", "routes"):
            db.x(f"DELETE FROM {t} WHERE slug IN ('stalwart', 'stalwart2')")
        db.kv_set("mail_dns", {})
        db.kv_set("public_ports", {})


def _installe(c, same, spawned):
    page = c.get("/catalogue?app=stalwart").text
    assert 'name="mail_host"' in page and "mail.exemple.fr" in page
    form = {"app": "stalwart", "slug": "stalwart", "sub": "stalwart", "domain": "exemple.fr", "node": "local",
            "mail_domain": "exemple.fr", "mail_host": "stalwart.exemple.fr"}
    r = c.post("/catalogue/install", data=form, headers=same, follow_redirects=False)
    assert "catalogue" in r.headers["location"] and not db.app("stalwart")     # nom déjà pris par l'adresse web
    r = c.post("/catalogue/install", data={**form, "mail_host": "mail.exemple.fr", "mail_cf_token": "jeton"},
               headers=same, follow_redirects=False)
    assert r.headers["location"] == "/apps/stalwart"
    assert spawned[-1] == (mail.install, ("stalwart", "v1.1-alpine", "jeton"))   # déploiement puis assistant par l'API
    assert mail.needs_setup("stalwart") and "Configurer Stalwart" in c.get("/apps/stalwart").text
    a = db.app("stalwart")
    assert "STALWART_HOSTNAME=mail.exemple.fr" in a["env"] and "STALWART_PUBLIC_URL=https://stalwart.exemple.fr" in a["env"]
    assert "{" not in a["env"] and a["data_user"] == "2000:2000"
    assert "STALWART_RECOVERY_ADMIN=••••••" in P.mask_env(a["env"])          # compte temporaire masqué dans la fiche
    assert [p["port"] for p in gameports.of("stalwart")] == [25, 465, 993]
    assert mail.of("stalwart") == {"host": "mail.exemple.fr", "domain": "exemple.fr"}
    assert "Messagerie" in c.get("/apps/stalwart").text
    # un second serveur mail sur la même machine : ports déjà pris
    r = c.post("/catalogue/install", data={**form, "slug": "stalwart2", "sub": "stalwart2", "mail_domain": "autre.fr",
                                           "mail_host": "mail.autre.fr"}, headers=same, follow_redirects=False)
    assert "catalogue" in r.headers["location"] and not db.app("stalwart2")


def test_ports_deja_ecoutes(monkeypatch):
    out = ('tcp   LISTEN 0 100 127.0.0.1:25 0.0.0.0:* users:(("master",pid=338,fd=13))\n'
           'tcp   LISTEN 0 4096 0.0.0.0:993 0.0.0.0:* users:(("docker-proxy",pid=9,fd=7))\n'
           'udp   UNCONN 0 0 0.0.0.0:25 0.0.0.0:*\n')
    monkeypatch.setattr(P, "nsh", lambda node, cmd, timeout=120, input=None: (0, out))
    ports = [{"proto": "tcp", "port": p, "cport": p} for p in (25, 465, 993)]
    assert gameports.busy("vps", ports) == ["tcp 25 (master)", "tcp 993 (docker-proxy)"]
    monkeypatch.setattr(P, "nsh", lambda node, cmd, timeout=120, input=None: (255, ""))
    assert gameports.busy("vps", ports) == []


def test_deplacement_verifie_les_ports(serveur, monkeypatch):
    from app import move
    gameports.save("courrier", gameports.parse("tcp 25, tcp 993", "courrier", "vps-m"))
    monkeypatch.setattr(P, "nsh", lambda node, cmd, timeout=120, input=None:
                        (0, 'tcp LISTEN 0 100 127.0.0.1:25 0.0.0.0:* users:(("master",pid=3,fd=13))\n'))
    assert "postfix" in gameports.check_target("courrier", "local")

    def interdit(*a, **k):
        raise AssertionError("aucune commande Docker : refus avant la coupure")
    monkeypatch.setattr(P, "dk", interdit)
    move.move("courrier", "local")
    a = db.app("courrier")
    assert a["node"] == "vps-m" and a["state"] == "ok"
    monkeypatch.setattr(P, "nsh", lambda node, cmd, timeout=120, input=None: (0, ""))
    assert gameports.check_target("courrier", "local") is None
    gameports.save("courrier", [])
    assert gameports.check_target("courrier", "local") is None


def test_pas_de_haute_dispo_pour_un_serveur_mail(serveur):
    from app import ha
    assert "serveur mail" in ha.validate(db.app("courrier"), "standby", ["local"], False)



class FakeStalwart:
    """Le strict nécessaire de l'API de Stalwart en mode « premier démarrage »."""
    def __init__(self, cred, fail=None):
        import http.server
        import threading
        outer = self
        self.cred, self.fail, self.bodies = cred, fail, []

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj):
                b = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def _auth(self):
                want = "Basic " + base64.b64encode(outer.cred.encode()).decode()
                if self.headers.get("Authorization") != want:
                    self._send(401, {"status": 401})
                    return False
                return True

            def do_GET(self):
                if self._auth():
                    self._send(200, {"primaryAccounts": {"urn:stalwart:jmap": "d333333"}})

            def do_POST(self):
                if not self._auth():
                    return
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.bodies.append(body)
                call = body["methodCalls"][0]
                if outer.fail:
                    out = {"accountId": "d333333", "notUpdated": {"singleton": {"type": "invalidProperties",
                                                                                "description": outer.fail}}}
                else:
                    out = {"accountId": "d333333", "updated": {"singleton": {"username": "admin@exemple.fr",
                                                                             "secret": "permanent-123"}}}
                self._send(200, {"methodResponses": [[call[0], out, call[2]]]})

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


def _stalwart_app(port):
    db.x("DELETE FROM apps WHERE slug = 'stw'")
    db.insert_app("stw", {"name": "Stw", "pkg": "", "source": "image", "image": "stalwartlabs/stalwart",
                          "version": "v1.1-alpine", "port": 8080, "health_path": "/healthz/live", "mem_mb": 512,
                          "env": "STALWART_RECOVERY_ADMIN=admin:temp-456\nSTALWART_PUBLIC_URL=https://stw.exemple.fr",
                          "db": 0, "state": "ok", "desired": "running", "created_at": 0, "node": "local",
                          "kind": "tool", "host_port": port, "data_user": "2000:2000"})
    mail.save("stw", "mail.exemple.fr", "exemple.fr")


def test_configuration_par_l_api(monkeypatch):
    fake = FakeStalwart("admin:temp-456")
    deployed = []
    monkeypatch.setattr(P, "deploy", lambda slug, v, kind, previous=None: deployed.append((slug, kind)))
    monkeypatch.setattr(P, "apply_routing", lambda: None)
    try:
        _stalwart_app(fake.port)
        assert mail.needs_setup("stw")
        assert mail.setup("stw", "jeton-cf", "alice") is True
        sent = fake.bodies[0]["methodCalls"][0]
        assert sent[0] == "x:Bootstrap/set"
        b = sent[1]["update"]["singleton"]
        assert b["defaultHostname"] == "mail.exemple.fr" and b["defaultDomain"] == "exemple.fr"
        assert b["requestTlsCertificate"] and b["dnsServer"]["@type"] == "Cloudflare"
        assert b["dnsServer"]["secret"] == {"@type": "Value", "secret": "jeton-cf"} and b["tracer"]["@type"] == "Stdout"
        a = db.app("stw")
        assert "STALWART_RECOVERY_ADMIN" not in a["env"] and "STALWART_PUBLIC_URL" in a["env"]
        assert mail.admin_of("stw")["user"] == "admin@exemple.fr" and deployed == [("stw", "config")]
        assert not mail.needs_setup("stw") and mail.of("stw")["stalwart_dns"]
        assert "jeton-cf" not in json.dumps(db.kv_get("mail_dns"))           # le jeton ne fait que passer
        assert [r["type"] for r in mail.records("stw")] == ["MX", "TXT"]      # DMARC laissé à Stalwart
        mail.forget_admin("stw")
        assert not mail.admin_of("stw")
    finally:
        fake.close()
        db.x("DELETE FROM apps WHERE slug = 'stw'")
        mail.forget("stw")


def test_configuration_refusee(monkeypatch):
    fake = FakeStalwart("admin:autre")                 # mauvais compte temporaire
    monkeypatch.setattr(P, "deploy", lambda *a, **k: (_ for _ in ()).throw(AssertionError("pas de redémarrage")))
    try:
        _stalwart_app(fake.port)
        assert mail.setup("stw") is False
        assert "STALWART_RECOVERY_ADMIN" in db.app("stw")["env"] and mail.needs_setup("stw")
        fake.cred, fake.fail = "admin:temp-456", "Invalid server hostname"
        assert mail.setup("stw") is False
        b = fake.bodies[-1]["methodCalls"][0][1]["update"]["singleton"]
        assert not b["requestTlsCertificate"] and b["dnsServer"] == {"@type": "Manual"}
        ev = db.q("SELECT msg FROM events WHERE app = 'stw' ORDER BY id DESC LIMIT 1")[0]["msg"]
        assert "Invalid server hostname" in ev and "temp-456" not in ev
    finally:
        fake.close()
        db.x("DELETE FROM apps WHERE slug = 'stw'")
        mail.forget("stw")
