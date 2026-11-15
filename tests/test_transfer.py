"""Transfert d'un nœud entre deux consoles : demande, contrôles, paquet chiffré, cession sans arrêt, reprise."""
import base64
import json
import time

import pytest

from app import crypt, db, nodes, transfer
from app import platform as P

KEY_B = "ssh-ed25519 " + "B" * 68 + " hangar@console"
KEY_A = "ssh-ed25519 " + "A" * 68 + " hangar@console"
WG_B = "W" * 43 + "="
WG_NODE = "N" * 43 + "="


@pytest.fixture
def console(monkeypatch, tmp_path):
    """Console d'essai : clés factices, dossiers jetables, aucune commande réelle sur une machine."""
    monkeypatch.setattr(P, "APPS_DIR", str(tmp_path / "apps"))
    monkeypatch.setattr(transfer, "DIR", str(tmp_path / "transferts"))
    monkeypatch.setattr(nodes, "pubkey", lambda: KEY_A)
    monkeypatch.setattr(nodes, "ensure_key", lambda: KEY_A)
    monkeypatch.setattr(nodes, "ensure_local", lambda: None)
    monkeypatch.setattr(nodes, "_wg_alive", lambda n, within=200: True)
    monkeypatch.setattr(nodes, "apply_mesh", lambda: None)
    monkeypatch.setattr(P, "apply_routing", lambda: None)
    monkeypatch.setattr(P, "spawn", lambda fn, *a: None)

    def no_docker(*a, **k):
        raise AssertionError("aucune commande Docker pendant un transfert côté cédant")
    monkeypatch.setattr(P, "dk", no_docker)
    for t in ("apps", "nodes", "routes", "domains", "app_history", "kv"):
        try:
            db.x(f"DELETE FROM {t}")
        except Exception:
            pass
    db.x("INSERT INTO nodes(id, name, address, wg_ip, wg_pubkey, state, created_at) VALUES('local', 'console', "
         "'192.168.1.2', '10.88.0.1', ?, 'ok', 0)", (WG_B,))
    yield tmp_path


def _node(nid="vps-1", ip="10.88.0.2", address="203.0.113.5"):
    db.x("INSERT INTO nodes(id, name, address, ssh_port, ssh_user, wg_ip, wg_pubkey, state, created_at) "
         "VALUES(?, ?, ?, 22, 'root', ?, ?, 'ok', 0)", (nid, nid.upper(), address, ip, WG_NODE))


def _app(slug, node="vps-1", port=18001):
    db.insert_app(slug, {"name": slug.title(), "pkg": "", "expose": "path", "sub": "", "source": "image",
                         "image": "ghcr.io/exemple/app", "version": "1.0.0", "port": 8080, "host_port": port,
                         "health_path": "/", "mem_mb": 256, "env": "SECRET=abc", "db": 1,
                         "db_password": "a1b2c3d4e5f6a7b8", "state": "ok", "desired": "running",
                         "created_at": time.time(), "node": node, "kind": "web"})


def _req(**over):
    r = {"v": 1, "nonce": "0" * 32, "created": time.time(), "console": "console-b", "ssh_key": KEY_B,
         "wg_pubkey": WG_B, "ips": ["10.88.0.1"], "ports": [], "slugs": [], "nodes": ["local"], "addresses": [],
         "domains": []}
    r.update(over)
    return transfer.REQ_PREFIX + base64.urlsafe_b64encode(json.dumps(r).encode()).decode()


def test_demande_aller_retour(console, monkeypatch):
    _node()
    _app("blog")
    monkeypatch.setattr(nodes, "pubkey", lambda: KEY_B)       # préparée sur B…
    text = transfer.make_request()
    assert transfer.pending_request()["text"] == text
    monkeypatch.setattr(nodes, "pubkey", lambda: KEY_A)       # … lue sur A
    req = transfer.parse_request(text[:40] + "\n  " + text[40:])   # coupée en deux par un copier-coller : acceptée
    assert req["slugs"] == ["blog"] and req["ports"] == [18001] and "10.88.0.2" in req["ips"]
    assert req["ssh_key"] == KEY_B and req["wg_pubkey"] == WG_B


@pytest.mark.parametrize("text, msg", [
    ("bonjour", "n'est pas une demande"),
    (transfer.REQ_PREFIX + "%%%", "illisible"),
])
def test_demande_refusee(console, text, msg):
    with pytest.raises(ValueError, match=msg):
        transfer.parse_request(text)


def test_demande_expiree_ou_de_soi_meme(console):
    with pytest.raises(ValueError, match="expirée"):
        transfer.parse_request(_req(created=time.time() - 8 * 86400))
    with pytest.raises(ValueError, match="cette console-ci"):
        transfer.parse_request(_req(ssh_key=KEY_A))
    with pytest.raises(ValueError, match="clés"):
        transfer.parse_request(_req(ssh_key="ssh-rsa AAAA"))


def test_controles(console):
    _node()
    _app("blog")
    _app("shop", port=18002)
    req = transfer.parse_request(_req(slugs=["shop"], ports=[18001], ips=["10.88.0.1", "10.88.0.2"]))
    c = transfer.check("vps-1", req)
    assert any("shop" in e and "existe déjà" in e for e in c["errors"])
    blog = next(a for a in c["apps"] if a["slug"] == "blog")
    assert any("port interne" in x for x in blog["notes"])
    assert c["ip"] == "10.88.0.3"                           # 10.88.0.2 pris là-bas
    c2 = transfer.check("vps-1", transfer.parse_request(_req()))
    assert c2["ip"] == "10.88.0.2" and not c2["errors"]     # même adresse privée si elle est libre là-bas


def test_controles_haute_dispo(console, monkeypatch):
    _node()
    from app import ha
    monkeypatch.setattr(ha, "participants", lambda: {"vps-1"})
    c = transfer.check("vps-1", transfer.parse_request(_req()))
    assert any("haute dispo" in e for e in c["errors"])


def test_cession_puis_reprise(console, monkeypatch):
    _node()
    _app("blog")
    _app("ailleurs", node="local", port=18005)
    db.kv_set("app_limits", {"blog": {"cpus": 1.5}, "ailleurs": {"cpus": 2}})
    db.kv_set("jobs", {"blog": [{"id": "j1", "cmd": "echo"}]})
    db.kv_set("user_apps", {"alice": {"blog": "viewer"}})
    calls = []

    def fake_ssh(n, cmd, timeout=60, input=None, via_wg=True):
        calls.append((cmd, input))
        return 0, ""
    monkeypatch.setattr(nodes, "ssh", fake_ssh)
    req = transfer.parse_request(_req())
    res = transfer.cede("vps-1", req, "admin")
    # A : clé de B autorisée, puis bascule du réseau privé programmée ; nœud et appli oubliés, l'autre appli intacte
    assert KEY_B.split()[1] in calls[0][1] and 'from="10.88.0.1"' in calls[0][1]
    assert "hangar-transfer-wg" in calls[1][0] and WG_B in calls[1][1] and "Address = 10.88.0.2/24" in calls[1][1]
    assert not db.app("blog") and db.app("ailleurs") and not nodes.get("vps-1")
    assert db.kv_get("app_limits") == {"ailleurs": {"cpus": 2}} and db.kv_get("jobs") == {}
    assert db.kv_get("user_apps") == {}
    assert transfer.ceded()[0]["code"] == res["code"]
    path = transfer.package_path("vps-1")
    raw = open(path, "rb").read()
    assert b"a1b2c3d4e5f6a7b8" not in raw and b"SECRET" not in raw      # chiffré

    # B : même base d'essai, vidée de ce que A connaissait encore ; la demande en attente est celle du paquet
    db.x("DELETE FROM apps")
    db.kv_set("transfer_request", {"nonce": "0" * 32, "created": time.time(), "text": "x"})
    with pytest.raises(ValueError, match="Code incorrect"):
        transfer.read_package(path, "MAUVA-ISCOD-E0000-00000")
    deployed, removed = [], []
    monkeypatch.setattr(P, "run", lambda args, **k: (0, ""))

    def fake_install(nid, sudo_password=""):
        nodes._update(nid, state="ok")
    monkeypatch.setattr(nodes, "install", fake_install)
    monkeypatch.setattr(P, "deploy", lambda slug, v, kind: deployed.append((slug, v, kind)))
    from app import segment
    monkeypatch.setattr(segment, "push", lambda nid: [])

    def fake_ssh_b(n, cmd, timeout=60, input=None, via_wg=True):
        removed.append(input)
        return 0, ""
    monkeypatch.setattr(nodes, "ssh", fake_ssh_b)
    ran = []
    monkeypatch.setattr(P, "spawn", lambda fn, *a: ran.append((fn, a)))
    nid = transfer.takeover(path, res["code"].lower(), "admin")
    assert nid == "vps-1" and nodes.get(nid)["wg_ip"] == "10.88.0.2" and nodes.get(nid)["wg_pubkey"] == WG_NODE
    assert not transfer.pending_request()          # demande consommée : le paquet ne resert pas
    fn, args = ran[0]
    fn(*args)
    a = db.app("blog")
    assert a and a["node"] == "vps-1" and a["env"] == "SECRET=abc" and a["db_password"] == "a1b2c3d4e5f6a7b8"
    assert a["host_port"] == 18001
    assert db.kv_get("app_limits")["blog"] == {"cpus": 1.5} and db.kv_get("jobs")["blog"][0]["id"] == "j1"
    assert deployed == [("blog", "1.0.0", "config")]
    assert removed and removed[-1].strip() == KEY_A.split()[1]     # clé de l'ancienne console retirée du nœud
    assert not db.kv_get("transfer_in:vps-1") and nodes.get(nid)["state"] == "ok"


def test_paquet_pour_une_autre_demande(console, tmp_path):
    pkg = {"v": 1, "kind": "hangar-noeud", "nonce": "1" * 32, "node": {}, "apps": []}
    clear, enc = tmp_path / "p.json", tmp_path / "p.hangar-noeud"
    clear.write_text(json.dumps(pkg))
    crypt.encrypt_file(str(clear), str(enc), "CODE1-CODE2-CODE3-CODE4")
    db.kv_set("transfer_request", {"nonce": "0" * 32, "created": time.time(), "text": "x"})
    with pytest.raises(ValueError, match="demande de reprise en cours"):
        transfer.read_package(str(enc), "code1-code2-code3-code4")


def test_reprise_sans_lien_reseau(console, monkeypatch):
    db.kv_set("transfer_in:vps-9", {"apps": [], "node": {"wg_ip": "10.88.0.9"}, "from": "a", "old_key": "x"})
    _node("vps-9", "10.88.0.9", "203.0.113.9")
    monkeypatch.setattr(nodes, "_wg_alive", lambda n, within=200: False)
    monkeypatch.setattr(transfer.time, "sleep", lambda s: None)
    transfer.resume("vps-9")
    n = nodes.get("vps-9")
    assert n["state"] == "error" and "réseau privé" in n["error"]
    transfer.abandon("vps-9")
    assert not nodes.get("vps-9") and not db.kv_get("transfer_in:vps-9")
