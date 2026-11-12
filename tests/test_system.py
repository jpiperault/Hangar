"""Mises à jour système : commandes envoyées aux nœuds, recensement, page par machine."""
import pytest

from app import db, system
from app import platform as P


def test_commande_distante(monkeypatch):
    seen = []
    monkeypatch.setattr(P, "nsh", lambda node, cmd, timeout=120, input=None: seen.append((node, cmd)) or (0, ""))
    system._apt("n1", "install", "--only-upgrade", "caddy")
    node, cmd = seen[0]
    assert node == "n1"
    assert cmd.startswith("DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get -q -y ")
    assert cmd.endswith("install --only-upgrade caddy") and "PATH=" not in cmd   # pas tout l'environnement local
    system._x("n1", ["dpkg-query", "-W", "-f", "${Version}", "docker-ce"])
    assert seen[1][1] == "dpkg-query -W -f '${Version}' docker-ce"


def test_commande_locale(monkeypatch):
    seen = []
    monkeypatch.setattr(P, "run", lambda argv, timeout=600, env=None, **k: seen.append((argv, env)) or (0, ""))
    system._apt(None, "update")
    argv, env = seen[0]
    assert argv[:2] == ["apt-get", "-q"] and env["DEBIAN_FRONTEND"] == "noninteractive" and "PATH" in env


def test_en_attente():
    res = {"components": {"docker": {"available": "5:30"}, "debian": {"available": "3 paquets"}, "caddy": {}},
           "nodes": {"n1": {"components": {"postgres": {"available": "nouvelle image 17.x"}, "debian": {"available": "1"}}},
                     "n2": {"error": "injoignable", "components": {}}}}
    assert sorted(system.pending(res)) == [("local", "docker"), ("n1", "postgres")]


def test_unites():
    assert system.unit("docker") == "hangar-maj-docker"
    assert system.unit("docker", "local") == "hangar-maj-docker"
    assert system.unit("caddy", "ns1") == "hangar-maj-ns1-caddy"


def test_machine_inconnue(monkeypatch):
    monkeypatch.setattr(system, "machines", lambda: [("local", "Console")])
    with pytest.raises(ValueError):
        system.launch("caddy", "absent")
    with pytest.raises(ValueError):
        system.launch("inconnu", "local")


def test_page_par_machine(monkeypatch):
    from argon2 import PasswordHasher
    from fastapi.testclient import TestClient
    from app import main
    same = {"sec-fetch-site": "same-origin"}
    db.x("INSERT OR REPLACE INTO users(username, hash) VALUES(?, ?)", ("sys", PasswordHasher().hash("mot-de-passe-sys")))
    comp = lambda cur, av=None: {"current": cur, "available": av, "packages": []}   # noqa: E731
    db.kv_set("sys_check", {"ts": 1, "reboot": False, "hangar": {"head": "abc", "ahead": 0, "behind": 0},
                            "components": {k: comp("1") for k in system.COMPONENTS},
                            "nodes": {"vps": {"ts": 1, "reboot": True,
                                              "components": {**{k: comp("1") for k in system.COMPONENTS},
                                                             "caddy": comp("2.11.9", "2.12.0")}},
                                      "hs": {"ts": 1, "error": "apt update : délai dépassé", "components": {}}}})
    db.kv_set("sys_pending_since", {"vps:caddy": {"ts": 1, "reminded": False}})
    monkeypatch.setattr(system, "machines", lambda: [("local", "Console"), ("vps", "Mon VPS"), ("hs", "En panne")])
    monkeypatch.setattr(system, "running", lambda *a, **k: None)
    monkeypatch.setattr(P, "system_info", lambda: {})
    c = TestClient(main.app, base_url="https://hangar.test", client=("127.0.0.1", 50003))
    main._fails.clear()
    c.post("/login", data={"username": "sys", "password": "mot-de-passe-sys"}, headers=same)
    r = c.get("/system")
    assert r.status_code == 200
    t = r.text
    assert "Mon VPS" in t and "2.12.0" in t and 'name="node" value="vps"' in t and "en attente depuis" in t
    assert "délai dépassé" in t and "Redémarrage demandé" in t
    seen = []
    monkeypatch.setattr(system, "launch", lambda cid, node=None: seen.append((cid, node)))
    r = c.post("/system/update/caddy", data={"node": "vps"}, headers=same, follow_redirects=False)
    assert r.headers["location"] == "/system" and seen == [("caddy", "vps")]
