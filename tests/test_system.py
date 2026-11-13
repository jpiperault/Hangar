"""Mises à jour système : commandes envoyées aux nœuds, recensement, page par machine."""
import time

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
    monkeypatch.setattr(main, "_tz_now", lambda: [("Console", "Etc/UTC"), ("Mon VPS", "Europe/Paris")])
    c = TestClient(main.app, base_url="https://hangar.test", client=("127.0.0.1", 50003))
    main._fails.clear()
    c.post("/login", data={"username": "sys", "password": "mot-de-passe-sys"}, headers=same)
    r = c.get("/system")
    assert r.status_code == 200
    t = r.text
    assert "Mon VPS" in t and "2.12.0" in t and 'name="node" value="vps"' in t and "en attente depuis" in t
    assert "délai dépassé" in t and "Redémarrage demandé" in t and 'id="fuseau"' in t and "<option selected>Europe/Paris</option>" in t
    seen = []
    monkeypatch.setattr(system, "launch", lambda cid, node=None: seen.append((cid, node)))
    r = c.post("/system/update/caddy", data={"node": "vps"}, headers=same, follow_redirects=False)
    assert r.headers["location"] == "/system#maj-vps" and seen == [("caddy", "vps")]
    assert 'data-mtab="maj-vps"' in t and 'data-mpane="maj-hs"' in t and "def = 'maj-vps'" in t   # onglet ouvert : celui qui attend


def _res():
    comp = lambda av=None: {"current": "1", "available": av, "packages": []}   # noqa: E731
    return {"components": {"docker": comp("5:30"), "cloudflared": comp("2026.12"), "debian": comp("2 paquets"),
                           "caddy": comp(), "postgres": comp()},
            "nodes": {"vps": {"components": {"cloudflared": comp("2026.12"), "postgres": comp("nouvelle image 17.x"),
                                             "docker": comp(), "caddy": comp(), "debian": comp()}}}}


NUIT = time.mktime((2026, 11, 13, 3, 30, 0, 0, 0, -1))
JOUR = time.mktime((2026, 11, 13, 14, 0, 0, 0, 0, -1))
ON = {"on": True, "comps": ["cloudflared", "caddy", "postgres"], "start": 3, "end": 5}


def test_auto_plage_et_ordre():
    assert system.auto_pick(_res(), ON, {}, JOUR) is None
    assert system.auto_pick(_res(), {**ON, "on": False}, {}, NUIT) is None
    assert system.auto_pick(_res(), ON, {}, NUIT)[0] == "vps"   # nœuds avant la console
    tried = {"vps:cloudflared": {"ts": NUIT - 3600, "available": "2026.12"},
             "vps:postgres": {"ts": NUIT - 3600, "available": "nouvelle image 17.x"}}
    assert system.auto_pick(_res(), ON, tried, NUIT) == ("local", "cloudflared")
    # docker et debian seulement si cochés, docker en dernier
    allc = {**ON, "comps": list(system.COMPONENTS)}
    order = []
    t = {}
    while (p := system.auto_pick(_res(), allc, t, NUIT)):
        order.append(p)
        t[f"{p[0]}:{p[1]}"] = {"ts": NUIT, "available": "x"}
        t[f"{p[0]}:{p[1]}"]["available"] = (_res() if p[0] == "local" else _res()["nodes"][p[0]])["components"][p[1]]["available"]
    assert order[-1] == ("local", "docker") and ("local", "debian") in order and len(order) == 5


def test_auto_reessai():
    tried = {"vps:cloudflared": {"ts": NUIT - 8 * 86400, "available": "2026.12"}}
    one = {**ON, "comps": ["cloudflared"]}
    assert system.auto_pick(_res(), one, tried, NUIT)[0] == "vps"          # plus de 7 jours : retentée
    tried["vps:cloudflared"]["ts"] = NUIT - 86400
    assert system.auto_pick(_res(), one, tried, NUIT) == ("local", "cloudflared")
    tried["vps:cloudflared"]["available"] = "2026.11"                      # nouvelle version depuis : retentée
    assert system.auto_pick(_res(), one, tried, NUIT)[0] == "vps"


def test_plage_qui_passe_minuit():
    assert system.in_window(23, 22, 2) and system.in_window(1, 22, 2) and not system.in_window(12, 22, 2)
    with pytest.raises(ValueError):
        system.save_auto(True, ["caddy"], 4, 4)


def test_fuseau(monkeypatch, app_row, tmp_path):
    import json
    seen = []
    monkeypatch.setattr(P, "nsh", lambda node, cmd, timeout=120, input=None: seen.append((node, cmd))
                        or (0, "/usr/share/zoneinfo/Europe/Paris"))
    monkeypatch.setattr(P, "run", lambda *a, **k: (0, ""))
    monkeypatch.setattr(system, "machines", lambda: [("local", "Console"), ("vps", "VPS")])
    with pytest.raises(ValueError):
        system.apply_tz("Mars/Olympus", False)
    assert system.apply_tz("Europe/Paris", True) == []
    assert [n for n, _ in seen] == ["local", "vps"] and "timedatectl set-timezone Europe/Paris" in seen[0][1]
    assert system.tz_settings() == {"tz": "Europe/Paris", "apps": True}
    monkeypatch.setattr(P, "app_dir", lambda slug: str(tmp_path / slug))
    monkeypatch.setattr(P, "compose_path", lambda slug, inst=None: str(tmp_path / slug / "compose.yml"))
    svc = json.loads("".join(l for l in open(P.write_compose(app_row, "1")) if not l.startswith("#")))["services"]["app"]
    assert svc["environment"]["TZ"] == "Europe/Paris" and "/etc/localtime:/etc/localtime:ro" in svc["volumes"]
    svc = json.loads("".join(l for l in open(P.write_compose({**app_row, "env": "TZ=UTC"}, "1"))
                             if not l.startswith("#")))["services"]["app"]
    assert svc["environment"]["TZ"] == "UTC"   # la valeur de l'appli l'emporte
    db.kv_set("timezone", {})
