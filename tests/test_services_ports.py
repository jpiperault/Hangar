"""Services sans page web et serveurs de jeu : ports publics, santé du conteneur, contrôle de sécurité."""
import json

import pytest

from app import db, gameports, kinds
from app import platform as P


@pytest.fixture
def appli(app_row):
    db.x("DELETE FROM apps WHERE slug IN ('mc', 'mc2')")
    db.insert_app("mc", {**app_row, "kind": "game", "state": "ok", "created_at": 0, "host_port": 18501, "pkg": ""})
    db.kv_set("public_ports", {})
    yield db.app("mc")
    db.x("DELETE FROM apps WHERE slug IN ('mc', 'mc2')")
    db.kv_set("public_ports", {})


def test_saisie(appli):
    assert gameports.parse("tcp 25565, udp 19132\n25566, tcp 8081:8080", "mc", "local") == [
        {"proto": "tcp", "port": 25565, "cport": 25565}, {"proto": "udp", "port": 19132, "cport": 19132},
        {"proto": "tcp", "port": 25566, "cport": 25566}, {"proto": "tcp", "port": 8081, "cport": 8080}]
    for bad, msg in (("http 80", "il faut"), ("tcp 22", "réservé"), ("tcp 18501", "réservé"), ("udp 70000", "hors"),
                     ("tcp 8080", "réservé")):
        with pytest.raises(ValueError, match=msg):
            gameports.parse(bad, "mc", "local")
    gameports.save("mc", [{"proto": "tcp", "port": 25565}])
    db.insert_app("mc2", {**dict(appli), "kind": "game", "host_port": 18502, "pkg": "", "name": "Autre"})
    with pytest.raises(ValueError, match="déjà ouvert"):
        gameports.parse("tcp 25565", "mc2", "local")
    assert gameports.parse("udp 25565", "mc2", "local")           # même numéro, autre protocole
    assert gameports.parse("tcp 25565", "mc2", "vps")             # autre machine


def test_compose(appli, tmp_path, monkeypatch):
    monkeypatch.setattr(P, "app_dir", lambda slug: str(tmp_path / slug))
    monkeypatch.setattr(P, "compose_path", lambda slug, inst=None: str(tmp_path / slug / "compose.yml"))
    gameports.save("mc", [{"proto": "tcp", "port": 25565}, {"proto": "udp", "port": 19132, "cport": 19133}])
    svc = json.loads("".join(l for l in open(P.write_compose(appli, "1")) if not l.startswith("#")))["services"]["app"]
    assert svc["ports"] == ["25565:25565/tcp", "19132:19133/udp"]
    svc = json.loads("".join(l for l in open(P.write_compose({**appli, "kind": "worker"}, "1"))
                             if not l.startswith("#")))["services"]["app"]
    assert svc["ports"] == [] and not kinds.http("worker")


def test_sante_sans_page_web(appli, monkeypatch):
    seq = iter([{"status": "running", "restarts": 0, "code": "0"}] * 20)
    monkeypatch.setattr(P, "_container_state", lambda name, node=None: next(seq))
    monkeypatch.setattr(P.time, "sleep", lambda s: None)
    assert P.wait_health({**appli, "kind": "worker"})[0]
    seq2 = iter([{"status": "running", "restarts": 0, "code": "0"}, {"status": "exited", "restarts": 0, "code": "1"}])
    monkeypatch.setattr(P, "_container_state", lambda name, node=None: next(seq2))
    monkeypatch.setattr(P, "container_report", lambda *a, **k: "")
    ok, why = P.wait_health({**appli, "kind": "worker"})
    assert not ok and "arrêté" in why


def test_controle_securite(appli):
    gameports.save("mc", [{"proto": "tcp", "port": 25565}])
    assert ("app-mc-app-1", 25565) in gameports.expected("local")
