"""Redis (Valkey) d'une appli : compose, variable, refus avec la haute dispo."""
import json

import pytest

from app import db, services
from app import platform as P


@pytest.fixture(autouse=True)
def propre():
    db.kv_set("app_services", {})
    yield
    db.kv_set("app_services", {})


def test_compose_avec_redis(app_row, tmp_path, monkeypatch):
    monkeypatch.setattr(P, "app_dir", lambda slug: str(tmp_path / slug))
    monkeypatch.setattr(P, "compose_path", lambda slug, inst=None: str(tmp_path / slug / "compose.yml"))
    services.enable_redis("mon-jeu", 96)
    pw = services.redis("mon-jeu")["password"]
    doc = json.loads("".join(l for l in open(P.write_compose(app_row, "1.2.0")) if not l.startswith("#")))
    r = doc["services"]["redis"]
    assert r["image"].startswith("valkey/valkey:") and r["networks"] == ["hangar-mon-jeu"] and r["mem_limit"] == "96m"
    assert r["volumes"] == [f"{tmp_path}/mon-jeu/data/.hangar-redis:/data"] and "ports" not in r
    assert pw in r["command"] and "noeviction" in r["command"]
    assert doc["services"]["app"]["environment"]["REDIS_URL"] == f"redis://:{pw}@redis:6379/0"
    assert "fr.hangar.app" not in r["labels"]          # pas pris pour l'appli par la surveillance
    services.enable_redis("mon-jeu", 128)
    assert services.redis("mon-jeu")["password"] == pw  # le mot de passe ne change pas avec la mémoire
    services.disable_redis("mon-jeu")
    doc = json.loads("".join(l for l in open(P.write_compose(app_row, "1.2.0")) if not l.startswith("#")))
    assert "redis" not in doc["services"] and "REDIS_URL" not in doc["services"]["app"]["environment"]


def test_limites():
    with pytest.raises(ValueError):
        services.enable_redis("mon-jeu", 8)


@pytest.fixture
def instances(app_row, monkeypatch, tmp_path):
    """mon-jeu en haute dispo « instances multiples » : principal sur vps1, instance sur vps2."""
    monkeypatch.setattr(P, "app_dir", lambda slug: str(tmp_path / slug))
    monkeypatch.setattr(P, "compose_path", lambda slug, inst=None: str(tmp_path / slug / (inst or "main") / "compose.yml"))
    monkeypatch.setattr(P, "node_wg", lambda n: {"vps1": "10.88.0.5", "vps2": "10.88.0.6"}.get(n, "10.88.0.1"))
    monkeypatch.setattr(P, "nsh", lambda *a, **k: (0, ""))
    import app.segment as seg
    monkeypatch.setattr(seg, "push_all", lambda: [])
    if not db.app("mon-jeu"):
        db.insert_app("mon-jeu", {**app_row, "state": "ok", "created_at": 0})
    db.update_app("mon-jeu", node="vps1")
    db.x("INSERT OR REPLACE INTO ha(slug, mode, nodes, auto, delay, sync_min, db_port, db_admin, repl_password, state, "
         "info, updated_at) VALUES('mon-jeu', 'replicas', '[\"vps2\"]', 1, 4, 5, ?, 'x', 'y', 'ok', '{}', 0)",
         (app_row["host_port"] + 10000,))
    yield db.app("mon-jeu")
    db.x("DELETE FROM ha WHERE slug = 'mon-jeu'")
    db.update_app("mon-jeu", node="local")


def _doc(path):
    return json.loads("".join(l for l in open(path) if not l.startswith("#")))


def test_redis_partage_entre_instances(instances):
    a = instances
    services.enable_redis("mon-jeu", 128)
    pw, port = services.redis("mon-jeu")["password"], a["host_port"] + 20000
    main = _doc(P.write_compose(a, "1.2.0"))
    assert main["services"]["redis"]["ports"] == [f"10.88.0.5:{port}:6379"]          # réseau privé seulement
    assert main["services"]["app"]["environment"]["REDIS_URL"] == f"redis://:{pw}@redis:6379/0"
    inst = _doc(P.write_compose(a, "1.2.0", instance="vps2", role="instance"))
    assert "redis" not in inst["services"]                                            # pas de second Redis
    assert inst["services"]["app"]["environment"]["REDIS_URL"] == f"redis://:{pw}@10.88.0.5:{port}/0"
    from app import segment
    assert ("mon-jeu", port) in segment._dbports() and ("mon-jeu", a["host_port"] + 10000) in segment._dbports()


def test_redis_secours_a_chaud(instances):
    db.x("UPDATE ha SET mode = 'standby' WHERE slug = 'mon-jeu'")
    services.enable_redis("mon-jeu", 128)
    main = _doc(P.write_compose(instances, "1.2.0"))
    assert "ports" not in main["services"]["redis"] and services.shared_port("mon-jeu") is None
    from app import segment
    assert all(p != instances["host_port"] + 20000 for _, p in segment._dbports())
