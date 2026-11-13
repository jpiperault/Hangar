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


def test_limites(monkeypatch):
    with pytest.raises(ValueError):
        services.enable_redis("mon-jeu", 8)
    monkeypatch.setattr("app.ha.get", lambda slug: {"slug": slug})
    with pytest.raises(ValueError, match="haute disponibilité"):
        services.enable_redis("mon-jeu", 128)
