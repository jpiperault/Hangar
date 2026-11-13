"""Préproduction : identifiant, adresses, variable d'environnement, liens."""
import json

import pytest

from app import db, preprod
from app import domains as D
from app import platform as P


@pytest.fixture
def prod(app_row):
    db.x("DELETE FROM apps WHERE slug IN ('cuisine', 'cuisine-preprod')")
    db.insert_app("cuisine", {**app_row, "state": "ok", "created_at": 0, "host_port": 18777})
    db.x("INSERT OR IGNORE INTO domains(name, mode, hub, created_at) VALUES('exemple.fr', 'tunnel', 'apps', 0)")
    D.set_routes("cuisine", [{"kind": "sub", "domain": "exemple.fr", "sub": "cuisine"},
                             {"kind": "path", "domain": "exemple.fr", "sub": ""}])
    db.kv_set("preprod", {})
    yield db.app("cuisine")
    db.x("DELETE FROM apps WHERE slug IN ('cuisine', 'cuisine-preprod')")
    db.x("DELETE FROM routes WHERE slug IN ('cuisine', 'cuisine-preprod')")
    db.kv_set("preprod", {})


def test_identifiant():
    assert preprod.target("cuisine") == "cuisine-preprod"
    long = "a" * 30
    assert len(preprod.target(long)) <= 32 and preprod.target(long).endswith("-preprod")


def test_adresses_et_controles(prod):
    assert preprod.check("cuisine") == "cuisine-preprod"
    assert preprod._routes("cuisine", "cuisine-preprod") == [
        {"kind": "sub", "domain": "exemple.fr", "sub": "cuisine-preprod"}, {"kind": "path", "domain": "exemple.fr", "sub": ""}]
    D.set_routes("autre", [{"kind": "sub", "domain": "exemple.fr", "sub": "cuisine-preprod"}])
    try:
        with pytest.raises(ValueError, match="déjà prise"):
            preprod.check("cuisine")
    finally:
        D.set_routes("autre", [])


def test_creation(prod, monkeypatch):
    deployed = []
    monkeypatch.setattr(P, "deploy", lambda slug, v, kind, *a: deployed.append((slug, v, kind)))
    monkeypatch.setattr(P, "log", lambda *a, **k: None)
    preprod.create("cuisine", "1.3.0")
    pre = db.app("cuisine-preprod")
    assert pre["name"] == "Mon jeu (préprod)" and pre["pkg"] == "" and pre["version"] == "1.3.0"
    assert pre["env"] == prod["env"] and pre["db_password"] != prod["db_password"] and pre["host_port"] != prod["host_port"]
    assert deployed == [("cuisine-preprod", "1.3.0", "create")]
    assert preprod.of("cuisine") == "cuisine-preprod" and preprod.prod_of("cuisine-preprod") == "cuisine"
    with pytest.raises(ValueError, match="déjà une préproduction"):
        preprod.check("cuisine")
    with pytest.raises(ValueError, match="déjà une préproduction"):
        preprod.check("cuisine-preprod")
    preprod.forget("cuisine-preprod")
    assert preprod.of("cuisine") is None


def test_variable_preprod(prod, tmp_path, monkeypatch):
    monkeypatch.setattr(P, "app_dir", lambda slug: str(tmp_path / slug))
    monkeypatch.setattr(P, "compose_path", lambda slug, inst=None: str(tmp_path / slug / "compose.yml"))
    db.kv_set("preprod", {"cuisine-preprod": "cuisine"})
    env = lambda slug: json.loads("".join(l for l in open(P.write_compose({**prod, "slug": slug}, "1"))   # noqa: E731
                                          if not l.startswith("#")))["services"]["app"]["environment"]
    assert env("cuisine-preprod")["HANGAR_ENVIRONMENT"] == "preprod" and "HANGAR_ENVIRONMENT" not in env("cuisine")
