"""Démarrage du conteneur : point d'entrée, commande, santé par commande."""
import json

import pytest

from app import db, runopts
from app import platform as P


@pytest.fixture(autouse=True)
def vide():
    db.kv_set("app_run", {})
    yield
    db.kv_set("app_run", {})


def _svc(app_row, tmp_path, monkeypatch):
    monkeypatch.setattr(P, "app_dir", lambda slug: str(tmp_path / slug))
    monkeypatch.setattr(P, "compose_path", lambda slug, inst=None: str(tmp_path / slug / "compose.yml"))
    return json.loads("".join(l for l in open(P.write_compose(app_row, "1")) if not l.startswith("#")))["services"]["app"]


def test_saisie():
    assert runopts.save("mon-jeu", {"command": 'python worker.py --nom "deux mots"'})
    assert not runopts.save("mon-jeu", {"command": 'python worker.py --nom "deux mots"'})   # rien de changé
    for bad in ({"command": 'echo "pas fermé'}, {"entrypoint": "a\nb"}, {"health_cmd": "x" * 1001}):
        with pytest.raises(ValueError):
            runopts.save("mon-jeu", bad)
    assert runopts.of("mon-jeu")["command"].startswith("python")   # une saisie refusée ne change rien
    runopts.save("mon-jeu", {})
    assert runopts.of("mon-jeu") == {}


def test_compose(app_row, tmp_path, monkeypatch):
    svc = _svc(app_row, tmp_path, monkeypatch)
    assert "command" not in svc and "entrypoint" not in svc and "healthcheck" not in svc
    runopts.save(app_row["slug"], {"entrypoint": "/bin/sh -c", "command": '"echo $HOME et ; rm"',
                                   "health_cmd": "test -f /tmp/ok || exit 1 # $X"})
    svc = _svc(app_row, tmp_path, monkeypatch)
    assert svc["entrypoint"] == ["/bin/sh", "-c"]
    assert svc["command"] == ["echo $$HOME et ; rm"]          # une seule valeur, $ protégé de compose
    assert svc["healthcheck"]["test"] == ["CMD-SHELL", "test -f /tmp/ok || exit 1 # $$X"]
    assert svc["healthcheck"]["retries"] == 3


def test_attente_sante(monkeypatch):
    a = {"slug": "mon-jeu", "node": "local", "kind": "worker"}
    runopts.save("mon-jeu", {"health_cmd": "true"})
    seq = iter([{"status": "running", "health": "starting", "code": "0", "restarts": 0, "oom": False},
                {"status": "running", "health": "healthy", "code": "0", "restarts": 0, "oom": False}])
    monkeypatch.setattr(P, "_container_state", lambda name, node=None: next(seq))
    monkeypatch.setattr(P.time, "sleep", lambda s: None)
    assert P.wait_health(a) == (True, "commande de santé réussie")
    monkeypatch.setattr(P, "_container_state", lambda name, node=None:
                        {"status": "running", "health": "unhealthy", "code": "0", "restarts": 0, "oom": False})
    monkeypatch.setattr(P, "_health_log", lambda name, node: "1: pas prêt")
    monkeypatch.setattr(P, "container_report", lambda name, node=None: "")
    ok, why = P.wait_health(a)
    assert not ok and "pas prêt" in why
