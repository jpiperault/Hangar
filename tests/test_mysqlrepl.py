"""Réplication MySQL/MariaDB vers le secours : options de la base principale, garde-fous, lecture de l'état."""
import pytest

from app import db, ha, mysqlrepl, services
from app import platform as P


@pytest.fixture
def appli(app_row, monkeypatch):
    db.x("DELETE FROM apps WHERE slug = 'mon-jeu'")
    db.insert_app("mon-jeu", {**app_row, "state": "ok", "created_at": 0, "node": "n1"})
    db.kv_set("app_services", {})
    services.enable_mysql("mon-jeu", "mariadb", 256)
    monkeypatch.setattr(ha, "get", lambda slug: {"mode": "standby", "nodes": ["n2"]})
    yield
    db.kv_set("app_services", {})
    db.x("DELETE FROM apps WHERE slug = 'mon-jeu'")


def test_options_et_port(appli, monkeypatch):
    assert "--log-bin=mysql-bin" in mysqlrepl.primary_args("mon-jeu", "mariadb")
    assert "--gtid-mode=ON" in mysqlrepl.primary_args("mon-jeu", "mysql")
    assert mysqlrepl.ports("mon-jeu") == 18001 + 30000
    monkeypatch.setattr(ha, "get", lambda slug: None)
    assert mysqlrepl.primary_args("mon-jeu", "mariadb") == [] and mysqlrepl.ports("mon-jeu") is None


def test_jamais_sur_la_machine_principale(appli, monkeypatch):
    monkeypatch.setattr(mysqlrepl, "_wait_up", lambda *a, **k: True)
    with pytest.raises(RuntimeError, match="base principale"):
        mysqlrepl.build("mon-jeu", "n1")


def test_etat(appli, monkeypatch):
    mysqlrepl._set("mon-jeu", replica={"node": "n2", "ts": 0})
    monkeypatch.setattr(P, "dk", lambda node, *a, timeout=0: (0, "Slave_IO_Running: Yes\n Slave_SQL_Running: Yes\n"
                                                              " Seconds_Behind_Master: 3\n Last_IO_Error: \n"))
    assert mysqlrepl.status("mon-jeu") == {"running": True, "lag": 3, "error": ""}
    monkeypatch.setattr(P, "dk", lambda node, *a, timeout=0: (0, "Slave_IO_Running: Connecting\n Slave_SQL_Running: Yes\n"
                                                              " Seconds_Behind_Master: NULL\n Last_IO_Error: refusé\n"))
    st = mysqlrepl.status("mon-jeu")
    assert not st["running"] and st["error"] == "refusé"
