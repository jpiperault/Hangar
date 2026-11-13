"""Supervision des nœuds : services relevés, alertes sur front montant et retour à la normale."""
import json
import time

import pytest

from app import db, monitor


@pytest.fixture
def noeud(monkeypatch):
    sent = []
    monkeypatch.setattr(monitor.alerts, "send", lambda title, msg, **k: sent.append(title))
    monkeypatch.setattr(monitor.P, "log", lambda *a, **k: None)
    monkeypatch.setattr(monitor.security, "web_needed", lambda node: [])
    monitor._flags.clear()

    def put(**info):
        base = {"cpu": 5, "mem": 500, "mem_total": 2000, "disk": 10, "disk_total": 100, "pg": "healthy",
                "svc": {"docker": "active", "caddy": "active", "fw": "ok"}}
        base.update(info)
        db.x("INSERT OR REPLACE INTO nodes(id, name, address, wg_ip, state, info, last_seen, created_at) "
             "VALUES('vps', 'Mon VPS', '203.0.113.5', '10.88.0.250', 'ok', ?, ?, 0)", (json.dumps(base), time.time()))
        monitor.check_nodes()
    yield put, sent
    db.x("DELETE FROM nodes WHERE id = 'vps'")
    monitor._flags.clear()


def test_tout_va_bien(noeud):
    put, sent = noeud
    put()
    assert sent == []


def test_disque_puis_retour(noeud):
    put, sent = noeud
    put(disk=90)
    put(disk=91)   # une seule alerte tant que ça dure
    assert sent == ["Nœud Mon VPS : disque presque plein"]
    put(disk=50)
    assert sent[-1] == "Nœud Mon VPS : espace disque revenu à la normale"


def test_services(noeud):
    put, sent = noeud
    put(pg="unhealthy", svc={"docker": "failed", "caddy": "failed", "fw": ""}, mem=1950)
    assert set(sent) == {"Nœud Mon VPS : PostgreSQL arrêté", "Nœud Mon VPS : Docker arrêté",
                         "Nœud Mon VPS : pare-feu absent", "Nœud Mon VPS : mémoire presque saturée"}
    # Caddy arrêté : sans objet tant que le nœud n'est pas une entrée web directe


def test_caddy_si_entree_web(noeud, monkeypatch):
    put, sent = noeud
    monkeypatch.setattr(monitor.security, "web_needed", lambda node: ["exemple.fr"])
    put(svc={"docker": "active", "caddy": "failed", "fw": "ok"})
    assert sent == ["Nœud Mon VPS : Caddy arrêté"]


def test_releve_ancien_ignore(noeud):
    put, sent = noeud
    put(disk=99)
    sent.clear()
    monitor._flags.clear()
    db.x("UPDATE nodes SET last_seen = ? WHERE id = 'vps'", (time.time() - 600,))
    monitor.check_nodes()
    assert sent == []   # nœud muet : c'est l'alerte « injoignable » qui parle
