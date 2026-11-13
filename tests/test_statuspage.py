"""Page de statut publique : contenu, réglages, bloc Caddy."""
import pytest

from app import db, statuspage
from app import domains as D
from app import platform as P


@pytest.fixture
def page(app_row, monkeypatch):
    if not db.app("mon-jeu"):
        db.insert_app("mon-jeu", {**app_row, "state": "ok", "created_at": 0})
    db.update_app("mon-jeu", name="Mon <jeu>", desired="running", state="ok")
    db.x("INSERT OR IGNORE INTO domains(name, mode, hub, created_at) VALUES('exemple.fr', 'tunnel', 'apps', 0)")
    db.kv_set("maintenance", {})
    yield
    db.kv_set("status_page", {})
    db.update_app("mon-jeu", name="Mon jeu")


def test_reglages(page):
    with pytest.raises(ValueError, match="sous-domaine"):
        statuspage.save(True, "exemple.fr", "Pas bon", "", [])
    with pytest.raises(ValueError, match="routes par chemin"):
        statuspage.save(True, "exemple.fr", "apps", "", [])
    statuspage.save(True, "exemple.fr", "statut", "", ["mon-jeu", "inconnue"])
    s = statuspage.settings()
    assert s["apps"] == ["mon-jeu"] and s["title"] == "État des services" and statuspage.host() == "statut.exemple.fr"
    assert "statut.exemple.fr" in [n["name"] for n in D.public_names()]


def test_contenu(page, monkeypatch):
    from app import monitor
    statuspage.save(True, "exemple.fr", "statut", "Nos <services>", ["mon-jeu"])
    monitor.health["mon-jeu"] = {"ok": True, "ms": 5, "ts": 0, "why": ""}
    html1, sig1 = statuspage.render(1_800_000_000)
    assert "Mon &lt;jeu&gt;" in html1 and "Nos &lt;services&gt;" in html1 and "Tous les services sont opérationnels" in html1
    assert html1.count("<i class=") == 30
    _, sig2 = statuspage.render(1_800_000_000 + 60)
    assert sig1 == sig2                                   # l'heure seule ne compte pas comme un changement
    monkeypatch.setattr(P, "apply_routing", lambda: None)
    P.set_maintenance("mon-jeu", True)
    assert "Maintenance en cours" in statuspage.render()[0]
    P.set_maintenance("mon-jeu", False)
    monitor.health["mon-jeu"] = {"ok": False, "ms": 0, "ts": 0, "why": "x"}
    monitor._fails["mon-jeu"] = 3
    assert "Panne en cours" in statuspage.render()[0]
    monitor._fails.pop("mon-jeu", None)
    monitor.health.pop("mon-jeu", None)


def test_bloc_caddy(page):
    statuspage.save(True, "exemple.fr", "statut", "", ["mon-jeu"])
    conf = P.render_caddyfile({**db.settings(), "tunnel_bind": "127.0.0.1:8080"}, db.apps())
    assert "http://statut.exemple.fr:8080 {" in conf and f"root * {P.PUBLIC}/_status" in conf
