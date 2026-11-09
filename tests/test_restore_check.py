"""Test de restauration : un échec est signalé (journal + alerte), le test revient chaque semaine."""
import time

from app import backup, db


def test_echec_sans_sauvegarde(monkeypatch):
    sent = []
    monkeypatch.setattr(backup, "restic", lambda *a, **k: (1, "", "dépôt introuvable"))
    monkeypatch.setattr(backup.alerts, "send", lambda *a, **k: sent.append(a))
    r = backup._verify({"id": "test", "name": "Test"})
    assert r["ok"] is False and r["checks"][0]["label"] == "dernière sauvegarde"
    assert sent and "Test de restauration" in sent[0][0]
    assert backup.restore_tests()["test"]["ok"] is False


def test_frequence(monkeypatch):
    d = {"id": "freq", "name": "F"}
    db.kv_set("restore_test", {})
    assert backup.verify_due(d)
    db.kv_set("restore_test", {"freq": {"ts": time.time() - 3600}})
    assert not backup.verify_due(d)
    db.kv_set("restore_test", {"freq": {"ts": time.time() - 8 * 86400}})
    assert backup.verify_due(d)


def test_hors_des_chemins_sauvegardes():
    assert not backup.VERIFY.startswith((backup.STAGING + "/", "/srv/apps", "/srv/platform"))
