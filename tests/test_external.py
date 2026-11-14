"""Surveillance de l'extérieur : analyse des réponses, échecs d'affilée, alerte et retour."""
import pytest

from app import db, external
from app import platform as P


@pytest.fixture
def sonde(app_row, monkeypatch):
    db.x("DELETE FROM apps WHERE slug = 'mon-jeu'")
    db.insert_app("mon-jeu", {**app_row, "state": "ok", "created_at": 0})
    db.kv_set("external_checks", None)
    external.save(True, "vps", 5, 2)
    sent = []
    monkeypatch.setattr(external.alerts, "send", lambda title, *a, **k: sent.append(title))
    monkeypatch.setattr(external.P, "log", lambda *a, **k: None)
    monkeypatch.setattr(external, "targets", lambda: [(db.app("mon-jeu"), "https://jeu.exemple.fr/")])
    replies = []
    monkeypatch.setattr(P, "nsh", lambda node, cmd, input=None, timeout=0: (0, replies.pop(0)))
    yield sent, replies
    db.kv_set("external_checks", None)
    db.kv_set("external_probe", None)
    db.x("DELETE FROM apps WHERE slug = 'mon-jeu'")


def test_panne_et_retour(sonde):
    sent, replies = sonde
    replies += ["https://jeu.exemple.fr/ 200 0.120", "https://jeu.exemple.fr/ 530 0.05",
                "https://jeu.exemple.fr/ 000 0", "https://jeu.exemple.fr/ 000 0", "https://jeu.exemple.fr/ 401 0.2"]
    r = external.run()
    assert r["https://jeu.exemple.fr/"]["ok"] and r["https://jeu.exemple.fr/"]["ms"] == 120 and not sent
    r = external.run()
    assert r["https://jeu.exemple.fr/"]["why"] == "tunnel ou nom DNS non relié" and not sent    # 1 échec : pas encore
    external.run()
    assert sent == ["Mon jeu injoignable de l'extérieur"]                                        # 2e échec : alerte
    external.run()
    assert len(sent) == 1                                                                         # pas de répétition
    r = external.run()
    assert r["https://jeu.exemple.fr/"]["ok"] and sent[-1] == "Mon jeu de nouveau joignable de l'extérieur"   # 401 : répond


def test_rythme(sonde, monkeypatch):
    calls = []
    monkeypatch.setattr(external, "run", lambda now=None: calls.append(now))
    db.kv_set("external_checks", {"u": {"ts": 1000}})
    external.tick(now=1000 + 120)
    assert not calls
    external.tick(now=1000 + 300)
    assert calls
