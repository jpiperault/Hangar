"""Canaux d'alerte : seuils, canal en panne sans bloquer les autres, validation des réglages."""
import pytest

from app import alerts, db


@pytest.fixture
def canaux(monkeypatch):
    before = {k: db.settings().get(k) for k in ("alerts_on", "ntfy_topic", "ntfy_min")}
    db.set_setting("alerts_on", "1")
    db.set_setting("ntfy_topic", "sujet-essai")
    db.set_setting("ntfy_min", "1")
    db.kv_set("alert_channels", {"email": {"on": True, "min": 4, "host": "smtp.x", "to": ["a@b.fr"]},
                                 "discord": {"on": True, "min": 3, "url": "u"},
                                 "telegram": {"on": False, "min": 1, "token": "t", "chat_id": "1"}})
    sent = []
    monkeypatch.setattr(alerts, "_post", lambda s, t, m, p, tags: sent.append("ntfy"))

    def boom(c, t, m, p):
        raise OSError("serveur injoignable")
    monkeypatch.setitem(alerts.SENDERS, "email", lambda c, t, m, p: sent.append("email"))
    monkeypatch.setitem(alerts.SENDERS, "discord", boom)
    monkeypatch.setitem(alerts.SENDERS, "telegram", lambda c, t, m, p: sent.append("telegram"))
    yield sent
    db.kv_set("alert_channels", {})
    for k, v in before.items():
        db.set_setting(k, v or "")


def test_seuils_et_pannes(canaux):
    ok, err = alerts.send("Titre", "message", priority=2)
    assert ok and canaux == ["ntfy"] and not err                 # e-mail (4) et Discord (3) : trop discret
    canaux.clear()
    ok, err = alerts.send("Titre", "message", priority=5)
    assert ok and canaux == ["ntfy", "email"] and "Discord" in err   # Discord en panne, les autres partent
    canaux.clear()
    ok, _ = alerts.send("Test", "x", force=True, only="telegram")     # essai d'un canal désactivé
    assert ok and canaux == ["telegram"]


def test_coupees(canaux):
    db.set_setting("alerts_on", "0")
    assert alerts.send("Titre", "x", priority=5) == (False, "alertes désactivées") and not canaux


def test_formulaires():
    from app.routes.system import _channel_form
    ok = _channel_form("discord", {"on": "on", "url": "https://discord.com/api/webhooks/123456789/" + "a" * 60, "min": "4"})
    assert ok["on"] and ok["min"] == 4
    for ch, f in [("discord", {"url": "https://exemple.com/hook"}),
                  ("telegram", {"token": "pas-un-jeton"}),
                  ("telegram", {"token": "123456:" + "A" * 35, "on": "on"}),            # pas de chat_id
                  ("email", {"host": "smtp.x.fr", "to": "pas-une-adresse"}),
                  ("email", {"host": "smtp.x.fr", "to": "a@b.fr", "user": "a@b.fr", "security": "none"})]:
        with pytest.raises(ValueError):
            _channel_form(ch, f)
    e = _channel_form("email", {"host": "smtp.x.fr", "to": "a@b.fr; c@d.fr", "user": "moi@x.fr", "password": "p"})
    assert e["to"] == ["a@b.fr", "c@d.fr"] and e["security"] == "starttls" and e["port"] == 587


def test_rapport_sur_tous_les_canaux(canaux, monkeypatch):
    from app import report
    monkeypatch.setattr(report, "build", lambda now=None: ("Rapport", "texte"))
    db.kv_set("report_options", None)
    report.send()
    assert canaux == ["ntfy", "email"]                       # par défaut : malgré le seuil 4 de l'e-mail
    canaux.clear()
    db.kv_set("report_options", {"on": True, "all_channels": False})
    report.send()
    assert canaux == ["ntfy"]
    db.kv_set("report_options", {"on": False, "all_channels": True})
    assert report.maybe_send(1794819600) is False and db.kv_get("weekly_report") != "2026-W47"   # lundi 10 h, coupé
    db.kv_set("report_options", None)
