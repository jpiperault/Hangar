"""Logs : filtres et alertes sur motif."""
import pytest

from app import applogs, db


@pytest.fixture(autouse=True)
def propre():
    db.kv_set("log_alerts", {})
    yield
    db.kv_set("log_alerts", {})


def test_motifs():
    applogs.save("mon-jeu", True, "Exception\n\nre:HTTP 5\\d\\d\n")
    s = applogs.settings("mon-jeu")
    assert s["on"] and s["patterns"] == "Exception\nre:HTTP 5\\d\\d"
    found = applogs.scan("mon-jeu", "ok\nNullPointerEXCEPTION at x\nGET / HTTP 503\nGET / HTTP 200\n")
    assert [(p, len(h)) for p, h in found] == [("Exception", 1), ("re:HTTP 5\\d\\d", 1)]
    with pytest.raises(ValueError, match="invalide"):
        applogs.save("mon-jeu", True, "re:(")
    applogs.save("mon-jeu", True, "")
    assert not applogs.settings("mon-jeu")["on"]   # rien à chercher : coupé


def test_lecture_filtree(monkeypatch, app_row):
    if not db.app(app_row["slug"]):
        db.insert_app(app_row["slug"], {**app_row, "state": "ok", "created_at": 0})
    seen = []
    log = "\n".join(["2026 info démarrage", "2026 ERROR base injoignable", "2026 info requête /api", "2026 Traceback (x)"])
    monkeypatch.setattr(applogs.P, "dk", lambda node, *a, **k: seen.append(a) or (0, log))
    lines, total, cut = applogs.read("mon-jeu", "24h", "", True)
    assert "--since" in seen[0] and "24h" in seen[0] and total == 4 and lines == ["2026 ERROR base injoignable", "2026 Traceback (x)"]
    lines, _, _ = applogs.read("mon-jeu", "", "requête")
    assert "--tail" in seen[1] and lines == ["2026 info requête /api"]


def test_alerte(monkeypatch, app_row):
    if not db.app(app_row["slug"]):
        db.insert_app(app_row["slug"], {**app_row, "state": "ok", "created_at": 0})
    db.update_app("mon-jeu", desired="running")
    applogs.save("mon-jeu", True, "OutOfMemory")
    sent = []
    monkeypatch.setattr(applogs.P, "dk", lambda node, *a, **k: (0, "x\njava.lang.OutOfMemoryError: heap\n"))
    monkeypatch.setattr(applogs.P, "log", lambda *a, **k: None)
    monkeypatch.setattr(applogs.alerts, "send", lambda title, msg, **k: sent.append((title, k.get("key"))))
    applogs.tick(1_800_000_000)
    assert sent == [("Mon jeu : « OutOfMemory » dans les logs", "logs:mon-jeu:OutOfMemory")]
