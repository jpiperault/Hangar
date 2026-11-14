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


def test_recherche_toutes_applis(app_row, monkeypatch):
    from app import applogs, db
    for s in ("mon-jeu", "autre-log"):
        db.x("DELETE FROM apps WHERE slug = ?", (s,))
    db.insert_app("mon-jeu", {**app_row, "state": "ok", "created_at": 0})
    db.insert_app("autre-log", {**app_row, "pkg": "", "name": "Autre", "state": "ok", "created_at": 0, "host_port": 18904})
    logs = {"mon-jeu": "2026-11-14T10:00:02Z requête 42 ok\n2026-11-14T10:00:05Z ERROR requête 43",
            "autre-log": "2026-11-14T10:00:03Z requête 42 vue ici aussi\n2026-11-14T10:00:04Z rien"}
    monkeypatch.setattr(applogs.P, "app_dir", lambda slug: slug)
    monkeypatch.setattr(applogs.P, "dk", lambda node, *a, cwd=None, **k: (0, logs[cwd]))
    found, errs, cut = applogs.search("requête 42", "24h")
    assert [(f["slug"], f["ts"]) for f in found] == [("mon-jeu", "2026-11-14T10:00:02Z"), ("autre-log", "2026-11-14T10:00:03Z")]
    assert found[0]["line"] == "requête 42 ok" and not errs and not cut
    found, _, _ = applogs.search("", "24h", errors_only=True, slugs=["mon-jeu", "autre-log"])
    assert [f["line"] for f in found] == ["ERROR requête 43"]
    for s in ("mon-jeu", "autre-log"):
        db.x("DELETE FROM apps WHERE slug = ?", (s,))
