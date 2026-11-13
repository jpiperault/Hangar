"""Rapport hebdomadaire et disponibilité."""
import time

from app import db, report

LUNDI_10H = time.mktime((2026, 11, 16, 10, 0, 0, 0, 0, -1))
LUNDI_8H = time.mktime((2026, 11, 16, 8, 0, 0, 0, 0, -1))
MARDI = time.mktime((2026, 11, 17, 10, 0, 0, 0, 0, -1))


def test_disponibilite():
    db.x("DELETE FROM uptime WHERE app = 'dispo'")
    for i, (ok, tot) in enumerate([(1440, 1440), (1430, 1440), (0, 0)]):
        day = time.strftime("%Y-%m-%d", time.localtime(LUNDI_10H - i * 86400))
        db.x("INSERT INTO uptime(app, day, ok, total) VALUES('dispo', ?, ?, ?)", (day, ok, tot))
    pct, ok, total = report.uptime("dispo", 7, LUNDI_10H)
    assert total == 2880 and round(pct, 2) == 99.65
    days = report.uptime_days("dispo", 3, LUNDI_10H)
    assert [round(p) if p is not None else None for _, p in days] == [None, 99, 100]
    assert report.uptime("inconnue", 7, LUNDI_10H)[0] is None


def test_une_fois_par_semaine(monkeypatch):
    sent = []
    monkeypatch.setattr(report, "send", lambda now=None, force=False: sent.append(now) or (True, ""))
    db.kv_set("weekly_report", "")
    assert not report.maybe_send(LUNDI_8H) and not report.maybe_send(MARDI)
    assert report.maybe_send(LUNDI_10H) and not report.maybe_send(LUNDI_10H + 3600)
    assert sent == [LUNDI_10H]


def test_contenu(monkeypatch):
    monkeypatch.setattr(report.nodes, "local_info", lambda: {"disk": 10, "disk_total": 100, "mem": 1, "mem_total": 4})
    title, text = report.build(LUNDI_10H)
    assert title.startswith("Rapport de la semaine") and "SAUVEGARDES" in text and "MACHINES" in text
