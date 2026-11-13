"""Tâches planifiées : validation, échéances, lancement par la surveillance."""
import time

import pytest

from app import db, jobs

T = time.mktime((2026, 11, 13, 10, 0, 30, 0, 0, -1))   # vendredi 10:00:30


def J(**k):
    base = {"id": "x", "name": "t", "cmd": "true", "kind": "daily", "every": 60, "at": "10:00", "dow": 4, "on": True,
            "last": None, "created": T - 86400}
    return {**base, **k}


@pytest.mark.parametrize("f, msg", [
    ({"name": "", "cmd": "x"}, "nom"), ({"name": "a", "cmd": ""}, "commande"),
    ({"name": "a", "cmd": "x", "kind": "minutes", "every": "2"}, "entre 5"),
    ({"name": "a", "cmd": "x", "kind": "daily", "at": "25:00"}, "HH:MM"), ({"name": "a", "cmd": "x", "kind": "cron"}, "fréquence"),
])
def test_validation(f, msg):
    with pytest.raises(ValueError, match=msg):
        jobs.validate(f)


def test_validation_ok():
    j = jobs.validate({"name": " Purge ", "cmd": "echo ok", "kind": "weekly", "at": "04:30", "dow": "6"})
    assert j["name"] == "Purge" and j["dow"] == 6 and jobs.describe({**j}) == "chaque dimanche à 04:30"


def test_echeances():
    assert jobs.due(J(), T)                                            # 10:00 aujourd'hui, jamais lancée
    assert not jobs.due(J(last={"ts": T - 10}), T)                     # déjà faite à cette échéance
    assert not jobs.due(J(at="10:01"), T)                              # pas encore
    assert not jobs.due(J(at="07:00"), T)                              # manquée de plus de 2 h : sautée
    assert jobs.due(J(kind="weekly", dow=4), T) and not jobs.due(J(kind="weekly", dow=3), T)
    m = J(kind="minutes", every=15)
    assert jobs.due(m, T) and not jobs.due({**m, "last": {"ts": T - 20}}, T)
    assert not jobs.due(J(on=False), T)
    assert not jobs.due(J(created=T), T + 1)                           # créée après l'échéance : attend la suivante


def test_tick_lance_et_ne_chevauche_pas(app_row, monkeypatch):
    if not db.app(app_row["slug"]):
        db.insert_app(app_row["slug"], {**app_row, "state": "ok", "created_at": 0})
    db.update_app(app_row["slug"], state="ok", desired="running")
    db.kv_set("jobs", {"mon-jeu": [J()], "disparue": [J()]})
    started = []
    monkeypatch.setattr(jobs.P, "spawn", lambda fn, *a: started.append(a))
    assert jobs.tick(T) == [("mon-jeu", "x")] and "disparue" not in jobs.all_jobs()
    jobs._running.add("mon-jeu:x")
    try:
        assert jobs.tick(T) == []
    finally:
        jobs._running.discard("mon-jeu:x")
    db.kv_set("jobs", {})


def test_execution(app_row, monkeypatch):
    if not db.app(app_row["slug"]):
        db.insert_app(app_row["slug"], {**app_row, "state": "ok", "created_at": 0})
    db.kv_set("jobs", {"mon-jeu": [J(cmd="exit 3")]})
    calls, sent = [], []
    monkeypatch.setattr(jobs.P, "dk", lambda node, *a, **k: calls.append(a) or (3, "boum"))
    monkeypatch.setattr(jobs.P, "log", lambda *a, **k: None)
    monkeypatch.setattr(jobs.alerts, "send", lambda title, *a, **k: sent.append(title))
    assert jobs.run("mon-jeu", "x")
    assert calls[0] == ("exec", "app-mon-jeu-app-1", "sh", "-c", "exit 3")
    last = jobs.of("mon-jeu")[0]["last"]
    assert last["rc"] == 3 and last["out"] == "boum" and sent and "en échec" in sent[0]
    db.kv_set("jobs", {})
