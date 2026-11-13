"""Limite de processeur et alertes d'usage (mémoire, processeur, redémarrages)."""
import json
import time

import pytest

from app import cache, db, limits, monitor
from app import platform as P


@pytest.fixture
def appli(app_row, monkeypatch):
    if not db.app("mon-jeu"):
        db.insert_app("mon-jeu", {**app_row, "state": "ok", "created_at": 0})
    db.update_app("mon-jeu", desired="running", state="ok", mem_mb=200)
    db.kv_set("app_limits", {})
    db.x("DELETE FROM stats_res WHERE app = 'mon-jeu'")
    sent = []
    monkeypatch.setattr(monitor.alerts, "send", lambda title, *a, **k: sent.append(title))
    monkeypatch.setattr(monitor.P, "log", lambda *a, **k: None)
    monitor._flags.clear()
    monitor._restarts.clear()
    yield sent
    db.kv_set("app_limits", {})
    cache.invalidate("mon_containers")


def test_saisie():
    limits.save("mon-jeu", "1,5")
    assert limits.cpus("mon-jeu") == 1.5
    for bad in ("beaucoup", "0", "100"):
        with pytest.raises(ValueError):
            limits.save("mon-jeu", bad)
    limits.save("mon-jeu", "")
    assert limits.cpus("mon-jeu") is None


def test_compose(app_row, tmp_path, monkeypatch):
    monkeypatch.setattr(P, "app_dir", lambda slug: str(tmp_path / slug))
    monkeypatch.setattr(P, "compose_path", lambda slug, inst=None: str(tmp_path / slug / "compose.yml"))
    limits.save("mon-jeu", "0.5")
    svc = json.loads("".join(l for l in open(P.write_compose(app_row, "1")) if not l.startswith("#")))["services"]["app"]
    assert svc["cpus"] == 0.5
    limits.save("mon-jeu", "")
    svc = json.loads("".join(l for l in open(P.write_compose(app_row, "1")) if not l.startswith("#")))["services"]["app"]
    assert "cpus" not in svc


def _stats(now, minutes, cpu, mem):
    for i in range(minutes):
        db.x("INSERT OR REPLACE INTO stats_res(app, t, cpu, mem) VALUES('mon-jeu', ?, ?, ?)", (int(now) - i * 60, cpu, mem))


def test_memoire_et_processeur(appli):
    now = time.time()
    _stats(now, 10, 98, 190)                                          # 95 % de 200 Mo, processeur à 0,98 cœur
    monitor.check_usage(now)
    assert appli == ["Mon jeu : mémoire presque pleine"]              # pas de limite processeur : rien à signaler
    limits.save("mon-jeu", "1")
    monitor.check_usage(now)
    assert appli[-1] == "Mon jeu : processeur bridé"
    _stats(now, 10, 10, 50)
    monitor.check_usage(now)
    assert "Mon jeu : mémoire revenue à la normale" in appli and "Mon jeu : processeur revenu sous sa limite" in appli


def test_redemarrage(appli):
    cache._data["mon_containers"] = (time.time(), {"mon-jeu": {"restarts": 2, "started": 0, "oom": False}})
    monitor.check_usage()
    assert appli == []                                                # premier passage : référence
    cache._data["mon_containers"] = (time.time(), {"mon-jeu": {"restarts": 3, "started": 0, "oom": True}})
    monitor.check_usage()
    assert appli == ["Mon jeu a redémarré toute seule"]
