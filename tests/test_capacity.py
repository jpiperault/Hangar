"""Capacité : pente du disque, jours restants, alertes."""
import time

from app import capacity, db


def test_pente():
    now = 1_000_000_000
    pts = [(now + h * 3600, 10 + h * (2 / 24)) for h in range(72)]      # +2 Go par jour
    assert abs(capacity.slope(pts) - 2) < 1e-6
    assert capacity.slope(pts[:10]) is None                             # trop peu de recul


def test_alerte_disque(monkeypatch):
    sent = []
    monkeypatch.setattr(capacity.alerts, "send", lambda title, *a, **k: sent.append((title, k.get("priority"))))
    db.kv_set("capacity", None)
    monkeypatch.setattr(capacity, "machines", lambda now=None: [
        {"id": "local", "data": True, "disk": 90, "disk_total": 100, "disk_pct": 90, "per_day": 2, "days_left": 2.5,
         "mem_total_mb": 2048, "mem_used_mb": 900, "allocated_mb": 1024},
        {"id": "vps", "data": True, "disk": 10, "disk_total": 100, "disk_pct": 10, "per_day": 0.1, "days_left": 850,
         "mem_total_mb": 2048, "mem_used_mb": 900, "allocated_mb": 3000}])
    capacity.check(time.time())
    assert sent == [("Disque de la console plein dans 2 jour(s)", 5), ("Mémoire du nœud vps surréservée", 3)]
    sent.clear()
    capacity.save(False, 14)
    capacity.check(time.time())
    assert not sent
    db.kv_set("capacity", None)
