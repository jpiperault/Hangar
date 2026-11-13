"""Cache des mesures lentes : valeur fraîche, périmée servie puis rafraîchie, attente d'une lecture en cours."""
import threading
import time

from app import cache


def test_frais_perime_et_invalidation():
    calls = []
    f = lambda: calls.append(1) or len(calls)   # noqa: E731
    cache.invalidate("t1")
    assert cache.get("t1", 60, f) == 1 and cache.get("t1", 60, f) == 1 and len(calls) == 1
    cache._data["t1"] = (time.time() - 120, 1)          # périmée : servie tout de suite, relue en arrière-plan
    assert cache.get("t1", 60, f) == 1
    for _ in range(100):
        if cache._data["t1"][1] == 2:
            break
        time.sleep(0.02)
    assert cache.get("t1", 60, f) == 2
    cache.invalidate("t1")
    assert cache.get("t1", 60, f) == 3


def test_sans_attendre_puis_lecture_en_cours():
    go = threading.Event()
    calls = []

    def slow():
        calls.append(1)
        go.wait(2)
        return "ok"
    cache.invalidate("t2")
    assert cache.get("t2", 60, slow, wait=False) is None   # lancée en arrière-plan
    threading.Timer(0.2, go.set).start()
    assert cache.get("t2", 60, slow) == "ok" and len(calls) == 1   # attend celle en cours, ne la double pas
