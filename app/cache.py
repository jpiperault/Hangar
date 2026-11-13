"""Cache en mémoire des mesures lentes (commandes Docker sur les nœuds, ~0,4 s chacune par SSH) :
une valeur périmée est servie aussitôt et rafraîchie en arrière-plan (« stale-while-revalidate ») ; un fil de
fond garde les plus utilisées au chaud, pour que les pages n'attendent jamais un nœud.
"""
import threading
import time

_data = {}            # clé -> (horodatage, valeur)
_running = set()      # clés en cours de rafraîchissement
_lock = threading.Lock()
_warm = {}            # clé -> (ttl, fonction, args) gardées au chaud par le fil de fond
_started = False


def _refresh(key, fn, args):
    try:
        v = fn(*args)
        with _lock:
            _data[key] = (time.time(), v)
    except Exception:
        pass
    finally:
        with _lock:
            _running.discard(key)


def _spawn(key, fn, args):
    with _lock:
        if key in _running:
            return
        _running.add(key)
    threading.Thread(target=_refresh, args=(key, fn, args), daemon=True, name=f"cache-{key}").start()


def get(key, ttl, fn, *args, wait=True):
    """Valeur de moins de `ttl` secondes ; sinon la dernière connue (rafraîchie en arrière-plan) ;
    sinon calculée tout de suite (wait=True) ou None (wait=False, calcul lancé en arrière-plan)."""
    e = _data.get(key)
    if e and time.time() - e[0] < ttl:
        return e[1]
    if e:
        _spawn(key, fn, args)
        return e[1]
    if not wait:
        _spawn(key, fn, args)
        return None
    if key in _running:   # déjà en cours de lecture (page affichée juste avant) : on l'attend au lieu de la doubler
        end = time.time() + 60
        while key in _running and time.time() < end:
            time.sleep(0.05)
        e = _data.get(key)
        if e:
            return e[1]
    v = fn(*args)
    with _lock:
        _data[key] = (time.time(), v)
    return v


def age(key):
    e = _data.get(key)
    return time.time() - e[0] if e else None


def invalidate(*keys):
    """Oublie ces clés (toutes si aucune) : le prochain affichage les relit pour de vrai."""
    with _lock:
        for k in keys or list(_data):
            _data.pop(k, None)


def keep_warm(key, ttl, fn, *args):
    _warm[key] = (ttl, fn, args)
    start()


def _loop():
    while True:
        for key, (ttl, fn, args) in list(_warm.items()):
            e = _data.get(key)
            if not e or time.time() - e[0] > ttl * 0.7:   # rafraîchie un peu avant d'être périmée
                _spawn(key, fn, args)
        time.sleep(3)


def start():
    global _started
    if not _started:
        _started = True
        threading.Thread(target=_loop, daemon=True, name="hangar-cache").start()
