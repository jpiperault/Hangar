"""Surveillance de l'extérieur : une machine choisie (de préférence un VPS loin de la console) ouvre l'adresse publique
de chaque appli par Internet, comme un visiteur. Elle voit ce que le contrôle interne ne voit pas : DNS, Cloudflare,
tunnel, certificat, Caddy d'entrée.

Toutes les `every` minutes, une seule connexion SSH vers la sonde : curl sur chaque adresse (10 s au plus). Une adresse
est en panne si rien ne répond, ou si elle renvoie 5xx (dont les erreurs propres à Cloudflare, 520 à 530) ; alerte
après `fails` échecs d'affilée, puis quand elle revient. Réglage kv « external_probe » : {on, node, every, fails} ;
résultats kv « external_checks » : {adresse: {slug, ok, code, ms, ts, fails, why}}.
"""
import time

from . import alerts, db
from . import domains as D
from . import platform as P

DEFAULT = {"on": False, "node": "", "every": 5, "fails": 2}
CF_ERRORS = {520: "Cloudflare ne joint pas le serveur", 521: "serveur injoignable pour Cloudflare",
             522: "délai dépassé vers le serveur", 523: "serveur introuvable", 524: "le serveur répond trop lentement",
             525: "échec TLS entre Cloudflare et le serveur", 526: "certificat du serveur refusé",
             530: "tunnel ou nom DNS non relié"}


def settings():
    return {**DEFAULT, **(db.kv_get("external_probe") or {})}


def save(on, node, every, fails):
    db.kv_set("external_probe", {"on": bool(on), "node": node or "", "every": max(1, min(60, int(every))),
                                 "fails": max(1, min(10, int(fails)))})


def results():
    return db.kv_get("external_checks") or {}


def targets():
    """[(appli, adresse)] des applis en marche, hors maintenance."""
    out = []
    for a in db.apps():
        if a["desired"] != "running" or P.maintenance(a["slug"]):
            continue
        for _, u in D.urls(a["slug"]):
            out.append((a, u))
    return out


SCRIPT = ("while read -r u; do r=$(curl -s -o /dev/null -A 'Hangar (surveillance externe)' --max-time 10 "
          "-w '%{http_code} %{time_total}' \"$u\" 2>/dev/null || echo '000 0'); echo \"$u $r\"; done")


def probe(node, urls):
    """{adresse: (code, secondes)} vus depuis la sonde (code 0 : rien n'a répondu)."""
    if not urls:
        return {}
    rc, out = P.nsh(node, SCRIPT, input="\n".join(urls) + "\n", timeout=15 * len(urls) + 30)
    if rc:
        raise RuntimeError(P.tail(out, 2))
    res = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] in urls:
            try:
                res[parts[0]] = (int(parts[1][-3:]), float(parts[2]))
            except ValueError:
                res[parts[0]] = (0, 0.0)
    return res


def why(code):
    if code == 0:
        return "aucune réponse (DNS, réseau ou délai)"
    return CF_ERRORS.get(code) or f"HTTP {code}"


def run(now=None):
    s = settings()
    if not s["node"]:
        return None
    now = now or time.time()
    tg = targets()
    seen = probe(s["node"], [u for _, u in tg])
    prev, out = results(), {}
    for a, u in tg:
        code, sec = seen.get(u, (0, 0.0))
        ok = 0 < code < 500
        p = prev.get(u) or {}
        fails = 0 if ok else (p.get("fails") or 0) + 1
        out[u] = {"slug": a["slug"], "ok": ok, "code": code, "ms": round(sec * 1000), "ts": now, "fails": fails,
                  "why": "" if ok else why(code), "since": p.get("since") if (p and p.get("ok") == ok) else now}
        if not ok and fails == s["fails"]:
            alerts.send(f"{a['name']} injoignable de l'extérieur", f"{u} : {why(code)} (vu depuis {s['node']}, "
                        f"{fails} essais d'affilée). Le contrôle interne peut la voir en marche : regarde le DNS, "
                        "Cloudflare, le tunnel ou le Caddy d'entrée.", priority=5, tags=["globe_with_meridians", "x"])
            P.log("error", a["slug"], f"injoignable de l'extérieur : {u} ({why(code)})")
        elif ok and (p.get("fails") or 0) >= s["fails"]:
            alerts.send(f"{a['name']} de nouveau joignable de l'extérieur", u, priority=3, tags=["white_check_mark"])
            P.log("ok", a["slug"], f"de nouveau joignable de l'extérieur : {u}")
    db.kv_set("external_checks", out)
    return out


def tick(now=None):
    s = settings()
    if not s["on"] or not s["node"]:
        return
    last = max([r.get("ts", 0) for r in results().values()], default=0)
    if (now or time.time()) - last >= s["every"] * 60 - 5:
        try:
            run(now)
            db.kv_set("external_error", None)
        except Exception as e:   # sonde injoignable : signalée une fois, pas à chaque minute
            if not db.kv_get("external_error"):
                P.log("warn", "supervision", f"surveillance de l'extérieur impossible depuis {s['node']} : {str(e)[:200]}")
            db.kv_set("external_error", str(e)[:300])
