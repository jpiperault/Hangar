"""Page de statut publique (status.<domaine>) : état actuel et disponibilité sur 30 jours des applis choisies.

Page fixe régénérée chaque minute dans public/_status/index.html, servie par Caddy (console et nœuds qui reçoivent
le trafic : envoyée seulement quand son contenu change). Aucune donnée interne : noms affichés, état, pourcentages.
Réglage kv « status_page » : {on, domain, sub, title, apps: [slugs]}.
"""
import html
import os
import time

from . import db
from . import domains as D
from . import platform as P

DIR = "_status"
DEFAULT = {"on": False, "domain": "", "sub": "status", "title": "État des services", "apps": []}
_last = {"sig": None, "ts": 0}


def settings():
    s = {**DEFAULT, **(db.kv_get("status_page") or {})}
    if not s["domain"]:
        d = D.default()
        s["domain"] = d["name"] if d else ""
    return s


def host(s=None):
    s = s or settings()
    return f"{s['sub']}.{s['domain']}" if s["on"] and s["domain"] and s["sub"] else None


def save(on, domain, sub, title, apps):
    sub = (sub or "").strip().lower()
    import re
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", sub):
        raise ValueError("sous-domaine invalide")
    if domain not in D.by_name():
        raise ValueError("domaine inconnu")
    if db.one("SELECT 1 FROM routes WHERE kind = 'sub' AND domain = ? AND sub = ?", (domain, sub)):
        raise ValueError(f"{sub}.{domain} est déjà l'adresse d'une appli")
    if D.get(domain)["hub"] == sub:
        raise ValueError(f"{sub}.{domain} sert déjà aux routes par chemin")
    title = (title or "").strip()[:80] or DEFAULT["title"]
    known = {a["slug"] for a in db.apps()}
    db.kv_set("status_page", {"on": bool(on), "domain": domain, "sub": sub, "title": title,
                              "apps": [a for a in apps if a in known]})


def _state(a):
    from . import monitor
    if a["desired"] != "running":
        return "off", "Arrêté"
    if P.maintenance(a["slug"]):
        return "maint", "Maintenance"
    h = monitor.health.get(a["slug"])
    if a["state"] == "deploying":
        return "ok", "Opérationnel"
    if h is None:
        return "unk", "Inconnu"
    return ("ok", "Opérationnel") if h["ok"] or monitor._fails.get(a["slug"], 0) < 2 else ("down", "Panne")


def render(now=None):
    """(html, signature sans l'heure) de la page."""
    from . import report
    now = now or time.time()
    s = settings()
    esc = lambda t: html.escape(str(t), quote=True)   # noqa: E731
    rows, states = [], []
    for slug in s["apps"]:
        a = db.app(slug)
        if not a:
            continue
        st, label = _state(a)
        states.append(st)
        days = report.uptime_days(slug, 30, now)
        pct = report.uptime(slug, 30, now)[0]
        bars = "".join(
            f'<i class="{"n" if p is None else ("g" if p >= 99.5 else ("y" if p >= 95 else "r"))}" '
            f'title="{d[8:10]}/{d[5:7]} : {"pas de mesure" if p is None else f"{p:.2f} %".replace(".", ",")}"></i>'
            for d, p in days)
        rows.append(f'<section><div class="h"><b>{esc(a["name"])}</b><span class="s {st}">{label}</span></div>'
                    f'<div class="bars" aria-label="Disponibilité sur 30 jours">{bars}</div>'
                    f'<div class="f"><span>il y a 30 jours</span><span>{"—" if pct is None else f"{pct:.2f} %".replace(".", ",")}'
                    f' sur 30 jours</span><span>aujourd\'hui</span></div></section>')
    if not states:
        head, cls = "Aucun service affiché", "unk"
    elif "down" in states:
        head, cls = "Panne en cours", "down"
    elif "maint" in states:
        head, cls = "Maintenance en cours", "maint"
    elif all(x in ("ok", "off") for x in states):
        head, cls = "Tous les services sont opérationnels", "ok"
    else:
        head, cls = "État partiellement inconnu", "unk"
    sig = "".join(rows) + head + s["title"]
    page = f"""<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="60"><title>{esc(s['title'])}</title><style>
:root{{--bg:#f6f7f9;--fg:#1d2330;--mut:#6b7385;--card:#fff;--line:#e3e6eb;--g:#1f9d6b;--y:#d9a300;--r:#d64545;--b:#3b6fd6;--n:#d5d9e0}}
@media (prefers-color-scheme:dark){{:root{{--bg:#12151b;--fg:#e7e9ee;--mut:#9aa2b1;--card:#1a1e26;--line:#2a303b;--n:#343b47}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}}main{{max-width:760px;margin:0 auto;padding:32px 16px}}
h1{{font-size:1.5rem;margin:0 0 18px}}.top{{padding:16px 18px;border-radius:10px;color:#fff;font-weight:600;margin-bottom:22px}}
.top.ok{{background:var(--g)}}.top.down{{background:var(--r)}}.top.maint{{background:var(--b)}}.top.unk{{background:var(--mut)}}
section{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:12px}}
.h{{display:flex;justify-content:space-between;gap:10px;margin-bottom:10px}}.s{{font-size:.9rem;font-weight:600}}
.s.ok{{color:var(--g)}}.s.down{{color:var(--r)}}.s.maint{{color:var(--b)}}.s.off,.s.unk{{color:var(--mut)}}
.bars{{display:flex;gap:2px;height:30px}}.bars i{{flex:1;border-radius:2px}}.g{{background:var(--g)}}.y{{background:var(--y)}}.r{{background:var(--r)}}.n{{background:var(--n)}}
.f{{display:flex;justify-content:space-between;color:var(--mut);font-size:.78rem;margin-top:6px}}footer{{color:var(--mut);font-size:.8rem;margin-top:22px}}
</style></head><body><main><h1>{esc(s['title'])}</h1><div class="top {cls}">{head}</div>
{''.join(rows) or '<p>Aucun service.</p>'}
<footer>Mis à jour le {time.strftime('%d/%m/%Y à %H:%M', time.localtime(now))} · vérifié chaque minute</footer></main></body></html>
"""
    return page, sig


def write(now=None, push=True):
    """Écrit la page (et l'envoie aux nœuds d'entrée si elle a changé, ou toutes les 10 minutes)."""
    if not host():
        return False
    page, sig = render(now)
    path = f"{P.PUBLIC}/{DIR}/index.html"
    os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
    with open(path + ".tmp", "w") as f:
        f.write(page)
    os.chmod(path + ".tmp", 0o644)
    os.replace(path + ".tmp", path)
    now = now or time.time()
    if push and (sig != _last["sig"] or now - _last["ts"] > 600):
        _last.update(sig=sig, ts=now)
        for n in P.ingress_nodes():
            P.nsh(n["id"], f"install -d -m 755 /srv/platform/public/{DIR} && cat > /srv/platform/public/{DIR}/index.html.tmp "
                           f"&& chmod 644 /srv/platform/public/{DIR}/index.html.tmp "
                           f"&& mv /srv/platform/public/{DIR}/index.html.tmp /srv/platform/public/{DIR}/index.html",
                  timeout=30, input=page)
    return True


def tick():
    write()
