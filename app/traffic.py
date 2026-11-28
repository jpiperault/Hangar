"""Trafic par appli : journal d'accès détaillé et statistiques de visite, tirés du journal JSON de Caddy.

stats.collect_requests() lit déjà ce journal chaque minute (console et nœuds d'entrée) ; il passe ici chaque ligne
d'une appli. Base à part (traffic.db, à côté de platform.db, hors sauvegarde) pour ne pas alourdir le registre :
- hits : une ligne par requête, sauf les fichiers statiques réussis (images, CSS, JS…, seulement comptés) ;
  chemin sans paramètres (ils peuvent contenir des jetons), origine réduite à son nom de domaine ;
- daily : compteurs par appli et par jour (requêtes, octets, codes, robots ; puis, une fois la journée finie,
  visiteurs, pages, origines, pays, navigateurs…) pour les périodes plus longues que le journal.
Visiteurs uniques sans cookie : adresse + navigateur, comptés sur la période. Pays : en-tête Cf-IPCountry
(domaines en mode tunnel). Réglage kv « traffic_settings » : durée du journal, des adresses complètes, plafond.
"""
import ipaddress
import os
import re
import sqlite3
import threading
import time
from urllib.parse import urlsplit

from . import db

PATH = os.path.join(os.path.dirname(os.path.abspath(db.DB_PATH)), "traffic.db")
DEFAULTS = {"days": 14, "ip_days": 7, "max_rows": 500000, "autoblock": 0}
DAILY_DAYS = 400
RANGES = {"1h": (3600, 300), "24h": (86400, 3600), "7j": (7 * 86400, 6 * 3600), "30j": (30 * 86400, 86400)}

SCHEMA = """
CREATE TABLE IF NOT EXISTS hits (app TEXT NOT NULL, ts REAL NOT NULL, ip TEXT, cc TEXT, method TEXT, path TEXT,
  status INTEGER, dur REAL, size INTEGER, ua TEXT, br TEXT, dev TEXT, bot TEXT, ref TEXT, page INTEGER DEFAULT 0,
  trunc INTEGER DEFAULT 0);
CREATE INDEX IF NOT EXISTS hits_app_ts ON hits(app, ts);
CREATE INDEX IF NOT EXISTS hits_ts ON hits(ts);
CREATE TABLE IF NOT EXISTS daily (app TEXT NOT NULL, day TEXT NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL,
  n INTEGER NOT NULL, PRIMARY KEY (app, day, kind, key)) WITHOUT ROWID;
"""

_lock = threading.RLock()
_c = None


def conn():
    global _c
    with _lock:
        if _c is None:
            os.close(os.open(PATH, os.O_CREAT | os.O_RDWR, 0o600))   # adresses IP : lisible par root seulement
            _c = sqlite3.connect(PATH, check_same_thread=False, isolation_level=None)
            _c.row_factory = sqlite3.Row
            _c.execute("PRAGMA journal_mode=WAL")
            _c.execute("PRAGMA synchronous=NORMAL")
            _c.executescript(SCHEMA)
            for f in (PATH, PATH + "-wal", PATH + "-shm"):
                if os.path.exists(f):
                    os.chmod(f, 0o600)
        return _c


def q(sql, args=()):
    with _lock:
        return [dict(r) for r in conn().execute(sql, args).fetchall()]


def x(sql, args=()):
    with _lock:
        return conn().execute(sql, args)


def settings():
    s = dict(DEFAULTS)
    s.update({k: v for k, v in (db.kv_get("traffic_settings") or {}).items() if k in DEFAULTS})
    return s


def save_settings(days, ip_days, max_rows, autoblock=None):
    days, ip_days, max_rows = int(days), int(ip_days), int(max_rows)
    autoblock = settings()["autoblock"] if autoblock is None else int(autoblock or 0)
    if autoblock not in (0, 1, 24, 168):
        raise ValueError("blocage automatique : non, 1 h, 24 h ou 7 jours")
    if not 1 <= days <= 90:
        raise ValueError("journal détaillé : entre 1 et 90 jours")
    if not 1 <= ip_days <= days:
        raise ValueError("adresses complètes : entre 1 jour et la durée du journal")
    if not 10000 <= max_rows <= 5000000:
        raise ValueError("plafond : entre 10 000 et 5 000 000 lignes par appli")
    db.kv_set("traffic_settings", {"days": days, "ip_days": ip_days, "max_rows": max_rows, "autoblock": autoblock})


# ---------------------------------------------------------------- lecture d'une ligne du journal de Caddy

STATIC = re.compile(r"\.(css|js|mjs|map|png|jpe?g|gif|svg|webp|avif|ico|bmp|woff2?|ttf|otf|eot|mp4|webm|mp3|ogg|wasm)$", re.I)
BOTS = [("Googlebot", r"googlebot|google-inspectiontool|googleother"), ("bingbot", r"bingbot|bingpreview"),
        ("Applebot", r"applebot"), ("DuckDuckBot", r"duckduckbot"), ("YandexBot", r"yandex"),
        ("Baiduspider", r"baiduspider"), ("AhrefsBot", r"ahrefsbot"), ("SemrushBot", r"semrushbot"),
        ("GPTBot", r"gptbot|chatgpt-user|oai-searchbot"), ("ClaudeBot", r"claudebot|claude-web|anthropic"),
        ("facebook", r"facebookexternalhit|meta-externalagent"), ("Uptime Kuma", r"uptime-kuma"),
        ("curl", r"^curl/"), ("Wget", r"^wget/"), ("python", r"python-requests|python-urllib|aiohttp|httpx"),
        ("Go", r"go-http-client"), ("autre robot", r"bot\b|bot/|crawl|spider|slurp|scan|headless|monitor|scrapy|"
                                                 r"libwww|java/|zgrab|masscan|nmap|nuclei|httpclient")]
BOTS = [(n, re.compile(p, re.I)) for n, p in BOTS]


def classify(ua):
    """(navigateur, appareil, robot) ; robot = nom, ou '' pour un vrai navigateur."""
    ua = ua or ""
    if not ua.strip():
        return "", "", "sans navigateur"
    for name, rx in BOTS:
        if rx.search(ua):
            return "", "", name
    u = ua.lower()
    if "edg/" in u or "edga/" in u or "edgios/" in u:
        br = "Edge"
    elif "opr/" in u or "opera" in u:
        br = "Opera"
    elif "samsungbrowser" in u:
        br = "Samsung Internet"
    elif "firefox/" in u or "fxios/" in u:
        br = "Firefox"
    elif "chrome/" in u or "crios/" in u or "chromium" in u:
        br = "Chrome"
    elif "safari/" in u or "applewebkit" in u:
        br = "Safari"
    elif "okhttp" in u or "dalvik" in u or "cfnetwork" in u or "dart:io" in u:
        br = "Appli mobile"
    else:
        br = "Autre"
    if "ipad" in u or "tablet" in u or ("android" in u and "mobile" not in u and br != "Appli mobile"):
        dev = "Tablette"
    elif "mobi" in u or "iphone" in u or "android" in u or br == "Appli mobile":
        dev = "Mobile"
    else:
        dev = "Ordinateur"
    return br, dev, ""


def _h(headers, name):
    v = (headers or {}).get(name) or []
    return (v[0] if isinstance(v, list) and v else v if isinstance(v, str) else "") or ""


def ref_host(ref, host):
    try:
        h = (urlsplit(ref).hostname or "").lower()
    except ValueError:
        return ""
    h = h[4:] if h.startswith("www.") else h
    own = (host or "").split(":")[0].lower()
    return "" if not h or h == own or h == own.removeprefix("www.") else h[:120]


def truncate_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if a.version == 4:
        return str(ipaddress.ip_network(f"{a}/24", strict=False).network_address)
    return str(ipaddress.ip_network(f"{a}/48", strict=False).network_address)


def day_of(ts):
    return time.strftime("%Y-%m-%d", time.localtime(ts))


def parse(d):
    """Ligne JSON de Caddy (d'une appli) → (ligne du journal ou None si fichier statique réussi, compteurs du jour)."""
    r = d.get("request") or {}
    hd = r.get("headers") or {}
    status = int(d.get("status") or 0)
    ua = _h(hd, "User-Agent")[:300]
    br, dev, bot = classify(ua)
    ts = float(d.get("ts") or time.time())
    path = (r.get("uri") or "/").split("?", 1)[0][:300] or "/"
    cls = f"{status // 100}xx" if 100 <= status < 600 else "autre"
    tot = {"req": 1, "bytes": int(d.get("size") or 0), cls: 1}
    if bot:
        tot["bot"] = 1
    if STATIC.search(path) and status < 400:
        return None, tot
    cc = _h(hd, "Cf-Ipcountry").upper()
    ctype = _h(d.get("resp_headers"), "Content-Type").lower()
    page = int(r.get("method") == "GET" and status == 200 and ctype.startswith("text/html"))
    row = (d["hangar_app"], ts, r.get("client_ip") or r.get("remote_ip") or "", cc if re.fullmatch(r"[A-Z]{2}", cc) and cc not in ("XX", "T1") else "",
           (r.get("method") or "")[:10], path, status, float(d.get("duration") or 0), int(d.get("size") or 0), ua, br, dev, bot,
           ref_host(_h(hd, "Referer"), r.get("host")), page)
    return row, tot


def store(lines):
    """Enregistre des lignes JSON de Caddy déjà décodées (celles qui portent hangar_app)."""
    rows, tots = [], {}
    for d in lines:
        try:
            row, tot = parse(d)
        except (TypeError, ValueError, KeyError):
            continue
        if row:
            rows.append(row)
        key = (d["hangar_app"], day_of(float(d.get("ts") or time.time())))
        acc = tots.setdefault(key, {})
        for k, v in tot.items():
            acc[k] = acc.get(k, 0) + v
    if not rows and not tots:
        return 0
    with _lock:
        c = conn()
        c.execute("BEGIN")
        try:
            c.executemany("INSERT INTO hits(app, ts, ip, cc, method, path, status, dur, size, ua, br, dev, bot, ref, page) "
                          "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
            c.executemany("INSERT INTO daily(app, day, kind, key, n) VALUES(?, ?, 'tot', ?, ?) "
                          "ON CONFLICT(app, day, kind, key) DO UPDATE SET n = n + excluded.n",
                          [(app, day, k, v) for (app, day), acc in tots.items() for k, v in acc.items()])
            c.execute("COMMIT")
        except Exception:
            c.execute("ROLLBACK")
            raise
    return len(rows)


# ---------------------------------------------------------------- entretien (toutes les heures)

def _day_bounds(day):
    start = time.mktime(time.strptime(day, "%Y-%m-%d"))
    end = time.mktime(time.strptime(day_of(start + 26 * 3600), "%Y-%m-%d"))   # lendemain minuit (changement d'heure)
    return start, end


def _aggs(slug, start, end, bots=False):
    """Visiteurs, pages et classements d'une appli sur [start, end[ depuis le journal détaillé."""
    w = "app = ? AND ts >= ? AND ts < ?" + ("" if bots else " AND bot = ''")
    a = (slug, start, end)
    vis = "count(DISTINCT ip || '|' || ua)"
    one = q(f"SELECT {vis} v, sum(page) p, count(*) n FROM hits WHERE {w}", a)[0]

    def top(col, metric=vis, extra="", limit=10):
        return [(r["k"], r["n"]) for r in q(f"SELECT {col} k, {metric} n FROM hits WHERE {w}{extra} GROUP BY k "
                                            "ORDER BY n DESC LIMIT ?", a + (limit,))]
    return {
        "visitors": one["v"] or 0, "pages": one["p"] or 0, "hits": one["n"] or 0,
        "page": top("path", "sum(page)", " AND page = 1"),
        "ref": top("ref"), "cc": top("cc"), "br": top("br", extra=" AND br != ''"), "dev": top("dev", extra=" AND dev != ''"),
        "code": top("status", "count(*)", limit=20),
        "404": top("path", "count(*)", " AND status = 404", limit=5),
        "bot": [(r["k"], r["n"]) for r in q("SELECT bot k, count(*) n FROM hits WHERE app = ? AND ts >= ? AND ts < ? "
                                            "AND bot != '' GROUP BY k ORDER BY n DESC LIMIT 10", a)],
    }


ROLL_KINDS = ("page", "ref", "cc", "br", "dev", "code", "404", "bot")


def rollup(day=None, now=None):
    """Résume les journées finies (hors robots) dans daily, avant que le journal détaillé ne les oublie."""
    now = now or time.time()
    today = day_of(now)
    if day:
        days = [day]
    else:   # depuis le dernier jour résumé (ou le plus ancien du journal) jusqu'à hier
        oldest = q("SELECT min(ts) t FROM hits")[0]["t"]
        if oldest is None:
            return 0
        d, until, days = day_of(oldest), db.kv_get("traffic_rolled") or "", []
        while d < today:
            if d > until:
                days.append(d)
            d = day_of(_day_bounds(d)[1] + 3600)
    done = 0
    for d in sorted(set(days)):
        if d >= today:
            continue
        for app in [r["app"] for r in q("SELECT DISTINCT app FROM hits WHERE ts >= ? AND ts < ?", _day_bounds(d))]:
            if q("SELECT 1 FROM daily WHERE app = ? AND day = ? AND kind = 'sum' AND key = 'rolled'", (app, d)):
                continue
            g = _aggs(app, *_day_bounds(d))
            vals = [(app, d, "sum", "visitors", g["visitors"]), (app, d, "sum", "pages", g["pages"]),
                    (app, d, "sum", "rolled", 1)]
            vals += [(app, d, k, str(key), n) for k in ROLL_KINDS for key, n in g[k]]
            with _lock:
                conn().executemany("INSERT OR REPLACE INTO daily(app, day, kind, key, n) VALUES(?, ?, ?, ?, ?)", vals)
            done += 1
        if not day:
            db.kv_set("traffic_rolled", d)
    return done


def purge(now=None):
    now = now or time.time()
    s = settings()
    rollup(now=now)
    x("DELETE FROM hits WHERE ts < ?", (now - s["days"] * 86400,))
    old = q("SELECT rowid, ip FROM hits WHERE trunc = 0 AND ts < ? LIMIT 200000", (now - s["ip_days"] * 86400,))
    if old:
        with _lock:
            conn().executemany("UPDATE hits SET ip = ?, trunc = 1 WHERE rowid = ?", [(truncate_ip(r["ip"]), r["rowid"]) for r in old])
    for r in q("SELECT app, count(*) n FROM hits GROUP BY app HAVING n > ?", (s["max_rows"],)):
        x("DELETE FROM hits WHERE rowid IN (SELECT rowid FROM hits WHERE app = ? ORDER BY ts LIMIT ?)",
          (r["app"], r["n"] - s["max_rows"]))
    x("DELETE FROM daily WHERE day < ?", (day_of(now - DAILY_DAYS * 86400),))


def forget(slug):
    x("DELETE FROM hits WHERE app = ?", (slug,))
    x("DELETE FROM daily WHERE app = ?", (slug,))


# ---------------------------------------------------------------- lecture pour la page Trafic

def _merge(*lists, limit=10):
    acc = {}
    for li in lists:
        for k, n in li:
            acc[k] = acc.get(k, 0) + n
    return sorted(acc.items(), key=lambda kv: -kv[1])[:limit]


def _rows(items, label=None, limit=10):
    items = items[:limit]
    top = max([n for _, n in items], default=0) or 1
    return [{"key": k, "label": (label(k) if label else k), "n": n, "w": max(2, round(n / top * 100))} for k, n in items]


COUNTRIES = {"FR": "France", "BE": "Belgique", "CH": "Suisse", "CA": "Canada", "US": "États-Unis", "DE": "Allemagne",
             "GB": "Royaume-Uni", "ES": "Espagne", "IT": "Italie", "NL": "Pays-Bas", "LU": "Luxembourg", "MA": "Maroc",
             "DZ": "Algérie", "TN": "Tunisie", "SN": "Sénégal", "CI": "Côte d'Ivoire", "PT": "Portugal", "IE": "Irlande",
             "PL": "Pologne", "SE": "Suède", "RU": "Russie", "CN": "Chine", "JP": "Japon", "IN": "Inde", "BR": "Brésil",
             "SG": "Singapour", "HK": "Hong Kong", "AU": "Australie", "RE": "La Réunion", "MQ": "Martinique",
             "GP": "Guadeloupe", "NC": "Nouvelle-Calédonie", "PF": "Polynésie française"}


def country(cc):
    return COUNTRIES.get(cc, cc) if cc else "Inconnu"


def overview(slug, rng="24h", bots=False, now=None):
    from . import stats
    now = int(now or time.time())
    span, step = RANGES.get(rng, RANGES["24h"])
    start = now - span
    daily = rng == "30j"
    if daily:   # jours finis : résumés ; aujourd'hui : journal détaillé
        today = day_of(now)
        first = day_of(start + 86400)
        tstart = _day_bounds(today)[0]
        g = _aggs(slug, tstart, now + 1)
        rows = q("SELECT day, kind, key, n FROM daily WHERE app = ? AND day >= ? AND day < ?", (slug, first, today))
        by = {}
        for r in rows:
            by.setdefault(r["kind"], []).append((r["key"], r["n"]))
        tops = {k: _merge(by.get(k, []), g[k], limit=20 if k == "code" else 10) for k in ROLL_KINDS}
        tops["code"] = [(int(k), n) for k, n in tops["code"]]
        sums = {}
        for r in rows:
            if r["kind"] == "sum":
                sums.setdefault(r["day"], {})[r["key"]] = r["n"]
        days = [day_of(start + 86400 * (i + 1)) for i in range(30)]
        vis = [(sums.get(d) or {}).get("visitors", 0) for d in days[:-1]] + [g["visitors"]]
        pag = [(sums.get(d) or {}).get("pages", 0) for d in days[:-1]] + [g["pages"]]
        slots = [int(_day_bounds(d)[0]) for d in days]
        visitors, pages = sum(vis), sum(pag)
        tot = {}
        for r in q("SELECT key, sum(n) n FROM daily WHERE app = ? AND day >= ? AND kind = 'tot' GROUP BY key", (slug, first)):
            tot[r["key"]] = r["n"]
        req = {"requests": tot.get("req", 0), "e5": tot.get("5xx", 0), "bytes": tot.get("bytes", 0), "p95": None}
    else:
        g = _aggs(slug, start, now + 1, bots)
        tops = {k: g[k] for k in ROLL_KINDS}
        first_slot = start // step * step + step
        slots = list(range(first_slot, now // step * step + step, step))
        idx = {t: i for i, t in enumerate(slots)}
        vis, pag = [0] * len(slots), [0] * len(slots)
        w = "" if bots else " AND bot = ''"
        for r in q(f"SELECT CAST(ts / {step} AS INTEGER) * {step} s, count(DISTINCT ip || '|' || ua) v, sum(page) p "
                   f"FROM hits WHERE app = ? AND ts >= ?{w} GROUP BY s", (slug, first_slot)):
            i = idx.get(r["s"])
            if i is not None:
                vis[i], pag[i] = r["v"], r["p"] or 0
        visitors, pages = g["visitors"], g["pages"]
        st = stats.series(slug, {"1h": "1h", "24h": "24h"}.get(rng, "7j"))
        su = st["summary"]
        b = db.q("SELECT sum(bytes) b FROM stats_req WHERE app = ? AND t >= ?", (slug, start))[0]["b"] or 0
        req = {"requests": su["requests"], "e5": su["errors5"], "bytes": b, "p95": su["p95_ms"]}
    codes = {}
    for code, n in tops["code"]:
        c = f"{int(code) // 100}xx"
        codes[c] = codes.get(c, 0) + n
    code_total = sum(codes.values()) or 1
    bot_n = sum(n for _, n in tops["bot"])
    hits_n = g["hits"] if not daily else None
    return {
        "range": rng, "step": step, "bots": bots, "daily": daily,
        "visitors": visitors, "pages": pages, "per_visitor": (pages / visitors) if visitors else None,
        "req": req, "error_rate": (req["e5"] / req["requests"] * 100) if req["requests"] else None,
        "t": slots, "vis": vis, "pag": pag,
        "top_pages": _rows(tops["page"]),
        "top_refs": _rows(tops["ref"], lambda k: k or "Accès direct"),
        "top_cc": _rows(tops["cc"], country),
        "top_br": _rows(tops["br"]), "top_dev": _rows(tops["dev"]),
        "codes": [{"label": c, "n": codes.get(c, 0), "w": round(codes.get(c, 0) / code_total * 100, 1)}
                  for c in ("2xx", "3xx", "4xx", "5xx") if codes.get(c)],
        "top_404": tops["404"][:5],
        "top_bots": _rows(tops["bot"]), "bot_n": bot_n, "bot_share": (bot_n / hits_n * 100) if hits_n else None,
        "suspects": [] if daily else suspects(slug, start, now + 1),
    }


def charts(ov):
    """Données pour charts.js (mêmes graphiques que les statistiques)."""
    per = "par jour" if ov["step"] >= 86400 else f"par {ov['step'] // 3600} h" if ov["step"] >= 3600 else f"par {ov['step'] // 60} min"
    return {"t": ov["t"], "step": ov["step"], "range": "7j" if ov["step"] >= 6 * 3600 else ov["range"],
            "charts": [{"title": "Visiteurs uniques", "sub": per, "unit": "", "kind": "bar", "values": ov["vis"]},
                       {"title": "Pages vues", "sub": per, "unit": "", "kind": "bar", "values": ov["pag"]}]}


JOURNAL_PERIODS = {"1h": 3600, "24h": 86400, "7j": 7 * 86400, "tout": None}


def journal(slug, period="24h", search="", status="", bots=True, limit=300, now=None):
    now = now or time.time()
    w, a = ["app = ?"], [slug]
    span = JOURNAL_PERIODS.get(period, 86400)
    if span:
        w.append("ts >= ?")
        a.append(now - span)
    if status in ("2", "3", "4", "5"):
        w.append("status >= ? AND status < ?")
        a += [int(status) * 100, int(status) * 100 + 100]
    elif status == "err":
        w.append("status >= 400")
    if not bots:
        w.append("bot = ''")
    s = (search or "").strip()[:200]
    if s:
        like = "%" + s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        w.append("(ip LIKE ? ESCAPE '\\' OR path LIKE ? ESCAPE '\\' OR ua LIKE ? ESCAPE '\\' OR ref LIKE ? ESCAPE '\\')")
        a += [like] * 4
    where = " AND ".join(w)
    rows = q(f"SELECT ts, ip, cc, method, path, status, dur, size, ua, br, dev, bot, ref, trunc FROM hits WHERE {where} "
             "ORDER BY ts DESC LIMIT ?", tuple(a) + (limit,))
    total = q(f"SELECT count(*) n FROM hits WHERE {where}", tuple(a))[0]["n"]
    return rows, total


def ip_detail(slug, ip, now=None):
    now = now or time.time()
    one = q("SELECT count(*) n, sum(status >= 400) err, min(ts) first, max(ts) last FROM hits WHERE app = ? AND ip = ?",
            (slug, ip))[0]
    if not one["n"]:
        return None
    day = q("SELECT count(*) n FROM hits WHERE app = ? AND ip = ? AND ts >= ?", (slug, ip, now - 86400))[0]["n"]
    uas = q("SELECT ua, bot, count(*) n FROM hits WHERE app = ? AND ip = ? GROUP BY ua ORDER BY n DESC LIMIT 3", (slug, ip))
    paths = q("SELECT path, count(*) n FROM hits WHERE app = ? AND ip = ? GROUP BY path ORDER BY n DESC LIMIT 6", (slug, ip))
    codes = q("SELECT status, count(*) n FROM hits WHERE app = ? AND ip = ? GROUP BY status ORDER BY n DESC LIMIT 5", (slug, ip))
    cc = q("SELECT cc FROM hits WHERE app = ? AND ip = ? AND cc != '' LIMIT 1", (slug, ip))
    return {"ip": ip, "n": one["n"], "n24": day, "err": one["err"] or 0, "first": one["first"], "last": one["last"],
            "uas": uas, "paths": paths, "codes": codes, "country": country(cc[0]["cc"]) if cc else ""}



# ---------------------------------------------------------------- comportements suspects

SCAN_MIN, SCAN_SHARE = 30, 0.8        # recherche de failles : au moins 30 erreurs 404, 80 % de ses requêtes en erreur
LOGIN_MIN = 20                        # essais de mots de passe : au moins 20 envois refusés (401/403)
WINDOW = 600                          # surveillance : 10 dernières minutes


def suspects(slug, start, end=None):
    """Adresses au comportement suspect sur [start, end[ : [{ip, kind, n, err, what, cc, paths}]."""
    from . import protect
    end = end or time.time() + 1
    blocked = [ipaddress.ip_network(n, strict=False) for n in protect.deny_ips(slug)]
    out = []
    rows = q("SELECT ip, count(*) n, sum(status = 404) nf, sum(status >= 400) err, "
             "sum(method = 'POST' AND status IN (401, 403)) lg, max(cc) cc FROM hits "
             "WHERE app = ? AND ts >= ? AND ts < ? AND trunc = 0 GROUP BY ip HAVING nf >= ? OR lg >= ? ORDER BY n DESC LIMIT 20",
             (slug, start, end, SCAN_MIN, LOGIN_MIN))
    for r in rows:
        try:
            a = ipaddress.ip_address(r["ip"])
        except ValueError:
            continue
        if a.is_private or a.is_loopback or any(a in n for n in blocked if n.version == a.version):
            continue
        if r["lg"] >= LOGIN_MIN:
            kind, what = "login", f"{r['lg']} connexions refusées (401/403)"
        elif r["err"] >= SCAN_SHARE * r["n"]:
            kind, what = "scan", f"{r['n']} requêtes, {round(r['err'] / r['n'] * 100)} % en erreur, recherche de fichiers absents"
        else:
            continue
        paths = [x["path"] for x in q("SELECT path, count(*) c FROM hits WHERE app = ? AND ip = ? AND ts >= ? AND ts < ? "
                                      "AND status >= 400 GROUP BY path ORDER BY c DESC LIMIT 3", (slug, r["ip"], start, end))]
        out.append({"ip": r["ip"], "kind": kind, "n": r["n"], "err": r["err"], "what": what, "cc": r["cc"] or "",
                    "paths": paths})
    return out


def watch(now=None):
    """Toutes les 5 minutes : alerte (et blocage, si réglé) pour chaque adresse suspecte des 10 dernières minutes."""
    from . import alerts, protect
    from . import platform as P
    now = now or time.time()
    s = settings()
    seen = {k: v for k, v in (db.kv_get("traffic_suspects") or {}).items() if v > now - 86400}
    changed = False
    for a in db.apps():
        for x in suspects(a["slug"], now - WINDOW, now + 1):
            key = f"{a['slug']}|{x['ip']}|{x['kind']}"
            if key in seen:
                continue
            seen[key] = now
            why = ("recherche de failles" if x["kind"] == "scan" else "essais de mots de passe") + f" : {x['what']}"
            blocked = ""
            if s["autoblock"]:
                try:
                    protect.block(a["slug"], x["ip"], s["autoblock"], why)
                    changed = True
                    blocked = f"\nBloquée automatiquement pour {s['autoblock']} h."
                except ValueError:
                    pass
            P.log("warn", a["slug"], f"comportement suspect de {x['ip']} : {why}" + (" ; bloquée" if blocked else ""))
            alerts.send(f"{a['name']} : comportement suspect", f"{x['ip']} ({country(x['cc'])}) : {why}.\n"
                        f"Chemins : {', '.join(x['paths'])}{blocked}\nJournal d'accès de l'appli : bloquer ou débloquer.",
                        priority=3, tags=["shield"])
    db.kv_set("traffic_suspects", seen)
    if changed or protect.expire(now):
        P.apply_routing()


# ---------------------------------------------------------------- export

CSV_COLUMNS = ("heure", "adresse", "pays", "méthode", "chemin", "statut", "durée_ms", "taille", "navigateur", "appareil",
               "robot", "origine")


def export_csv(slug, period="24h", search="", status="", bots=True, limit=100000):
    import csv
    import io
    rows, _ = journal(slug, period, search, status, bots, limit=limit)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(CSV_COLUMNS)
    for r in rows:
        w.writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"])), r["ip"], r["cc"], r["method"],
                    _cell(r["path"]), r["status"], round(r["dur"] * 1000), r["size"], r["br"], r["dev"], r["bot"], _cell(r["ref"])])
    return buf.getvalue()


def _cell(v):
    """Jamais de formule dans un tableur : une cellule qui commence par = + - @ est préfixée d'une apostrophe."""
    v = v or ""
    return "'" + v if v[:1] in ("=", "+", "-", "@") else v
