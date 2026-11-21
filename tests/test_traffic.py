"""Trafic par appli : lecture des lignes de Caddy, journal d'accès, visiteurs, résumés, conservation, pages."""
import time

import pytest

from app import db, stats, traffic


def line(app="blog", ts=None, ip="192.0.2.10", uri="/", status=200, ua="Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) "
         "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1", ref="", ctype="text/html; charset=utf-8",
         method="GET", cc="FR", host="blog.exemple.fr"):
    h = {"User-Agent": [ua], "Cf-Ipcountry": [cc]}
    if ref:
        h["Referer"] = [ref]
    return {"ts": ts or time.time(), "hangar_app": app, "status": status, "size": 1000, "duration": 0.04,
            "request": {"client_ip": ip, "remote_ip": "127.0.0.1", "method": method, "host": host, "uri": uri, "headers": h},
            "resp_headers": {"Content-Type": [ctype]}}


@pytest.fixture(autouse=True)
def vide():
    traffic.x("DELETE FROM hits")
    traffic.x("DELETE FROM daily")
    db.kv_set("traffic_settings", {})
    db.kv_set("traffic_rolled", "")
    yield


def test_classement_des_clients():
    assert traffic.classify("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/131.0 Safari/537.36 Edg/131.0") == ("Edge", "Ordinateur", "")
    assert traffic.classify("Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 Chrome/131.0 Mobile Safari/537.36")[:2] == ("Chrome", "Mobile")
    assert traffic.classify("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")[2] == "Googlebot"
    assert traffic.classify("curl/8.5.0")[2] == "curl"
    assert traffic.classify("")[2] == "sans navigateur"
    assert traffic.classify("okhttp/4.12.0") == ("Appli mobile", "Mobile", "")


def test_lecture_d_une_ligne():
    row, tot = traffic.parse(line(uri="/articles/x?token=SECRET123", ref="https://www.google.com/search?q=hangar"))
    assert row[5] == "/articles/x" and "SECRET123" not in str(row)            # paramètres jamais gardés
    assert row[13] == "google.com" and row[3] == "FR" and row[14] == 1        # origine réduite, pays, page HTML
    assert tot == {"req": 1, "bytes": 1000, "2xx": 1}
    assert traffic.parse(line(ref="https://blog.exemple.fr/a-propos"))[0][13] == ""   # navigation interne : pas une origine
    row, tot = traffic.parse(line(uri="/static/app.css", ctype="text/css"))
    assert row is None and tot["req"] == 1                                    # fichier statique réussi : compté seulement
    assert traffic.parse(line(uri="/static/manque.css", status=404))[0]      # … mais gardé s'il échoue
    assert traffic.parse(line(cc="XX"))[0][3] == ""
    assert traffic.parse(line(ctype="application/json"))[0][14] == 0         # API : pas une page vue


def test_collecte_depuis_le_journal_de_caddy(monkeypatch, tmp_path):
    import json
    log = tmp_path / "access.log"
    log.write_text("")
    monkeypatch.setattr(stats.P, "ACCESS_LOG", str(log))
    monkeypatch.setattr(stats.P, "ingress_nodes", lambda: [])
    db.kv_set("stats_pos", {})
    stats.collect_requests()                                                  # premier passage : position notée
    with open(log, "a") as f:
        for d in (line(), line(ip="192.0.2.11"), {"msg": "autre site"}):
            f.write(json.dumps(d) + "\n")
    stats.collect_requests()
    assert traffic.q("SELECT count(*) n FROM hits WHERE app = 'blog'")[0]["n"] == 2


def test_vue_d_ensemble_et_journal(monkeypatch):
    now = time.time()
    traffic.store([line(ts=now - 60, ip="192.0.2.1", uri="/"), line(ts=now - 50, ip="192.0.2.1", uri="/a-propos"),
                   line(ts=now - 40, ip="192.0.2.2", uri="/", ref="https://news.ycombinator.com/item"),
                   line(ts=now - 30, ip="203.0.113.47", uri="/wp-login.php", status=404, ua="curl/8.5.0", cc="NL"),
                   line(ts=now - 20, ip="66.249.66.1", uri="/", ua="Googlebot/2.1", cc="US")])
    ov = traffic.overview("blog", "24h", now=now)
    assert ov["visitors"] == 2 and ov["pages"] == 3                           # robots exclus par défaut
    assert [r["key"] for r in ov["top_pages"]][0] == "/"
    assert {r["label"] for r in ov["top_refs"]} == {"Accès direct", "news.ycombinator.com"}
    assert ov["top_cc"][0]["label"] == "France"
    assert {r["key"] for r in ov["top_bots"]} == {"curl", "Googlebot"} and ov["bot_n"] == 2
    assert traffic.overview("blog", "24h", bots=True, now=now)["visitors"] == 4
    assert sum(ov["vis"]) >= 2 and len(ov["t"]) == len(ov["vis"])
    rows, total = traffic.journal("blog", "24h", now=now)
    assert total == 5 and rows[0]["ip"] == "66.249.66.1"                     # plus récente d'abord
    assert traffic.journal("blog", "24h", status="err", now=now)[1] == 1
    assert traffic.journal("blog", "24h", bots=False, now=now)[1] == 3
    assert traffic.journal("blog", "24h", search="wp-login", now=now)[1] == 1
    assert traffic.journal("blog", "24h", search="%", now=now)[1] == 0       # caractères spéciaux pris tels quels
    d = traffic.ip_detail("blog", "203.0.113.47", now=now)
    assert d["n"] == 1 and d["err"] == 1 and d["country"] == "Pays-Bas" and d["paths"][0]["path"] == "/wp-login.php"
    assert traffic.ip_detail("blog", "198.51.100.1") is None


def test_resumes_30_jours_et_conservation():
    now = time.time()
    old = now - 3 * 86400
    traffic.store([line(ts=old, ip="192.0.2.1"), line(ts=old + 10, ip="192.0.2.2", uri="/x"),
                   line(ts=now - 10 * 86400, ip="192.0.2.3"), line(ts=now - 60, ip="192.0.2.4")])
    traffic.purge(now=now)
    day = traffic.day_of(old)
    sums = {r["key"]: r["n"] for r in traffic.q("SELECT key, n FROM daily WHERE app = 'blog' AND day = ? AND kind = 'sum'", (day,))}
    assert sums["visitors"] == 2 and sums["pages"] == 2 and sums["rolled"] == 1
    ips = {r["ip"] for r in traffic.q("SELECT ip FROM hits")}
    assert "192.0.2.0" in ips and "192.0.2.4" in ips                         # 10 jours : tronquée ; récente : complète
    ov = traffic.overview("blog", "30j", now=now)
    assert ov["visitors"] == 4 and ov["daily"] and len(ov["vis"]) == 30
    assert ov["req"]["requests"] == 4
    db.kv_set("traffic_settings", {"days": 2, "ip_days": 1, "max_rows": 10000})
    traffic.purge(now=now)
    assert traffic.q("SELECT count(*) n FROM hits")[0]["n"] == 1            # au-delà de 2 jours : effacé
    assert traffic.overview("blog", "30j", now=now)["visitors"] == 4        # les résumés restent
    traffic.forget("blog")
    assert not traffic.q("SELECT 1 FROM daily") and not traffic.q("SELECT 1 FROM hits")


def test_plafond_et_reglages():
    now = time.time()
    db.kv_set("traffic_settings", {"days": 14, "ip_days": 7, "max_rows": 10000})
    traffic.store([line(ts=now - 20000 + i, ip=f"192.0.2.{i % 250}") for i in range(10005)])
    traffic.purge(now=now)
    assert traffic.q("SELECT count(*) n FROM hits")[0]["n"] == 10000
    assert traffic.q("SELECT min(ts) t FROM hits")[0]["t"] == now - 20000 + 5    # les plus anciennes parties
    with pytest.raises(ValueError):
        traffic.save_settings(14, 20, 100000)
    traffic.save_settings(30, 7, 100000)
    assert traffic.settings() == {"days": 30, "ip_days": 7, "max_rows": 100000}


def test_ip_tronquee():
    assert traffic.truncate_ip("203.0.113.47") == "203.0.113.0"
    assert traffic.truncate_ip("2001:db8:1234:5678::1") == "2001:db8:1234::"


def test_pages(monkeypatch):
    from argon2 import PasswordHasher
    from fastapi.testclient import TestClient
    from app import main
    db.x("DELETE FROM apps WHERE slug = 'trafic-essai'")
    db.insert_app("trafic-essai", {"name": "Essai", "pkg": "", "expose": "path", "sub": "", "source": "image",
                                   "image": "ghcr.io/exemple/app", "version": "1.0.0", "port": 8080, "host_port": 18077,
                                   "health_path": "/", "mem_mb": 256, "env": "", "db": 0, "db_password": "", "state": "ok",
                                   "desired": "running", "created_at": time.time(), "node": "local", "kind": "web"})
    traffic.store([line(app="trafic-essai", ip="192.0.2.9", uri="/bonjour<script>"),
                   line(app="trafic-essai", ip="203.0.113.5", uri="/.env", status=404, ua="curl/8.5.0")])
    db.x("INSERT OR REPLACE INTO users(username, hash) VALUES(?, ?)", ("tra", PasswordHasher().hash("mot-de-passe-tra")))
    c = TestClient(main.app, base_url="https://hangar.test", client=("127.0.0.1", 50042))
    main._fails.clear()
    same = {"sec-fetch-site": "same-origin"}
    c.post("/login", data={"username": "tra", "password": "mot-de-passe-tra"}, headers=same)
    for rng in traffic.RANGES:
        r = c.get(f"/apps/trafic-essai/trafic?r={rng}")
        assert r.status_code == 200 and "Visiteurs uniques" in r.text, rng
    r = c.get("/apps/trafic-essai/trafic?vue=journal&ip=203.0.113.5")
    assert r.status_code == 200 and "/.env" in r.text and "Adresse sélectionnée" in r.text
    assert "<script>" not in r.text.split("/bonjour")[1][:20]                # échappé
    r = c.post("/apps/trafic-essai/trafic/reglages", data={"days": "21", "ip_days": "3", "max_rows": "200000"},
               headers=same, follow_redirects=False)
    assert r.status_code in (302, 303) and traffic.settings()["days"] == 21
    db.x("DELETE FROM apps WHERE slug = 'trafic-essai'")
