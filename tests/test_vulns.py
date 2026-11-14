"""Analyse des vulnérabilités : lecture du rapport Trivy, alerte sur une nouvelle faille critique."""
import json

from app import db, vulns
from app import platform as P

REPORT = {"Results": [{"Target": "debian 12", "Vulnerabilities": [
    {"VulnerabilityID": "CVE-1", "Severity": "HIGH", "PkgName": "libc", "InstalledVersion": "1", "FixedVersion": "2"},
    {"VulnerabilityID": "CVE-2", "Severity": "CRITICAL", "PkgName": "openssl", "InstalledVersion": "3.0", "FixedVersion": ""},
    {"VulnerabilityID": "CVE-3", "Severity": "CRITICAL", "PkgName": "zlib", "InstalledVersion": "1.2", "FixedVersion": "1.3"},
    {"VulnerabilityID": "CVE-3", "Severity": "CRITICAL", "PkgName": "zlib", "InstalledVersion": "1.2", "FixedVersion": "1.3"},
    {"VulnerabilityID": "CVE-4", "Severity": "LOW", "PkgName": "x", "InstalledVersion": "1"}]}]}


def test_lecture():
    counts, items = vulns.parse(REPORT)
    assert counts == {"CRITICAL": 3, "HIGH": 1}
    assert [i["id"] for i in items] == ["CVE-3", "CVE-2", "CVE-1"]      # critiques corrigeables d'abord, doublon retiré


def test_alerte_nouvelle_critique(app_row, monkeypatch):
    db.x("DELETE FROM apps WHERE slug = 'mon-jeu'")
    db.insert_app("mon-jeu", {**app_row, "state": "ok", "created_at": 0})
    db.kv_set("vulns", None)
    sent = []
    monkeypatch.setattr(vulns.alerts, "send", lambda title, *a, **k: sent.append(title))
    monkeypatch.setattr(P, "log", lambda *a, **k: None)
    monkeypatch.setattr(P, "dk", lambda node, *args, timeout=0: (0, "sha256:abc") if args[0] == "image" else (0, json.dumps(REPORT)))
    r = vulns.scan("mon-jeu")
    assert r["counts"]["CRITICAL"] == 3 and not sent        # première analyse : notée, sans alerte
    vulns.scan("mon-jeu")
    assert not sent                                         # mêmes failles : rien de nouveau
    allv = db.kv_get("vulns")
    allv["mon-jeu"]["items"] = [i for i in allv["mon-jeu"]["items"] if i["id"] != "CVE-3"]
    db.kv_set("vulns", allv)
    vulns.scan("mon-jeu")
    assert sent == ["Mon jeu : 1 faille(s) critique(s)"]   # CVE-3 réapparaît : nouvelle
    db.kv_set("vulns", None)
    db.x("DELETE FROM apps WHERE slug = 'mon-jeu'")
