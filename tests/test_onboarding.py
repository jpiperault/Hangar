"""Premier démarrage : étapes, étapes essentielles restantes, masquage, valeurs par défaut neutres."""
import os

from app import alerts, backup, onboarding
from app import domains as D


def test_etapes(monkeypatch):
    monkeypatch.setattr(D, "all_domains", lambda: [])
    monkeypatch.setattr(backup, "configured", lambda: False)
    monkeypatch.setattr(alerts, "configured", lambda s=None: [])
    left = {x["key"] for x in onboarding.pending()}
    assert {"domain", "tunnel", "backup", "alerts"} <= left and "app" not in left   # facultatif : pas sur l'accueil
    monkeypatch.setattr(D, "all_domains", lambda: [{"name": "exemple.fr", "mode": "direct", "hub": "apps"}])
    monkeypatch.setattr(backup, "configured", lambda: True)
    left = {x["key"] for x in onboarding.pending()}
    assert "domain" not in left and "tunnel" not in left and "backup" not in left   # direct : pas de jeton de tunnel


def test_masquer():
    onboarding.set_hidden(True)
    assert onboarding.hidden()
    onboarding.set_hidden(False)
    assert not onboarding.hidden()


def test_valeurs_neutres():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for path in ("install.sh", "README.md", "deploy/platform.env.example", "deploy/nftables/platform.nft",
                 "app/__main__.py", "app/db.py", "app/main.py", "app/domains.py", "docs/prompt-deploiement.md"):
        txt = open(os.path.join(root, path)).read()
        assert "piperault.fr" not in txt and "192.168.91." not in txt, path   # ni domaine ni réseau personnels
