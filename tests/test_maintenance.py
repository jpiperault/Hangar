"""Mode maintenance (page 503 dans Caddy) et point de restauration à la demande."""
import shutil
import subprocess

import pytest

from app import db
from app import platform as P


@pytest.fixture(autouse=True)
def propre(monkeypatch):
    monkeypatch.setattr(P, "apply_routing", lambda: None)
    db.kv_set("maintenance", {})
    yield
    db.kv_set("maintenance", {})


def test_manuel_et_automatique():
    assert P.set_maintenance("mon-jeu", True, msg="migration")
    assert P.set_maintenance("mon-jeu", True, auto=True) is False      # une opération ne remplace pas la main
    assert P.set_maintenance("mon-jeu", False, auto=True) is False     # ni ne la retire
    assert P.maintenance("mon-jeu")["msg"] == "migration"
    assert P.set_maintenance("mon-jeu", False)
    assert P.set_maintenance("mon-jeu", True, auto=True) and P.maintenance("mon-jeu")["auto"]
    assert P.set_maintenance("mon-jeu", False, auto=True) and not P.maintenance("mon-jeu")


def test_page_echappee(app_row):
    P.set_maintenance("mon-jeu", True, msg="Retour `bientôt` <script>")
    lines = P._upstream({**app_row, "name": "Mon <jeu>"}, None, "\t")
    body = lines[-1]
    assert "respond `" in body and body.endswith("` 503") and body.count("`") == 2
    assert "<script>" not in body and "&lt;script&gt;" in body and "Mon &lt;jeu&gt;" in body
    assert "\theader X-Hangar-Maintenance 1" in lines


@pytest.mark.skipif(not shutil.which("caddy"), reason="caddy absent")
def test_caddy_accepte(app_row, tmp_path):
    P.set_maintenance("mon-jeu", True, msg='Fin à 14 h "promis"')
    conf = tmp_path / "Caddyfile"
    conf.write_text("http://x.test:8080 {\n" + "\n".join(P._upstream(app_row, None, "\t")) + "\n}\n")
    r = subprocess.run(["caddy", "validate", "--config", str(conf), "--adapter", "caddyfile"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-400:]
