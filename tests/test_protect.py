"""Protéger une appli : mot de passe et adresses autorisées, en Caddy valide."""
import shutil
import subprocess

import pytest

from app import db, protect
from app import platform as P

pytestmark = pytest.mark.skipif(not shutil.which("caddy"), reason="caddy absent (empreinte et validation)")


@pytest.fixture
def appli(app_row, monkeypatch):
    from app import domains as D
    db.x("DELETE FROM apps WHERE slug = 'mon-jeu'")
    db.insert_app("mon-jeu", {**app_row, "state": "ok", "created_at": 0})
    db.kv_set("app_protect", None)
    if not D.get("exemple.fr"):
        D.save("exemple.fr", "tunnel", "apps", make_default=False)
    D.set_routes("mon-jeu", [{"kind": "sub", "domain": "exemple.fr", "sub": "jeu"}, {"kind": "path", "domain": "exemple.fr"}])
    yield
    db.kv_set("app_protect", None)
    D.set_routes("mon-jeu", [])
    db.x("DELETE FROM apps WHERE slug = 'mon-jeu'")


def test_saisie(appli):
    with pytest.raises(ValueError):
        protect.add_user("mon-jeu", "a b", "motdepasse")
    with pytest.raises(ValueError):
        protect.add_user("mon-jeu", "ana", "court")
    protect.add_user("mon-jeu", "ana", "un-bon-mot-de-passe")
    assert protect.of("mon-jeu")["users"][0]["hash"].startswith("$2")
    assert protect.parse_ips("203.0.113.4, 2001:db8::/48") == ["203.0.113.4/32", "2001:db8::/48"]
    for bad in ("pas-une-ip", "0.0.0.0/0"):
        with pytest.raises(ValueError):
            protect.parse_ips(bad)
    protect.remove_user("mon-jeu", "ana")
    assert protect.of("mon-jeu") == {}


def test_caddy_valide(appli, tmp_path):
    protect.add_user("mon-jeu", "ana", "un-bon-mot-de-passe")
    protect.set_ips("mon-jeu", ["203.0.113.4/32"])
    conf = P.render_caddyfile({**db.settings(), "tunnel_bind": "127.0.0.1:8080"}, db.apps())
    assert conf.count("basic_auth") == 2 and "not client_ip 203.0.113.4/32" in conf and "not path /.well-known/hangar/*" in conf
    f = tmp_path / "Caddyfile"
    f.write_text(conf.replace(P.ACCESS_LOG, str(tmp_path / "a.log")))
    r = subprocess.run(["caddy", "validate", "--config", str(f), "--adapter", "caddyfile"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-400:]
