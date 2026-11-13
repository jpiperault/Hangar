"""Affinité par partie : réglage et politique de répartition de Caddy."""
import shutil
import subprocess

import pytest

from app import affinity, db
from app import platform as P


@pytest.fixture(autouse=True)
def propre():
    db.kv_set("ha_affinity", {})
    yield
    db.kv_set("ha_affinity", {})


@pytest.mark.parametrize("mode, name, policy", [
    ("", "", "lb_policy round_robin"), ("header", "", "lb_policy header X-Match-Id"),
    ("query", "partie", "lb_policy query partie"), ("cookie", "", "lb_policy cookie hangar_instance"),
    ("ip", "", "lb_policy client_ip_hash"),
])
def test_politique(mode, name, policy):
    affinity.save("jeu", mode, name)
    assert affinity.caddy_policy("jeu") == policy


def test_refus():
    for mode, name in (("header", "X Match"), ("query", "a&b"), ("magie", "")):
        with pytest.raises(ValueError):
            affinity.save("jeu", mode, name)


@pytest.mark.skipif(not shutil.which("caddy"), reason="caddy absent")
@pytest.mark.parametrize("mode", ["", "header", "query", "cookie", "ip"])
def test_caddy_accepte(mode, app_row, tmp_path, monkeypatch):
    from app import ha
    monkeypatch.setattr(ha, "instance_nodes", lambda a: ["local", "vps2"])
    monkeypatch.setattr(P, "node_wg", lambda n: "10.88.0.6")
    affinity.save(app_row["slug"], mode, "")
    conf = tmp_path / "Caddyfile"
    conf.write_text("http://x.test:8080 {\n" + "\n".join(P._upstream(app_row, None, "\t")) + "\n}\n")
    r = subprocess.run(["caddy", "validate", "--config", str(conf), "--adapter", "caddyfile"], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-400:]
