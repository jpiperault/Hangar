"""Compose généré : réseau propre à l'appli, durcissement, ports jamais publics, valeurs non interprétées."""
import json

import pytest

from app import platform as P


@pytest.fixture
def compose(tmp_path, monkeypatch, app_row):
    monkeypatch.setattr(P, "APPS_DIR", str(tmp_path))
    path = P.write_compose(app_row, app_row["version"])
    return json.loads("".join(l for l in open(path) if not l.startswith("#")))


def test_reseau_propre(compose):
    svc = compose["services"]["app"]
    assert svc["networks"] == ["hangar-mon-jeu"]
    assert compose["networks"] == {"hangar-mon-jeu": {"external": True}}
    assert "platform" not in json.dumps(compose["networks"])


def test_durcissement(compose):
    svc = compose["services"]["app"]
    assert "no-new-privileges:true" in svc["security_opt"]
    assert {"NET_RAW", "MKNOD"} <= set(svc["cap_drop"])
    assert svc["pids_limit"] == 1024 and svc["mem_limit"] == "384m"
    assert "privileged" not in svc and "cap_add" not in svc and "network_mode" not in svc


def test_ports_jamais_sur_toutes_les_interfaces(compose):
    for p in compose["services"]["app"]["ports"]:
        host = p.rsplit(":", 2)[0]
        assert host and host not in ("0.0.0.0", "::"), p


def test_variables_sans_interpolation(compose):
    env = compose["services"]["app"]["environment"]
    assert env["PRIX"] == "10$$"   # compose n'interprète pas « $ »
    assert env["DATABASE_URL"].startswith("postgresql://app_mon_jeu:") and "@postgres:5432/app_mon_jeu" in env["DATABASE_URL"]


def test_seul_data_est_monte(compose, tmp_path):
    assert compose["services"]["app"]["volumes"] == [f"{tmp_path}/mon-jeu/data:/data"]
