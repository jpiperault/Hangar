"""MySQL / MariaDB comme service, dossiers persistants, détection des nouvelles images sous un tag qui bouge."""
import json

import pytest

from app import catalog, db, monitor, registry, runopts, services
from app import platform as P


@pytest.fixture(autouse=True)
def propre():
    db.kv_set("app_services", {})
    db.kv_set("app_run", {})
    db.kv_set("image_updates", {})
    yield
    db.kv_set("app_services", {})
    db.kv_set("app_run", {})
    db.kv_set("image_updates", {})


def _doc(app_row, tmp_path, monkeypatch):
    monkeypatch.setattr(P, "app_dir", lambda slug: str(tmp_path / slug))
    monkeypatch.setattr(P, "compose_path", lambda slug, inst=None: str(tmp_path / slug / "compose.yml"))
    return json.loads("".join(l for l in open(P.write_compose(app_row, "1")) if not l.startswith("#")))


@pytest.mark.parametrize("engine", ["mariadb", "mysql"])
def test_compose(app_row, tmp_path, monkeypatch, engine):
    services.enable_mysql("mon-jeu", engine, 300)
    doc = _doc(app_row, tmp_path, monkeypatch)
    m, app = doc["services"]["mysql"], doc["services"]["app"]
    assert m["image"] == services.ENGINES[engine]["image"]
    raw, init = m["volumes"]
    assert raw == f"{tmp_path}/mon-jeu/mysql:/var/lib/mysql"                 # fichiers bruts hors de data/
    assert init == f"{tmp_path}/mon-jeu/data/.hangar-mysql:/docker-entrypoint-initdb.d:ro"
    assert "--innodb-buffer-pool-size=150M" in m["command"] and m["mem_limit"] == "300m"
    assert app["environment"]["MYSQL_HOST"] == "mysql" and app["environment"]["MYSQL_PASSWORD"] == services.mysql("mon-jeu")["password"]
    assert app["depends_on"] == {"mysql": {"condition": "service_healthy"}}
    assert m["networks"] == app["networks"]


def test_saisie():
    with pytest.raises(ValueError):
        services.enable_mysql("mon-jeu", "oracle", 256)
    with pytest.raises(ValueError):
        services.enable_mysql("mon-jeu", "mariadb", 64)
    services.enable_mysql("mon-jeu", "mariadb", 256)
    pw = services.mysql("mon-jeu")["password"]
    services.enable_mysql("mon-jeu", "mariadb", 512)
    assert services.mysql("mon-jeu")["password"] == pw and services.mysql("mon-jeu")["mem"] == 512
    with pytest.raises(ValueError):            # changer de moteur perdrait la base
        services.enable_mysql("mon-jeu", "mysql", 512)


def test_dossiers(app_row, tmp_path, monkeypatch):
    runopts.save("mon-jeu", {"mounts": "www:/var/www/html/, conf:/opt/app/conf"})
    assert runopts.of("mon-jeu")["mounts"] == "www:/var/www/html, conf:/opt/app/conf"
    vols = _doc(app_row, tmp_path, monkeypatch)["services"]["app"]["volumes"]
    assert f"{tmp_path}/mon-jeu/data/www:/var/www/html" in vols and f"{tmp_path}/mon-jeu/data:/data" in vols
    for bad in ("www:/", "www:/etc", "../x:/a", ".hangar-mysql:/a", "www:/a/../b", "a:/x, b:/x", "www"):
        with pytest.raises(ValueError):
            runopts.save("mon-jeu", {"mounts": bad})


def test_catalogue_mysql():
    for c in catalog.CATALOG:
        if c.get("mysql"):
            assert c["mysql"] in services.ENGINES and not c["db"]
            runopts.parse_mounts(c.get("mounts", ""))
            assert "{mysql_password}" in c["env"]


def test_nouvelle_image(app_row, monkeypatch):
    a = {**app_row, "version": "latest", "name": "Mon jeu"}
    sent = []
    monkeypatch.setattr(monitor.alerts, "send", lambda title, *x, **k: sent.append(title))
    monkeypatch.setattr(monitor.P, "log", lambda *x, **k: None)
    monkeypatch.setattr(registry, "digest", lambda image, tag: "sha256:neuf")
    monkeypatch.setattr(monitor, "_running_digests", lambda a: {"sha256:ancien"})
    assert monitor.check_image_update(a) is True and monitor.image_update("mon-jeu")["digest"] == "sha256:neuf"
    assert monitor.check_image_update(a) is False and len(sent) == 1          # une seule alerte par image
    monkeypatch.setattr(monitor, "_running_digests", lambda a: {"sha256:neuf"})
    monitor.check_image_update(a)
    assert monitor.image_update("mon-jeu") is None


def test_relais_email(app_row, tmp_path, monkeypatch):
    db.kv_set("mail_relay", None)
    with pytest.raises(ValueError):
        services.enable_mail("mon-jeu", "noreply@exemple.fr")          # pas de relais
    services.save_relay({"host": "smtp.exemple.fr", "port": 587, "security": "starttls", "user": "u", "password": "p$w",
                         "from": "noreply@exemple.fr"})
    with pytest.raises(ValueError):
        services.enable_mail("mon-jeu", "pas-une-adresse")
    services.enable_mail("mon-jeu", "jeu@exemple.fr")
    env = _doc({**app_row, "env": "SMTP_PORT=2525"}, tmp_path, monkeypatch)["services"]["app"]["environment"]
    assert env["SMTP_HOST"] == "smtp.exemple.fr" and env["SMTP_FROM"] == "jeu@exemple.fr"
    assert env["SMTP_PASSWORD"] == "p$$w" and env["SMTP_PORT"] == "2525"        # $ protégé ; réglage de l'appli gardé
    assert services.mail_users() == ["mon-jeu"]
    db.kv_set("mail_relay", None)


def test_haute_dispo(app_row, monkeypatch):
    from app import ha
    services.enable_mysql("mon-jeu", "mariadb", 256)
    monkeypatch.setattr(ha, "_ok", lambda n: True)
    monkeypatch.setattr(ha.P, "node_wg", lambda n: "10.88.0.9")
    a = {**app_row, "node": "n1"}
    assert ha.validate(a, "standby", ["n2"], False) is None
    assert "secours à chaud" in ha.validate(a, "replicas", ["n2"], True)
    monkeypatch.setattr(ha, "get", lambda slug: {"mode": "replicas"})
    with pytest.raises(ValueError):
        services.enable_mysql("mon-jeu", "mariadb", 512)
