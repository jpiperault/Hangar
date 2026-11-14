"""Webhooks de publication : signature, rejeu, sites statiques, applis en image, lignes Caddy."""
import hashlib
import hmac
import json
import shutil
import subprocess

import pytest

from app import db, hooks, monitor, sites
from app import platform as P


@pytest.fixture
def env(app_row, monkeypatch):
    spawned = []
    monkeypatch.setattr(P, "spawn", lambda fn, *a: spawned.append((fn.__name__, a)))
    monkeypatch.setattr(P, "log", lambda *a, **k: None)
    for s in ("vitrine", "mon-jeu"):
        db.x("DELETE FROM apps WHERE slug = ?", (s,))
    db.insert_app("vitrine", {**app_row, "kind": "static", "source": "static", "image": "", "version": "—", "pkg": "",
                              "state": "ok", "created_at": 0, "host_port": 18601, "db": 0})
    db.insert_app("mon-jeu", {**app_row, "kind": "web", "state": "ok", "created_at": 0, "image": "ghcr.io/moi/jeu"})
    db.kv_set("hooks", {})
    db.kv_set("static_sites", {"vitrine": {"git": {"repo": "https://github.com/moi/site", "branch": "main",
                                                   "cmd": "", "out": ".", "image": "node:22-alpine"}}})
    yield spawned
    for s in ("vitrine", "mon-jeu"):
        db.x("DELETE FROM apps WHERE slug = ?", (s,))
    db.kv_set("hooks", {})
    db.kv_set("static_sites", {})


def _send(slug, data, event, secret=None, delivery=None, sig=None):
    body = json.dumps(data).encode()
    secret = secret or hooks.of(slug)["secret"]
    h = {"Content-Type": "application/json",
         "X-Hub-Signature-256": sig or "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()}
    if event:
        h["X-GitHub-Event"] = event
    if delivery:
        h["X-GitHub-Delivery"] = delivery
    return hooks.handle(slug, h, body)


def test_signature_et_rejeu(env):
    assert hooks.handle("vitrine", {}, b"{}")[0] == 404          # pas activé
    hooks.enable("vitrine")
    assert _send("vitrine", {}, "ping", secret="faux")[0] == 403
    assert _send("vitrine", {}, "ping", sig="sha256=00")[0] == 403
    assert hooks.handle("vitrine", {"Content-Type": "application/json"}, b"{}")[0] == 403   # sans signature
    assert _send("vitrine", {}, "ping", delivery="d1") == (200, "pong")
    assert _send("vitrine", {}, "ping", delivery="d1") == (200, "déjà reçu")
    assert hooks.of("vitrine")["last"]["event"] == "ping"
    gl = hooks.handle("vitrine", {"X-Gitlab-Token": hooks.of("vitrine")["secret"], "X-Gitlab-Event": "Push Hook"},
                      json.dumps({"ref": "refs/heads/main"}).encode())
    assert gl[0] == 202 and env == [("build_git", ("vitrine",))]


def test_site_statique(env, monkeypatch):
    hooks.enable("vitrine")
    assert _send("vitrine", {"ref": "refs/heads/dev"}, "push")[0] == 200 and not env
    assert _send("vitrine", {"ref": "refs/heads/main", "after": "abcdef123"}, "push") == \
        (202, "construction de main@abcdef1 lancée")
    monkeypatch.setattr(sites, "busy", lambda slug: True)
    assert _send("vitrine", {"ref": "refs/heads/main"}, "push")[0] == 409


def test_image(env, monkeypatch):
    hooks.enable("mon-jeu")              # en ligne : 1.2.0
    pkg = lambda name, tag: {"action": "published", "package": {"name": name, "package_version": {
        "container_metadata": {"tag": {"name": tag}}}}}
    assert _send("mon-jeu", pkg("jeu", "1.1.0"), "package")[0] == 200 and not env       # plus ancien
    assert _send("mon-jeu", pkg("autre", "9.0.0"), "package")[0] == 200 and not env     # autre paquet
    assert _send("mon-jeu", pkg("jeu", "sha-1234"), "package")[0] == 200 and not env    # non numéroté
    assert _send("mon-jeu", pkg("jeu", "1.3.0"), "package")[0] == 202
    assert env[-1] == ("deploy", ("mon-jeu", "1.3.0", "update"))
    assert _send("mon-jeu", {"ref": "refs/heads/main"}, "push")[0] == 200
    assert _send("mon-jeu", {"version": "1.4.0"}, None)[0] == 202 and env[-1][1][1] == "1.4.0"
    monkeypatch.setattr(monitor, "check_versions", lambda slug: db.update_app(slug, latest_version="1.5.0"))
    assert _send("mon-jeu", {"action": "completed", "workflow_run": {"conclusion": "failure"}}, "workflow_run")[0] == 200
    assert _send("mon-jeu", {"action": "completed", "workflow_run": {"conclusion": "success"}}, "workflow_run")[0] == 202
    assert env[-1][1][1] == "1.5.0"
    db.update_app("mon-jeu", version="latest", latest_version=None)
    assert _send("mon-jeu", pkg("jeu", "latest"), "package")[0] == 202 and env[-1][1][1] == "latest"   # nouveau tirage
    db.update_app("mon-jeu", state="deploying")
    assert _send("mon-jeu", {"version": "1.4.0"}, None)[0] == 409


def test_caddy(env, tmp_path):
    hooks.enable("vitrine")
    lines = hooks.caddy_hub_lines("127.0.0.1:8099") + hooks.caddy_app_lines("vitrine", "127.0.0.1:8099")
    assert hooks.caddy_app_lines("mon-jeu", "x") == []
    if shutil.which("caddy"):
        conf = tmp_path / "Caddyfile"
        conf.write_text("http://x.test:8080 {\n" + "\n".join(lines) + '\n\trespond "ok"\n}\n')
        r = subprocess.run(["caddy", "validate", "--config", str(conf), "--adapter", "caddyfile"], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr[-300:]


def test_appli_git(env, app_row, monkeypatch):
    db.x("DELETE FROM apps WHERE slug = 'depot'")
    db.insert_app("depot", {**app_row, "pkg": "", "kind": "web", "state": "ok", "created_at": 0, "source": "git",
                            "image": "https://github.com/moi/depot.git", "version": "main", "host_port": 18777})
    rebuilt = []
    monkeypatch.setattr(P, "request_rebuild", lambda slug: rebuilt.append(slug))
    hooks.enable("depot")
    assert _send("depot", {"ref": "refs/heads/dev"}, "push")[0] == 200 and not env
    assert _send("depot", {"ref": "refs/heads/main", "after": "abc1234567"}, "push")[0] == 202
    assert rebuilt == ["depot"] and env[-1] == ("deploy", ("depot", "main", "update"))
    assert _send("depot", {"ref": "refs/tags/1.2.0"}, "push")[0] == 200          # tags : désactivés par défaut
    hooks.set_options("depot", False, True)
    assert _send("depot", {"ref": "refs/heads/main"}, "push")[0] == 200 and rebuilt == ["depot"]
    assert _send("depot", {"ref": "refs/tags/1.2.0"}, "push")[0] == 202 and env[-1][1][1] == "1.2.0"
    db.x("DELETE FROM apps WHERE slug = 'depot'")
