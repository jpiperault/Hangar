"""Correction des paquets système : image dérivée, retour à l'image d'avant si l'appli ne répond plus, mode auto."""
from app import db, patch, vulns
from app import platform as P


def test_dockerfile():
    df = patch._dockerfile("nginx:1.25-alpine", "101")
    assert df.startswith("FROM nginx:1.25-alpine\nUSER root\nRUN ") and "\nUSER 101\n" in df and "apk upgrade" in df
    assert "USER 0" not in patch._dockerfile("x:1", "") and patch._dockerfile("x:1", "root").count("USER") == 1


def test_image_deployee(app_row):
    a = {**app_row, "source": "image"}
    db.kv_set("image_patches", None)
    assert P.image_ref(a, "1.2.0") == P.base_ref(a, "1.2.0") == "ghcr.io/exemple/jeu:1.2.0"
    db.kv_set("image_patches", {"mon-jeu": {"version": "1.2.0", "ref": "hangar-patch/mon-jeu:1.2.0-x"}})
    assert P.image_ref(a, "1.2.0") == "hangar-patch/mon-jeu:1.2.0-x" and P.image_ref(a, "1.3.0") == "ghcr.io/exemple/jeu:1.3.0"
    db.kv_set("image_patches", None)


def test_retour_si_en_panne(app_row, monkeypatch):
    db.x("DELETE FROM apps WHERE slug = 'mon-jeu'")
    db.insert_app("mon-jeu", {**app_row, "state": "ok", "created_at": 0})
    db.kv_set("image_patches", None)
    monkeypatch.setattr(patch, "build", lambda a: ("hangar-patch/mon-jeu:1.2.0-x", "ghcr.io/exemple/jeu:1.2.0", []))
    monkeypatch.setattr(P, "log", lambda *a, **k: None)
    monkeypatch.setattr(patch.alerts, "send", lambda *a, **k: None)
    deployed = []

    def deploy(slug, version, kind, previous=None):
        deployed.append(P.image_ref(db.app(slug), version))
        db.update_app(slug, state="error" if len(deployed) == 1 else "ok")   # l'image corrigée ne démarre pas
    monkeypatch.setattr(P, "deploy", deploy)
    ok, msg = patch.apply("mon-jeu")
    assert not ok and deployed == ["hangar-patch/mon-jeu:1.2.0-x", "ghcr.io/exemple/jeu:1.2.0"] and patch.of("mon-jeu") is None
    assert not patch.last_try("mon-jeu")["ok"]
    db.x("DELETE FROM apps WHERE slug = 'mon-jeu'")


def test_auto(app_row, monkeypatch):
    db.x("DELETE FROM apps WHERE slug = 'mon-jeu'")
    db.insert_app("mon-jeu", {**app_row, "state": "ok", "created_at": 0})
    spawned = []
    monkeypatch.setattr(P, "spawn", lambda fn, *a: spawned.append(a))
    res = {"items": [{"id": "CVE-1", "sev": "HIGH", "pkg": "zlib", "installed": "1", "fixed": "2", "title": "", "class": "os"}]}
    db.kv_set("vuln_fix", None)
    db.kv_set("vuln_fix_apps", None)
    db.kv_set("image_patch_tries", None)
    patch.maybe_auto("mon-jeu", res)
    assert not spawned                                         # général : à la main
    patch.set_mode("mon-jeu", "auto")
    patch.maybe_auto("mon-jeu", res)
    assert spawned == [("mon-jeu", "automatique")]
    patch._try("mon-jeu", "1.2.0", False, "essai")
    patch.maybe_auto("mon-jeu", res)
    assert len(spawned) == 1                                   # un essai par jour et par version
    patch.maybe_auto("mon-jeu", {"items": [{**res["items"][0], "class": "lang"}]})
    assert len(spawned) == 1
    assert vulns.groups(res["items"])["os"][0]["pkg"] == "zlib"
    db.kv_set("vuln_fix_apps", None)
    db.x("DELETE FROM apps WHERE slug = 'mon-jeu'")
