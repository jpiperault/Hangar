"""Nettoyage des images : ce qui est gardé (en ligne, précédente, récentes, utilisées), ce qui part."""
import pytest

from app import db, images
from app import platform as P

IMGS = [  # dépôt, tag, id, date
    ("ghcr.io/moi/jeu", "1.5.0", "sha256:a5", "2026-11-05"), ("ghcr.io/moi/jeu", "1.4.0", "sha256:a4", "2026-11-04"),
    ("ghcr.io/moi/jeu", "1.3.0", "sha256:a3", "2026-11-03"), ("ghcr.io/moi/jeu", "1.2.0", "sha256:a2", "2026-11-02"),
    ("ghcr.io/moi/jeu", "1.1.0", "sha256:a1", "2026-11-01"), ("ghcr.io/moi/jeu", "1.0.0", "sha256:a0", "2026-10-01"),
    ("postgres", "17", "sha256:pg", "2026-01-01"), ("ghcr.io/moi/parti", "2.0.0", "sha256:b2", "2026-11-01"),
    ("<none>", "<none>", "sha256:zz", "2026-01-01")]


@pytest.fixture
def machine(app_row, monkeypatch):
    for s in ("mon-jeu", "parti"):
        db.x("DELETE FROM apps WHERE slug = ?", (s,))
    db.insert_app("mon-jeu", {**app_row, "image": "ghcr.io/moi/jeu", "version": "1.2.0", "prev_version": "1.0.0",
                              "state": "ok", "created_at": 0, "node": "local"})
    db.insert_app("parti", {**app_row, "pkg": "", "image": "ghcr.io/moi/parti", "version": "2.0.0", "state": "ok",
                            "created_at": 0, "node": "ns1", "host_port": 18902})

    def dk(node, *args, **kw):
        if args[:2] == ("image", "ls"):
            return 0, "\n".join("|".join(x) for x in IMGS)
        if args[:2] == ("ps", "-a"):
            return 0, "c1"
        if args[0] == "inspect":
            return 0, "sha256:pg"          # seul PostgreSQL tourne ici
        return 0, ""
    monkeypatch.setattr(P, "dk", dk)
    yield
    for s in ("mon-jeu", "parti"):
        db.x("DELETE FROM apps WHERE slug = ?", (s,))


def test_plan(machine):
    out = {i["ref"]: i["why"] for i in images.plan("local", keep=2)}
    # gardées : 1.5.0 et 1.4.0 (récentes), 1.2.0 (en ligne), 1.0.0 (précédente) ; PostgreSQL et l'orpheline : à part
    assert out == {"ghcr.io/moi/jeu:1.3.0": "ancienne version", "ghcr.io/moi/jeu:1.1.0": "ancienne version",
                   "ghcr.io/moi/parti:2.0.0": "appli plus sur cette machine"}


def test_reglages():
    images.save(True, 99, 9, False)
    assert images.settings() == {"on": True, "keep": 20, "day": 6, "build_cache": False}
    db.kv_set("image_cleanup", None)
    assert not images.settings()["on"]          # désactivé tant qu'on ne l'active pas


def test_espace():
    assert images._reclaimed("Deleted…\nTotal reclaimed space: 1.5GB") == 1_500_000_000
    assert images._reclaimed("rien") == 0
