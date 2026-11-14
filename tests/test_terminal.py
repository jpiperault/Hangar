"""Terminal : dossier courant gardé, sortie et code, garde-fous."""
import pytest

from app import db, terminal
from app import platform as P


def test_sortie(app_row, monkeypatch):
    db.x("DELETE FROM apps WHERE slug = 'mon-jeu'")
    db.insert_app("mon-jeu", {**app_row, "state": "ok", "created_at": 0})
    monkeypatch.setattr(P, "log", lambda *a, **k: None)
    seen = []

    def dk(node, *args, timeout=0):
        seen.append(args)
        return 1, f"ligne 1\nerreur\n{terminal.MARK}/srv/app"
    monkeypatch.setattr(P, "dk", dk)
    out, rc, cwd = terminal.run("mon-jeu", "app", "cd /srv/app && false", cwd="/tmp", user="ana")
    assert (out, rc, cwd) == ("ligne 1\nerreur", 1, "/srv/app")
    assert seen[0][-1] == "/tmp" and "app-mon-jeu-app-1" in seen[0] and "-u" not in seen[0]
    terminal.run("mon-jeu", "app", "id", cwd="pas/absolu", as_root=True)
    assert seen[-1][-1] == "" and "-u" in seen[-1]                     # dossier invalide ignoré ; root demandé
    for bad in (("app", ""), ("redis", "id"), ("app", "x" * 5000)):
        with pytest.raises(ValueError):
            terminal.run("mon-jeu", *bad)
    db.x("DELETE FROM apps WHERE slug = 'mon-jeu'")
