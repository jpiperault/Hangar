"""Explorateur de data/ : chemins sûrs, liste, lecture, remplacement (ancienne version gardée), liens refusés."""
import os

import pytest

from app import datafiles, db
from app import platform as P


@pytest.fixture
def dossier(app_row, tmp_path, monkeypatch):
    db.x("DELETE FROM apps WHERE slug = 'mon-jeu'")
    db.insert_app("mon-jeu", {**app_row, "state": "ok", "created_at": 0, "node": "local"})
    monkeypatch.setattr(P, "app_dir", lambda slug: str(tmp_path / "apps" / slug))
    monkeypatch.setattr(datafiles, "SAFE", str(tmp_path / "avant"))
    d = tmp_path / "apps" / "mon-jeu" / "data"
    (d / "conf").mkdir(parents=True)
    (d / "conf" / "app.ini").write_text("ancien")
    (d / ".hangar-mysql").mkdir()
    (tmp_path / "secret").write_text("ne doit pas sortir")
    os.symlink(tmp_path / "secret", d / "lien")
    yield d, tmp_path
    db.x("DELETE FROM apps WHERE slug = 'mon-jeu'")


def test_chemins():
    assert datafiles.clean("/a//b/./c/") == "a/b/c"
    for bad in ("../x", "a/../../etc"):
        with pytest.raises(ValueError):
            datafiles.clean(bad)
    assert datafiles.internal(".hangar-mysql/dump.sql.gz") and not datafiles.internal("conf")


def test_liste_lecture_ecriture(dossier):
    d, tmp = dossier
    items, cut = datafiles.listdir("mon-jeu")
    assert [(i["name"], i["type"]) for i in items] == [(".hangar-mysql", "d"), ("conf", "d"), ("lien", "l")] and not cut
    assert b"".join(datafiles.stream("mon-jeu", "conf/app.ini")) == b"ancien"
    with pytest.raises(ValueError):
        datafiles.stream("mon-jeu", "lien")            # lien vers l'extérieur de data/ : refusé
    with pytest.raises(ValueError):
        datafiles.listdir("mon-jeu", "../..")
    new = tmp / "nouveau"
    new.write_text("nouveau")
    prev = datafiles.write("mon-jeu", "conf/app.ini", str(new))
    assert (d / "conf" / "app.ini").read_text() == "nouveau" and open(prev).read() == "ancien"
    assert datafiles.write("mon-jeu", "conf/autre.txt", str(new)) is None and (d / "conf" / "autre.txt").exists()
    for bad in (".hangar-mysql/dump.sql.gz", "lien"):
        with pytest.raises((ValueError, RuntimeError)):
            datafiles.write("mon-jeu", bad, str(new))
    assert (tmp / "secret").read_text() == "ne doit pas sortir"
