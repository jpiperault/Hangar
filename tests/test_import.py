"""Import de données : formats reconnus, membres dangereux refusés, page et routes."""
import io
import tarfile

import pytest

from app import dataimport


def _tar(tmp_path, members, name="x.tar.gz"):
    """members : liste de (nom, contenu bytes | None pour un dossier | ('lien', cible))."""
    p = tmp_path / name
    with tarfile.open(p, "w:gz") as t:
        for n, c in members:
            ti = tarfile.TarInfo(n)
            if c is None:
                ti.type = tarfile.DIRTYPE
                t.addfile(ti)
            elif isinstance(c, tuple):
                ti.type, ti.linkname = tarfile.SYMTYPE, c[1]
                t.addfile(ti)
            else:
                ti.size = len(c)
                t.addfile(ti, io.BytesIO(c))
    return str(p)


DUMP = b"PGDMP" + b"\x00" * 20


def test_format_simple(tmp_path):
    i = dataimport.inspect(_tar(tmp_path, [("db.dump", DUMP), ("data", None), ("data/photos", None),
                                           ("data/photos/a.jpg", b"123"), ("./data/b.txt", b"45")]))
    assert i["dump"] == "db.dump" and i["data"] == "data" and i["files"] == 2 and i["data_size"] == 5
    assert i["db_size"] == len(DUMP) and i["src_slug"] == ""


def test_base_seule_et_fichiers_seuls(tmp_path):
    assert dataimport.inspect(_tar(tmp_path, [("db.dump", DUMP)], "a.tar.gz"))["data"] is None
    i = dataimport.inspect(_tar(tmp_path, [("data/x", b"1")], "b.tar.gz"))
    assert i["dump"] is None and i["data"] == "data"


def test_archive_hangar_une_appli(tmp_path):
    i = dataimport.inspect(_tar(tmp_path, [("manifest.json", b"{}"), ("db/mon-jeu.dump", DUMP),
                                           ("apps/mon-jeu/data", None), ("apps/mon-jeu/data/s.json", b"{}")]))
    assert i["dump"] == "db/mon-jeu.dump" and i["data"] == "apps/mon-jeu/data" and i["src_slug"] == "mon-jeu"
    assert i["files"] == 1


@pytest.mark.parametrize("members, msg", [
    ([("db/a.dump", DUMP), ("db/b.dump", DUMP)], "plusieurs applis"),
    ([("data/../../etc/passwd", b"x")], "chemin refusé"),
    ([("/etc/cron.d/x", b"x")], "chemin refusé"),
    ([("data/lien", ("lien", "/etc/shadow"))], "lien"),
    ([("db.dump", DUMP), ("notes.txt", b"x")], "inattendu"),
    ([("manifest.json", b"{}")], "ni base"),
    ([("db.dump", DUMP), ("apps/a/data/x", b"1")], "deux formats"),
])
def test_refus(tmp_path, members, msg):
    with pytest.raises(ValueError, match=msg):
        dataimport.inspect(_tar(tmp_path, members))


def test_pas_une_archive(tmp_path):
    p = tmp_path / "x.tar.gz"
    p.write_bytes(b"pas du gzip")
    with pytest.raises(ValueError, match="illisible"):
        dataimport.inspect(str(p))


def test_parts_selon_appli():
    i = {"dump": "db.dump", "data": "data"}
    assert dataimport.parts_for(i, {"db": 1}) == ["data", "db"]
    assert dataimport.parts_for(i, {"db": 0}) == ["data"]
    assert dataimport.parts_for({"dump": "db.dump", "data": None}, {"db": 0}) == []


def test_noms():
    assert dataimport.NAME_RE.match(dataimport.new_name())
    assert dataimport.path("../platform.db") is None and dataimport.path("import-x.tar.gz") is None


def test_parcours_web(tmp_path, app_row, monkeypatch):
    """Envoi, page de choix, confirmation exigée, puis lancement (le travail lui-même est remplacé)."""
    from argon2 import PasswordHasher
    from fastapi.testclient import TestClient
    from app import db, main
    same = {"sec-fetch-site": "same-origin"}
    db.x("INSERT OR REPLACE INTO users(username, hash) VALUES(?, ?)", ("imp", PasswordHasher().hash("mot-de-passe-imp")))
    if not db.app(app_row["slug"]):
        db.insert_app(app_row["slug"], {**app_row, "state": "ok", "created_at": 0})
    c = TestClient(main.app, base_url="https://hangar.test", client=("127.0.0.1", 50001))
    main._fails.clear()
    assert c.post("/login", data={"username": "imp", "password": "mot-de-passe-imp"}, headers=same,
                  follow_redirects=False).headers["location"] == "/"
    f = _tar(tmp_path, [("data/a.txt", b"bonjour")])
    r = c.post("/backups/import/upload", files={"file": ("migration.tar.gz", open(f, "rb"), "application/gzip")},
               headers=same, follow_redirects=False)
    loc = r.headers["location"]
    assert loc.startswith("/backups/import/import-"), loc
    name = loc.rsplit("/", 1)[1]
    page = c.get(loc)
    assert page.status_code == 200 and "migration.tar.gz" in page.text and 'value="mon-jeu"' in page.text
    assert 'name="db"' not in page.text   # pas de base dans ce fichier
    r = c.post(f"{loc}/run", data={"app": "mon-jeu", "data": "on", "confirm": "faux"}, headers=same,
               follow_redirects=False)
    assert r.headers["location"].startswith(loc) and db.app("mon-jeu")["state"] == "ok"
    seen = []
    monkeypatch.setattr(main.P, "spawn", lambda fn, *a: seen.append((fn.__name__, a)))
    r = c.post(f"{loc}/run", data={"app": "mon-jeu", "data": "on", "confirm": "mon-jeu"}, headers=same,
               follow_redirects=False)
    assert r.headers["location"] == "/apps/mon-jeu"
    assert seen == [("run", (name, "mon-jeu", ["data"], "ok"))] and db.app("mon-jeu")["state"] == "deploying"
    db.update_app("mon-jeu", state="ok")
    c.post(f"{loc}/delete", headers=same)
    assert dataimport.info(name) is None
    bad = _tar(tmp_path, [("notes.txt", b"x")], "bad.tar.gz")
    r = c.post("/backups/import/upload", files={"file": ("bad.tar.gz", open(bad, "rb"), "application/gzip")},
               headers=same, follow_redirects=False)
    assert r.headers["location"] == "/backups#import" and not dataimport.pending()
