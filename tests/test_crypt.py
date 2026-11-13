"""Archives chiffrées : aller-retour gpg, mauvais mot de passe, téléchargement et envoi par la console."""
import io
import json
import os
import shutil
import tarfile

import pytest

from app import crypt

pytestmark = pytest.mark.skipif(not shutil.which("gpg"), reason="gpg absent")


def test_aller_retour(tmp_path):
    src = tmp_path / "a.tar.gz"
    src.write_bytes(os.urandom(300_000))
    enc, out = tmp_path / "a.gpg", tmp_path / "b"
    enc.write_bytes(b"".join(crypt.encrypt_stream(str(src), "mot-de-passe-1")))
    assert crypt.is_encrypted(str(enc)) and not crypt.is_encrypted(str(src))
    assert src.read_bytes()[:64] not in enc.read_bytes()
    assert crypt.decrypt_file(str(enc), str(out), ["faux", "", "mot-de-passe-1"]) == "mot-de-passe-1"
    assert out.read_bytes() == src.read_bytes() and oct(out.stat().st_mode & 0o777) == "0o600"


def test_mauvais_mot_de_passe(tmp_path):
    src = tmp_path / "a"
    src.write_bytes(b"secret")
    enc = tmp_path / "a.gpg"
    crypt.encrypt_file(str(src), str(enc), "bon")
    with pytest.raises(ValueError, match="mot de passe incorrect"):
        crypt.decrypt_file(str(enc), str(tmp_path / "x"), ["mauvais"])
    assert not (tmp_path / "x").exists()


def test_fichier_altere(tmp_path):
    src = tmp_path / "a"
    src.write_bytes(os.urandom(5000))
    enc = tmp_path / "a.gpg"
    crypt.encrypt_file(str(src), str(enc), "bon")
    b = bytearray(enc.read_bytes())
    b[len(b) // 2] ^= 0xFF
    enc.write_bytes(bytes(b))
    with pytest.raises(ValueError):
        crypt.decrypt_file(str(enc), str(tmp_path / "x"), ["bon"])


def test_telechargement_et_envoi(tmp_path, monkeypatch, app_row):
    """L'archive téléchargée est chiffrée ; renvoyée à la console avec le bon mot de passe, elle est relue."""
    from argon2 import PasswordHasher
    from fastapi.testclient import TestClient
    from app import backup, db, main
    same = {"sec-fetch-site": "same-origin"}
    monkeypatch.setattr(backup, "ARCHIVES", str(tmp_path / "archives"))
    monkeypatch.setattr(backup, "PASS_FILE", str(tmp_path / "restic.pass"))
    monkeypatch.setattr(backup, "BK", str(tmp_path))
    (tmp_path / "restic.pass").write_text("pass-de-ce-serveur\n")
    os.makedirs(backup.ARCHIVES)
    name = "hangar-20261113-010203.tar.gz"
    man = {"format": 2, "created": 1, "apps": [{k: app_row[k] for k in backup.APP_KEYS if k in app_row} | {"slug": "mon-jeu"}]}
    with tarfile.open(os.path.join(backup.ARCHIVES, name), "w:gz") as t:
        data = json.dumps(man).encode()
        ti = tarfile.TarInfo("manifest.json")
        ti.size = len(data)
        t.addfile(ti, io.BytesIO(data))
    db.x("INSERT OR REPLACE INTO users(username, hash) VALUES(?, ?)", ("arc", PasswordHasher().hash("mot-de-passe-arc")))
    c = TestClient(main.app, base_url="https://hangar.test", client=("127.0.0.1", 50004))
    main._fails.clear()
    c.post("/login", data={"username": "arc", "password": "mot-de-passe-arc"}, headers=same)
    r = c.get(f"/backups/archive/{name}/download")
    assert r.status_code == 200 and f'filename="{name}.gpg"' in r.headers["content-disposition"]
    enc = tmp_path / "dl.gpg"
    enc.write_bytes(r.content)
    assert crypt.is_encrypted(str(enc))
    # envoyée à un autre serveur (autre mot de passe local) : refusée sans le bon mot de passe…
    (tmp_path / "restic.pass").write_text("pass-d-un-autre-serveur\n")
    r = c.post("/backups/archive/upload", files={"file": ("x.tar.gz.gpg", enc.read_bytes())}, headers=same,
               follow_redirects=False)
    assert r.headers["location"] == "/backups#archives"
    # … acceptée avec
    r = c.post("/backups/archive/upload", files={"file": ("x.tar.gz.gpg", enc.read_bytes())},
               data={"password": "pass-de-ce-serveur"}, headers=same, follow_redirects=False)
    assert r.headers["location"].startswith("/backups/archive/hangar-"), r.headers["location"]
    imported = r.headers["location"].rsplit("/", 1)[1]
    assert backup.read_manifest(os.path.join(backup.ARCHIVES, imported))["apps"][0]["slug"] == "mon-jeu"
    assert not [f for f in os.listdir(backup.ARCHIVES) if f.endswith((".part", ".clair"))]
