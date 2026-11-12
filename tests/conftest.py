"""Tests de Hangar : sans root, sans Docker, sans réseau. Base SQLite et secret de session jetables."""
import os
import sys
import tempfile

_tmp = tempfile.mkdtemp(prefix="hangar-tests-")
os.environ["HANGAR_DB"] = os.path.join(_tmp, "platform.db")
os.environ["HANGAR_SECRET_FILE"] = os.path.join(_tmp, "hangar.secret")
os.environ["HANGAR_IMPORTS"] = os.path.join(_tmp, "imports")
os.environ["HANGAR_IMPORTS_TMP"] = os.path.join(_tmp, "restore-tmp")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import shutil  # noqa: E402
import subprocess  # noqa: E402

import pytest  # noqa: E402

from app import db  # noqa: E402

db.init()


def nft_available():
    """`nft -c` a besoin de CAP_NET_ADMIN : root, ou sudo sans mot de passe (intégration continue GitHub)."""
    if not shutil.which("nft") and not os.path.exists("/usr/sbin/nft"):
        return None
    for cmd in (["nft"], ["sudo", "-n", "nft"]):
        try:
            if subprocess.run(cmd + ["-c", "-f", "-"], input=b"table inet hangartest {}\n",
                              capture_output=True, timeout=10).returncode == 0:
                return cmd
        except (OSError, subprocess.TimeoutExpired):
            pass
    return None


NFT = nft_available()


@pytest.fixture
def nft_check():
    if not NFT:
        pytest.skip("nft indisponible (ni root ni sudo)")

    def check(text):
        r = subprocess.run(NFT + ["-c", "-f", "-"], input=text.encode(), capture_output=True, timeout=20)
        assert r.returncode == 0, r.stderr.decode()
    return check


@pytest.fixture
def app_row():
    """Une appli valide, comme le formulaire l'enregistre."""
    return {"slug": "mon-jeu", "name": "Mon jeu", "pkg": "fr.exemple.jeu", "source": "image",
            "image": "ghcr.io/exemple/jeu", "version": "1.2.0", "port": 8080, "mem_mb": 384,
            "health_path": "/health", "env": "JWT_SECRET=abc\nPRIX=10$", "db": 1,
            "db_password": "a1b2c3d4e5f6a7b8", "desired": "running", "node": "local",
            "host_port": 18001, "data_user": ""}
