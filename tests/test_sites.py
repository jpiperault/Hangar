"""Sites statiques : zip sûr, versions, mise en ligne, Caddy, création sans conteneur."""
import os
import shutil
import subprocess
import zipfile

import pytest

from app import db, kinds, sites
from app import platform as P


@pytest.fixture
def site(tmp_path, monkeypatch, app_row):
    monkeypatch.setattr(sites, "SITES", str(tmp_path / "sites"))
    monkeypatch.setattr(P, "app_dir", lambda slug: str(tmp_path / "apps" / slug))
    monkeypatch.setattr(P, "ingress_nodes", lambda s=None: [])
    monkeypatch.setattr(P, "apply_routing", lambda: None)
    monkeypatch.setattr(P, "log", lambda *a, **k: None)
    db.x("DELETE FROM apps WHERE slug = 'vitrine'")
    db.insert_app("vitrine", {**app_row, "kind": "static", "source": "static", "image": "", "version": "—", "pkg": "",
                              "state": "ok", "created_at": 0, "host_port": 18601, "db": 0})
    db.kv_set("static_sites", {})
    yield tmp_path
    db.x("DELETE FROM apps WHERE slug = 'vitrine'")
    db.kv_set("static_sites", {})


def _zip(path, files, top=""):
    with zipfile.ZipFile(path, "w") as z:
        for name, data in files.items():
            z.writestr(top + name, data)
    return str(path)


def test_zip_sur(tmp_path):
    with pytest.raises(ValueError, match="chemin refusé"):
        sites.extract_zip(_zip(tmp_path / "a.zip", {"../evil.html": "x"}), str(tmp_path / "x1"))
    root = sites.extract_zip(_zip(tmp_path / "b.zip", {"index.html": "ok", "app.js": "1"}, top="dist/"), str(tmp_path / "x2"))
    assert root.endswith("dist") and os.path.isfile(os.path.join(root, "index.html"))


def test_versions_et_mise_en_ligne(site):
    n1 = sites.publish_zip("vitrine", _zip(site / "v1.zip", {"index.html": "<h1>v1</h1>"}), "v1.zip")
    assert open(site / "sites" / "vitrine" / "index.html").read() == "<h1>v1</h1>" and db.app("vitrine")["version"] == "#1"
    n2 = sites.publish_zip("vitrine", _zip(site / "v2.zip", {"index.html": "<h1>v2</h1>", "a.css": "x"}), "v2.zip")
    assert sites.meta("vitrine")["current"] == n2 and sites.healthy("vitrine")
    sites.activate("vitrine", n1)                                     # retour arrière
    assert open(site / "sites" / "vitrine" / "index.html").read() == "<h1>v1</h1>"
    with pytest.raises(ValueError, match="index.html"):
        sites.publish_zip("vitrine", _zip(site / "v3.zip", {"page.html": "x"}), "v3.zip")
    for i in range(12):
        sites.publish_zip("vitrine", _zip(site / f"w{i}.zip", {"index.html": str(i)}), "w")
    m = sites.meta("vitrine")
    assert len(m["releases"]) == sites.KEEP and len(os.listdir(site / "apps" / "vitrine" / "site" / "releases")) == sites.KEEP


def test_caddy(site):
    a = db.app("vitrine")
    assert sites.caddy_lines(a, "\t")[0].endswith("503")            # rien de publié
    sites.publish_zip("vitrine", _zip(site / "v.zip", {"index.html": "x"}), "v.zip")
    lines = sites.caddy_lines(db.app("vitrine"), "\t")
    assert any("try_files" in l for l in lines) and lines[-1].strip() == "file_server"
    if shutil.which("caddy"):
        conf = site / "Caddyfile"
        conf.write_text("http://x.test:8080 {\n" + "\n".join(lines) + "\n}\n")
        r = subprocess.run(["caddy", "validate", "--config", str(conf), "--adapter", "caddyfile"], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr[-300:]
    assert kinds.static("static") and kinds.http("static")


def test_git_saisie(site):
    with pytest.raises(ValueError):
        sites.save_git("vitrine", {"repo": "file:///etc", "branch": "main", "out": "dist"})
    with pytest.raises(ValueError):
        sites.save_git("vitrine", {"repo": "https://github.com/x/y", "branch": "main", "out": "../.."})
    g = sites.save_git("vitrine", {"repo": "https://github.com/x/y", "branch": "main", "cmd": "npm run build", "out": "dist/"})
    assert g["out"] == "dist" and g["image"] == sites.BUILD_IMAGE
