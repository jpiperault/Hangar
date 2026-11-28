"""Construction sans Dockerfile : technologie reconnue, Dockerfile écrit par Hangar, passage à Docker Compose."""
import json
import os

import pytest

from app import autobuild, db


def proj(tmp_path, files):
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text if isinstance(text, str) else json.dumps(text))
    return str(tmp_path)


def test_dockerfile_du_depot(tmp_path):
    assert autobuild.detect(proj(tmp_path, {"Dockerfile": "FROM scratch", "package.json": {}})) is None


@pytest.mark.parametrize("lock, label, install", [
    ({}, "Node.js 22", "npm install"),
    ({"package-lock.json": "{}"}, "Node.js 22", "npm ci"),
    ({"pnpm-lock.yaml": ""}, "Node.js 22 (pnpm)", "pnpm install --frozen-lockfile"),
    ({"yarn.lock": ""}, "Node.js 22 (yarn)", "yarn install --frozen-lockfile"),
    ({"bun.lock": ""}, "Bun", "bun install"),
])
def test_node_gestionnaires(tmp_path, lock, label, install):
    d = autobuild.detect(proj(tmp_path, {"package.json": {"scripts": {"start": "node server.js"}}, **lock}))
    assert d["stack"] == "node" and d["label"] == label and f"RUN {install}" in d["dockerfile"]
    assert "EXPOSE 8080" in d["dockerfile"] and "PORT=8080" in d["dockerfile"] and "USER " in d["dockerfile"]
    assert d["start"].endswith("start")


def test_node_versions_et_frameworks(tmp_path):
    d = autobuild.detect(proj(tmp_path, {"package.json": {"engines": {"node": "20.x"}, "scripts": {"build": "next build", "start": "next start"},
                                                          "dependencies": {"next": "15"}}}))
    assert d["label"] == "Node.js 20 · Next.js" and "FROM node:20-bookworm-slim" in d["dockerfile"] and "RUN npm run build" in d["dockerfile"]
    d = autobuild.detect(proj(tmp_path, {"package.json": {"engines": {"node": ">=16"}, "main": "app.js"}}))
    assert "node:22" in d["dockerfile"] and d["start"] == "node app.js"
    d = autobuild.detect(proj(tmp_path, {".nvmrc": "v24.1.0\n", "package.json": {"main": "x.js;rm -rf /"}, "index.js": ""}))
    assert "node:24" in d["dockerfile"] and d["start"] == "node index.js"         # « main » douteux : ignoré


def test_node_site_statique(tmp_path):
    d = autobuild.detect(proj(tmp_path, {"package.json": {"scripts": {"build": "vite build", "dev": "vite"}, "devDependencies": {"vite": "6"}}}))
    assert d["stack"] == "node-static" and "nginx-unprivileged" in d["dockerfile"] and "try_files $uri $uri/ /index.html" in d["dockerfile"]


def test_node_sans_demarrage(tmp_path):
    with pytest.raises(autobuild.Unsupported, match="start"):
        autobuild.detect(proj(tmp_path, {"package.json": {"scripts": {"test": "jest"}}}))


def test_procfile_en_json(tmp_path):
    d = autobuild.detect(proj(tmp_path, {"package.json": {"scripts": {"start": "x"}}, "Procfile": 'web: node web.js --name "a b"\nworker: x\n'}))
    assert d["start"] == 'node web.js --name "a b"'
    assert 'CMD ["sh", "-c", "node web.js --name \\"a b\\""]' in d["dockerfile"]


@pytest.mark.parametrize("files, fw, start", [
    ({"requirements.txt": "django\n", "manage.py": "", "monsite/wsgi.py": "application = get_wsgi_application()"},
     "Django", "gunicorn monsite.wsgi --bind 0.0.0.0:8080 --workers 2"),
    ({"requirements.txt": "fastapi\n", "app/main.py": "from fastapi import FastAPI\napi = FastAPI()\n"},
     "FastAPI", "uvicorn app.main:api --host 0.0.0.0 --port 8080"),
    ({"requirements.txt": "flask\ngunicorn\n", "app.py": "app = Flask(__name__)\n"}, "Flask", "gunicorn app:app --bind 0.0.0.0:8080 --workers 2"),
    ({"pyproject.toml": "[project]\nname='x'\n", "main.py": "print(1)"}, None, "python main.py"),
])
def test_python(tmp_path, files, fw, start):
    d = autobuild.detect(proj(tmp_path, files))
    assert d["stack"] == "python" and d["start"] == start and (fw is None or d["label"].endswith(fw))
    assert "FROM python:3.12-slim" in d["dockerfile"] and "USER app" in d["dockerfile"]
    if fw == "Flask":
        assert "pip install gunicorn" not in d["dockerfile"]                   # déjà demandé par le projet
    if fw == "FastAPI":
        assert 'pip install uvicorn[standard]' in d["dockerfile"]


def test_python_outils(tmp_path):
    d = autobuild.detect(proj(tmp_path, {"pyproject.toml": "[project]\n", "uv.lock": "", ".python-version": "3.11\n", "main.py": ""}))
    assert "Python 3.11 (uv)" in d["label"] and "uv export --frozen" in d["dockerfile"]
    d = autobuild.detect(proj(tmp_path / "p", {"pyproject.toml": "[tool.poetry]\n", "poetry.lock": "", "app.py": ""}))
    assert "(Poetry)" in d["label"]


def test_php_go_statique(tmp_path):
    d = autobuild.detect(proj(tmp_path / "l", {"composer.json": "{}", "artisan": "", "public/index.php": ""}))
    assert d["label"] == "PHP 8.3 (Apache) · Laravel" and "/var/www/html/public" in d["dockerfile"] and "composer install" in d["dockerfile"]
    d = autobuild.detect(proj(tmp_path / "g", {"go.mod": "module x\n\ngo 1.22.4\n", "cmd/api/main.go": "package main"}))
    assert d["label"] == "Go 1.22" and "go build -trimpath" in d["dockerfile"] and "./cmd/api" in d["dockerfile"]
    with pytest.raises(autobuild.Unsupported, match="cmd"):
        autobuild.detect(proj(tmp_path / "g2", {"go.mod": "module x\n", "cmd/a/main.go": "", "cmd/b/main.go": ""}))
    d = autobuild.detect(proj(tmp_path / "s", {"index.html": "<h1>x</h1>"}))
    assert d["stack"] == "static"


def test_non_reconnu(tmp_path):
    with pytest.raises(autobuild.Unsupported, match="Ruby"):
        autobuild.detect(proj(tmp_path / "r", {"Gemfile": ""}))
    with pytest.raises(autobuild.Unsupported, match="non reconnue"):
        autobuild.detect(proj(tmp_path / "v", {"README.md": ""}))


def test_lien_symbolique_ignore(tmp_path):
    root = proj(tmp_path / "p", {"index.js": ""})
    os.symlink("/etc/passwd", os.path.join(root, "package.json"))
    with pytest.raises(autobuild.Unsupported):
        autobuild.detect(root)                                                # jamais lu hors du dépôt


def test_lecture_et_compose(tmp_path, monkeypatch):
    import subprocess
    repo = tmp_path / "repo"
    proj(repo, {"package.json": {"scripts": {"start": "node index.js"}}, "index.js": "require('http').createServer().listen(8080)"})
    run = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)  # noqa: E731
    run("init", "-q", "-b", "main")
    run("-c", "user.email=t@t", "-c", "user.name=t", "add", ".")
    run("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x")
    a = {"slug": "autob", "image": f"file://{repo}"}
    ab = autobuild.refresh(a, "main")
    assert ab["stack"] == "node" and autobuild.inline("autob").startswith("FROM node:22")
    sha = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    assert autobuild.refresh(a, sha)["version"] == sha                        # un commit précis
    with pytest.raises(RuntimeError):
        autobuild.refresh(a, "branche-absente")
    (repo / "Dockerfile").write_text("FROM scratch\n")
    run("-c", "user.email=t@t", "-c", "user.name=t", "add", ".")
    run("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "y")
    assert autobuild.refresh(a, "main")["own"] and autobuild.inline("autob") is None
    autobuild.forget("autob")
    assert autobuild.of("autob") is None


def test_compose_recoit_le_dockerfile(monkeypatch, tmp_path, app_row):
    from app import platform as P
    monkeypatch.setattr(P, "APPS_DIR", str(tmp_path))
    a = {**app_row, "slug": "autoc", "source": "git", "image": "https://github.com/exemple/app", "version": "main", "kind": "web"}
    db.kv_set("autobuild", {"autoc": {"own": False, "dockerfile": "FROM node:22\n", "label": "Node.js 22", "start": "npm run start"}})
    doc = json.loads(open(P.write_compose(a, "main")).read().split("\n", 1)[1])
    assert doc["services"]["app"]["build"] == {"context": f"{tmp_path}/autoc/src", "dockerfile_inline": "FROM node:22\n"}
    autobuild.save_source("autoc", "apps/api", None)
    doc = json.loads(open(P.write_compose(a, "main")).read().split("\n", 1)[1])
    assert doc["services"]["app"]["build"]["context"] == f"{tmp_path}/autoc/src/apps/api"
    autobuild.forget("autoc")
    db.kv_set("autobuild", {})
    doc = json.loads(open(P.write_compose(a, "main")).read().split("\n", 1)[1])
    assert "dockerfile_inline" not in doc["services"]["app"]["build"]


def test_nouveaux_commits_sans_webhook(monkeypatch, app_row):
    from app import platform as P
    db.x("DELETE FROM apps WHERE slug IN ('suivie', 'figee')")
    for slug, v, port in (("suivie", "main", 18091), ("figee", "a1b2c3d", 18092)):
        db.insert_app(slug, {**app_row, "slug": slug, "name": slug, "source": "git", "image": "https://github.com/exemple/app",
                             "version": v, "state": "ok", "kind": "web", "created_at": 0, "expose": "path", "sub": "", "host_port": port})
    db.kv_set("git_watch", {"disparue": "x" * 40})
    heads = {"main": "1" * 40}
    monkeypatch.setattr(autobuild, "head", lambda repo, br, token="": heads.get(br))
    deployed = []
    monkeypatch.setattr(P, "spawn", lambda fn, *a: deployed.append(a))
    autobuild.watch_tick()
    assert db.kv_get("git_watch") == {"suivie": "1" * 40} and not deployed      # premier passage : repère seulement
    autobuild.watch_tick()
    assert not deployed                                                       # rien de neuf
    heads["main"] = "2" * 40
    autobuild.watch_tick()
    assert deployed == [("suivie", "main", "update")] and "suivie" in P._rebuild
    P._rebuild.discard("suivie")
    db.x("DELETE FROM apps WHERE slug IN ('suivie', 'figee')")
    db.kv_set("git_watch", {})


def test_source_dossier_et_jeton():
    autobuild.save_source("srcx", "apps/api/", "ghp_abcdefgh12345678")
    assert autobuild.source("srcx") == {"dir": "apps/api", "token": "ghp_abcdefgh12345678"}
    for bad in ("../x", "a/../../b", "a b", "a;b"):
        with pytest.raises(ValueError):
            autobuild.save_source("srcx", bad, None)
    autobuild.save_source("srcx", None, "")                                   # jeton retiré, dossier gardé
    assert autobuild.source("srcx") == {"dir": "apps/api", "token": ""}
    autobuild.save_source("srcx", "", None)
    assert "srcx" not in (db.kv_get("git_source") or {})


def test_jeton_jamais_sur_la_ligne_de_commande():
    sc = autobuild.clone_script("https://github.com/moi/prive.git", "main", "/srv/apps/x/src", "ghp_SECRET12345678")
    lines = sc.splitlines()
    assert any(l.startswith("export GIT_CONFIG_VALUE_0=") for l in lines)
    assert not any("SECRET" in l or "Authorization" in l for l in lines if l.startswith("git "))
    import base64
    assert base64.b64encode(b"x-access-token:ghp_SECRET12345678").decode() in sc
    assert "oauth2:" in base64.b64decode(autobuild._auth_env("https://gitlab.com/a/b.git", "glpat-12345678")["GIT_CONFIG_VALUE_0"].split()[-1]).decode()
    assert "'main'" in sc or " main" in sc
    sc = autobuild.clone_script("https://x/y.git", "main; rm -rf /", "/d")
    assert "'main; rm -rf /'" in sc                                            # valeurs toujours citées


def test_analyse_sous_dossier(tmp_path):
    import subprocess
    repo = tmp_path / "mono"
    proj(repo, {"README.md": "", "apps/api/requirements.txt": "flask\n", "apps/api/app.py": "app = Flask(__name__)\n"})
    g = lambda *a: subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *a], check=True, capture_output=True)  # noqa: E731
    g("init", "-q", "-b", "main")
    g("add", ".")
    g("commit", "-qm", "x")
    d = autobuild.analyse(f"file://{repo}", "main", "apps/api")
    assert d["label"].endswith("Flask") and len(d["sha"]) == 40
    with pytest.raises(RuntimeError, match="absent"):
        autobuild.analyse(f"file://{repo}", "main", "apps/web")
    with pytest.raises(RuntimeError, match="non reconnue"):
        autobuild.analyse(f"file://{repo}", "main")
    with pytest.raises(RuntimeError, match="introuvable"):
        autobuild.analyse(f"file://{repo}", "pas-de-branche")


def test_variables_django():
    db.x("DELETE FROM routes WHERE slug = 'dj'")
    db.x("INSERT OR IGNORE INTO domains(name, mode, hub, created_at) VALUES('exemple.fr', 'tunnel', 'apps', 0)")
    db.x("INSERT INTO routes(slug, pos, kind, domain, sub) VALUES('dj', 0, 'sub', 'exemple.fr', 'blog')")
    db.kv_set("autobuild", {"dj": {"framework": "Django"}})
    env = autobuild.extra_env("dj")
    assert env["DJANGO_ALLOWED_HOSTS"].startswith("blog.exemple.fr,") and env["ALLOWED_HOSTS"] == env["DJANGO_ALLOWED_HOSTS"]
    assert env["CSRF_TRUSTED_ORIGINS"] == "https://blog.exemple.fr" and len(env["DJANGO_SECRET_KEY"]) > 40
    assert autobuild.extra_env("dj")["SECRET_KEY"] == env["SECRET_KEY"]       # stable d'un déploiement à l'autre
    db.kv_set("autobuild", {"dj": {"framework": "Flask"}})
    assert autobuild.extra_env("dj") == {}
    autobuild.forget("dj")
    db.x("DELETE FROM routes WHERE slug = 'dj'")


def test_analyse_depuis_le_formulaire(monkeypatch):
    from argon2 import PasswordHasher
    from fastapi.testclient import TestClient
    from app import main
    seen = []
    monkeypatch.setattr(autobuild, "analyse", lambda repo, ref, folder="", token="": seen.append((repo, ref, folder, token))
                        or {"own": False, "label": "Python 3.12 (pip) · Django", "start": "gunicorn x", "notes": ["n"], "sha": "a" * 40})
    db.x("INSERT OR REPLACE INTO users(username, hash) VALUES(?, ?)", ("ana", PasswordHasher().hash("mot-de-passe-ana")))
    c = TestClient(main.app, base_url="https://hangar.test", client=("127.0.0.1", 50045))
    main._fails.clear()
    same = {"sec-fetch-site": "same-origin"}
    c.post("/login", data={"username": "ana", "password": "mot-de-passe-ana"}, headers=same, follow_redirects=False)
    r = c.post("/depot/analyse", data={"repo": "https://github.com/moi/app", "ref": "main", "git_dir": "apps/api",
                                      "git_token": "ghp_abcdefgh12345678"}, headers=same).json()
    assert r == {"ok": True, "own": False, "label": "Python 3.12 (pip) · Django", "start": "gunicorn x", "notes": ["n"], "sha": "aaaaaaa"}
    assert seen == [("https://github.com/moi/app", "main", "apps/api", "ghp_abcdefgh12345678")]
    r = c.post("/depot/analyse", data={"repo": "file:///etc", "ref": "main"}, headers=same).json()
    assert not r["ok"] and "invalide" in r["error"]
    r = c.post("/depot/analyse", data={"repo": "https://github.com/moi/app", "git_dir": "../x"}, headers=same).json()
    assert not r["ok"]
