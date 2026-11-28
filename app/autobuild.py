"""Construction sans Dockerfile : Hangar reconnaît la technologie d'un dépôt Git et écrit lui-même le Dockerfile.

Utilisé pour les applis « construites depuis Git » dont le dépôt n'a pas de Dockerfile à la racine. Avant chaque
construction, refresh() clone le dépôt (profondeur 1) dans un dossier jetable de la console, LIT ses fichiers (rien
n'y est exécuté), puis garde le Dockerfile choisi dans kv « autobuild » ; platform.write_compose() le passe à Docker
(dockerfile_inline), la construction elle-même restant sur la machine de l'appli, comme avec un Dockerfile.

Reconnu, dans cet ordre : Dockerfile (celui du dépôt, rien à faire) ; Node.js (npm, pnpm, Yarn, Bun ; serveur avec
« start », ou appli construite en fichiers statiques : Vite, React, Vue, Astro…) ; Python (requirements.txt,
pyproject.toml, uv, Poetry ; Django, FastAPI, Flask) ; PHP (Composer, Laravel…) ; Go ; site statique (index.html).
Un Procfile « web: … » donne la commande de démarrage. Toutes les applis écoutent sur le port 8080 (variable PORT).
Tout ce qui vient du dépôt et entre dans le Dockerfile est vérifié (noms de modules, chemins) ou passé en JSON.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import time

from . import db

PORT = 8080
NODE = (18, 20, 22, 24)
NODE_DEFAULT = 22
PYTHON = ("3.9", "3.10", "3.11", "3.12", "3.13")
PYTHON_DEFAULT = "3.12"
SAFE_PATH = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./-]{0,120}$")
SAFE_MOD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
SAFE_VAR = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,60}$")
UNSUPPORTED = {"Gemfile": "Ruby", "pom.xml": "Java (Maven)", "build.gradle": "Java (Gradle)", "build.gradle.kts": "Kotlin",
               "Cargo.toml": "Rust", "mix.exs": "Elixir", "deno.json": "Deno", "*.csproj": ".NET"}
FW_NAMES = {"next": "Next.js", "nuxt": "Nuxt", "@remix-run/serve": "Remix", "@nestjs/core": "NestJS", "express": "Express",
            "fastify": "Fastify", "hono": "Hono", "koa": "Koa"}
STATIC_FRAMEWORKS = ("vite", "react-scripts", "@vue/cli-service", "astro", "@angular/cli", "parcel", "gatsby",
                     "@docusaurus/core", "vitepress", "@sveltejs/adapter-static")


class Unsupported(ValueError):
    pass


# ---------------------------------------------------------------- lecture du dépôt (sans rien exécuter)

def _file(root, name, limit=512 * 1024):
    """Contenu d'un fichier du dépôt, ou None (absent, lien symbolique, trop gros, hors du dépôt)."""
    p = os.path.join(root, name)
    if os.path.islink(p) or not os.path.isfile(p) or os.path.getsize(p) > limit:
        return None
    if not os.path.realpath(p).startswith(os.path.realpath(root) + os.sep):
        return None
    with open(p, encoding="utf-8", errors="replace") as f:
        return f.read()


def _has(root, *names):
    return any(os.path.lexists(os.path.join(root, n)) for n in names)


def procfile_web(root):
    for line in (_file(root, "Procfile") or "").splitlines():
        m = re.match(r"^\s*web\s*:\s*(.+?)\s*$", line)
        if m and "\n" not in m.group(1):
            return m.group(1)[:500]
    return None


def _cmd(start):
    """CMD d'un Dockerfile : commande shell passée en JSON (jamais interprétée par le Dockerfile lui-même)."""
    return "CMD " + json.dumps(["sh", "-c", start])


# ---------------------------------------------------------------- Node.js

def _node_version(root, pkg):
    for src in ((_file(root, ".nvmrc") or "").strip(), (_file(root, ".node-version") or "").strip(),
                str(((pkg.get("engines") or {}).get("node")) or "")):
        m = re.search(r"(\d+)", src or "")
        if m:
            n = int(m.group(1))
            if src.lstrip().startswith(">"):
                return max(n, NODE_DEFAULT) if max(n, NODE_DEFAULT) in NODE else NODE_DEFAULT
            return n if n in NODE else NODE_DEFAULT
    return NODE_DEFAULT


def _node(root):
    raw = _file(root, "package.json")
    try:
        pkg = json.loads(raw)
        assert isinstance(pkg, dict)
    except (TypeError, ValueError, AssertionError):
        raise Unsupported("package.json illisible")
    scripts = pkg.get("scripts") if isinstance(pkg.get("scripts"), dict) else {}
    deps = {}
    for k in ("dependencies", "devDependencies"):
        if isinstance(pkg.get(k), dict):
            deps.update(pkg[k])
    if _has(root, "bun.lockb", "bun.lock"):
        pm, install, run = "bun", "bun install", "bun run"
    elif _has(root, "pnpm-lock.yaml"):
        pm, install, run = "pnpm", "pnpm install --frozen-lockfile", "pnpm run"
    elif _has(root, "yarn.lock"):
        pm, install, run = "yarn", "yarn install --frozen-lockfile", "yarn run"
    else:
        pm, install, run = "npm", "npm ci" if _has(root, "package-lock.json") else "npm install", "npm run"
    ver = _node_version(root, pkg)
    build = f"RUN {run} build\n" if "build" in scripts else ""
    web = procfile_web(root)
    fw = next((f for f in ("next", "nuxt", "@remix-run/serve", "@nestjs/core", "express", "fastify", "hono", "koa") if f in deps), None)
    static = not web and "start" not in scripts and "build" in scripts and fw is None and any(f in deps for f in STATIC_FRAMEWORKS)
    base = "oven/bun:1" if pm == "bun" else f"node:{ver}-bookworm-slim"
    label = ("Bun" if pm == "bun" else f"Node.js {ver}") + ("" if pm in ("npm", "bun") else f" ({pm})")
    setup = "" if pm in ("npm", "bun") else "RUN corepack enable\n"
    if static:   # appli construite en fichiers (Vite, React…) : servis par nginx, sans Node au démarrage
        return {"stack": "node-static", "label": f"{label}, construite en site statique",
                "start": "fichiers servis par nginx (dist/, build/ ou out/)", "dockerfile": f"""FROM {base} AS build
WORKDIR /app
{setup}COPY . .
RUN {install}
{build}RUN set -e; for d in dist build out .output/public dist/*/browser dist/*; do if [ -f "$d/index.html" ]; then mkdir -p /site && cp -r "$d"/. /site/; break; fi; done; test -f /site/index.html || {{ echo "Aucun index.html après la construction (dist/, build/ ou out/)"; exit 1; }}

FROM nginxinc/nginx-unprivileged:stable-alpine
COPY --from=build /site /usr/share/nginx/html
RUN printf 'server {{ listen {PORT}; root /usr/share/nginx/html; location / {{ try_files $uri $uri/ /index.html; }} }}\\n' > /etc/nginx/conf.d/default.conf
EXPOSE {PORT}
"""}
    if web:
        start = web
    elif "start" in scripts:
        start = f"{run} start"
    elif fw == "next":
        start = "npx next start"
    else:
        main = pkg.get("main") if isinstance(pkg.get("main"), str) and SAFE_PATH.match(pkg.get("main") or "") else None
        main = main or next((f for f in ("server.js", "index.js", "app.js", "main.js", "server.mjs", "index.mjs") if _has(root, f)), None)
        if not main:
            raise Unsupported("projet Node.js sans commande de démarrage : ajoute un script « start » dans package.json "
                              "(ou un Procfile « web: … »)")
        start = ("bun " if pm == "bun" else "node ") + main
    user = "bun" if pm == "bun" else "node"
    return {"stack": "node", "label": label + (f" · {FW_NAMES[fw]}" if fw else ""),
            "start": start, "dockerfile": f"""FROM {base}
WORKDIR /app
{setup}RUN chown {user}:{user} /app
USER {user}
COPY --chown={user}:{user} . .
RUN {install}
{build}ENV NODE_ENV=production PORT={PORT} HOST=0.0.0.0 HOSTNAME=0.0.0.0
EXPOSE {PORT}
{_cmd(start)}
"""}


# ---------------------------------------------------------------- Python

def _python_version(root):
    for name in (".python-version", "runtime.txt"):
        m = re.search(r"(3\.\d+)", _file(root, name) or "")
        if m and m.group(1) in PYTHON:
            return m.group(1)
    return PYTHON_DEFAULT


def _find_app(root, ctor):
    """(module, variable) d'une appli FastAPI ou Flask dans les fichiers habituels."""
    for rel in ("main.py", "app.py", "server.py", "wsgi.py", "asgi.py", "api.py", "app/main.py", "app/__init__.py",
                "src/main.py", "src/app.py", "app/app.py"):
        text = _file(root, rel)
        if not text:
            continue
        m = re.search(rf"^(\w+)\s*(?::\s*\w+\s*)?=\s*{ctor}\(", text, re.M)
        if m and SAFE_VAR.match(m.group(1)):
            mod = rel[:-3].replace("/", ".").removesuffix(".__init__")
            if SAFE_MOD.match(mod):
                return mod, m.group(1)
    return None


def _django_wsgi(root):
    if not _has(root, "manage.py"):
        return None
    for d in sorted(os.listdir(root)):
        if SAFE_VAR.match(d) and "get_wsgi_application" in (_file(root, f"{d}/wsgi.py") or ""):
            return f"{d}.wsgi"
    return None


def _python(root):
    reqs = (_file(root, "requirements.txt") or "") + (_file(root, "pyproject.toml") or "") + (_file(root, "Pipfile") or "")
    low = reqs.lower()
    ver = _python_version(root)
    if _has(root, "uv.lock"):
        tool, install = "uv", "RUN pip install uv && uv export --frozen --no-dev --no-hashes -o /tmp/req.txt && pip install -r /tmp/req.txt\n"
        if "[project]" in (_file(root, "pyproject.toml") or "") and "[build-system]" in (_file(root, "pyproject.toml") or ""):
            install += "RUN pip install --no-deps .\n"
    elif _has(root, "poetry.lock"):
        tool, install = "Poetry", ("RUN pip install poetry poetry-plugin-export && poetry export --without-hashes -o /tmp/req.txt "
                                   "&& pip install -r /tmp/req.txt\n")
    elif _has(root, "requirements.txt"):
        tool, install = "pip", "RUN pip install -r requirements.txt\n"
    elif _has(root, "pyproject.toml"):
        tool, install = "pip", "RUN pip install .\n"
    else:
        tool, install = "pipenv", "RUN pip install pipenv && pipenv requirements > /tmp/req.txt && pip install -r /tmp/req.txt\n"
    web, extra, fw = procfile_web(root), [], None
    if web:
        start = web
    elif (wsgi := _django_wsgi(root)):
        fw, start = "Django", f"gunicorn {wsgi} --bind 0.0.0.0:{PORT} --workers 2"
        extra.append("gunicorn")
    elif (app := _find_app(root, "FastAPI")):
        fw, start = "FastAPI", f"uvicorn {app[0]}:{app[1]} --host 0.0.0.0 --port {PORT}"
        extra.append("uvicorn[standard]")
    elif (app := _find_app(root, "Flask")):
        fw, start = "Flask", f"gunicorn {app[0]}:{app[1]} --bind 0.0.0.0:{PORT} --workers 2"
        extra.append("gunicorn")
    else:
        main = next((f for f in ("main.py", "app.py", "server.py") if _has(root, f)), None)
        if not main:
            raise Unsupported("projet Python sans point d'entrée reconnu (Django, FastAPI, Flask, main.py, app.py) : "
                              "ajoute un Procfile « web: … »")
        start = f"python {main}"
    extra = [e for e in extra if e.split("[")[0] not in low]
    add = f"RUN pip install {' '.join(extra)}\n" if extra else ""
    static = "RUN python manage.py collectstatic --noinput >/dev/null 2>&1 || true\n" if fw == "Django" else ""
    notes = ["Hangar fournit DJANGO_ALLOWED_HOSTS, DJANGO_SECRET_KEY et DJANGO_CSRF_TRUSTED_ORIGINS (aussi sans le "
             "préfixe DJANGO_) avec les adresses de l'appli : settings.py doit les lire (os.environ)."] if fw == "Django" else []
    return {"stack": "python", "framework": fw or "", "notes": notes,
            "label": f"Python {ver} ({tool})" + (f" · {fw}" if fw else ""), "start": start,
            "dockerfile": f"""FROM python:{ver}-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PORT={PORT}
WORKDIR /app
COPY . .
{install}{add}{static}RUN useradd --uid 10001 --no-create-home app && chown -R app /app
USER app
EXPOSE {PORT}
{_cmd(start)}
"""}


# ---------------------------------------------------------------- PHP, Go, statique

def _php(root):
    pub = "public" if os.path.isdir(os.path.join(root, "public")) and not os.path.islink(os.path.join(root, "public")) else ""
    laravel = _has(root, "artisan")
    composer = "COPY --from=composer:2 /usr/bin/composer /usr/bin/composer\nRUN composer install --no-dev --optimize-autoloader --no-interaction\n" \
        if _has(root, "composer.json") else ""
    perms = "RUN chown -R www-data:www-data storage bootstrap/cache\n" if laravel else ""
    return {"stack": "php", "label": "PHP 8.3 (Apache)" + (" · Laravel" if laravel else ""), "start": "Apache"
            + (f", dossier {pub}/" if pub else ""), "dockerfile": f"""FROM php:8.3-apache
RUN apt-get update && apt-get install -y --no-install-recommends libpq-dev libzip-dev unzip git \\
 && docker-php-ext-install pdo_mysql pdo_pgsql zip && a2enmod rewrite && rm -rf /var/lib/apt/lists/*
RUN sed -i 's/Listen 80$/Listen {PORT}/' /etc/apache2/ports.conf \\
 && sed -i 's/<VirtualHost \\*:80>/<VirtualHost *:{PORT}>/; s#/var/www/html#/var/www/html/{pub}#' /etc/apache2/sites-available/000-default.conf \\
 && printf '<Directory /var/www/html>\\n  AllowOverride All\\n</Directory>\\n' > /etc/apache2/conf-enabled/hangar.conf
WORKDIR /var/www/html
COPY . .
{composer}{perms}EXPOSE {PORT}
"""}


def _go(root):
    mod = _file(root, "go.mod") or ""
    m = re.search(r"^go\s+(1\.\d+)", mod, re.M)
    ver = m.group(1) if m else "1.23"
    if _has(root, "main.go"):
        pkg = "."
    else:
        cmds = sorted(d for d in (os.listdir(os.path.join(root, "cmd")) if os.path.isdir(os.path.join(root, "cmd")) else [])
                      if SAFE_VAR.match(d) and _has(root, f"cmd/{d}/main.go"))
        if len(cmds) != 1:
            raise Unsupported("projet Go : main.go à la racine, ou un seul programme dans cmd/<nom>/, attendu")
        pkg = f"./cmd/{cmds[0]}"
    return {"stack": "go", "label": f"Go {ver}", "start": f"programme construit depuis {pkg}", "dockerfile": f"""FROM golang:{ver} AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app {pkg}

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
ENV PORT={PORT}
EXPOSE {PORT}
ENTRYPOINT ["/app"]
"""}


def _static(root):
    return {"stack": "static", "label": "Site statique (nginx)", "start": "fichiers du dépôt servis par nginx",
            "notes": ["Le type « site statique » de Hangar sert ce genre de dépôt sans conteneur."],
            "dockerfile": f"""FROM nginxinc/nginx-unprivileged:stable-alpine
COPY . /usr/share/nginx/html
RUN rm -rf /usr/share/nginx/html/.git && printf 'server {{ listen {PORT}; root /usr/share/nginx/html; location / {{ try_files $uri $uri/ =404; }} }}\\n' > /etc/nginx/conf.d/default.conf
EXPOSE {PORT}
"""}


def detect(root):
    """Ce que Hangar construira pour ce dépôt : None s'il a son propre Dockerfile, sinon {stack, label, start, dockerfile}."""
    if _has(root, "Dockerfile"):
        return None
    if _has(root, "package.json"):
        return _node(root)
    if _has(root, "requirements.txt", "pyproject.toml", "Pipfile"):
        return _python(root)
    if _has(root, "composer.json") or (_has(root, "index.php") and not _has(root, "index.html")):
        return _php(root)
    if _has(root, "go.mod"):
        return _go(root)
    if _has(root, "index.html"):
        return _static(root)
    for name, what in UNSUPPORTED.items():
        if (name.startswith("*") and any(f.endswith(name[1:]) for f in os.listdir(root))) or _has(root, name):
            raise Unsupported(f"{what} n'est pas encore reconnu : ajoute un Dockerfile au dépôt")
    raise Unsupported("technologie non reconnue (Node.js, Python, PHP, Go ou site statique attendus) : "
                      "ajoute un Dockerfile au dépôt")


# ---------------------------------------------------------------- dépôt → réglage

# ---------------------------------------------------------------- dépôt : lecture (console) et copie (machine de construction)

GIT_SOURCE = "git_source"   # kv : {slug: {"dir": "sous/dossier", "token": "jeton de lecture"}}
DIR_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*(/[A-Za-z0-9_][A-Za-z0-9_.-]*){0,6}$")


def source(slug):
    return {"dir": "", "token": "", **((db.kv_get(GIT_SOURCE) or {}).get(slug) or {})}


def save_source(slug, folder=None, token=None):
    """Sous-dossier de l'appli dans le dépôt, et jeton de lecture d'un dépôt privé (None : inchangé, '' : retiré)."""
    cur = source(slug)
    if folder is not None:
        folder = folder.strip().strip("/")
        if folder and (not DIR_RE.match(folder) or ".." in folder.split("/")):
            raise ValueError("dossier : un chemin relatif simple, par exemple apps/api")
        cur["dir"] = folder
    if token is not None:
        token = token.strip()
        if token and not re.fullmatch(r"[A-Za-z0-9_.\-]{8,255}", token):
            raise ValueError("jeton : caractères inattendus")
        cur["token"] = token
    allv = db.kv_get(GIT_SOURCE) or {}
    if cur["dir"] or cur["token"]:
        allv[slug] = {k: v for k, v in cur.items() if v}
    else:
        allv.pop(slug, None)
    db.kv_set(GIT_SOURCE, allv)


def _auth_env(repo, token):
    """Jeton passé à git par l'environnement (jamais sur la ligne de commande, visible par ps)."""
    if not token or not repo.startswith("https://"):
        return {}
    import base64
    user = "oauth2" if "gitlab" in repo.split("/")[2] else "x-access-token"
    return {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraHeader",
            "GIT_CONFIG_VALUE_0": "Authorization: Basic " + base64.b64encode(f"{user}:{token}".encode()).decode()}


def clone_script(repo, ref, dest, token=""):
    """Script bash (lu sur l'entrée standard) : copie superficielle d'une branche, d'un tag ou d'un commit dans dest."""
    import shlex
    env = {"GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1", **_auth_env(repo, token)}
    q = shlex.quote
    return "\n".join(["set -e", *[f"export {k}={q(v)}" for k, v in env.items()],
                      "command -v git >/dev/null || { apt-get -q -y install git >/dev/null; }",
                      f"rm -rf {q(dest)}", f"mkdir -p {q(dest)}", f"cd {q(dest)}", "git init -q",
                      f"git remote add origin {q(repo)}",
                      f"git fetch -q --depth 1 --no-tags origin {q(ref)} 2>&1 || git fetch -q --depth 1 origin {q('refs/tags/' + ref)} 2>&1",
                      "git checkout -q FETCH_HEAD", "git rev-parse HEAD", ""])


def _clone_error(out):
    if re.search(r"could not read Username|Authentication failed|terminal prompts disabled|Permission denied|"
                 r"not found|Repository not found|403", out or "", re.I):
        return "dépôt introuvable, ou privé : renseigne un jeton de lecture (Réglages de l'appli)"
    if re.search(r"couldn't find remote ref|unknown revision|not our ref", out or "", re.I):
        return "branche, tag ou commit introuvable dans le dépôt"
    last = (out or "").strip().splitlines()
    return "lecture du dépôt impossible" + (" : " + last[-1][:200] if last else "")


def fetch(repo, ref, dest, token=""):
    """Copie superficielle sur la console (dossier jetable), pour lire le dépôt. Retourne le commit."""
    p = subprocess.run(["bash", "-s"], input=clone_script(repo, ref, dest, token), capture_output=True, text=True, timeout=300)
    if p.returncode:
        raise RuntimeError(_clone_error(p.stdout + p.stderr))
    return (p.stdout.strip().splitlines() or [""])[-1][:40]


def checkout(a, version):
    """Copie du dépôt sur la machine de l'appli (<dossier de l'appli>/src), d'où Docker construit."""
    from . import platform as P
    rc, out = P.nsh(a.get("node"), "bash -s", timeout=900,
                    input=clone_script(a["image"], version, src_dir(a["slug"]), source(a["slug"])["token"]))
    if rc:
        raise RuntimeError(_clone_error(out))


def src_dir(slug):
    from . import platform as P
    return f"{P.app_dir(slug)}/src"


def context(slug):
    """Dossier construit par Docker sur la machine de l'appli (sous-dossier compris)."""
    d = source(slug)["dir"]
    return src_dir(slug) + (f"/{d}" if d else "")


def analyse(repo, ref, folder="", token=""):
    """Ce que Hangar construirait pour ce dépôt, sans rien garder. Lève RuntimeError si impossible."""
    work = tempfile.mkdtemp(prefix="hangar-detect-")
    try:
        src = os.path.join(work, "src")
        sha = fetch(repo, ref, src, token)
        root = os.path.join(src, folder) if folder else src
        if folder and (os.path.islink(root) or not os.path.isdir(root)
                       or not os.path.realpath(root).startswith(os.path.realpath(src) + os.sep)):
            raise RuntimeError(f"dossier {folder} absent du dépôt")
        try:
            d = detect(root)
        except Unsupported as e:
            raise RuntimeError(str(e))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return {"own": True, "sha": sha} if d is None else {**d, "own": False, "sha": sha}


def of(slug):
    return (db.kv_get("autobuild") or {}).get(slug)


def forget(slug):
    for key in ("autobuild", GIT_SOURCE, "autobuild_secrets"):
        allv = db.kv_get(key) or {}
        if allv.pop(slug, None) is not None:
            db.kv_set(key, allv)


def refresh(a, version):
    """Lit le dépôt de l'appli à cette version et garde ce qu'il faut construire. Lève RuntimeError si impossible."""
    src = source(a["slug"])
    d = analyse(a["image"], version, src["dir"], src["token"])
    allv = db.kv_get("autobuild") or {}
    allv[a["slug"]] = {**d, "version": version, "ts": time.time()}
    db.kv_set("autobuild", allv)
    return allv[a["slug"]]


def inline(slug):
    """Dockerfile écrit par Hangar pour cette appli, ou None (dépôt avec son propre Dockerfile, pas encore lu)."""
    d = of(slug)
    return d["dockerfile"] if d and not d.get("own") else None


# ---------------------------------------------------------------- nouveaux commits, sans webhook

WATCH_EVERY = 120


def head(repo, branch, token=""):
    """Dernier commit d'une branche (git ls-remote, sans rien télécharger), ou None."""
    try:
        p = subprocess.run(["git", "ls-remote", "--", repo, f"refs/heads/{branch}"], capture_output=True, text=True,
                           timeout=30, env={**os.environ, "GIT_TERMINAL_PROMPT": "0", **_auth_env(repo, token)})
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.match(r"^([0-9a-f]{40})\s", p.stdout or "")
    return m.group(1) if p.returncode == 0 and m else None


def watch_tick():
    """Applis construites depuis une branche Git : un nouveau commit relance construction et déploiement.
    Le webhook (hooks.py) fait la même chose sans attendre ; « reconstruire au push » décoché : rien."""
    from . import hooks
    from . import platform as P
    seen = db.kv_get("git_watch") or {}
    apps = [a for a in db.q("SELECT * FROM apps WHERE source = 'git'")]
    changed = False
    for a in apps:
        a = dict(a)
        if a["desired"] == "stopped" or a["state"] == "deploying" or not hooks.options(a["slug"])["rebuild"]:
            continue
        if re.fullmatch(r"[0-9a-f]{7,40}", a["version"] or "") or not re.fullmatch(r"[A-Za-z0-9._/-]{1,120}", a["version"] or ""):
            continue   # commit figé : rien à suivre
        sha = head(a["image"], a["version"], source(a["slug"])["token"])
        if not sha:
            continue
        last = seen.get(a["slug"])
        seen[a["slug"]] = sha
        changed = changed or last != sha
        if last and last != sha:
            P.log("info", a["slug"], f"nouveau commit {sha[:7]} sur {a['version']} : reconstruction")
            P.request_rebuild(a["slug"])
            P.spawn(P.deploy, a["slug"], a["version"], "update")
    for slug in [s for s in seen if not any(a["slug"] == s for a in apps)]:
        seen.pop(slug)
        changed = True
    if changed:
        db.kv_set("git_watch", seen)


# ---------------------------------------------------------------- variables attendues par certains frameworks

def extra_env(slug):
    """Variables données à l'appli selon sa technologie (une variable réglée dans la fiche l'emporte toujours)."""
    ab = of(slug) or {}
    if ab.get("framework") != "Django":
        return {}
    from . import domains as D
    hosts = [h for h in (D.host_of(r) for r in D.routes(slug)) if h]
    allv = db.kv_get("autobuild_secrets") or {}
    if slug not in allv:
        import secrets
        allv[slug] = secrets.token_urlsafe(48)
        db.kv_set("autobuild_secrets", allv)
    names = ",".join(hosts + ["localhost", "127.0.0.1"])
    origins = ",".join(f"https://{h}" for h in hosts)
    env = {}
    for pre in ("DJANGO_", ""):
        env.update({f"{pre}ALLOWED_HOSTS": names, f"{pre}SECRET_KEY": allv[slug], f"{pre}CSRF_TRUSTED_ORIGINS": origins})
    return env
