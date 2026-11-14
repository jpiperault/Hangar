"""Préproduction d'une appli : une deuxième appli `<slug>-preprod`, même image, mêmes réglages, sur le même nœud,
avec une copie de la base et de data/ de la production. On y teste une version avec de vraies données, puis on la
déploie en production d'un clic.

- Adresses : chaque sous-domaine `x` devient `x-preprod` ; une route par chemin devient /<slug>-preprod/.
- L'appli de préproduction reçoit HANGAR_ENVIRONMENT=preprod : à elle de couper ce qui part vers l'extérieur
  (e-mails, notifications, paiements…) ; ses variables sont celles de la production, à revoir dans ses Réglages.
- Réglage kv « preprod » : {slug de la préproduction: slug de la production}.
"""
import os
import re
import secrets
import shutil
import subprocess
import time

from . import backup, db
from . import domains as D
from . import platform as P

SUFFIX = "-preprod"
COPY_KEYS = ["source", "image", "port", "health_path", "mem_mb", "env", "db", "data_user", "expose", "sub"]
TMP = P.WORK_TMP


def links():
    return db.kv_get("preprod") or {}


def prod_of(slug):
    return links().get(slug)


def of(slug):
    """Slug de la préproduction de la production `slug`, ou None."""
    return next((p for p, prod in links().items() if prod == slug and db.app(p)), None)


def target(slug):
    s = slug[:32 - len(SUFFIX)].rstrip("-") + SUFFIX
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?", s):
        raise ValueError("identifiant de préproduction impossible")
    return s


def _forget(pre):
    m = links()
    if m.pop(pre, None) is not None:
        db.kv_set("preprod", m)


def forget(slug):
    """Appli supprimée : son lien de préproduction (dans un sens ou dans l'autre) disparaît."""
    m = {p: prod for p, prod in links().items() if p != slug and prod != slug}
    db.kv_set("preprod", m)


def _routes(slug, pre):
    taken = {(r["domain"], r["sub"]) for r in db.q("SELECT domain, sub FROM routes WHERE kind = 'sub'")}
    out = []
    for r in D.routes(slug):
        if r["kind"] == "sub":
            sub = (f"{r['sub']}{SUFFIX}" if r["sub"] else pre)[:63]
            if (r["domain"], sub) in taken:
                raise ValueError(f"l'adresse {sub}.{r['domain']} est déjà prise")
            out.append({"kind": "sub", "domain": r["domain"], "sub": sub})
        else:
            out.append({"kind": "path", "domain": r["domain"], "sub": ""})
    return out


def check(slug):
    """Vérifie qu'une préproduction peut être créée ; retourne son slug. ValueError sinon."""
    a = db.app(slug)
    if not a:
        raise ValueError("appli introuvable")
    if prod_of(slug):
        raise ValueError("c'est déjà une préproduction")
    if of(slug):
        raise ValueError("cette appli a déjà une préproduction")
    from . import kinds
    if not kinds.http(a["kind"]):
        raise ValueError("la préproduction n'existe que pour les applis web (pas d'adresse à dupliquer)")
    pre = target(slug)
    if db.app(pre):
        raise ValueError(f"une appli « {pre} » existe déjà")
    _routes(slug, pre)
    return pre


def create(slug, version=None):
    """Thread : crée la préproduction, la déploie, puis y copie la base et data/ de la production."""
    a = db.app(slug)
    pre = check(slug)
    version = version or a["version"]
    data = {k: a[k] for k in COPY_KEYS}
    data.update(name=f"{a['name']} (préprod)"[:80], pkg="", version=version, node=a["node"],
                host_port=P.next_host_port(), state="deploying", desired="running", created_at=time.time(),
                db_password=secrets.token_hex(16) if a["db"] else None)
    db.insert_app(pre, data)
    D.set_routes(pre, _routes(slug, pre))
    from . import services
    r = services.redis(slug)
    if r:
        services.enable_redis(pre, r["mem"])   # son propre Redis (mot de passe à lui), données copiées avec data/
    my = services.mysql(slug)
    if my:   # sa propre base MySQL/MariaDB, remplie par l'export de la production (copié avec data/)
        services.enable_mysql(pre, my["engine"], my["mem"])
    m = links()
    m[pre] = slug
    db.kv_set("preprod", m)
    P.log("info", pre, f"préproduction de {slug} créée ({version}), copie des données de la production ensuite")
    P.deploy(pre, version, "create")
    if db.app(pre)["state"] == "ok":
        refresh(pre)


def _dump(slug, dest):
    """Export pg_dump -Fc sans propriétaires (rechargé ensuite pour le rôle de la préproduction)."""
    node, pg = P.pg_where(slug)
    with open(dest, "wb") as f:
        p = subprocess.run(["docker", "exec", pg, "pg_dump", "-U", "platform", "-Fc", "--no-owner", "--no-acl",
                            P.db_name(slug)], stdout=f, stderr=subprocess.PIPE, timeout=3600, env=P.denv(node))
    if p.returncode:
        raise RuntimeError("export de la base de production impossible : " + p.stderr.decode(errors="replace")[-300:])


def refresh(pre):
    """Recopie la base et data/ de la production dans la préproduction (état d'avant mis de côté)."""
    slug = prod_of(pre)
    prod, a = db.app(slug or ""), db.app(pre)
    if not prod or not a:
        raise RuntimeError("production ou préproduction introuvable")
    work = f"{TMP}/preprod-{pre}-{time.strftime('%Y%m%d-%H%M%S')}"
    os.makedirs(work, mode=0o700)
    started = False
    try:
        parts = ["data"]
        from . import services
        services.fresh_dump(prod)   # MySQL / MariaDB de la production : export à jour, copié avec data/
        if prod["db"] and a["db"]:
            _dump(slug, f"{work}/db.dump")
            parts.append("db")
        if P.is_local(prod["node"]):
            src = f"{P.app_dir(slug)}/data"
            if os.path.isdir(src):
                shutil.copytree(src, f"{work}/data", symlinks=True)
        else:
            P.pull_dir(prod["node"], f"{P.app_dir(slug)}/data", f"{work}/data")
        os.makedirs(f"{work}/data", exist_ok=True)
        with P.op_lock:
            started = True
            db.update_app(pre, state="deploying")
            backup._apply(db.app(pre), f"{work}/data", f"{work}/db.dump", parts, f"la production {slug}")
    except Exception as e:
        P.log("error", pre, f"copie des données de la production impossible : {str(e)[:500]}")
        backup.after_failure(pre, started, "ok")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def promote(pre):
    """Déploie en production la version qui tourne en préproduction (thread)."""
    slug, a = prod_of(pre), db.app(pre)
    prod = db.app(slug or "")
    if not prod or not a:
        raise RuntimeError("production ou préproduction introuvable")
    P.log("info", slug, f"déploiement de {a['version']}, validée en préproduction ({pre})")
    P.deploy(slug, a["version"], "update")
