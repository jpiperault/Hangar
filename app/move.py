"""Déplacement d'une appli d'un nœud à un autre, avec retour à l'origine si la cible ne répond pas.

1. Pendant que l'appli tourne : image préparée sur la cible, première copie de data/ vers la console (relais).
2. Coupure : arrêt à l'origine, copie finale (différences seulement), export de la base.
3. Cible : base recréée et restaurée, data/ copié, démarrage, healthcheck.
4. Succès : routes basculées, l'origine est nettoyée ; une copie reste dans /srv/backups/avant-deplacement.
   Échec : la cible est nettoyée, l'appli redémarre à l'origine.
"""
import os
import shutil
import subprocess
import time

from . import alerts, db
from . import platform as P

SAFE = "/srv/backups/avant-deplacement"


def _dump(slug, node, path):
    with open(path, "wb") as f:
        p = subprocess.run(["docker", "exec", P.PG, "pg_dump", "-U", "platform", "-Fc", P.db_name(slug)],
                           stdout=f, stderr=subprocess.PIPE, timeout=3600, env=P.denv(node))
    if p.returncode:
        raise RuntimeError("export de la base impossible : " + p.stderr.decode(errors="replace")[-300:])


def _restore(slug, node, path):
    name = P.db_name(slug)
    with open(path, "rb") as f:
        p = subprocess.run(["docker", "exec", "-i", P.PG, "pg_restore", "-U", "platform", "--clean", "--if-exists",
                            "--no-owner", "--no-acl", f"--role={name}", "-d", name],
                           stdin=f, capture_output=True, timeout=3600, env=P.denv(node))
    errs = [l for l in p.stderr.decode(errors="replace").splitlines() if "error" in l.lower()]
    if p.returncode and errs:
        P.log("warn", slug, "restauration de la base sur la cible avec avertissements : " + " | ".join(errs[-3:]))


def _cleanup(slug, node, with_db):
    d = P.app_dir(slug)
    P.dk(node, "compose", "down", "--remove-orphans", cwd=d, timeout=180)
    if with_db:
        P.drop_db(slug, node)
    if not P.is_local(node):
        P.nsh(node, f"rm -rf {d}", timeout=600)
    else:
        shutil.rmtree(f"{d}/data", ignore_errors=True)


def move(slug, target):
    from . import ha
    if ha.get(slug):
        P.log("error", slug, "déplacement refusé : appli en haute dispo (utilise « Basculer » ou retire la haute dispo)")
        return
    with P.op_lock:
        a = db.app(slug)
        if not a:
            return
        src = a["node"]
        d = P.app_dir(slug)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        stage = f"{SAFE}/{slug}-{stamp}"
        os.makedirs(stage, mode=0o700, exist_ok=True)
        b = {**a, "node": target}
        t0 = time.time()
        stopped = False
        P.log("info", slug, f"déplacement de {src} vers {target}")
        db.update_app(slug, state="deploying")
        try:
            # 1. sans coupure : image sur la cible, première copie de data/
            P.write_compose(b, a["version"])
            if a["source"] == "git":
                rc, out = P.dk(target, "compose", "build", "--pull", cwd=d, timeout=1800)
            else:
                rc, out = P.dk(target, "compose", "pull", "--quiet", cwd=d, timeout=900)
            if rc:
                raise RuntimeError("image indisponible sur la cible : " + P.tail(out, 2))
            P.pull_dir(src, f"{d}/data", f"{stage}/data")
            # 2. coupure
            P.write_compose(a, a["version"])
            P.dk(src, "compose", "stop", cwd=d, timeout=120)
            stopped = True
            t_cut = time.time()
            P.pull_dir(src, f"{d}/data", f"{stage}/data")
            if a["db"]:
                _dump(slug, src, f"{stage}/base.dump")
            # 3. cible
            P.write_compose(b, a["version"])
            if a["db"]:
                P.ensure_db(b)
                _restore(slug, target, f"{stage}/base.dump")
            P.push_dir(target, f"{stage}/data", f"{d}/data")
            P.prepare_data(b, a["version"])
            rc, out = P.dk(target, "compose", "up", "-d", "--remove-orphans", "--no-build", cwd=d, timeout=300)
            if rc:
                raise RuntimeError("démarrage sur la cible impossible : " + P.tail(out, 2))
            ok, detail = P.wait_health(b)
            if not ok:
                raise RuntimeError(f"healthcheck sur la cible en échec : {detail}")
            if a["desired"] == "stopped":   # appli arrêtée avant le déplacement : elle le reste
                P.dk(target, "compose", "stop", cwd=d, timeout=120)
            # 4. bascule
            db.update_app(slug, node=target, state="ok")
            P.apply_routing()
            cut = time.time() - t_cut
            try:
                _cleanup(slug, src, a["db"])
            except Exception as e:
                P.log("warn", slug, f"nettoyage de {src} incomplet : {e}")
            P.log("ok", slug, f"déplacée sur {target} en {time.time() - t0:.0f} s, dont {cut:.0f} s de coupure. "
                              f"Copie de sécurité (data/ et base) : {stage}")
        except Exception as e:
            P.log("error", slug, f"déplacement vers {target} en échec : {e}. Retour sur {src}.")
            try:
                _cleanup(slug, target, False)
                if a["db"]:
                    P._psql(f"DROP DATABASE IF EXISTS {P.db_name(slug)} WITH (FORCE);", target)
            except Exception:
                pass
            db.update_app(slug, node=src)
            P.write_compose(a, a["version"])
            if stopped or a["desired"] == "running":
                P.dk(src, "compose", "up", "-d", "--no-build", cwd=d, timeout=300)
            ok, detail = P.wait_health(a) if a["desired"] == "running" else (True, "")
            db.update_app(slug, state="ok" if ok else "error")
            P.log("warn" if ok else "error", slug, f"toujours sur {src}" + ("" if ok else f", mais ne répond pas : {detail}"))
            alerts.send(f"{a['name']} : déplacement en échec", f"Vers {target} : {e}\nL'appli est restée sur {src}.",
                        priority=4, tags=["warning"])
            P.apply_routing()
