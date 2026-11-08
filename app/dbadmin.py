"""Gestion de la base PostgreSQL d'une appli : taille, tables, export, import, remise à zéro."""
import gzip
import os
import subprocess
import time

from . import db
from . import platform as P

SAFETY = "/srv/backups/avant-import"


def info(slug):
    n = P.db_name(slug)
    rc, out = P._psql(f"SELECT pg_database_size('{n}');")
    if rc:
        return None
    size = int(out.strip() or 0)
    q = ("SELECT schemaname || '.' || relname, n_live_tup, pg_total_relation_size(relid) "
         "FROM pg_stat_user_tables ORDER BY pg_total_relation_size(relid) DESC LIMIT 12;")
    p = subprocess.run(["docker", "exec", "-i", P.PG, "psql", "-U", "platform", "-d", n, "-qtA", "-F", "\t"],
                       input=q, capture_output=True, text=True, timeout=30)
    tables = []
    for line in p.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 3:
            tables.append({"name": parts[0].removeprefix("public."), "rows": int(parts[1]), "size": int(parts[2])})
    rc, cnt = P.run(["docker", "exec", P.PG, "psql", "-U", "platform", "-d", n, "-qtA", "-c",
                     "SELECT count(*) FROM pg_stat_user_tables"], timeout=30)
    return {"name": n, "size": size, "tables": tables, "count": int(cnt.strip() or 0) if rc == 0 else len(tables)}


def export_stream(slug):
    """Générateur : dump SQL compressé (gzip) en flux, sans fichier temporaire."""
    n = P.db_name(slug)
    proc = subprocess.Popen(["docker", "exec", P.PG, "pg_dump", "-U", "platform", "--no-owner", "--no-acl", n],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    comp = gzip.compress
    try:
        buf = []
        size = 0
        while True:
            chunk = proc.stdout.read(256 * 1024)
            if not chunk:
                break
            buf.append(chunk)
            size += len(chunk)
            if size >= 4 * 1024 * 1024:
                yield comp(b"".join(buf))   # membres gzip concaténés : format valide, lu par gunzip
                buf, size = [], 0
        if buf:
            yield comp(b"".join(buf))
    finally:
        proc.stdout.close()
        proc.wait(timeout=60)
    P.log("info", slug, "base exportée depuis la console")


def _safety_dump(slug):
    os.makedirs(SAFETY, mode=0o700, exist_ok=True)
    path = f"{SAFETY}/{slug}-{time.strftime('%Y%m%d-%H%M%S')}.sql.gz"
    P.dump_db(slug, path)
    os.chmod(path, 0o600)
    return path


def _recreate(slug):
    """Vide la base : DROP + CREATE, propriétaire = rôle de l'appli."""
    n = P.db_name(slug)
    rc, out = P._psql(f"DROP DATABASE IF EXISTS {n} WITH (FORCE); CREATE DATABASE {n} OWNER {n};")
    if rc:
        raise RuntimeError("recréation de la base impossible : " + P.tail(out))


def _psql_file(n, path, compressed):
    """Joue un fichier SQL (éventuellement gzip) en tant que rôle de l'appli, décompressé au fil de l'eau."""
    proc = subprocess.Popen(["docker", "exec", "-i", P.PG, "psql", "-U", "platform", "-d", n, "-q",
                             "-v", "ON_ERROR_STOP=1", "-c", f"SET ROLE {n}", "-f", "-"],
                            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    opener = gzip.open if compressed else open
    try:
        with opener(path, "rb") as f:
            while chunk := f.read(1024 * 1024):
                proc.stdin.write(chunk)
    except BrokenPipeError:
        pass   # psql s'est arrêté sur une erreur : on lit son message plus bas
    finally:
        try:
            proc.stdin.close()
        except BrokenPipeError:
            pass
    err = proc.stderr.read().decode(errors="replace")
    proc.wait(timeout=3600)
    return proc.returncode, err


def _stop(slug):
    P.run(["docker", "compose", "stop"], cwd=P.app_dir(slug), timeout=120)


def _start(a):
    if a["desired"] != "running":
        return True, "appli arrêtée, non redémarrée"
    P.run(["docker", "compose", "up", "-d", "--no-build"], cwd=P.app_dir(a["slug"]), timeout=300)
    return P.wait_health(a)


def import_file(slug, path, kind):
    """Remplace le contenu de la base par un fichier .sql, .sql.gz ou .dump (pg_dump -Fc)."""
    with P.op_lock:
        a = db.app(slug)
        n = P.db_name(slug)
        db.update_app(slug, state="deploying")
        try:
            safe = _safety_dump(slug)
            _stop(slug)
            _recreate(slug)
            if kind == "dump":
                with open(path, "rb") as f:
                    p = subprocess.run(["docker", "exec", "-i", P.PG, "pg_restore", "-U", "platform", "--no-owner",
                                        "--no-acl", f"--role={n}", "-d", n], stdin=f, capture_output=True, timeout=3600)
                err, code = p.stderr.decode(errors="replace"), p.returncode
            else:
                code, err = _psql_file(n, path, kind == "sqlgz")
            if code:
                raise RuntimeError(P.tail(err, 4) or f"code {code}")
            ok, detail = _start(a)
            db.update_app(slug, state="ok" if ok else "error")
            P.log("ok" if ok else "error", slug, f"base importée ({detail}). Copie d'avant l'import : {safe}")
        except Exception as e:
            P.log("error", slug, f"import de la base en échec : {e}. Restauration de l'état d'avant…")
            try:
                _recreate(slug)
                code, err = _psql_file(n, safe, True)
                if code:
                    raise RuntimeError(P.tail(err, 3))
                P.log("warn", slug, "base remise dans son état d'avant l'import")
            except Exception as e2:
                P.log("error", slug, f"remise en état impossible ({e2}) : copie dans {SAFETY}")
            ok, detail = _start(a)
            db.update_app(slug, state="ok" if ok else "error")
        finally:
            try:
                os.remove(path)
            except OSError:
                pass


def reset(slug):
    with P.op_lock:
        a = db.app(slug)
        db.update_app(slug, state="deploying")
        try:
            safe = _safety_dump(slug)
            _stop(slug)
            _recreate(slug)
            ok, detail = _start(a)
            db.update_app(slug, state="ok" if ok else "error")
            P.log("ok" if ok else "error", slug, f"base remise à zéro ({detail}). Copie d'avant : {safe}")
        except Exception as e:
            ok, detail = _start(a)
            db.update_app(slug, state="ok" if ok else "error")
            P.log("error", slug, f"remise à zéro impossible : {e}")
