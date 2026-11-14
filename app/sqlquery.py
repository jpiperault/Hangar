"""Requêtes SQL en lecture seule sur la base d'une appli (PostgreSQL, ou MySQL/MariaDB du service), depuis la console.

Trois protections :
- une seule instruction, qui commence par SELECT, WITH, SHOW, EXPLAIN, DESCRIBE/DESC, TABLE ou VALUES ;
- exécutée avec l'utilisateur de l'appli (jamais l'administrateur de la base), dans une transaction en lecture seule
  (PostgreSQL : default_transaction_read_only + BEGIN READ ONLY ; MySQL : SESSION TRANSACTION READ ONLY) ;
- 10 s au plus, 500 lignes affichées au plus.
Chaque requête est notée au journal de l'appli (texte tronqué).
"""
import csv
import io
import re
import shlex

from . import db
from . import platform as P

MAX_ROWS = 500
TIMEOUT_S = 10
FIRST = re.compile(r"^\s*(select|with|show|explain|describe|desc|table|values)\b", re.I)


def _strip_strings(q):
    """La requête sans ses chaînes ni commentaires (pour chercher un « ; » qui séparerait deux instructions)."""
    q = re.sub(r"--[^\n]*|/\*.*?\*/", " ", q, flags=re.S)
    return re.sub(r"'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\"|`[^`]*`", "''", q)


def check(q):
    q = (q or "").strip().rstrip(";").strip()
    if not q:
        raise ValueError("requête vide")
    if len(q) > 20000:
        raise ValueError("requête trop longue")
    if ";" in _strip_strings(q):
        raise ValueError("une seule instruction à la fois")
    if not FIRST.match(_strip_strings(q)):
        raise ValueError("lecture seulement : SELECT, WITH, SHOW, EXPLAIN, DESCRIBE, TABLE ou VALUES")
    return q


def engines(slug):
    from . import services
    a = db.app(slug)
    out = []
    if a and a["db"]:
        out.append("postgres")
    if services.mysql(slug):
        out.append("mysql")
    return out


def _parse_csv(text, delim=","):
    rows = list(csv.reader(io.StringIO(text), delimiter=delim))
    return (rows[0] if rows else []), rows[1:]


def run(slug, engine, q):
    """(colonnes, lignes, tronqué ?) ; ValueError si refusée, RuntimeError si la base répond une erreur."""
    q = check(q)
    a = db.app(slug)
    if engine not in engines(slug):
        raise ValueError("pas de base de ce type pour cette appli")
    if engine == "postgres":
        node, pg = P.pg_where(slug)
        user = P.db_name(slug)
        sql = (f"SET statement_timeout = {TIMEOUT_S * 1000};\nBEGIN READ ONLY;\n{q};\nROLLBACK;\n")
        rc, out = P.dk(node, "exec", "-i", "-e", f"PGPASSWORD={a['db_password']}",
                       "-e", "PGOPTIONS=-c default_transaction_read_only=on", pg,
                       "psql", "-h", "127.0.0.1", "-U", user, "-d", user, "-X", "-q", "--csv", "-v", "ON_ERROR_STOP=1",
                       input=sql, timeout=TIMEOUT_S + 20)
        if rc:
            raise RuntimeError(P.tail(out, 3))
        notes = [l for l in out.splitlines() if re.match(r"^(WARNING|NOTICE|INFO|DETAIL|HINT):", l)]
        cols, rows = _parse_csv("\n".join(l for l in out.splitlines() if l not in notes))
    else:
        from . import services
        m = services.mysql(slug)
        tool = "mariadb" if m["engine"] == "mariadb" else "mysql"
        limit = (f"SET SESSION max_statement_time = {TIMEOUT_S};" if m["engine"] == "mariadb"
                 else f"SET SESSION max_execution_time = {TIMEOUT_S * 1000};")
        sql = f"SET SESSION TRANSACTION READ ONLY; {limit} {q};"
        cmd = f'MYSQL_PWD="$MYSQL_PASSWORD" {tool} -uapp -h127.0.0.1 app --batch -e {shlex.quote(sql)}'
        rc, out = P.dk(a["node"], "exec", f"app-{slug}-mysql-1", "sh", "-c", cmd, timeout=TIMEOUT_S + 20)
        if rc:
            raise RuntimeError(P.tail(out, 3))
        cols, rows = _parse_csv(out, "\t")
    cut = len(rows) > MAX_ROWS
    return cols, rows[:MAX_ROWS], cut
