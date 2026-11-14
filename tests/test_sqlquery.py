"""Requêtes SQL en lecture seule : ce qui est accepté, ce qui est refusé."""
import pytest

from app import sqlquery


@pytest.mark.parametrize("q", ["SELECT 1", "  with t as (select 1) select * from t;", "EXPLAIN SELECT * FROM users",
                               "SELECT 'a;b', \"x;y\" FROM t -- commentaire ; ici", "show tables", "DESC users"])
def test_accepte(q):
    assert sqlquery.check(q)


@pytest.mark.parametrize("q", ["", "DELETE FROM users", "SELECT 1; DROP TABLE users", "UPDATE t SET a = 1",
                               "select 1;; select 2", "/* x */ insert into t values (1)", "COPY t TO '/tmp/x'"])
def test_refuse(q):
    with pytest.raises(ValueError):
        sqlquery.check(q)
