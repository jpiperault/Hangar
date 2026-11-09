"""Règles des champs d'une appli : formulaire et manifeste d'archive (failles d'injection de l'audit)."""
import pytest

from app import platform as P

INJECTIONS = ["x; rm -rf /", "a$(id)", "../etc", "a b", "-rf", "A", "a" * 33, "", "a\nb", "jeu-", "é"]


@pytest.mark.parametrize("slug", ["a", "mon-jeu", "jeu2", "a" * 32])
def test_slug_ok(slug):
    assert P.SLUG.match(slug)


@pytest.mark.parametrize("slug", INJECTIONS)
def test_slug_refuse(slug):
    assert not P.SLUG.match(slug)


@pytest.mark.parametrize("slug", INJECTIONS + [None, 3, ["a"]])
def test_app_dir_refuse_tout_identifiant_hors_regle(slug):
    with pytest.raises(ValueError):
        P.app_dir(slug)


def test_app_dir_ok():
    assert P.app_dir("mon-jeu").endswith("/mon-jeu")


def test_entree_valide(app_row):
    assert P.check_app_entry(app_row) == []


@pytest.mark.parametrize("champ,valeur", [
    ("slug", "x; reboot"), ("image", "ghcr.io/x/y;id"), ("image", "$(id)"), ("version", "1.0;id"),
    ("version", "../../x"), ("port", 0), ("port", 70000), ("port", "8080"), ("port", True), ("mem_mb", 8),
    ("health_path", "health"), ("health_path", "/a b"), ("pkg", "fr..x"), ("db_password", "court"),
    ("db_password", "pa'ss$word12"), ("desired", "boom"), ("node", "../x"), ("name", "a\x00b"), ("name", ""),
    ("env", "PAS UNE LIGNE"), ("source", "ftp"), ("data_user", "root;id"),
])
def test_entree_refusee(app_row, champ, valeur):
    app_row[champ] = valeur
    assert P.check_app_entry(app_row), f"{champ}={valeur!r} aurait dû être refusé"


def test_source_git(app_row):
    app_row.update(source="git", image="https://github.com/exemple/jeu.git")
    assert P.check_app_entry(app_row) == []
    app_row["image"] = "https://github.com/x/y.git;id"
    assert P.check_app_entry(app_row)


def test_parse_env():
    env, err = P.parse_env("# commentaire\nA=1\n\nB=deux=trois\n")
    assert env == {"A": "1", "B": "deux=trois"} and err == []
    _, err = P.parse_env("sans egal")
    assert err


def test_masquage_des_secrets():
    out = P.mask_env("JWT_SECRET=abc\nAPI_KEY=x\nDB_PASSWORD=y\nMODE=prod")
    assert "abc" not in out and "=x" not in out and "=y" not in out and "MODE=prod" in out
