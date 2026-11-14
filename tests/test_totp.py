"""Double authentification : codes RFC 6238, rejeu refusé, codes de secours, connexion en deux temps."""
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient

from app import db, totp

SAME = {"sec-fetch-site": "same-origin"}


def test_rfc6238():
    # vecteur de la RFC 6238 (SHA-1, secret « 12345678901234567890 », t = 59 s → 94287082, 8 chiffres)
    import base64
    sec = base64.b32encode(b"12345678901234567890").decode()
    assert totp.code_at(sec, 59 // 30) == "287082"          # les 6 derniers chiffres
    assert totp.check(sec, "287082", now=59) == 1
    assert totp.check(sec, "287082", now=59, last_step=1) is None     # déjà utilisé
    assert totp.check(sec, "287082", now=59 + 90) is None             # trop tard


@pytest.fixture
def compte():
    from app import main
    main._fails.clear()
    db.x("DELETE FROM users WHERE username = 'deuxf'")
    db.x("INSERT INTO users(username, hash, role) VALUES('deuxf', ?, 'lecture')", (PasswordHasher().hash("mot-de-passe-2fa"),))
    c = TestClient(main.app, base_url="https://hangar.test", client=("127.0.0.1", 50020))
    yield c
    db.x("DELETE FROM sessions WHERE username = 'deuxf'")
    db.x("DELETE FROM users WHERE username = 'deuxf'")


def _login(c):
    return c.post("/login", data={"username": "deuxf", "password": "mot-de-passe-2fa"}, headers=SAME, follow_redirects=False)


def test_parcours(compte, monkeypatch):
    c = compte
    assert _login(c).headers["location"] == "/"
    # mise en place par le compte lui-même (même en lecture seule)
    assert c.post("/users/deuxf/2fa/start", headers=SAME, follow_redirects=False).status_code == 303
    page = c.get("/settings").text
    assert "Scanne ce QR code" in page and "<svg" in page
    import re
    sec = re.search(r'la clé à la main : <code class="mono">([A-Z2-7 ]+)</code>', page).group(1).replace(" ", "")
    assert c.post("/users/deuxf/2fa/confirm", data={"code": "000000"}, headers=SAME).url.path == "/settings"
    assert not totp.enabled("deuxf")
    r = c.post("/users/deuxf/2fa/confirm", data={"code": totp.code_at(sec, int(__import__("time").time() // 30))}, headers=SAME)
    assert totp.enabled("deuxf")
    codes = re.findall(r"\b[0-9a-f]{4}-[0-9a-f]{4}\b", r.text)
    assert len(codes) == 8 and not re.findall(r"\b[0-9a-f]{4}-[0-9a-f]{4}\b", c.get("/settings").text)   # une seule fois
    # nouvelle connexion : mot de passe, puis code
    c.post("/logout", headers=SAME)
    r = _login(c)
    assert r.headers["location"] == "/login/code"
    assert c.post("/login/code", data={"code": "123456"}, headers=SAME, follow_redirects=False).headers["location"] == "/login/code"
    db.x("UPDATE users SET totp_last = NULL WHERE username = 'deuxf'")
    r = c.post("/login/code", data={"code": totp.code_at(sec, int(__import__("time").time() // 30))}, headers=SAME, follow_redirects=False)
    assert r.headers["location"] == "/" and c.get("/", follow_redirects=False).status_code == 200
    assert totp.verify_login("deuxf", codes[0] if codes else "x") in ("secours", None)
    if codes:
        assert totp.verify_login("deuxf", codes[0]) is None          # code de secours : une seule fois
        assert totp.recovery_left("deuxf") == 7
    # mot de passe seul, puis une autre page : pas connecté, et l'étape du code est perdue
    c.post("/logout", headers=SAME)
    _login(c)
    assert c.get("/", follow_redirects=False).headers["location"] == "/login"
    assert c.get("/login/code", follow_redirects=False).headers["location"] == "/login"


def test_retrait_par_un_admin():
    db.x("INSERT OR REPLACE INTO users(username, hash, role) VALUES('perdu', 'x', 'admin')")
    totp.enable("perdu", totp.new_secret(), totp.new_recovery()[1])
    assert totp.enabled("perdu")
    totp.disable("perdu")
    assert not totp.enabled("perdu")
    db.x("DELETE FROM users WHERE username = 'perdu'")


def test_secours_en_ligne_de_commande(capsys):
    from app import __main__ as cli
    db.x("INSERT OR REPLACE INTO users(username, hash, role) VALUES('perdu2', 'x', 'admin')")
    totp.enable("perdu2", totp.new_secret(), totp.new_recovery()[1])
    cli.users_cmd([])
    assert "perdu2" in capsys.readouterr().out
    cli.twofa_reset(["perdu2"])
    assert not totp.enabled("perdu2") and "retirée" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        cli.twofa_reset(["inconnu-xyz"])
    db.x("DELETE FROM users WHERE username = 'perdu2'")
