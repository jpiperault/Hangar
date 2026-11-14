"""Double authentification par code à usage unique (TOTP, RFC 6238), choisie par chaque compte.

- Mise en place : un secret aléatoire (QR code à scanner avec Aegis, Google Authenticator, 1Password…), confirmé par un
  premier code ; 8 codes de secours à usage unique sont donnés une fois (gardés hachés).
- Connexion : après le mot de passe, le code à 6 chiffres (fenêtre de ±30 s), ou un code de secours. Un code déjà
  utilisé est refusé (pas de rejeu dans sa fenêtre).
- Un administrateur peut retirer la double authentification d'un autre compte (téléphone perdu).
Colonnes users.totp_secret, users.totp_recovery (JSON des empreintes), users.totp_last (dernier pas accepté).
"""
import base64
import hashlib
import hmac
import io
import json
import secrets
import struct
import time
import urllib.parse

from . import db

STEP, DIGITS, WINDOW = 30, 6, 1
ISSUER = "Hangar"


def new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret):
    return base64.b32decode(secret + "=" * (-len(secret) % 8))


def code_at(secret, step):
    h = hmac.new(_key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    n = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** DIGITS
    return str(n).zfill(DIGITS)


def check(secret, code, now=None, last_step=None):
    """Pas accepté (entier) si `code` est bon dans la fenêtre et pas déjà utilisé, sinon None."""
    code = "".join(c for c in (code or "") if c.isdigit())
    if len(code) != DIGITS or not secret:
        return None
    cur = int((now or time.time()) // STEP)
    for st in range(cur - WINDOW, cur + WINDOW + 1):
        if last_step is not None and st <= last_step:
            continue
        if hmac.compare_digest(code_at(secret, st), code):
            return st
    return None


def uri(secret, username, home=""):
    label = urllib.parse.quote(f"{ISSUER} ({home}):{username}" if home else f"{ISSUER}:{username}")
    return f"otpauth://totp/{label}?" + urllib.parse.urlencode(
        {"secret": secret, "issuer": ISSUER, "digits": DIGITS, "period": STEP})


def qr_svg(text):
    """QR code en SVG (texte), ou None si la bibliothèque segno manque (la clé reste affichée en clair)."""
    try:
        import segno
    except ImportError:
        return None
    buf = io.BytesIO()
    segno.make(text, error="m").save(buf, kind="svg", scale=5, border=2, dark="#000", light="#fff", xmldecl=False,
                                     svgns=True)
    return buf.getvalue().decode()


def _h(code):
    return hashlib.sha256(code.replace("-", "").lower().encode()).hexdigest()


def new_recovery():
    """8 codes de secours lisibles (xxxx-xxxx), et leurs empreintes à garder."""
    codes = [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(8)]
    return codes, [_h(c) for c in codes]


def user(username):
    return db.one("SELECT username, totp_secret, totp_recovery, totp_last FROM users WHERE username = ?", (username,))


def enabled(username):
    u = user(username)
    return bool(u and u["totp_secret"])


def enable(username, secret, hashes):
    db.x("UPDATE users SET totp_secret = ?, totp_recovery = ?, totp_last = NULL WHERE username = ?",
         (secret, json.dumps(hashes), username))


def disable(username):
    db.x("UPDATE users SET totp_secret = NULL, totp_recovery = NULL, totp_last = NULL WHERE username = ?", (username,))


def recovery_left(username):
    u = user(username)
    return len(json.loads(u["totp_recovery"] or "[]")) if u else 0


def verify_login(username, code, now=None):
    """Vérifie un code (ou un code de secours, consommé). Retourne "totp", "secours" ou None."""
    u = user(username)
    if not u or not u["totp_secret"]:
        return None
    st = check(u["totp_secret"], code, now, u["totp_last"])
    if st is not None:
        db.x("UPDATE users SET totp_last = ? WHERE username = ?", (st, username))
        return "totp"
    hashes = json.loads(u["totp_recovery"] or "[]")
    h = _h((code or "").strip())
    if h in hashes:
        hashes.remove(h)
        db.x("UPDATE users SET totp_recovery = ? WHERE username = ?", (json.dumps(hashes), username))
        return "secours"
    return None
