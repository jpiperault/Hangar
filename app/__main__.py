"""Point d'entrée : `python -m app` lance la console, `python -m app passwd [--random]` gère le compte."""
import getpass
import os
import secrets
import sys


def passwd(args):
    from argon2 import PasswordHasher
    from . import db
    db.init()
    user = os.environ.get("HANGAR_USER", "admin")
    if "--random" in args:
        pw = secrets.token_urlsafe(15)
        path = "/root/hangar-mot-de-passe.txt"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(f"Console Hangar\nidentifiant : {user}\nmot de passe : {pw}\n")
        print(f"Mot de passe généré pour {user}, enregistré dans {path}")
    else:
        pw = getpass.getpass(f"Nouveau mot de passe pour {user} : ")
        if len(pw) < 10:
            sys.exit("10 caractères minimum.")
        if pw != getpass.getpass("Confirme : "):
            sys.exit("Les deux saisies diffèrent.")
        print("Mot de passe enregistré.")
    db.x("INSERT INTO users(username, hash) VALUES(?, ?) ON CONFLICT(username) DO UPDATE SET hash = excluded.hash",
         (user, PasswordHasher().hash(pw)))


def serve():
    import uvicorn
    host, port = os.environ.get("ADMIN_BIND", "192.168.91.93:8443").rsplit(":", 1)
    uvicorn.run("app.main:app", host=host, port=int(port), workers=1, log_level="warning",
                ssl_certfile="/srv/platform/tls/hangar.crt", ssl_keyfile="/srv/platform/tls/hangar.key",
                proxy_headers=False, server_header=False)


if __name__ == "__main__":
    if sys.argv[1:2] == ["passwd"]:
        passwd(sys.argv[2:])
    else:
        serve()
