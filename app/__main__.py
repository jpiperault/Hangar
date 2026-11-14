"""Point d'entrée : `python -m app` lance la console.
`python -m app passwd [compte] [--random]` gère un compte, `users` liste les comptes,
`2fa-reset <compte>` retire la double authentification d'un compte (téléphone et codes de secours perdus), `backup [--manual]` sauvegarde, `archive` crée une archive, `restore <archive>` reprend tout,
`routing` régénère la configuration de Caddy, `sysupdate <composant> [--node <nœud>]` met à jour."""
import getpass
import os
import secrets
import sys


def passwd(args):
    from argon2 import PasswordHasher
    from . import db
    db.init()
    names = [x for x in args if not x.startswith("-")]
    user = names[0] if names else os.environ.get("HANGAR_USER", "admin")
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
    db.x("DELETE FROM sessions WHERE username = ?", (user,))   # sessions ouvertes fermées


def users_cmd(args):
    from . import db
    db.init()
    rows = db.q("SELECT username, role, totp_secret IS NOT NULL AS totp FROM users ORDER BY username")
    if not rows:
        print("Aucun compte. Crée-en un : hangar passwd admin")
    for r in rows:
        print(f"{r['username']:24} {r['role']:8} {'double authentification' if r['totp'] else ''}")


def twofa_reset(args):
    """Secours : retire la double authentification d'un compte (en root sur la console)."""
    from . import db, totp
    from . import platform as P
    db.init()
    names = [x for x in args if not x.startswith("-")]
    if len(names) != 1:
        sys.exit("Usage : hangar 2fa-reset <compte>   (hangar users pour la liste)")
    user = names[0]
    if not db.one("SELECT 1 FROM users WHERE username = ?", (user,)):
        sys.exit(f"Compte inconnu : {user}")
    if not totp.enabled(user):
        print(f"{user} n'a pas de double authentification : rien à faire.")
        return
    totp.disable(user)
    db.x("DELETE FROM sessions WHERE username = ?", (user,))
    P.log("warn", "console", f"double authentification de {user} retirée en ligne de commande (secours)")
    print(f"Double authentification retirée pour {user}. Il se connecte avec son mot de passe seul, puis peut la remettre"
          " (Accès et comptes). Mot de passe oublié aussi : hangar passwd " + user)


def serve():
    import uvicorn
    host, port = os.environ.get("ADMIN_BIND", "127.0.0.1:8443").rsplit(":", 1)   # réglé par install.sh
    uvicorn.run("app.main:app", host=host, port=int(port), workers=1, log_level="warning",
                ssl_certfile="/srv/platform/tls/hangar.crt", ssl_keyfile="/srv/platform/tls/hangar.key",
                proxy_headers=False, server_header=False)


def backup_cmd(args):
    from . import backup, db
    db.init()
    if "--verify" in args:
        sys.exit(backup.run_verify())
    sys.exit(backup.run_backup("manuelle" if "--manual" in args else "planifiée"))


def archive_cmd(args):
    from . import backup, db
    db.init()
    sys.exit(backup.create_archive())


def routing(args):
    from . import db, platform as P
    db.init()
    P.apply_routing()
    print("Caddyfile régénéré et Caddy rechargé.")


def restore(args):
    """hangar restore <archive.tar.gz> [--apps a,b] [--no-settings] : reprise complète en ligne de commande."""
    import shutil
    from . import backup, db
    db.init()
    files, only, i = [], None, 0
    while i < len(args):
        if args[i] == "--apps" and i + 1 < len(args):
            only = {x.strip() for x in args[i + 1].split(",") if x.strip()}
            i += 2
            continue
        if not args[i].startswith("--"):
            files.append(args[i])
        i += 1
    if len(files) != 1 or not os.path.exists(files[0]):
        sys.exit("Usage : hangar restore <archive.tar.gz> [--apps appli1,appli2] [--no-settings]")
    src = os.path.abspath(files[0])
    from . import crypt
    if crypt.is_encrypted(src):   # archive téléchargée depuis la console : chiffrée par gpg
        pws = [os.environ.get("HANGAR_ARCHIVE_PASSWORD", ""), backup.password() or ""]
        if not any(pws) and sys.stdin.isatty():
            pws.append(getpass.getpass("Mot de passe de l'archive (mot de passe des sauvegardes du serveur d'origine) : "))
        os.makedirs(backup.ARCHIVES, mode=0o700, exist_ok=True)
        clear = f"{backup.ARCHIVES}/{backup.save_upload_name()}"
        try:
            crypt.decrypt_file(src, clear, pws)
        except ValueError as e:
            if not sys.stdin.isatty():
                sys.exit(f"{e}. Indique-le avec HANGAR_ARCHIVE_PASSWORD=… avant la commande.")
            try:
                crypt.decrypt_file(src, clear, [getpass.getpass("Mot de passe de l'archive : ")])
            except ValueError as e2:
                sys.exit(str(e2))
        print("Archive déchiffrée.")
        src = clear
    man = backup.read_manifest(src)
    os.makedirs(backup.ARCHIVES, mode=0o700, exist_ok=True)
    if os.path.dirname(src) == backup.ARCHIVES and backup.NAME_RE.match(os.path.basename(src)):
        name = os.path.basename(src)
    else:
        name = backup.save_upload_name()
        shutil.copy2(src, f"{backup.ARCHIVES}/{name}")
        os.chmod(f"{backup.ARCHIVES}/{name}", 0o600)
    if "--no-settings" not in args and man.get("settings"):
        backup.apply_settings(man["settings"])
        print("Domaines repris : " + (", ".join(f"{d['name']} ({d['mode']})" for d in man["settings"]["domains"]) or "aucun"))
    choices = {a["slug"]: [p for p in ("data", "db") if a.get(f"has_{p}")]
               for a in man["apps"] if only is None or a["slug"] in only}
    print(f"Restauration de {len(choices)} appli(s) : {', '.join(choices) or 'aucune'}")
    backup.restore_archive(name, choices)
    bad = 0
    for slug in choices:
        a = db.app(slug)
        state = a["state"] if a else "absente"
        bad += state != "ok"
        print(f"  {slug:24} {state}")
    sys.exit(1 if bad else 0)


def access_revert(args):
    """Appelé par le minuteur hangar-acces-retour : remet l'ancien accès à la console s'il n'a pas été confirmé."""
    from . import access, db
    db.init()
    sys.exit(0 if access.revert() else 1)


def sysupdate(args):
    from . import db, system
    db.init()
    node = args[args.index("--node") + 1] if "--node" in args and args.index("--node") + 1 < len(args) else None
    if not args or args[0] not in system.COMPONENTS:
        sys.exit("Usage : hangar sysupdate " + "|".join(system.COMPONENTS) + " [--node <nœud>]")
    sys.exit(system.run_update(args[0], node))


def segment_cmd(args):
    """Cloisonnement des applis sur une installation existante : chaque appli sur son propre réseau."""
    from . import db, segment
    db.init()
    sys.exit(0 if segment.migrate() else 1)


if __name__ == "__main__":
    cmd = sys.argv[1:2]
    if cmd == ["passwd"]:
        passwd(sys.argv[2:])
    elif cmd == ["users"]:
        users_cmd(sys.argv[2:])
    elif cmd == ["2fa-reset"]:
        twofa_reset(sys.argv[2:])
    elif cmd == ["backup"]:
        backup_cmd(sys.argv[2:])
    elif cmd == ["routing"]:
        routing(sys.argv[2:])
    elif cmd == ["restore"]:
        restore(sys.argv[2:])
    elif cmd == ["archive"]:
        archive_cmd(sys.argv[2:])
    elif cmd == ["access-revert"]:
        access_revert(sys.argv[2:])
    elif cmd == ["sysupdate"]:
        sysupdate(sys.argv[2:])
    elif cmd == ["segment"]:
        segment_cmd(sys.argv[2:])
    else:
        serve()
