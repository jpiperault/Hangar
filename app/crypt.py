"""Chiffrement des archives téléchargées : gpg symétrique (AES-256, clé dérivée du mot de passe des sauvegardes).

Format standard OpenPGP : l'archive s'ouvre sur n'importe quel PC avec `gpg -d archive.tar.gz.gpg > archive.tar.gz`.
gpg vérifie l'intégrité (MDC) : un fichier modifié ou un mauvais mot de passe est refusé.
Chaque appel utilise un dossier gpg jetable : le trousseau de root n'est jamais touché.
"""
import os
import shutil
import subprocess
import tempfile

GPG = "gpg"
COMMON = ["--batch", "--quiet", "--no-tty", "--pinentry-mode", "loopback", "--passphrase-fd", "0"]
ENC = ["--symmetric", "--cipher-algo", "AES256", "--s2k-mode", "3", "--s2k-digest-algo", "SHA512",
       "--s2k-count", "65011712", "--compress-algo", "none"]
SUFFIX = ".gpg"


def is_encrypted(path):
    """Fichier OpenPGP chiffré par mot de passe (paquet SKESK en tête, ancien ou nouveau format) ?"""
    try:
        with open(path, "rb") as f:
            b = f.read(1)
    except OSError:
        return False
    return bool(b) and b[0] in (0x8C, 0x8D, 0xC3)


def _home():
    return tempfile.mkdtemp(prefix="hangar-gpg-")


def encrypt_stream(path, password, chunk=1024 * 1024):
    """Générateur : le fichier chiffré, morceau par morceau (téléchargement sans fichier intermédiaire)."""
    home = _home()
    p = subprocess.Popen([GPG, "--homedir", home, *COMMON, *ENC, "-o", "-", path], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        p.stdin.write((password + "\n").encode())
        p.stdin.close()
        while data := p.stdout.read(chunk):
            yield data
        if p.wait(timeout=60):
            raise RuntimeError("chiffrement de l'archive impossible")
    finally:
        if p.poll() is None:
            p.kill()
        shutil.rmtree(home, ignore_errors=True)


def encrypt_file(src, dest, password):
    home = _home()
    try:
        r = subprocess.run([GPG, "--homedir", home, *COMMON, *ENC, "--yes", "-o", dest, src],
                           input=(password + "\n").encode(), capture_output=True, timeout=7200)
        if r.returncode:
            raise RuntimeError("chiffrement impossible : " + r.stderr.decode(errors="replace")[-200:])
        os.chmod(dest, 0o600)
    finally:
        shutil.rmtree(home, ignore_errors=True)


def decrypt_file(src, dest, passwords):
    """Déchiffre src vers dest avec le premier mot de passe qui convient. ValueError si aucun ne va."""
    home = _home()
    try:
        for pw in [p for p in passwords if p]:
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.close(fd)
            r = subprocess.run([GPG, "--homedir", home, *COMMON, "--yes", "-o", dest, "-d", src],
                               input=(pw.strip() + "\n").encode(), capture_output=True, timeout=7200)
            if r.returncode == 0:
                return pw
        if os.path.exists(dest):
            os.remove(dest)
        raise ValueError("archive chiffrée : mot de passe incorrect (c'est le mot de passe des sauvegardes du "
                         "serveur qui l'a créée), ou fichier abîmé")
    finally:
        shutil.rmtree(home, ignore_errors=True)
