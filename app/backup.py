"""Sauvegardes : dumps PostgreSQL locaux, restic chiffré vers une ou plusieurs destinations, archives manuelles.

- Dossier de travail : /srv/platform/backup (700) : restic.pass (commun), rclone.conf (Drive), nas.rclone.conf (NAS).
- Destinations : Google Drive (rclone:hangar-gdrive:Hangar-sauvegardes, droit drive.file) et un NAS en SMB ou SFTP
  (rclone:hangar-nas:<chemin>). Même mot de passe restic pour toutes.
- Contenu : dumps par appli (/srv/backups/staging/db), /srv/apps (compose + data/), /srv/platform.
- Archives manuelles (/srv/backups/archives) : .tar.gz téléchargeable, restaurable ici ou sur un autre serveur.
"""
import base64
import datetime
import fcntl
import json
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import alerts, db
from . import domains as D
from . import platform as P

BK = "/srv/platform/backup"
RCLONE_CONF = f"{BK}/rclone.conf"
PASS_FILE = f"{BK}/restic.pass"
REMOTE = "hangar-gdrive"
FOLDER = "Hangar-sauvegardes"
REPO = f"rclone:{REMOTE}:{FOLDER}"
NAS_CONF = f"{BK}/nas.rclone.conf"
NAS_REMOTE = "hangar-nas"
ARCHIVES = "/srv/backups/archives"
STAGING = "/srv/backups/staging"
LOCAL_PG = "/srv/backups/postgres"
LOCK = "/run/hangar-backup.lock"
SAFETY = "/srv/backups/avant-restauration"


# ---------------------------------------------------------------- état

def drive_configured():
    return os.path.exists(RCLONE_CONF) and os.path.exists(PASS_FILE)


def nas_info():
    try:
        return json.loads(db.settings().get("backup_nas") or "null")
    except ValueError:
        return None


def dests():
    """Destinations configurées : [{id, name, conf, repo}]."""
    out = []
    if drive_configured():
        out.append({"id": "gdrive", "name": "Google Drive", "conf": RCLONE_CONF, "repo": REPO})
    n = nas_info()
    if n and os.path.exists(NAS_CONF) and os.path.exists(PASS_FILE):
        out.append({"id": "nas", "name": f"NAS ({n['host']})", "conf": NAS_CONF,
                    "repo": f"rclone:{NAS_REMOTE}:{_nas_path(n)}"})
    return out


def dest(dest_id):
    return next((d for d in dests() if d["id"] == dest_id), None)


def configured():
    return bool(dests())


def password():
    try:
        return open(PASS_FILE).read().strip()
    except OSError:
        return None


def _ensure_password():
    os.makedirs(BK, mode=0o700, exist_ok=True)
    os.chmod(BK, 0o700)
    if not os.path.exists(PASS_FILE):
        # lisible et facile à recopier : 6 groupes de 5 caractères sans ambiguïté
        alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
        raw = "".join(alphabet[b % len(alphabet)] for b in os.urandom(30))
        P.write_private(PASS_FILE, "-".join(raw[i:i + 5] for i in range(0, 30, 5)) + "\n")


def set_password(pw):
    """Reprise sur un nouveau serveur : utiliser le mot de passe des sauvegardes existantes.
    Seulement tant qu'aucune destination n'est connectée (sinon on casserait l'accès aux dépôts actuels)."""
    pw = (pw or "").strip()
    if dests():
        raise ValueError("Déconnecte d'abord Drive et le NAS : le mot de passe ne peut changer que sans destination.")
    if len(pw) < 8 or any(c in pw for c in "\r\n"):
        raise ValueError("Mot de passe invalide.")
    os.makedirs(BK, mode=0o700, exist_ok=True)
    P.write_private(PASS_FILE, pw + "\n")
    P.log("info", "sauvegarde", "mot de passe des sauvegardes remplacé (reprise d'un serveur)")


def _check_repo(d, where):
    """Dépôt présent : vérifie qu'il s'ouvre avec notre mot de passe. Absent : le crée."""
    rc, _, err = restic("cat", "config", timeout=120, d=d)
    if rc == 0:
        P.log("ok", "sauvegarde", f"{where} : dépôt existant retrouvé")
        return
    if re.search(r"wrong password|no key found", err, re.I):
        raise RuntimeError(f"{where} contient déjà des sauvegardes chiffrées avec un autre mot de passe. Pour les "
                           "reprendre, saisis ce mot de passe dans « Mot de passe des sauvegardes » puis reconnecte.")
    rc, _, err = restic("init", timeout=300, d=d)
    if rc:
        raise RuntimeError(f"Initialisation du dépôt chiffré impossible ({where}) : " + P.tail(err, 3))
    P.log("ok", "sauvegarde", f"{where} : dépôt chiffré créé")


def _env(d=None):
    d = d or {"repo": REPO, "conf": RCLONE_CONF}
    return {**os.environ, "RESTIC_REPOSITORY": d["repo"], "RESTIC_PASSWORD_FILE": PASS_FILE,
            "RCLONE_CONFIG": d["conf"], "RESTIC_CACHE_DIR": "/var/cache/restic",
            "RESTIC_PROGRESS_FPS": "0.016"}


def restic(*args, timeout=3600, input=None, d=None):
    """`d` : destination (dests()) ; par défaut Google Drive."""
    try:
        p = subprocess.run(["restic", "-o", "rclone.program=rclone", *args], capture_output=True, text=True,
                           timeout=timeout, env=_env(d), input=input)
    except subprocess.TimeoutExpired:
        return 124, "", f"délai dépassé ({timeout} s)"
    return p.returncode, p.stdout, p.stderr


def last_runs(n=10):
    return db.q("SELECT * FROM backups ORDER BY id DESC LIMIT ?", (n,))


def last_ok(dest_id=None):
    if dest_id:
        return db.one("SELECT * FROM backups WHERE ok = 1 AND dest = ? ORDER BY id DESC LIMIT 1", (dest_id,))
    return db.one("SELECT * FROM backups WHERE ok = 1 AND remote = 1 ORDER BY id DESC LIMIT 1")


def running():
    try:
        fd = os.open(LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:
        return False
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    except BlockingIOError:
        return True
    finally:
        os.close(fd)


# ---------------------------------------------------------------- connexion Google Drive

_auth = {"proc": None, "out": [], "state": None, "started": 0}
_auth_lock = threading.Lock()


def _reader(proc, sink):
    for line in proc.stdout:
        sink.append(line)


def auth_start(client_id="", client_secret=""):
    """Lance `rclone authorize` (écoute sur 127.0.0.1:53682 du serveur) et renvoie l'URL Google.
    Avec un identifiant OAuth personnel : quota Google réservé (celui de rclone est partagé et souvent saturé)."""
    with _auth_lock:
        auth_cancel()
        cfg = {"scope": "drive.file"}
        if client_id:
            cfg.update(client_id=client_id, client_secret=client_secret)
        _auth["client"] = (client_id, client_secret)
        opts = base64.urlsafe_b64encode(json.dumps(cfg).encode()).decode().rstrip("=")
        proc = subprocess.Popen(["rclone", "authorize", "drive", opts, "--auth-no-open-browser"],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                env={**os.environ, "RCLONE_CONFIG": "/dev/null"})
        out = []
        threading.Thread(target=_reader, args=(proc, out), daemon=True).start()
        _auth.update(proc=proc, out=out, started=time.time())
        local = None
        for _ in range(100):
            m = re.search(r"(http://127\.0\.0\.1:53682/auth\?state=[A-Za-z0-9_-]+)", "".join(out))
            if m:
                local = m.group(1)
                break
            if proc.poll() is not None:
                break
            time.sleep(0.1)
        if not local:
            auth_cancel()
            raise RuntimeError("rclone n'a pas démarré l'autorisation : " + P.tail("".join(out)))
        _auth["state"] = urllib.parse.parse_qs(urllib.parse.urlparse(local).query)["state"][0]

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        try:
            urllib.request.build_opener(NoRedirect).open(local, timeout=10)
            raise RuntimeError("rclone n'a pas renvoyé vers Google.")
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location", "")
        if not loc.startswith("https://accounts.google.com/"):
            auth_cancel()
            raise RuntimeError("Adresse Google inattendue.")
        return loc


def auth_cancel():
    p = _auth.get("proc")
    if p and p.poll() is None:
        p.kill()
    _auth.update(proc=None, out=[], state=None)


def auth_pending():
    p = _auth.get("proc")
    return bool(p and p.poll() is None and time.time() - _auth["started"] < 900)


def _parse_token(out):
    """Jeton OAuth renvoyé par `rclone authorize` : JSON en clair (anciennes versions)
    ou blob base64 de {"token": "<json>"} (rclone 1.5x/1.60)."""
    m = re.search(r"--->\s*(.*?)\s*<---", out, re.S)
    if not m:
        return None
    blob = m.group(1).strip()
    try:
        if blob.startswith("{"):
            data = json.loads(blob)
        else:
            raw = re.sub(r"\s+", "", blob)
            data = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    except (ValueError, json.JSONDecodeError):
        return None
    tok = data.get("token", data) if isinstance(data, dict) else None
    if isinstance(tok, str):
        try:
            tok = json.loads(tok)
        except json.JSONDecodeError:
            return None
    return tok if isinstance(tok, dict) and tok.get("refresh_token") else None


def auth_finish(pasted):
    """`pasted` : l'adresse http://127.0.0.1:53682/?state=…&code=… sur laquelle le navigateur a échoué."""
    with _auth_lock:
        if not auth_pending():
            raise ValueError("Autorisation expirée : recommence depuis « Connecter Google Drive ».")
        qs = urllib.parse.parse_qs(urllib.parse.urlparse((pasted or "").strip()).query)
        state, code = (qs.get("state") or [""])[0], (qs.get("code") or [""])[0]
        if not code:
            raise ValueError("Cette adresse ne contient pas de code. Copie toute la barre d'adresse après l'autorisation.")
        if state != _auth["state"]:
            raise ValueError("Cette adresse ne correspond pas à la dernière demande. Recommence la connexion.")
        try:
            urllib.request.urlopen("http://127.0.0.1:53682/?" + urllib.parse.urlencode({"state": state, "code": code}),
                                   timeout=30).read()
        except Exception:
            pass
        proc = _auth["proc"]
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            pass
        out = "".join(_auth["out"])
        client = _auth.get("client") or ("", "")
        auth_cancel()
        token = _parse_token(out)
        if not token:
            # jamais la sortie brute : elle peut contenir un jeton
            errs = [l for l in out.splitlines() if ("ERROR" in l or "Failed" in l) and "--->" not in l]
            raise RuntimeError("Google n'a pas donné de jeton exploitable" + (" : " + P.tail("\n".join(errs), 2) if errs else "."))
    _ensure_password()
    cid, csec = client
    conf = (f"[{REMOTE}]\ntype = drive\nscope = drive.file\n"
            + (f"client_id = {cid}\nclient_secret = {csec}\n" if cid else "")
            + f"token = {json.dumps(token, separators=(',', ':'))}\n")
    P.write_private(RCLONE_CONF, conf)
    rc, out = P.run(["rclone", "--config", RCLONE_CONF, "mkdir", f"{REMOTE}:{FOLDER}"], timeout=180)
    if rc and "rateLimitExceeded" in out or rc == 124:
        os.remove(RCLONE_CONF)
        raise RuntimeError("Google limite les accès faits avec l'identifiant partagé de rclone (quota saturé). "
                           "Crée ton propre identifiant Google (étapes ci-dessous) et reconnecte Drive.")
    if rc:
        raise RuntimeError("Drive refuse la création du dossier : " + P.tail(out, 3))
    try:
        _check_repo(None, f"Google Drive « {FOLDER} »")
    except RuntimeError:
        os.remove(RCLONE_CONF)
        raise


def disconnect():
    """Oublie l'accès à Drive. Le mot de passe est gardé : sans lui, les sauvegardes existantes sont perdues."""
    if os.path.exists(RCLONE_CONF):
        os.remove(RCLONE_CONF)
    P.log("info", "sauvegarde", "Google Drive déconnecté (les sauvegardes restent sur le Drive)")


# ---------------------------------------------------------------- NAS (SMB ou SFTP, via rclone)

def _nas_path(n):
    path = n.get("path", "").strip("/")
    if n["kind"] == "smb":
        return f"{n['share'].strip('/')}/{path}".rstrip("/")
    return ("/" + path) if n.get("abs") else path


def nas_connect(kind, host, port, user, password, share, path):
    """Teste l'accès, crée le dossier et le dépôt chiffré. Lève ValueError/RuntimeError avec un message clair."""
    if kind not in ("smb", "sftp"):
        raise ValueError("Type de NAS inconnu.")
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host or ""):
        raise ValueError("Adresse du NAS invalide (nom ou IP, par exemple 192.168.91.20).")
    port = int(port or (445 if kind == "smb" else 22))
    if not 1 <= port <= 65535:
        raise ValueError("Port invalide.")
    if not re.fullmatch(r"[A-Za-z0-9._@\\-]{1,64}", user or ""):
        raise ValueError("Utilisateur invalide.")
    if not password:
        raise ValueError("Indique le mot de passe de cet utilisateur sur le NAS.")
    if kind == "smb" and not re.fullmatch(r"[A-Za-z0-9 ._$-]{1,80}", share or ""):
        raise ValueError("Nom du dossier partagé invalide (par exemple « backup »).")
    path = (path or "Hangar-sauvegardes").strip()
    if not re.fullmatch(r"/?[A-Za-z0-9 ._/-]{1,200}", path) or ".." in path:
        raise ValueError("Chemin invalide.")
    p = subprocess.run(["rclone", "obscure", "-"], input=password, capture_output=True, text=True, timeout=20)
    if p.returncode:
        raise RuntimeError("rclone obscure : " + p.stderr[-200:])
    obscured = p.stdout.strip()
    conf = f"[{NAS_REMOTE}]\ntype = {kind}\nhost = {host}\nuser = {user}\nport = {port}\npass = {obscured}\n"
    if kind == "sftp":
        conf += "shell_type = unix\nmd5sum_command = none\nsha1sum_command = none\n"
    n = {"kind": kind, "host": host, "port": port, "user": user, "share": share or "", "path": path.strip("/"),
         "abs": kind == "sftp" and path.startswith("/")}
    _ensure_password()
    tmp = NAS_CONF + ".test"
    P.write_private(tmp, conf)
    target = f"{NAS_REMOTE}:{_nas_path(n)}"
    try:
        rc, out = P.run(["rclone", "--config", tmp, "--contimeout", "10s", "--timeout", "30s",
                         "--low-level-retries", "1", "--retries", "1", "mkdir", target], timeout=90)
        if rc:
            hint = ""
            if re.search(r"logon failure|STATUS_LOGON|authenticat|permission denied|unable to authenticate", out, re.I):
                hint = " Identifiants refusés par le NAS."
            elif re.search(r"connection refused|no route|i/o timeout|timed out|dial tcp", out, re.I):
                hint = (" NAS injoignable : vérifie l'adresse, le port et que le service "
                        + ("SMB" if kind == "smb" else "SFTP") + " est activé.")
            elif re.search(r"BAD_NETWORK_NAME|share", out, re.I):
                hint = " Dossier partagé introuvable."
            raise RuntimeError(f"Accès au NAS impossible.{hint} Détail : {P.tail(out, 2)}")
        os.replace(tmp, NAS_CONF)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    db.set_setting("backup_nas", n)
    try:
        _check_repo(dest("nas"), f"le NAS {host} ({_nas_path(n)})")
    except RuntimeError:
        nas_disconnect()
        raise


def nas_disconnect():
    if os.path.exists(NAS_CONF):
        os.remove(NAS_CONF)
    db.set_setting("backup_nas", "null")
    P.log("info", "sauvegarde", "NAS déconnecté (les sauvegardes restent sur le NAS)")


def drive_usage():
    rc, out = P.run(["rclone", "--config", RCLONE_CONF, "size", "--json", f"{REMOTE}:{FOLDER}"], timeout=120)
    try:
        return json.loads(out)["bytes"] if rc == 0 else None
    except (ValueError, KeyError):
        return None


# ---------------------------------------------------------------- sauvegarde

def _dump_apps():
    os.makedirs(f"{STAGING}/db", mode=0o700, exist_ok=True)
    keep = set()
    for a in db.apps():
        if not a["db"]:
            continue
        name = P.db_name(a["slug"])
        path = f"{STAGING}/db/{a['slug']}.dump"
        pnode, pg = P.pg_where(a["slug"])
        with open(path + ".tmp", "wb") as f:
            p = subprocess.run(["docker", "exec", pg, "pg_dump", "-U", "platform", "-Fc", name],
                               stdout=f, stderr=subprocess.PIPE, timeout=1800, env=P.denv(pnode))
        if p.returncode:
            os.remove(path + ".tmp")
            raise RuntimeError(f"pg_dump {name} : {p.stderr.decode(errors='replace')[-300:]}")
        os.replace(path + ".tmp", path)
        os.chmod(path, 0o600)
        keep.add(f"{a['slug']}.dump")
    for f in os.listdir(f"{STAGING}/db"):
        if f not in keep:
            os.remove(f"{STAGING}/db/{f}")


MIRROR = f"{STAGING}/nodes"


def data_source(slug, node, root=""):
    """Où trouver le data/ d'une appli dans une arborescence de sauvegarde (root = dossier d'extraction)."""
    local, mirror = f"{root}{P.app_dir(slug)}/data", f"{root}{MIRROR}/{slug}/data"
    if P.is_local(node):
        return local if os.path.isdir(local) else mirror
    return mirror if os.path.isdir(mirror) else local


def _mirror_remote():
    """Recopie (incrémentale) le data/ des applis des nœuds distants sous staging/nodes/<appli>/data, pour qu'il parte
    dans les sauvegardes et les archives. Un nœud injoignable garde sa dernière copie (signalée)."""
    os.makedirs(MIRROR, mode=0o700, exist_ok=True)
    keep, warn = set(), []
    for a in db.apps():
        if P.is_local(a["node"]):
            continue
        keep.add(a["slug"])
        try:
            P.pull_dir(a["node"], f"{P.app_dir(a['slug'])}/data", f"{MIRROR}/{a['slug']}/data")
        except RuntimeError as e:
            warn.append(f"{a['slug']} ({a['node']})")
            P.log("warn", a["slug"], f"data/ du nœud non recopié, dernière copie conservée : {e}")
    for d in os.listdir(MIRROR):
        if d not in keep:
            shutil.rmtree(f"{MIRROR}/{d}", ignore_errors=True)
    return warn


def _copy_registry():
    """Copie cohérente du registre SQLite (API de sauvegarde), même pendant une écriture."""
    import sqlite3
    os.makedirs(STAGING, mode=0o700, exist_ok=True)
    dst = sqlite3.connect(f"{STAGING}/platform.db.copie")
    with dst:
        db._c.backup(dst)
    dst.close()
    os.chmod(f"{STAGING}/platform.db.copie", 0o600)


def _dump_all_local():
    os.makedirs(LOCAL_PG, exist_ok=True)
    f = f"{LOCAL_PG}/all-{time.strftime('%F')}.sql.gz"
    p = subprocess.run(f"docker exec {P.PG} pg_dumpall -U platform | gzip > '{f}.tmp' && mv '{f}.tmp' '{f}'",
                       shell=True, capture_output=True, text=True, timeout=1800)
    if p.returncode:
        raise RuntimeError("pg_dumpall : " + p.stderr[-300:])
    for name in os.listdir(LOCAL_PG):
        path = f"{LOCAL_PG}/{name}"
        if name.startswith("all-") and time.time() - os.path.getmtime(path) > 14 * 86400:
            os.remove(path)


def _send(d, trigger):
    """Sauvegarde restic vers une destination, puis rotation. Retourne (ok, message, added, total, snap)."""
    rc, out, err = restic("backup", "--json", "--tag", "hangar", "--host", "hangar",
                          "--exclude", "*.tmp", "--exclude", f"{BK}",
                          # fichiers bruts de PostgreSQL et registre en cours d'écriture : incohérents
                          # si copiés à chaud ; remplacés par les exports et la copie du registre
                          "--exclude", f"{P.PLATFORM}/postgres", "--exclude", f"{P.PLATFORM}/platform.db*",
                          "--exclude", "/srv/apps/*/pgdata",
                          STAGING, P.APPS_DIR, P.PLATFORM, timeout=6 * 3600, d=d)
    summary = next((json.loads(l) for l in out.splitlines()[::-1] if l.startswith("{") and '"summary"' in l), None)
    if rc not in (0, 3) or not summary:   # 3 : certains fichiers illisibles, instantané quand même créé
        return False, f"{d['name']} : " + P.tail(err or out, 4), None, None, None
    added, total, snap = summary.get("data_added"), summary.get("total_bytes_processed"), summary.get("snapshot_id")
    keep = json.loads(db.settings().get("backup_keep") or "{}")
    args = ["forget", "--tag", "hangar", "--keep-daily", str(keep.get("daily", 7)),
            "--keep-weekly", str(keep.get("weekly", 4)), "--keep-monthly", str(keep.get("monthly", 12))]
    if time.localtime().tm_wday == 6:   # nettoyage des données orphelines le dimanche
        args.append("--prune")
    rc2, _, err2 = restic(*args, timeout=3 * 3600, d=d)
    if rc2:
        P.log("warn", "sauvegarde", f"{d['name']} : rotation des anciennes sauvegardes en échec : " + P.tail(err2, 3))
    warn = " (certains fichiers illisibles ignorés)" if rc == 3 else ""
    return True, f"envoyée sur {d['name']}{warn} : {_h(added)} ajoutés, {_h(total)} au total", added, total, snap


def run_backup(trigger="planifiée"):
    """Appelée par le timer systemd (ou le bouton). Un seul passage à la fois. Une ligne par destination."""
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("Une sauvegarde est déjà en cours.")
        return 1
    t0, failed = time.time(), 0
    try:
        try:
            _dump_all_local()
            _dump_apps()
            _copy_registry()
            stale = _mirror_remote()
        except Exception as e:
            msg = f"préparation impossible (exports des bases, copie des nœuds) : {str(e)[:1200]}"
            db.x("INSERT INTO backups(ts, duration, ok, remote, trigger, msg) VALUES(?, ?, 0, 0, ?, ?)",
                 (t0, time.time() - t0, trigger, msg))
            P.log("error", "sauvegarde", f"sauvegarde en échec : {msg}")
            alerts.send("Sauvegarde en échec", msg, priority=4, tags=["floppy_disk", "warning"])
            return 1
        targets = dests()
        if not targets:
            msg = "sauvegarde locale seulement (aucune destination connectée)"
            db.x("INSERT INTO backups(ts, duration, ok, remote, trigger, msg) VALUES(?, ?, 1, 0, ?, ?)",
                 (t0, time.time() - t0, trigger, msg))
            P.log("ok", "sauvegarde", msg)
            return 0
        for d in targets:
            t1 = time.time()
            try:
                ok, msg, added, total, snap = _send(d, trigger)
                if ok and stale:
                    msg += f" ; data/ non à jour pour {', '.join(stale)} (nœud injoignable)"
            except Exception as e:
                ok, msg, added, total, snap = False, f"{d['name']} : {e}", None, None, None
            db.x("INSERT INTO backups(ts, duration, ok, remote, added, total, snapshot, trigger, msg, dest) "
                 "VALUES(?, ?, ?, 1, ?, ?, ?, ?, ?, ?)",
                 (t1, time.time() - t1, int(ok), added, total, snap, trigger, msg[:1500], d["id"]))
            db.kv_set(f"snapshots_{d['id']}", None)
            if ok:
                P.log("ok", "sauvegarde", "sauvegarde " + msg)
            else:
                failed += 1
                P.log("error", "sauvegarde", f"sauvegarde en échec : {msg}")
                alerts.send(f"Sauvegarde en échec ({d['name']})", msg, priority=4, tags=["floppy_disk", "warning"])
        return 1 if failed else 0
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def start_now():
    P.run(["systemctl", "reset-failed", "hangar-sauvegarde-manuelle"], timeout=10)
    rc, out = P.run(["systemd-run", "--unit=hangar-sauvegarde-manuelle", "--collect", "--quiet", "--nice=10",
                     "--property=EnvironmentFile=/srv/platform/.env", "--working-directory=/opt/hangar",
                     "/opt/hangar/venv/bin/python", "-m", "app", "backup", "--manual"], timeout=30)
    if rc:
        raise RuntimeError(out)


def _h(n):
    if n is None:
        return "?"
    for unit in ("o", "Ko", "Mo", "Go", "To"):
        if n < 1024 or unit == "To":
            return f"{n:.0f} {unit}" if unit == "o" else f"{n:.1f} {unit}".replace(".", ",")
        n /= 1024


human = _h


# ---------------------------------------------------------------- instantanés et restauration

def snapshots(dest_id="gdrive", refresh=False):
    """Instantanés d'une destination, du plus récent au plus ancien (cache 10 min)."""
    key = f"snapshots_{dest_id}"
    cached, ts = db.kv_get(key), db.kv_ts(key)
    if cached is not None and not refresh and ts and time.time() - ts < 600:
        return cached, None
    d = dest(dest_id)
    if not d:
        return [], None
    rc, out, err = restic("snapshots", "--json", "--tag", "hangar", timeout=180, d=d)
    if rc:
        return cached or [], f"liste des sauvegardes de {d['name']} indisponible : " + P.tail(err, 2)
    snaps = []
    for x in json.loads(out or "[]"):
        iso = re.sub(r"\.\d+", "", x["time"])   # restic donne des nanosecondes
        snaps.append({"id": x["short_id"], "ts": datetime.datetime.fromisoformat(iso).timestamp()})
    snaps.sort(key=lambda x: x["ts"], reverse=True)
    db.kv_set(key, snaps)
    return snaps, None


def _pg_restore(slug, dump_path):
    name = P.db_name(slug)
    pnode, pg = P.pg_where(slug)
    with open(dump_path, "rb") as f:
        p = subprocess.run(["docker", "exec", "-i", pg, "pg_restore", "-U", "platform", "--clean", "--if-exists",
                            "--no-owner", "--no-acl", f"--role={name}", "-d", name],
                           stdin=f, capture_output=True, timeout=3600, env=P.denv(pnode))
    if p.returncode:
        errs = [l for l in p.stderr.decode(errors="replace").splitlines() if "error" in l.lower()]
        if errs:
            P.log("warn", slug, "restauration de la base avec avertissements : " + " | ".join(errs[-3:]))


def _apply(a, src_data, src_dump, parts, label):
    """Remplace data/ et/ou la base d'une appli existante. Appelant : tient P.op_lock."""
    slug, node = a["slug"], a["node"]
    d = P.app_dir(slug)
    safe = f"{SAFETY}/{slug}-{time.strftime('%Y%m%d-%H%M%S')}"
    if "data" in parts and not (src_data and os.path.isdir(src_data)):
        raise RuntimeError("cette sauvegarde ne contient pas de dossier data/ pour cette appli")
    if "db" in parts and not (src_dump and os.path.exists(src_dump)):
        raise RuntimeError("cette sauvegarde ne contient pas de base pour cette appli")
    os.makedirs(safe, mode=0o700, exist_ok=True)
    P.dk(node, "compose", "stop", cwd=d, timeout=120)
    try:
        if "db" in parts:
            P.ensure_db(a)
            P.dump_db(slug, f"{safe}/base-avant.sql.gz", node)
            _pg_restore(slug, src_dump)
        if "data" in parts:
            if P.is_local(node):
                if os.path.exists(f"{d}/data"):
                    shutil.move(f"{d}/data", f"{safe}/data")
                shutil.move(src_data, f"{d}/data")
            else:   # état actuel rapatrié en copie de sécurité, puis data/ restauré poussé sur le nœud
                P.pull_dir(node, f"{d}/data", f"{safe}/data")
                P.push_dir(node, src_data, f"{d}/data")
    finally:
        if a["desired"] == "running":
            P.prepare_data(a, a["version"])
            P.dk(node, "compose", "up", "-d", "--no-build", cwd=d, timeout=300)
    ok, detail = P.wait_health(a) if a["desired"] == "running" else (True, "appli arrêtée, non redémarrée")
    db.update_app(slug, state="ok" if ok else "error")
    P.log("ok" if ok else "error", slug, f"restauration terminée depuis {label} ({detail}). "
          f"L'état d'avant est gardé dans {safe}")
    if not ok:
        alerts.send(f"{a['name']} : restauration", f"Restaurée, mais le healthcheck échoue : {detail}",
                    priority=4, tags=["warning"])


def restore_app(slug, dest_id, snap, parts):
    """Restaure data/ et/ou la base d'une appli depuis un instantané d'une destination."""
    with P.op_lock:
        a = db.app(slug)
        d = dest(dest_id)
        if not a or not d:
            return
        tmp = f"/srv/backups/restore-tmp/{slug}-{time.strftime('%Y%m%d-%H%M%S')}"
        db.update_app(slug, state="deploying")
        P.log("info", slug, f"restauration de {', '.join(parts)} depuis {d['name']}, sauvegarde {snap}")
        try:
            inc = []
            if "data" in parts:
                inc += ["--include", f"{P.app_dir(slug)}/data", "--include", f"{MIRROR}/{slug}/data"]
            if "db" in parts:
                inc += ["--include", f"{STAGING}/db/{slug}.dump"]
            rc, out, err = restic("restore", snap, "--target", tmp, *inc, timeout=6 * 3600, d=d)
            if rc:
                raise RuntimeError("restic restore : " + P.tail(err, 3))
            _apply(a, data_source(slug, a["node"], tmp), f"{tmp}{STAGING}/db/{slug}.dump", parts,
                   f"{d['name']} ({snap})")
        except Exception as e:
            db.update_app(slug, state="error")
            P.log("error", slug, f"restauration impossible : {e}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def client_id():
    """Identifiant OAuth personnel enregistré dans rclone.conf ('' = celui, partagé, de rclone)."""
    try:
        m = re.search(r"^client_id = (.+)$", open(RCLONE_CONF).read(), re.M)
        return m.group(1).strip() if m else ""
    except OSError:
        return ""


# ---------------------------------------------------------------- archives manuelles (.tar.gz)
#
# Contenu : manifest.json (réglages + fiche de chaque appli, secrets compris), db/<appli>.dump (pg_dump -Fc),
# apps/<appli>/data/… Format autonome : restaurable ici ou dans un Hangar neuf (les applis absentes sont recréées).

ARCHIVE_KEEP = 10
APP_KEYS = ["name", "pkg", "expose", "sub", "source", "image", "version", "port", "health_path", "mem_mb", "env",
            "db", "db_password", "desired", "data_user"]
NAME_RE = re.compile(r"^hangar-[0-9]{8}-[0-9]{6}(-import)?\.tar\.gz$")


def archives():
    os.makedirs(ARCHIVES, mode=0o700, exist_ok=True)
    out = []
    for f in sorted(os.listdir(ARCHIVES), reverse=True):
        if NAME_RE.match(f):
            st = os.stat(f"{ARCHIVES}/{f}")
            out.append({"name": f, "size": st.st_size, "ts": st.st_mtime, "imported": "-import" in f})
    return out


def archive_path(name):
    if not NAME_RE.match(name or ""):
        return None
    p = f"{ARCHIVES}/{name}"
    return p if os.path.exists(p) else None


def create_archive(trigger="manuelle"):
    """Crée l'archive (unité transitoire `hangar archive`). Partage le verrou des sauvegardes (exports communs)."""
    import tarfile
    import io
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        P.log("warn", "sauvegarde", "archive non créée : une sauvegarde est déjà en cours")
        return 1
    t0 = time.time()
    os.makedirs(ARCHIVES, mode=0o700, exist_ok=True)
    name = f"hangar-{time.strftime('%Y%m%d-%H%M%S')}.tar.gz"
    part = f"{ARCHIVES}/.{name}.part"
    try:
        _dump_apps()
        stale = _mirror_remote()
        apps = db.apps()
        s = db.settings()
        rc, head = P.run(["git", "-C", "/opt/hangar", "log", "-1", "--format=%h"], timeout=10)
        manifest = {"format": 2, "created": time.time(), "hangar": head.strip(),
                    "settings": {"domains": D.export(), "security": db.kv_get("security")},
                    "apps": [{"slug": a["slug"], "node": a["node"], "routes": D.export_routes(a["slug"]),
                              **{k: a[k] for k in APP_KEYS}} for a in apps]}
        fdp = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fdp, "wb") as raw, tarfile.open(fileobj=raw, mode="w:gz", compresslevel=6) as tar:
            data = json.dumps(manifest, ensure_ascii=False, indent=1).encode()
            ti = tarfile.TarInfo("manifest.json")
            ti.size, ti.mtime, ti.mode = len(data), int(time.time()), 0o600
            tar.addfile(ti, io.BytesIO(data))   # en premier : lisible sans parcourir toute l'archive
            for a in apps:
                dump = f"{STAGING}/db/{a['slug']}.dump"
                if a["db"] and os.path.exists(dump):
                    tar.add(dump, arcname=f"db/{a['slug']}.dump")
                ddir = data_source(a["slug"], a["node"])
                if os.path.isdir(ddir):
                    tar.add(ddir, arcname=f"apps/{a['slug']}/data")
        os.replace(part, f"{ARCHIVES}/{name}")
        size = os.path.getsize(f"{ARCHIVES}/{name}")
        for old in [x for x in archives() if not x["imported"]][ARCHIVE_KEEP:]:
            os.remove(f"{ARCHIVES}/{old['name']}")
        msg = f"archive {name} créée : {len(apps)} appli(s), {_h(size)}" + (
            f" ; data/ non à jour pour {', '.join(stale)} (nœud injoignable)" if stale else "")
        db.x("INSERT INTO backups(ts, duration, ok, remote, total, trigger, msg, dest) VALUES(?, ?, 1, 0, ?, ?, ?, 'archive')",
             (t0, time.time() - t0, size, trigger, msg))
        P.log("ok", "sauvegarde", msg)
        return 0
    except Exception as e:
        if os.path.exists(part):
            os.remove(part)
        msg = f"archive impossible : {str(e)[:1000]}"
        db.x("INSERT INTO backups(ts, duration, ok, remote, trigger, msg, dest) VALUES(?, ?, 0, 0, ?, ?, 'archive')",
             (t0, time.time() - t0, trigger, msg))
        P.log("error", "sauvegarde", msg)
        return 1
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def start_archive():
    P.run(["systemctl", "reset-failed", "hangar-archive"], timeout=10)
    rc, out = P.run(["systemd-run", "--unit=hangar-archive", "--collect", "--quiet", "--nice=10",
                     "--property=EnvironmentFile=/srv/platform/.env", "--working-directory=/opt/hangar",
                     "/opt/hangar/venv/bin/python", "-m", "app", "archive"], timeout=30)
    if rc:
        raise RuntimeError(out)


def archive_running():
    return P.run(["systemctl", "is-active", "hangar-archive"], timeout=10)[1].strip() in ("active", "activating")


def read_manifest(path):
    """Lit manifest.json (premier membre) et la liste des contenus par appli, sans tout extraire."""
    import tarfile
    try:
        with tarfile.open(path, "r:gz") as tar:
            manifest, has_db, has_data = None, set(), set()
            for m in tar:
                if m.name == "manifest.json" and m.isfile() and m.size < 20 * 1024 * 1024:
                    manifest = json.load(tar.extractfile(m))
                elif m.name.startswith("db/") and m.name.endswith(".dump"):
                    has_db.add(m.name[3:-5])
                elif m.name.startswith("apps/"):
                    parts = m.name.split("/")
                    if len(parts) >= 3 and parts[2] == "data":
                        has_data.add(parts[1])
    except (tarfile.TarError, OSError, EOFError, json.JSONDecodeError) as e:
        raise ValueError(f"archive illisible : {e}")
    if not manifest or manifest.get("format") not in (1, 2) or not isinstance(manifest.get("apps"), list):
        raise ValueError("ce fichier n'est pas une archive Hangar (manifest.json absent ou inconnu)")
    # archives d'avant le multi-domaine : un domaine de base + alias, expose/sub par appli
    doms = D.legacy_domains(manifest.get("settings"))
    manifest["settings"] = {"domains": doms} if doms else None
    for a in manifest["apps"]:
        a["routes"] = D.legacy_routes(a, doms)
        a["has_db"], a["has_data"] = a.get("slug") in has_db, a.get("slug") in has_data
        cur = db.app(a.get("slug", ""))
        a["exists"] = bool(cur)
        a["target"] = cur["node"] if cur else target_node(a)
    return manifest


def _extract(path, slugs, dest_dir):
    """Extrait db/<slug>.dump et apps/<slug>/data des applis choisies, avec le filtre de sécurité 'data'."""
    import tarfile
    wanted = tuple(f"db/{s}.dump" for s in slugs) + tuple(f"apps/{s}/data" for s in slugs)
    with tarfile.open(path, "r:gz") as tar:
        for m in tar:
            if m.name in wanted or m.name.startswith(tuple(w + "/" for w in wanted if w.startswith("apps/"))):
                tar.extract(m, dest_dir, filter="data")


def restore_archive(name, choices):
    """choices : {slug: ["data", "db"]}. Applis existantes : remplacement (état d'avant mis de côté).
    Applis absentes : recréées depuis le manifeste, puis déployées."""
    path = archive_path(name)
    if not path:
        return
    manifest = read_manifest(path)
    entries = {a["slug"]: a for a in manifest["apps"]}
    tmp = f"/srv/backups/restore-tmp/archive-{time.strftime('%Y%m%d-%H%M%S')}"
    os.makedirs(tmp, mode=0o700, exist_ok=True)
    try:
        P.log("info", "sauvegarde", f"restauration depuis l'archive {name} : {', '.join(choices)}")
        _extract(path, list(choices), tmp)
        for slug, parts in choices.items():
            e = entries.get(slug)
            if not e:
                continue
            src_data, src_dump = f"{tmp}/apps/{slug}/data", f"{tmp}/db/{slug}.dump"
            try:
                if db.app(slug):
                    with P.op_lock:
                        a = db.app(slug)
                        db.update_app(slug, state="deploying")
                        _apply(a, src_data, src_dump, parts, f"l'archive {name}")
                else:
                    _recreate_app(e, src_data, src_dump, parts, name)
            except Exception as ex:
                if db.app(slug):
                    db.update_app(slug, state="error")
                P.log("error", slug, f"restauration depuis l'archive impossible : {ex}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def target_node(e):
    """Nœud où recréer une appli absente : son nœud d'origine s'il existe ici et est en ligne, sinon la console."""
    n = e.get("node") or "local"
    if n != "local" and not db.one("SELECT 1 FROM nodes WHERE id = ? AND state = 'ok'", (n,)):
        return "local"
    return n


def _recreate_app(e, src_data, src_dump, parts, name):
    slug = e["slug"]
    data = {k: e.get(k) for k in APP_KEYS if k in e}
    data.setdefault("expose", "path")
    data.setdefault("sub", "")
    rts, dropped = D.usable_routes(slug, e.get("routes"))
    if dropped:
        P.log("warn", slug, "adresses de l'archive non reprises : " + ", ".join(dropped))
    if data["pkg"] and db.one("SELECT 1 FROM apps WHERE pkg = ?", (data["pkg"],)):
        data["pkg"] = ""
    if data["db"] and not data.get("db_password"):
        data["db_password"] = os.urandom(16).hex()
    node = target_node(e)
    data.update(host_port=P.next_host_port(), state="deploying", desired="running", created_at=time.time(), node=node)
    db.insert_app(slug, data)
    D.set_routes(slug, rts)
    a = db.app(slug)
    P.log("info", slug, f"appli recréée depuis l'archive {name}" + ("" if P.is_local(node) else f" sur le nœud {node}"))
    os.makedirs(P.app_dir(slug), mode=0o700, exist_ok=True)
    if "db" in parts and a["db"] and os.path.exists(src_dump):
        P.ensure_db(a)
        _pg_restore(slug, src_dump)
    if "data" in parts and os.path.isdir(src_data):
        if P.is_local(node):
            shutil.move(src_data, f"{P.app_dir(slug)}/data")
        else:
            P.push_dir(node, src_data, f"{P.app_dir(slug)}/data")
    P.deploy(slug, a["version"], "create")   # pull, /data, démarrage, healthcheck, routes


def snapshot_to_archive(dest_id, snap):
    """Reprise complète depuis Drive/NAS : extrait l'instantané et le convertit en archive Hangar (manifeste tiré
    de la copie du registre), à restaurer ensuite depuis la page de l'archive."""
    import sqlite3
    import tarfile
    import io
    d = dest(dest_id)
    if not d:
        return
    tmp = f"/srv/backups/restore-tmp/instantane-{time.strftime('%Y%m%d-%H%M%S')}"
    os.makedirs(tmp, mode=0o700, exist_ok=True)
    P.log("info", "sauvegarde", f"préparation de la reprise complète depuis {d['name']}, sauvegarde {snap}")
    try:
        rc, out, err = restic("restore", snap, "--target", tmp, "--include", STAGING,
                              "--include", P.APPS_DIR, timeout=12 * 3600, d=d)
        if rc:
            raise RuntimeError("restic restore : " + P.tail(err, 3))
        reg = f"{tmp}{STAGING}/platform.db.copie"
        if not os.path.exists(reg):
            raise RuntimeError("cette sauvegarde ne contient pas la copie du registre (sauvegarde trop ancienne)")
        c = sqlite3.connect(reg)
        c.row_factory = sqlite3.Row
        apps = [dict(r) for r in c.execute("SELECT * FROM apps")]
        sett = {r["key"]: r["value"] for r in c.execute("SELECT key, value FROM settings")}
        tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        if "domains" in tables:
            doms = [{k: r[k] for k in ("name", "mode", "hub", "entry", "ip", "is_default")}
                    for r in c.execute("SELECT * FROM domains")]
            rts = {}
            for r in c.execute("SELECT * FROM routes ORDER BY pos, id"):
                rts.setdefault(r["slug"], []).append({"kind": r["kind"], "domain": r["domain"], "sub": r["sub"]})
        else:
            try:
                aliases = json.loads(sett.get("aliases") or "[]")
            except ValueError:
                aliases = []
            doms = D.legacy_domains({"base_domain": sett.get("base_domain"), "hub": sett.get("hub"),
                                     "aliases": aliases, "mode": sett.get("mode")})
            rts = {a["slug"]: D.legacy_routes(a, doms) for a in apps}
        c.close()
        manifest = {"format": 2, "created": time.time(), "hangar": f"instantané {snap} ({d['name']})",
                    "settings": {"domains": doms},
                    "apps": [{"slug": a["slug"], "node": a.get("node") or "local", "routes": rts.get(a["slug"], []),
                              **{k: a.get(k) for k in APP_KEYS}} for a in apps]}
        os.makedirs(ARCHIVES, mode=0o700, exist_ok=True)
        name = save_upload_name()
        part = f"{ARCHIVES}/.{name}.part"
        fdp = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fdp, "wb") as raw, tarfile.open(fileobj=raw, mode="w:gz", compresslevel=6) as tar:
            data = json.dumps(manifest, ensure_ascii=False, indent=1).encode()
            ti = tarfile.TarInfo("manifest.json")
            ti.size, ti.mtime, ti.mode = len(data), int(time.time()), 0o600
            tar.addfile(ti, io.BytesIO(data))
            for a in apps:
                dump = f"{tmp}{STAGING}/db/{a['slug']}.dump"
                if os.path.exists(dump):
                    tar.add(dump, arcname=f"db/{a['slug']}.dump")
                ddir = data_source(a["slug"], a.get("node") or "local", tmp)
                if os.path.isdir(ddir):
                    tar.add(ddir, arcname=f"apps/{a['slug']}/data")
        os.replace(part, f"{ARCHIVES}/{name}")
        P.log("ok", "sauvegarde", f"reprise prête : archive {name} ({len(apps)} appli(s)). "
                                  "Ouvre-la dans Sauvegardes › Archives pour lancer la restauration.")
    except Exception as e:
        P.log("error", "sauvegarde", f"reprise complète impossible : {e}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def apply_settings(st):
    """Reprend les domaines d'une archive (ajoutés ou mis à jour ; ceux d'ici qui n'y sont pas restent),
    et la politique de sécurité des nœuds si elle y est (appliquée ensuite depuis la page Sécurité)."""
    if isinstance((st or {}).get("security"), dict):
        db.kv_set("security", st["security"])
        P.log("info", "sécurité", "politique générale reprise de l'archive")
    doms = D.legacy_domains(st)
    if not doms:
        return
    before = [dict(d) for d in D.all_domains()]
    D.import_domains(doms)
    try:
        P.apply_routing()
    except RuntimeError:
        db.x("DELETE FROM domains")
        for d in before:
            db.x("INSERT INTO domains(name, mode, hub, entry, ip, is_default, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)",
                 tuple(d[k] for k in ("name", "mode", "hub", "entry", "ip", "is_default", "created_at")))
        raise
    P.sync_all_tunnels()
    P.log("ok", "caddy", "domaines repris de l'archive : " + ", ".join(f"{d['name']} ({d['mode']})" for d in doms))


def start_archive_restore(name, choices):
    P.spawn(restore_archive, name, choices)


def save_upload_name():
    return f"hangar-{time.strftime('%Y%m%d-%H%M%S')}-import.tar.gz"
