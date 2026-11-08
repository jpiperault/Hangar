"""Sauvegardes : dumps PostgreSQL locaux + restic chiffré vers Google Drive (via rclone).

- Dossier de travail : /srv/platform/backup (700) : rclone.conf, restic.pass.
- Dépôt restic : rclone:hangar-gdrive:Hangar-sauvegardes (accès Drive limité à drive.file).
- Contenu : dumps par appli (/srv/backups/staging/db), /srv/apps (compose + data/), /srv/platform.
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
from . import platform as P

BK = "/srv/platform/backup"
RCLONE_CONF = f"{BK}/rclone.conf"
PASS_FILE = f"{BK}/restic.pass"
REMOTE = "hangar-gdrive"
FOLDER = "Hangar-sauvegardes"
REPO = f"rclone:{REMOTE}:{FOLDER}"
STAGING = "/srv/backups/staging"
LOCAL_PG = "/srv/backups/postgres"
LOCK = "/run/hangar-backup.lock"
SAFETY = "/srv/backups/avant-restauration"


# ---------------------------------------------------------------- état

def configured():
    return os.path.exists(RCLONE_CONF) and os.path.exists(PASS_FILE)


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


def _env():
    return {**os.environ, "RESTIC_REPOSITORY": REPO, "RESTIC_PASSWORD_FILE": PASS_FILE,
            "RCLONE_CONFIG": RCLONE_CONF, "RESTIC_CACHE_DIR": "/var/cache/restic",
            "RESTIC_PROGRESS_FPS": "0.016"}


def restic(*args, timeout=3600, input=None):
    try:
        p = subprocess.run(["restic", "-o", "rclone.program=rclone", *args], capture_output=True, text=True,
                           timeout=timeout, env=_env(), input=input)
    except subprocess.TimeoutExpired:
        return 124, "", f"délai dépassé ({timeout} s)"
    return p.returncode, p.stdout, p.stderr


def last_runs(n=10):
    return db.q("SELECT * FROM backups ORDER BY id DESC LIMIT ?", (n,))


def last_ok():
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
    rc, _, err = restic("cat", "config", timeout=120)
    if rc:
        rc, _, err = restic("init", timeout=300)
        if rc:
            raise RuntimeError("Initialisation du dépôt chiffré impossible : " + P.tail(err, 3))
        P.log("ok", "sauvegarde", f"Google Drive connecté, dépôt chiffré créé dans « {FOLDER} »")
    else:
        P.log("ok", "sauvegarde", f"Google Drive reconnecté, dépôt existant « {FOLDER} » retrouvé")


def disconnect():
    """Oublie l'accès à Drive. Le mot de passe est gardé : sans lui, les sauvegardes existantes sont perdues."""
    if os.path.exists(RCLONE_CONF):
        os.remove(RCLONE_CONF)
    P.log("info", "sauvegarde", "Google Drive déconnecté (les sauvegardes restent sur le Drive)")


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
        with open(path + ".tmp", "wb") as f:
            p = subprocess.run(["docker", "exec", P.PG, "pg_dump", "-U", "platform", "-Fc", name],
                               stdout=f, stderr=subprocess.PIPE, timeout=1800)
        if p.returncode:
            os.remove(path + ".tmp")
            raise RuntimeError(f"pg_dump {name} : {p.stderr.decode(errors='replace')[-300:]}")
        os.replace(path + ".tmp", path)
        os.chmod(path, 0o600)
        keep.add(f"{a['slug']}.dump")
    for f in os.listdir(f"{STAGING}/db"):
        if f not in keep:
            os.remove(f"{STAGING}/db/{f}")


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


def run_backup(trigger="planifiée"):
    """Appelée par le timer systemd (ou le bouton, via systemctl start). Un seul passage à la fois."""
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("Une sauvegarde est déjà en cours.")
        return 1
    t0, remote = time.time(), configured()
    added = total = snap = None
    try:
        _dump_all_local()
        _dump_apps()
        if remote:
            _copy_registry()
            rc, out, err = restic("backup", "--json", "--tag", "hangar", "--host", "hangar",
                                  "--exclude", "*.tmp", "--exclude", f"{BK}/restic.pass",
                                  # fichiers bruts de PostgreSQL et registre en cours d'écriture : incohérents
                                  # si copiés à chaud ; remplacés par les exports et la copie du registre
                                  "--exclude", f"{P.PLATFORM}/postgres", "--exclude", f"{P.PLATFORM}/platform.db*",
                                  STAGING, P.APPS_DIR, P.PLATFORM, timeout=6 * 3600)
            summary = next((json.loads(l) for l in out.splitlines()[::-1]
                            if l.startswith("{") and '"summary"' in l), None)
            if rc not in (0, 3) or not summary:   # 3 : certains fichiers illisibles, instantané quand même créé
                raise RuntimeError("restic backup : " + P.tail(err or out, 4))
            added, total, snap = summary.get("data_added"), summary.get("total_bytes_processed"), summary.get("snapshot_id")
            keep = json.loads(db.settings().get("backup_keep") or "{}")
            args = ["forget", "--tag", "hangar", "--keep-daily", str(keep.get("daily", 7)),
                    "--keep-weekly", str(keep.get("weekly", 4)), "--keep-monthly", str(keep.get("monthly", 12))]
            if time.localtime().tm_wday == 6:   # nettoyage des données orphelines le dimanche
                args.append("--prune")
            rc, out, err = restic(*args, timeout=3 * 3600)
            if rc:
                P.log("warn", "sauvegarde", "rotation des anciennes sauvegardes en échec : " + P.tail(err, 3))
            warn = " (certains fichiers illisibles ignorés)" if rc == 3 else ""
            msg = f"sauvegarde envoyée sur Google Drive{warn} : {_h(added)} ajoutés, {_h(total)} au total"
        else:
            msg = "sauvegarde locale seulement (Google Drive non connecté)"
        db.x("INSERT INTO backups(ts, duration, ok, remote, added, total, snapshot, trigger, msg) "
             "VALUES(?, ?, 1, ?, ?, ?, ?, ?, ?)", (t0, time.time() - t0, int(remote), added, total, snap, trigger, msg))
        P.log("ok", "sauvegarde", msg)
        db.kv_set("snapshots", None)
        return 0
    except Exception as e:
        msg = str(e)[:1500]
        db.x("INSERT INTO backups(ts, duration, ok, remote, trigger, msg) VALUES(?, ?, 0, ?, ?, ?)",
             (t0, time.time() - t0, int(remote), trigger, msg))
        P.log("error", "sauvegarde", f"sauvegarde en échec : {msg}")
        alerts.send("Sauvegarde en échec", msg, priority=4, tags=["floppy_disk", "warning"])
        return 1
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

def snapshots(refresh=False):
    """Liste des instantanés, du plus récent au plus ancien (cache 10 min)."""
    cached, ts = db.kv_get("snapshots"), db.kv_ts("snapshots")
    if cached is not None and not refresh and ts and time.time() - ts < 600:
        return cached, None
    if not configured():
        return [], None
    rc, out, err = restic("snapshots", "--json", "--tag", "hangar", timeout=180)
    if rc:
        return cached or [], "liste des sauvegardes indisponible : " + P.tail(err, 2)
    snaps = []
    for x in json.loads(out or "[]"):
        iso = re.sub(r"\.\d+", "", x["time"])   # restic donne des nanosecondes
        ts = datetime.datetime.fromisoformat(iso).timestamp()
        snaps.append({"id": x["short_id"], "ts": ts})
    snaps.sort(key=lambda x: x["ts"], reverse=True)
    db.kv_set("snapshots", snaps)
    return snaps, None


def restore_app(slug, snap, parts):
    """Restaure data/ et/ou la base d'une appli depuis un instantané. L'état actuel est d'abord mis de côté."""
    with P.op_lock:
        a = db.app(slug)
        if not a:
            return
        stamp = time.strftime("%Y%m%d-%H%M%S")
        tmp = f"/srv/backups/restore-tmp/{slug}-{stamp}"
        safe = f"{SAFETY}/{slug}-{stamp}"
        d = P.app_dir(slug)
        db.update_app(slug, state="deploying")
        P.log("info", slug, f"restauration de {', '.join(parts)} depuis la sauvegarde {snap}")
        try:
            inc = []
            if "data" in parts:
                inc += ["--include", f"{d}/data"]
            if "db" in parts:
                inc += ["--include", f"{STAGING}/db/{slug}.dump"]
            rc, out, err = restic("restore", snap, "--target", tmp, *inc, timeout=6 * 3600)
            if rc:
                raise RuntimeError("restic restore : " + P.tail(err, 3))
            got_data = os.path.isdir(f"{tmp}{d}/data")
            got_db = os.path.exists(f"{tmp}{STAGING}/db/{slug}.dump")
            if "data" in parts and not got_data:
                raise RuntimeError("cette sauvegarde ne contient pas de dossier data/ pour cette appli")
            if "db" in parts and not got_db:
                raise RuntimeError("cette sauvegarde ne contient pas de base pour cette appli")
            os.makedirs(safe, mode=0o700, exist_ok=True)
            P.run(["docker", "compose", "stop"], cwd=d, timeout=120)
            if "db" in parts:
                P.dump_db(slug, f"{safe}/base-avant.sql.gz")
                name = P.db_name(slug)
                with open(f"{tmp}{STAGING}/db/{slug}.dump", "rb") as f:
                    p = subprocess.run(["docker", "exec", "-i", P.PG, "pg_restore", "-U", "platform", "--clean",
                                        "--if-exists", "--no-owner", "--no-acl", f"--role={name}", "-d", name],
                                       stdin=f, capture_output=True, timeout=3600)
                if p.returncode:
                    errs = [l for l in p.stderr.decode(errors="replace").splitlines() if "error" in l.lower()]
                    if errs:
                        P.log("warn", slug, "restauration de la base avec avertissements : " + " | ".join(errs[-3:]))
            if "data" in parts:
                if os.path.exists(f"{d}/data"):
                    shutil.move(f"{d}/data", f"{safe}/data")
                shutil.move(f"{tmp}{d}/data", f"{d}/data")
            shutil.rmtree(tmp, ignore_errors=True)
            if a["desired"] == "running":
                P.prepare_data(a, a["version"])
                P.run(["docker", "compose", "up", "-d", "--no-build"], cwd=d, timeout=300)
                ok, detail = P.wait_health(a)
            else:
                ok, detail = True, "appli arrêtée, non redémarrée"
            db.update_app(slug, state="ok" if ok else "error")
            P.log("ok" if ok else "error", slug,
                  f"restauration terminée ({detail}). L'état d'avant est gardé dans {safe}")
            if not ok:
                alerts.send(f"{a['name']} : restauration", f"Restaurée, mais le healthcheck échoue : {detail}",
                            priority=4, tags=["warning"])
        except Exception as e:
            shutil.rmtree(tmp, ignore_errors=True)
            P.run(["docker", "compose", "up", "-d", "--no-build"], cwd=d, timeout=300)
            db.update_app(slug, state="error")
            P.log("error", slug, f"restauration impossible : {e}" +
                  (f". L'état d'avant est gardé dans {safe}" if os.path.exists(safe) else ". Rien n'a été remplacé"))


def client_id():
    """Identifiant OAuth personnel enregistré dans rclone.conf ('' = celui, partagé, de rclone)."""
    try:
        m = re.search(r"^client_id = (.+)$", open(RCLONE_CONF).read(), re.M)
        return m.group(1).strip() if m else ""
    except OSError:
        return ""
