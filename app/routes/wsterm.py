"""Terminal interactif dans le conteneur d'une appli : « docker exec -it » dans un pseudo-terminal, relié au navigateur par
WebSocket (xterm.js). Vim, top, la complétion et les couleurs marchent.

Les WebSocket ne passent pas par le contrôle d'accès HTTP de la console : il est refait ici (réseau local, session
valide, compte administrateur, même origine). Session coupée après 30 min sans activité, 4 h au plus. Ouverture et
fermeture notées au journal de l'appli et au journal des actions.
"""
import asyncio
import fcntl
import ipaddress
import json
import os
import pty
import signal
import struct
import subprocess
import termios
import time

from fastapi import APIRouter, WebSocket

from .. import db, terminal
from .. import platform as P
from .common import SESSION_IDLE

router = APIRouter()
IDLE = 30 * 60
MAX = 4 * 3600


def _allowed(ws):
    """Compte autorisé (administrateur, session valide, réseau local, même origine), ou None."""
    from ..main import LAN
    ip = ws.client.host if ws.client else ""
    try:
        addr = ipaddress.ip_address(ip)
        if not (any(addr in n for n in LAN) or addr.is_loopback):
            return None
    except ValueError:
        return None
    origin = ws.headers.get("origin")
    host = ws.headers.get("host")
    if not origin or origin != f"https://{host}":
        return None
    sess = ws.scope.get("session") or {}
    u, sid = sess.get("user"), sess.get("sid")
    if not u or not sid:
        return None
    row = db.one("SELECT s.seen, u.role FROM sessions s JOIN users u ON u.username = s.username "
                 "WHERE s.id = ? AND s.username = ?", (sid, u))
    if not row or time.time() - row["seen"] > SESSION_IDLE or row["role"] != "admin":
        return None
    return u, ip


def _audit(user, ip, path, status, detail):
    db.x("INSERT INTO audit(ts, username, ip, method, path, status, detail) VALUES(?, ?, ?, 'WS', ?, ?, ?)",
         (time.time(), user, ip, path[:300], status, detail))


@router.websocket("/apps/{slug}/terminal/ws")
async def terminal_ws(ws: WebSocket, slug: str):
    who = _allowed(ws)
    a = db.app(slug)
    if not who or not a:
        await ws.close(code=4403)
        return
    user, ip = who
    which = ws.query_params.get("which") or "app"
    name = dict((k, c) for k, c, _ in terminal.containers(slug)).get(which)
    if not name:
        await ws.close(code=4404)
        return
    as_root = ws.query_params.get("root") == "1"
    await ws.accept()
    master, slave = pty.openpty()
    cmd = ["docker", "exec", "-it", "-e", "TERM=xterm-256color"] + (["-u", "0"] if as_root else []) + \
        [name, "sh", "-c", "if command -v bash >/dev/null 2>&1; then exec bash -l; else exec sh -l; fi"]
    proc = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave, env=P.denv(a["node"]), start_new_session=True,
                            close_fds=True)
    os.close(slave)
    os.set_blocking(master, False)
    t0 = last = time.time()
    P.log("info", slug, f"terminal ouvert dans {which}{' (root)' if as_root else ''} par {user}")
    _audit(user, ip, ws.url.path, 101, f"terminal {which}{' root' if as_root else ''}")
    loop = asyncio.get_running_loop()
    out_q = asyncio.Queue()

    def readable():
        try:
            data = os.read(master, 65536)
        except OSError:
            data = b""
        out_q.put_nowait(data)
    loop.add_reader(master, readable)

    async def pump_out():
        while True:
            data = await out_q.get()
            if not data:
                break
            await ws.send_bytes(data)

    async def pump_in():
        nonlocal last
        while True:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            raw = msg.get("text") or (msg.get("bytes") or b"").decode(errors="replace")
            try:
                m = json.loads(raw)
            except ValueError:
                continue
            last = time.time()
            if m.get("t") == "i" and isinstance(m.get("d"), str):
                os.write(master, m["d"].encode())
            elif m.get("t") == "r":
                cols, rows = int(m.get("c") or 80), int(m.get("r") or 24)
                fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", max(2, min(rows, 500)),
                                                                    max(2, min(cols, 1000)), 0, 0))

    async def watchdog():
        while True:
            await asyncio.sleep(15)
            now = time.time()
            if now - last > IDLE or now - t0 > MAX or proc.poll() is not None:
                break

    tasks = [asyncio.create_task(x()) for x in (pump_out, pump_in, watchdog)]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in tasks:
            t.cancel()
        loop.remove_reader(master)
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGHUP)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        os.close(master)
        try:
            await ws.close()
        except RuntimeError:
            pass
        P.log("info", slug, f"terminal fermé ({user}, {int(time.time() - t0)} s)")
