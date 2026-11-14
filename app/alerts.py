"""Alertes : ntfy (notification sur le téléphone, sujet secret), e-mail (SMTP), Discord (webhook), Telegram (bot).

Chaque canal a son seuil : n'y partent que les alertes d'au moins cette priorité (1 discrète … 5 urgente). Un canal en
panne n'empêche pas les autres ; l'échec est noté dans le journal. Réglages : ntfy dans les réglages généraux
(ntfy_server, ntfy_topic, ntfy_token), les autres dans kv « alert_channels » :
  {"email": {"on", "host", "port", "security": starttls|ssl|none, "user", "password", "from", "to", "min"},
   "discord": {"on", "url", "min"}, "telegram": {"on", "token", "chat_id", "min"}}
"""
import json
import re
import smtplib
import ssl
import threading
import time
import urllib.request
from email.message import EmailMessage

from . import db

UA = "Hangar (alertes)"
CHANNELS = {"ntfy": "ntfy", "email": "E-mail", "discord": "Discord", "telegram": "Telegram"}
DEFAULT_MIN = {"ntfy": 1, "email": 4, "discord": 3, "telegram": 3}
DISCORD_RE = re.compile(r"^https://(?:discord|discordapp)\.com/api/webhooks/\d{5,25}/[A-Za-z0-9_-]{20,100}$")
TG_TOKEN_RE = re.compile(r"^\d{5,15}:[A-Za-z0-9_-]{30,60}$")
TG_CHAT_RE = re.compile(r"^(-?\d{1,20}|@[A-Za-z0-9_]{5,32})$")
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
MAIL_RE = re.compile(r"^[^@\s,;<>]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}$")

_last = {}          # clé -> horodatage du dernier envoi (anti-rafale)
_lock = threading.Lock()


def channels():
    return db.kv_get("alert_channels") or {}


def save_channel(name, cfg):
    allc = channels()
    allc[name] = cfg
    db.kv_set("alert_channels", allc)


def _json_post(url, data, timeout=10):
    req = urllib.request.Request(url, data=json.dumps(data).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


def _discord(c, title, msg, priority):
    icon = {5: "🔴", 4: "🟠", 3: "🔵"}.get(priority, "⚪")
    _json_post(c["url"], {"username": "Hangar", "content": f"{icon} **{title}**\n{msg}"[:1990],
                          "allowed_mentions": {"parse": []}})


def _telegram(c, title, msg, priority):
    _json_post(f"https://api.telegram.org/bot{c['token']}/sendMessage",
               {"chat_id": c["chat_id"], "text": f"{title}\n\n{msg}"[:4000], "disable_web_page_preview": True,
                "disable_notification": priority < 3})


def telegram_detect(token):
    """Dernière conversation où quelqu'un a écrit au bot (pour trouver chat_id). Retourne (chat_id, nom) ou None."""
    req = urllib.request.Request(f"https://api.telegram.org/bot{token}/getUpdates", headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=10) as r:
        res = json.load(r).get("result") or []
    for u in reversed(res):
        chat = (u.get("message") or u.get("channel_post") or u.get("my_chat_member") or {}).get("chat")
        if chat:
            return str(chat["id"]), chat.get("title") or chat.get("username") or chat.get("first_name") or ""
    return None


def _email(c, title, msg, priority):
    m = EmailMessage()
    m["Subject"] = ("[Hangar] " + ("URGENT : " if priority >= 5 else "") + title)[:200]
    m["From"] = c.get("from") or c.get("user")
    m["To"] = ", ".join(c["to"])
    m.set_content(msg + "\n\n— Hangar")
    port = int(c.get("port") or 587)
    ctx = ssl.create_default_context()
    if c.get("security") == "ssl":
        srv = smtplib.SMTP_SSL(c["host"], port, timeout=20, context=ctx)
    else:
        srv = smtplib.SMTP(c["host"], port, timeout=20)
    with srv:
        if c.get("security", "starttls") == "starttls":
            srv.starttls(context=ctx)
        if c.get("user"):
            srv.login(c["user"], c.get("password") or "")
        srv.send_message(m)


SENDERS = {"email": _email, "discord": _discord, "telegram": _telegram}


def configured(s=None):
    """Canaux prêts : [(nom, réglage)] ; ntfy compte s'il a un sujet."""
    s = s or db.settings()
    out = [("ntfy", {"min": int(s.get("ntfy_min") or 1)})] if s.get("ntfy_topic") else []
    for name, c in channels().items():
        if name in SENDERS and c.get("on"):
            out.append((name, c))
    return out


def _post(s, title, msg, priority, tags):
    # publication JSON : titre et message en UTF-8 sans passer par les en-têtes HTTP
    body = json.dumps({"topic": s["ntfy_topic"], "title": title, "message": msg[:3900],
                       "priority": priority, "tags": tags}).encode()
    req = urllib.request.Request(s["ntfy_server"].rstrip("/") + "/", data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    if s.get("ntfy_token"):
        req.add_header("Authorization", f"Bearer {s['ntfy_token']}")
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status


def send(title, msg, priority=3, tags=None, key=None, cooldown=0, force=False, only=None):
    """Envoie une alerte sur chaque canal prêt dont le seuil est atteint. `key` + `cooldown` évitent de répéter la même
    alerte trop souvent ; `only` : un seul canal (essai). Retourne (envoyée quelque part, erreurs)."""
    s = db.settings()
    if not force and s.get("alerts_on") != "1":
        return False, "alertes désactivées"
    chans = [(n, c) for n, c in configured(s) if (only is None or n == only)]
    if only and only != "ntfy" and not chans and only in channels():   # essai d'un canal pas encore activé
        chans = [(only, channels()[only])]
    if not chans:
        return False, "aucun canal d'alerte réglé"
    if key and cooldown:
        with _lock:
            if time.time() - _last.get(key, 0) < cooldown:
                return False, "déjà envoyée récemment"
            _last[key] = time.time()
    sent, errs = False, []
    for name, c in chans:
        if not force and priority < int(c.get("min") or DEFAULT_MIN[name]):
            continue
        try:
            if name == "ntfy":
                _post(s, title, msg, priority, tags or [])
            else:
                SENDERS[name](c, title, msg, priority)
            sent = True
        except Exception as e:  # le réseau ne doit jamais faire échouer l'opération qui alerte
            err = f"{CHANNELS[name]} : {str(getattr(e, 'reason', e))[:200]}"
            errs.append(err)
            db.x("INSERT INTO events(ts, level, app, msg) VALUES(?, ?, ?, ?)",
                 (time.time(), "warn", "alertes", f"notification non envoyée ({title}) — {err}"[:500]))
    return sent, " ; ".join(errs)


def send_async(*args, **kw):
    threading.Thread(target=send, args=args, kwargs=kw, daemon=True).start()
