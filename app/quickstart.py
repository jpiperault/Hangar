"""Démarrage rapide : un domaine et un seul jeton Cloudflare suffisent pour publier des applis.

connect() fait d'un coup ce qui demandait plusieurs pages : vérifie le jeton d'API et la zone du domaine, crée le tunnel
Cloudflare de cette console s'il n'y en a pas (ou reprend celui du même nom), relie cloudflared avec son jeton,
enregistre le jeton d'API (DNS et règles du tunnel gérés ensuite par cloudflare.sync), puis ajoute le domaine en mode
tunnel avec le préfixe « apps ». Rien n'est ouvert sur la box : le tunnel sort vers Cloudflare.

Droits du jeton : Compte › Cloudflare Tunnel › Modifier ; Zone › DNS › Modifier ; Zone › Zone › Lire.
"""
import os
import socket

from . import cloudflare as CF
from . import db
from . import domains as D
from . import platform as P

UNIT = "/etc/systemd/system/cloudflared.service"
UNIT_TEXT = """[Unit]
Description=Cloudflare Tunnel client
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/cloudflared --no-autoupdate tunnel run --token-file /etc/cloudflared/token
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
"""


def tunnel_name():
    host = "".join(c if c.isalnum() or c == "-" else "-" for c in socket.gethostname().lower())[:40] or "console"
    return f"hangar-{host}"


def zone_for(domain, zones):
    """Zone Cloudflare qui porte ce domaine (le domaine lui-même ou un domaine parent), ou None."""
    return next((z for z in sorted(zones, key=len, reverse=True) if domain == z or domain.endswith("." + z)), None)


def ensure_unit():
    """Service cloudflared lisant /etc/cloudflared/token (installé par install.sh ; recréé s'il manque)."""
    rc, unit = P.run(["systemctl", "cat", "cloudflared"], timeout=10)
    if rc == 0 and "--token-file" in unit:
        return
    with open(UNIT, "w") as f:
        f.write(UNIT_TEXT)
    P.run(["systemctl", "daemon-reload"], timeout=30)
    P.run(["systemctl", "enable", "cloudflared"], timeout=30)


def ensure_tunnel(acct, tok):
    """Id et jeton du tunnel de cette console chez Cloudflare (créé s'il n'existe pas)."""
    name = tunnel_name()
    found, _ = CF._api("GET", f"/accounts/{acct}/cfd_tunnel", tok=tok, params={"name": name, "is_deleted": "false"})
    if found:
        tid = found[0]["id"]
    else:
        t, _ = CF._api("POST", f"/accounts/{acct}/cfd_tunnel", {"name": name, "config_src": "cloudflare"}, tok=tok)
        tid = t["id"]
        P.log("ok", "tunnel", f"tunnel {name} créé chez Cloudflare")
    token, _ = CF._api("GET", f"/accounts/{acct}/cfd_tunnel/{tid}/token", tok=tok)
    return tid, token


def connect(domain, tok):
    """Domaine + jeton d'API → domaine publiable. Lève ValueError (saisie) ou RuntimeError (Cloudflare, tunnel)."""
    domain = (domain or "").strip().lower().rstrip(".")
    tok = (tok or "").strip()
    if not D.DOMAIN_RE.match(domain):
        raise ValueError("Nom de domaine invalide, par exemple exemple.fr")
    if not tok or len(tok) > 200 or any(c.isspace() for c in tok):
        raise ValueError("Jeton invalide : copie la valeur affichée une seule fois par Cloudflare.")
    try:
        zones = CF.verify(tok)
    except CF.CFError as e:
        raise ValueError(f"Cloudflare refuse ce jeton : {e}")
    zone = zone_for(domain, zones)
    if not zone:
        raise ValueError(f"{domain} n'est pas dans les zones visibles avec ce jeton ({', '.join(zones) or 'aucune'}) : "
                         "ajoute le domaine à Cloudflare, ou donne au jeton l'accès à cette zone.")
    try:
        z, _ = CF._api("GET", "/zones", tok=tok, params={"name": zone})
        acct = z[0]["account"]["id"]
        if not os.path.exists(P.TUNNEL_TOKEN) or not P.tunnel_id():   # console sans tunnel : on le crée
            tid, ttoken = ensure_tunnel(acct, tok)
            ensure_unit()
            P.set_tunnel_token(ttoken)
    except CF.CFError as e:
        raise RuntimeError(f"Cloudflare : {e} (le jeton a-t-il le droit « Cloudflare Tunnel › Modifier » ?)")
    CF.set_token(tok)
    if not D.get(domain):
        errs = D.save(domain, "tunnel", "apps", make_default=not D.all_domains())
        if errs:
            raise ValueError(" ".join(errs.values()))
    P.apply_routing()
    P.spawn(P.sync_all_tunnels)
    P.spawn(CF.sync_quiet)
    P.log("ok", "domaines", f"démarrage rapide : {domain} publié par le tunnel Cloudflare")
    return domain


def state():
    """Où en est le démarrage rapide (page /demarrage)."""
    doms = D.all_domains()
    first = next((a for a in db.apps() if a["kind"] != "static"), None)
    return {"domain": (D.default() or {}).get("name") if doms else None, "tunnel": os.path.exists(P.TUNNEL_TOKEN),
            "cf": bool(CF.token()), "app": dict(first) if first else None, "tunnel_name": tunnel_name()}
