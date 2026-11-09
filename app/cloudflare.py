"""Noms publics chez Cloudflare, gérés par Hangar avec un jeton d'API.

Droits du jeton (Mon profil › Jetons d'API › Créer un jeton personnalisé) :
- Compte › Cloudflare Tunnel › Modifier ;
- Zone › DNS › Modifier, et Zone › Zone › Lire, pour toutes les zones (ou celles des domaines de Hangar).

sync() rapproche Cloudflare de ce que veut Hangar :
- domaines en mode tunnel : une règle d'entrée du tunnel par nom (→ http://127.0.0.1:8080, Caddy) et un
  enregistrement CNAME <nom> → <id du tunnel>.cfargotunnel.com, proxifié ;
- domaines en mode direct avec une IP : un enregistrement A <nom> → IP, non proxifié (Let's Encrypt passe en direct).

Hangar ne touche qu'à ses propres noms : les autres règles du tunnel et les autres enregistrements DNS restent tels
quels. Un nom déjà pris par un enregistrement qui ne vient pas de Hangar n'est pas écrasé : il est signalé.
Le jeton est rangé dans /srv/platform/cloudflare.token (root seulement) et n'est jamais affiché.
"""
import base64
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import db
from . import domains as D
from . import platform as P

TOKEN = "/srv/platform/cloudflare.token"
API = "https://api.cloudflare.com/client/v4"
COMMENT = "géré par Hangar"
_lock = threading.Lock()


class CFError(RuntimeError):
    pass


def token():
    try:
        t = open(TOKEN).read().strip()
        return t or None
    except OSError:
        return None


def _api(method, path, body=None, tok=None, params=None):
    tok = tok or token()
    url = API + path + ("?" + urllib.parse.urlencode(params) if params else "")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {tok}", "Content-Type": "application/json", "User-Agent": "hangar"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            res = json.load(r)
    except urllib.error.HTTPError as e:
        try:
            res = json.load(e)
        except (ValueError, OSError):
            raise CFError(f"Cloudflare a répondu {e.code}")
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise CFError(f"Cloudflare injoignable : {e}")
    if not res.get("success"):
        errs = res.get("errors") or []
        msg = "; ".join(f"{x.get('message')} ({x.get('code')})" for x in errs) or "erreur inconnue"
        raise CFError(msg)
    return res.get("result"), res.get("result_info") or {}


def tunnel_info():
    """(compte, id du tunnel) d'après le jeton de cloudflared, ou None."""
    try:
        tok = open(P.TUNNEL_TOKEN).read().strip()
        d = json.loads(base64.b64decode(tok + "=" * (-len(tok) % 4),
                                        altchars=b"-_" if "-" in tok or "_" in tok else None))
        return d["a"], d["t"]
    except (OSError, ValueError, KeyError, TypeError):
        return None


def verify(tok):
    """Vérifie un jeton : actif, et capable de lire au moins une zone. Retourne la liste des zones visibles."""
    try:
        r, _ = _api("GET", "/user/tokens/verify", tok=tok)
    except CFError:
        t = tunnel_info()
        if not t:
            raise CFError("jeton refusé par Cloudflare")
        r, _ = _api("GET", f"/accounts/{t[0]}/tokens/verify", tok=tok)   # jeton de compte
    if (r or {}).get("status") != "active":
        raise CFError("jeton inactif ou expiré")
    zones, _ = _api("GET", "/zones", tok=tok, params={"per_page": 50})
    return [z["name"] for z in zones or []]


def set_token(tok):
    tok = (tok or "").strip()
    if not tok or len(tok) > 200 or any(c.isspace() for c in tok):
        raise ValueError("Jeton invalide : copie la valeur affichée une seule fois par Cloudflare.")
    try:
        zones = verify(tok)
    except CFError as e:
        raise ValueError(f"Cloudflare refuse ce jeton : {e}")
    P.write_private(TOKEN, tok + "\n")
    P.log("ok", "cloudflare", f"jeton d'API enregistré, zones visibles : {', '.join(zones) or 'aucune'}")
    return zones


def remove_token():
    try:
        os.remove(TOKEN)
    except FileNotFoundError:
        pass
    db.kv_set("cf_status", {})
    P.log("info", "cloudflare", "jeton d'API retiré : les noms publics se déclarent de nouveau à la main")


def zone_of(name, cache):
    """Zone Cloudflare qui contient ce nom (le suffixe le plus long trouvé), ou None."""
    labels = name.split(".")
    for i in range(len(labels) - 1):
        cand = ".".join(labels[i:])
        if cand in cache:
            if cache[cand]:
                return cache[cand]
            continue
        zs, _ = _api("GET", "/zones", params={"name": cand})
        cache[cand] = zs[0] if zs else None
        if cache[cand]:
            return cache[cand]
    return None


def _records(zone_id):
    out, page = [], 1
    while True:
        rs, info = _api("GET", f"/zones/{zone_id}/dns_records", params={"per_page": 1000, "page": page})
        out += rs or []
        if page >= (info.get("total_pages") or 1):
            return out
        page += 1


def status():
    st = db.kv_get("cf_status") or {}
    st["token"] = bool(token())
    return st


def sync_quiet():
    try:
        sync()
    except Exception as e:   # jamais bloquant pour le routage : l'erreur est visible dans la console
        P.log("error", "cloudflare", f"synchronisation impossible : {e}")
        st = db.kv_get("cf_status") or {}
        st.update(error=str(e)[:300], ts=time.time())
        db.kv_set("cf_status", st)


def sync():
    """Met Cloudflare en accord avec les noms publics de Hangar. Retourne le résumé (ou None sans jeton)."""
    if not token():
        return None
    with _lock:
        names = D.public_names()
        managed = set(db.kv_get("cf_managed") or [])
        res = {}            # nom → {ok, msg}
        changes = []
        tun = tunnel_info()
        tunnel_names = [n["name"] for n in names if n["mode"] == "tunnel"]
        direct = {n["name"]: n["ip"] for n in names if n["mode"] == "direct" and n["ip"]}
        for n in names:
            if n["mode"] == "direct" and not n["ip"]:
                res[n["name"]] = {"ok": None, "msg": "mode direct sans IP publique : DNS à déclarer à la main"}

        # 1. règles d'entrée du tunnel
        if tunnel_names and not tun:
            for h in tunnel_names:
                res[h] = {"ok": False, "msg": "pas de jeton de tunnel enregistré"}
        if tun:
            acct, tid = tun
            cur, _ = _api("GET", f"/accounts/{acct}/cfd_tunnel/{tid}/configurations")
            cfg = (cur or {}).get("config") or {}
            ingress = cfg.get("ingress") or []
            service = f"http://{db.settings()['tunnel_bind']}"
            want = set(tunnel_names)
            keep = [r for r in ingress if r.get("hostname") and r["hostname"] not in want and r["hostname"] not in managed]
            catch = next((r for r in reversed(ingress) if not r.get("hostname")), {"service": "http_status:404"})
            ours = {r["hostname"]: r for r in ingress if r.get("hostname") in want}
            rules = keep + [{**ours.get(h, {}), "hostname": h, "service": service} for h in tunnel_names] + [catch]
            if [(r.get("hostname"), r.get("service"), r.get("path")) for r in rules] != \
               [(r.get("hostname"), r.get("service"), r.get("path")) for r in ingress]:
                _api("PUT", f"/accounts/{acct}/cfd_tunnel/{tid}/configurations",
                     body={"config": {**cfg, "ingress": rules}})
                added = want - {r.get("hostname") for r in ingress}
                gone = {r.get("hostname") for r in ingress if r.get("hostname")} - {r.get("hostname") for r in rules}
                changes.append(f"tunnel : {len(added)} règle(s) ajoutée(s), {len(gone)} retirée(s)")

        # 2. DNS, zone par zone
        target = {}   # nom → (type, contenu, proxifié)
        if tun:
            for h in tunnel_names:
                target[h] = ("CNAME", f"{tun[1]}.cfargotunnel.com", True)
        for h, ip in direct.items():
            target[h] = ("AAAA" if ":" in ip else "A", ip, False)
        zcache, by_zone = {}, {}
        for h in set(target) | managed:
            z = zone_of(h, zcache)
            if z:
                by_zone.setdefault(z["id"], (z, []))[1].append(h)
            elif h in target:
                res[h] = {"ok": False, "msg": "aucune zone Cloudflare visible avec ce jeton pour ce nom"}
        for zid, (z, hs) in by_zone.items():
            recs = {}
            for r in _records(zid):
                recs.setdefault(r["name"], []).append(r)
            for h in hs:
                have = recs.get(h, [])
                if h not in target:
                    # nom qui n'est plus servi : on retire seulement ce que Hangar avait créé
                    for r in have:
                        if r.get("comment") == COMMENT:
                            _api("DELETE", f"/zones/{zid}/dns_records/{r['id']}")
                            changes.append(f"DNS {h} supprimé")
                    continue
                typ, content, proxied = target[h]
                body = {"type": typ, "name": h, "content": content, "proxied": proxied, "ttl": 1, "comment": COMMENT}
                same = [r for r in have if r["type"] == typ and r["content"] == content]
                if same:
                    r = same[0]
                    if r.get("proxied") != proxied or r.get("comment") != COMMENT:
                        _api("PATCH", f"/zones/{zid}/dns_records/{r['id']}",
                             body={"proxied": proxied, "comment": COMMENT})
                    res[h] = {"ok": True, "msg": "en place"}
                elif len(have) == 1 and have[0].get("comment") == COMMENT:
                    _api("PUT", f"/zones/{zid}/dns_records/{have[0]['id']}", body=body)
                    res[h] = {"ok": True, "msg": "mis à jour"}
                    changes.append(f"DNS {h} mis à jour")
                elif have:
                    kinds = ", ".join(f"{r['type']} {r['content']}" for r in have[:2])
                    res[h] = {"ok": False, "msg": f"nom déjà utilisé dans le DNS ({kinds}) : Hangar ne l'écrase pas"}
                else:
                    _api("POST", f"/zones/{zid}/dns_records", body=body)
                    res[h] = {"ok": True, "msg": "créé"}
                    changes.append(f"DNS {h} créé")
            # certificat universel de Cloudflare : un seul niveau sous la zone
            for h in hs:
                if h in target and target[h][2] and h.count(".") - z["name"].count(".") > 1 and res.get(h, {}).get("ok"):
                    res[h] = {"ok": True, "msg": "en place, mais le certificat gratuit de Cloudflare ne couvre qu'un "
                                                 f"niveau sous {z['name']} : HTTPS échouera sans certificat avancé"}
        db.kv_set("cf_managed", sorted(target))
        st = {"ts": time.time(), "names": res, "error": None, "changes": changes}
        db.kv_set("cf_status", st)
        if changes:
            P.log("ok", "cloudflare", " ; ".join(changes))
        return st
