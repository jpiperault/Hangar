"""Transfert d'un nœud et de ses applis d'une console Hangar (A) à une autre (B), sans copie de données.

Un nœud n'est piloté que par une console à la fois : elle seule a sa clé SSH (limitée à 10.88.0.1, son adresse sur
SON réseau privé), elle seule est son pair WireGuard, elle seule connaît les fiches de ses applis.

1. B prépare une demande de reprise (« HANGAR-REPRISE-1:… ») : ses clés publiques (SSH, WireGuard) et ce qu'elle
   utilise déjà (adresses privées, ports, identifiants d'applis, domaines). Rien de secret.
2. A cède le nœud avec cette demande : contrôles (pas de haute dispo, pas d'identifiant déjà pris chez B…), clé SSH de
   B autorisée sur le nœud, paquet chiffré par un code à usage unique (fiche du nœud, fiches complètes des applis :
   variables, mots de passe de base, adresses, réglages, historique), puis le nœud quitte le réseau privé de A pour
   celui de B (même adresse privée si B ne l'utilise pas), et A oublie le nœud et ses applis SANS les arrêter.
   Les conteneurs, data/, les bases et les services restent en place et continuent de tourner.
3. B reprend le nœud avec le paquet et le code : il rejoint son réseau privé, est remis à niveau par l'installation
   de B (pare-feu, sécurité, cloisonnement, Caddy, tunnel), les fiches sont recréées et les applis redéployées sur
   place (quelques secondes de coupure), puis la clé SSH de A est retirée du nœud.

Entre 2 et 3, les applis tournent mais ne sont plus publiées (adresses retirées par A, ajoutées par B).
"""
import base64
import json
import os
import re
import secrets
import shutil
import socket
import tempfile
import threading
import time

from . import crypt, db, nodes
from . import domains as D
from . import platform as P

REQ_PREFIX = "HANGAR-REPRISE-1:"
DIR = f"{P.BACKUPS}/transferts"
EXPIRE = 7 * 86400
SSH_KEY_RE = re.compile(r"^ssh-ed25519 [A-Za-z0-9+/]{68}(?:={0,2})?(?: [\w.@-]{1,64})?$")
WG_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
KV_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{1,39}$")
# réglages globaux ou propres à la console, jamais repris d'une autre console même s'ils ressemblent à {appli: …}
KV_SKIP = {"user_apps", "ha", "console", "security", "stats_pos", "external_checks", "external_error", "cf_managed",
           "cf_status", "alert_channels", "onboarding_hidden", "transfer_request", "custom_catalog"}
TABLES = (("app_history", "slug"), ("crash_groups", "slug"), ("crashes", "slug"), ("uptime", "app"))
_busy = threading.Lock()


# ---------------------------------------------------------------- console B : demande de reprise

def make_request():
    """Nouvelle demande (remplace la précédente). Retourne le texte à coller dans la console qui cède."""
    nodes.ensure_key()
    nodes.ensure_local()
    nonce = secrets.token_hex(16)
    req = {"v": 1, "nonce": nonce, "created": time.time(), "console": socket.gethostname()[:60],
           "ssh_key": nodes.pubkey(), "wg_pubkey": (nodes.get(nodes.LOCAL) or {}).get("wg_pubkey"),
           "ips": [r["wg_ip"] for r in db.q("SELECT wg_ip FROM nodes")],
           "ports": [r["host_port"] for r in db.q("SELECT host_port FROM apps")],
           "slugs": [r["slug"] for r in db.q("SELECT slug FROM apps")],
           "nodes": [r["id"] for r in db.q("SELECT id FROM nodes")],
           "addresses": [r["address"] for r in db.q("SELECT address FROM nodes WHERE id != 'local'")],
           "domains": [d["name"] for d in D.all_domains()]}
    text = REQ_PREFIX + base64.urlsafe_b64encode(json.dumps(req, separators=(",", ":")).encode()).decode()
    db.kv_set("transfer_request", {"nonce": nonce, "created": req["created"], "text": text})
    return text


def pending_request():
    r = db.kv_get("transfer_request")
    return r if r and time.time() - r.get("created", 0) < EXPIRE else None


def cancel_request():
    db.x("DELETE FROM kv WHERE key = 'transfer_request'")


def parse_request(text):
    """Demande collée dans la console qui cède : décodée et vérifiée. ValueError sinon."""
    t = re.sub(r"\s+", "", text or "")
    if not t.startswith(REQ_PREFIX):
        raise ValueError("Ce texte n'est pas une demande de reprise Hangar (il commence par HANGAR-REPRISE-1:).")
    try:
        req = json.loads(base64.urlsafe_b64decode(t[len(REQ_PREFIX):] + "=" * (-len(t) % 4)))
    except (ValueError, TypeError):
        raise ValueError("Demande de reprise illisible : recopie-la en entier.")
    if not isinstance(req, dict) or req.get("v") != 1:
        raise ValueError("Demande de reprise d'une version inconnue.")
    if time.time() - float(req.get("created") or 0) > EXPIRE:
        raise ValueError("Demande de reprise expirée (7 jours) : prépares-en une nouvelle sur l'autre console.")
    if not SSH_KEY_RE.match(str(req.get("ssh_key") or "")) or not WG_KEY_RE.match(str(req.get("wg_pubkey") or "")):
        raise ValueError("Demande de reprise invalide (clés).")
    if not re.fullmatch(r"[0-9a-f]{32}", str(req.get("nonce") or "")):
        raise ValueError("Demande de reprise invalide.")
    for k, typ in (("ips", str), ("ports", int), ("slugs", str), ("nodes", str), ("addresses", str), ("domains", str)):
        v = req.get(k) or []
        if not isinstance(v, list) or len(v) > 5000 or not all(isinstance(x, typ) for x in v):
            raise ValueError(f"Demande de reprise invalide ({k}).")
        req[k] = v
    if req["ssh_key"].split()[1] == nodes.pubkey().split()[1]:
        raise ValueError("Cette demande vient de cette console-ci : prépare-la sur la console qui reprend le nœud.")
    req["console"] = re.sub(r"[^\w.-]", "", str(req.get("console") or "?"))[:60] or "?"
    return req


# ---------------------------------------------------------------- console A : cession

def _apps_on(node_id):
    return db.q("SELECT * FROM apps WHERE node = ? ORDER BY slug", (node_id,))


def _new_ip(n, req):
    if n["wg_ip"] not in req["ips"]:
        return n["wg_ip"]
    for h in nodes.WG_NET.hosts():
        if str(h) not in req["ips"] and str(h) != nodes.WG_LOCAL:
            return str(h)
    raise ValueError("Plus d'adresse privée libre sur l'autre console.")


def check(node_id, req):
    """Ce que la cession ferait : {node, apps, errors, warnings, ip}. Les erreurs l'empêchent."""
    from . import ha, preprod
    n = nodes.get(node_id)
    errors, warnings = [], []
    if not n or node_id == nodes.LOCAL:
        raise ValueError("Nœud inconnu.")
    if n["state"] != "ok" or not nodes._wg_alive(n):
        errors.append("Le nœud doit être en ligne et joignable par le réseau privé.")
    if node_id in ha.participants():
        errors.append("Le nœud sert à la haute dispo d'une appli (secours ou instance) : retire-la d'abord.")
    if n["address"] in req["addresses"]:
        errors.append("L'autre console a déjà un nœud à cette adresse.")
    apps = []
    links = preprod.links()
    for a in _apps_on(node_id):
        e = {"slug": a["slug"], "name": a["name"], "notes": []}
        if ha.get(a["slug"]):
            errors.append(f"{a['name']} est en haute dispo : retire-la d'abord.")
        if a["slug"] in req["slugs"]:
            errors.append(f"L'identifiant {a['slug']} ({a['name']}) existe déjà sur l'autre console.")
        other = links.get(a["slug"]) or next((p for p, prod in links.items() if prod == a["slug"]), None)
        if other and (db.app(other) or {}).get("node") != node_id:
            errors.append(f"{a['name']} est liée à une préproduction sur un autre nœud : sépare-les d'abord.")
        if a["host_port"] in req["ports"]:
            e["notes"].append("port interne pris là-bas : redéployée avec un autre (quelques secondes de coupure)")
        lost = [r for r in D.export_routes(a["slug"]) if r["domain"] not in req["domains"]]
        if lost:
            e["notes"].append("adresses perdues (domaine absent là-bas) : " + ", ".join(
                (f"{r['sub']}.{r['domain']}" if r["sub"] else r["domain"]) if r["kind"] == "sub" else f"chemin sur {r['domain']}"
                for r in lost))
        from . import hooks
        if (hooks.of(a["slug"]) or {}).get("secret"):
            e["notes"].append("webhook GitHub : son adresse change, à refaire dans GitHub")
        apps.append(e)
    ip = _new_ip(n, req)
    if ip != n["wg_ip"]:
        warnings.append(f"Adresse privée {n['wg_ip']} déjà prise là-bas : le nœud devient {ip} et ses applis sont "
                        "redéployées (quelques secondes de coupure chacune).")
    warnings.append("Entre la cession et la reprise, les applis tournent mais ne sont plus publiées sur Internet.")
    warnings.append("Les sauvegardes déjà faites restent ici ; l'autre console sauvegarde les applis dès la reprise.")
    if db.kv_get("user_apps"):
        warnings.append("Les droits des comptes « appli » ne sont pas repris : à redonner sur l'autre console.")
    return {"node": n, "apps": apps, "errors": errors, "warnings": warnings, "ip": ip, "to": req["console"]}


def _code():
    abc = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "-".join("".join(secrets.choice(abc) for _ in range(5)) for _ in range(4))


def _app_export(a):
    slug = a["slug"]
    row = {k: a.get(k) for k in db.APP_FIELDS if k not in ("node", "state")}
    kv = {}
    for r in db.q("SELECT key, value FROM kv"):
        if r["key"] in KV_SKIP or not KV_KEY_RE.match(r["key"]):
            continue
        try:
            v = json.loads(r["value"])
        except ValueError:
            continue
        if isinstance(v, dict) and slug in v:
            kv[r["key"]] = v[slug]
    tables = {}
    for t, col in TABLES:
        try:
            tables[t] = db.q(f"SELECT * FROM {t} WHERE {col} = ?", (slug,))
        except Exception:
            tables[t] = []
    for t in tables.values():
        for r in t:
            r.pop("id", None)
    return {"slug": slug, "row": row, "routes": D.export_routes(slug), "kv": kv, "tables": tables,
            "smoke_last": db.kv_get(f"smoke_last:{slug}")}


def _forget_app(slug):
    """Oublie une appli ici sans toucher à ses conteneurs ni à ses fichiers sur le nœud."""
    for r in db.q("SELECT key, value FROM kv"):
        try:
            v = json.loads(r["value"])
        except ValueError:
            continue
        if isinstance(v, dict) and slug in v and r["key"] != "user_apps":
            v.pop(slug)
            db.kv_set(r["key"], v)
    from . import perms, preprod
    perms.forget_app(slug)
    preprod.forget(slug)
    for t, col in TABLES:
        try:
            db.x(f"DELETE FROM {t} WHERE {col} = ?", (slug,))
        except Exception:
            pass
    for t in ("stats_req", "stats_res"):
        db.x(f"DELETE FROM {t} WHERE app = ? OR app LIKE ?", (slug, f"{slug}:%"))
    db.x("DELETE FROM stats_disk WHERE app = ?", (slug,))
    db.x("DELETE FROM kv WHERE key = ?", (f"smoke_last:{slug}",))
    db.x("DELETE FROM apps WHERE slug = ?", (slug,))
    D.set_routes(slug, [])
    d = P.app_dir(slug)
    if os.path.isdir(d):   # copie des réglages côté console (le vrai dossier est sur le nœud)
        shutil.rmtree(d, ignore_errors=True)


def _wg_switch(n, ip, req):
    """Programme sur le nœud son passage au réseau privé de l'autre console (dans 5 s, après la fin de la session SSH)."""
    conf = "\n".join(["# Généré par Hangar (cédé à une autre console). Ne pas modifier à la main.", "[Interface]",
                      f"Address = {ip}/24", "PrivateKey = __HANGAR_KEY__", f"ListenPort = {nodes.WG_PORT}", "",
                      f"# console {req['console']}", "[Peer]", f"PublicKey = {req['wg_pubkey']}",
                      f"AllowedIPs = {nodes.WG_LOCAL}/32", "PersistentKeepalive = 25"]) + "\n"
    script = (f"set -e; umask 077; cat > /etc/wireguard/hangar-next.conf; "
              f"systemctl disable --now cloudflared >/dev/null 2>&1 || true; "
              f"systemd-run --quiet --collect --unit=hangar-transfer-wg --on-active=5 /bin/sh -c "
              f"'sed \"s|__HANGAR_KEY__|$(cat {nodes.WG_KEY})|\" /etc/wireguard/hangar-next.conf > "
              f"/etc/wireguard/{nodes.WG_IF}.conf && rm -f /etc/wireguard/hangar-next.conf && "
              f"systemctl restart wg-quick@{nodes.WG_IF}'")
    rc, out = nodes.ssh(n, script, input=conf, timeout=60)
    if rc:
        raise RuntimeError("bascule du réseau privé impossible : " + P.tail(out, 2))


def cede(node_id, req, user):
    """Cède le nœud à la console de la demande. Retourne {code, file}. ValueError / RuntimeError sinon."""
    if not _busy.acquire(blocking=False):
        raise ValueError("Un transfert est déjà en cours.")
    try:
        with P.op_lock:
            c = check(node_id, req)
            if c["errors"]:
                raise ValueError(" ".join(c["errors"]))
            n = c["node"]
            key = req["ssh_key"].split()
            line = f'from="{nodes.WG_LOCAL}" {key[0]} {key[1]} hangar@console'
            rc, out = nodes.ssh(n, "set -e; install -d -m 0700 /root/.ssh; touch /root/.ssh/authorized_keys; "
                                   "chmod 600 /root/.ssh/authorized_keys; read -r l; "
                                   "grep -qF \"$l\" /root/.ssh/authorized_keys || echo \"$l\" >> /root/.ssh/authorized_keys",
                                input=line + "\n", timeout=30)
            if rc:
                raise RuntimeError("clé de l'autre console non autorisée sur le nœud : " + P.tail(out, 2))
            apps = _apps_on(node_id)
            pkg = {"v": 1, "kind": "hangar-noeud", "nonce": req["nonce"], "created": time.time(),
                   "from": socket.gethostname()[:60], "old_key": nodes.pubkey().split()[1],
                   "node": {"id": n["id"], "name": n["name"], "address": n["address"], "ssh_port": n["ssh_port"],
                            "ssh_user": n.get("ssh_user") or "root", "ingress": n.get("ingress", 1),
                            "wg_pubkey": n["wg_pubkey"], "wg_ip": c["ip"], "old_wg_ip": n["wg_ip"]},
                   "apps": [_app_export(a) for a in apps]}
            os.makedirs(DIR, mode=0o700, exist_ok=True)
            code = _code()
            name = f"{node_id}-{time.strftime('%Y%m%d-%H%M%S')}.hangar-noeud"
            fd, tmp = tempfile.mkstemp(dir=DIR, prefix=".clair-")
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(pkg, f, ensure_ascii=False)
                crypt.encrypt_file(tmp, f"{DIR}/{name}", code)
            finally:
                os.remove(tmp)
            _wg_switch(n, c["ip"], req)
            for a in apps:
                _forget_app(a["slug"])
                P.log("warn", a["slug"], f"cédée à la console {req['console']} avec le nœud {node_id} (toujours en marche là-bas)")
            db.x("DELETE FROM nodes WHERE id = ?", (node_id,))
            db.x("DELETE FROM stats_node WHERE node = ?", (node_id,))
            db.x("DELETE FROM kv WHERE key IN (?, ?)", (f"diskuse:{node_id}", f"stats_pos_{node_id}"))
            db.kv_set(f"transfer_out:{node_id}", {"file": name, "code": code, "created": time.time(),
                                                  "to": req["console"], "apps": [a["slug"] for a in apps], "by": user})
        P.log("warn", f"nœud {node_id}", f"cédé à la console {req['console']} par {user} avec {len(apps)} appli(s) ; "
                                         "à reprendre là-bas avec le paquet et le code")
        for fn in (nodes.apply_mesh, P.apply_routing):
            try:
                fn()
            except RuntimeError as e:
                P.log("warn", f"nœud {node_id}", str(e))
        from . import ha
        P.spawn(ha.push_fence_all)
        return {"code": code, "file": name}
    finally:
        _busy.release()


def ceded():
    """Cessions des 7 derniers jours : paquet encore téléchargeable, avec son code."""
    out = []
    for r in db.q("SELECT key, value FROM kv WHERE key LIKE 'transfer_out:%'"):
        v = json.loads(r["value"])
        if time.time() - v.get("created", 0) > EXPIRE or not os.path.exists(f"{DIR}/{v['file']}"):
            db.x("DELETE FROM kv WHERE key = ?", (r["key"],))
            if os.path.exists(f"{DIR}/{v.get('file')}"):
                os.remove(f"{DIR}/{v['file']}")
            continue
        out.append({"node": r["key"].split(":", 1)[1], **v})
    return sorted(out, key=lambda x: -x["created"])


def package_path(node_id):
    v = db.kv_get(f"transfer_out:{node_id}")
    if not v or not re.fullmatch(r"[a-z0-9-]+-\d{8}-\d{6}\.hangar-noeud", v.get("file", "")):
        return None
    p = f"{DIR}/{v['file']}"
    return p if os.path.exists(p) else None


# ---------------------------------------------------------------- console B : reprise

def read_package(path, code):
    """Paquet déchiffré et vérifié (contre la demande en attente ici). ValueError sinon."""
    fd, clear = tempfile.mkstemp(prefix="hangar-noeud-")
    os.close(fd)
    try:
        try:
            crypt.decrypt_file(path, clear, [re.sub(r"\s+", "", (code or "").upper())])
        except ValueError:
            raise ValueError("Code incorrect, ou fichier abîmé.")
        if os.path.getsize(clear) > 50 * 1024 * 1024:
            raise ValueError("Paquet trop gros.")
        try:
            pkg = json.load(open(clear))
        except ValueError:
            raise ValueError("Ce fichier n'est pas un paquet de nœud Hangar.")
    finally:
        if os.path.exists(clear):
            os.remove(clear)
    if not isinstance(pkg, dict) or pkg.get("kind") != "hangar-noeud" or pkg.get("v") != 1:
        raise ValueError("Ce fichier n'est pas un paquet de nœud Hangar.")
    req = pending_request()
    if not req or pkg.get("nonce") != req["nonce"]:
        raise ValueError("Ce paquet ne répond pas à la demande de reprise en cours ici (prépare la demande ici, "
                         "puis cède le nœud avec elle sur l'autre console).")
    n = pkg.get("node") or {}
    if not (isinstance(n.get("id"), str) and nodes.ID_RE.match(n["id"]) and n["id"] != nodes.LOCAL
            and isinstance(n.get("address"), str) and re.fullmatch(r"[A-Za-z0-9.:-]{1,253}", n["address"])
            and isinstance(n.get("ssh_port"), int) and 1 <= n["ssh_port"] <= 65535
            and isinstance(n.get("ssh_user"), str) and nodes.USER_RE.match(n["ssh_user"])
            and WG_KEY_RE.match(str(n.get("wg_pubkey") or ""))
            and isinstance(n.get("wg_ip"), str) and n["wg_ip"] in {str(h) for h in nodes.WG_NET.hosts()}):
        raise ValueError("Paquet invalide (nœud).")
    if not re.fullmatch(r"[A-Za-z0-9+/]{68}={0,2}", str(pkg.get("old_key") or "")):
        raise ValueError("Paquet invalide (clé).")
    if db.one("SELECT 1 FROM nodes WHERE wg_ip = ?", (n["wg_ip"],)):
        raise ValueError(f"L'adresse privée {n['wg_ip']} a été prise ici depuis la demande : refais la demande et la cession.")
    if db.one("SELECT 1 FROM nodes WHERE address = ?", (n["address"],)):
        raise ValueError("Ce serveur est déjà un nœud de cette console.")
    apps = pkg.get("apps")
    if not isinstance(apps, list):
        raise ValueError("Paquet invalide (applis).")
    for e in apps:
        row = (e or {}).get("row") if isinstance(e, dict) else None
        if not isinstance(row, dict) or e.get("slug") != row.get("slug", e.get("slug")):
            raise ValueError("Paquet invalide (appli).")
        bad = P.check_app_entry({**row, "slug": e.get("slug")})
        if bad:
            raise ValueError(f"Paquet refusé : appli « {str(e.get('slug'))[:40]} » invalide ({', '.join(bad)}).")
        if db.app(e["slug"]):
            raise ValueError(f"L'appli {e['slug']} existe déjà ici.")
    pkg["from"] = re.sub(r"[^\w.-]", "", str(pkg.get("from") or "?"))[:60] or "?"
    return pkg


def _node_id(want):
    nid, i = want, 2
    while nodes.get(nid):
        nid, i = f"{want[:27]}-{i}", i + 1
    return nid


def takeover(path, code, user):
    """Vérifie le paquet, enregistre le nœud et lance la reprise en tâche de fond. Retourne l'identifiant du nœud."""
    pkg = read_package(path, code)
    n = pkg["node"]
    nodes.ensure_key()
    nodes.ensure_local()
    nid = _node_id(n["id"])
    db.x("INSERT INTO nodes(id, name, address, ssh_port, ssh_user, wg_ip, wg_pubkey, state, created_at) "
         "VALUES(?, ?, ?, ?, ?, ?, ?, 'installing', ?)",
         (nid, str(n.get("name") or nid)[:60], n["address"], n["ssh_port"], n["ssh_user"], n["wg_ip"],
          n["wg_pubkey"], time.time()))
    if n.get("ingress") in (0, 1):
        nodes._update(nid, ingress=n["ingress"])
    db.kv_set(f"transfer_in:{nid}", pkg)   # gardé jusqu'au bout : « Réessayer » repart de là
    cancel_request()
    P.log("info", f"nœud {nid}", f"reprise depuis la console {pkg['from']} par {user} : {len(pkg['apps'])} appli(s)")
    P.spawn(resume, nid)
    return nid


def pending_takeovers():
    return [r["key"].split(":", 1)[1] for r in db.q("SELECT key FROM kv WHERE key LIKE 'transfer_in:%'")]


def _restore_app(e, nid):
    """Recrée la fiche d'une appli (ligne, adresses, historique, plantages). Tout ou rien : en cas d'erreur, ce qui a
    été écrit est retiré, et « Réessayer » repart de zéro pour elle. Retourne True si son port interne a changé."""
    slug = e["slug"]
    row = e["row"]
    data = {k: row.get(k) for k in db.APP_FIELDS if k in row and k not in ("node", "state", "host_port")}
    used = {r["host_port"] for r in db.q("SELECT host_port FROM apps")}
    hp = row.get("host_port")
    data["host_port"] = hp if isinstance(hp, int) and hp >= P.HOST_PORT_MIN and hp not in used else P.next_host_port()
    data.update(node=nid, state="deploying", desired=row.get("desired") or "running")
    data.setdefault("created_at", time.time())
    from . import history
    history.init()          # table créée à la première utilisation : absente sur une console neuve
    db.insert_app(slug, data)
    try:
        rts, dropped = D.usable_routes(slug, e.get("routes"))
        D.set_routes(slug, rts)
        if dropped:
            P.log("warn", slug, "adresses non reprises : " + ", ".join(dropped))
        if isinstance(e.get("smoke_last"), dict):
            db.kv_set(f"smoke_last:{slug}", e["smoke_last"])
        for t, col in TABLES:
            rows = (e.get("tables") or {}).get(t) or []
            cols = {r["name"] for r in db.q(f"PRAGMA table_info({t})")} - {"id"}
            if not rows or not cols:
                continue
            for r in rows[:20000]:
                if not isinstance(r, dict):
                    continue
                r = {k: v for k, v in r.items() if k in cols}
                r[col] = slug
                db.x(f"INSERT OR IGNORE INTO {t}({', '.join(r)}) VALUES({', '.join('?' * len(r))})", list(r.values()))
    except Exception:
        for t, col in TABLES:
            if db.q(f"PRAGMA table_info({t})"):
                db.x(f"DELETE FROM {t} WHERE {col} = ?", (slug,))
        D.set_routes(slug, [])
        db.x("DELETE FROM apps WHERE slug = ?", (slug,))
        raise
    os.makedirs(P.app_dir(slug), mode=0o700, exist_ok=True)
    return data["host_port"] != hp


def _merge_kv(apps):
    """Réglages des applis ({clé: {appli: valeur}}) fusionnés dans ceux d'ici. Sans effet s'ils y sont déjà."""
    for k in {k for e in apps for k in (e.get("kv") or {})}:
        if not KV_KEY_RE.match(k) or k in KV_SKIP:
            continue
        cur = db.kv_get(k)
        if cur is None:
            cur = {}
        if not isinstance(cur, dict):
            continue
        for e in apps:
            if k in (e.get("kv") or {}):
                cur[e["slug"]] = e["kv"][k]
        db.kv_set(k, cur)


def resume(nid):
    """Reprise (ou nouvel essai) : réseau privé, installation de cette console, fiches, redéploiement, clé de A retirée."""
    pkg = db.kv_get(f"transfer_in:{nid}")
    if not pkg:
        return
    tag = f"nœud {nid}"
    try:
        nodes._update(nid, state="installing", error=None)
        try:
            nodes.apply_mesh()
        except RuntimeError:
            pass    # le nouveau nœud n'est pas encore joignable : normal, on attend le lien
        n = nodes.get(nid)
        for _ in range(60):
            if nodes._wg_alive(n, 60) and P.run(["ping", "-c1", "-W1", n["wg_ip"]], timeout=5)[0] == 0:
                break
            time.sleep(2)
        else:
            raise RuntimeError(f"le nœud ne répond pas sur le réseau privé ({n['wg_ip']}) : la cession a-t-elle été "
                               "faite sur l'autre console ? (UDP 51820 vers le nœud)")
        P.log("info", tag, "relié au réseau privé de cette console : remise à niveau (installation)")
        nodes.install(nid)
        if (nodes.get(nid) or {}).get("state") != "ok":
            raise RuntimeError("installation en échec : voir le journal du nœud, puis « Réessayer »")
        moved = []
        for e in pkg["apps"]:
            if not db.app(e["slug"]) and _restore_app(e, nid):
                moved.append(e["slug"])
        _merge_kv(pkg["apps"])
        from . import segment
        try:
            segment.push(nid)
        except RuntimeError as ex:
            P.log("warn", tag, str(ex))
        P.apply_routing()
        ip_changed = pkg["node"]["wg_ip"] != pkg["node"].get("old_wg_ip")
        from . import kinds
        for e in pkg["apps"]:
            a = db.app(e["slug"])
            if not a or a["node"] != nid:
                continue
            if kinds.static(a["kind"]) or a["desired"] == "stopped":
                db.update_app(a["slug"], state="ok")
                continue
            if not ip_changed and e["slug"] not in moved:
                P.log("info", a["slug"], f"reprise depuis la console {pkg['from']} : réglages de cette console appliqués")
            P.deploy(a["slug"], a["version"], "config")
        old = pkg["old_key"]
        rc, out = nodes.ssh(nodes.get(nid), "f=/root/.ssh/authorized_keys; [ -f $f ] || exit 0; read -r k; "
                                            "grep -vF \"$k\" $f > $f.hangar || true; cat $f.hangar > $f; rm -f $f.hangar",
                            input=old + "\n", timeout=30)
        if rc:
            P.log("warn", tag, "clé SSH de l'ancienne console non retirée : " + P.tail(out, 2))
        db.x("DELETE FROM kv WHERE key = ?", (f"transfer_in:{nid}",))
        P.log("ok", tag, f"repris depuis la console {pkg['from']} : {len(pkg['apps'])} appli(s) ; clé de l'ancienne "
                         "console retirée du nœud")
    except Exception as ex:
        nodes._update(nid, state="error", error=str(ex)[:500])
        P.log("error", tag, f"reprise en échec : {ex}")


def abandon(nid):
    """Abandonne une reprise en échec : le nœud est oublié ici (rien n'est touché sur la machine)."""
    if not db.kv_get(f"transfer_in:{nid}"):
        raise ValueError("Pas de reprise en cours pour ce nœud.")
    if db.one("SELECT 1 FROM apps WHERE node = ?", (nid,)):
        raise ValueError("Des applis de ce nœud sont déjà reprises ici : utilise « Réessayer ».")
    db.x("DELETE FROM kv WHERE key = ?", (f"transfer_in:{nid}",))
    db.x("DELETE FROM nodes WHERE id = ?", (nid,))
    try:
        nodes.apply_mesh()
    except RuntimeError:
        pass
