"""Routage public : Caddyfile (sites, protections, journal), noms publics et tunnel Cloudflare, entrée du trafic
sur les nœuds. Sorti de platform.py, qui ré-exporte ces fonctions : P.render_caddyfile(), P.apply_routing()… restent
valables. Ce qui reste dans platform.py est appelé par P.<nom> (les essais peuvent le remplacer)."""
import base64
import concurrent.futures
import html
import json
import os
import re
import shutil
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

from . import db
from . import domains as D
from . import platform as P


def maintenance(slug=None):
    """Appli(s) en maintenance : {slug: {on, auto, msg, since}}. Caddy y répond par une page 503."""
    m = db.kv_get("maintenance") or {}
    return m.get(slug) if slug else m


def set_maintenance(slug, on, auto=False, msg="", reroute=True):
    """auto : posée par une opération (restauration, import…) et retirée par elle, sans toucher à une maintenance
    posée à la main."""
    with P.routing_lock:
        m = db.kv_get("maintenance") or {}
        cur = m.get(slug)
        if on:
            if cur and not cur.get("auto") and auto:
                return False   # déjà en maintenance à la main : l'opération n'y touche pas
            m[slug] = {"on": True, "auto": auto, "msg": msg[:300], "since": time.time()}
        else:
            if not cur or (auto and not cur.get("auto")):
                return False
            m.pop(slug, None)
        db.kv_set("maintenance", m)
    if reroute:
        try:
            P.apply_routing()
        except RuntimeError as e:
            P.log("warn", slug, f"page de maintenance non appliquée : {e}")
    return True


def _maint_lines(a, ind):
    m = P.maintenance(a["slug"])
    msg = (m.get("msg") or "").strip() or "Le service revient dans quelques minutes. Merci de ta patience."
    body = P.MAINT_HTML.format(msg=html.escape(msg, quote=False), name=html.escape(a["name"], quote=False))
    body = body.replace("`", "'").replace("\n", " ")
    return [f"{ind}header Retry-After 120", f"{ind}header X-Hangar-Maintenance 1", f"{ind}header Cache-Control no-store",
            f'{ind}header Content-Type "text/html; charset=utf-8"', f"{ind}respond `{body}` 503"]


def _upstream(a, prefix, ind, here=P.LOCAL):
    if P.maintenance(a["slug"]):
        return P._maint_lines(a, ind)
    if a["desired"] == "stopped":
        return [f'{ind}respond "Service arrêté" 503']
    from . import ha
    # appli sur ce nœud : en local ; sur un autre nœud : par le réseau privé WireGuard
    nodes = ha.instance_nodes(a)
    hosts = [f"{'127.0.0.1' if n == here else P.node_wg(n)}:{a['host_port']}" for n in nodes]
    lines = [f"{ind}reverse_proxy {' '.join(hosts)} {{",
             f"{ind}\theader_up X-Real-IP {{client_ip}}"]
    if len(hosts) > 1:   # instances multiples : répartition, et une instance qui ne répond plus est écartée
        from . import affinity
        lines += [f"{ind}\t{affinity.caddy_policy(a['slug'])}", f"{ind}\tlb_try_duration 5s",
                  f"{ind}\thealth_uri {a['health_path'] or '/'}", f"{ind}\thealth_interval 10s",
                  f"{ind}\thealth_timeout 3s", f"{ind}\thealth_status 2xx", f"{ind}\tfail_duration 30s"]
    if prefix:
        lines.append(f"{ind}\theader_up X-Forwarded-Prefix {prefix}")
    lines.append(f"{ind}}}")
    return lines


def _site_names(hosts, tunnel, port):
    return ", ".join(f"http://{h}:{port}" if tunnel else h for h in hosts)


def render_caddyfile(s, apps, here=P.LOCAL):
    """Un bloc par nom public, selon le mode de son domaine :
    - tunnel : HTTP sur l'adresse locale de cloudflared (TUNNEL_BIND), TLS terminé chez Cloudflare ; sur la console et
      sur chaque nœud qui reçoit le trafic du tunnel ;
    - direct : Caddy écoute en 80/443 et obtient les certificats Let's Encrypt ; seulement sur la machine d'entrée
      choisie pour ce domaine (celle vers qui pointe le DNS)."""
    doms = D.by_name()
    rts = D.all_routes()
    bind_host, port = s["tunnel_bind"].rsplit(":", 1)
    ingress = here == P.LOCAL or bool(db.one("SELECT 1 FROM nodes WHERE id = ? AND ingress = 1", (here,)))

    def served(d):
        return (ingress and P.tunnel_ready()) if d["mode"] == "tunnel" else (d["entry"] or P.LOCAL) == here
    live = {n: d for n, d in doms.items() if served(d)}
    any_tunnel = any(d["mode"] == "tunnel" for d in live.values())

    L = [f"# Généré par Hangar le {time.strftime('%Y-%m-%d %H:%M:%S')} pour {here}. Ne pas éditer à la main.",
         "{", "\tadmin localhost:2019"]
    if any_tunnel:
        L += [f"\tservers {s['tunnel_bind']} {{",
              "\t\t# cloudflared est sur la même machine : on fait confiance à l'IP client qu'il transmet",
              "\t\ttrusted_proxies static 127.0.0.1/32 ::1",
              "\t\tclient_ip_headers Cf-Connecting-IP X-Forwarded-For",
              "\t}"]
    L += ["}", "",
          "# Journal des requêtes (JSON), lu par Hangar pour les statistiques",
          "(hangar_log) {", "\tlog {", f"\t\toutput file {P.ACCESS_LOG} {{", "\t\t\troll_size 20MiB",
          "\t\t\troll_keep 3", "\t\t}",
          # jamais de secrets dans le journal : sessions, jetons, clés des clients mobiles
          "\t\tformat filter {", "\t\t\twrap json", *[f"\t\t\t{f} delete" for f in P.LOG_SECRET_FIELDS], "\t\t}",
          "\t}", "}", "",
          "# Sites servis par le tunnel : HTTP local seulement",
          f"(tunnel) {{", f"\tbind {bind_host}", "}"]
    by_slug = {a["slug"]: a for a in apps}
    from . import hooks, statuspage
    sp = statuspage.settings()
    for name, d in sorted(live.items(), key=lambda x: (not x[1]["is_default"], x[0])):
        tunnel = d["mode"] == "tunnel"
        L += ["", f"# ---------------- {name} ({'tunnel Cloudflare' if tunnel else 'direct, Let’s Encrypt'})"]
        if statuspage.host(sp) and sp["domain"] == name:
            L += ["", "# page de statut publique", P._site_names([statuspage.host(sp)], tunnel, port) + " {"]
            if tunnel:
                L.append("\timport tunnel")
            L += ["\tencode zstd gzip", f"\troot * {P.PUBLIC}/{statuspage.DIR}", '\theader Cache-Control "public, max-age=30"',
                  "\trewrite * /index.html", "\tfile_server", "}"]
        if d["hub"]:
            L += ["", f"# Routes par chemin sur {d['hub']}.{name}", P._site_names([f"{d['hub']}.{name}"], tunnel, port) + " {"]
            if tunnel:
                L.append("\timport tunnel")
            L += ["\timport hangar_log", "\tencode zstd gzip",
                  "\t# configuration à distance des applis Android (remoteconfig.py)",
                  "\thandle /.well-known/apps/* {", f"\t\troot * {P.PUBLIC}/{name}",
                  '\t\theader Cache-Control "public, max-age=60"', "\t\tfile_server", "\t}",
                  "\t# rapports de plantage (crashes.py) : serveur interne de la console",
                  "\thandle /.well-known/hangar/crash/* {", "\t\trequest_body {", "\t\t\tmax_size 64KB", "\t\t}",
                  f"\t\treverse_proxy {'127.0.0.1' if here == P.LOCAL else P.node_wg(P.LOCAL)}:8099 {{",
                  "\t\t\theader_up X-Real-IP {client_ip}", "\t\t}", "\t}",
                  *hooks.caddy_hub_lines(f"{'127.0.0.1' if here == P.LOCAL else P.node_wg(P.LOCAL)}:8099"),
                  "\thandle /.well-known/apps.json {",
                  f"\t\troot * {P.PUBLIC}/{name}",
                  '\t\theader Cache-Control "public, max-age=300"',
                  "\t\tfile_server", "\t}",
                  "\thandle /health {", '\t\trespond "ok" 200', "\t}",
                  "\t# pages publiques : accueil et règles de confidentialité",
                  "\thandle / {", f"\t\troot * {P.PUBLIC}/{name}", "\t\trewrite * /index.html", "\t\tfile_server", "\t}",
                  "\thandle /confidentialite {", f"\t\troot * {P.PUBLIC}/{name}", "\t\trewrite * /confidentialite.html",
                  "\t\tfile_server", "\t}"]
            for slug, rs in rts.items():
                a = by_slug.get(slug)
                if not a or not any(r["kind"] == "path" and r["domain"] == name for r in rs):
                    continue
                L += ["", f"\t# appli {slug}", f"\tredir /{slug} /{slug}/ 308", f"\thandle_path /{slug}/* {{",
                      f"\t\tlog_append hangar_app {slug}"]
                from . import protect
                L += protect.caddy_lines(slug, "\t\t", site=False)   # mot de passe, adresses autorisées
                from . import kinds, sites
                L += sites.caddy_lines(a, "\t\t") if kinds.static(a["kind"]) else P._upstream(a, f"/{slug}", "\t\t", here)
                L.append("\t}")
            L += ["", "\thandle {", '\t\trespond "Not found" 404', "\t}", "}"]
        for slug, rs in rts.items():
            a = by_slug.get(slug)
            hosts = [D.host_of(r, doms) for r in rs if r["kind"] == "sub" and r["domain"] == name]
            if not a or not hosts:
                continue
            L += ["", f"# appli {slug}", P._site_names(hosts, tunnel, port) + " {"]
            if tunnel:
                L.append("\timport tunnel")
            L += ["\timport hangar_log", f"\tlog_append hangar_app {slug}", "\tencode zstd gzip"]
            L += hooks.caddy_app_lines(slug, f"{'127.0.0.1' if here == P.LOCAL else P.node_wg(P.LOCAL)}:8099")
            from . import protect
            L += protect.caddy_lines(slug, "\t")   # mot de passe, adresses autorisées
            if a["web_client"]:   # client web : script, configuration et envoi des erreurs, sur l'adresse de l'appli
                coll = f"{'127.0.0.1' if here == P.LOCAL else P.node_wg(P.LOCAL)}:8099"
                L += ["\thandle /.well-known/hangar/client.js {", f"\t\troot * {P.PUBLIC}/_clients",
                      "\t\trewrite * /hangar-client.js", '\t\theader Cache-Control "public, max-age=300"', "\t\tfile_server", "\t}",
                      "\thandle /.well-known/hangar/config.json {", f"\t\troot * {P.PUBLIC}/_clients",
                      f"\t\trewrite * /{slug}.json", '\t\theader Cache-Control "no-cache"', "\t\tfile_server", "\t}",
                      "\thandle /.well-known/hangar/crash {", "\t\trequest_body {", "\t\t\tmax_size 64KB", "\t\t}",
                      f"\t\trewrite * /.well-known/hangar/crash/web/{slug}",
                      f"\t\treverse_proxy {coll} {{", "\t\t\theader_up X-Real-IP {client_ip}", "\t\t}", "\t}"]
            from . import kinds, sites
            L += sites.caddy_lines(a, "\t") if kinds.static(a["kind"]) else P._upstream(a, None, "\t", here)
            L.append("}")
    if any_tunnel:
        L += ["", "# Tout autre nom arrivant par le tunnel", f"http://:{port} {{", "\timport tunnel",
              '\trespond "Not found" 404', "}"]
    return "\n".join(L) + "\n"


def tunnel_ready():
    """Le tunnel sert quelque chose : au moins un domaine en mode tunnel."""
    return D.has_mode("tunnel")


def manifests():
    """apps.json de chaque domaine qui a un hôte de routes par chemin : {pkg: adresse de l'appli sur ce domaine}.
    Une appli sans adresse sur ce domaine n'y figure pas."""
    doms = D.by_name()
    rts = D.all_routes()
    out = {}
    for name, d in doms.items():
        if not d["hub"]:
            continue
        m = {}
        for a in db.apps():
            keys = [k for k in (a["pkg"], a["ios_bundle"]) if k]   # package Android et bundle iOS
            if not keys:
                continue
            u = D.primary_url(a["slug"], rts.get(a["slug"], []), doms, domain=name)
            if u:
                for k in keys:
                    m[k] = u
        out[name] = m
    return out


def tunnel_status():
    rc, out = P.run(["systemctl", "is-active", "cloudflared"], timeout=10)
    installed = shutil.which("cloudflared") is not None
    return {"installed": installed, "active": out.strip() == "active",
            "state": out.strip() if installed else "non installé"}


def _doh(name, rtype):
    """Réponse du résolveur public de Cloudflare (DNS sur HTTPS) : True/False, None s'il ne répond pas."""
    url = "https://cloudflare-dns.com/dns-query?" + urllib.parse.urlencode({"name": name, "type": rtype})
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept": "application/dns-json"}),
                                    timeout=2.5) as r:
            d = json.loads(r.read())
    except (OSError, ValueError):
        return None
    return d.get("Status") == 0 and any(a.get("type") in (1, 28) for a in d.get("Answer") or [])


def _resolve(name):
    """Le nom est-il visible d'Internet ? Demandé à un résolveur public, pas à celui de la machine (souvent la box,
    qui garde en cache un « inexistant » jusqu'à 30 minutes après la déclaration)."""
    ok = P._doh(name, "A")
    if ok is False:
        ok = P._doh(name, "AAAA")
    if ok is not None:
        return ok
    try:   # résolveur public injoignable : celui de la machine
        socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)
        return True
    except OSError:
        return False


def resolves(names, ttl=30):
    """{nom: True/False/None} ; None si la résolution n'a pas répondu à temps."""
    now, out, todo = time.time(), {}, {}
    for n in names:
        c = P._dns_cache.get(n)
        if c and now - c[1] < ttl:
            out[n] = c[0]
        else:
            todo[n] = P._dns_pool.submit(P._resolve, n)
    for n, fut in todo.items():
        try:
            out[n] = fut.result(timeout=max(0.1, 3 - (time.time() - now)))
            P._dns_cache[n] = (out[n], time.time())
        except concurrent.futures.TimeoutError:
            out[n] = None
    return out


def public_names(s=None, slug=None):
    """Chaque nom public que Cloudflare (ou le DNS) doit connaître, sans joker, avec son état DNS et Cloudflare."""
    names = D.public_names(slug)
    st = P.resolves([n["name"] for n in names])
    cf = db.kv_get("cf_status") or {}
    for n in names:
        n["ok"] = st[n["name"]]
        n["cf"] = (cf.get("names") or {}).get(n["name"])
    return names


def app_public_names(a, s=None):
    return [n for n in P.public_names(slug=a["slug"]) if n["slug"]]


def parse_tunnel_token(tok):
    """Un jeton de tunnel est du JSON {a: compte, t: id du tunnel, s: secret} encodé en base64."""
    tok = (tok or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]{60,4096}", tok):
        return None
    try:
        raw = base64.b64decode(tok + "=" * (-len(tok) % 4), altchars=b"-_" if "-" in tok or "_" in tok else None)
        d = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        return None
    if not all(isinstance(d.get(k), str) and d[k] for k in ("a", "t", "s")):
        return None
    return {"tunnel_id": d["t"], "token": tok}


def tunnel_id():
    try:
        p = P.parse_tunnel_token(open(P.TUNNEL_TOKEN).read())
    except OSError:
        return None
    return p["tunnel_id"] if p else None


def _tunnel_connected(since, wait=25):
    end = time.time() + wait
    while time.time() < end:
        rc, out = P.run(["journalctl", "-u", "cloudflared", "--since", since, "--no-pager", "-o", "cat"], timeout=10)
        if "Registered tunnel connection" in out:
            return True, ""
        rc2, st = P.run(["systemctl", "is-active", "cloudflared"], timeout=10)
        if st.strip() in ("failed", "inactive"):
            break
        time.sleep(1)
    err = [l for l in out.splitlines() if " ERR " in l or "error" in l.lower()]
    return False, (err[-1] if err else "pas de connexion au bout de 25 s")[-300:]


def set_tunnel_token(tok):
    """Remplace le jeton, redémarre cloudflared, remet l'ancien si la connexion échoue."""
    p = P.parse_tunnel_token(tok)
    if not p:
        raise ValueError("Jeton invalide : copie la longue chaîne affichée après « cloudflared service install ».")
    rc, unit = P.run(["systemctl", "cat", "cloudflared"], timeout=10)
    if rc != 0 or "--token-file" not in unit:
        raise ValueError("Le service cloudflared n'utilise pas /etc/cloudflared/token. Installe-le d'abord (voir README).")
    try:
        old = open(P.TUNNEL_TOKEN).read()
    except OSError:
        old = None
    os.makedirs(os.path.dirname(P.TUNNEL_TOKEN), exist_ok=True)
    P.write_private(P.TUNNEL_TOKEN, p["token"] + "\n")
    since = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 1))
    P.run(["systemctl", "restart", "cloudflared"], timeout=30)
    ok, err = P._tunnel_connected(since)
    if ok:
        P.log("ok", "tunnel", f"jeton du tunnel remplacé, tunnel {p['tunnel_id']} connecté")
        P.sync_all_tunnels()   # les connecteurs des nœuds suivent le même tunnel
        return p["tunnel_id"]
    if old is not None:
        P.write_private(P.TUNNEL_TOKEN, old)
        P.run(["systemctl", "restart", "cloudflared"], timeout=30)
    P.log("error", "tunnel", f"nouveau jeton refusé ({err}), ancien jeton remis")
    raise RuntimeError(f"cloudflared n'a pas pu se connecter avec ce jeton : {err}. L'ancien jeton est remis.")


def _ensure_access_log():
    """`caddy validate` tourne en root : sans ça il créerait le journal en root et Caddy ne pourrait plus y écrire."""
    import grp
    import pwd
    try:
        uid, gid = pwd.getpwnam("caddy").pw_uid, grp.getgrnam("caddy").gr_gid
    except KeyError:
        return
    os.makedirs(os.path.dirname(P.ACCESS_LOG), exist_ok=True)
    if not os.path.exists(P.ACCESS_LOG):
        open(P.ACCESS_LOG, "a").close()
    st = os.stat(P.ACCESS_LOG)
    if (st.st_uid, st.st_gid) != (uid, gid):
        os.chown(P.ACCESS_LOG, uid, gid)
    os.chmod(P.ACCESS_LOG, 0o640)


def apply_routing():
    """Régénère le Caddyfile et apps.json. Ne remplace rien si Caddy refuse la config."""
    with P.routing_lock:
        s, apps = db.settings(), db.apps()
        P._ensure_access_log()
        new = P.CADDYFILE + ".new"
        with open(new, "w") as f:
            f.write(P.render_caddyfile(s, apps))
        rc, out = P.run(["caddy", "validate", "--config", new, "--adapter", "caddyfile"], timeout=60)
        if rc:
            os.remove(new)
            P.log("error", "caddy", "configuration refusée, l'ancienne est conservée : " + P.tail(out, 3))
            raise RuntimeError("Caddy a refusé la nouvelle configuration. Détail dans le journal.")
        if os.path.exists(P.CADDYFILE):
            shutil.copy2(P.CADDYFILE, P.CADDYFILE + ".prev")
        os.replace(new, P.CADDYFILE)
        rc, out = P.run(["systemctl", "reload", "caddy"], timeout=60)
        if rc:
            shutil.copy2(P.CADDYFILE + ".prev", P.CADDYFILE)
            P.run(["systemctl", "reload", "caddy"], timeout=60)
            P.log("error", "caddy", "rechargement impossible, ancienne configuration restaurée : " + P.tail(out, 3))
            raise RuntimeError("Caddy n'a pas pu recharger la configuration. Détail dans le journal.")
        files = P.write_manifests()
        P.push_routing(s, apps, files)
    from . import cloudflare      # noms publics chez Cloudflare (si un jeton d'API est enregistré)
    P.spawn(cloudflare.sync_quiet)
    from . import security
    P.spawn(security.reconcile)   # pare-feu des nœuds : 80/443 suivent les machines d'entrée des domaines directs


def public_pages(host, contact):
    """Page d'accueil et règles de confidentialité du domaine (demandées par Google pour publier l'accès au Drive)."""
    esc = lambda t: html.escape(t, quote=True)
    who = (f'<a href="mailto:{esc(contact)}">{esc(contact)}</a>' if contact else "l'administrateur de ce serveur")
    home = P.PAGE.format(title=f"Hangar · {esc(host)}", host=esc(host), body=f"""<h1>Hangar</h1>
<p class="sub">{esc(host)}</p>
<p>Ce serveur héberge les services de {esc(host.split('.', 1)[-1])} avec Hangar, une console d'hébergement
auto-hébergée et open source : applications web, bases de données, sauvegardes et surveillance.</p>
<h2>Utilisation de Google Drive</h2>
<p>Hangar peut envoyer les sauvegardes chiffrées du serveur dans le Google Drive de son administrateur. Il n'accède
qu'aux fichiers qu'il a créés lui-même (autorisation <code>drive.file</code>) et ne lit aucun autre document.</p>
<p>Contact : {who}.</p>""")
    priv = P.PAGE.format(title=f"Règles de confidentialité · {esc(host)}", host=esc(host), body=f"""<h1>Règles de confidentialité</h1>
<p class="sub">Hangar sur {esc(host)}</p>
<h2>Données consultées</h2>
<p>Quand son administrateur connecte Google Drive, Hangar demande uniquement l'autorisation <code>drive.file</code> :
il voit et modifie seulement les fichiers qu'il a lui-même créés, dans un dossier dédié. Il ne lit ni ne liste aucun
autre fichier du Drive, et n'accède à aucune autre donnée du compte Google (contacts, e-mails, profil).</p>
<h2>Utilisation</h2>
<p>Ces fichiers sont les sauvegardes du serveur. Ils sont chiffrés sur le serveur avant leur envoi : Google ne
reçoit que des données illisibles. Ils servent uniquement à restaurer le serveur après une panne.</p>
<h2>Conservation et partage</h2>
<p>Les sauvegardes sont gardées selon la durée choisie dans la console, puis supprimées. Le jeton d'accès
Google reste sur le serveur. Aucune donnée n'est vendue, partagée avec des tiers ni utilisée à des fins publicitaires.
L'utilisation des données reçues des API Google respecte les
<a href="https://developers.google.com/terms/api-services-user-data-policy">règles relatives aux données utilisateur des services API Google</a>,
y compris les exigences d'utilisation limitée.</p>
<h2>Révocation</h2>
<p>L'accès peut être retiré à tout moment depuis la console (Sauvegardes, Déconnecter) ou sur
<a href="https://myaccount.google.com/permissions">myaccount.google.com/permissions</a>.</p>
<h2>Contact</h2>
<p>{who[0].upper() + who[1:] if not contact else who}.</p>""")
    return {"index.html": home, "confidentialite.html": priv}


def write_manifests():
    """Écrit public/<domaine>/.well-known/apps.json et les pages publiques (accueil, confidentialité) ;
    retourne {chemin relatif: contenu} pour les nœuds."""
    files = {}
    doms = D.by_name()
    contact = db.settings().get("public_contact") or ""
    from . import remoteconfig
    for name, m in P.manifests().items():
        files[f"{name}/.well-known/apps.json"] = json.dumps(m, indent=2, ensure_ascii=False)
        files.update(remoteconfig.files(name, f"{doms[name]['hub']}.{name}", m))
        for fname, content in P.public_pages(f"{doms[name]['hub']}.{name}", contact).items():
            files[f"{name}/{fname}"] = content
    files.update(remoteconfig.web_files())   # clients web : public/_clients/
    from . import statuspage
    if statuspage.host():   # gardée dans l'envoi aux nœuds (qui remplace tout le dossier public)
        files[f"{statuspage.DIR}/index.html"] = statuspage.render()[0]
    for rel in files:
        path = f"{P.PUBLIC}/{rel}"
        os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write(files[rel])
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    keep = {rel.split("/", 1)[0] for rel in files}
    for name in os.listdir(P.PUBLIC) if os.path.isdir(P.PUBLIC) else []:
        if "." in name and not name.startswith(".") and name not in keep:   # domaine retiré ou sans préfixe
            shutil.rmtree(f"{P.PUBLIC}/{name}", ignore_errors=True)
    return files


def ingress_nodes(s=None):
    """Nœuds distants qui reçoivent du trafic Internet : par le tunnel (option « reçoit le trafic ») ou comme
    machine d'entrée d'un domaine en mode direct."""
    direct = {d["entry"] for d in D.all_domains() if d["mode"] == "direct"}
    rows = db.q("SELECT * FROM nodes WHERE id != 'local' AND state IN ('ok', 'offline')")
    return [n for n in rows if (n["ingress"] and P.tunnel_ready()) or n["id"] in direct]


def push_routing(s, apps, files):
    """Envoie à chaque nœud d'entrée sa propre configuration Caddy et les apps.json (en parallèle, erreurs journalisées).
    Un nœud qui ne reçoit plus de trafic garde une configuration vide."""
    targets = P.ingress_nodes(s)
    ids = {n["id"] for n in targets}
    idle = [n for n in db.q("SELECT * FROM nodes WHERE id != 'local' AND state = 'ok'") if n["id"] not in ids]
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for rel, content in files.items():
            data = content.encode()
            ti = tarfile.TarInfo(rel)
            ti.size, ti.mode = len(data), 0o644
            tar.addfile(ti, io.BytesIO(data))
    blob = buf.getvalue()

    def one(n):
        rc, out = P.nsh(n["id"], P.PUSH_CADDY, timeout=60, input=P.render_caddyfile(s, apps, here=n["id"]))
        if rc:
            return f"{n['id']} : " + P.tail(out, 2)
        rc, out = P.nsh(n["id"], P.PUSH_PUBLIC, timeout=30, input=blob)
        if rc:
            return f"{n['id']} : " + P.tail(out, 2)
        if os.path.isdir("/srv/platform/sites"):   # sites statiques servis aussi par ce nœud
            try:
                P.nsh(n["id"], "install -d -m 0755 /srv/platform/sites", timeout=30)
                P.push_dir(n["id"], "/srv/platform/sites", "/srv/platform/sites")
            except Exception as e:
                return f"{n['id']} : sites statiques non copiés ({e})"
        return None

    def empty(n):
        P.nsh(n["id"], P.PUSH_CADDY, timeout=60, input="# Généré par Hangar : ce nœud ne reçoit pas de trafic\n"
                                                  "{\n\tadmin localhost:2019\n}\n")
    if not targets and not idle:
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(targets) + len(idle)) as ex:
        errs = [e for e in ex.map(one, targets) if e]
        list(ex.map(empty, idle))
    for e in errs:
        P.log("warn", "caddy", f"routes non mises à jour sur le nœud {e}")


def sync_tunnel(node_id):
    """Connecteur cloudflared sur un nœud : même jeton que la console si le nœud reçoit le trafic, sinon arrêté."""
    n = P.node_row(node_id)
    if not n or P.is_local(node_id):
        return
    want = bool(n["ingress"]) and P.tunnel_ready() and os.path.exists(P.TUNNEL_TOKEN)
    if want:
        token = open(P.TUNNEL_TOKEN).read().strip()
        rc, out = P.nsh(node_id, "install -d -m 0755 /etc/cloudflared && umask 077 && cat > /etc/cloudflared/token.new && "
                               "mv /etc/cloudflared/token.new /etc/cloudflared/token", timeout=30, input=token + "\n")
        if rc == 0:
            rc, out = P.nsh(node_id, "cat > /etc/systemd/system/cloudflared.service && systemctl daemon-reload && "
                                   "systemctl enable cloudflared >/dev/null 2>&1 && systemctl restart cloudflared",
                          timeout=60, input=P.TUNNEL_UNIT)
        if rc:
            raise RuntimeError(f"connecteur du tunnel non démarré sur {node_id} : " + P.tail(out, 2))
        P.log("ok", f"nœud {node_id}", "connecteur du tunnel Cloudflare actif : ce nœud reçoit aussi le trafic Internet")
    else:
        P.nsh(node_id, "systemctl disable --now cloudflared >/dev/null 2>&1; true", timeout=30)


def sync_all_tunnels():
    for n in db.q("SELECT id FROM nodes WHERE id != 'local' AND state IN ('ok', 'offline')"):
        try:
            P.sync_tunnel(n["id"])
        except RuntimeError as e:
            P.log("warn", f"nœud {n['id']}", str(e))


def rebind_local_apps():
    """Après la création du réseau privé : republie les applis locales aussi sur 10.88.0.1, pour que les Caddy des
    autres nœuds les joignent. Recrée chaque conteneur (quelques secondes), une seule fois."""
    wg = P.node_wg(P.LOCAL)
    if not wg:
        return
    for a in db.apps():
        if not P.is_local(a["node"]) or a["desired"] != "running":
            continue
        d = P.app_dir(a["slug"])
        if not os.path.exists(f"{d}/compose.yml"):
            continue
        rc, ports = P.dk(P.LOCAL, "port", f"app-{a['slug']}-app-1", timeout=15)
        if rc or f"{wg}:{a['host_port']}" in ports:   # conteneur absent, ou déjà publié sur le réseau privé
            continue
        with P.op_lock:
            P.write_compose(a, a["version"])
            rc, out = P.dk(P.LOCAL, "compose", "up", "-d", "--no-build", cwd=d, timeout=300)
            ok, detail = (False, P.tail(out)) if rc else P.wait_health(a)
            P.log("ok" if ok else "error", a["slug"], "publiée aussi sur le réseau privé " + wg
                if ok else f"republication sur le réseau privé en échec : {detail}")
