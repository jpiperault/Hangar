"""Catalogue d'applis prêtes : des applis open source dont les réglages sont déjà faits (image, port, adresse de
santé, mémoire, base, variables). On choisit l'adresse et la machine ; Hangar crée l'appli comme une autre.

Variables : les valeurs entre accolades sont remplies à l'installation :
  {url}         adresse publique (https://…/)        {host}  son nom (sans https)
  {db_url}      DATABASE_URL (libpq)                  {db_host} {db_port} {db_name} {db_user} {db_password}
  {secret}      chaîne aléatoire (64 caractères hexadécimaux), une nouvelle à chaque occurrence
  {mysql_password}  mot de passe de la base MySQL/MariaDB de l'appli (hôte mysql, base et utilisateur app)
  {mail_host}   nom du serveur mail (applis « mail » : ports publics et enregistrements DNS, voir mail.py)
Seules les applis qui tiennent dans le modèle de Hangar y sont : un conteneur, données dans /data (ou dans des
dossiers de data/ montés ailleurs : « mounts »), PostgreSQL, MySQL/MariaDB (« mysql » : moteur) ou rien.
"""
import re
import secrets

from . import db

CATS = {"perso": "Mes modèles", "site": "Sites et blogs", "stats": "Statistiques et surveillance", "secu": "Sécurité",
        "mail": "Messagerie", "dev": "Développement", "auto": "Automatisation", "doc": "Documentation", "tools": "Outils"}

CATALOG = [
    {"id": "wordpress", "name": "WordPress", "cat": "site", "color": "#21759b",
     "desc": "Le moteur de sites et de blogs le plus répandu, avec ses thèmes et extensions.",
     "image": "wordpress", "version": "6-apache", "port": 80, "health": "/wp-includes/images/blank.gif", "mem": 256,
     "db": False, "mysql": "mariadb", "mysql_mem": 256, "mounts": "www:/var/www/html",
     "env": ("WORDPRESS_DB_HOST=mysql\nWORDPRESS_DB_NAME=app\nWORDPRESS_DB_USER=app\n"
             "WORDPRESS_DB_PASSWORD={mysql_password}\n"
             "WORDPRESS_CONFIG_EXTRA=define('WP_HOME', '{url_noslash}'); define('WP_SITEURL', '{url_noslash}');"),
     "after": "L'assistant d'installation s'ouvre à la première visite : choisis-y le compte administrateur. "
              "Extensions et médias sont gardés dans data/www.",
     "site": "https://wordpress.org"},
    {"id": "ghost", "name": "Ghost", "cat": "site", "color": "#15171a",
     "desc": "Blog et lettre d'information modernes, avec abonnements.",
     "image": "ghost", "version": "6-alpine", "port": 2368, "health": "/favicon.ico", "mem": 512,
     "db": False, "mysql": "mysql", "mysql_mem": 512, "mounts": "content:/var/lib/ghost/content",
     "env": ("url={url_noslash}\ndatabase__client=mysql\ndatabase__connection__host=mysql\n"
             "database__connection__user=app\ndatabase__connection__password={mysql_password}\n"
             "database__connection__database=app"),
     "after": "Crée le compte propriétaire sur /ghost à la première visite. Pour les invitations et les lettres, "
              "règle l'envoi d'e-mails (variables mail__…, voir la documentation de Ghost).",
     "site": "https://ghost.org"},
    {"id": "umami", "name": "Umami", "cat": "stats", "color": "#1f2a44",
     "desc": "Statistiques de visite simples, sans cookies, respectueuses de la vie privée.",
     "image": "ghcr.io/umami-software/umami", "version": "postgresql-latest", "port": 3000,
     "health": "/api/heartbeat", "mem": 384, "db": True,
     "env": "APP_SECRET={secret}",
     "after": "Connexion avec admin / umami : change ce mot de passe tout de suite.",
     "site": "https://umami.is"},
    {"id": "uptime-kuma", "name": "Uptime Kuma", "cat": "stats", "color": "#2f7a3d",
     "desc": "Surveillance de sites et de services extérieurs, avec alertes et pages de statut.",
     "image": "louislam/uptime-kuma", "version": "1", "port": 3001, "health": "/", "mem": 256, "db": False,
     "env": "DATA_DIR=/data/",
     "after": "Le compte administrateur se crée à la première visite.",
     "site": "https://github.com/louislam/uptime-kuma"},
    {"id": "vaultwarden", "name": "Vaultwarden", "cat": "secu", "color": "#175ddc",
     "desc": "Gestionnaire de mots de passe compatible avec les applis et extensions Bitwarden.",
     "image": "vaultwarden/server", "version": "latest", "port": 80, "health": "/alive", "mem": 128, "db": False,
     "env": "DOMAIN={url}\nSIGNUPS_ALLOWED=true\nADMIN_TOKEN={secret}",
     "after": "Crée ton compte, puis mets SIGNUPS_ALLOWED=false dans ses variables. Le jeton d'administration (/admin) est dans ses variables.",
     "site": "https://github.com/dani-garcia/vaultwarden"},
    # variante alpine : l'image standard exige un processeur x86-64-v2 (SSE4.2), absent des vieux serveurs (Atom…)
    {"id": "stalwart", "name": "Stalwart", "cat": "mail", "color": "#d6402c",
     "desc": "Serveur de messagerie complet : SMTP, IMAP, JMAP, agendas et contacts, anti-spam, DKIM, avec administration "
             "web et espace personnel pour chaque utilisateur.",
     "image": "stalwartlabs/stalwart", "version": "v1.1-alpine", "port": 8080, "health": "/healthz/live", "mem": 512, "db": False,
     "mounts": "etc:/etc/stalwart, lib:/var/lib/stalwart", "data_user": "2000:2000",
     "mail": True, "ports": "tcp 25, tcp 465, tcp 587, tcp 993",
     "env": "STALWART_RECOVERY_ADMIN=admin:{secret}\nSTALWART_PUBLIC_URL={url_noslash}\nSTALWART_HOSTNAME={mail_host}",
     "after": "Connecte-toi sur /admin avec admin et le mot de passe de STALWART_RECOVERY_ADMIN (ses variables), puis suis "
              "l'assistant : nom du serveur = celui choisi ici, domaine des adresses, stockage RocksDB, journaux sur la "
              "console, certificat par DNS Cloudflare (un jeton limité à la zone). Redémarre l'appli à la fin, publie "
              "la clé DKIM qu'il affiche, puis retire STALWART_RECOVERY_ADMIN de ses variables. Chacun gère son compte "
              "sur /account.",
     "site": "https://stalw.art"},
    {"id": "gitea", "name": "Gitea", "cat": "dev", "color": "#609926",
     "desc": "Hébergement Git léger : dépôts, tickets, revues, paquets.",
     "image": "gitea/gitea", "version": "1", "port": 3000, "health": "/api/healthz", "mem": 384, "db": True,
     "env": ("GITEA__database__DB_TYPE=postgres\nGITEA__database__HOST={db_host}:{db_port}\nGITEA__database__NAME={db_name}\n"
             "GITEA__database__USER={db_user}\nGITEA__database__PASSWD={db_password}\nGITEA__server__ROOT_URL={url}\n"
             "GITEA__server__DOMAIN={host}\nGITEA__server__DISABLE_SSH=true\nGITEA__security__INSTALL_LOCK=true\n"
             "GITEA__security__SECRET_KEY={secret}\nGITEA__service__DISABLE_REGISTRATION=false"),
     "after": "Le premier compte créé devient administrateur ; ferme ensuite les inscriptions (GITEA__service__DISABLE_REGISTRATION=true). Git par HTTPS seulement.",
     "site": "https://gitea.com"},
    {"id": "n8n", "name": "n8n", "cat": "auto", "color": "#c43d5c",
     "desc": "Automatisations entre services (webhooks, API, e-mails), sans code.",
     "image": "n8nio/n8n", "version": "latest", "port": 5678, "health": "/healthz", "mem": 512, "db": True,
     "env": ("N8N_USER_FOLDER=/data\nDB_TYPE=postgresdb\nDB_POSTGRESDB_HOST={db_host}\nDB_POSTGRESDB_PORT={db_port}\n"
             "DB_POSTGRESDB_DATABASE={db_name}\nDB_POSTGRESDB_USER={db_user}\nDB_POSTGRESDB_PASSWORD={db_password}\n"
             "N8N_ENCRYPTION_KEY={secret}\nWEBHOOK_URL={url}\nN8N_PROXY_HOPS=1\nN8N_DIAGNOSTICS_ENABLED=false"),
     "after": "Le compte propriétaire se crée à la première visite. La clé de chiffrement est dans ses variables : ne la change jamais.",
     "site": "https://n8n.io"},
    {"id": "wikijs", "name": "Wiki.js", "cat": "doc", "color": "#1976d2",
     "desc": "Wiki moderne pour la documentation d'une équipe ou d'un projet.",
     "image": "ghcr.io/requarks/wiki", "version": "2", "port": 3000, "health": "/healthz", "mem": 384, "db": True,
     "env": "DB_TYPE=postgres\nDB_HOST={db_host}\nDB_PORT={db_port}\nDB_NAME={db_name}\nDB_USER={db_user}\nDB_PASS={db_password}",
     "after": "Un assistant crée le compte administrateur à la première visite.",
     "site": "https://js.wiki"},
    {"id": "nextcloud", "name": "Nextcloud", "cat": "doc", "color": "#0082c9",
     "desc": "Fichiers, agenda, contacts et partage, synchronisés sur tous tes appareils.",
     "image": "nextcloud", "version": "32-apache", "port": 80, "health": "/status.php", "mem": 768, "db": True,
     "mounts": "www:/var/www/html",
     "env": ("POSTGRES_HOST={db_host}\nPOSTGRES_DB={db_name}\nPOSTGRES_USER={db_user}\nPOSTGRES_PASSWORD={db_password}\n"
             "NEXTCLOUD_ADMIN_USER=admin\nNEXTCLOUD_ADMIN_PASSWORD={secret}\nNEXTCLOUD_TRUSTED_DOMAINS={host}\n"
             "OVERWRITEPROTOCOL=https\nOVERWRITEHOST={host}\nTRUSTED_PROXIES=10.0.0.0/8 172.16.0.0/12 192.168.0.0/16\n"
             "PHP_UPLOAD_LIMIT=2G"),
     "after": "Connexion avec admin ; son mot de passe est dans les variables de l'appli (NEXTCLOUD_ADMIN_PASSWORD). "
              "La première installation prend une à deux minutes. Fichiers gardés dans data/www.",
     "site": "https://nextcloud.com"},
    {"id": "freshrss", "name": "FreshRSS", "cat": "doc", "color": "#0062be",
     "desc": "Lecteur de flux RSS : suis blogs, journaux et chaînes au même endroit.",
     "image": "freshrss/freshrss", "version": "1", "port": 80, "health": "/", "mem": 128, "db": True,
     "mounts": "data:/var/www/FreshRSS/data, extensions:/var/www/FreshRSS/extensions",
     "env": ("CRON_MIN=*/20\nTRUSTED_PROXY=10.0.0.0/8 172.16.0.0/12 192.168.0.0/16\n"
             "FRESHRSS_INSTALL=--api-enabled --base-url {url_noslash} --default-user admin --language fr --db-type pgsql "
             "--db-host {db_host}:{db_port} --db-user {db_user} --db-password {db_password} --db-base {db_name}\n"
             "FRESHRSS_USER=--user admin --password {secret} --language fr"),
     "after": "Connexion avec admin ; son mot de passe est dans les variables de l'appli (FRESHRSS_USER). "
              "Flux rafraîchis toutes les 20 minutes.",
     "site": "https://freshrss.org"},
    {"id": "linkding", "name": "Linkding", "cat": "tools", "color": "#5856e0",
     "desc": "Marque-pages partagés entre tes navigateurs, avec étiquettes et archive.",
     "image": "sissbruecker/linkding", "version": "1.42.0", "port": 9090, "health": "/health", "mem": 192, "db": True,
     "mounts": "data:/etc/linkding/data",
     "env": ("LD_DB_ENGINE=postgres\nLD_DB_HOST={db_host}\nLD_DB_PORT={db_port}\nLD_DB_DATABASE={db_name}\n"
             "LD_DB_USER={db_user}\nLD_DB_PASSWORD={db_password}\nLD_SUPERUSER_NAME=admin\nLD_SUPERUSER_PASSWORD={secret}\n"
             "LD_CSRF_TRUSTED_ORIGINS={url_noslash}"),
     "after": "Connexion avec admin ; son mot de passe est dans les variables (LD_SUPERUSER_PASSWORD).",
     "site": "https://linkding.link"},
    {"id": "vikunja", "name": "Vikunja", "cat": "tools", "color": "#1973ff",
     "desc": "Listes de tâches et projets, en liste, tableau Kanban, Gantt ou agenda.",
     "image": "vikunja/vikunja", "version": "latest", "port": 3456, "health": "/api/v1/info", "mem": 192, "db": True,
     "mounts": "files:/app/vikunja/files",
     "env": ("VIKUNJA_SERVICE_PUBLICURL={url}\nVIKUNJA_SERVICE_SECRET={secret}\nVIKUNJA_DATABASE_TYPE=postgres\n"
             "VIKUNJA_DATABASE_HOST={db_host}\nVIKUNJA_DATABASE_DATABASE={db_name}\nVIKUNJA_DATABASE_USER={db_user}\n"
             "VIKUNJA_DATABASE_PASSWORD={db_password}"),
     "after": "Crée ton compte à la première visite, puis coupe les inscriptions (VIKUNJA_SERVICE_ENABLEREGISTRATION=false).",
     "site": "https://vikunja.io"},
    {"id": "mealie", "name": "Mealie", "cat": "tools", "color": "#e58325",
     "desc": "Recettes, listes de courses et menus de la semaine, importés depuis n'importe quel site.",
     "image": "ghcr.io/mealie-recipes/mealie", "version": "latest", "port": 9000, "health": "/api/app/about", "mem": 512,
     "db": True, "mounts": "data:/app/data",
     "env": ("BASE_URL={url_noslash}\nDB_ENGINE=postgres\nPOSTGRES_SERVER={db_host}\nPOSTGRES_PORT={db_port}\n"
             "POSTGRES_DB={db_name}\nPOSTGRES_USER={db_user}\nPOSTGRES_PASSWORD={db_password}\nALLOW_SIGNUP=false"),
     "after": "Connexion avec changeme@example.com / MyPassword : change-les tout de suite (Profil).",
     "site": "https://mealie.io"},
    {"id": "it-tools", "name": "IT-Tools", "cat": "tools", "color": "#18a058",
     "desc": "Une centaine de petits outils pour développeurs : encodages, hachages, conversions, générateurs.",
     "image": "corentinth/it-tools", "version": "latest", "port": 80, "health": "/", "mem": 64, "db": False,
     "env": "", "after": "Rien à régler : tout se passe dans le navigateur.",
     "site": "https://github.com/CorentinTh/it-tools"},
    {"id": "excalidraw", "name": "Excalidraw", "cat": "tools", "color": "#6965db",
     "desc": "Tableau blanc pour schémas et croquis à main levée.",
     "image": "excalidraw/excalidraw", "version": "latest", "port": 80, "health": "/", "mem": 64, "db": False,
     "env": "", "after": "Les dessins restent dans le navigateur de chacun (ou s'exportent en fichier).",
     "site": "https://excalidraw.com"},
]


def custom():
    """Modèles enregistrés depuis une appli existante (kv « custom_catalog »)."""
    return db.kv_get("custom_catalog") or []


def items():
    return custom() + CATALOG


def get(cid):
    return next((c for c in items() if c["id"] == cid), None)


SECRET_KEY = re.compile(r"(SECRET|TOKEN|PASSWORD|PASSWD|PASS$|_KEY$|^KEY$|APIKEY|SALT)", re.I)


def from_app(a, name, desc):
    """Modèle tiré d'une appli : image, port, santé, mémoire, base, services, dossiers et variables. Les valeurs des
    variables qui ressemblent à des secrets deviennent {secret} (une nouvelle valeur à chaque installation) ; son adresse
    devient {url} / {host}."""
    from . import domains as D
    from . import platform as P
    from . import runopts, services
    url = (D.primary_url(a["slug"]) or "").rstrip("/")
    host = url.split("://", 1)[-1].split("/", 1)[0] if url else ""
    env, _ = P.parse_env(a["env"])
    lines = []
    for k, v in env.items():
        if SECRET_KEY.search(k):
            v = "{secret}"
        elif url and url in v:
            v = v.replace(url + "/", "{url}").replace(url, "{url_noslash}")
        elif host and host in v:
            v = v.replace(host, "{host}")
        lines.append(f"{k}={v}")
    my = services.mysql(a["slug"])
    cid = "perso-" + a["slug"]
    return {"id": cid, "name": name[:60] or a["name"], "cat": "perso", "color": "#5f6b7a", "custom": True,
            "desc": desc[:200] or f"Modèle tiré de l'appli {a['name']}.", "image": a["image"], "version": a["version"],
            "port": a["port"], "health": a["health_path"], "mem": a["mem_mb"], "db": bool(a["db"]),
            "mysql": my["engine"] if my else None, "mysql_mem": my["mem"] if my else None,
            "mounts": runopts.of(a["slug"]).get("mounts") or "", "env": "\n".join(lines), "data_user": a["data_user"] or "",
            "kind": a["kind"] if a["kind"] in ("web", "api", "worker", "tool") else "tool",
            "run": {k: v for k, v in runopts.of(a["slug"]).items() if k in ("entrypoint", "command", "health_cmd", "health_mode")},
            "after": "Modèle personnel : vérifie ses variables dans sa fiche après l'installation.", "site": url or ""}


def save_custom(t):
    lst = [c for c in custom() if c["id"] != t["id"]]
    db.kv_set("custom_catalog", [t] + lst)


def delete_custom(cid):
    db.kv_set("custom_catalog", [c for c in custom() if c["id"] != cid])


def render_env(tpl, vals):
    """Remplit les {variables} ; chaque {secret} reçoit sa propre valeur aléatoire."""
    def one(m):
        k = m.group(1)
        if k == "secret":
            return secrets.token_hex(32)
        return str(vals.get(k, m.group(0)))
    return re.sub(r"\{([a-z_]+)\}", one, tpl or "")
