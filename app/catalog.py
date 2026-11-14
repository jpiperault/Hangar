"""Catalogue d'applis prêtes : des applis open source dont les réglages sont déjà faits (image, port, adresse de
santé, mémoire, base, variables). On choisit l'adresse et la machine ; Hangar crée l'appli comme une autre.

Variables : les valeurs entre accolades sont remplies à l'installation :
  {url}         adresse publique (https://…/)        {host}  son nom (sans https)
  {db_url}      DATABASE_URL (libpq)                  {db_host} {db_port} {db_name} {db_user} {db_password}
  {secret}      chaîne aléatoire (64 caractères hexadécimaux), une nouvelle à chaque occurrence
  {mysql_password}  mot de passe de la base MySQL/MariaDB de l'appli (hôte mysql, base et utilisateur app)
Seules les applis qui tiennent dans le modèle de Hangar y sont : un conteneur, données dans /data (ou dans des
dossiers de data/ montés ailleurs : « mounts »), PostgreSQL, MySQL/MariaDB (« mysql » : moteur) ou rien.
"""
import re
import secrets

CATS = {"site": "Sites et blogs", "stats": "Statistiques et surveillance", "secu": "Sécurité",
        "dev": "Développement", "auto": "Automatisation", "doc": "Documentation", "tools": "Outils"}

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


def get(cid):
    return next((c for c in CATALOG if c["id"] == cid), None)


def render_env(tpl, vals):
    """Remplit les {variables} ; chaque {secret} reçoit sa propre valeur aléatoire."""
    def one(m):
        k = m.group(1)
        if k == "secret":
            return secrets.token_hex(32)
        return str(vals.get(k, m.group(0)))
    return re.sub(r"\{([a-z_]+)\}", one, tpl or "")
