# Hangar

*English version: [README.en.md](README.en.md).*

Hébergeur d'applications auto-hébergé : sites, API, applis web, jeux, outils open source et services, sur une ou plusieurs machines, avec une console d'administration web accessible uniquement depuis le réseau local. Les backends d'applis mobiles (Android, iOS) y ont en plus leurs outils : découverte du serveur, configuration à distance, rapports de plantage.

- Chaque appli a un **type** (appli web, API, backend mobile…) qui adapte le formulaire et ses réglages par défaut, et tourne dans **un conteneur Docker** (un projet Compose par appli dans `/srv/apps/<id>`).
- **Caddy** route le trafic par sous-domaine (`https://<sous-domaine>.<domaine>/`, ou le domaine nu) ou par chemin (`https://apps.<domaine>/<id>/`).
- **Multi-domaine** : autant de domaines que tu veux, chacun avec son mode d'exposition :
  - **tunnel** : Caddy en HTTP local derrière `cloudflared`, TLS chez Cloudflare, aucun port ouvert ;
  - **direct** : Caddy sur 80/443 avec Let's Encrypt, sur la machine d'entrée choisie (la console ou un nœud).
- Une appli a une **liste d'adresses**, sur un ou plusieurs domaines ; la première est l'adresse principale. Les applis mobiles (client facultatif d'une appli) trouvent leur serveur via `https://apps.<domaine>/.well-known/apps.json`.
- **Cloudflare automatique** avec un jeton d'API : règles du tunnel et enregistrements DNS créés, mis à jour et retirés par Hangar, sans jamais toucher aux noms qui ne viennent pas de lui.
- **PostgreSQL 17** est partagé, avec une base et un rôle dédiés par appli, injectés dans `DATABASE_URL`.

## Console

FastAPI + Jinja, sans build front. Elle écoute en HTTPS (certificat auto-signé) sur l'IP LAN, port 8443. L'accès est limité aux réseaux privés choisis, par le pare-feu et par la console elle-même. Tout se règle depuis la console : domaines, Cloudflare, adresse, port et réseaux de la console (avec retour automatique à l'ancien réglage s'il n'est pas confirmé en 3 minutes), comptes (mots de passe argon2).

- Créer, modifier, démarrer, arrêter et supprimer des applis (source : image Docker ou dépôt Git).
- Déployer une version : healthcheck, puis **retour automatique** à la version précédente en cas d'échec. Retour arrière en un clic.
- Modifier la configuration : si le healthcheck échoue, l'ancienne configuration est restaurée.
- `/data` attribué automatiquement à l'utilisateur `USER` de l'image.
- Secrets masqués dans le formulaire, logs des conteneurs, journal des opérations.
- Générateur de prompt pour préparer un projet avec Claude (Dockerfile, healthcheck, CI ghcr.io, clients mobiles en option).
- Le Caddyfile est validé avant chaque rechargement. Une configuration refusée n'est jamais appliquée.
- Images privées : un jeton de lecture du registre (ghcr.io : `read:packages`) se saisit dans la fiche de l'appli. Il est vérifié par `docker login`, puis enregistré une fois pour tout le registre dans `/root/.docker/config.json`.
- **Sauvegardes** chiffrées (restic) chaque nuit vers Google Drive et/ou un NAS (SMB ou SFTP) : exports des bases, `data/` des applis, configuration. Restauration d'une appli depuis la destination choisie, avec copie de l'état d'avant. **Import de données** dans une appli existante (base et/ou `data/`), pour migrer une instance hébergée ailleurs. Retour arrière en un clic vers l'état d'avant chaque restauration ou import, et **points de restauration** à la demande. **Test de restauration** chaque semaine : la dernière sauvegarde est restaurée pour de vrai à côté (bases rechargées dans un PostgreSQL jetable), alerte en cas d'échec.
- **Nœuds** : ajout de serveurs supplémentaires (VPS, dédié, conteneur) depuis la console. Hangar les installe par SSH, avec root ou un compte `sudo` (Docker, PostgreSQL, Caddy, cloudflared, pare-feu), puis ne les pilote plus que par le réseau privé et les relie par un réseau privé WireGuard (10.88.0.0/24) qu'il initie lui-même : la box reste fermée. Mesures et alertes par nœud.
- **Cloisonnement** : chaque appli sur son propre réseau ; une appli piratée n'atteint ni les autres applis, ni sa machine, ni le réseau local, ni les autres nœuds (pare-feu), ni les bases des autres applis. Conteneurs sans élévation de privilèges, archives importées revalidées, console protégée par une CSP stricte, des sessions révocables et une limite de tentatives de connexion.
- **Rôle de la console** (page Nœuds) : elle héberge aussi des applis (une seule machine suffit pour démarrer) ou fait seulement la gestion. Ce second mode garde les clés des nœuds et du compte Cloudflare à l'écart des applis et permet de mettre toutes les applis en haute dispo. Elle peut rester machine de secours à chaud.
- **Sécurité des nœuds** exposés sur Internet, réglée depuis la page Sécurité (politique générale, ou réglages propres à un nœud) : pare-feu fermé par défaut (80/443 seulement sur les machines d'entrée d'un domaine en mode direct), SSH public ouvert, restreint à des adresses ou fermé, port au choix, clés seulement, root interdit, fail2ban avec récidive, mises à jour de sécurité et redémarrage automatiques, clés d'administration. Chaque changement programme sur le nœud le retour à l'ancien réglage, annulé seulement si la console s'y reconnecte. Liste de contrôle par nœud (adresses bannies, mises à jour en attente, ports Docker publics) et alerte en cas de problème.
- **Haute disponibilité**, au choix pour chaque appli depuis sa fiche :
  - *secours à chaud* : réplique de la base PostgreSQL en continu et copie de `data/` sur un nœud de secours ; si le nœud principal tombe, bascule automatique (environ une minute) ; bascule programmée sans perte pour la maintenance ;
  - *instances multiples* : l'appli tourne sur plusieurs nœuds, Caddy répartit les requêtes et écarte une instance en panne (applis sans état dans `data/`).
  Bascule seulement si la panne est certaine (la console a Internet, aucun autre nœud ne joint le nœud, arrêt de sécurité ou absence de réponse publique) ; un nœud isolé arrête lui-même ses applis protégées pour qu'elles ne tournent jamais en double ; à son retour, il est reconstruit en secours.
- **Répartition** : chaque appli tourne sur le nœud choisi à sa création (Hangar conseille celui qui a le plus de RAM libre), avec sa base PostgreSQL sur ce même nœud. Pour les domaines en mode tunnel, chaque nœud reçoit aussi le trafic Internet (connecteur du même tunnel + Caddy qui connaît toutes les applis) : si une machine tombe, les applis des autres restent joignables.
- **Déplacement** d'une appli vers un autre nœud depuis sa fiche : copie de `data/` pendant que l'appli tourne, puis coupure courte (copie finale, base, démarrage) et bascule des routes seulement si la cible répond ; sinon retour sur le nœud d'origine.
- Les **sauvegardes** couvrent tous les nœuds : le `data/` des applis distantes est recopié chaque nuit sur la console avant l'envoi chiffré ; restauration et archives fonctionnent quel que soit le nœud.
- **Archives manuelles** à télécharger (fiche, base et `data/` de chaque appli), **chiffrées** (gpg AES-256, mot de passe des sauvegardes), restaurables ici ou sur un autre serveur Hangar : les applis absentes sont recréées.
- **Supervision** de toutes les machines (console et nœuds) : processeur, mémoire, disque, Docker, PostgreSQL, Caddy, pare-feu.
- **Alertes** par ntfy, e-mail, Discord ou Telegram (seuil de priorité par canal) : appli qui ne répond plus, échec de déploiement, de sauvegarde ou de mise à jour, disque, mémoire, PostgreSQL, tunnel ; pour chaque nœud : injoignable, disque, mémoire, Docker, PostgreSQL, pare-feu, Caddy s'il reçoit le web en direct.
- **Nouvelles versions** : les tags x.y.z des images sont vérifiés toutes les 6 h, avec un bouton pour déployer la nouvelle version.
- **Base de données** de chaque appli : taille, tables, export `.sql.gz`, import (`.sql`, `.sql.gz`, `.dump`) et remise à zéro, avec copie de sécurité.
- **Mises à jour système** (Debian, Docker, Caddy, cloudflared, PostgreSQL) de la console et de chaque nœud, depuis la page Système, avec retour à la version précédente si le service ne repart pas, rappel si une mise à jour attend depuis plus de 14 jours, et option de mises à jour automatiques la nuit.
- **Statistiques** par appli sur 1 h, 24 h ou 7 jours : requêtes, erreurs, temps de réponse, mémoire, processeur.
- **Mode maintenance** par appli : page « Maintenance en cours » (503, `X-Hangar-Maintenance: 1`), posée aussi automatiquement pendant une restauration ou un import.
- **Préproduction** d'une appli : copie `<appli>-preprod` avec la base et `data/` de la production, `HANGAR_ENVIRONMENT=preprod`, recopie des données et déploiement en production d'un clic.
- **Tâches planifiées** par appli : commande lancée dans son conteneur toutes les N minutes, chaque jour ou chaque semaine, résultat gardé, alerte en cas d'échec.
- **Redis (Valkey)** à la demande pour une appli : sur son réseau cloisonné, persistant dans `data/`, `REDIS_URL` injectée.
- **Analyse des vulnérabilités** des images (Trivy, chaque semaine et après chaque déploiement), **terminal** dans un conteneur, **explorateur de data/**, **requêtes SQL en lecture seule**, **historique des réglages** et **alertes de capacité**.
- **Protéger une appli** par mot de passe ou adresses IP (appliqué par Caddy, chemins techniques laissés ouverts).
- **Relais e-mail** partagé : un compte SMTP réglé une fois, variables `SMTP_…` données aux applis qui en ont besoin.
- **MySQL 8.4 ou MariaDB 11.4** à la demande : base propre à l'appli, exportée de façon cohérente avant chaque sauvegarde, archive ou déplacement, et rechargée depuis cet export après une restauration (`MYSQL_HOST`, `MYSQL_URL`…).
- **Logs** consultables (période, recherche, erreurs seulement) et **alertes sur motif** (`Exception`, `OutOfMemory`…).
- **Rapport hebdomadaire** le lundi sur les canaux d'alerte : disponibilité, trafic, sauvegardes, mises à jour, machines, incidents.
- **Vérifications après déploiement** : adresses qui doivent répondre comme prévu (code, texte, `{version}`) pour garder une nouvelle version.
- **Processeur max** par appli, et alertes quand une appli frôle sa mémoire, reste bridée ou redémarre toute seule.
- **Affinité par partie** en instances multiples : même partie (en-tête, paramètre, cookie ou adresse) → même instance.
- **Interface en français ou en anglais**, au choix de chaque compte (textes des pages ; les messages d'action, le journal et les alertes restent en français pour l'instant).
- **Comptes en lecture seule** ou **limités à certaines applis** (voir, ou voir et redéployer), **double authentification** (code à usage unique, choisie par chaque compte, codes de secours) et **journal des actions** (qui a fait quoi, quand, depuis où).
- **Applis Android** : configuration à distance (version minimale ou conseillée, interrupteurs de fonctionnalités, annonce) servie à côté de `apps.json`, et **rapports de plantage** reçus par Hangar, regroupés, avec alerte au premier plantage d'un groupe et en cas de régression.
- **Types d'applis** : site statique (sans conteneur : zip ou dépôt Git construit dans un conteneur jetable, 10 versions, retour arrière instantané), appli web, API, backend d'appli mobile, service sans page web (jugé sain tant que son conteneur tourne), serveur de jeu avec ports TCP/UDP publics, outil auto-hébergé ; une appli web peut aussi ouvrir des ports publics.
- **Catalogue d'applis prêtes** (WordPress, Ghost, Nextcloud, FreshRSS, Linkding, Vikunja, Mealie, Umami, Uptime Kuma, Vaultwarden, Gitea, n8n, Wiki.js, IT-Tools, Excalidraw, et le serveur de messagerie Stalwart) : image, port, santé, base, secrets et variables remplis à l'installation ; toute appli peut aussi devenir un modèle personnel. Pour un tag qui bouge (`latest`…), Hangar signale quand une image plus récente est publiée.
- **Messagerie** (Stalwart, du catalogue) : SMTP, IMAP, JMAP, agendas et contacts, administration web et espace utilisateur ; Hangar fait son assistant de premier démarrage par son API (compte admin affiché dans la fiche), ouvre les ports 25, 465 et 993 sur sa machine et tient chez Cloudflare le nom du serveur (non proxifié), le MX, le SPF et le DMARC, sans jamais écraser un enregistrement qu'il n'a pas créé. Il faut une machine à IP publique fixe, port 25 ouvert chez l'hébergeur et DNS inverse réglé.
- **Clients** d'une appli : Android, iOS et navigateur (script servi sur l'adresse de l'appli), avec configuration à distance et rapports de plantage.
- **Page de statut publique** (`status.<domaine>`) : état et disponibilité sur 30 jours des applis choisies.
- Liste des noms publics (sans joker), avec leur état DNS et Cloudflare. Remplacement du jeton du tunnel, avec retour à l'ancien si cloudflared ne se connecte pas.

## Arborescence

```
app/                 code de la console : main.py (démarrage), routes/ (pages par thème), platform.py (déploiements, Caddy), db.py (registre SQLite),
                     backup.py, monitor.py (surveillance), alerts.py (ntfy, e-mail, Discord, Telegram), stats.py, system.py (mises à jour),
                     dbadmin.py (bases), registry.py (API des registres Docker)
deploy/              fichiers système installés sur le serveur (copies de référence)
  systemd/           hangar, platform-backup (+timer), platform-firewall, drop-in caddy
  caddy/             /etc/caddy/Caddyfile (importe /srv/platform/Caddyfile généré)
  docker/            daemon.json (live-restore, rotation des logs), compose PostgreSQL
  nftables/          pare-feu dans une table dédiée (ne touche pas aux règles Docker)
  apt/               mises à jour de sécurité automatiques (Docker, Caddy, cloudflared exclus)
  bin/               hangar (CLI : passwd, backup [--verify], archive, restore, routing, segment, sysupdate [--node])
  node/              préparation d'un nœud (bootstrap.sh, pare-feu)
docs/                exploitation, reprise sur un nouveau serveur, prompt de déploiement d'une appli
install.sh           installation complète (idempotente), avec restauration optionnelle d'une archive
tests/               tests automatiques (pytest), lancés à chaque push par GitHub Actions
```

## Installation (Debian 13)

```bash
./install.sh                     # questions : IP, réseau local, domaine, mode
./install.sh --domain exemple.fr --mode tunnel --tunnel-token <jeton> --restore archive.tar.gz --yes
```

Le script installe Docker, Caddy, cloudflared, restic et rclone, puis PostgreSQL, la console, le pare-feu et les services. Il génère les secrets et le compte administrateur, et peut restaurer une archive dans la foulée. Il est idempotent : le relancer ne remplace aucun secret ni réglage existant.

À la première connexion, l'accueil liste les réglages essentiels qui manquent (domaine, tunnel, sauvegarde, alertes), chacun avec son lien ; la liste complète est sur `/bienvenue`.

Dans un conteneur LXC Proxmox, active d'abord l'imbrication sur l'hôte : `pct set <id> --features nesting=1,keyctl=1`.

Reprise complète sur un nouveau serveur, depuis une archive téléchargée, Drive ou le NAS : voir [docs/reprise.md](docs/reprise.md).

## Tests

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt ruff
.venv/bin/pytest            # validations, archives piégées, compose, pare-feu (nft -c si root ou sudo), console web
.venv/bin/ruff check app tests
```

Sans root, Docker ni réseau : base SQLite et secret de session jetables. GitHub Actions (`.github/workflows/tests.yml`) lance aussi `shellcheck` sur les scripts et vérifie la syntaxe des pare-feu générés avec `nft`.

## Documentation

- [docs/reprise.md](docs/reprise.md) : installer sur un nouveau serveur et tout restaurer (archive téléchargée, Drive, NAS)
- [docs/exploitation.md](docs/exploitation.md) : services, fichiers, sauvegardes, alertes, mises à jour
- [docs/google-drive.md](docs/google-drive.md) : créer le projet Google et connecter Google Drive aux sauvegardes
- [docs/prompt-deploiement.md](docs/prompt-deploiement.md) : exemple écrit de prompt (backend d'appli mobile) ; pour tout type de projet, le générateur « Préparer un projet » de la console
- [docs/prompt-migration.md](docs/prompt-migration.md) : amener dans Hangar les données d'une instance hébergée ailleurs, avec Claude

## Contrat pour un backend

- Écoute HTTP sur `0.0.0.0` et un port fixe. Ne gère jamais le TLS.
- Répond avec un code inférieur à 500 sur le chemin du healthcheck, en moins de 3 s. La console attend 90 s au plus.
- Configuration par variables d'environnement. La base est fournie dans `DATABASE_URL`, au format libpq, avec l'hôte `postgres`.
- Seul `/data` est persistant. Un `USER` numérique non-root est recommandé.
- En-têtes reçus : `X-Forwarded-Proto`, `X-Forwarded-For`, `X-Real-IP`. En mode chemin, le préfixe est retiré et transmis dans `X-Forwarded-Prefix`.

Voir `docs/prompt-deploiement.md` pour la version détaillée à donner à Claude dans le projet d'une appli.
