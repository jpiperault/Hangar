# Hangar

Serveur d'applications auto-hébergé pour les backends d'applications Android, avec une console d'administration web accessible uniquement depuis le réseau local.

- Chaque backend tourne dans **un conteneur Docker** (un projet Compose par appli dans `/srv/apps/<id>`).
- **Caddy** route le trafic par sous-domaine (`https://<sous-domaine>.<domaine>/`, ou le domaine nu) ou par chemin (`https://apps.<domaine>/<id>/`).
- **Multi-domaine** : autant de domaines que tu veux, chacun avec son mode d'exposition :
  - **tunnel** : Caddy en HTTP local derrière `cloudflared`, TLS chez Cloudflare, aucun port ouvert ;
  - **direct** : Caddy sur 80/443 avec Let's Encrypt, sur la machine d'entrée choisie (la console ou un nœud).
- Une appli a une **liste d'adresses**, sur un ou plusieurs domaines ; la première est l'adresse principale. Les applis Android trouvent leur serveur via `https://apps.<domaine>/.well-known/apps.json`.
- **Cloudflare automatique** avec un jeton d'API : règles du tunnel et enregistrements DNS créés, mis à jour et retirés par Hangar, sans jamais toucher aux noms qui ne viennent pas de lui.
- **PostgreSQL 17** est partagé, avec une base et un rôle dédiés par appli, injectés dans `DATABASE_URL`.

## Console

FastAPI + Jinja, sans build front. Elle écoute en HTTPS (certificat auto-signé) sur l'IP LAN, port 8443. L'accès est limité aux réseaux privés choisis, par le pare-feu et par la console elle-même. Tout se règle depuis la console : domaines, Cloudflare, adresse, port et réseaux de la console (avec retour automatique à l'ancien réglage s'il n'est pas confirmé en 3 minutes), comptes (mots de passe argon2).

- Créer, modifier, démarrer, arrêter et supprimer des applis (source : image Docker ou dépôt Git).
- Déployer une version : healthcheck, puis **retour automatique** à la version précédente en cas d'échec. Retour arrière en un clic.
- Modifier la configuration : si le healthcheck échoue, l'ancienne configuration est restaurée.
- `/data` attribué automatiquement à l'utilisateur `USER` de l'image.
- Secrets masqués dans le formulaire, logs des conteneurs, journal des opérations.
- Générateur de prompt pour préparer un projet d'appli avec Claude (Dockerfile, healthcheck, CI ghcr.io, client Android).
- Le Caddyfile est validé avant chaque rechargement. Une configuration refusée n'est jamais appliquée.
- Images privées : un jeton de lecture du registre (ghcr.io : `read:packages`) se saisit dans la fiche de l'appli. Il est vérifié par `docker login`, puis enregistré une fois pour tout le registre dans `/root/.docker/config.json`.
- **Sauvegardes** chiffrées (restic) chaque nuit vers Google Drive et/ou un NAS (SMB ou SFTP) : exports des bases, `data/` des applis, configuration. Restauration d'une appli depuis la destination choisie, avec copie de l'état d'avant. **Import de données** dans une appli existante (base et/ou `data/`), pour migrer une instance hébergée ailleurs. Retour arrière en un clic vers l'état d'avant chaque restauration ou import. **Test de restauration** chaque semaine : la dernière sauvegarde est restaurée pour de vrai à côté (bases rechargées dans un PostgreSQL jetable), alerte en cas d'échec.
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
- **Archives manuelles** `.tar.gz` à télécharger (fiche, base et `data/` de chaque appli), restaurables ici ou sur un autre serveur Hangar : les applis absentes sont recréées.
- **Alertes ntfy** sur le téléphone : appli qui ne répond plus, échec de déploiement, de sauvegarde ou de mise à jour, disque, mémoire, PostgreSQL, tunnel.
- **Nouvelles versions** : les tags x.y.z des images sont vérifiés toutes les 6 h, avec un bouton pour déployer la nouvelle version.
- **Base de données** de chaque appli : taille, tables, export `.sql.gz`, import (`.sql`, `.sql.gz`, `.dump`) et remise à zéro, avec copie de sécurité.
- **Mises à jour système** (Debian, Docker, Caddy, cloudflared, PostgreSQL) depuis la console, avec retour à la version précédente si le service ne repart pas.
- **Statistiques** par appli sur 1 h, 24 h ou 7 jours : requêtes, erreurs, temps de réponse, mémoire, processeur.
- Liste des noms publics (sans joker), avec leur état DNS et Cloudflare. Remplacement du jeton du tunnel, avec retour à l'ancien si cloudflared ne se connecte pas.

## Arborescence

```
app/                 code de la console : main.py (routes), platform.py (déploiements, Caddy), db.py (registre SQLite),
                     backup.py, monitor.py (surveillance), alerts.py (ntfy), stats.py, system.py (mises à jour),
                     dbadmin.py (bases), registry.py (API des registres Docker)
deploy/              fichiers système installés sur le serveur (copies de référence)
  systemd/           hangar, platform-backup (+timer), platform-firewall, drop-in caddy
  caddy/             /etc/caddy/Caddyfile (importe /srv/platform/Caddyfile généré)
  docker/            daemon.json (live-restore, rotation des logs), compose PostgreSQL
  nftables/          pare-feu dans une table dédiée (ne touche pas aux règles Docker)
  apt/               mises à jour de sécurité automatiques (Docker, Caddy, cloudflared exclus)
  bin/               hangar (CLI : passwd, backup [--verify], archive, restore, routing, segment, sysupdate)
  node/              préparation d'un nœud (bootstrap.sh, pare-feu)
docs/                exploitation, reprise sur un nouveau serveur, prompt de déploiement d'une appli
install.sh           installation complète (idempotente), avec restauration optionnelle d'une archive
tests/               tests automatiques (pytest), lancés à chaque push par GitHub Actions
```

## Installation (Debian 13)

```bash
./install.sh                     # questions : IP, réseau local, domaine, mode
./install.sh --domain piperault.fr --mode tunnel --tunnel-token <jeton> --restore archive.tar.gz --yes
```

Le script installe Docker, Caddy, cloudflared, restic et rclone, puis PostgreSQL, la console, le pare-feu et les services. Il génère les secrets et le compte administrateur, et peut restaurer une archive dans la foulée. Il est idempotent : le relancer ne remplace aucun secret ni réglage existant.

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
- [docs/prompt-deploiement.md](docs/prompt-deploiement.md) : préparer une appli pour Hangar avec Claude
- [docs/prompt-migration.md](docs/prompt-migration.md) : amener dans Hangar les données d'une instance hébergée ailleurs, avec Claude

## Contrat pour un backend

- Écoute HTTP sur `0.0.0.0` et un port fixe. Ne gère jamais le TLS.
- Répond avec un code inférieur à 500 sur le chemin du healthcheck, en moins de 3 s. La console attend 90 s au plus.
- Configuration par variables d'environnement. La base est fournie dans `DATABASE_URL`, au format libpq, avec l'hôte `postgres`.
- Seul `/data` est persistant. Un `USER` numérique non-root est recommandé.
- En-têtes reçus : `X-Forwarded-Proto`, `X-Forwarded-For`, `X-Real-IP`. En mode chemin, le préfixe est retiré et transmis dans `X-Forwarded-Prefix`.

Voir `docs/prompt-deploiement.md` pour la version détaillée à donner à Claude dans le projet d'une appli.
