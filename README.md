# Hangar

Serveur d'applications auto-hébergé pour les backends d'applications Android, avec une console d'administration web accessible uniquement depuis le réseau local.

- Chaque backend tourne dans **un conteneur Docker** (un projet Compose par appli dans `/srv/apps/<id>`).
- **Caddy** route le trafic par chemin (`https://apps.piperault.fr/<id>/`) ou par sous-domaine (`https://<sous-domaine>.piperault.fr/`).
- **PostgreSQL 17** est partagé, avec une base et un rôle dédiés par appli, injectés dans `DATABASE_URL`.
- **Deux modes d'exposition**, au choix dans la console :
  - **tunnel** : Caddy en HTTP local derrière `cloudflared`, TLS chez Cloudflare ;
  - **direct** : Caddy sur 80/443 avec Let's Encrypt, pour un serveur dédié.
- Le domaine est interchangeable. Les anciens domaines restent servis en alias. Les applis Android trouvent leur serveur via `/.well-known/apps.json`.

## Console

FastAPI + Jinja, sans build front. Elle écoute en HTTPS (certificat auto-signé) sur l'IP LAN, port 8443. L'accès est limité au réseau local par le pare-feu et par la console elle-même. Mot de passe argon2.

- Créer, modifier, démarrer, arrêter et supprimer des applis (source : image Docker ou dépôt Git).
- Déployer une version : healthcheck, puis **retour automatique** à la version précédente en cas d'échec. Retour arrière en un clic.
- Modifier la configuration : si le healthcheck échoue, l'ancienne configuration est restaurée.
- `/data` attribué automatiquement à l'utilisateur `USER` de l'image.
- Secrets masqués dans le formulaire, logs des conteneurs, journal des opérations.
- Générateur de prompt pour préparer un projet d'appli avec Claude (Dockerfile, healthcheck, CI ghcr.io, client Android).
- Le Caddyfile est validé avant chaque rechargement. Une configuration refusée n'est jamais appliquée.
- Images privées : un jeton de lecture du registre (ghcr.io : `read:packages`) se saisit dans la fiche de l'appli. Il est vérifié par `docker login`, puis enregistré une fois pour tout le registre dans `/root/.docker/config.json`.
- **Sauvegardes** chiffrées (restic) chaque nuit vers Google Drive et/ou un NAS (SMB ou SFTP) : exports des bases, `data/` des applis, configuration. Restauration d'une appli depuis la destination choisie, avec copie de l'état d'avant.
- **Nœuds** : ajout de serveurs supplémentaires (VPS, dédié, conteneur) depuis la console. Hangar les installe par SSH (Docker, PostgreSQL, Caddy, cloudflared, pare-feu) et les relie par un réseau privé WireGuard (10.88.0.0/24) qu'il initie lui-même : la box reste fermée. Mesures et alertes par nœud.
- **Répartition** : chaque appli tourne sur le nœud choisi à sa création (Hangar conseille celui qui a le plus de RAM libre), avec sa base PostgreSQL sur ce même nœud. En mode tunnel, chaque nœud reçoit aussi le trafic Internet (connecteur du même tunnel + Caddy qui connaît toutes les applis) : si une machine tombe, les applis des autres restent joignables.
- **Archives manuelles** `.tar.gz` à télécharger (fiche, base et `data/` de chaque appli), restaurables ici ou sur un autre serveur Hangar : les applis absentes sont recréées.
- **Alertes ntfy** sur le téléphone : appli qui ne répond plus, échec de déploiement, de sauvegarde ou de mise à jour, disque, mémoire, PostgreSQL, tunnel.
- **Nouvelles versions** : les tags x.y.z des images sont vérifiés toutes les 6 h, avec un bouton pour déployer la nouvelle version.
- **Base de données** de chaque appli : taille, tables, export `.sql.gz`, import (`.sql`, `.sql.gz`, `.dump`) et remise à zéro, avec copie de sécurité.
- **Mises à jour système** (Debian, Docker, Caddy, cloudflared, PostgreSQL) depuis la console, avec retour à la version précédente si le service ne repart pas.
- **Statistiques** par appli sur 1 h, 24 h ou 7 jours : requêtes, erreurs, temps de réponse, mémoire, processeur.
- Liste des noms publics à déclarer chez Cloudflare (sans joker), avec leur état DNS. Remplacement du jeton du tunnel, avec retour à l'ancien si cloudflared ne se connecte pas.

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
  bin/               hangar (CLI : passwd, backup, archive, restore, routing, sysupdate)
  node/              préparation d'un nœud (bootstrap.sh, pare-feu)
docs/                exploitation, reprise sur un nouveau serveur, prompt de déploiement d'une appli
install.sh           installation complète (idempotente), avec restauration optionnelle d'une archive
```

## Installation (Debian 13)

```bash
./install.sh                     # questions : IP, réseau local, domaine, mode
./install.sh --domain piperault.fr --mode tunnel --tunnel-token <jeton> --restore archive.tar.gz --yes
```

Le script installe Docker, Caddy, cloudflared, restic et rclone, puis PostgreSQL, la console, le pare-feu et les services. Il génère les secrets et le compte administrateur, et peut restaurer une archive dans la foulée. Il est idempotent : le relancer ne remplace aucun secret ni réglage existant.

Dans un conteneur LXC Proxmox, active d'abord l'imbrication sur l'hôte : `pct set <id> --features nesting=1,keyctl=1`.

Reprise complète sur un nouveau serveur, depuis une archive téléchargée, Drive ou le NAS : voir [docs/reprise.md](docs/reprise.md).

## Documentation

- [docs/reprise.md](docs/reprise.md) : installer sur un nouveau serveur et tout restaurer (archive téléchargée, Drive, NAS)
- [docs/exploitation.md](docs/exploitation.md) : services, fichiers, sauvegardes, alertes, mises à jour
- [docs/prompt-deploiement.md](docs/prompt-deploiement.md) : préparer une appli pour Hangar avec Claude

## Contrat pour un backend

- Écoute HTTP sur `0.0.0.0` et un port fixe. Ne gère jamais le TLS.
- Répond avec un code inférieur à 500 sur le chemin du healthcheck, en moins de 3 s. La console attend 90 s au plus.
- Configuration par variables d'environnement. La base est fournie dans `DATABASE_URL`, au format libpq, avec l'hôte `postgres`.
- Seul `/data` est persistant. Un `USER` numérique non-root est recommandé.
- En-têtes reçus : `X-Forwarded-Proto`, `X-Forwarded-For`, `X-Real-IP`. En mode chemin, le préfixe est retiré et transmis dans `X-Forwarded-Prefix`.

Voir `docs/prompt-deploiement.md` pour la version détaillée à donner à Claude dans le projet d'une appli.
