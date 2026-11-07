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

## Arborescence

```
app/                 code de la console (main.py routes, platform.py opérations, db.py registre SQLite)
deploy/              fichiers système installés sur le serveur (copies de référence)
  systemd/           hangar, platform-backup (+timer), platform-firewall, drop-in caddy
  caddy/             /etc/caddy/Caddyfile (importe /srv/platform/Caddyfile généré)
  docker/            daemon.json (live-restore, rotation des logs), compose PostgreSQL
  nftables/          pare-feu dans une table dédiée (ne touche pas aux règles Docker)
  apt/               mises à jour de sécurité automatiques (Docker, Caddy, cloudflared exclus)
  bin/               hangar (CLI), platform-backup (dump quotidien)
docs/                exploitation et prompt de déploiement d'une appli
```

## Installation (Debian 13)

Dans un conteneur LXC Proxmox, active d'abord l'imbrication sur l'hôte : `pct set <id> --features nesting=1,keyctl=1`.

1. Paquets : Docker (dépôt officiel), Caddy (dépôt Cloudsmith), `cloudflared` (dépôt Cloudflare) en mode tunnel, `python3-venv`, `git`, `unattended-upgrades`.
2. `deploy/docker/daemon.json` → `/etc/docker/daemon.json`, puis redémarrer Docker et créer le réseau : `docker network create platform`.
3. Dossiers : `/srv/platform/{caddy,public/.well-known,tls}`, `/srv/apps`, `/srv/backups/postgres`.
4. `deploy/platform.env.example` → `/srv/platform/.env` : adapter `ADMIN_BIND`, `LAN_CIDR`, `EXPOSURE_MODE`. Groupe `caddy`, mode 640.
5. `deploy/postgres.env.example` → `/srv/platform/postgres.env` (mode 600) avec un mot de passe aléatoire. `deploy/docker/platform-compose.yml` → `/srv/platform/compose.yml`, puis `docker compose up -d` dans `/srv/platform`.
6. `deploy/caddy/etc-caddy-Caddyfile` → `/etc/caddy/Caddyfile`, et `deploy/systemd/caddy-platform.conf` → `/etc/systemd/system/caddy.service.d/platform.conf`.
7. Code : ce dépôt dans `/opt/hangar`, puis `python3 -m venv venv && venv/bin/pip install -r requirements.txt`. Copier `deploy/bin/*` dans `/usr/local/bin/`.
8. Certificat de la console :
   ```
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 \
     -subj "/CN=Hangar" -addext "subjectAltName=IP:<ip-lan>" \
     -keyout /srv/platform/tls/hangar.key -out /srv/platform/tls/hangar.crt
   ```
9. Pare-feu : `deploy/nftables/platform.nft` → `/etc/nftables.d/` (adapter le set `lan`). **Ne pas activer `nftables.service`**, qui effacerait les règles Docker.
10. Unités systemd de `deploy/systemd/` → `/etc/systemd/system/`, puis `systemctl daemon-reload` et `systemctl enable --now hangar platform-backup.timer platform-firewall`.
11. Compte admin : `hangar passwd`.
12. En mode tunnel : `cloudflared service install <jeton>`. Dans Zero Trust, publier `apps.<domaine>` et `*.<domaine>` vers `http://127.0.0.1:8080`, avec un CNAME `*` vers `<id>.cfargotunnel.com`.

## Contrat pour un backend

- Écoute HTTP sur `0.0.0.0` et un port fixe. Ne gère jamais le TLS.
- Répond avec un code inférieur à 500 sur le chemin du healthcheck, en moins de 3 s. La console attend 90 s au plus.
- Configuration par variables d'environnement. La base est fournie dans `DATABASE_URL`, au format libpq, avec l'hôte `postgres`.
- Seul `/data` est persistant. Un `USER` numérique non-root est recommandé.
- En-têtes reçus : `X-Forwarded-Proto`, `X-Forwarded-For`, `X-Real-IP`. En mode chemin, le préfixe est retiré et transmis dans `X-Forwarded-Prefix`.

Voir `docs/prompt-deploiement.md` pour la version détaillée à donner à Claude dans le projet d'une appli.
