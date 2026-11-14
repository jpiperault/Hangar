# Hangar

*Version française : [README.md](README.md).*

Self-hosted application host: sites, APIs, web apps, games, open source tools and services, on one or more machines, with a web administration console reachable only from the local network. Mobile app backends (Android, iOS) also get their own tools: server discovery, remote configuration, crash reports.

- Each app has a **type** (web app, API, mobile backend…) that adapts the form and its default settings, and runs in **a Docker container** (one Compose project per app in `/srv/apps/<id>`).
- **Caddy** routes traffic by subdomain (`https://<subdomain>.<domain>/`, or the bare domain) or by path (`https://apps.<domain>/<id>/`).
- **Multi-domain**: as many domains as you want, each with its own exposure mode:
  - **tunnel**: Caddy on local HTTP behind `cloudflared`, TLS at Cloudflare, no open port;
  - **direct**: Caddy on 80/443 with Let's Encrypt, on the chosen entry machine (the console or a node).
- An app has a **list of addresses**, on one or more domains; the first one is the main address. Mobile apps (an optional client of an app) find their server via `https://apps.<domain>/.well-known/apps.json`.
- **Automatic Cloudflare** with an API token: tunnel rules and DNS records created, updated and removed by Hangar, without ever touching names that do not come from it.
- **PostgreSQL 17** is shared, with a dedicated database and role per app, injected into `DATABASE_URL`.

## Console

FastAPI + Jinja, no front-end build. It listens over HTTPS (self-signed certificate) on the LAN IP, port 8443. Access is limited to the chosen private networks, by the firewall and by the console itself. Everything is configured from the console: domains, Cloudflare, the console's address, port and networks (with automatic return to the previous setting if not confirmed within 3 minutes), accounts (argon2 passwords).

- Create, edit, start, stop and delete apps (source: Docker image or Git repository).
- Deploy a version: healthcheck, then **automatic rollback** to the previous version on failure. One-click rollback.
- Edit the configuration: if the healthcheck fails, the previous configuration is restored.
- `/data` automatically assigned to the image's `USER`.
- Secrets masked in the form, container logs, operations log.
- Prompt generator to prepare a project with Claude (Dockerfile, healthcheck, ghcr.io CI, optional mobile clients).
- The Caddyfile is validated before each reload. A rejected configuration is never applied.
- Private images: a registry read token (ghcr.io: `read:packages`) is entered on the app page. It is verified by `docker login`, then stored once for the whole registry in `/root/.docker/config.json`.
- Encrypted **backups** (restic) every night to Google Drive and/or a NAS (SMB or SFTP): database exports, apps' `data/`, configuration. Restore of an app from the chosen destination, with a copy of the previous state. **Data import** into an existing app (database and/or `data/`), to migrate an instance hosted elsewhere. One-click rollback to the state before each restore or import, and on-demand **restore points**. Weekly **restore test**: the latest backup is actually restored alongside (databases reloaded into a throwaway PostgreSQL), alert on failure.
- **Nodes**: add extra servers (VPS, dedicated, container) from the console. Hangar installs them over SSH, with root or a `sudo` account (Docker, PostgreSQL, Caddy, cloudflared, firewall), then drives them only over the private network and links them with a WireGuard private network (10.88.0.0/24) that it initiates itself: the home router stays closed. Per-node metrics and alerts.
- **Isolation**: each app on its own network; a compromised app reaches neither the other apps, nor its machine, nor the local network, nor the other nodes (firewall), nor the other apps' databases. Containers without privilege escalation, imported archives revalidated, console protected by a strict CSP, revocable sessions and a login attempt limit.
- **Console role** (Nodes page): it also hosts apps (a single machine is enough to start) or only does management. The second mode keeps the node keys and the Cloudflare account away from the apps and allows every app to be in high availability. It can remain a hot standby machine.
- **Security of nodes** exposed to the Internet, configured from the Security page (general policy, or node-specific settings): firewall closed by default (80/443 only on the entry machines of a direct-mode domain), public SSH open, restricted to addresses or closed, port of your choice, keys only, root forbidden, fail2ban with repeat-offender jail, automatic security updates and reboot, admin keys. Each change schedules on the node a return to the previous setting, cancelled only if the console can reconnect to it. Per-node checklist (banned addresses, pending updates, public Docker ports) and alert on problems.
- **High availability**, chosen per app from its app page:
  - *hot standby*: continuous PostgreSQL database replication and copy of `data/` to a standby node; if the primary node goes down, automatic failover (about one minute); lossless planned switchover for maintenance;
  - *multiple instances*: the app runs on several nodes, Caddy load-balances requests and removes a failed instance (apps with no state in `data/`).
  Failover only when the outage is certain (the console has Internet, no other node can reach the node, safety shutdown or no public response); an isolated node stops its protected apps itself so they never run twice; when it comes back, it is rebuilt as a standby.
- **Placement**: each app runs on the node chosen at creation (Hangar suggests the one with the most free RAM), with its PostgreSQL database on that same node. For tunnel-mode domains, each node also receives Internet traffic (connector of the same tunnel + a Caddy that knows all apps): if one machine goes down, the apps on the others stay reachable.
- **Moving** an app to another node from its app page: copy of `data/` while the app is running, then a short cut-over (final copy, database, start) and routes switched only if the target answers; otherwise back to the original node.
- **Backups** cover all nodes: the `data/` of remote apps is copied to the console every night before the encrypted upload; restore and archives work whatever the node.
- Downloadable **manual archives** (record, database and `data/` of each app), **encrypted** (gpg AES-256, backup password), restorable here or on another Hangar server: missing apps are recreated.
- **Monitoring** of all machines (console and nodes): CPU, memory, disk, Docker, PostgreSQL, Caddy, firewall.
- **Alerts** via ntfy, email, Discord or Telegram (priority threshold per channel): app no longer responding, deployment, backup or update failure, disk, memory, PostgreSQL, tunnel; for each node: unreachable, disk, memory, Docker, PostgreSQL, firewall, Caddy if it receives web traffic directly.
- **New versions**: image x.y.z tags are checked every 6 h, with a button to deploy the new version.
- **Database** of each app: size, tables, `.sql.gz` export, import (`.sql`, `.sql.gz`, `.dump`) and reset, with a safety copy.
- **System updates** (Debian, Docker, Caddy, cloudflared, PostgreSQL) of the console and each node, from the System page, with rollback to the previous version if the service does not come back, a reminder if an update has been waiting for more than 14 days, and an option for automatic nightly updates.
- **Statistics** per app over 1 h, 24 h or 7 days: requests, errors, response time, memory, CPU.
- **Maintenance mode** per app: "Maintenance in progress" page (503, `X-Hangar-Maintenance: 1`), also set automatically during a restore or an import.
- **Staging** for an app: copy `<appli>-preprod` with the production database and `data/`, `HANGAR_ENVIRONMENT=preprod`, one-click data refresh and deployment to production.
- **Scheduled tasks** per app: command run in its container every N minutes, daily or weekly, result kept, alert on failure.
- **Redis (Valkey)** on demand for an app: on its isolated network, persistent in `data/`, `REDIS_URL` injected.
- Image **vulnerability scanning** (Trivy, weekly and after each deployment), **terminal** in a container, **data/ explorer**, **read-only SQL queries**, **settings history** and **capacity alerts**.
- **Protect an app** with a password or IP addresses (enforced by Caddy, technical paths left open).
- Shared **email relay**: one SMTP account set once, `SMTP_…` variables given to the apps that need them.
- **MySQL 8.4 or MariaDB 11.4** on demand: database owned by the app, exported consistently before each backup, archive or move, and reloaded from that export after a restore (`MYSQL_HOST`, `MYSQL_URL`…).
- Searchable **logs** (period, search, errors only) and **pattern alerts** (`Exception`, `OutOfMemory`…).
- **Weekly report** on Monday on the alert channels: availability, traffic, backups, updates, machines, incidents.
- **Post-deployment checks**: addresses that must respond as expected (code, text, `{version}`) to keep a new version.
- **Max CPU** per app, and alerts when an app nears its memory limit, stays throttled or restarts by itself.
- **Session affinity** with multiple instances: same session (header, parameter, cookie or address) → same instance.
- **French or English interface**, chosen by each account (page texts; action messages, the event log and alerts remain in French for now).
- **Read-only accounts** or accounts **limited to certain apps** (view, or view and redeploy), **two-factor authentication** (one-time code, chosen by each account, recovery codes) and **audit log** (who did what, when, from where).
- **Android apps**: remote configuration (minimum or recommended version, feature switches, announcement) served alongside `apps.json`, and **crash reports** received by Hangar, grouped, with an alert on a group's first crash and on regressions.
- **App types**: static site (no container: zip or Git repository built in a throwaway container, 10 versions, instant rollback), web app, API, mobile app backend, service without a web page (considered healthy as long as its container runs), game server with public TCP/UDP ports, self-hosted tool.
- **Catalog of ready-made apps** (WordPress, Ghost, Nextcloud, FreshRSS, Linkding, Vikunja, Mealie, Umami, Uptime Kuma, Vaultwarden, Gitea, n8n, Wiki.js, IT-Tools, Excalidraw): image, port, health, database, secrets and variables filled in at installation; any app can also become a personal template. For a moving tag (`latest`…), Hangar reports when a newer image is published.
- **Clients** of an app: Android, iOS and browser (script served on the app's address), with remote configuration and crash reports.
- **Public status page** (`status.<domaine>`): status and 30-day availability of the selected apps.
- List of public names (no wildcard), with their DNS and Cloudflare status. Tunnel token replacement, with return to the old one if cloudflared does not connect.

## Directory layout

```
app/                 console code: main.py (startup), routes/ (pages by theme), platform.py (deployments, Caddy), db.py (SQLite registry),
                     backup.py, monitor.py (monitoring), alerts.py (ntfy, email, Discord, Telegram), stats.py, system.py (updates),
                     dbadmin.py (databases), registry.py (Docker registry API)
deploy/              system files installed on the server (reference copies)
  systemd/           hangar, platform-backup (+timer), platform-firewall, caddy drop-in
  caddy/             /etc/caddy/Caddyfile (imports the generated /srv/platform/Caddyfile)
  docker/            daemon.json (live-restore, log rotation), PostgreSQL compose
  nftables/          firewall in a dedicated table (does not touch Docker rules)
  apt/               automatic security updates (Docker, Caddy, cloudflared excluded)
  bin/               hangar (CLI: passwd, backup [--verify], archive, restore, routing, segment, sysupdate [--node])
  node/              node preparation (bootstrap.sh, firewall)
docs/                operations, recovery on a new server, app deployment prompt
install.sh           full installation (idempotent), with optional restore of an archive
tests/               automated tests (pytest), run on every push by GitHub Actions
```

## Installation (Debian 13)

```bash
./install.sh                     # questions: IP, local network, domain, mode
./install.sh --domain exemple.fr --mode tunnel --tunnel-token <jeton> --restore archive.tar.gz --yes
```

The script installs Docker, Caddy, cloudflared, restic and rclone, then PostgreSQL, the console, the firewall and the services. It generates the secrets and the administrator account, and can restore an archive right away. It is idempotent: running it again replaces no existing secret or setting.

On first login, the home page lists the missing essential settings (domain, tunnel, backup, alerts), each with its link; the full list is at `/bienvenue`.

In a Proxmox LXC container, first enable nesting on the host: `pct set <id> --features nesting=1,keyctl=1`.

Full recovery on a new server, from a downloaded archive, Drive or the NAS: see [docs/en/recovery.md](docs/en/recovery.md).

## Tests

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt ruff
.venv/bin/pytest            # validations, booby-trapped archives, compose, firewall (nft -c if root or sudo), web console
.venv/bin/ruff check app tests
```

No root, Docker or network needed: throwaway SQLite database and session secret. GitHub Actions (`.github/workflows/tests.yml`) also runs `shellcheck` on the scripts and checks the syntax of the generated firewalls with `nft`.

## Documentation

- [docs/en/recovery.md](docs/en/recovery.md): install on a new server and restore everything (downloaded archive, Drive, NAS)
- [docs/en/operations.md](docs/en/operations.md): services, files, backups, alerts, updates
- [docs/google-drive.md](docs/google-drive.md): create the Google project and connect Google Drive to backups (in French)
- [docs/prompt-deploiement.md](docs/prompt-deploiement.md): written prompt example (mobile app backend) (in French); for any type of project, the console's "Prepare a project" generator
- [docs/prompt-migration.md](docs/prompt-migration.md): bring the data of an instance hosted elsewhere into Hangar, with Claude (in French)

## Backend contract

- Listens for HTTP on `0.0.0.0` and a fixed port. Never handles TLS.
- Answers with a code below 500 on the healthcheck path, in less than 3 s. The console waits 90 s at most.
- Configuration through environment variables. The database is provided in `DATABASE_URL`, in libpq format, with host `postgres`.
- Only `/data` is persistent. A numeric non-root `USER` is recommended.
- Headers received: `X-Forwarded-Proto`, `X-Forwarded-For`, `X-Real-IP`. In path mode, the prefix is stripped and passed in `X-Forwarded-Prefix`.

See `docs/prompt-deploiement.md` for the detailed version to give Claude in an app's project.
