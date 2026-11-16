# Operating Hangar

*Version française : [../exploitation.md](../exploitation.md).*

Console: https://<console IP>:8443 (local network only, self-signed certificate)
Initial credentials: /root/hangar-mot-de-passe.txt — change with `hangar passwd [account]`. Accounts: `hangar users`.

## Domains (Domains page of the console)
Tables domains (name, mode, hub, entry, ip, is_default) and routes (app addresses, ordered) in platform.db.
Each domain has its own mode:
- tunnel: sites http://<name>:8080 bound to 127.0.0.1 (TUNNEL_BIND), cloudflared forwards the traffic, TLS at
  Cloudflare. Served by the console and by every node with "receives traffic" on. One tunnel ingress rule per name
  (no wildcard) → http://127.0.0.1:8080.
- direct: sites <name> on 80/443 with Let's Encrypt, only on the domain's entry machine (entry).
  DNS A record pointing to its public IP.
Host for path-based routes: <hub>.<domain>, with a per-domain /.well-known/apps.json
(public/<domain>/.well-known/apps.json: apps that have an address on this domain).
Cloudflare (optional): API token in /srv/platform/cloudflare.token (600). app/cloudflare.py syncs
after every route change: tunnel rules (cfd_tunnel configurations API) and DNS (proxied CNAME
<id>.cfargotunnel.com, or unproxied A record in direct mode), comment "géré par Hangar". Names already
used by another record are not overwritten; only records commented by Hangar are
deleted. Status of the last sync: kv cf_status.
Tunnel token: /etc/cloudflared/token (600), replaceable from the console.
Backends receive X-Real-IP (visitor IP), X-Forwarded-For and X-Forwarded-Proto.

## Console access (Access and accounts page)
ADMIN_BIND and LAN_CIDR (comma-separated networks) in .env, port and networks in
/etc/nftables.d/platform.nft. A change is applied immediately and schedules hangar-acces-retour.timer
(3 min): without confirmation from the new address, `hangar access-revert` restores .env, firewall and certificate
(copies in /srv/platform/access.prev). Manually: `systemctl stop hangar-acces-retour.timer` to keep the change.
Accounts: Access and accounts page (add, password, delete). As a fallback: `hangar passwd`.
Sessions: sessions table (revocable). Closed on logout, after 30 min of inactivity, and for other
devices when the password changes (`hangar passwd` closes them all). Login: 5 failures from one address
(or 20 on one account) within 15 min block for 15 min; each failure is recorded in the event log, an alert is sent on blocking.
Pages: strict CSP (scripts from the site or carrying the page nonce, no JavaScript in attributes: confirmations
via `data-confirm`, see app/static/app.js), forms rejected if they come from another site.

## App isolation
- One Docker network per app, "hangar-<slug>" (interface hg-<hash>, addresses taken from 172.20.0.0/14, never
  those of the local network): the app is alone there with its dedicated database in high availability. The node's shared
  PostgreSQL is attached as "postgres" only if the app has a database on it. The network is created (or repaired) before
  each start and removed when the app is deleted or moved.
- nftables table "inet hangarapps" (/etc/nftables.d/hangar-apps.nft, identical everywhere, reloaded at boot with
  the machine's firewall): no traffic from one app network to another, including through a port published on
  the host address; towards the nodes' private network, only the port of the app's own dedicated database.
- Firewall of the console (/etc/nftables.d/platform.nft) and of the nodes (table hangarnode): a container cannot reach
  any service of its machine except 80/443 (SSH included, even if open to the Internet), nor the local network, nor
  private addresses. Exceptions: DNS (port 53) and the Internet.
- On WireGuard, a node only accepts the console (10.88.0.1).
- Existing installation: `hangar segment`, also run by every `install.sh` (no effect if there is nothing to do). Installs the
  isolation firewall and the Docker address range on the console and every reachable node (Docker restarts,
  live-restore keeps the containers), then recreates each running app on its network: a few seconds of
  downtime per app. Unreachable nodes are handled by running the command again. Check:
  `nft list table inet hangarapps` and `docker network ls` (one "hangar-<slug>" per app).
- Still shared: the node's PostgreSQL (one database and one role per app, distinct passwords) and the machine's
  kernel. A container escape gives the machine: dedicate the console to management (Nodes page, "Console
  role") so that the machine holding the node keys runs no app.
- Containers: no-new-privileges, capabilities NET_RAW, MKNOD, SYS_CHROOT, SETFCAP and AUDIT_WRITE dropped, 1024
  processes at most. An image that relies on a setuid binary (sudo, su) can no longer switch users that way.
- PostgreSQL: each app can only open its own database (REVOKE CONNECT … FROM PUBLIC on every deployment).
- Imported archives: each app in the manifest is revalidated as in the form, otherwise the archive is
  rejected. The security policy is restored after validation, without the admin keys.
- hangar service: NoNewPrivileges, PrivateTmp and light systemd hardening (it must remain root).
- Console SSH: "This server" block of the Security page (root keys, key-only login, fail2ban),
  file /etc/ssh/sshd_config.d/00-hangar-console.conf. Passwords can only be disabled once a
  key is in place.

## Console role (Nodes page)

- **Also hosts apps** (default): everything fits on a single machine.
- **Management only**, recommended as soon as there are nodes:
  - no app is created on or moved to the console any more, and no multiple instance runs there;
  - the console holds the nodes' root SSH keys, the Cloudflare token and the backup credentials, which a compromised app then cannot reach;
  - the console decides failovers, so every app can be in high availability;
  - an option lets it act as a hot standby: it then only runs an app after a failover.
- Apps that remain on the console are flagged on the Nodes page and on their app page; move them with the "Node" block.
- If the console stops, the apps on the nodes keep running, each node having its own Caddy and tunnel. Only management, monitoring, failovers and backups are lost until it comes back.

## Moving a node to another console (Nodes page, a node's Maintenance tab)

A node and its apps move from one Hangar console to another, without copying: containers, data/, databases and
services stay on the machine and keep running (transfer.py).

1. Console taking over: "Prepare a takeover request" (text HANGAR-REPRISE-1:…, valid 7 days, no secret: SSH and
   WireGuard public keys, private addresses, ports, IDs and domains already in use).
2. Console handing over: node page, Maintenance, "Hand over to another console", paste the request, check.
   Refused if the node is used for high availability, if an app ID already exists on the other side, or if an app
   is linked to a pre-production on another node. On confirmation: the other console's SSH key is authorized
   (limited to 10.88.0.1), a package is encrypted with a code (gpg, kept 7 days in /srv/backups/transferts and on
   the Nodes page), the tunnel connector is stopped, the node's WireGuard switches 5 s later to the other console
   (same private address if free there), then the node and its apps are forgotten here without being stopped.
3. Console taking over: upload the package and the code. The node joins its private network, this console's
   installation brings it up to date (firewall, security, isolation, Caddy, tunnel), the records are recreated
   (variables, passwords, addresses whose domain exists here, settings, history, crashes) and the apps are
   redeployed in place; the old console's SSH key is removed from the node. On failure: "Retry" or "Abandon" on
   the node page.

Between the handover and the takeover, the apps are not published. Not carried over: permissions of "app" accounts,
backups already made (they stay on the old console), statistics; GitHub webhooks must be set up again.

## Node security (Security page)
General policy: kv "security". Node-specific settings: column nodes.security (NULL = general
policy). Applied, observed: nodes.sec (applied fingerprint, last check, original port). Code: app/security.py.
Files installed on the node:
- /etc/nftables.d/hangar-node.nft (table inet hangarnode, loaded by hangar-node-firewall.service);
- /etc/ssh/sshd_config.d/00-hangar.conf, and /etc/systemd/system/ssh.socket.d/hangar.conf if SSH is socket-activated
  and the public port is not 22 (sshd then listens on 22 and the chosen port; the firewall only opens 22
  on the private network);
- /etc/fail2ban/jail.d/hangar.local (nftables table f2b-table);
- /etc/apt/apt.conf.d/53hangar-securite, /etc/sysctl.d/90-hangar.conf;
- "hangar : clés d'administration" block in ~/.ssh/authorized_keys of the installation account.
Applying: the console uploads /opt/hangar-node/sec and runs security-apply.sh detached (hangar-sec-apply). The
script copies the previous setting to /var/lib/hangar-sec/prev and schedules hangar-sec-retour.timer (2 min) before
touching anything. The console confirms (stops the timer) only if a new SSH connection over the
private network succeeds. The firewall is reapplied automatically when a direct domain changes entry machine.
Status checked every 30 min ("Refresh status" button); ntfy alert if the firewall is missing or if a container
publishes a port on all addresses (Docker bypasses the firewall).
Unlocking a node from the hosting provider's emergency console: `nft delete table inet hangarnode`,
`rm /etc/ssh/sshd_config.d/00-hangar.conf`, `systemctl restart ssh`, `fail2ban-client unban --all`.

## High availability (app page, settings on the Nodes page)
Code: app/ha.py. Per-app settings: table ha (mode standby | replicas, nodes, auto, delay, sync_min, db_node,
db_port, state, info). General settings: kv "ha" (safety shutdown auto | always | never, fence_after).
- Dedicated database: a protected app with a database has its own PostgreSQL (container appdb-<app>, compose project
  appdb-<app>, files /srv/apps/<app>/pgdata, compose on the console in /srv/apps/<app>/db-<node>/),
  published only on the node's WireGuard address, port = app port + 10000. Superuser "platform",
  account "replicator" for streaming replication (pg_basebackup -R). The console tools (export, import,
  backups) go through P.pg_where(). Safety export on every setup or removal:
  /srv/backups/avant-haute-dispo.
- Hot standby: data/ copied every sync_min minutes from the primary to the standby, relayed by the console
  (mirror /srv/backups/staging/nodes/<app>/data, also used by backups).
- Multiple instances: instance compose /srv/apps/<app>/inst-<node>/compose.yml (same project app-<app>);
  Caddy lists all instances with active health checks (health_uri = the app's health path).
- Automatic failover (monitoring, every minute): primary node unreachable for `delay` minutes, the console has
  Internet, no other node can reach it; if the safety shutdown is inactive on that node, it also does not answer
  on its public address and its tunnel connector is no longer connected (with a Cloudflare API token).
  Replica promotion (pg_promote), app start, routes switched, ntfy alert.
- Safety shutdown: /usr/local/sbin/hangar-fence (timer hangar-fence.timer, 30 s); conf /etc/hangar/fence.conf.
  With no WireGuard peer seen for AFTER seconds, stops the containers labelled fr.hangar.ha-role=primary or
  instance and cloudflared, and writes /var/lib/hangar/fenced. The console restarts them (or rebuilds as standby) on return.
- Limitation: the console decides failovers; an app whose primary node is the console does not fail over if the
  console goes down. Put protected apps on remote nodes; the console can act as standby.

## Mail (Stalwart, from the catalog)
- At install: address domain (example.com) and server name (mail.example.com, distinct from the admin's web
  address). Hangar opens public ports tcp 25, 465 and 993 (Stalwart does not listen on 587) on the chosen machine (the app's "Public ports"
  setting, as for a game server) and stores the rest in kv `mail_dns`.
- With a Cloudflare token, DNS sync keeps: A/AAAA of the server to its machine's public IP (never proxied), the
  domain's MX, SPF `v=spf1 mx -all`, DMARC `v=DMARC1; p=none`. Comment "géré par Hangar (messagerie)"; an existing
  MX, SPF or DMARC that Hangar did not create is never overwritten: it is reported on the app's page.
  Without a token, or if the machine has no public IP, the page lists the records to add by hand.
- First start: Stalwart only accepts its wizard, over plain HTTP, and rejects its UI served over HTTPS ("Client
  metadata documents are disabled"). Hangar completes the wizard through the JMAP API (`x:Bootstrap/set`) from the
  console, over the private network, with the temporary STALWART_RECOVERY_ADMIN account: server name, domain, RocksDB,
  console logs, DKIM keys. It keeps the permanent admin account created (kv `mail_admin`, shown to admins on the page
  until they "forget" it), removes the temporary account variable and restarts the app; STALWART_PUBLIC_URL then takes
  effect and the UI works over HTTPS. On failure: "Configure Stalwart" button on the page.
- Optional Cloudflare token (zone-limited, DNS › Edit), passed to Stalwart and not kept by Hangar: Stalwart gets its
  certificate (DNS-01) and publishes DKIM, DMARC, SRV, autoconfig, MTA-STS; Hangar then only keeps A, MX and SPF.
  Without a token: certificate and DKIM to set up in Stalwart's admin.
- Outside Hangar: outbound port 25 open at the host, and reverse DNS (PTR) of the IP set to the server name.
- Data: data/etc (config.json) and data/lib (RocksDB), backed up with the app.
- Changing machines: "Move" (mailboxes copied, the server's A record updated at Cloudflare; PTR and port 25 to set
  at the new host). Hangar refuses before any cutover if the ports are taken on the target (local postfix…).
  No high availability: data/ is only copied periodically there, so a failover would lose mail.

## Services
- `hangar`            console (FastAPI, /opt/hangar), runs as root
- `caddy`             reverse proxy, reads /srv/platform/Caddyfile (generated by the console)
- `docker`            backends: one compose project per app in /srv/apps/<id>
- `platform-postgres-1` shared PostgreSQL 17 (/srv/platform/compose.yml), 127.0.0.1:5432
- `platform-backup.timer` 03:00: `hangar backup` → local global dump (/srv/backups/postgres, 14 days),
  per-app export (/srv/backups/staging), then encrypted restic to Google Drive if connected
- monitoring (console thread): stats every minute, app health, disk, memory, PostgreSQL,
  tunnel; new image versions every 6 h; system updates daily
- `platform-firewall` nftables, /etc/nftables.d/platform.nft (do not enable `nftables.service`)

## Files
- platform.db          registry (apps, settings, event log, accounts)
- .env                 ADMIN_BIND, LAN_CIDR (adjustable from the console), TUNNEL_BIND
                       (BASE_DOMAIN, HUB, EXPOSURE_MODE: installation values, converted once into a domain)
- Caddyfile(.prev)     generated configuration and the previous one
- public/<domain>/.well-known/apps.json  manifest of each domain, read by the Android apps
- /srv/backups/deleted deleted apps (files + dump), to purge by hand
- /srv/backups/avant-import, avant-restauration: state set aside before an import or a restore
- backup/rclone.conf   Google Drive access (drive.file only)
- backup/restic.pass   BACKUP PASSWORD: without it, the Drive copy is unreadable.
                       Keep it off the server (password manager).

## Backend contract
- listens for HTTP on the declared internal port, answers < 500 on the healthcheck path
- persistent files in /data, assigned on every deployment to the image's USER
  (or to the UID entered in "Owner of /data")
- database: DATABASE_URL variable (host `postgres`)
- path-based exposure: the prefix is stripped and passed in X-Forwarded-Prefix

Private registries
  Token entered on the app page ("Access token" field), verified by docker login.
  Stored in /root/.docker/config.json (600), shared by all apps on the same registry.
  List and removal: Access and accounts › Private image registries. Manually: docker logout ghcr.io

Backups (Backups page)
  restic repository: rclone:hangar-gdrive:Hangar-sauvegardes (My Drive). Contents: database exports,
  /srv/apps (compose + data/), /srv/platform (without PostgreSQL raw files), copy of the registry.
  Default retention: 7 daily, 4 weekly, 12 monthly; cleanup (prune) on Sunday.
  Google project: full procedure in docs/google-drive.md. It must be published "In production", otherwise
  Google cuts access after 7 days. The two public pages Google requires (https://<prefix>.<domain>/
  and /confidentialite) are served by Hangar: files public/<domain>/index.html and confidentialite.html,
  regenerated with the routing; optional contact (public_contact setting, Backups page).
  Disaster recovery, on a fresh machine with restic and rclone:
    rclone config (remote "hangar-gdrive", type drive, scope drive.file)
    RESTIC_PASSWORD=<password> restic -r rclone:hangar-gdrive:Hangar-sauvegardes snapshots
    restic ... restore latest --target /
  then pg_restore each /srv/backups/staging/db/<app>.dump into app_<app> (see README).

NAS (Backups page): SMB or SFTP via rclone, /srv/platform/backup/nas.rclone.conf (obscured
  password, root file 600). restic repository rclone:hangar-nas:<share>/<path>, same password as Drive.
  Each backup is sent to every connected destination (one line per destination).

Restore test (Backups page, "Restore test" block): after a successful backup, at most once
  a week per destination, or via "Test now" / `hangar backup --verify`. Restores the latest
  backup into /srv/backups/verif-restauration (deleted afterwards): restic check, registry (PRAGMA integrity_check),
  each database reloaded by pg_restore into a throwaway postgres:17 container without network, data/ of each app
  looked up in the snapshot (restic find, without downloading it). Result in the restore_test setting, event log,
  ntfy alert on failure.
Data import (Backups page, "Import data into an app" block): migration from an instance
  hosted elsewhere (kit in docs/prompt-migration.md), or a single app from another server's archive. File
  .tar.gz with db.dump (pg_dump -Fc, checked on upload by pg_restore -l of PostgreSQL 17) and/or data/, or
  db/<app>.dump + apps/<app>/data; links, absolute paths and other files rejected. Stored in
  /srv/backups/imports/import-AAAAMMJJ-HHMMSS.tar.gz (+ .json: contents), deleted after a successful import. The target
  app already exists; its previous state goes to /srv/backups/avant-restauration, then database and/or data/ replaced,
  restart and healthcheck, like a restore. Its variables (secrets) do not change.
Safety copies: before each restore, data import or rollback, the app's state goes to
  /srv/backups/avant-restauration/<app>-AAAAMMJJ-HHMMSS (base-avant.sql.gz + data/). "Go back to this state" button
  on the app page ("Roll back" block): database loaded into a temporary database then swapped (if the
  load fails, the current database is untouched), data/ copied back, healthcheck; the replaced state is itself set
  aside. Listing and deletion also on the Backups page. Purge: older than 30 days, except the last 3 per app.
Manual archives (Backups page): /srv/backups/archives/hangar-AAAAMMJJ-HHMMSS.tar.gz, 10 kept.
  Contents: manifest.json (settings + each app's record, SECRETS INCLUDED), db/<app>.dump, apps/<app>/data.
  Kept unencrypted on the server; downloaded encrypted (gpg --symmetric AES256, S2K SHA512, backup
  password /srv/platform/backup/restic.pass), decrypted on upload, by hangar restore (HANGAR_ARCHIVE_PASSWORD) and
  install.sh --restore. To open by hand: gpg -d file.tar.gz.gpg > file.tar.gz.
  Not encrypted. Creation: `hangar archive`. Restore: upload the file on the page, select the apps;
  a missing app is recreated from its record and then deployed.

Alerts: ntfy, email (SMTP), Discord, Telegram (System and alerts), priority threshold per channel; alert
  language configurable (French or English). Random ntfy topic, keep it secret.
Updates: System and alerts, one table per machine (console and each reachable node). Run in a
  transient unit of the console, hangar-maj-<component> or hangar-maj-<node>-<component>
  (journalctl -u hangar-maj-docker; CLI: hangar sysupdate <component> [--node <node>]). On a node, over SSH
  on the private network. One at a time. Rollback to the previous version if the service does not come back (Docker: the
  daemon, PostgreSQL and the node's apps; Caddy, cloudflared: only if they were running). PostgreSQL on a node:
  pg_dumpall to /srv/backups/avant-maj-postgres-*.sql.gz on the node beforehand (3 kept). ntfy reminder if an update
  has been waiting for more than 14 days (sys_pending_since setting). Debian security fixes remain
  automatic (Security page).
Automatic nightly updates (option, System page, off by default; sys_auto setting): selected components
  (by default cloudflared, Caddy, PostgreSQL minor), time window (3 am – 5 am). Every 5 minutes within the window,
  at most one started (nodes first, console last, Docker after the rest), never during a backup, an
  archive or a deployment. Failure (old version restored): no new attempt for 7 days, unless a newer
  version appears (sys_auto_tried).
Stats: Caddy JSON log /var/log/caddy/access.log (field hangar_app), aggregated per minute, kept 8 days.
Console speed: each Docker command to a node costs ~0.4 s (SSH). Slow measurements are kept in a
  memory cache (app/cache.py) served immediately and refreshed in the background: container state and memory (20 s,
  kept warm), monitoring (30-60 s), system info and time zones (10 min), an app's database (60 s, block loaded
  after the page), size of data/ (5 min). A change in an app's state clears the relevant cache. Backup
  list: last known one immediately, re-read in the background after 10 min. Pages compressed (gzip, except
  downloads), menus prefetched on hover (speculation rules, Chrome/Edge), loading bar.
Availability: uptime table (successful / performed healthchecks per app and per day, 95 days; maintenance excluded).
Weekly report: Monday from 9 am (weekly_report setting = week already sent), button in System.
Maintenance: maintenance setting {app: {on, auto, msg, since}}; Caddy answers 503 with the page, Retry-After and
  X-Hangar-Maintenance: 1. "auto": set and removed by _apply (restore, import, rollback).
Restore points: /srv/backups/avant-restauration/<app>-AAAAMMJJ-HHMMSS with note.txt.
Scheduled tasks: jobs setting, docker exec app-<app>-app-1 sh -c <command> on the app's node, 30 min
  at most, a run missed by more than 2 h is skipped, alert on failure (1 per hour and per task).
Logs: docker compose logs (json-file, 3 × 10 MB per container); pattern alerts (log_alerts setting), checked
  every minute, 1 alert per pattern every 30 minutes.
Redis: app_services setting; redis service (valkey/valkey:8-alpine) added to the app's compose, data in
  data/.hangar-redis, random password, REDIS_URL injected. High availability: hot standby, it follows data/;
  multiple instances, a single Redis on the primary node published on its WireGuard address (app port + 20000),
  reached by the instances (dbports set of hangarapps), recreated empty by a failover. Machine firewall: private
  network open to apps on 28001-58000 (dedicated databases +10000, shared Redis +20000, replicated MySQL/MariaDB
  databases +30000), each app limited to its own ports. An existing console moves from 48000 to 58000 by itself
  at startup (security.upgrade_console_firewall); nodes on the next "Apply" on the Security page.
Staging: preprod setting {staging: prod}, app <app>-preprod (-preprod subdomains), data copied
  by pg_dump -Fc --no-owner + data/ then _apply; HANGAR_ENVIRONMENT=preprod in its compose.
Time zone: System and alerts (timezone setting {tz, apps}): timedatectl set-timezone (otherwise a
  /etc/localtime link) on the console and each node, then on each new node at installation; the console restarts.
  apps option: TZ and /etc/localtime:ro in each app's compose (unless TZ is already in its variables).
Accounts: admin or read role (users table); read-only rejected in the common filter (forms,
  archive and export downloads), except logout and one's own password. Audit log: audit table
  (account, address, method, path, code), never the form contents, 180 days.
Post-deployment checks: smoke setting {app: lines "/path [code] [text]"}, run by deploy() after
  the healthcheck on the starting instance; a failure fails the deployment (automatic rollback).
Max CPU: app_limits setting {app: {cpus}} → compose "cpus". Alerts: memory > 90 % for 5 min, CPU at
  its limit for 10 min (stats_res table), spontaneous restart (RestartCount, OOMKilled).
Session affinity (multiple instances): ha_affinity setting {app: {mode, name}} → Caddy lb_policy header / query /
  cookie / client_ip_hash (round_robin without affinity).
Android apps: remote configuration (remote_config setting) written alongside apps.json in
  public/<domain>/.well-known/apps/<package>.json (minimum and recommended versions, switches, announcement, crash
  upload address and key), served by Caddy on the routes host, pushed to the nodes. Crashes: POST
  /.well-known/hangar/crash/<package> (header X-Hangar-Key, crash_keys setting) → Caddy → console internal server
  (127.0.0.1:8099 and 10.88.0.1:8099; console firewall: 8099 open to the private network only); tables crashes and
  crash_groups, 90 days, 5000 per app; 64 KB per report, 30/min per address, 600/h per app.
App types (column apps.kind, app/kinds.py): web, api, mobile, tool (catalog), worker (no web page: no
  port nor Caddy, healthy if the container is still running after 30 s), game (public ports, public_ports setting, published by
  Docker on all the machine's addresses; rejected if taken by Hangar or another app), static.
Catalog: app/catalog.py; variables {url} {host} {db_*} {secret} filled in at installation.
Clients: pkg (Android), ios_bundle, web_client; web clients served on the app's address
  (/.well-known/hangar/client.js, config.json, crash → internal server), files in public/_clients/.
Static sites: versions in /srv/apps/<app>/site/releases/<n> (10 kept), live version copied to
  /srv/platform/sites/<app> (served by Caddy: root + try_files if single-page), copied to the entry nodes on each
  publication and each route push. Git build: clone --depth 1, command in a throwaway container
  (1 GB, 2 cores at most, 30 min), output folder published without .git. static_sites setting.
Status page: status_page setting, file /srv/platform/public/_status/index.html regenerated every minute,
  sent to the entry nodes when it changes (or every 10 minutes), Caddy block on <subdomain>.<domain>.

Nodes (Nodes page)
  Console SSH key: /srv/platform/nodes/id_ed25519.
  Installation over the public address with root or a sudo account. The sudo password, if any,
  is passed on the input of sudo -k -S and is not stored. bootstrap.sh then allows root by key
  only from 10.88.0.1 (from= in /root/.ssh/authorized_keys, Match Address in
  /etc/ssh/sshd_config.d/00-hangar.conf). Everything else (Docker, rsync, measurements, repairs) goes through there.
  Installation: the console copies deploy/node to /opt/hangar-node and runs bootstrap.sh (idempotent):
  Docker, PostgreSQL (/srv/platform/compose.yml), hangar-node-firewall firewall (SSH, UDP 51820,
  everything from wg-hangar), WireGuard key /etc/wireguard/hangar.key.
  Private network: interface wg-hangar (wg-quick@wg-hangar), 10.88.0.1 = console, 10.88.0.N = nodes.
  The console initiates the link (keepalive 25 s): the VPS must accept UDP 51820 (hosting provider's firewall).
  Remote Docker: DOCKER_HOST=ssh://root@10.88.0.N (Include /srv/platform/nodes/ssh_config in /root/.ssh/config).
  Measurements every minute over SSH (CPU via cgroup v2), alert if unreachable for 2 minutes.
  Apps on a node: compose.yml stays on the console (/srv/apps/<id>), container, data/ and database on the node;
  the console drives them via DOCKER_HOST. Ports published on 127.0.0.1 and on the node's private address
  (Docker starts after wg-quick, drop-in docker.service.d/hangar-wg.conf).
  Traffic entry (tunnel domains if the node's option is on, direct domains it is the entry for): the node's Caddy (Caddyfile pushed by the console on every
  route change, local apps on 127.0.0.1, the others via 10.88.0.x) + cloudflared connector with
  the same token. Statistics: nodes' access logs read over SSH.
  Move (app page › Node): app/move.py. Relayed by the console (rsync), safety copy in
  /srv/backups/avant-deplacement/<app>-<date> (data/ and database): to purge by hand.
  Backups: before each upload, data/ of remote apps copied to /srv/backups/staging/nodes/<app>/data
  (incremental); this mirror takes space on the console. Restore: data/ pushed back to the node,
  database restored into the node's PostgreSQL. Archives: original node in the manifest; a missing app
  is recreated on that node if it exists and is online, otherwise on the console.

## Accounts, two-factor authentication, language
- Roles (table users.role): admin; read (sees everything except secrets, changes nothing); app ("selected apps":
  sees only the granted apps, user_apps setting {account: {app: voir | deployer}}, "My account" page).
- Two-factor authentication (app/totp.py): chosen by each account (Access and accounts or My account), QR code, 8
  single-use recovery codes. Columns users.totp_secret, totp_recovery, totp_last. An administrator can remove it
  from another account. **Phone and codes lost, sole administrator**: as root on the console,
  `hangar 2fa-reset <account>` (and `hangar passwd <account>` if the password is lost too).
- Console language per account (users.lang): templates are translated when loaded (app/i18n.py,
  app/i18n/en.json); messages composed by the code (actions, event log, alerts) according to their template
  (app/msgs.py, app/i18n/msg_en.json). Adding a text: write it in French, then complete both files
  (the tests report templates extracted from the code).

## App: advanced settings
- Startup and health (Advanced tab, app_run setting): entrypoint, command (lists, no shell), health
  command (Docker healthcheck; an app without a web page waits for "healthy"), responses accepted by the health check
  (any code < 500, 2xx-3xx, 2xx; default in System, health_mode setting), persistent folders other than /data
  ("www:/var/www/html" mounts data/www).
- Settings history (Settings tab, app_history table, 50 per app): snapshot taken after each action on
  the app, "Revert" restores a setting and redeploys (automatic rollback if the app does not start).
- Protection (Access and publishing tab, app_protect setting): accounts (bcrypt via `caddy hash-password`) and/or
  allowed addresses, enforced by Caddy; /.well-known/hangar/ stays open.
- Automatic publishing (webhook, hooks setting): /.well-known/hangar/hook[/<app>] → internal server 8099,
  X-Hub-Signature-256 signature or GitLab token, replay rejected. Static site: push → build; image app:
  package published, successful workflow or {"version"}; Git app: push to the live branch → rebuild, tag x.y.z
  → deployment (configurable).
- Tools (Advanced tab): interactive terminal (WebSocket /apps/<app>/terminal/ws, xterm.js served by the console,
  "docker exec -it" in a pseudo-terminal, administrators only, 30 min of inactivity, 4 h at most, recorded in the event log
  and the audit log); data/ files (app/datafiles.py: list, download, replace with the old
  version kept in /srv/backups/avant-remplacement, file restored from the latest backup via restic dump); read-only SQL
  queries (app/sqlquery.py: one read statement, the app's user, read-only
  transaction, 10 s, 500 rows).
- Personal template (custom_catalog setting): an image app becomes a catalog entry; variables that
  look like secrets are regenerated on each installation.

## App services
- MySQL 8.4 / MariaDB 11.4 (app_services[mysql] setting): "mysql" service in the compose, raw files in
  /srv/apps/<app>/mysql (never backed up), consistent export to data/.hangar-mysql/dump.sql.gz before each
  backup, archive, restore point, staging, move; when data/ is replaced, the database restarts from this
  export (the image's initialization folder). Variables MYSQL_HOST, MYSQL_DATABASE, MYSQL_USER, MYSQL_PASSWORD,
  MYSQL_URL. The app waits for the database to answer.
- High availability for a MySQL/MariaDB database (hot standby only, app/mysqlrepl.py): the primary database writes a
  binary log (GTID) and is published on its WireGuard address (app port + 30000, open to this app
  only); on the standby, the myrepl-<app> container (data in /srv/apps/<app>/mysql) follows in read-only
  mode. Seeding: folder prepared by Hangar (mariadb-install-db / mysqld --initialize-insecure), then an export with
  GTID position loaded directly. Planned switchover: app stopped, wait for the GTID position, promotion of the
  replica, app restarted on its data. Outage: promotion as is. The old primary becomes the replica again
  when it returns. Checked every 5 minutes, rebuilt if it has not been following for 10 minutes (never on the
  machine of the primary database). Without a replica, falls back to the export copied with data/.
- Email relay (mail_relay setting, System): a shared SMTP account; an app that enables "Emails" receives
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_SECURE, SMTP_FROM (its own variables take precedence).

## Images and vulnerabilities
- New image under a moving tag (latest…): registry digest compared with that of the running image
  (image_updates setting); "Update" pulls it.
- Trivy scan (app/vulns.py, aquasec/trivy:0.75.0, volume hangar-trivy-cache on each machine): high
  and critical vulnerabilities, every week (configurable day) and after each deployment; alert on a new critical vulnerability
  (not on the first scan). Vulnerabilities tab: vulnerabilities by package, in three families.
- Fixing system packages (app/patch.py): image hangar-patch/<app>:<version>-<date> derived from the live one
  (apk / apt / dnf upgrade), built on each machine of the app (standby and instances too), deployed, rollback to
  the previous image if the app stops answering. Manual or automatic after a scan (general setting vuln_fix, per
  app vuln_fix_apps; at most one attempt per day and per version). Dropped on a move or a new
  build. The app's dependencies: fix prompt in the tab.
- Image cleanup (System, image_cleanup setting, off by default): keeps the live version, the previous one,
  the N most recent and the original of a patched image; deletes the others and those of apps moved elsewhere.

## Monitoring
- Seen from outside (Monitoring, external_probe setting): a chosen machine opens each public address over the
  Internet (curl over SSH); outage = nothing or 5xx (Cloudflare errors explained); alert after N failures.
- Capacity (Monitoring, capacity setting): disk trend over 7 days, date when it will be full, alert before
  the horizon; memory reserved for apps (limits, Redis, MySQL) compared with each machine.
- Disk space (diskuse.py, every hour or "Measure now"): per app and per container on each machine
  (data/, Redis, MySQL export and files, PostgreSQL database, volumes, writable layer, Docker logs, image);
  a machine's page: "What uses the disk" (apps, images, build cache, Trivy cache, orphaned volumes,
  backups, system). Latest reading in kv "diskuse:<machine>", history in stats_disk (90 days).
- Search the logs of all apps: App logs page.
- An app's charts: memory and CPU (limit drawn), memory of its Redis and its MySQL database
  (stats_res, keys "app:redis", "app:mysql").

## Tests
`pytest` (tests/), without root or Docker: throwaway database and folders (conftest.py), HANGAR_NO_BACKGROUND=1 (no
monitoring, no internal server, no measurements during the tests). Firewalls checked by `nft -c` (root or sudo),
Caddyfile by `caddy validate` if installed. Continuous integration: .github/workflows/tests.yml.

