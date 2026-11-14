# Installing Hangar on a new server and restoring everything

*Version française : [../reprise.md](../reprise.md).*

This guide covers three cases:
- the current server is lost;
- you are moving to another machine (another container, or a dedicated server at a hosting provider);
- you want a test copy.

## 1. Prepare the machine

**Proxmox LXC container** (as today):
- Debian 13, 1 to 2 vCPUs, 2 GB of RAM, 20 GB of disk or more;
- a fixed IP on the local network;
- unprivileged, which is fine as is;
- **Options › Features**: tick `nesting` and `keyctl`. From the command line, on the host:

```bash
pct set <id> --features nesting=1,keyctl=1
```

**Dedicated server or VM**: minimal Debian 13, with SSH access. No direct root access needed: your usual account is enough if it has `sudo` (the default at most hosting providers). In the steps below, prefix the commands with `sudo`, for example `sudo ./install.sh`.

The console server must stay on the local network, because the console is only reachable from the LAN. A rented VPS or dedicated server is better connected as an additional **node** (Nodes page): see below.

## 2. Get the code

The repository is private. Two ways to copy it to the new machine:

- **Without Git**: on GitHub, open "Code", then "Download ZIP". Then:
  ```bash
  scp Hangar-main.zip <compte>@<ip>:
  ```
  then, on the machine:
  ```bash
  apt install -y unzip && unzip Hangar-main.zip && cd Hangar-main
  ```
- **With Git**: create a read-only deploy key on the machine (as for this server), then clone the repository:
  ```bash
  git clone <adresse de ton dépôt Hangar> hangar && cd hangar
  ```

## 3. Install (and restore at the same time if you have an archive)

```bash
./install.sh --domain exemple.fr --mode tunnel --tunnel-token <jeton> --restore hangar-AAAAMMJJ-HHMMSS.tar.gz
```

- Without options, the script asks the questions: IP, local network, domain, mode.
- `--tunnel-token`: the tunnel token, in Zero Trust › Networks › Tunnels › your tunnel. You can reuse the same tunnel: the old server simply must no longer be running.
- `--mode direct`: for a dedicated server with ports 80 and 443 open. Certificates then come from Let's Encrypt.
- `--restore`: the archive downloaded from the Backups page. It recreates all apps, their databases, their files and the domain.
- The script can be run again safely: it never replaces an existing secret or setting.

At the end, the script shows the console address. The generated username and password are in `/root/hangar-mot-de-passe.txt` (change them in Access and accounts, or with `hangar passwd`).

## 4. Recover from a downloaded file

A `.tar.gz` archive downloaded from **Backups › Archives to download** is enough to recover everything. It contains, for each app:
- its record: image, version, variables, settings;
- the export of its database;
- its `data/` folder.

It also contains the domains (mode, prefix, entry machine) and the addresses of each app. Archives from before multi-domain support (base domain and aliases) remain readable: each alias becomes a domain.

### From the browser

1. Install Hangar with `./install.sh`, without `--restore`.
2. Open the console, then **Backups › Archives to download**.
3. With **Choose file**, pick the archive on your PC (`.tar.gz.gpg`), type the old server's **Backup password**, then click **Upload an archive to restore it**. The archive can be up to 20 GB.
4. The archive page opens:
   - click **Select all**;
   - keep **Restore settings** ticked to get the same domain and the same mode back;
   - type `restaurer` and start the restore.
5. Follow the progress in **Apps**. A missing app is recreated from its record, with its database and its files, then deployed.

An app that already exists is not overwritten without a safety net: its current files and database are first copied to `/srv/backups/avant-restauration`.

### From the command line

First copy the archive to the machine. From your PC:

```bash
scp hangar-AAAAMMJJ-HHMMSS.tar.gz <compte>@<ip-du-serveur>:
```

During installation, from the code folder:

```bash
sudo HANGAR_ARCHIVE_PASSWORD='<mot de passe des sauvegardes>' ./install.sh --restore ~/hangar-AAAAMMJJ-HHMMSS.tar.gz.gpg
```

Without `HANGAR_ARCHIVE_PASSWORD`, the password is asked for at restore time.

Or on a server that is already installed:

```bash
sudo hangar restore ~/hangar-AAAAMMJJ-HHMMSS.tar.gz.gpg
```

`hangar restore` options:
- `--apps appli1,appli2`: restores only these apps;
- `--no-settings`: keeps the domain and mode of the current server.

The command shows the final state of each app. It exits with an error if an app is not online.

### Good to know

- **The downloaded archive is encrypted** (`.tar.gz.gpg`, gpg AES-256) with the **backup password** of the server that created it (Backups › Backup password page). Without it, the archive is unreadable: keep it in your password manager. Hangar decrypts it automatically on upload ("Password" field if it comes from another server), with `hangar restore` and `install.sh --restore`. To open it on a PC: `gpg -d hangar-….tar.gz.gpg > hangar-….tar.gz` (Gpg4win on Windows). Older unencrypted archives are still accepted.
- On the server, archives are kept unencrypted in `/srv/backups/archives`, readable by root only (the server holds these secrets anyway). Delete the decrypted copies on your PC once the recovery is done.
- **Private images**: registry tokens are not in the archive. If an app fails to pull its image, paste the `read:packages` token into its app page and save: it redeploys.

## 5. Restore from Google Drive or the NAS (without an archive)

1. Install without `--restore`.
2. In the console, open **Backups › Backup password › New server?** and enter **your backup password**, the one you wrote down.
3. Connect **Google Drive** with the same Google account as before, and/or the **NAS** with the same folders. Hangar finds the existing repository. The existing Google project (client ID and client secret) can be reused as is; it must stay "In production", and its two public pages come back as soon as the domain is restored (see [google-drive.md](../google-drive.md)).
4. In **Restore an app**, choose the most recent backup, then click **Restore everything (server recovery)…**. Hangar downloads it and converts it into an archive.
5. In **Archives**, open the "imported" archive and click **Select all**. Tick **Restore settings**, then start the restore.

## 6. After the restore

- **Private images**: if an app fails to pull, paste the `read:packages` token into its app page, then redeploy. Registry tokens are not in the backups.
- **Cloudflare**: with an API token (Domains › Cloudflare), Hangar declares the names again by itself; otherwise, check that they are declared in the tunnel (Domains › Public names).
- **Alerts**: subscribe to the new ntfy topic (System and alerts page), or set the old one back.
- **Backups**: check that Drive and/or the NAS are connected, then run a backup.

## Several nodes

Backups and archives contain the apps of **all** nodes. Each app keeps track of its node.

- **Recovering the console only**, while the nodes are still running: install the console, then add each node again in **Nodes** with **the same identifier**. Reinstalling is safe, nothing is erased on the machine. Then restore the archive: each app goes back to its node.
- **Lost node**: its apps are recreated on the console if it no longer exists. Add a new node, then use **Move** from each app's page.
- **Before a restore**, add the nodes: an app is only recreated on its original node if that node is already online.

## What is not backed up

These items must be redone by hand:
- image registry tokens;
- the tunnel token;
- Drive and NAS access;
- the console's SSH key for the nodes (a new one is created: paste its authorization line on each node again);
- the console administrator account, and the accounts' two-factor authentication;
- publishing webhooks (secret to recreate on the app page, then in GitHub);
- patched images (system packages): redone with "Fix now", or by themselves in automatic mode;
- the standbys' MySQL/MariaDB replicas: rebuilt when high availability is set up again.

## Locked out of the console

- **Lost password**: as root on the console, `hangar passwd <compte>` (list: `hangar users`).
- **Lost two-factor authentication phone** (and recovery codes too): another administrator can remove it
  from Access and accounts; otherwise, as root on the console, `hangar 2fa-reset <compte>`.
- **Console address or network changed by mistake**: without confirmation within 3 minutes, the old setting
  comes back by itself; manually, `hangar access-revert`.

## Adding a VPS or dedicated server as a node

On the console's **Nodes** page:

1. On the server, log in with your usual account (or as root if the hosting provider allows it) and paste the line shown by the console. It adds Hangar's key to `~/.ssh/authorized_keys`.
2. In the form, enter this account. If its `sudo` asks for a password, enter that password too.
3. Start the installation.

The `sudo` password is only used during installation. It goes through `sudo`'s input (never on the command line) and is not stored anywhere.

At the end of the installation, the console drives the node as root, but only over the WireGuard private network:

- Hangar's key is authorized for root with `from="10.88.0.1"`, the console's address on that network;
- `/etc/ssh/sshd_config.d/00-hangar.conf` adds `PermitRootLogin prohibit-password` for that address only.

Root access through the public address stays as the hosting provider set it, usually closed. Repairs ("Reinstall / repair") go through the private network and therefore need no password as long as it works.

If `sshd_config` contains an `AllowUsers` list, add `root@10.88.0.1` to it. Otherwise the installation stops with a message saying so.

### Node security

At the end of the installation, the console applies the policy of the **Security** page: firewall, SSH, fail2ban, updates. By default, SSH stays open on the installation port with passwords allowed: nothing changes for your own connection.

To harden: add your public key in **Admin SSH keys**, choose **Keys only**, and if possible **Restricted to addresses** with your router's public address. Each change reverts by itself after 2 minutes if the console can no longer connect to the node.

The console always goes through the private network: even with SSH closed on the public address, it keeps driving the node. Before closing it, check that you have access to your hosting provider's emergency console. The commands to unlock a node are on the Security page.
