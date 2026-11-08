#!/usr/bin/env bash
# Prépare une machine Debian 13 comme nœud Hangar. Lancé par la console via SSH (root), idempotent.
# Fichiers reçus dans /opt/hangar-node : ce script, compose PostgreSQL, daemon.json, pare-feu, drop-in nftables.
# Sortie lue par la console : lignes « HANGAR_… = valeur ».
set -euo pipefail
cd "$(dirname "$0")"
export DEBIAN_FRONTEND=noninteractive
APT="apt-get -q -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
say() { echo "HANGAR_STEP=$*"; }

. /etc/os-release
[ "${ID:-}" = debian ] || { echo "HANGAR_ERROR=Debian requis (trouvé : ${PRETTY_NAME:-?})"; exit 1; }

say "paquets de base"
$APT update >/dev/null
$APT install --no-upgrade ca-certificates curl gnupg nftables wireguard-tools python3 rsync unattended-upgrades >/dev/null

say "Docker"
install -m 0755 -d /etc/apt/keyrings
[ -f /etc/apt/keyrings/docker.asc ] || curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $VERSION_CODENAME stable" \
  > /etc/apt/sources.list.d/docker.list
$APT update >/dev/null
$APT install --no-upgrade docker-ce docker-ce-cli containerd.io docker-compose-plugin docker-buildx-plugin >/dev/null
if ! cmp -s daemon.json /etc/docker/daemon.json 2>/dev/null; then
  install -m 0644 daemon.json /etc/docker/daemon.json
  systemctl restart docker
fi
systemctl enable --now docker >/dev/null 2>&1
docker info >/dev/null 2>&1 || { echo "HANGAR_ERROR=Docker ne démarre pas (en LXC : nesting=1,keyctl=1 sur l'hôte Proxmox)"; exit 1; }
docker network inspect platform >/dev/null 2>&1 || docker network create platform >/dev/null

say "PostgreSQL"
install -d -m 0755 /srv/platform /srv/apps /srv/backups
install -d -m 0700 /srv/backups/staging
if [ ! -f /srv/platform/postgres.env ]; then
  umask 077; printf 'POSTGRES_USER=platform\nPOSTGRES_PASSWORD=%s\n' "$(openssl rand -hex 24)" > /srv/platform/postgres.env; umask 022
fi
install -m 0644 platform-compose.yml /srv/platform/compose.yml
(cd /srv/platform && docker compose up -d --quiet-pull >/dev/null 2>&1)
for _ in $(seq 1 60); do docker exec platform-postgres-1 pg_isready -U platform >/dev/null 2>&1 && break; sleep 2; done
docker exec platform-postgres-1 pg_isready -U platform >/dev/null 2>&1 || { echo "HANGAR_ERROR=PostgreSQL ne démarre pas"; exit 1; }

say "pare-feu"
install -d /etc/nftables.d /etc/systemd/system/nftables.service.d
install -m 0644 node.nft /etc/nftables.d/hangar-node.nft
install -m 0644 nftables-neutralise.conf /etc/systemd/system/nftables.service.d/hangar.conf
cat > /etc/systemd/system/hangar-node-firewall.service <<'EOF'
[Unit]
Description=Pare-feu nftables du nœud Hangar
After=network-pre.target
Before=network-online.target docker.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/nftables.d/hangar-node.nft
ExecStop=/usr/sbin/nft delete table inet hangarnode
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl disable nftables.service >/dev/null 2>&1 || true
nft -c -f /etc/nftables.d/hangar-node.nft
systemctl enable hangar-node-firewall >/dev/null 2>&1
systemctl restart hangar-node-firewall

say "mises à jour de sécurité automatiques"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
cat > /etc/apt/apt.conf.d/52platform-unattended <<'EOF'
// Sécurité Debian uniquement. Docker reste manuel (via la console Hangar).
Unattended-Upgrade::Origins-Pattern { "origin=Debian,codename=${distro_codename}-security,label=Debian-Security"; };
Unattended-Upgrade::Package-Blacklist { "docker-ce"; "docker-ce-cli"; "containerd.io"; };
Unattended-Upgrade::Automatic-Reboot "false";
EOF

say "clé WireGuard"
install -d -m 0700 /etc/wireguard
if [ ! -f /etc/wireguard/hangar.key ]; then
  umask 077; wg genkey > /etc/wireguard/hangar.key; umask 022
fi
echo "HANGAR_WG_PUBKEY=$(wg pubkey < /etc/wireguard/hangar.key)"
echo "HANGAR_DOCKER=$(docker version --format '{{.Server.Version}}')"
echo "HANGAR_OS=$PRETTY_NAME"
echo "HANGAR_DONE=1"
