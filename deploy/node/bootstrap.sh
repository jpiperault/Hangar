#!/usr/bin/env bash
# Prépare une machine Debian 13 comme nœud Hangar. Lancé par la console via SSH (root, ou un compte avec sudo), idempotent.
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
$APT install --no-upgrade ca-certificates curl gnupg nftables wireguard-tools python3 rsync git openssh-server unattended-upgrades >/dev/null

say "Docker"
install -m 0755 -d /etc/apt/keyrings
[ -f /etc/apt/keyrings/docker.asc ] || curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $VERSION_CODENAME stable" \
  > /etc/apt/sources.list.d/docker.list
[ -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg ] || \
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main" \
  > /etc/apt/sources.list.d/caddy-stable.list
[ -f /usr/share/keyrings/cloudflare-main.gpg ] || curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
  > /etc/apt/sources.list.d/cloudflared.list
$APT update >/dev/null
$APT install --no-upgrade docker-ce docker-ce-cli containerd.io docker-compose-plugin docker-buildx-plugin caddy cloudflared >/dev/null
# Docker après WireGuard : les conteneurs publient leurs ports sur l'adresse privée du nœud
install -d /etc/systemd/system/docker.service.d
printf '[Unit]\nAfter=wg-quick@wg-hangar.service\nWants=wg-quick@wg-hangar.service\n' > /etc/systemd/system/docker.service.d/hangar-wg.conf
systemctl daemon-reload
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

say "Caddy"
install -d /srv/platform/public/.well-known
[ -f /srv/platform/Caddyfile ] || echo "# généré par la console Hangar" > /srv/platform/Caddyfile
printf '# Caddy lit la configuration poussée par la console Hangar\nimport /srv/platform/Caddyfile\n' > /etc/caddy/Caddyfile
systemctl enable caddy >/dev/null 2>&1
systemctl restart caddy

say "pare-feu"
install -d /etc/nftables.d /etc/systemd/system/nftables.service.d
# pare-feu de départ ; ensuite celui de la page Sécurité de la console (posé à la fin de l'installation)
[ -f /etc/nftables.d/hangar-node.nft ] || install -m 0644 node.nft /etc/nftables.d/hangar-node.nft
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
ExecStart=-/bin/sh -c '[ ! -f /etc/nftables.d/hangar-apps.nft ] || /usr/sbin/nft -f /etc/nftables.d/hangar-apps.nft'
ExecStop=/usr/sbin/nft delete table inet hangarnode
ExecStop=-/usr/sbin/nft delete table inet hangarapps
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
// Sécurité Debian uniquement. Docker, Caddy, cloudflared : page Système et alertes de la console Hangar.
Unattended-Upgrade::Origins-Pattern { "origin=Debian,codename=${distro_codename}-security,label=Debian-Security"; };
Unattended-Upgrade::Package-Blacklist { "docker-ce"; "docker-ce-cli"; "containerd.io"; "caddy"; "cloudflared"; };
Unattended-Upgrade::Automatic-Reboot "false";
EOF

say "clé WireGuard"
install -d -m 0700 /etc/wireguard
if [ ! -f /etc/wireguard/hangar.key ]; then
  umask 077; wg genkey > /etc/wireguard/hangar.key; umask 022
fi
say "accès SSH de la console"
# La console travaille ensuite en root, par clé, et uniquement depuis son adresse sur le réseau privé (10.88.0.1).
# L'accès root par l'adresse publique n'est pas nécessaire : il reste tel que l'hébergeur l'a configuré.
if [ -f console.authorized ]; then
  install -d -m 0700 /root/.ssh
  touch /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
  k=$(awk '{print $(NF-1)}' console.authorized)
  grep -qF "from=\"10.88.0.1\" ssh-ed25519 $k" /root/.ssh/authorized_keys || cat console.authorized >> /root/.ssh/authorized_keys
  # une fois la sécurité gérée par la console, ce fichier est le sien : on n'y touche plus ici
  if [ -d /etc/ssh/sshd_config.d ] && ! grep -qs 'Sécurité' /etc/ssh/sshd_config.d/00-hangar.conf; then
    printf '# Hangar : root par clé, seulement depuis la console (réseau privé)\nMatch Address 10.88.0.1\n    PermitRootLogin prohibit-password\n' \
      > /etc/ssh/sshd_config.d/00-hangar.conf
    install -d -m 0755 /run/sshd   # absent hors connexion quand SSH est lancé par socket : sshd -t échouerait
    sshd -t || { rm -f /etc/ssh/sshd_config.d/00-hangar.conf; echo "HANGAR_ERROR=configuration SSH refusée par sshd"; exit 1; }
    # les sessions ouvertes survivent à un redémarrage de sshd
    systemctl reload ssh 2>/dev/null || systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
  fi
  install -d -m 0755 /run/sshd
  t=$(sshd -T -C user=root,host=hangar,addr=10.88.0.1 2>/dev/null) || t=""
  echo "$t" | grep -qi '^permitrootlogin \(no\|forced-commands-only\)' && \
    { echo "HANGAR_ERROR=sshd refuse root même depuis la console (PermitRootLogin) : vérifie /etc/ssh/sshd_config"; exit 1; }
  if echo "$t" | grep -qi '^allowusers ' && ! echo "$t" | grep -i '^allowusers ' | grep -qw root; then
    echo "HANGAR_ERROR=AllowUsers dans sshd_config : ajoute root@10.88.0.1 à la liste"; exit 1
  fi
fi

echo "HANGAR_WG_PUBKEY=$(wg pubkey < /etc/wireguard/hangar.key)"
echo "HANGAR_DOCKER=$(docker version --format '{{.Server.Version}}')"
echo "HANGAR_OS=$PRETTY_NAME"
echo "HANGAR_DONE=1"
