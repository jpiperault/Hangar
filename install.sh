#!/usr/bin/env bash
# Installation de Hangar sur Debian 13 (conteneur LXC Proxmox, VM ou serveur dédié).
# Idempotent : peut être relancé ; les secrets et réglages existants ne sont jamais remplacés.
#
#   ./install.sh                                  installation interactive
#   ./install.sh --domain piperault.fr --mode tunnel --tunnel-token <jeton> --restore hangar-….tar.gz --yes
#
# À lancer en root depuis une copie du dépôt (git clone ou archive du dépôt).
set -euo pipefail

DOMAIN="" HUB="apps" MODE="" LAN="" IP="" TOKEN="" RESTORE="" TZONE="Europe/Paris" YES=0
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST=/opt/hangar

usage() {
  cat <<EOF
Usage : $0 [options]
  --domain DOMAINE      domaine de base (ex. piperault.fr)
  --hub NOM             hôte des routes par chemin (défaut : apps → apps.DOMAINE)
  --mode tunnel|direct  tunnel Cloudflare (défaut) ou direct (ports 80/443, Let's Encrypt)
  --ip IP               IP locale de la console (défaut : IP de l'interface principale)
  --lan CIDR            réseau autorisé pour la console et SSH (défaut : réseau de cette IP)
  --tunnel-token JETON  relie cloudflared au tunnel (mode tunnel)
  --restore ARCHIVE     restaure toutes les applis et les réglages d'une archive Hangar (.tar.gz)
  --timezone TZ         fuseau horaire (défaut : Europe/Paris ; « keep » pour ne pas changer)
  --yes                 ne pose aucune question
EOF
  exit "${1:-0}"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --hub) HUB="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --ip) IP="$2"; shift 2 ;;
    --lan) LAN="$2"; shift 2 ;;
    --tunnel-token) TOKEN="$2"; shift 2 ;;
    --restore) RESTORE="$(readlink -f "$2")"; shift 2 ;;
    --timezone) TZONE="$2"; shift 2 ;;
    --yes|-y) YES=1; shift ;;
    -h|--help) usage ;;
    *) echo "Option inconnue : $1"; usage 1 ;;
  esac
done

step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
die() { printf '\n\033[1;31mErreur : %s\033[0m\n' "$*" >&2; exit 1; }
ask() {  # ask VAR "question" "défaut"
  local __v="$1" __q="$2" __d="$3" __r
  if [ -n "${!__v}" ]; then return; fi
  if [ "$YES" = 1 ]; then printf -v "$__v" '%s' "$__d"; return; fi
  read -r -p "    $__q [$__d] : " __r </dev/tty || true
  printf -v "$__v" '%s' "${__r:-$__d}"
}

# ------------------------------------------------------------------ vérifications
[ "$(id -u)" = 0 ] || die "lance ce script en root."
[ -f "$SRC/app/main.py" ] && [ -f "$SRC/requirements.txt" ] || die "lance ce script depuis le dossier du dépôt Hangar."
. /etc/os-release
[ "${ID:-}" = debian ] || die "Debian requis (trouvé : ${PRETTY_NAME:-inconnu})."
[ "${VERSION_CODENAME:-}" = trixie ] || echo "Attention : prévu pour Debian 13 (trixie), trouvé ${VERSION_CODENAME:-?}. On continue."
[ -z "$RESTORE" ] || [ -f "$RESTORE" ] || die "archive introuvable : $RESTORE"
case "$(dpkg --print-architecture)" in amd64|arm64) ;; *) die "architecture non prise en charge : $(dpkg --print-architecture)";; esac
if [ "$(systemd-detect-virt -c 2>/dev/null || true)" = lxc ]; then
  info "Conteneur LXC : Docker y demande « pct set <id> --features nesting=1,keyctl=1 » sur l'hôte Proxmox."
fi

DEFIF=$(ip -4 route show default | awk '{print $5; exit}')
DEFIP=$(ip -4 -o addr show dev "${DEFIF:-eth0}" 2>/dev/null | awk '{print $4; exit}')
ask IP "IP locale de la console" "${DEFIP%/*}"
if [ -z "$LAN" ] && [ -n "$DEFIP" ]; then
  LAN=$(python3 -c "import ipaddress,sys;print(ipaddress.ip_interface(sys.argv[1]).network)" "$DEFIP")
fi
ask LAN "Réseau local autorisé" "${LAN:-192.168.1.0/24}"

if [ -f /srv/platform/.env ]; then
  info "Configuration existante trouvée (/srv/platform/.env) : domaine et mode conservés."
  . /srv/platform/.env
  DOMAIN="${DOMAIN:-$BASE_DOMAIN}"; MODE="${MODE:-$EXPOSURE_MODE}"
fi
ask DOMAIN "Domaine de base" "piperault.fr"
ask MODE "Mode d'exposition (tunnel ou direct)" "tunnel"
case "$MODE" in tunnel|direct) ;; *) die "mode invalide : $MODE";; esac
python3 -c "import ipaddress,sys;ipaddress.ip_address(sys.argv[1]);ipaddress.ip_network(sys.argv[2])" "$IP" "$LAN" \
  || die "IP ou réseau invalide : $IP / $LAN"

echo
info "Console : https://$IP:8443 (réseau $LAN)   Domaine : $HUB.$DOMAIN   Mode : $MODE"
[ -n "$RESTORE" ] && info "Restauration de : $RESTORE"
if [ "$YES" != 1 ]; then read -r -p "    Continuer ? [O/n] " r </dev/tty || true; case "${r:-o}" in [oOyY]*) ;; *) exit 1;; esac; fi

export DEBIAN_FRONTEND=noninteractive
# --no-upgrade : un paquet déjà présent n'est jamais mis à jour ici (les mises à jour passent par la console)
APT="apt-get -q -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
APTI="$APT install --no-upgrade"

# ------------------------------------------------------------------ paquets
step "Paquets de base"
[ "$TZONE" = keep ] || timedatectl set-timezone "$TZONE" 2>/dev/null || ln -sf "/usr/share/zoneinfo/$TZONE" /etc/localtime
$APT update >/dev/null
$APTI ca-certificates curl gnupg git openssl python3 python3-venv nftables unattended-upgrades \
  restic rclone sqlite3 >/dev/null

step "Dépôts Docker, Caddy et cloudflared"
install -m 0755 -d /etc/apt/keyrings
if [ ! -f /etc/apt/keyrings/docker.asc ]; then
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
fi
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $VERSION_CODENAME stable" \
  > /etc/apt/sources.list.d/docker.list
if [ ! -f /usr/share/keyrings/caddy-stable-archive-keyring.gpg ]; then
  curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
fi
echo "deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main" \
  > /etc/apt/sources.list.d/caddy-stable.list
if [ ! -f /usr/share/keyrings/cloudflare-main.gpg ]; then
  curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
fi
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
  > /etc/apt/sources.list.d/cloudflared.list
$APT update >/dev/null
$APTI docker-ce docker-ce-cli containerd.io docker-compose-plugin docker-buildx-plugin caddy cloudflared >/dev/null
info "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '?'), $(caddy version | cut -d' ' -f1), $(cloudflared --version 2>/dev/null | awk '{print $3}')"

# ------------------------------------------------------------------ dossiers et Docker
step "Dossiers et Docker"
install -d -m 0755 /srv/platform /srv/platform/public/.well-known /srv/apps /srv/backups /var/log/caddy
install -d -m 0700 /srv/platform/tls /srv/platform/backup /srv/backups/postgres /srv/backups/staging \
  /srv/backups/archives /var/cache/restic
chown caddy:caddy /var/log/caddy
if ! cmp -s "$SRC/deploy/docker/daemon.json" /etc/docker/daemon.json 2>/dev/null; then
  install -m 0644 "$SRC/deploy/docker/daemon.json" /etc/docker/daemon.json
  systemctl restart docker
fi
systemctl enable --now docker >/dev/null 2>&1
docker info >/dev/null 2>&1 || die "Docker ne démarre pas. En LXC : active nesting=1,keyctl=1 sur l'hôte puis redémarre le conteneur."
docker network inspect platform >/dev/null 2>&1 || docker network create platform >/dev/null

# ------------------------------------------------------------------ code de la console
step "Console Hangar ($DEST)"
if [ "$SRC" != "$DEST" ]; then
  install -d -m 0755 "$DEST"
  tar -C "$SRC" --exclude=./venv --exclude='*/__pycache__' -cf - . | tar -C "$DEST" -xf -
fi
[ -x "$DEST/venv/bin/python" ] || python3 -m venv "$DEST/venv"
"$DEST/venv/bin/pip" install -q --upgrade pip >/dev/null
"$DEST/venv/bin/pip" install -q -r "$DEST/requirements.txt"
install -m 0755 "$DEST/deploy/bin/hangar" /usr/local/bin/hangar

# ------------------------------------------------------------------ configuration de la plateforme
step "Configuration"
if [ ! -f /srv/platform/.env ]; then
  cat > /srv/platform/.env <<EOF
BASE_DOMAIN=$DOMAIN
HUB=$HUB
ADMIN_BIND=$IP:8443
LAN_CIDR=$LAN
EXPOSURE_MODE=$MODE
TUNNEL_BIND=127.0.0.1:8080
EOF
  info "/srv/platform/.env créé"
else
  sed -i "s|^ADMIN_BIND=.*|ADMIN_BIND=$IP:8443|; s|^LAN_CIDR=.*|LAN_CIDR=$LAN|" /srv/platform/.env
fi
chgrp caddy /srv/platform/.env && chmod 640 /srv/platform/.env
if [ ! -f /srv/platform/postgres.env ]; then
  umask 077; printf 'POSTGRES_USER=platform\nPOSTGRES_PASSWORD=%s\n' "$(openssl rand -hex 24)" > /srv/platform/postgres.env; umask 022
  info "mot de passe PostgreSQL généré"
fi
install -m 0644 "$SRC/deploy/docker/platform-compose.yml" /srv/platform/compose.yml
[ -f /srv/platform/Caddyfile ] || echo "# généré par Hangar" > /srv/platform/Caddyfile
if [ ! -f /srv/platform/tls/hangar.crt ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 -subj "/CN=Hangar" \
    -addext "subjectAltName=IP:$IP" -keyout /srv/platform/tls/hangar.key -out /srv/platform/tls/hangar.crt 2>/dev/null
  chmod 600 /srv/platform/tls/hangar.key
  info "certificat de la console créé (auto-signé, IP $IP)"
fi

step "PostgreSQL"
(cd /srv/platform && docker compose up -d --quiet-pull >/dev/null 2>&1)
for _ in $(seq 1 60); do
  docker exec platform-postgres-1 pg_isready -U platform >/dev/null 2>&1 && break
  sleep 2
done
docker exec platform-postgres-1 pg_isready -U platform >/dev/null 2>&1 || die "PostgreSQL ne démarre pas."
info "PostgreSQL prêt"

step "Caddy, pare-feu, mises à jour automatiques"
install -m 0644 "$SRC/deploy/caddy/etc-caddy-Caddyfile" /etc/caddy/Caddyfile
install -d /etc/systemd/system/caddy.service.d
install -m 0644 "$SRC/deploy/systemd/caddy-platform.conf" /etc/systemd/system/caddy.service.d/platform.conf
install -d /etc/nftables.d
sed "s|elements = { [^}]* }|elements = { $LAN }|" "$SRC/deploy/nftables/platform.nft" > /etc/nftables.d/platform.nft
nft -c -f /etc/nftables.d/platform.nft || die "règles de pare-feu invalides"
install -m 0644 "$SRC/deploy/apt/20auto-upgrades" /etc/apt/apt.conf.d/20auto-upgrades
install -m 0644 "$SRC/deploy/apt/52platform-unattended" /etc/apt/apt.conf.d/52platform-unattended
# nftables.service fait « flush ruleset » au démarrage comme à l'arrêt : il effacerait les règles de Docker.
# On le désactive sans l'arrêter (l'arrêter déclencherait justement ce flush).
# Neutralisé par un drop-in : son démarrage comme son arrêt deviennent sans effet.
systemctl disable nftables.service >/dev/null 2>&1 || true
install -d /etc/systemd/system/nftables.service.d
install -m 0644 "$SRC/deploy/systemd/nftables-neutralise.conf" /etc/systemd/system/nftables.service.d/hangar.conf

step "Services"
for u in hangar.service platform-backup.service platform-backup.timer platform-firewall.service; do
  install -m 0644 "$SRC/deploy/systemd/$u" "/etc/systemd/system/$u"
done
systemctl daemon-reload
systemctl enable --now platform-firewall.service >/dev/null 2>&1
systemctl restart caddy
systemctl enable --now platform-backup.timer >/dev/null 2>&1
systemctl enable hangar.service >/dev/null 2>&1
systemctl restart hangar.service

if [ "$MODE" = tunnel ] && [ -n "$TOKEN" ]; then
  step "Tunnel Cloudflare"
  install -d -m 0755 /etc/cloudflared
  umask 077; printf '%s\n' "$TOKEN" > /etc/cloudflared/token; umask 022
  cat > /etc/systemd/system/cloudflared.service <<'EOF'
[Unit]
Description=Cloudflare Tunnel client
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/cloudflared --no-autoupdate tunnel run --token-file /etc/cloudflared/token
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now cloudflared >/dev/null 2>&1
  systemctl restart cloudflared
  info "cloudflared lancé"
fi

step "Compte administrateur"
for _ in $(seq 1 30); do systemctl is-active -q hangar && break; sleep 1; done
NEWPW=0
if ! sqlite3 /srv/platform/platform.db "SELECT 1 FROM users LIMIT 1" 2>/dev/null | grep -q 1; then
  hangar passwd --random >/dev/null
  NEWPW=1
  info "mot de passe généré dans /root/hangar-mot-de-passe.txt"
else
  info "compte existant conservé"
fi
hangar routing >/dev/null && info "routes Caddy générées"

if [ -n "$RESTORE" ]; then
  step "Restauration de l'archive"
  hangar restore "$RESTORE" || echo "    Certaines applis ne sont pas en ligne : voir la console (Applications et Journal)."
fi

step "Terminé"
info "Console : https://$IP:8443  (réseau local uniquement, certificat auto-signé)"
[ "$NEWPW" = 1 ] && info "Identifiants : cat /root/hangar-mot-de-passe.txt   (à changer avec : hangar passwd)"
if [ "$MODE" = tunnel ]; then
  if ! systemctl is-active -q cloudflared; then
    info "Tunnel : cloudflared n'est pas relié. Relance avec --tunnel-token <jeton> (Zero Trust › Tunnels)."
  fi
  info "Cloudflare Zero Trust : publie $HUB.$DOMAIN (et chaque sous-domaine d'appli) vers http://127.0.0.1:8080"
else
  info "DNS : enregistrement A $HUB.$DOMAIN (et chaque sous-domaine d'appli) vers l'IP publique ; ports 80 et 443 ouverts."
fi
info "Sauvegardes : reconnecte Drive et/ou le NAS dans la console (avec le mot de passe de tes sauvegardes)."
info "Images privées : renseigne le jeton du registre dans la fiche d'une appli si son déploiement échoue."
