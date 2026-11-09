#!/usr/bin/env bash
# Applique la politique de sécurité envoyée par la console Hangar (page Sécurité).
# Lancé détaché par systemd-run (une coupure SSH ne l'interrompt pas) ; sortie lue par la console : « HANGAR_… = valeur ».
# Avant tout changement, le retour à l'ancien réglage est programmé (minuteur hangar-sec-retour) : la console l'annule
# seulement si une nouvelle connexion par le réseau privé passe encore.
set -uo pipefail
cd "$(dirname "$0")"
. ./env
say() { echo "HANGAR_STEP=$*"; }
WARN=""
warn() { WARN="${WARN:+$WARN ; }$*"; }
PREV=/var/lib/hangar-sec/prev
die() { echo "HANGAR_ERROR=$*"; [ -f $PREV/list ] && bash $PREV/revert.sh >/dev/null 2>&1; exit 1; }

HOME_DIR=$(getent passwd "$ADMIN_USER" | cut -d: -f6)
[ -n "$HOME_DIR" ] || { echo "HANGAR_ERROR=compte $ADMIN_USER introuvable"; exit 1; }
AK="$HOME_DIR/.ssh/authorized_keys"
SOCK=/etc/systemd/system/ssh.socket.d/hangar.conf
NFT=/etc/nftables.d/hangar-node.nft
SSHD=/etc/ssh/sshd_config.d/00-hangar.conf
JAIL=/etc/fail2ban/jail.d/hangar.local
SOCKMODE=0
systemctl is-enabled ssh.socket 2>/dev/null | grep -q '^enabled' && SOCKMODE=1

# un changement précédent jamais confirmé : on le défait d'abord
[ -f $PREV/list ] && bash $PREV/revert.sh >/dev/null 2>&1

if [ "$F2B" = 1 ] && ! command -v fail2ban-client >/dev/null; then
  say "installation de fail2ban"
  export DEBIAN_FRONTEND=noninteractive
  apt-get -q -y install fail2ban python3-systemd >/dev/null 2>&1 || \
    { apt-get -q update >/dev/null 2>&1; apt-get -q -y install fail2ban python3-systemd >/dev/null 2>&1; } || \
    { echo "HANGAR_ERROR=installation de fail2ban impossible (apt)"; exit 1; }
  systemctl stop fail2ban 2>/dev/null   # démarré par le paquet avec la configuration Debian : on pose la nôtre d'abord
fi

say "sauvegarde de l'ancien réglage"
rm -rf $PREV && mkdir -p -m 0700 $PREV
cp revert.sh $PREV/revert.sh
i=0
for t in $NFT $SSHD $JAIL /etc/apt/apt.conf.d/53hangar-securite /etc/sysctl.d/90-hangar.conf $SOCK "$AK"; do
  i=$((i + 1)); [ -e "$t" ] && cp -a "$t" "$PREV/$i"; echo "$i $t" >> $PREV/list
done
systemctl is-active fail2ban >/dev/null 2>&1 && touch $PREV/f2b-actif
systemctl stop hangar-sec-retour.timer >/dev/null 2>&1
systemctl reset-failed hangar-sec-retour.timer hangar-sec-retour.service >/dev/null 2>&1
systemd-run --unit=hangar-sec-retour --on-active=120 --timer-property=AccuracySec=1s --quiet \
  /usr/bin/bash $PREV/revert.sh || die "retour automatique impossible à programmer"

say "pare-feu"
nft -c -f hangar-node.nft >/dev/null 2>nft.err || die "règles de pare-feu refusées : $(tail -c 300 nft.err | tr '\n' ' ')"
install -m 0644 hangar-node.nft $NFT
nft -f $NFT || die "pare-feu non appliqué"

say "SSH"
cp sshd.conf sshd.new
if [ "$SSH_PORT" != 22 ]; then
  # le réseau privé garde le port 22 (console) ; le pare-feu n'ouvre que le port choisi sur l'adresse publique
  if [ $SOCKMODE = 1 ]; then
    install -d /etc/systemd/system/ssh.socket.d
    printf '# Hangar : port SSH public %s, et 22 pour la console par le réseau privé\n[Socket]\nListenStream=\nListenStream=22\nListenStream=%s\n' \
      "$SSH_PORT" "$SSH_PORT" > $SOCK
  else
    sed -i "/^Match /i Port 22\nPort $SSH_PORT" sshd.new
    rm -f $SOCK
  fi
else
  rm -f $SOCK
fi
install -m 0644 sshd.new $SSHD
install -d -m 0755 /run/sshd
sshd -t 2>sshd.err || die "configuration SSH refusée : $(tail -c 300 sshd.err | tr '\n' ' ')"
if [ $SOCKMODE = 1 ] && ! cmp -s $SOCK $PREV/6 2>/dev/null && { [ -e $SOCK ] || [ -e $PREV/6 ]; }; then
  # socket sans Accept : il refuse de redémarrer tant que sshd tient ses ports. Les sessions ouvertes restent
  # (KillMode=process), seul le processus d'écoute est remplacé.
  systemctl daemon-reload
  systemctl stop ssh.service 2>/dev/null
  systemctl restart ssh.socket || die "SSH (socket) ne redémarre pas"
  systemctl start ssh.service 2>/dev/null || true
else
  systemctl reload ssh 2>/dev/null || systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
fi
sleep 1
for p in 22 $SSH_PORT; do
  [ -n "$(ss -Hltn "sport = :$p")" ] || die "SSH n'écoute pas sur le port $p"
done

say "anti-force brute"
if [ "$F2B" = 1 ]; then
  install -m 0644 jail.local $JAIL
  fail2ban-client -t >/dev/null 2>f2b.err || die "configuration fail2ban refusée : $(tail -c 300 f2b.err | tr '\n' ' ')"
  systemctl enable fail2ban >/dev/null 2>&1
  systemctl restart fail2ban || die "fail2ban ne démarre pas"
elif command -v fail2ban-client >/dev/null; then
  install -m 0644 jail.local $JAIL
  systemctl disable --now fail2ban >/dev/null 2>&1
fi

say "mises à jour automatiques"
install -m 0644 apt.conf /etc/apt/apt.conf.d/53hangar-securite

say "réglages réseau du noyau"
install -m 0644 sysctl.conf /etc/sysctl.d/90-hangar.conf
sysctl -e -q -p /etc/sysctl.d/90-hangar.conf 2>/dev/null || warn "certains réglages du noyau sont refusés (conteneur LXC ?)"

say "clés d'administration"
install -d -m 0700 -o "$ADMIN_USER" -g "$(id -gn "$ADMIN_USER")" "$HOME_DIR/.ssh"
touch "$AK"
python3 - "$AK" admin_keys <<'EOF' || die "clés d'administration non posées"
import sys
path, src = sys.argv[1], sys.argv[2]
BEGIN, END = "# hangar : clés d'administration (début, gérées par la console)", "# hangar : clés d'administration (fin)"
lines = open(path).read().splitlines()
if BEGIN in lines and END in lines:
    a, b = lines.index(BEGIN), lines.index(END)
    lines = lines[:a] + lines[b + 1:]
keys = [k for k in open(src).read().splitlines() if k.strip()]
if keys:
    lines += [BEGIN] + keys + [END]
open(path, "w").write("\n".join(lines) + ("\n" if lines else ""))
EOF
chown "$ADMIN_USER:" "$AK" && chmod 600 "$AK"

[ -n "$WARN" ] && echo "HANGAR_WARN=$WARN"
echo "HANGAR_DONE=1"
