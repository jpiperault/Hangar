#!/usr/bin/env bash
# Remet le réglage de sécurité d'avant : lancé par le minuteur hangar-sec-retour si la console n'a pas confirmé
# le nouveau à temps, ou tout de suite si l'application échoue. Copié dans /var/lib/hangar-sec/prev.
PREV=/var/lib/hangar-sec/prev
[ -f $PREV/list ] || exit 0
SOCK_BEFORE=$(cat /etc/systemd/system/ssh.socket.d/hangar.conf 2>/dev/null)
while read -r i t; do
  if [ -e "$PREV/$i" ]; then cp -a "$PREV/$i" "$t"; else rm -f "$t"; fi
done < $PREV/list
nft -f /etc/nftables.d/hangar-node.nft 2>/dev/null
install -d -m 0755 /run/sshd
if systemctl is-enabled ssh.socket 2>/dev/null | grep -q '^enabled' && \
   [ "$SOCK_BEFORE" != "$(cat /etc/systemd/system/ssh.socket.d/hangar.conf 2>/dev/null)" ]; then
  systemctl daemon-reload; systemctl stop ssh.service 2>/dev/null; systemctl restart ssh.socket
  systemctl start ssh.service 2>/dev/null
else
  systemctl reload ssh 2>/dev/null || systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
fi
if command -v fail2ban-client >/dev/null; then
  if [ -f $PREV/f2b-actif ]; then systemctl enable fail2ban >/dev/null 2>&1; systemctl restart fail2ban
  else systemctl disable --now fail2ban >/dev/null 2>&1; fi
fi
rm -rf $PREV
systemctl stop hangar-sec-retour.timer >/dev/null 2>&1
logger -t hangar "sécurité : nouveau réglage non confirmé par la console, ancien réglage remis"
echo "HANGAR_REVERTED=1"
