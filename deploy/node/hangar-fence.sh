#!/bin/bash
# Arrêt de sécurité d'un nœud Hangar (haute dispo), lancé toutes les 30 s par hangar-fence.timer.
# Un nœud qui ne voit plus aucun pair du réseau privé (ni la console, ni les autres nœuds) depuis AFTER secondes
# arrête ses applis en haute dispo et son connecteur de tunnel : si la console a basculé ces applis ailleurs,
# elles ne servent jamais en double. La console le relance (ou le reconstruit en secours) à son retour.
. /etc/hangar/fence.conf 2>/dev/null || exit 0
[ "${ENABLED:-0}" = 1 ] || exit 0
AFTER=${AFTER:-180}
[ "$(cut -d. -f1 /proc/uptime)" -gt "$AFTER" ] || exit 0      # juste après un démarrage : le lien se refait
now=$(date +%s)
while read -r _ t; do
  [ "${t:-0}" -gt 0 ] && [ $((now - t)) -lt "$AFTER" ] && exit 0    # au moins un pair vu récemment
done < <(wg show wg-hangar latest-handshakes 2>/dev/null)
ids=$( (docker ps -q --filter label=fr.hangar.ha-role=primary; docker ps -q --filter label=fr.hangar.ha-role=instance) | sort -u)
[ -n "$ids" ] || exit 0
docker stop $ids >/dev/null 2>&1
install -d -m 0755 /var/lib/hangar && date +%s > /var/lib/hangar/fenced
systemctl stop cloudflared 2>/dev/null
logger -t hangar "arrêt de sécurité : plus aucun lien avec la console ni les autres nœuds depuis ${AFTER} s, applis en haute dispo et connecteur de tunnel arrêtés"
