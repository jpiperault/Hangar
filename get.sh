#!/usr/bin/env bash
# Installation de Hangar en une commande, sur un Debian 13 neuf (VM, conteneur LXC, VPS) :
#   curl -fsSL https://raw.githubusercontent.com/jpiperault/Hangar/main/get.sh | sudo bash
# Les options sont passées à install.sh : … | sudo bash -s -- --domain exemple.fr
# Récupère (ou met à jour) le dépôt dans /usr/local/src/hangar, puis lance install.sh.
set -euo pipefail
REPO="${HANGAR_REPO:-https://github.com/jpiperault/Hangar.git}"
BRANCH="${HANGAR_BRANCH:-main}"
SRC=/usr/local/src/hangar

[ "$(id -u)" = 0 ] || { echo "Lance en root : curl … | sudo bash" >&2; exit 1; }
command -v git >/dev/null || { apt-get -q update >/dev/null && apt-get -q -y install git ca-certificates >/dev/null; }
if [ -d "$SRC/.git" ]; then
  git -C "$SRC" fetch -q --depth 1 origin "$BRANCH" && git -C "$SRC" checkout -q -B "$BRANCH" FETCH_HEAD
else
  git clone -q --depth 1 --branch "$BRANCH" "$REPO" "$SRC"
fi
exec bash "$SRC/install.sh" "$@"
