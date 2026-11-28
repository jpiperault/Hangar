# API et serveur MCP

Hangar se pilote aussi sans la console web : depuis un script, une CI, ou Claude par le serveur MCP.

## Jetons

Créés dans **Réglages › Jetons d'API** (ou **Mon compte** pour un compte « applis choisies »). Un jeton :

- appartient à un compte et n'a jamais plus de droits que lui (rôle, applis choisies) ;
- a une portée : **lecture** (état, événements, logs, trafic) ou **lecture et déploiement** (en plus : déployer,
  démarrer, arrêter, redémarrer) ;
- ne permet jamais de supprimer une appli, de changer ses réglages ni de lire ses secrets ;
- n'est affiché qu'une fois ; Hangar ne garde que son empreinte SHA-256.

Comme la console, l'API ne répond que sur le réseau local. Chaque action passée par l'API est inscrite au journal
des actions (`api:<compte>/<nom du jeton>`) et dans les événements de l'appli.

## Appels

En-tête `Authorization: Bearer hgr_…`, réponses JSON. Certificat auto-signé : `curl -k`, ou mieux
`--pinnedpubkey`, ou le certificat de la console (`/srv/platform/tls/hangar.crt`) avec `--cacert`.

| Méthode | Chemin | Rôle |
|---|---|---|
| GET | `/api/v1` | le jeton et la liste des appels |
| GET | `/api/v1/apps` | applis visibles : état, version, machine, adresse |
| GET | `/api/v1/apps/{slug}` | détail, adresses, construction (technologie reconnue, commit) |
| GET | `/api/v1/apps/{slug}/events?limit=30` | derniers événements |
| GET | `/api/v1/apps/{slug}/logs?period=1h&q=texte&errors=1&limit=300` | logs du conteneur (`period` : vide, 1h, 24h, 168h) |
| GET | `/api/v1/apps/{slug}/traffic?range=24h` | visiteurs, pages, erreurs, origines, pays, suspects |
| POST | `/api/v1/apps/{slug}/deploy` `{"version": "1.4.0"}` | déploiement (vide : la version en ligne ; dépôt Git : reconstruite) |
| POST | `/api/v1/apps/{slug}/start`, `/stop`, `/restart` | démarrer, arrêter, redémarrer |

Un déploiement répond `202` tout de suite ; son résultat arrive dans les événements (healthcheck, puis retour
automatique à l'ancienne version en cas d'échec). `409` si un déploiement est déjà en cours.

```bash
curl -k -H "Authorization: Bearer $HANGAR_TOKEN" https://192.168.1.10:8443/api/v1/apps
curl -k -X POST -H "Authorization: Bearer $HANGAR_TOKEN" -d '{"version":"1.4.0"}' \
     https://192.168.1.10:8443/api/v1/apps/blog/deploy
```

## Serveur MCP (Claude)

`deploy/bin/hangar-mcp` : un fichier Python 3.9+ sans dépendance, à copier sur l'ordinateur où tourne Claude Code
(ou à télécharger depuis la console, à côté des jetons). Outils : `list_apps`, `app_status`, `app_logs`,
`app_traffic`, `deploy_app`, `app_action`.

```bash
claude mcp add hangar -e HANGAR_URL=https://192.168.1.10:8443 -e HANGAR_TOKEN=hgr_… \
  -e HANGAR_FINGERPRINT=<empreinte affichée dans la console> -- python3 /chemin/vers/hangar-mcp
```

`HANGAR_FINGERPRINT` épingle le certificat auto-signé de la console (connexion refusée si une autre machine se fait
passer pour elle). À défaut, `HANGAR_INSECURE=1` accepte n'importe quel certificat (déconseillé). Un jeton
« lecture » suffit pour diagnostiquer ; le serveur demande à Claude de confirmer avec toi avant de déployer ou
d'arrêter.
