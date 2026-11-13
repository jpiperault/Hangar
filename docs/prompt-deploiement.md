<!--
  Version écrite d'exemple : un backend d'appli mobile (API + client Android).
  Pour tout autre type de projet (appli web, API, bot ou service sans page web, serveur de jeu, site statique),
  et pour les clients iOS ou web, utilise le générateur de la console : « Préparer un projet » (/prompt),
  qui adapte chaque section au type choisi.

  Prompt à donner à Claude dans le projet de ton application.
  1. Remplis les 6 lignes de la section « Mon application ».
  2. Colle tout le fichier dans le prompt, ou enregistre-le dans le dépôt
     (par exemple docs/HANGAR.md) et dis à Claude : « Suis docs/HANGAR.md ».
-->

# Préparer cette application pour le serveur Hangar

Rends ce projet déployable sur mon serveur d'applications « Hangar ». Commence par lire le dépôt pour comprendre la stack existante (langage, framework, base de données, présence d'une version web). Fais ensuite les modifications décrites ci-dessous, vérifie-les, puis donne-moi un récapitulatif. Si une information manque et change la solution, pose-moi la question avant de coder. Pour le reste, choisis l'option la plus simple et dis-moi ce que tu as choisi.

## Mon application

- Nom : `<Cuisine>`
- Package Android : `<fr.piperault.cuisine>`
- Identifiant / sous-domaine souhaité : `<cuisine>`  → https://`<cuisine>`.piperault.fr/
- Image Docker : `ghcr.io/<compte-github>/<cuisine>`
- Version web : `<oui / non>`
- Base de données : `<PostgreSQL / aucune>`

## Comment fonctionne le serveur (à respecter, ne pas modifier)

- Chaque backend tourne dans **un conteneur Docker** créé par la console Hangar à partir d'une **image publiée sur ghcr.io** et d'un **tag de version précis**.
- Le serveur est en **linux/amd64** (x86_64). L'image doit être construite pour cette architecture, même si le poste de développement est un Mac ARM.
- Le trafic arrive ainsi : Internet → Cloudflare (HTTPS) → tunnel cloudflared → Caddy → conteneur, **en HTTP simple**. Le conteneur ne gère jamais le TLS.
- L'appli est exposée en **sous-domaine** : `https://<sous-domaine>.piperault.fr/` arrive tel quel à la racine `/` du conteneur.
- En-têtes transmis au conteneur : `Host`, `X-Forwarded-Proto: https`, `X-Forwarded-For`, `X-Real-IP` (IP réelle du visiteur). En mode chemin seulement, le préfixe est retiré et transmis dans `X-Forwarded-Prefix`.
- Variables d'environnement fournies par la console :
  - `DATABASE_URL=postgresql://<user>:<mdp>@postgres:5432/<base>` si la base est activée. Le format est celui d'une URI libpq. **Pour la JVM, il faut le convertir** en `jdbc:postgresql://postgres:5432/<base>`, avec l'utilisateur et le mot de passe passés séparément.
  - Toutes les autres variables que je saisis dans la console (secrets, options).
  - `PORT` n'est **pas** fourni : le port d'écoute est fixe, choisi dans l'image et déclaré dans la console.
- **Seul `/data` est persistant** : c'est un dossier de l'hôte monté dans le conteneur. Tout le reste est effacé à chaque déploiement. Le processus tourne avec un **utilisateur non-root**, déclaré dans le Dockerfile par un `USER` **numérique** (par exemple `USER 10001:10001`). À chaque déploiement, Hangar attribue `/data` à cet utilisateur. Un `USER` donné par son nom fonctionne aussi, à condition que l'image contienne la commande `id`. Sinon, il faut indiquer l'UID dans la console.
- Limite mémoire fixée par la console (256 Mo par défaut, réglable). Le processus doit la respecter.
- Au déploiement, la console démarre le conteneur, puis interroge `http://<conteneur>:<port><healthcheck>` toutes les 2 s, avec 3 s maximum par requête, pendant 90 s au plus. Une réponse **inférieure à 500** valide le déploiement. Sinon, ou si le conteneur s'arrête, **la version précédente est remise en ligne**.
- À l'arrêt, le conteneur reçoit `SIGTERM`, puis il est tué au bout de 10 s.
- **Sauvegardes** : chaque nuit, Hangar sauvegarde la base (`pg_dump`) et le dossier `/data`, **pendant que l'appli tourne**. Une restauration remet les deux, puis redémarre l'appli dans sa **version actuelle**, qui peut être plus récente que la sauvegarde. Le healthcheck valide la restauration. Rien d'autre n'est sauvegardé.
- Les logs sont lus depuis la **sortie standard**.
- Les anciennes versions de l'appli Android restent installées chez les utilisateurs : **l'API doit rester compatible** avec elles.
- Limites Cloudflare : 100 Mo maximum par requête (envoi de fichiers) et réponse en moins de 100 s.
- Manifeste public : `https://apps.piperault.fr/.well-known/apps.json` retourne `{ "<package android>": "https://<sous-domaine>.piperault.fr/" }`. L'appli Android l'utilise pour trouver son serveur.

## Ce que tu dois produire

### 1. Backend

- Écoute HTTP sur **`0.0.0.0`** et un port fixe (8080 par défaut).
- Route **`GET /health`** : répond `200 ok` en moins d'une seconde, vérifie la connexion à la base, sans authentification. Si la base ne répond pas, renvoie 503.
- **Toute la configuration vient de variables d'environnement** : aucun secret, domaine ou URL de serveur dans le code ni dans l'image. Si une variable obligatoire manque, le démarrage échoue avec un message clair qui la nomme.
- Lecture de `DATABASE_URL` au format libpq, avec la conversion JDBC si besoin.
- **Migrations de base au démarrage** (Flyway, Alembic, Prisma migrate…), idempotentes et **uniquement additives** : on ajoute des tables et des colonnes nullables ou avec une valeur par défaut. On ne supprime ni ne renomme rien qu'une ancienne version de l'appli utilise encore.
- **API versionnée** sous `/api/v1/`.
- Fichiers envoyés par les utilisateurs (photos…) stockés sous `/data/…`, jamais dans la base ni ailleurs dans le conteneur.
- **Restaurable par Hangar** :
  - Tout l'état de l'appli est dans la base ou dans `/data` : aucun autre volume, aucun cache indispensable (Redis…). Une clé générée au premier démarrage (signature des sessions, chiffrement) est écrite dans `/data` ou fournie en variable, sinon une restauration déconnecte tout le monde ou rend des données illisibles.
  - Les migrations amènent une base de **n'importe quelle version précédente** à la version actuelle : une sauvegarde ancienne peut être restaurée sous une version plus récente.
  - `/data` est copié pendant que l'appli écrit : écriture **atomique** des fichiers (d'abord `nom.tmp`, puis renommage ; Hangar ignore les `*.tmp`). Pas de SQLite ni d'autre fichier de base dans `/data` pour des données importantes, car une copie faite pendant une écriture peut être corrompue : elles vont dans PostgreSQL.
  - La base et `/data` ne sont pas copiés au même instant : un fichier référencé mais absent donne une erreur propre (404), jamais un plantage, et un fichier orphelin ne gêne rien.
  - Aucun nom de base ou d'utilisateur en dur (seulement `DATABASE_URL`), pas de `GRANT` vers d'autres rôles, pas d'extension PostgreSQL qui exige un super-utilisateur : la restauration se fait sans les propriétaires ni les droits d'origine, éventuellement dans un Hangar neuf.
  - Chemins relatifs à `/data`, jamais un chemin ou un nom de machine du serveur.
- Les URL absolues générées (liens vers les photos, par exemple) se construisent à partir de `X-Forwarded-Proto` et `Host`. Pas de domaine en dur.
- Logs sur stdout, une ligne par événement, sans données personnelles ni secrets.
- Arrêt propre sur `SIGTERM`.
- Si une version web existe : le **même conteneur** sert les fichiers construits du front à la racine `/`, avec un repli sur `index.html` pour les routes du front, et l'API sous `/api/v1/`. Même origine, donc pas de CORS. Le build du front se fait dans le Dockerfile.

### 2. Image Docker

- `Dockerfile` **multi-étapes** : une étape de build (backend et front web), puis une image d'exécution minimale (JRE seul pour la JVM, slim pour Node ou Python).
- JVM : `-XX:MaxRAMPercentage=75`, sans `-Xmx` fixe.
- Utilisateur non-root avec `USER` numérique dans l'étape finale (`USER 10001:10001`). Les fichiers de l'appli dans l'image doivent être lisibles par cet utilisateur. Il ne doit pas avoir besoin d'écrire ailleurs que dans `/data` et `/tmp`.
- `EXPOSE <port>`, et `HEALTHCHECK` optionnel (la console fait le sien).
- Dans l'image : aucun secret, aucun `.env`, aucune donnée.
- `.dockerignore` : `.git`, builds locaux, `node_modules`, `.gradle`, `.env*`, l'appli Android si elle est dans le même dépôt.
- Une image qui démarre en moins de 60 s, et la plus petite possible.

### 3. Test local qui reproduit le serveur

- `docker-compose.local.yml` avec :
  - le backend construit depuis le Dockerfile ;
  - un `postgres:17` ;
  - `DATABASE_URL` au même format que sur le serveur, avec l'hôte `postgres` ;
  - un volume `./.data:/data` ;
  - `mem_limit` à la valeur que tu recommandes ;
  - le port publié sur `127.0.0.1` uniquement.
- Une commande unique pour lancer le tout, écrite dans `DEPLOY.md`.

### 4. Publication automatique

- `.github/workflows/docker.yml` :
  - déclenché sur un tag Git `v*` (par exemple `v1.2.0`) ;
  - construit l'image pour `linux/amd64` ;
  - la pousse sur `ghcr.io/<compte>/<app>:1.2.0`, c'est-à-dire **le tag sans le v** ;
  - utilise `GITHUB_TOKEN`, avec les permissions `packages: write` et `contents: read`.
- Ne pousse jamais `latest` seul : chaque version publiée doit avoir son tag précis, pour que le retour arrière fonctionne.

### 5. Appli Android

- Plus aucune URL de serveur en dur dans le code. `BuildConfig.DEFAULT_BASE_URL = "https://<sous-domaine>.piperault.fr/"` sert uniquement de valeur de secours.
- Au démarrage :
  1. lire `https://apps.piperault.fr/.well-known/apps.json` avec un timeout court ;
  2. y prendre l'entrée `BuildConfig.APPLICATION_ID` ;
  3. la mémoriser (DataStore).
  
  En cas d'échec, utiliser la dernière valeur mémorisée, sinon `DEFAULT_BASE_URL`. Le démarrage de l'appli ne doit jamais attendre ce fichier.
- Le client HTTP (Retrofit/Ktor client) utilise `baseUrl + "api/v1/"`, construit à partir de cette valeur.
- Si l'appli a des données locales (Room), elle continue de fonctionner hors ligne.

### 6. `DEPLOY.md`

Un document court qui contient :

- **Les valeurs à saisir dans la console Hangar** (Nouvelle application), sous forme de tableau :

  | Champ | Valeur |
  |---|---|
  | Nom | |
  | Package Android | |
  | Adresse | Sous-domaine + valeur |
  | Source | Image Docker + nom de l'image sans tag |
  | Version | |
  | Port interne | |
  | Healthcheck | `/health` |
  | RAM max (Mo) | |
  | Base PostgreSQL | oui/non |
  | Variables d'environnement | liste des clés avec leur rôle, **sans les valeurs secrètes**, et comment générer chaque secret |

- **La procédure de mise à jour** :
  1. `git tag v1.2.0 && git push --tags` ;
  2. attendre la fin de l'Action GitHub ;
  3. dans Hangar, bloc Version, saisir `1.2.0` puis Déployer.
- **Si l'image ghcr est privée**, la commande à lancer une seule fois sur le serveur : `docker login ghcr.io -u <compte>`, avec un token GitHub ayant la permission `read:packages`.
- **Les sauvegardes** : Hangar sauvegarde chaque nuit la base et `/data`, et sait les restaurer. Décris le contenu de `/data` (à quoi sert chaque sous-dossier) et ce qui est recréé tout seul s'il manque.

## Vérifications à faire avant de me rendre la main

1. `docker build --platform linux/amd64 .` réussit. Donne la taille de l'image.
2. `docker compose -f docker-compose.local.yml up` démarre, et `curl -i http://127.0.0.1:<port>/health` répond 200 en moins d'une seconde.
3. Avec la base arrêtée, `/health` répond 503, et le conteneur ne plante pas.
4. Sans une variable obligatoire, le démarrage échoue avec un message clair.
5. Un fichier écrit dans `/data` survit à `docker compose down` puis `up`.
6. Les migrations passent sur une base créée par la version précédente de l'appli (dernier tag), pas seulement sur une base vide.
7. Restauration : exporte la base (`pg_dump -Fc`) et copie `.data/`, efface les deux, puis restaure la base (`pg_restore --clean --if-exists --no-owner --no-acl`) et remets `.data/` : l'appli redémarre, `/health` répond 200 et les données sont là.
8. La consommation mémoire après démarrage (`docker stats`) reste sous la limite proposée.
9. Si une version web existe : `/` affiche le site, une route du front rechargée directement fonctionne, et `/api/v1/…` répond.
10. Les tests existants du projet passent toujours.

Termine par un récapitulatif :
- les fichiers créés ou modifiés ;
- les valeurs à saisir dans Hangar ;
- les secrets à générer ;
- ce que tu n'as pas pu vérifier.
