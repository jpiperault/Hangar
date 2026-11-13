<!--
  Prompt à donner à Claude dans le projet de ton application, pour amener dans Hangar les données
  d'une instance hébergée ailleurs.
  Plus simple : la console le remplit pour toi (Prompt de déploiement › Prompt de migration, /prompt/migration).
  1. Sinon, remplis les <…> des sections « L'instance de départ » et « La cible ». Laisse un <…> si tu ne sais pas :
     Claude posera la question.
  2. Colle tout le fichier dans le prompt, ou enregistre-le dans le dépôt
     (par exemple docs/MIGRATION-HANGAR.md) et dis à Claude : « Suis docs/MIGRATION-HANGAR.md ».
  Le kit produit un fichier db.dump + data/, à envoyer dans Sauvegardes → Importer des données dans une appli.
-->

# Kit de migration de « <Nom de l'appli> » vers Hangar

Crée dans ce dépôt un kit qui exporte les données d'une instance existante de l'appli, hébergée hors de Hangar, sous la forme d'un **fichier importable par Hangar**. Commence par lire le dépôt pour comprendre où l'appli range ses données : base, fichiers, stockage externe éventuel. Si une information manque et change la solution, pose-moi la question avant de coder. Pour le reste, choisis l'option la plus simple et dis-moi ce que tu as choisi. Ne modifie pas le comportement de l'appli.

## L'instance de départ

- Serveur : `<VPS, NAS, PC…>`, accès `<SSH root / utilisateur…>`, Docker `<disponible / non>`
- Base : `<PostgreSQL x.y / MySQL / SQLite / aucune>`, accès `<URL de connexion, à passer en variable, jamais dans le code>`
- Fichiers : `<dossier, volume Docker, S3…>`
- Version de l'appli installée : `<x.y.z ou commit>`
- Volume approximatif : `<taille de la base, taille des fichiers>`

## La cible : l'appli dans Hangar

- Identifiant Hangar (slug) : `<slug>`. Image : `ghcr.io/<compte>/<slug>`. Version déployée : `<x.y.z>`. Port : `<port>`. Healthcheck : `/health`.
- L'appli tourne dans un conteneur. **Seuls la base PostgreSQL 17 dédiée et le dossier `/data` sont conservés.**
- Hangar restaure la base avec :
  `pg_restore --clean --if-exists --no-owner --no-acl --role=<rôle de l'appli> -d <base>`.
  Il remplace ensuite `/data`, puis redémarre l'appli dans sa version actuelle. Les migrations de l'appli s'exécutent alors au démarrage.
- Hangar attribue `/data` à l'utilisateur du conteneur. Les propriétaires d'origine des fichiers n'ont donc pas d'importance.

## Format du fichier d'import (imposé par Hangar)

Un fichier `.tar.gz`, de 20 Go au plus, qui contient **seulement** :

- `db.dump` : un export **`pg_dump -Fc --no-owner --no-acl`**, produit par un client **`pg_dump` version 17** (image `postgres:17`). Un `pg_dump` plus récent produit un fichier que Hangar ne saurait pas lire : Hangar le vérifie à l'envoi avec `pg_restore -l` et le refuse sinon. À omettre si l'appli n'a pas de base.
- `data/…` : l'arborescence exacte que l'appli attend dans `/data`.
  - Uniquement des fichiers et des dossiers ordinaires : ni liens symboliques, ni chemins absolus, ni `..`. Hangar refuse le reste.
  - Pas de fichiers temporaires ni de cache recréable.

Aucun autre fichier à la racine : Hangar refuse l'archive. Elle ne contient ni réglages ni secrets : ceux-ci restent dans la fiche de l'appli dans la console.

## Ce que tu dois produire

### 1. Script d'export `migration/export.sh`

Il se lance sur l'ancien serveur et n'y modifie **rien**. Il demande seulement l'arrêt ou la mise en maintenance de l'appli, pour obtenir une copie cohérente.

- Paramètres par variables d'environnement, avec un message clair si l'une manque : accès à la base, dossier des fichiers, slug, version cible.
- **La base :**
  - Si la source est PostgreSQL et que son schéma est celui d'une version de l'appli : un `pg_dump -Fc --no-owner --no-acl` fait avec `docker run --rm postgres:17 pg_dump …`.
  - Sinon (MySQL, SQLite, schéma d'une ancienne version incompatible) :
    1. lance un `postgres:17` temporaire ;
    2. crée-y le schéma **avec les migrations de l'appli**, dans la version la plus proche de celle de la source, pour que l'historique des migrations (Flyway, Alembic, Prisma…) soit correct et que Hangar puisse continuer à migrer ;
    3. copie les données, en convertissant les types (dates, booléens, JSON, encodage UTF-8) ;
    4. recale les séquences et les auto-incréments sur le maximum des identifiants ;
    5. exporte ensuite avec `pg_dump -Fc --no-owner --no-acl`.
  - Aucun objet ne doit dépendre d'un rôle ou d'un nom de base précis : pas de `GRANT`, pas d'`ALTER … OWNER`. Pas d'extension qui exige un super-utilisateur. Si l'appli en a besoin, dis-le moi.
- **Les fichiers :**
  - Copie-les vers la disposition attendue sous `/data`, y compris ceux d'un stockage externe (S3…) s'il y en a.
  - Si la base contient des chemins absolus ou des URL de l'ancien serveur, réécris-les dans la copie (jamais dans la source) en chemins relatifs à `/data`, ou en URL relatives.
- **L'archive :** `migration-<slug>-<date>.tar.gz`, avec `db.dump` et `data/` à la racine.
- **Le rapport `migration/rapport-<date>.txt`, sans aucun secret ni donnée personnelle :**
  - le nombre de lignes par table, dans la source et dans l'export ;
  - le nombre de fichiers et la taille totale de `/data` ;
  - la somme SHA-256 de l'archive ;
  - les anomalies : fichiers référencés absents, lignes non converties.
- Le script s'arrête à la première erreur (`set -euo pipefail`) et efface ses conteneurs et fichiers temporaires, même en cas d'échec.

### 2. Script de vérification `migration/verify.sh`

Il rejoue en local ce que Hangar fera :

1. extrait l'archive dans un dossier temporaire ;
2. vérifie qu'elle ne contient que `db.dump` et `data/…`, sans lien ni chemin absolu ;
3. démarre un `postgres:17` vide ;
4. crée un rôle et une base, puis lance `pg_restore --clean --if-exists --no-owner --no-acl --role=<rôle>` ;
5. démarre l'image `ghcr.io/<compte>/<slug>:<version>`, avec ce dossier `data/` monté sur `/data` et `DATABASE_URL` pointant sur cette base ;
6. attend `/health` = 200 ;
7. compare les nombres de lignes à ceux du rapport.

Il doit échouer clairement au moindre écart.

### 3. `MIGRATION.md`

Un document court qui contient :

- **Avant :**
  - créer l'appli dans Hangar avec le **même identifiant** `<slug>`, la base PostgreSQL activée et la même version, puis la déployer ;
  - la liste des **variables d'environnement à recopier** de l'ancienne instance vers la console Hangar, en particulier les secrets dont dépendent les données : clé de signature des sessions, clé de chiffrement… Donne les noms, jamais les valeurs. Une clé perdue déconnecte les utilisateurs, ou rend illisibles des données chiffrées.
- **Export :** arrêter l'ancienne instance ou la passer en maintenance, lancer `export.sh`, puis `verify.sh`.
- **Import :** dans Hangar, Sauvegardes → Importer des données dans une appli → Envoyer les données. Choisir ensuite l'appli `<slug>`, cocher la base et le dossier data/, taper l'identifiant pour confirmer, puis Importer. Hangar garde une copie de l'état d'avant (/srv/backups/avant-restauration) et vérifie le healthcheck.
- **Contrôles après l'import :** une liste courte de vérifications fonctionnelles (connexion, quelques écrans, un fichier envoyé).
- **Bascule :** faire pointer le domaine vers Hangar (adresse de l'appli dans la console). Garder l'ancienne instance arrêtée mais intacte quelques jours : c'est le **retour arrière**.
- **Si l'archive dépasse 20 Go :** la marche à suivre (par exemple, envoyer les fichiers volumineux à part dans `/data`).

## Vérifications à faire avant de me rendre la main

1. Sur une instance de test, avec des données factices : `export.sh` puis `verify.sh` passent, et les nombres de lignes sont identiques.
2. `tar -tzf` ne montre que `db.dump` et `data/…`, sans lien symbolique ni chemin absolu.
3. L'export est fait par un `pg_dump` en version 17 : vérifie l'en-tête du fichier avec `pg_restore -l`.
4. Une deuxième exécution de `export.sh` donne le même résultat, et la source n'a pas changé.
5. Aucun secret dans l'archive, le rapport ou les journaux.
6. Les tests existants du projet passent toujours.

Termine par un récapitulatif : les fichiers créés, les choix faits (en particulier la conversion de la base si la source n'est pas PostgreSQL), les variables à recopier dans Hangar, et ce que tu n'as pas pu vérifier.
