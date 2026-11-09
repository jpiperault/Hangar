# Connecter Google Drive aux sauvegardes

Hangar envoie chaque nuit une copie chiffrée (restic) de ses sauvegardes dans ton Google Drive. Il n'utilise que
l'autorisation `drive.file` : il voit uniquement les fichiers qu'il crée lui-même, dans le dossier
`Hangar-sauvegardes`, et rien d'autre du compte.

Il faut ton propre projet Google : l'identifiant fourni par défaut avec rclone est partagé par tous ses
utilisateurs et Google le bloque souvent (« quota dépassé »). Compte 15 minutes, une seule fois.
La console reprend cette procédure, avec tes adresses déjà remplies, dans **Sauvegardes › Google Drive ›
Étape préalable**.

## Avant de commencer

- Un domaine avec un **préfixe pour les routes par chemin** (page Domaines), par exemple `apps.exemple.fr`.
  Google exige une page d'accueil et des règles de confidentialité publiques pour publier le projet : Hangar les
  sert lui-même sur ce préfixe.
  - Page d'accueil : `https://apps.exemple.fr/`
  - Règles de confidentialité : `https://apps.exemple.fr/confidentialite`

  Ouvre-les depuis un navigateur pour vérifier qu'elles répondent. Un e-mail de contact facultatif peut y être
  affiché (même encadré de la console).
- Un compte Google : celui dont le Drive recevra les sauvegardes.

## Étapes dans la console Google Cloud

1. **Projet** : sur [console.cloud.google.com](https://console.cloud.google.com/projectcreate), crée un projet
   « Hangar ».
2. **API** : dans *API et services › Bibliothèque*, active **Google Drive API**.
3. **Google Auth Platform** : ouvre [Google Auth Platform](https://console.cloud.google.com/auth/overview),
   clique sur « Commencer » : nom de l'application « Hangar », ton e-mail d'assistance, audience **Externe**,
   ton e-mail comme contact, puis « Créer ».
4. **Branding**, partie « Domaine de l'application », puis « Enregistrer » en bas de page :
   - page d'accueil et règles de confidentialité : les deux adresses ci-dessus ;
   - conditions d'utilisation : laisser vide (facultatif) ;
   - **domaines autorisés** : « + Ajouter un domaine », puis le domaine principal seul (`exemple.fr`, sans
     `https://` ni préfixe). Sans lui, Google affiche « Domaine manquant » et refuse d'enregistrer ;
   - **pas de logo** : un logo oblige à faire valider l'application par Google (plusieurs jours).
5. **Accès aux données** : « Ajouter ou supprimer des champs d'application », coche
   `https://www.googleapis.com/auth/drive.file`, « Mettre à jour », puis « Enregistrer ».
6. **Audience** : « Publier l'application », puis « Confirmer ». L'état doit passer à **En production**.
   - Indispensable : en mode « Test », Google coupe l'accès au bout de **7 jours** et les sauvegardes
     s'arrêtent sans prévenir.
   - Si Drive a déjà été connecté pendant que le projet était en « Test », son accès expire quand même 7 jours
     après la connexion : une fois le projet publié, clique sur « Déconnecter » dans Hangar et reconnecte Drive.
   - `drive.file` ne demande pas de validation par Google. Si Google demande quand même de prouver que le domaine
     t'appartient : dans [Search Console](https://search.google.com/search-console), ajoute une propriété de type
     « Domaine », puis l'enregistrement TXT `google-site-verification=…` qu'il indique dans le DNS du domaine
     (chez Cloudflare : type TXT, nom `@`), et clique sur « Valider ».
7. **Clients** : « Créer un client », type **Application de bureau**, nom « Hangar ». Note l'**ID client** et le
   **code secret** (le secret n'est affiché en entier qu'à la création : télécharge le JSON au besoin).

## Dans la console Hangar

1. **Sauvegardes › Google Drive** : colle l'ID client et le code secret, puis « Connecter Google Drive ».
2. « Ouvrir Google et autoriser l'accès », puis choisis le compte. Google affiche
   « Google n'a pas validé cette application » : c'est normal pour un projet personnel. Clique sur
   « Paramètres avancés », puis « Accéder à Hangar (non sécurisé) », coche l'accès aux fichiers et « Continuer ».
3. Le navigateur arrive sur `http://127.0.0.1:53682/…` et affiche « site inaccessible » : c'est normal. Copie toute
   l'adresse de l'onglet, colle-la dans la console et clique sur « Terminer la connexion ».
4. Lance « Sauvegarder maintenant » et vérifie que la sauvegarde Drive est marquée réussie.

## En cas de problème

| Symptôme | Cause et solution |
| --- | --- |
| Les sauvegardes Drive échouent après une semaine (`invalid_grant`, « token expired ») | Projet resté en mode « Test ». Publie-le (étape 6), puis déconnecte et reconnecte Drive dans Hangar. |
| `rateLimitExceeded`, « quota dépassé » | Identifiant partagé de rclone. Reconnecte Drive avec ton propre ID client. |
| « Domaine manquant » dans Branding | Ajoute le domaine principal dans « Domaines autorisés » (étape 4). |
| `redirect_uri_mismatch` | Le client n'est pas de type « Application de bureau ». Crée-en un nouveau (étape 7). |
| La page de confidentialité ne s'ouvre pas | Vérifie le domaine et son préfixe dans la page Domaines, et l'état du tunnel Cloudflare. |

Pour retirer l'accès : **Sauvegardes › Déconnecter** dans Hangar, ou
[myaccount.google.com/permissions](https://myaccount.google.com/permissions). Les sauvegardes déjà envoyées
restent dans le Drive.
