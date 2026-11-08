# Installer Hangar sur un nouveau serveur et tout restaurer

Ce guide sert dans trois cas :
- le serveur actuel est perdu ;
- tu passes sur une autre machine (un autre conteneur, ou un serveur dédié chez un hébergeur) ;
- tu veux une copie de test.

## 1. Préparer la machine

**Conteneur LXC Proxmox** (comme aujourd'hui) :
- Debian 13, 1 à 2 vCPU, 2 Go de RAM, 20 Go de disque ou plus ;
- une IP fixe sur le réseau local ;
- non privilégié, c'est très bien ainsi ;
- **Options › Fonctionnalités** : coche `nesting` et `keyctl`. En ligne de commande, sur l'hôte :

```bash
pct set <id> --features nesting=1,keyctl=1
```

**Serveur dédié ou VM** : Debian 13 minimal, accès root en SSH.

## 2. Récupérer le code

Le dépôt est privé. Deux façons de le copier sur la nouvelle machine :

- **Sans Git** : sur GitHub, ouvre « Code », puis « Download ZIP ». Ensuite :
  ```bash
  scp Hangar-main.zip root@<ip>:
  ```
  puis, sur la machine :
  ```bash
  apt install -y unzip && unzip Hangar-main.zip && cd Hangar-main
  ```
- **Avec Git** : crée une clé de déploiement en lecture sur la machine (comme pour ce serveur), puis clone le dépôt :
  ```bash
  git clone git@github.com:jpiperault/Hangar.git && cd Hangar
  ```

## 3. Installer (et restaurer en même temps si tu as une archive)

```bash
./install.sh --domain piperault.fr --mode tunnel --tunnel-token <jeton> --restore hangar-AAAAMMJJ-HHMMSS.tar.gz
```

- Sans options, le script pose les questions : IP, réseau local, domaine, mode.
- `--tunnel-token` : le jeton du tunnel, dans Zero Trust › Networks › Tunnels › ton tunnel. Tu peux réutiliser le même tunnel : l'ancien serveur ne doit simplement plus tourner.
- `--mode direct` : pour un serveur dédié avec les ports 80 et 443 ouverts. Les certificats viennent alors de Let's Encrypt.
- `--restore` : l'archive téléchargée depuis la page Sauvegardes. Elle recrée toutes les applis, leurs bases, leurs fichiers et le domaine.
- Le script peut être relancé sans risque : il ne remplace jamais un secret ni un réglage existant.

À la fin, le script affiche l'adresse de la console. L'identifiant et le mot de passe générés sont dans `/root/hangar-mot-de-passe.txt` (change-les avec `hangar passwd`).

## 4. Reprendre depuis un fichier téléchargé

Une archive `.tar.gz` téléchargée depuis **Sauvegardes › Archives à télécharger** suffit pour tout reprendre. Elle contient, pour chaque appli :
- sa fiche : image, version, variables, réglages ;
- l'export de sa base ;
- son dossier `data/`.

Elle contient aussi les réglages de la plateforme : domaine, alias et mode d'exposition.

### Par le navigateur

1. Installe Hangar avec `./install.sh`, sans `--restore`.
2. Ouvre la console, puis **Sauvegardes › Archives à télécharger**.
3. Avec **Choisir un fichier**, prends l'archive sur ton PC, puis clique sur **Envoyer une archive pour la restaurer**. L'archive peut peser jusqu'à 20 Go.
4. La page de l'archive s'ouvre :
   - clique sur **Tout cocher** ;
   - garde **Reprendre les réglages** coché pour retrouver le même domaine et le même mode ;
   - tape `restaurer` et lance la restauration.
5. Suis l'avancement dans **Applications**. Une appli absente est recréée à partir de sa fiche, avec sa base et ses fichiers, puis déployée.

Une appli qui existe déjà n'est pas écrasée sans filet : ses fichiers et sa base actuels sont d'abord copiés dans `/srv/backups/avant-restauration`.

### En ligne de commande

Copie d'abord l'archive sur la machine. Depuis ton PC :

```bash
scp hangar-AAAAMMJJ-HHMMSS.tar.gz root@<ip-du-serveur>:
```

Pendant l'installation, depuis le dossier du code :

```bash
./install.sh --restore ~/hangar-AAAAMMJJ-HHMMSS.tar.gz
```

Ou sur un serveur déjà installé :

```bash
hangar restore ~/hangar-AAAAMMJJ-HHMMSS.tar.gz
```

Options de `hangar restore` :
- `--apps appli1,appli2` : ne restaure que ces applis ;
- `--no-settings` : garde le domaine et le mode du serveur actuel.

La commande affiche l'état final de chaque appli. Elle se termine en erreur si une appli n'est pas en ligne.

### À savoir

- **L'archive n'est pas chiffrée** et contient les secrets : variables d'environnement et mots de passe des bases. Garde-la en lieu sûr, et supprime les copies temporaires une fois la reprise faite. Sur le serveur, les archives sont dans `/srv/backups/archives`, lisibles par root seulement.
- **Images privées** : les jetons des registres ne sont pas dans l'archive. Si une appli échoue au téléchargement de son image, colle le jeton `read:packages` dans sa fiche puis enregistre : elle se redéploie.

## 5. Restaurer depuis Google Drive ou le NAS (sans archive)

1. Installe sans `--restore`.
2. Dans la console, ouvre **Sauvegardes › Mot de passe des sauvegardes › Nouveau serveur ?** et saisis **le mot de passe de tes sauvegardes**, celui que tu as noté.
3. Connecte **Google Drive** avec le même identifiant Google qu'avant, et/ou le **NAS** avec les mêmes dossiers. Hangar retrouve le dépôt existant.
4. Dans **Restaurer une appli**, choisis la sauvegarde la plus récente, puis clique sur **Tout restaurer (reprise du serveur)…**. Hangar la télécharge et la convertit en archive.
5. Dans **Archives**, ouvre l'archive « importée » et clique sur **Tout cocher**. Coche **Reprendre les réglages**, puis lance la restauration.

## 6. Après la restauration

- **Images privées** : si une appli échoue au téléchargement, colle le jeton `read:packages` dans sa fiche, puis redéploie. Les jetons de registre ne sont pas dans les sauvegardes.
- **Cloudflare** : vérifie que les noms publics sont déclarés dans le tunnel (Domaine et accès › Noms publics).
- **Alertes** : abonne-toi au nouveau sujet ntfy (page Système et alertes), ou remets l'ancien.
- **Sauvegardes** : vérifie que Drive et/ou le NAS sont connectés, puis lance une sauvegarde.

## Plusieurs nœuds

Les sauvegardes et les archives contiennent les applis de **tous** les nœuds. Chaque appli garde la trace de son nœud.

- **Reprise de la console seule**, alors que les nœuds tournent toujours : installe la console, puis ajoute à nouveau chaque nœud dans **Nœuds** avec **le même identifiant**. La réinstallation est sans danger, rien n'est effacé sur la machine. Restaure ensuite l'archive : chaque appli retourne sur son nœud.
- **Nœud perdu** : ses applis sont recréées sur la console s'il n'existe plus. Ajoute un nouveau nœud, puis utilise **Déplacer** depuis la fiche de chaque appli.
- **Avant une restauration**, ajoute les nœuds : une appli n'est recréée sur son nœud d'origine que s'il est déjà en ligne.

## Ce qui n'est pas sauvegardé

Ces éléments sont à refaire à la main :
- les jetons des registres d'images ;
- le jeton du tunnel ;
- les accès Drive et NAS ;
- la clé SSH de la console pour les nœuds (une nouvelle est créée : recolle sa ligne d'autorisation sur chaque nœud) ;
- le compte administrateur de la console.
