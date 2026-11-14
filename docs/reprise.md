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

**Serveur dédié ou VM** : Debian 13 minimal, avec un accès SSH. Pas besoin d'un accès root direct : ton compte habituel suffit s'il a `sudo` (c'est le cas par défaut chez la plupart des hébergeurs). Dans la suite, préfixe alors les commandes par `sudo`, par exemple `sudo ./install.sh`.

Le serveur de la console doit rester sur le réseau local, car la console n'est accessible que depuis le LAN. Un VPS ou un dédié loué se branche plutôt comme **nœud** supplémentaire (page Nœuds) : voir plus bas.

## 2. Récupérer le code

Le dépôt est privé. Deux façons de le copier sur la nouvelle machine :

- **Sans Git** : sur GitHub, ouvre « Code », puis « Download ZIP ». Ensuite :
  ```bash
  scp Hangar-main.zip <compte>@<ip>:
  ```
  puis, sur la machine :
  ```bash
  apt install -y unzip && unzip Hangar-main.zip && cd Hangar-main
  ```
- **Avec Git** : crée une clé de déploiement en lecture sur la machine (comme pour ce serveur), puis clone le dépôt :
  ```bash
  git clone <adresse de ton dépôt Hangar> hangar && cd hangar
  ```

## 3. Installer (et restaurer en même temps si tu as une archive)

```bash
./install.sh --domain exemple.fr --mode tunnel --tunnel-token <jeton> --restore hangar-AAAAMMJJ-HHMMSS.tar.gz
```

- Sans options, le script pose les questions : IP, réseau local, domaine, mode.
- `--tunnel-token` : le jeton du tunnel, dans Zero Trust › Networks › Tunnels › ton tunnel. Tu peux réutiliser le même tunnel : l'ancien serveur ne doit simplement plus tourner.
- `--mode direct` : pour un serveur dédié avec les ports 80 et 443 ouverts. Les certificats viennent alors de Let's Encrypt.
- `--restore` : l'archive téléchargée depuis la page Sauvegardes. Elle recrée toutes les applis, leurs bases, leurs fichiers et le domaine.
- Le script peut être relancé sans risque : il ne remplace jamais un secret ni un réglage existant.

À la fin, le script affiche l'adresse de la console. L'identifiant et le mot de passe générés sont dans `/root/hangar-mot-de-passe.txt` (change-les dans Accès et comptes, ou avec `hangar passwd`).

## 4. Reprendre depuis un fichier téléchargé

Une archive `.tar.gz` téléchargée depuis **Sauvegardes › Archives à télécharger** suffit pour tout reprendre. Elle contient, pour chaque appli :
- sa fiche : image, version, variables, réglages ;
- l'export de sa base ;
- son dossier `data/`.

Elle contient aussi les domaines (mode, préfixe, machine d'entrée) et les adresses de chaque appli. Les archives d'avant le multi-domaine (domaine de base et alias) restent lisibles : chaque alias devient un domaine.

### Par le navigateur

1. Installe Hangar avec `./install.sh`, sans `--restore`.
2. Ouvre la console, puis **Sauvegardes › Archives à télécharger**.
3. Avec **Choisir un fichier**, prends l'archive sur ton PC (`.tar.gz.gpg`), tape le **mot de passe des sauvegardes** de l'ancien serveur, puis clique sur **Envoyer une archive pour la restaurer**. L'archive peut peser jusqu'à 20 Go.
4. La page de l'archive s'ouvre :
   - clique sur **Tout cocher** ;
   - garde **Reprendre les réglages** coché pour retrouver le même domaine et le même mode ;
   - tape `restaurer` et lance la restauration.
5. Suis l'avancement dans **Applications**. Une appli absente est recréée à partir de sa fiche, avec sa base et ses fichiers, puis déployée.

Une appli qui existe déjà n'est pas écrasée sans filet : ses fichiers et sa base actuels sont d'abord copiés dans `/srv/backups/avant-restauration`.

### En ligne de commande

Copie d'abord l'archive sur la machine. Depuis ton PC :

```bash
scp hangar-AAAAMMJJ-HHMMSS.tar.gz <compte>@<ip-du-serveur>:
```

Pendant l'installation, depuis le dossier du code :

```bash
sudo HANGAR_ARCHIVE_PASSWORD='<mot de passe des sauvegardes>' ./install.sh --restore ~/hangar-AAAAMMJJ-HHMMSS.tar.gz.gpg
```

Sans `HANGAR_ARCHIVE_PASSWORD`, le mot de passe est demandé au moment de la restauration.

Ou sur un serveur déjà installé :

```bash
sudo hangar restore ~/hangar-AAAAMMJJ-HHMMSS.tar.gz.gpg
```

Options de `hangar restore` :
- `--apps appli1,appli2` : ne restaure que ces applis ;
- `--no-settings` : garde le domaine et le mode du serveur actuel.

La commande affiche l'état final de chaque appli. Elle se termine en erreur si une appli n'est pas en ligne.

### À savoir

- **L'archive téléchargée est chiffrée** (`.tar.gz.gpg`, gpg AES-256) avec le **mot de passe des sauvegardes** du serveur qui l'a créée (page Sauvegardes › Mot de passe des sauvegardes). Sans lui, elle est illisible : garde-le dans ton gestionnaire de mots de passe. Hangar la déchiffre tout seul à l'envoi (champ « Mot de passe » si elle vient d'un autre serveur), avec `hangar restore` et `install.sh --restore`. Pour l'ouvrir sur un PC : `gpg -d hangar-….tar.gz.gpg > hangar-….tar.gz` (Gpg4win sous Windows). Les archives non chiffrées d'avant restent acceptées.
- Sur le serveur, les archives sont gardées en clair dans `/srv/backups/archives`, lisibles par root seulement (le serveur détient de toute façon ces secrets). Supprime les copies déchiffrées sur ton PC une fois la reprise faite.
- **Images privées** : les jetons des registres ne sont pas dans l'archive. Si une appli échoue au téléchargement de son image, colle le jeton `read:packages` dans sa fiche puis enregistre : elle se redéploie.

## 5. Restaurer depuis Google Drive ou le NAS (sans archive)

1. Installe sans `--restore`.
2. Dans la console, ouvre **Sauvegardes › Mot de passe des sauvegardes › Nouveau serveur ?** et saisis **le mot de passe de tes sauvegardes**, celui que tu as noté.
3. Connecte **Google Drive** avec le même compte Google qu'avant, et/ou le **NAS** avec les mêmes dossiers. Hangar retrouve le dépôt existant. Le projet Google existant (ID client et code secret) resservira tel quel ; il doit rester « En production » et ses deux pages publiques réapparaissent dès que le domaine est repris (voir [google-drive.md](google-drive.md)).
4. Dans **Restaurer une appli**, choisis la sauvegarde la plus récente, puis clique sur **Tout restaurer (reprise du serveur)…**. Hangar la télécharge et la convertit en archive.
5. Dans **Archives**, ouvre l'archive « importée » et clique sur **Tout cocher**. Coche **Reprendre les réglages**, puis lance la restauration.

## 6. Après la restauration

- **Images privées** : si une appli échoue au téléchargement, colle le jeton `read:packages` dans sa fiche, puis redéploie. Les jetons de registre ne sont pas dans les sauvegardes.
- **Cloudflare** : avec un jeton d'API (Domaines › Cloudflare), Hangar redéclare lui-même les noms ; sinon, vérifie qu'ils sont déclarés dans le tunnel (Domaines › Noms publics).
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

## Ajouter un VPS ou un serveur dédié comme nœud

Sur la page **Nœuds** de la console :

1. Sur le serveur, connecte-toi avec ton compte habituel (ou en root si l'hébergeur le permet) et colle la ligne affichée par la console. Elle ajoute la clé de Hangar dans `~/.ssh/authorized_keys`.
2. Dans le formulaire, indique ce compte. Si son `sudo` demande un mot de passe, indique aussi ce mot de passe.
3. Lance l'installation.

Le mot de passe `sudo` ne sert que pendant l'installation. Il passe par l'entrée de `sudo` (jamais en ligne de commande) et n'est enregistré nulle part.

À la fin de l'installation, la console pilote le nœud en root, mais seulement par le réseau privé WireGuard :

- la clé de Hangar est autorisée pour root avec `from="10.88.0.1"`, l'adresse de la console sur ce réseau ;
- `/etc/ssh/sshd_config.d/00-hangar.conf` ajoute `PermitRootLogin prohibit-password` pour cette seule adresse.

L'accès root par l'adresse publique reste tel que l'hébergeur l'a réglé, généralement fermé. Les réparations (« Réinstaller / réparer ») passent par le réseau privé et ne demandent donc pas de mot de passe tant qu'il fonctionne.

Si `sshd_config` contient une liste `AllowUsers`, ajoute-y `root@10.88.0.1`. Sinon l'installation s'arrête avec un message qui l'indique.

### Sécurité du nœud

À la fin de l'installation, la console applique la politique de la page **Sécurité** : pare-feu, SSH, fail2ban, mises à jour. Par défaut, SSH reste ouvert sur le port d'installation avec les mots de passe permis : rien ne change pour ta propre connexion.

Pour durcir : ajoute ta clé publique dans **Clés SSH d'administration**, choisis **Clés seulement**, et si possible **Restreint à des adresses** avec l'adresse publique de ta box. Chaque changement revient tout seul en 2 minutes si la console ne peut plus se connecter au nœud.

La console passe toujours par le réseau privé : même avec SSH fermé sur l'adresse publique, elle continue de piloter le nœud. Avant de fermer, vérifie que tu as accès à la console d'urgence de ton hébergeur. Les commandes pour débloquer un nœud sont sur la page Sécurité.
