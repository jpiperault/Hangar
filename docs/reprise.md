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

## 3. Installer, et restaurer en même temps si tu as une archive

```bash
./install.sh --domain piperault.fr --mode tunnel --tunnel-token <jeton> --restore hangar-AAAAMMJJ-HHMMSS.tar.gz
```

- Sans options, le script pose les questions : IP, réseau local, domaine, mode.
- `--tunnel-token` : le jeton du tunnel, dans Zero Trust › Networks › Tunnels › ton tunnel. Tu peux réutiliser le même tunnel : l'ancien serveur ne doit simplement plus tourner.
- `--mode direct` : pour un serveur dédié avec les ports 80 et 443 ouverts. Les certificats viennent alors de Let's Encrypt.
- `--restore` : l'archive téléchargée depuis la page Sauvegardes. Elle recrée toutes les applis, leurs bases, leurs fichiers et le domaine.
- Le script peut être relancé sans risque : il ne remplace jamais un secret ni un réglage existant.

À la fin, le script affiche l'adresse de la console. L'identifiant et le mot de passe générés sont dans `/root/hangar-mot-de-passe.txt` (change-les avec `hangar passwd`).

## 4. Restaurer depuis Google Drive ou le NAS (sans archive)

1. Installe sans `--restore`.
2. Dans la console, ouvre **Sauvegardes › Mot de passe des sauvegardes › Nouveau serveur ?** et saisis **le mot de passe de tes sauvegardes**, celui que tu as noté.
3. Connecte **Google Drive** avec le même identifiant Google qu'avant, et/ou le **NAS** avec les mêmes dossiers. Hangar retrouve le dépôt existant.
4. Dans **Restaurer une appli**, choisis la sauvegarde la plus récente, puis clique sur **Tout restaurer (reprise du serveur)…**. Hangar la télécharge et la convertit en archive.
5. Dans **Archives**, ouvre l'archive « importée » et clique sur **Tout cocher**. Coche **Reprendre les réglages**, puis lance la restauration.

## 5. Après la restauration

- **Images privées** : si une appli échoue au téléchargement, colle le jeton `read:packages` dans sa fiche, puis redéploie. Les jetons de registre ne sont pas dans les sauvegardes.
- **Cloudflare** : vérifie que les noms publics sont déclarés dans le tunnel (Domaine et accès › Noms publics).
- **Alertes** : abonne-toi au nouveau sujet ntfy (page Système et alertes), ou remets l'ancien.
- **Sauvegardes** : vérifie que Drive et/ou le NAS sont connectés, puis lance une sauvegarde.

## Ce qui n'est pas sauvegardé

Ces éléments sont à refaire à la main :
- les jetons des registres d'images ;
- le jeton du tunnel ;
- les accès Drive et NAS ;
- le compte administrateur de la console.
