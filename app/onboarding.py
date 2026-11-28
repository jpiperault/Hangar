"""Premier démarrage : la liste des réglages qui rendent une installation utilisable, chacun avec son état et le lien
qui le règle. Affichée en tête de l'accueil tant qu'un réglage essentiel manque (masquable : kv « onboarding_hidden »).
"""
import os

from . import db
from . import domains as D
from . import platform as P


def steps():
    from . import alerts, backup, cloudflare, nodes, system
    doms = D.all_domains()
    tunnel = [d for d in doms if d["mode"] == "tunnel"]
    s = db.settings()
    out = [
        {"key": "domain", "done": bool(doms), "essential": True, "title": "Ajouter un domaine",
         "text": "Le nom sous lequel tes applis seront publiées (exemple.fr → appli.exemple.fr) : un domaine et un jeton "
                 "Cloudflare, Hangar fait le reste.", "href": "/demarrage"},
        {"key": "tunnel", "done": bool(doms) and (not tunnel or os.path.exists(P.TUNNEL_TOKEN)), "essential": True,
         "title": "Relier le tunnel Cloudflare" if tunnel or not doms else "Exposition directe",
         "text": "Jeton du tunnel (Cloudflare Zero Trust → Networks → Tunnels) : rien à ouvrir sur ta box. "
                 "En mode direct, les ports 80 et 443 doivent arriver sur la machine d'entrée.", "href": "/demarrage" if tunnel else "/domains#tunnel"},
        {"key": "dns", "done": bool(cloudflare.token()) or not tunnel, "essential": False,
         "title": "Laisser Hangar créer les DNS",
         "text": "Un jeton d'API Cloudflare (droit DNS) : chaque nouvelle adresse est créée et retirée toute seule.",
         "href": "/domains#cloudflare"},
        {"key": "backup", "done": backup.configured(), "essential": True, "title": "Brancher une sauvegarde",
         "text": "Google Drive ou un NAS, chiffré, chaque nuit, avec une vérification de restauration chaque semaine.",
         "href": "/backups"},
        {"key": "alerts", "done": s.get("alerts_on") == "1" and bool(alerts.configured(s)), "essential": True,
         "title": "Recevoir les alertes",
         "text": "ntfy sur le téléphone, e-mail, Discord ou Telegram : appli en panne, sauvegarde ratée, disque plein…",
         "href": "/system#alertes"},
        {"key": "tz", "done": bool(system.tz_settings()["tz"]), "essential": False, "title": "Choisir le fuseau horaire",
         "text": "Heure des tâches planifiées, des sauvegardes et des journaux.", "href": "/system#fuseau"},
        {"key": "app", "done": bool(db.apps()), "essential": False, "title": "Publier une première appli",
         "text": "Depuis une image Docker, un dépôt Git, un zip de site, ou le catalogue d'applis prêtes.",
         "href": "/catalogue"},
        {"key": "nodes", "done": len(nodes.all_nodes()) > 1, "essential": False, "title": "Ajouter une autre machine",
         "text": "Facultatif : un VPS ou un autre serveur, pour répartir les applis ou en mettre en haute dispo.",
         "href": "/nodes"},
    ]
    return out


def pending():
    """Étapes essentielles restantes (vide : installation prête)."""
    return [x for x in steps() if x["essential"] and not x["done"]]


def hidden():
    return bool(db.kv_get("onboarding_hidden"))


def set_hidden(v):
    db.kv_set("onboarding_hidden", bool(v))
