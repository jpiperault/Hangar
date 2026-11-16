"""Types d'applis : ce qu'est l'appli, pour n'afficher que ce qui lui sert et proposer les bons réglages par défaut.
Le type est un réglage de l'appli (colonne apps.kind), modifiable ; il ne change pas son fonctionnement de fond,
sauf pour les types sans page web (service, serveur de jeu) et le site statique (sans conteneur).
"""

KINDS = {
    "web": {"name": "Site ou appli web", "short": "Appli web",
            "desc": "Une appli dans un conteneur qui sert des pages : Node, PHP, Python, Java…",
            "http": True, "client": False, "ports_opt": True, "defaults": {"port": 8080, "health_path": "/health", "db": 1}},
    "api": {"name": "API", "short": "API",
            "desc": "Un service appelé par d'autres applis, un site ou une appli mobile.",
            "http": True, "client": True, "ports_opt": True, "defaults": {"port": 8080, "health_path": "/health", "db": 1}},
    "mobile": {"name": "Backend d'appli mobile", "short": "Backend mobile",
               "desc": "L'API d'une appli Android ou iOS, avec configuration à distance et rapports de plantage.",
               "http": True, "client": True, "client_open": True,
               "defaults": {"port": 8080, "health_path": "/health", "db": 1}},
    "static": {"name": "Site statique", "short": "Site statique",
               "desc": "HTML, ou un front React/Vue déjà construit. Servi par Caddy, sans conteneur.",
               "http": True, "static": True, "client": False, "defaults": {"port": 8080, "health_path": "/", "db": 0}},
    "tool": {"name": "Outil auto-hébergé", "short": "Outil",
             "desc": "Une appli open source prête, installée depuis le catalogue.",
             "http": True, "client": False, "catalog": True, "ports_opt": True, "defaults": {"port": 8080, "health_path": "/", "db": 0}},
    "worker": {"name": "Service sans page web", "short": "Service",
               "desc": "Bot, traitement de fond, file d'attente : jugé sain tant que son conteneur tourne.",
               "http": False, "client": False, "ports_opt": True, "defaults": {"port": 8080, "health_path": "/", "db": 0}},
    "game": {"name": "Serveur de jeu ou TCP/UDP", "short": "Serveur de jeu",
             "desc": "Minecraft, serveur UDP, tout service qui n'est pas du web : ports publics sur sa machine.",
             "http": False, "ports": True, "client": False, "defaults": {"port": 25565, "health_path": "/", "db": 0}},
}
ORDER = ["static", "web", "api", "mobile", "worker", "game", "tool"]
DEFAULT = "web"


def get(kind):
    return KINDS.get(kind) or KINDS[DEFAULT]


def http(kind):
    """L'appli sert-elle du web (adresses, Caddy, adresse de santé) ?"""
    return get(kind).get("http", True)


def ports(kind):
    """Ports publics TCP/UDP : « required » (serveur de jeu), « optional » (appli web, service, outil : un serveur de
    messagerie par exemple) ou None."""
    k = get(kind)
    return "required" if k.get("ports") else ("optional" if k.get("ports_opt") else None)


def static(kind):
    return bool(get(kind).get("static"))


def valid(kind):
    return kind in KINDS


def choices():
    return [{"id": k, **KINDS[k]} for k in ORDER if k in KINDS]


def register(kind, spec, after=None):
    """Ajoute un type (lots suivants : service, serveur de jeu, outil, site statique)."""
    KINDS[kind] = spec
    if kind not in ORDER:
        ORDER.insert(ORDER.index(after) + 1 if after in ORDER else len(ORDER), kind)
