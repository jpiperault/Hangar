"""Types d'applis : ce qu'est l'appli, pour n'afficher que ce qui lui sert et proposer les bons réglages par défaut.
Le type est un réglage de l'appli (colonne apps.kind), modifiable ; il ne change pas son fonctionnement de fond,
sauf pour les types sans page web (service, serveur de jeu) et le site statique (sans conteneur).
"""

KINDS = {
    "web": {"name": "Site ou appli web", "short": "Appli web",
            "desc": "Une appli dans un conteneur qui sert des pages : Node, PHP, Python, Java…",
            "http": True, "client": False, "defaults": {"port": 8080, "health_path": "/health", "db": 1}},
    "api": {"name": "API", "short": "API",
            "desc": "Un service appelé par d'autres applis, un site ou une appli mobile.",
            "http": True, "client": True, "defaults": {"port": 8080, "health_path": "/health", "db": 1}},
    "mobile": {"name": "Backend d'appli mobile", "short": "Backend mobile",
               "desc": "L'API d'une appli Android ou iOS, avec configuration à distance et rapports de plantage.",
               "http": True, "client": True, "client_open": True,
               "defaults": {"port": 8080, "health_path": "/health", "db": 1}},
}
ORDER = ["web", "api", "mobile"]
DEFAULT = "web"


def get(kind):
    return KINDS.get(kind) or KINDS[DEFAULT]


def valid(kind):
    return kind in KINDS


def choices():
    return [{"id": k, **KINDS[k]} for k in ORDER if k in KINDS]


def register(kind, spec, after=None):
    """Ajoute un type (lots suivants : service, serveur de jeu, outil, site statique)."""
    KINDS[kind] = spec
    if kind not in ORDER:
        ORDER.insert(ORDER.index(after) + 1 if after in ORDER else len(ORDER), kind)
