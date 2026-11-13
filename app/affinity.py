"""Affinité par partie (haute dispo, instances multiples) : toutes les requêtes d'une même partie vont sur la même
instance. Caddy choisit l'instance d'après un hachage :
- header : la valeur d'un en-tête envoyé par l'appli cliente (ex. X-Match-Id) ;
- query  : un paramètre d'adresse (ex. ?match=…, pratique pour un WebSocket) ;
- cookie : un cookie posé par Caddy à la première requête (même joueur → même instance) ;
- ip     : l'adresse du joueur.
Sans la valeur (en-tête ou paramètre absent), la requête part sur n'importe quelle instance.
Réglage kv « ha_affinity » : {slug: {"mode": ..., "name": ...}}.
"""
import re

from . import db

MODES = {"": "aucune (répartition tour à tour)", "header": "en-tête", "query": "paramètre d'adresse",
         "cookie": "cookie", "ip": "adresse du joueur"}
DEFAULT_NAME = {"header": "X-Match-Id", "query": "match", "cookie": "hangar_instance"}
NAME_RE = {"header": r"[A-Za-z0-9-]{1,64}", "query": r"[A-Za-z0-9_.-]{1,64}", "cookie": r"[A-Za-z0-9_-]{1,64}"}


def of(slug):
    return (db.kv_get("ha_affinity") or {}).get(slug) or {"mode": "", "name": ""}


def save(slug, mode, name):
    if mode not in MODES:
        raise ValueError("affinité inconnue")
    name = (name or "").strip() or DEFAULT_NAME.get(mode, "")
    if mode in NAME_RE and not re.fullmatch(NAME_RE[mode], name):
        raise ValueError(f"nom invalide pour {MODES[mode]} : lettres, chiffres, tirets (64 au plus)")
    allv = db.kv_get("ha_affinity") or {}
    if mode:
        allv[slug] = {"mode": mode, "name": name if mode in NAME_RE else ""}
    else:
        allv.pop(slug, None)
    db.kv_set("ha_affinity", allv)


def caddy_policy(slug):
    """Ligne lb_policy de Caddy pour cette appli (répartition tour à tour sans affinité)."""
    a = of(slug)
    m, n = a.get("mode"), a.get("name")
    if m == "header":
        return f"lb_policy header {n}"
    if m == "query":
        return f"lb_policy query {n}"
    if m == "cookie":
        return f"lb_policy cookie {n}"
    if m == "ip":
        return "lb_policy client_ip_hash"
    return "lb_policy round_robin"
