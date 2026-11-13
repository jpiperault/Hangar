"""Limites par appli au-delà de la mémoire : processeur maximal (cœurs), et surveillance de l'usage.

Réglage kv « app_limits » : {slug: {"cpus": 1.5}}. Sans limite, une appli peut prendre tout le processeur du nœud
et ralentir les autres ; avec, Docker la bride (compose « cpus »).
"""
from . import db


def of(slug):
    return (db.kv_get("app_limits") or {}).get(slug) or {}


def cpus(slug):
    return of(slug).get("cpus")


def save(slug, value):
    """value : texte du formulaire (vide = sans limite). ValueError si invalide."""
    v = (value or "").strip().replace(",", ".")
    allv = db.kv_get("app_limits") or {}
    if not v:
        allv.pop(slug, None)
    else:
        try:
            c = round(float(v), 2)
        except ValueError:
            raise ValueError("processeur : un nombre de cœurs, par exemple 0.5 ou 2")
        if not 0.1 <= c <= 64:
            raise ValueError("processeur : entre 0,1 et 64 cœurs")
        allv[slug] = {**allv.get(slug, {}), "cpus": c}
    db.kv_set("app_limits", allv)


def drop(slug):
    allv = db.kv_get("app_limits") or {}
    if allv.pop(slug, None) is not None:
        db.kv_set("app_limits", allv)
