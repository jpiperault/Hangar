"""Historique des réglages : instantanés différents seulement, changements lisibles, retour à un réglage."""
from app import db, history, limits


def test_historique(app_row):
    db.x("DELETE FROM apps WHERE slug = 'mon-jeu'")
    db.insert_app("mon-jeu", {**app_row, "state": "ok", "created_at": 0})
    history.drop("mon-jeu")
    db.kv_set("app_limits", {})
    assert history.record("mon-jeu", "ana") and not history.record("mon-jeu", "ana")     # rien de changé : rien noté
    db.update_app("mon-jeu", mem_mb=512, env="JWT_SECRET=nouveau\nPRIX=10$\nNOUVELLE=1")
    limits.save("mon-jeu", "1.5")
    assert history.record("mon-jeu", "bob")
    e = history.entries("mon-jeu")
    assert e[0]["current"] and e[0]["user"] == "bob" and not e[1]["current"]
    ch = dict((lbl, (b, a)) for lbl, b, a in e[0]["changes"])
    assert ch["mémoire"] == ("384", "512") and ch["processeur max"] == ("—", "1.5")
    assert ch["variables"][1] == "~ JWT_SECRET, + NOUVELLE" and "nouveau" not in str(e)   # valeurs jamais montrées
    history.restore("mon-jeu", history.get("mon-jeu", e[1]["id"]))
    a = db.app("mon-jeu")
    assert a["mem_mb"] == 384 and "NOUVELLE" not in a["env"] and limits.cpus("mon-jeu") is None
    history.drop("mon-jeu")
    db.x("DELETE FROM apps WHERE slug = 'mon-jeu'")
