"""Messages écrits par le code : traduction d'après leur modèle, parties variables comprises."""
import json
import os

from app import msgs

CAT = {"version {} en ligne ({})": "{} online ({})", "conteneur en marche depuis {} s": "container running for {} s",
       "{} : sauvegarde en échec": "{}: backup failed", "Compte {} créé.": "Account {} created.",
       "{} a été remplacé par {}": "{1} replaced {0}", "Ce compte existe déjà.": "This account already exists."}


def test_traduction(monkeypatch):
    monkeypatch.setitem(msgs._cat, "en", None)
    msgs._cat.pop("en")
    monkeypatch.setattr(msgs.json, "load", lambda f: CAT)
    assert msgs.tr("version 1.2.0 en ligne (conteneur en marche depuis 30 s)", "en") == "1.2.0 online (container running for 30 s)"
    assert msgs.tr("Compte ana créé.", "en") == "Account ana created."
    assert msgs.tr("Ce compte existe déjà.", "en") == "This account already exists."
    assert msgs.tr("A a été remplacé par B", "en") == "B replaced A"
    assert msgs.tr("message inconnu", "en") == "message inconnu" and msgs.tr("Compte ana créé.", "fr") == "Compte ana créé."
    msgs._cat.pop("en")


def test_extraction_et_catalogue():
    found = set(msgs.extract())
    assert "Compte {} créé." in found and "{} : tâche « {} » en échec" in found
    cat = json.load(open(os.path.join(os.path.dirname(msgs.__file__), "i18n", "msg_en.json")))
    assert len(cat) > 800
    for fr, en in cat.items():
        assert fr.count("{}") == (en.count("{}") or len(set(__import__("re").findall(r"\{(\d+)\}", en)))), fr
