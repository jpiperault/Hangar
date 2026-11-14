"""Langue de la console : traduction des gabarits au chargement, sans toucher à la logique."""
from app import i18n

SRC = """<h1>Applications</h1>
<p class="hint">Version {{ a.version }} disponible. <a href="/x">Voir</a></p>
<input placeholder="par exemple : moi" aria-label="Nom {{ n }}" name="nom">
{% if role == 'lecture' %}<span>{{ 'lecture seule' if x else 'Administrateur' }}</span>{% endif %}
<span>{{ {'running': 'en marche'}.get(s, s) }}</span>
<script nonce="1">var t = 'Voir';</script>
<code>SMTP_HOST</code>"""

TABLE = {"Applications": "Apps", "Version": "Version", "disponible.": "available.", "Voir": "See",
         "par exemple : moi": "for example: me", "Nom": "Name", "lecture seule": "read-only",
         "Administrateur": "Administrator", "en marche": "running", "lecture": "PIÈGE"}


def test_traduction(monkeypatch):
    monkeypatch.setitem(i18n._dicts, "en", TABLE)
    out = i18n.translate_source(SRC, "en")
    assert "<h1>Apps</h1>" in out and "Version {{ a.version }} available." in out and '<a href="/x">See</a>' in out
    assert 'placeholder="for example: me"' in out and 'aria-label="Name {{ n }}"' in out and 'name="nom"' in out
    assert "{% if role == 'lecture' %}" in out                      # logique jamais traduite
    assert "{{ 'read-only' if x else 'Administrator' }}" in out     # chaînes affichées, oui
    assert "{'running': 'running'}" in out                          # valeur affichée traduite, clé gardée
    assert "var t = 'Voir';" in out and "<code>SMTP_HOST</code>" in out


def test_francais_intact():
    assert i18n.translate_source(SRC, "fr") == SRC


def test_extraction():
    keys = i18n.extract(SRC)
    assert {"Applications", "Version", "disponible.", "Voir", "par exemple : moi", "Nom", "lecture seule", "en marche"} <= keys
    assert "lecture" not in keys and "var t = 'Voir';" not in keys


def test_filtre(monkeypatch):
    monkeypatch.setitem(i18n._dicts, "en", TABLE)
    assert i18n.tr("En  marche", "en") == "En  marche" and i18n.tr("en marche", "en") == "running"
    assert i18n.tr("en marche", "fr") == "en marche" and i18n.tr(3, "en") == 3


def test_tous_les_gabarits_compilent_en_anglais():
    import json
    import os
    from app.routes.common import TPLS
    env = TPLS["en"].env
    for name in env.list_templates():
        if name.endswith(".html"):
            env.get_template(name)          # une traduction ne doit jamais casser la syntaxe d'un gabarit
    d = json.load(open(os.path.join(os.path.dirname(i18n.__file__), "i18n", "en.json")))
    assert len(d) > 1000 and not any("{{" in v or "{%" in v for v in d.values())
