"""Langue de la console : français (source) ou anglais, choisie par chaque compte (users.lang).

Les gabarits restent écrits en français. Pour l'anglais, chaque gabarit est traduit une fois, à son chargement : chaque
morceau de texte fixe (entre deux balises HTML, entre deux expressions Jinja), les attributs lisibles (placeholder,
title, aria-label, alt, data-confirm) et les chaînes affichées dans les expressions {{ … }} sont remplacés par leur
traduction, trouvée dans app/i18n/en.json ({"texte français": "English text"}). Ce qui n'y est pas reste en français.
Les blocs {% … %} (logique) et <script>/<style> ne sont jamais touchés.

Le filtre « tr » traduit une valeur venue de Python (libellés d'état, types d'appli, catalogue) ; il ne fait rien en
français.
"""
import json
import os
import re

HERE = os.path.dirname(__file__)
LANGS = {"fr": "Français", "en": "English"}
DEFAULT = "fr"
_dicts = {}

JINJA = re.compile(r"\{\{.*?\}\}|\{%.*?%\}|\{#.*?#\}", re.S)
SKIP = re.compile(r"(<script\b.*?</script>|<style\b.*?</style>)", re.S | re.I)
TAG = re.compile(r"<[^>]*>")
ATTR = re.compile(r'(\b(?:placeholder|title|aria-label|alt|data-confirm)=")([^"]*)(")')
STR = re.compile(r"'(?:[^'\\]|\\.)*'" + r'|"(?:[^"\\]|\\.)*"')
LOGIC_BEFORE = re.compile(r"(==|!=|\bin|\bnot in|\[|\.get\(|\bis|startswith\(|endswith\()\s*$")
WORDY = re.compile(r"[A-Za-zÀ-ÿ]{2}")


def table(lang):
    if lang not in _dicts:
        path = os.path.join(HERE, "i18n", f"{lang}.json")
        try:
            _dicts[lang] = json.load(open(path, encoding="utf-8")) if lang != DEFAULT else {}
        except (OSError, ValueError):
            _dicts[lang] = {}
    return _dicts[lang]


def norm(s):
    return " ".join(s.split())


def _shown_literal(s):
    """Une chaîne d'une expression {{ … }} qui ressemble à du texte affiché (pas un nom de classe ou une clé)."""
    return bool(WORDY.search(s)) and (" " in s.strip() or bool(re.search(r"[À-ÿ]", s)) or s[:1].isupper())


def _pieces(text, protect, fn):
    """Applique fn à chaque morceau de `text` situé entre deux expressions Jinja protégées (\\x00n\\x00)."""
    parts = re.split(r"(\x00\d+\x00)", text)
    return "".join(p if p.startswith("\x00") else fn(p) for p in parts)


def _walk(source, on_text, on_literal):
    """Parcourt un gabarit : on_text(morceau) pour le texte fixe et les attributs lisibles, on_literal(chaîne) pour les
    chaînes des expressions {{ … }} ; retourne le gabarit réécrit avec leurs résultats."""
    blocks = []

    def protect(m):
        blocks.append(m.group(0))
        return f"\x00{len(blocks) - 1}\x00"
    src = JINJA.sub(protect, source)
    out = []
    for chunk in SKIP.split(src):
        if SKIP.fullmatch(chunk or ""):
            out.append(chunk)
            continue
        pos = 0
        for m in TAG.finditer(chunk):
            out.append(_pieces(chunk[pos:m.start()], protect, on_text))
            out.append(ATTR.sub(lambda a: a.group(1) + _pieces(a.group(2), protect, on_text) + a.group(3), m.group(0)))
            pos = m.end()
        out.append(_pieces(chunk[pos:], protect, on_text))
    res = "".join(out)

    def restore(m):
        b = blocks[int(m.group(1))]
        if b.startswith("{{"):
            b = _literals(b, on_literal)
        return b
    return re.sub(r"\x00(\d+)\x00", restore, res)


def _literals(expr, fn):
    """Chaînes d'une expression {{ … }}, lues une à une (une chaîne passée n'est jamais relue). Celles qui suivent une
    comparaison, un « in », un indice ou un appel restent telles quelles : ce sont des valeurs, pas du texte affiché.
    Exception : la valeur d'un dictionnaire ({'clé': 'texte'}) est traduite, sa clé non."""
    out, pos = [], 0
    for m in STR.finditer(expr):
        out.append(expr[pos:m.start()])
        tok, before = m.group(0), expr[:m.start()]
        q, s = tok[0], tok[1:-1]
        value_of_dict = before.rstrip().endswith(":")
        if (value_of_dict or not LOGIC_BEFORE.search(before)) and _shown_literal(s):
            t = fn(s)
            if t != s:   # espaces de début et de fin gardés (« propriétaire  » ~ valeur)
                t = s[:len(s) - len(s.lstrip())] + t.strip() + s[len(s.rstrip()):]
            tok = q + t.replace("\\", "\\\\").replace(q, "\\" + q) + q if t != s else tok
        out.append(tok)
        pos = m.end()
    out.append(expr[pos:])
    return "".join(out)


def _keep_space(piece, tr):
    core = norm(piece)
    if not core or not WORDY.search(core):
        return piece
    t = tr.get(core)
    if not t:
        return piece
    lead = piece[:len(piece) - len(piece.lstrip())]
    trail = piece[len(piece.rstrip()):]
    return lead + t + trail


def translate_source(source, lang):
    tr = table(lang)
    if not tr:
        return source
    return _walk(source, lambda p: _keep_space(p, tr), lambda s: tr.get(norm(s), s))


def extract(source):
    """Textes à traduire d'un gabarit (normalisés)."""
    found = set()

    def grab(p):
        core = norm(p)
        if core and WORDY.search(core):
            found.add(core)
        return p

    def grab_lit(s):
        found.add(norm(s))
        return s
    _walk(source, grab, grab_lit)
    return found


def tr(value, lang):
    if lang == DEFAULT or not isinstance(value, str):
        return value
    return table(lang).get(norm(value), value)
