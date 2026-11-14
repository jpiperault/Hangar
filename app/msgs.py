"""Traduction des messages écrits par le code (messages après une action, journal des événements, alertes, erreurs).

Ces messages sont composés en français avec des parties variables (« version {} en ligne »). Le catalogue
app/i18n/msg_en.json associe chaque modèle français (parties variables notées {}) à son modèle anglais ({} dans le même
ordre, ou {0}, {1}… pour les remettre dans un autre ordre). À l'affichage, un message est reconnu d'après son modèle
(le plus précis d'abord) et recomposé en anglais ; ses parties variables sont elles-mêmes traduites si ce sont des
messages connus (une erreur dans un message, par exemple). Un message inconnu reste tel quel.

Le catalogue se régénère depuis le code : extract() parcourt app/ (appels à flash, log, alerts.send, et les
ValueError / RuntimeError) — voir tests/test_msgs.py.
"""
import ast
import glob
import json
import os
import re

HERE = os.path.dirname(__file__)
_cat = {}
HOLE = "{}"


# ---------------------------------------------------------------- extraction depuis le code

def _templates(node):
    """Modèles possibles d'une expression (f-chaîne, chaîne, concaténation, choix) ; [] si autre chose."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.JoinedStr):
        outs = [""]
        for v in node.values:
            if isinstance(v, ast.Constant):
                outs = [o + str(v.value) for o in outs]
            else:
                outs = [o + HOLE for o in outs]
        return outs
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _templates(node.left) or [HOLE], _templates(node.right) or [HOLE]
        return [a + b for a in left for b in right][:8]
    if isinstance(node, ast.IfExp):
        return (_templates(node.body) or [HOLE]) + (_templates(node.orelse) or [HOLE])
    return []


NAMES = {"msg", "detail", "why", "err", "title", "text", "label", "reason", "verb", "what", "state", "upd", "hint", "note"}
FRENCH = re.compile(r"[àâçéèêëîïôûùüœ]|\b(le|la|les|de|des|du|une?|est|sont|pas|aucune?|depuis|sur|dans|avec|pour)\b", re.I)
CALLS = {"flash": 1, "log": 2, "send": 0, "send_async": 0, "_flag": 2, "ValueError": 0, "RuntimeError": 0}


def extract(root=None):
    root = root or HERE
    found = set()
    for path in glob.glob(os.path.join(root, "**", "*.py"), recursive=True):
        tree = ast.parse(open(path, encoding="utf-8").read())
        for n in ast.walk(tree):
            if not isinstance(n, ast.Call):
                continue
            f = n.func
            name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
            if name == "append" and path.endswith("report.py"):   # lignes du rapport de la semaine
                name, pos = "append", 0
            elif name not in CALLS:
                continue
            else:
                pos = CALLS[name]
            args = list(n.args)
            idx = [pos] + ([pos + 1] if name in ("send", "send_async") else []) + ([3, 4] if name == "_flag" else [])
            for i in idx:
                if i < len(args):
                    for t in _templates(args[i]):
                        if re.search(r"[A-Za-zÀ-ÿ]{3}", t.replace(HOLE, "")):
                            found.add(t)
        for n in ast.walk(tree):   # textes composés en deux temps : variable, valeur renvoyée, table de mots
            vals = []
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in NAMES for t in n.targets):
                vals = [n.value]
            elif isinstance(n, ast.Return) and isinstance(n.value, ast.Tuple):
                vals = list(n.value.elts)
            elif isinstance(n, ast.Assign) and isinstance(n.value, ast.Dict) and \
                    any(isinstance(t, ast.Name) and t.id in NAMES for t in n.targets):
                vals = list(n.value.values)
            elif isinstance(n, ast.Subscript) and isinstance(n.value, ast.Dict):   # {"create": "création", …}[kind]
                vals = list(n.value.values)
            for v in vals:
                for t in _templates(v):
                    if FRENCH.search(t) and re.search(r"[A-Za-zÀ-ÿ]{3}", t.replace(HOLE, "")):
                        found.add(t)
    return sorted(found)


# ---------------------------------------------------------------- traduction à l'affichage

def _load(lang):
    if lang not in _cat:
        try:
            d = json.load(open(os.path.join(HERE, "i18n", f"msg_{lang}.json"), encoding="utf-8"))
        except (OSError, ValueError):
            d = {}
        compiled = []
        for fr, en in d.items():
            parts = fr.split(HOLE)
            if len(parts) == 1:
                continue
            lit = sum(len(p) for p in parts)
            if lit < 4:
                continue
            rx = "^" + "(.*?)".join(re.escape(p) for p in parts[:-1]) + "(.*?)" + re.escape(parts[-1]) + "$"
            compiled.append((lit, parts[0], re.compile(rx, re.S), en))
        compiled.sort(key=lambda x: -x[0])
        _cat[lang] = ({fr: en for fr, en in d.items() if HOLE not in fr}, compiled)
    return _cat[lang]


def _fill(en, groups):
    """Modèle anglais + parties variables ; None si leur nombre ne correspond pas (le message reste alors en français)."""
    if re.search(r"\{\d+\}", en):
        idx = [int(x) for x in re.findall(r"\{(\d+)\}", en)]
        if max(idx) >= len(groups):
            return None
        return re.sub(r"\{(\d+)\}", lambda m: groups[int(m.group(1))], en)
    pieces = en.split(HOLE)
    if len(pieces) - 1 != len(groups):
        return None
    return pieces[0] + "".join(g + p for g, p in zip(groups, pieces[1:]))


def tr(text, lang, depth=0):
    """Message en français → dans `lang` (si son modèle est connu), sinon inchangé."""
    if lang == "fr" or not isinstance(text, str) or not text:
        return text
    exact, compiled = _load(lang)
    if text in exact:
        return exact[text]
    if depth > 2:
        return text
    if "; " in text and depth == 0:   # plusieurs messages mis bout à bout
        parts = text.split("; ")
        out = [tr(x, lang, depth + 1) for x in parts]
        if out != parts:
            return "; ".join(out)
    for _lit, first, rx, en in compiled:
        if first and not text.startswith(first):
            continue
        m = rx.match(text)
        if m:
            out = _fill(en, [tr(g, lang, depth + 1) for g in m.groups()])
            if out is not None:
                return out
    return text
