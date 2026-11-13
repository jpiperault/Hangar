"""Configuration à distance des clients d'une appli (Android, iOS, navigateur), servie par Caddy :
- applis mobiles : https://<hôte des routes>.<domaine>/.well-known/apps/<package ou bundle>.json, à côté de apps.json ;
- client web : https://<adresse de l'appli>/.well-known/hangar/config.json (même origine, pas de CORS), avec le
  script https://<adresse de l'appli>/.well-known/hangar/client.js.
Contenu : version minimale (bloquante) et conseillée par plateforme, interrupteurs « cle = valeur », message
d'annonce avec date de fin, adresse et clé d'envoi des plantages (crashes.py).
Réglage kv « remote_config » : {slug: {min_code, rec_code, ios_min, ios_rec, ios_store, flags, message, level, until}}.
"""
import json
import re
import time

from . import db

KEY = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
DIR = "_clients"   # dans public/ : config.json de chaque client web, et le script commun


def of(slug):
    return {"min_code": None, "rec_code": None, "ios_min": None, "ios_rec": None, "ios_store": "", "flags": "",
            "message": "", "level": "info", "until": "", **((db.kv_get("remote_config") or {}).get(slug) or {})}


def parse_flags(text):
    """« cle = valeur » par ligne → dict typé (true/false, nombres, texte). ValueError avec la ligne fautive."""
    out = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        k, sep, v = line.partition("=")
        k, v = k.strip(), v.strip()
        if not sep or not KEY.match(k):
            raise ValueError(f"ligne « {line[:50]} » : il faut « cle = valeur » (clé en minuscules, chiffres, . _ -)")
        if len(v) > 500:
            raise ValueError(f"valeur de {k} trop longue (500 caractères au plus)")
        low = v.lower()
        if low in ("true", "vrai", "oui", "on"):
            out[k] = True
        elif low in ("false", "faux", "non", "off"):
            out[k] = False
        elif re.fullmatch(r"-?\d{1,15}", v):
            out[k] = int(v)
        elif re.fullmatch(r"-?\d{1,12}\.\d{1,6}", v):
            out[k] = float(v)
        else:
            out[k] = v.strip('"')
    if len(out) > 100:
        raise ValueError("100 interrupteurs au plus")
    return out


def save(slug, f):
    def code(name):
        v = (f.get(name) or "").strip()
        if not v:
            return None
        if not re.fullmatch(r"\d{1,10}", v) or int(v) > 2_100_000_000:
            raise ValueError("numéro de version : un nombre entier (versionCode Android, numéro de build iOS)")
        return int(v)
    c = {"min_code": code("min_code"), "rec_code": code("rec_code"), "ios_min": code("ios_min"), "ios_rec": code("ios_rec"),
         "ios_store": (f.get("ios_store") or "").strip()[:300], "flags": (f.get("flags") or "").strip(),
         "message": (f.get("message") or "").strip()[:500], "level": "warn" if f.get("level") == "warn" else "info",
         "until": (f.get("until") or "").strip()}
    parse_flags(c["flags"])
    if c["until"] and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", c["until"]):
        raise ValueError("date de fin au format AAAA-MM-JJ")
    for lo, hi in (("min_code", "rec_code"), ("ios_min", "ios_rec")):
        if c[lo] and c[hi] and c[hi] < c[lo]:
            raise ValueError("la version conseillée ne peut pas être plus ancienne que la version minimale")
    if c["ios_store"] and not c["ios_store"].startswith("https://apps.apple.com/"):
        raise ValueError("lien App Store : https://apps.apple.com/…")
    allv = db.kv_get("remote_config") or {}
    allv[slug] = c
    db.kv_set("remote_config", allv)


def platform_of(a, key):
    if key and key == a["pkg"]:
        return "android"
    if key and key == a["ios_bundle"]:
        return "ios"
    return "web"


def build(a, url, hub, platform="android", key=None):
    """Contenu du fichier public d'un client."""
    from . import crashes
    key = key or (a["pkg"] if platform == "android" else a["ios_bundle"] if platform == "ios" else None)
    c = of(a["slug"])
    msg = None
    if c["message"] and (not c["until"] or c["until"] >= time.strftime("%Y-%m-%d")):
        msg = {"text": c["message"], "level": c["level"], "until": c["until"] or None}
    out = {"app": a["slug"], "platform": platform, "url": url, "flags": parse_flags(c["flags"]), "message": msg,
           "crash_key": crashes.key(a["slug"]), "updated": int(time.time())}
    if platform == "android":
        out.update(package=key, min_version_code=c["min_code"], recommended_version_code=c["rec_code"],
                   store_url=f"https://play.google.com/store/apps/details?id={key}",
                   crash_url=f"https://{hub}/.well-known/hangar/crash/{key}")
    elif platform == "ios":
        out.update(bundle=key, min_version_code=c["ios_min"], recommended_version_code=c["ios_rec"],
                   store_url=c["ios_store"] or None, crash_url=f"https://{hub}/.well-known/hangar/crash/{key}")
    else:
        out.update(crash_url="/.well-known/hangar/crash")   # même origine que la page
    return out


def files(name, hub, manifest):
    """{chemin relatif dans public/: contenu} pour un domaine : un fichier par client mobile de son apps.json."""
    owners = {}
    for a in db.apps():
        for k in (a["pkg"], a["ios_bundle"]):
            if k:
                owners[k] = a
    out = {}
    for key, url in manifest.items():
        a = owners.get(key)
        if a:
            out[f"{name}/.well-known/apps/{key}.json"] = json.dumps(build(a, url, hub, platform_of(a, key), key),
                                                                   indent=1, ensure_ascii=False)
    return out


def web_files():
    """public/_clients/ : config.json de chaque appli avec un client web, et le script commun."""
    from . import platform as P
    out = {}
    for a in db.apps():
        if a["web_client"]:
            out[f"{DIR}/{a['slug']}.json"] = json.dumps(build(a, P.primary_url(a) or "", "", "web"), indent=1,
                                                        ensure_ascii=False)
    if out:
        out[f"{DIR}/hangar-client.js"] = CLIENT_JS
    return out


CLIENT_JS = r"""/* Hangar : client web (configuration à distance, erreurs du navigateur). Servi par Hangar. */
(function () {
  if (window.hangar) return;
  var h = window.hangar = { flags: {}, message: null, ready: null, sent: 0 };
  var BASE = '/.well-known/hangar/';
  h.ready = fetch(BASE + 'config.json', { credentials: 'omit', cache: 'no-cache' }).then(function (r) { return r.json(); })
    .then(function (c) {
      h.config = c; h.flags = c.flags || {}; h.message = c.message;
      try { window.dispatchEvent(new CustomEvent('hangar:config', { detail: c })); } catch (e) {}
      return c;
    }).catch(function () { return null; });
  var seen = {};
  function send(kind, msg, stack) {
    if (h.sent >= 5) return;                       // 5 rapports au plus par page
    var sig = kind + '|' + msg + '|' + (stack || '').slice(0, 200);
    if (seen[sig]) return; seen[sig] = 1; h.sent++;
    h.ready.then(function (c) {
      if (!c || !c.crash_key) return;
      var body = JSON.stringify({ exception: kind, message: String(msg || '').slice(0, 1000), stacktrace: String(stack || '').slice(0, 15000),
        version_name: (document.querySelector('meta[name="app-version"]') || {}).content || '', version_code: 0,
        os: navigator.platform || '', device: navigator.userAgent.slice(0, 80), page: location.pathname });
      fetch(c.crash_url, { method: 'POST', keepalive: true, credentials: 'omit',
        headers: { 'Content-Type': 'application/json', 'X-Hangar-Key': c.crash_key }, body: body }).catch(function () {});
    });
  }
  window.addEventListener('error', function (e) {
    if (!e.error && !e.message) return;
    send((e.error && e.error.name) || 'Error', e.message, (e.error && e.error.stack) || (e.filename + ':' + e.lineno + ':' + e.colno));
  });
  window.addEventListener('unhandledrejection', function (e) {
    var r = e.reason || {};
    send(r.name || 'UnhandledRejection', r.message || String(r), r.stack || '');
  });
  h.report = function (err) { send((err && err.name) || 'Error', (err && err.message) || String(err), err && err.stack); };
})();
"""
