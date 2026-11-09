"""Client minimal de l'API des registres Docker (v2) : liste des tags et empreinte d'un tag.
Utilise les identifiants de `docker login` (/root/.docker/config.json) quand il y en a."""
import json
import re
import urllib.error
import urllib.parse
import urllib.request

DOCKER_CFG = "/root/.docker/config.json"
ACCEPT = ", ".join(["application/vnd.oci.image.index.v1+json",
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.docker.distribution.manifest.v2+json",
                    "application/vnd.oci.image.manifest.v1+json"])


def split(image):
    """ghcr.io/a/b -> ("ghcr.io", "a/b") ; postgres -> ("registry-1.docker.io", "library/postgres")."""
    first = image.split("/", 1)[0]
    if "/" in image and ("." in first or ":" in first or first == "localhost"):
        host, repo = image.split("/", 1)
    else:
        host, repo = "docker.io", image
    if host == "docker.io":
        host = "registry-1.docker.io"
        if "/" not in repo:
            repo = "library/" + repo
    return host, repo


def _basic(host):
    try:
        auths = json.load(open(DOCKER_CFG)).get("auths", {})
    except (OSError, ValueError):
        return None
    key = "https://index.docker.io/v1/" if host == "registry-1.docker.io" else host
    a = auths.get(key, {}).get("auth")
    return f"Basic {a}" if a else None


def _get(url, headers, method="GET"):
    req = urllib.request.Request(url, headers=headers, method=method)
    return urllib.request.urlopen(req, timeout=20)


def _request(host, repo, path, method="GET", accept=None):
    """Requête vers le registre en suivant le défi d'authentification Bearer."""
    url = f"https://{host}/v2/{repo}/{path}"
    headers = {"Accept": accept} if accept else {}
    try:
        return _get(url, headers, method)
    except urllib.error.HTTPError as e:
        if e.code != 401:
            raise
        challenge = e.headers.get("WWW-Authenticate", "")
    if not challenge.lower().startswith("bearer"):
        basic = _basic(host)
        if not basic:
            raise PermissionError("le registre demande des identifiants")
        return _get(url, {**headers, "Authorization": basic}, method)
    params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
    realm = params.pop("realm", "")
    params.setdefault("scope", f"repository:{repo}:pull")
    treq = urllib.request.Request(realm + "?" + urllib.parse.urlencode(params))
    basic = _basic(host)
    if basic:
        treq.add_header("Authorization", basic)
    try:
        with urllib.request.urlopen(treq, timeout=20) as r:
            tok = json.load(r)
    except urllib.error.HTTPError as e:
        raise PermissionError(f"jeton refusé par {host} (HTTP {e.code})")
    token = tok.get("token") or tok.get("access_token")
    try:
        return _get(url, {**headers, "Authorization": f"Bearer {token}"}, method)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise PermissionError(f"accès refusé à {repo} (image privée sans identifiants ?)")
        if e.code == 404:
            raise LookupError(f"{repo} introuvable sur {host}")
        raise


def tags(image, limit_pages=10):
    host, repo = split(image)
    out, path = [], "tags/list?n=1000"
    for _ in range(limit_pages):
        with _request(host, repo, path) as r:
            out += json.load(r).get("tags") or []
            link = r.headers.get("Link", "")
        m = re.search(r'<[^>]*/v2/[^>]*/(tags/list\?[^>]*)>', link)
        if not m:
            break
        path = m.group(1)
    return out


def digest(image, tag):
    host, repo = split(image)
    with _request(host, repo, f"manifests/{tag}", method="HEAD", accept=ACCEPT) as r:
        return r.headers.get("Docker-Content-Digest")


SEMVER = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?$")


def semver(tag):
    m = SEMVER.match(tag or "")
    if not m:
        return None
    major, minor, patch, pre = m.groups()
    # une version finale passe avant ses pré-versions : (…, 1) > (…, 0, "rc1")
    return (int(major), int(minor), int(patch or 0)) + ((1,) if pre is None else (0, pre))


def newest(tags_list, current):
    """Plus haute version semver supérieure à `current` (pré-versions seulement si current en est une)."""
    cur = semver(current)
    if not cur:
        return None
    allow_pre = cur[3] == 0
    best, best_v = None, cur
    for t in tags_list:
        v = semver(t)
        if not v or (v[3] == 0 and not allow_pre):
            continue
        if v > best_v:
            best, best_v = t, v
    return best
