"""Pare-feu généré : cloisonnement des applis, nœuds, console. Syntaxe vérifiée par nft quand c'est possible."""
import os

import pytest

from app import access, security, segment
from app import platform as P

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _policy(**kw):
    p = dict(security.DEFAULT)
    p.update(ssh_port=22, **kw)
    return p


@pytest.mark.parametrize("mode,extra", [
    ("open", []), ("closed", []),
    ("restricted", []), ("open", [{"proto": "tcp", "from": 25565, "to": 25565, "src": []}]),
    ("open", [{"proto": "udp", "from": 27015, "to": 27020, "src": ["203.0.113.0/24", "2001:db8::/48"]}]),
])
@pytest.mark.parametrize("web", [[], ["exemple.fr"]])
def test_noeud(nft_check, mode, extra, web):
    p = _policy(ssh_mode=mode, extra=extra, ssh_sources=["203.0.113.7/32", "2001:db8::/48"] if mode == "restricted" else [])
    nft_check(security.render_nft(p, web))


def test_noeud_conteneurs_sans_acces_a_l_hote():
    txt = security.render_nft(_policy(), [])
    assert 'iifname { "docker0", "br-*", "hg-*" } meta l4proto { tcp, udp } th dport != { 80, 443 } counter drop' in txt
    # la règle doit passer avant toute ouverture SSH
    assert txt.index("th dport != { 80, 443 }") < txt.index("tcp dport 22 accept")
    assert "ip daddr { 10.0.0.0/8" in txt   # réseau local et adresses privées interdits aux applis


def test_sshd_durci():
    txt = security.render_sshd(_policy(ssh_passwords=False), {"ssh_user": "root"})
    for l in ("PasswordAuthentication no", "AllowTcpForwarding no", "PermitTunnel no"):
        assert l in txt


def test_cloisonnement_vide(nft_check, monkeypatch):
    monkeypatch.setattr(segment, "_slugs", lambda: [])
    monkeypatch.setattr(segment, "_dbports", lambda: [])
    nft_check(segment.render())


def test_cloisonnement(nft_check, monkeypatch):
    monkeypatch.setattr(segment, "_slugs", lambda: ["jeu", "autre"])
    monkeypatch.setattr(segment, "_dbports", lambda: [("jeu", 28001)])
    txt = segment.render()
    nft_check(txt)
    b = segment.bridge("jeu")
    assert f'"{b}" . "{b}"' in txt and f'"{b}" . 28001' in txt
    assert '"%s" . 28001' % segment.bridge("autre") not in txt


def test_nom_de_pont():
    names = {segment.bridge(s) for s in ("a", "b", "mon-jeu", "a" * 32)}
    assert len(names) == 4 and all(len(n) <= 15 and n.startswith("hg-") for n in names)


def test_console(nft_check):
    txt = access.render_nft(open(f"{ROOT}/deploy/nftables/platform.nft").read(), ["192.168.1.0/24"], 9443)
    assert "elements = { 192.168.1.0/24 }" in txt and "tcp dport { 22, 9443 }" in txt
    nft_check(txt)


@pytest.mark.parametrize("raw", [None, "x", {"ssh_mode": "restricted"}, {"ssh_mode": "open", "ssh_port": 99999},
                                 {"ssh_mode": "open", "extra": [{"proto": "icmp", "from": 1, "to": 2}]}])
def test_politique_d_archive_invalide(raw):
    assert security.validate_policy(raw) is None


def test_plage_docker_hors_reseau_local():
    import ipaddress
    import json
    d = json.load(open(f"{ROOT}/deploy/docker/daemon.json"))
    for pool in d["default-address-pools"]:
        net = ipaddress.ip_network(pool["base"])
        assert not net.overlaps(ipaddress.ip_network("192.168.0.0/16"))
        assert not net.overlaps(ipaddress.ip_network("10.88.0.0/24"))
    assert P.HOST_PORT_MIN == 18001


@pytest.mark.parametrize("nets", [["203.0.113.4/32"], ["2001:db8::/48"], ["203.0.113.0/24", "2001:db8::/48"]])
def test_ports_publics_reserves(nft_check, monkeypatch, nets):
    from app import gameports
    monkeypatch.setattr(segment, "_slugs", lambda: ["jeu"])
    monkeypatch.setattr(segment, "_dbports", lambda: [])
    monkeypatch.setattr(gameports, "restricted", lambda: [
        ("jeu", "ns1", [{"proto": "tcp", "port": 25565, "cport": 25565}, {"proto": "udp", "port": 19132, "cport": 19132},
                        {"proto": "tcp", "port": 8081, "cport": 8080}], nets)])
    b = segment.bridge("jeu")
    ici, ailleurs = segment.render("ns1"), segment.render("local")
    nft_check(ici)
    nft_check(ailleurs)
    v4 = [n for n in nets if ":" not in n]
    assert (f'oifname "{b}" ct state new meta nfproto ipv4 meta l4proto tcp ct original proto-dst {{ 8081, 25565 }} '
            + (f"ip saddr != {{ {', '.join(v4)} }} " if v4 else "") + "counter drop") in ici
    assert "chain input" in ici and "udp dport { 19132 }" in ici
    assert "chain input" not in ailleurs and "proto-dst { 8081, 25565 }" in ailleurs   # instances ailleurs : filtrées aussi


def test_sources_saisie():
    from app import gameports
    assert gameports.parse_sources("203.0.113.4, 198.51.100.7/24 2001:db8::1/48") == \
        ["203.0.113.4/32", "198.51.100.0/24", "2001:db8::/48"]
    for bad in ("pas-une-ip", "0.0.0.0/0", "::/0"):
        with pytest.raises(ValueError):
            gameports.parse_sources(bad)
