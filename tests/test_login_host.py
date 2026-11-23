"""Page de connexion : nom de la machine de la console, pas le domaine."""
import socket


def test_nom_de_la_machine():
    from fastapi.testclient import TestClient
    from app import main
    r = TestClient(main.app, base_url="https://hangar.test", client=("127.0.0.1", 50044)).get("/login")
    assert r.status_code == 200 and f'<span class="mono">{socket.gethostname()}</span>' in r.text
