"""Terminal interactif : le WebSocket refait le contrôle d'accès (session, administrateur, origine)."""
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app import db


def test_refus_sans_session(app_row):
    from app import main
    db.x("DELETE FROM apps WHERE slug = 'mon-jeu'")
    db.insert_app("mon-jeu", {**app_row, "state": "ok", "created_at": 0})
    c = TestClient(main.app, base_url="https://hangar.test", client=("127.0.0.1", 50040))
    with pytest.raises(WebSocketDisconnect) as e:
        with c.websocket_connect("/apps/mon-jeu/terminal/ws", headers={"origin": "https://hangar.test"}) as ws:
            ws.receive_bytes()
    assert e.value.code == 4403
    db.x("DELETE FROM apps WHERE slug = 'mon-jeu'")
