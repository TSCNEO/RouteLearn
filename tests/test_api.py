from fastapi.testclient import TestClient
from sqlalchemy import select

from routelearn.api import app
from routelearn.db import IngestEvent, IPClient, LearnedIP, SessionLocal
from routelearn.security import setup_code


def test_setup_agent_auth_and_idempotent_ingest() -> None:
    with TestClient(app) as client:
        assert client.get("/readyz").status_code == 200
        assert client.get("/api/v1/auth/status").json() == {"needs_setup": True}
        response = client.post(
            "/api/v1/auth/setup",
            json={"username": "admin", "password": "a-long-password-123", "setup_code": setup_code()},
        )
        assert response.status_code == 200
        assert (
            client.post(
                "/api/v1/auth/setup",
                json={"username": "other", "password": "a-long-password-123", "setup_code": "x"},
            ).status_code
            == 409
        )
        assert (
            client.post("/api/v1/auth/login", json={"username": "admin", "password": "wrong"}).status_code
            == 401
        )
        assert (
            client.post(
                "/api/v1/auth/login", json={"username": "admin", "password": "a-long-password-123"}
            ).status_code
            == 200
        )
        headers = {"X-CSRF-Token": client.cookies["routelearn_csrf"]}
        service = client.post(
            "/api/v1/services", json={"name": "Video", "patterns": ["*.googlevideo.com"]}, headers=headers
        )
        assert service.status_code == 200
        service_id = service.json()["id"]
        agent = client.post("/api/v1/agents", json={"name": "primary-dns"}, headers=headers)
        assert agent.status_code == 200
        assert client.post("/api/v1/agents", json={"name": "primary-dns"}, headers=headers).status_code == 409
        token = agent.json()["token"]
        event = {
            "event_id": "abcdef0123456789",
            "service_id": service_id,
            "domain": "edge.googlevideo.com",
            "ip": "8.8.8.8",
            "client_ip": "192.0.2.10",
            "ttl": 240,
            "source": "dns-live",
        }
        auth = {"Authorization": f"Bearer {token}"}
        assert client.post("/api/v1/ingest/dns", json={"events": [event]}, headers=auth).json() == {
            "accepted": 1
        }
        assert client.post("/api/v1/ingest/dns", json={"events": [event]}, headers=auth).json() == {
            "accepted": 0
        }
        event["event_id"] = "abcdef0123456790"
        event["ip"] = "192.168.1.1"
        assert client.post("/api/v1/ingest/dns", json={"events": [event]}, headers=auth).json() == {
            "accepted": 0
        }
        with SessionLocal() as db:
            assert len(db.scalars(select(IngestEvent)).all()) == 1
            assert db.scalar(select(LearnedIP)).hits == 1
            assert db.scalar(select(IPClient)).client_ip == "192.0.2.10"
        assert client.post(f"/api/v1/agents/{agent.json()['id']}/revoke", headers=headers).status_code == 200
        assert client.get("/api/v1/agents/config", headers=auth).status_code == 401
