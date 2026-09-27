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
        csrf = client.cookies["routelearn_csrf"]
        client.cookies.delete("routelearn_csrf")
        assert (
            client.post(
                "/api/v1/services", json={"name": "Blocked", "patterns": ["blocked.example"]}
            ).status_code
            == 403
        )
        client.cookies.set("routelearn_csrf", csrf)
        headers = {"X-CSRF-Token": csrf}
        service = client.post(
            "/api/v1/services", json={"name": "Video", "patterns": ["*.googlevideo.com"]}, headers=headers
        )
        assert service.status_code == 200
        service_id = service.json()["id"]
        changed = client.patch(
            f"/api/v1/services/{service_id}",
            json={"patterns": ["*.googlevideo.com", "youtube.com"], "live_window_hours": 48},
            headers=headers,
        )
        assert changed.status_code == 200 and changed.json()["live_window_hours"] == 48
        assert (
            client.patch(
                f"/api/v1/services/{service_id}", json={"patterns": ["*.example.*"]}, headers=headers
            ).status_code
            == 422
        )
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
        assert client.get(f"/api/v1/services/{service_id}/ips").json()[0]["agents"] == ["primary-dns"]
        assert client.post(f"/api/v1/agents/{agent.json()['id']}/revoke", headers=headers).status_code == 200
        assert client.get("/api/v1/agents/config", headers=auth).status_code == 401


def test_router_and_policy_management() -> None:
    with TestClient(app) as client:
        client.post("/api/v1/auth/login", json={"username": "admin", "password": "a-long-password-123"})
        csrf = client.cookies["routelearn_csrf"]
        headers = {"X-CSRF-Token": csrf}

        # Create router
        router_res = client.post(
            "/api/v1/routers",
            json={
                "name": "TestGateway",
                "host": "192.168.1.1",
                "site": "default",
                "verify_tls": False,
                "api_key": "some-test-api-key-12345",
            },
            headers=headers,
        )
        assert router_res.status_code == 200
        router_id = router_res.json()["id"]

        # Update router
        patch_res = client.patch(
            f"/api/v1/routers/{router_id}",
            json={"name": "UpdatedGateway", "site": "custom-site"},
            headers=headers,
        )
        assert patch_res.status_code == 200
        assert patch_res.json()["name"] == "UpdatedGateway"
        assert patch_res.json()["site"] == "custom-site"

        # Create service and policy
        svc_res = client.post(
            "/api/v1/services", json={"name": "TestSvc", "patterns": ["*.test.com"]}, headers=headers
        )
        svc_id = svc_res.json()["id"]

        policy_res = client.post(
            "/api/v1/routes",
            json={
                "service_id": svc_id,
                "router_id": router_id,
                "vpn_network_id": "vpn-123",
                "vpn_name": "TestVPN",
                "state": "learning",
            },
            headers=headers,
        )
        assert policy_res.status_code == 200
        policy_id = policy_res.json()["id"]

        # Delete policy
        del_pol_res = client.delete(f"/api/v1/routes/{policy_id}", headers=headers)
        assert del_pol_res.status_code == 200
        assert del_pol_res.json()["status"] == "deleted"

        # Delete router
        del_router_res = client.delete(f"/api/v1/routers/{router_id}", headers=headers)
        assert del_router_res.status_code == 200
        assert del_router_res.json()["status"] == "deleted"
        assert client.get(f"/api/v1/routers/{router_id}/discover", headers=headers).status_code == 404
