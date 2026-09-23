"""Disposable Docker Compose smoke test for setup, ingest, UI, and restart persistence."""

from __future__ import annotations

import http.cookiejar
import json
import os
import re
import subprocess
import urllib.error
import urllib.request

from docker_capture import docker, wait_for

PROJECT = "routelearn-ci-server-smoke"
BASE_URL = "http://127.0.0.1:18088"
ENV = {**os.environ, "ROUTELEARN_PORT": "18088"}


def compose(*args: str) -> str:
    return subprocess.check_output(
        ["docker", "compose", "-p", PROJECT, "-f", "compose.yml", *args],
        env=ENV,
        text=True,
    ).strip()


def request(
    opener: urllib.request.OpenerDirector,
    path: str,
    body: dict | None = None,
    headers: dict[str, str] | None = None,
):
    data = json.dumps(body).encode() if body is not None else None
    with opener.open(
        urllib.request.Request(
            BASE_URL + path,
            data=data,
            headers={"Content-Type": "application/json", **(headers or {})},
        ),
        timeout=10,
    ) as response:
        return json.load(response)


def main() -> None:
    docker("tag", "routelearn:ci", "routelearn:local")
    compose("down", "-v")
    try:
        compose("up", "-d", "routelearn")
        wait_for(lambda: urllib.request.urlopen(BASE_URL + "/readyz").status == 200)
        with urllib.request.urlopen(BASE_URL + "/") as response:
            html = response.read().decode()
        assert "RouteLearn" in html
        asset = re.search(r'(?:src|href)="(/assets/[^\"]+)"', html)
        assert asset is not None
        assert urllib.request.urlopen(BASE_URL + asset.group(1)).status == 200

        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        assert request(opener, "/api/v1/auth/status") == {"needs_setup": True}
        code = compose("exec", "-T", "routelearn", "cat", "/data/setup.code")
        assert request(
            opener,
            "/api/v1/auth/setup",
            {"username": "ci-admin", "password": "ci-password-123456", "setup_code": code},
        ) == {"status": "created"}
        request(opener, "/api/v1/auth/login", {"username": "ci-admin", "password": "ci-password-123456"})
        csrf = next(cookie.value for cookie in jar if cookie.name == "routelearn_csrf")
        try:
            request(opener, "/api/v1/services", {"name": "Blocked", "patterns": ["blocked.example"]})
        except urllib.error.HTTPError as error:
            assert error.code == 403
        else:
            raise AssertionError("A mutation without a CSRF header was accepted")

        service = request(
            opener,
            "/api/v1/services",
            {"name": "Video", "patterns": ["*.example.test"]},
            {"X-CSRF-Token": csrf},
        )
        agent = request(
            opener,
            "/api/v1/agents",
            {"name": "smoke-dns"},
            {"X-CSRF-Token": csrf},
        )
        event = {
            "event_id": "ci-smoke-event-0001",
            "service_id": service["id"],
            "domain": "video.example.test",
            "ip": "8.8.8.8",
            "client_ip": "192.0.2.15",
            "ttl": 300,
            "source": "dns-live",
        }
        auth = {"Authorization": f"Bearer {agent['token']}"}
        assert request(opener, "/api/v1/ingest/dns", {"events": [event]}, auth) == {"accepted": 1}
        assert request(opener, "/api/v1/ingest/dns", {"events": [event]}, auth) == {"accepted": 0}

        compose("restart", "routelearn")
        wait_for(lambda: urllib.request.urlopen(BASE_URL + "/readyz").status == 200)
        assert request(opener, "/api/v1/auth/status") == {"needs_setup": False}
        assert request(opener, "/api/v1/auth/me") == {"username": "ci-admin"}
        assert request(opener, "/api/v1/services")[0]["name"] == "Video"
        ips = request(opener, f"/api/v1/services/{service['id']}/ips")
        assert len(ips) == 1
        assert ips[0]["ip"] == "8.8.8.8" and ips[0]["clients"] == ["192.0.2.15"]
        assert ips[0]["agents"] == ["smoke-dns"] and ips[0]["hits"] == 1
        assert request(opener, "/api/v1/agents/config", headers=auth)["agent_id"] == agent["id"]
        dashboard = request(opener, "/api/v1/dashboard")
        assert dashboard["services"] == 1 and dashboard["agents"] == 1
        assert dashboard["active_ipv4"] == 1 and dashboard["policies"] == 0
        print("Docker server passed: UI assets, setup, CSRF, ingest, and restart persistence")
    finally:
        compose("down", "-v")


if __name__ == "__main__":
    main()
