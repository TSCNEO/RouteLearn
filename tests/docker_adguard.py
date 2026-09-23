"""Linux smoke test for both optional AdGuard Compose stacks and their agents.

The test creates disposable Compose projects and a DNS rewrite.  It never
changes the host's DNS or DHCP configuration.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import subprocess
import sys
import time
import urllib.request

from docker_capture import CLIENT, docker, wait_for

MAIN_PROJECT = "routelearn-ci-adguard-main"
NODE_PROJECT = "routelearn-ci-adguard-node"
MAIN_FILES = ("compose.yml", "compose.adguard.yml")
NODE_FILES = ("compose.dns-node.yml",)
BASE_URL = "http://127.0.0.1:18082"


def compose(project: str, files: tuple[str, ...], env: dict[str, str], *args: str) -> str:
    command = ["docker", "compose", "-p", project]
    for file in files:
        command += ["-f", file]
    return subprocess.check_output([*command, *args], env={**os.environ, **env}, text=True).strip()


def json_request(
    opener: urllib.request.OpenerDirector,
    url: str,
    body: dict | None = None,
    csrf: str = "",
):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if csrf:
        headers["X-CSRF-Token"] = csrf
    with opener.open(urllib.request.Request(url, data=data, headers=headers), timeout=10) as response:
        raw = response.read()
        return json.loads(raw) if raw and response.headers.get_content_type() == "application/json" else {}


def start_adguard(answer: str) -> None:
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    wait_for(lambda: urllib.request.urlopen("http://127.0.0.1:13000/").status == 200)
    json_request(
        opener,
        "http://127.0.0.1:13000/control/install/configure",
        {
            "web": {"ip": "0.0.0.0", "port": 80},
            "dns": {"ip": "0.0.0.0", "port": 53},
            "username": "ci-admin",
            "password": "ci-password-123456",
        },
    )
    wait_for(lambda: urllib.request.urlopen("http://127.0.0.1:18081/").status == 200)
    json_request(
        opener,
        "http://127.0.0.1:18081/control/login",
        {"name": "ci-admin", "password": "ci-password-123456"},
    )
    json_request(
        opener,
        "http://127.0.0.1:18081/control/rewrite/add",
        {"domain": "edge.googlevideo.com", "answer": answer},
    )


def observe(
    opener: urllib.request.OpenerDirector,
    csrf: str,
    service_id: int,
    project: str,
    files: tuple[str, ...],
    env: dict[str, str],
    name: str,
    ip: str,
    gateway: str,
) -> None:
    agent = json_request(
        opener,
        f"{BASE_URL}/api/v1/agents",
        {"name": name, "interface": "docker0", "resolver_ips": [gateway], "dns_port": 53},
        csrf,
    )
    compose(project, files, {**env, "ROUTELEARN_AGENT_TOKEN": agent["token"]}, "up", "-d", "routelearn-agent")

    def online():
        agents = json_request(opener, f"{BASE_URL}/api/v1/agents")
        return any(item["name"] == name and item["last_heartbeat"] for item in agents)

    wait_for(online, 30)
    for _ in range(12):
        docker(
            "run",
            "--rm",
            "--network",
            "bridge",
            "python:3.12-slim",
            "python",
            "-c",
            CLIENT,
            gateway,
            "53",
        )
        rows = json_request(opener, f"{BASE_URL}/api/v1/services/{service_id}/ips")
        if any(row["ip"] == ip and name in row["agents"] and row["clients"] for row in rows):
            return
        time.sleep(2)
    print("Observed IPs:", json.dumps(rows))
    print("Agent metrics:", json.dumps(json_request(opener, f"{BASE_URL}/api/v1/agents")))
    print(compose(project, files, env, "logs", "--tail", "30", "routelearn-agent", "adguard"))
    raise AssertionError(f"AdGuard reply from {name} was not attributed to its client")


def main() -> None:
    if sys.platform != "linux":
        print("AdGuard Compose capture smoke test requires Linux")
        return
    gateway = docker("network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}")
    env = {
        "ROUTELEARN_PORT": "18082",
        "ADGUARD_BIND_IP": gateway,
        "ADGUARD_SETUP_PORT": "13000",
        "ADGUARD_WEB_PORT": "18081",
        "ROUTELEARN_SERVER": BASE_URL,
        "ROUTELEARN_AGENT_TOKEN": "dummy",
        "ROUTELEARN_INTERFACE": "docker0",
    }
    docker("tag", "routelearn:ci", "routelearn:local")
    for project, files in ((NODE_PROJECT, NODE_FILES), (MAIN_PROJECT, MAIN_FILES)):
        subprocess.run(
            [
                "docker",
                "compose",
                "-p",
                project,
                *(part for file in files for part in ("-f", file)),
                "down",
                "-v",
            ],
            env={**os.environ, **env},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    try:
        compose(MAIN_PROJECT, MAIN_FILES, env, "up", "-d", "routelearn", "adguard")
        wait_for(lambda: urllib.request.urlopen(f"{BASE_URL}/readyz").status == 200)
        setup = compose(MAIN_PROJECT, MAIN_FILES, env, "exec", "-T", "routelearn", "cat", "/data/setup.code")
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        json_request(
            opener,
            f"{BASE_URL}/api/v1/auth/setup",
            {"username": "ci-admin", "password": "ci-password-123456", "setup_code": setup},
        )
        json_request(
            opener,
            f"{BASE_URL}/api/v1/auth/login",
            {"username": "ci-admin", "password": "ci-password-123456"},
        )
        csrf = next(cookie.value for cookie in jar if cookie.name == "routelearn_csrf")
        service = json_request(
            opener,
            f"{BASE_URL}/api/v1/services",
            {"name": "Video", "patterns": ["*.googlevideo.com"]},
            csrf,
        )

        start_adguard("8.8.8.8")
        observe(
            opener, csrf, service["id"], MAIN_PROJECT, MAIN_FILES, env, "main-adguard", "8.8.8.8", gateway
        )
        compose(MAIN_PROJECT, MAIN_FILES, env, "stop", "routelearn-agent", "adguard")

        compose(NODE_PROJECT, NODE_FILES, env, "up", "-d", "adguard")
        start_adguard("9.9.9.9")
        observe(
            opener, csrf, service["id"], NODE_PROJECT, NODE_FILES, env, "node-adguard", "9.9.9.9", gateway
        )
        print("AdGuard Compose capture passed: main and secondary stacks, with client attribution")
    finally:
        for project, files in ((NODE_PROJECT, NODE_FILES), (MAIN_PROJECT, MAIN_FILES)):
            subprocess.run(
                [
                    "docker",
                    "compose",
                    "-p",
                    project,
                    *(part for file in files for part in ("-f", file)),
                    "down",
                    "-v",
                ],
                env={**os.environ, **env},
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )


if __name__ == "__main__":
    main()
