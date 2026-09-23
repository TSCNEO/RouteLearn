"""Linux Docker smoke test: capture replies from a host DNS process and a bridged DNS container.

Run after building routelearn:ci. This script uses only disposable Docker containers
and a disposable named volume. It never touches the host's port 53 or DHCP.
"""

from __future__ import annotations

import http.cookiejar
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request

SERVER = r"""
import os, socket, struct
port = int(os.environ.get("DNS_PORT", "53"))
answer = socket.inet_aton(os.environ.get("ANSWER_IP", "8.8.8.8"))
bind = os.environ.get("DNS_BIND", "0.0.0.0")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((bind, port))
while True:
    data, peer = sock.recvfrom(4096)
    if len(data) < 17:
        continue
    question = data[12:]
    payload = data[:2] + b"\x81\x80" + struct.pack("!HHHH", 1, 1, 0, 0) + question
    payload += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 240, 4) + answer
    sock.sendto(payload, peer)
"""
CLIENT = r"""
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
labels = b"".join(bytes([len(label)]) + label.encode() for label in "edge.googlevideo.com".split(".")) + b"\0"
query = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00\x01\x00\x01"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)
sock.sendto(query, (host, port))
answer = sock.recv(4096)
assert answer[:2] == b"\xab\xcd" and len(answer) > len(query)
"""


def docker(*args: str) -> str:
    return subprocess.check_output(["docker", *args], text=True).strip()


def request(
    opener: urllib.request.OpenerDirector, path: str, body: dict | None = None, csrf: str = ""
) -> dict:
    url = "http://127.0.0.1:18080" + path
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if csrf:
        headers["X-CSRF-Token"] = csrf
    with opener.open(urllib.request.Request(url, data=data, headers=headers)) as response:
        return json.load(response)


def wait_for(check, seconds: int = 30):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            value = check()
            if value:
                return value
        except Exception:
            pass
        time.sleep(1)
    raise AssertionError("Timed out waiting for Docker capture test")


def main() -> None:
    if sys.platform != "linux":
        print("Docker capture smoke test requires a Linux host")
        return
    names = [
        "routelearn-ci-server",
        "routelearn-ci-agent-host",
        "routelearn-ci-agent-docker",
        "routelearn-ci-dns",
    ]
    for name in names:
        subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(
        ["docker", "volume", "rm", "routelearn-ci-data"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    host_thread = None
    try:
        gateway = docker("network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}")
        docker(
            "run",
            "-d",
            "--name",
            names[0],
            "-p",
            "18080:8080",
            "-v",
            "routelearn-ci-data:/data",
            "routelearn:ci",
            "server",
        )
        wait_for(lambda: urllib.request.urlopen("http://127.0.0.1:18080/readyz").status == 200)
        code = docker("exec", names[0], "cat", "/data/setup.code")
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        request(
            opener,
            "/api/v1/auth/setup",
            {"username": "ci-admin", "password": "ci-password-123456", "setup_code": code},
        )
        request(opener, "/api/v1/auth/login", {"username": "ci-admin", "password": "ci-password-123456"})
        csrf = next(cookie.value for cookie in jar if cookie.name == "routelearn_csrf")
        service = request(
            opener, "/api/v1/services", {"name": "Video", "patterns": ["*.googlevideo.com"]}, csrf
        )
        service_id = service["id"]
        host_agent = request(
            opener,
            "/api/v1/agents",
            {"name": "host-dns", "interface": "docker0", "resolver_ips": [gateway], "dns_port": 5353},
            csrf,
        )
        docker_agent = request(
            opener,
            "/api/v1/agents",
            {"name": "docker-dns", "interface": "docker0", "resolver_ips": [gateway], "dns_port": 5354},
            csrf,
        )
        os.environ["DNS_PORT"] = "5353"
        os.environ["ANSWER_IP"] = "8.8.8.8"
        os.environ["DNS_BIND"] = gateway
        host_thread = threading.Thread(target=lambda: exec(SERVER, {}), daemon=True)
        host_thread.start()
        docker(
            "run",
            "-d",
            "--name",
            names[3],
            "-p",
            "5354:53/udp",
            "-e",
            "DNS_PORT=53",
            "-e",
            "ANSWER_IP=9.9.9.9",
            "python:3.12-slim",
            "python",
            "-u",
            "-c",
            SERVER,
        )
        for name, port, token in (
            (names[1], 5353, host_agent["token"]),
            (names[2], 5354, docker_agent["token"]),
        ):
            docker(
                "run",
                "-d",
                "--name",
                name,
                "--network",
                "host",
                "--cap-add",
                "NET_RAW",
                "-e",
                "ROUTELEARN_SERVER=http://127.0.0.1:18080",
                "-e",
                f"ROUTELEARN_AGENT_TOKEN={token}",
                "-e",
                "ROUTELEARN_INTERFACE=docker0",
                "-e",
                f"ROUTELEARN_RESOLVER_IPS={gateway}",
                "-e",
                f"ROUTELEARN_DNS_PORT={port}",
                "routelearn:ci",
                "agent",
            )

        def agents_online():
            rows = request(opener, "/api/v1/agents")
            return len(rows) == 2 and all(item["last_heartbeat"] for item in rows)

        wait_for(agents_online, 30)
        for _ in range(12):
            for port in (5353, 5354):
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
                    str(port),
                )
            ips = request(opener, f"/api/v1/services/{service_id}/ips")
            if len(ips) == 2 and all(row["clients"] and row["sources"] == ["dns-live"] for row in ips):
                break
            time.sleep(2)
        else:
            print("Observed IPs:", json.dumps(ips))
            print("Agent metrics:", json.dumps(request(opener, "/api/v1/agents")))
            for name in names[1:3]:
                print(f"{name} logs:\n{docker('logs', '--tail', '30', name)}")
            raise AssertionError("Docker agents did not observe both resolver replies")
        print("Docker capture passed: host DNS and bridged DNS, both with client attribution")
    finally:
        for name in names:
            subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(
            ["docker", "volume", "rm", "routelearn-ci-data"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


if __name__ == "__main__":
    main()
