"""Passive Linux DNS sensor with a bounded persistent retry queue."""

from __future__ import annotations

import ipaddress
import json
import logging
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
import psutil
from scapy.all import conf, sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

from .config import settings
from .learning import parse_dns_response

logger = logging.getLogger(__name__)


def interface_name(configured: str) -> str:
    return str(conf.iface) if configured == "auto" else configured


def local_addresses(interface: str) -> set[str]:
    result = set()
    for address in psutil.net_if_addrs().get(interface, []):
        try:
            result.add(str(ipaddress.ip_address(address.address.split("%", 1)[0])))
        except ValueError:
            continue
    return result


class OfflineQueue:
    def __init__(self, path: Path, max_events: int = 100_000):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)")
        self.db.commit()
        self.lock = threading.Lock()
        self.max_events = max_events
        self.dropped = 0

    def put(self, value: dict[str, Any]) -> None:
        with self.lock:
            self.db.execute("INSERT INTO events(payload) VALUES (?)", (json.dumps(value),))
            count = self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            if count > self.max_events:
                excess = count - self.max_events
                self.db.execute(
                    "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id LIMIT ?)", (excess,)
                )
                self.dropped += excess
            self.db.commit()

    def batch(self, limit: int = 100) -> list[tuple[int, dict[str, Any]]]:
        with self.lock:
            rows = self.db.execute("SELECT id,payload FROM events ORDER BY id LIMIT ?", (limit,)).fetchall()
        return [(row[0], json.loads(row[1])) for row in rows]

    def remove(self, ids: list[int]) -> None:
        if not ids:
            return
        with self.lock:
            self.db.executemany("DELETE FROM events WHERE id=?", [(item,) for item in ids])
            self.db.commit()

    def size(self) -> int:
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]


class AgentRuntime:
    def __init__(self):
        if not settings.server_url or not settings.agent_token:
            raise ValueError("ROUTELEARN_SERVER and ROUTELEARN_AGENT_TOKEN are required")
        self.http = httpx.Client(
            base_url=settings.server_url.rstrip("/"),
            timeout=8,
            headers={"Authorization": f"Bearer {settings.agent_token}"},
        )
        self.queue = OfflineQueue(settings.data_dir / "agent-queue.db")
        self.patterns: dict[int, list[str]] = {}
        self.interface = interface_name(settings.interface)
        self.resolver_ips: set[str] = set(settings.resolver_ips.split(",")) - {""}
        self.port = settings.dns_port
        self.metrics: dict[str, int | str] = {
            "packets_seen": 0,
            "parsed": 0,
            "matching": 0,
            "tcp_ignored": 0,
            "errors": 0,
            "interface": self.interface,
        }
        cached = settings.data_dir / "agent-config.json"
        if cached.exists():
            try:
                self._apply_config(json.loads(cached.read_text()))
            except (OSError, ValueError, KeyError, TypeError):
                logger.warning("Ignoring invalid cached agent configuration")

    def _apply_config(self, payload: dict[str, Any]) -> None:
        self.patterns = {int(k): list(v) for k, v in payload["patterns"].items()}
        if settings.interface == "auto":
            self.interface = interface_name(payload.get("interface", "auto"))
        if not settings.resolver_ips:
            self.resolver_ips = set(payload.get("resolver_ips") or [])
        if settings.dns_port == 53:
            self.port = int(payload.get("dns_port", 53))
        if not self.resolver_ips:
            self.resolver_ips = local_addresses(self.interface)
        self.metrics["interface"] = self.interface

    def refresh(self) -> None:
        response = self.http.get("/api/v1/agents/config")
        response.raise_for_status()
        payload = response.json()
        self._apply_config(payload)
        (settings.data_dir / "agent-config.json").write_text(json.dumps(payload))

    def handle_packet(self, packet: Any) -> None:
        self.metrics["packets_seen"] = int(self.metrics["packets_seen"]) + 1
        network = packet.getlayer(IP) or packet.getlayer(IPv6)
        transport = packet.getlayer(UDP) or packet.getlayer(TCP)
        if network is None or transport is None or transport.sport != self.port:
            return
        source = str(ipaddress.ip_address(network.src.split("%", 1)[0]))
        client = str(ipaddress.ip_address(network.dst.split("%", 1)[0]))
        if source not in self.resolver_ips or client in self.resolver_ips:
            return
        wire = bytes(transport.payload)
        if isinstance(transport, TCP):
            if len(wire) < 2:
                self.metrics["tcp_ignored"] = int(self.metrics["tcp_ignored"]) + 1
                return
            size = int.from_bytes(wire[:2], "big")
            if len(wire) < size + 2:
                self.metrics["tcp_ignored"] = int(self.metrics["tcp_ignored"]) + 1
                return
            wire = wire[2 : size + 2]
        observations = parse_dns_response(wire, self.patterns)
        self.metrics["parsed"] = int(self.metrics["parsed"]) + 1
        for service_id, domain, ip, ttl in observations:
            self.queue.put(
                {
                    "event_id": uuid.uuid4().hex,
                    "service_id": service_id,
                    "domain": domain,
                    "ip": ip,
                    "client_ip": client,
                    "ttl": ttl,
                    "source": "dns-live",
                }
            )
            self.metrics["matching"] = int(self.metrics["matching"]) + 1

    def capture(self) -> None:
        while True:
            try:
                sniff(
                    iface=self.interface,
                    filter=f"(udp or tcp) and src port {self.port}",
                    prn=self.handle_packet,
                    store=False,
                    timeout=2,
                )
            except Exception:
                self.metrics["errors"] = int(self.metrics["errors"]) + 1
                logger.exception("capture_failed")
                time.sleep(5)

    def run(self) -> None:
        if settings.server_url.startswith("http://"):
            logger.warning("Agent token is sent over HTTP. Use HTTPS outside a trusted LAN.")
        try:
            self.refresh()
        except Exception:
            logger.warning("Server unavailable; waiting for pattern configuration")
        threading.Thread(target=self.capture, daemon=True).start()
        last_heartbeat = last_refresh = 0.0
        while True:
            now = time.monotonic()
            if now - last_refresh >= 60:
                try:
                    self.refresh()
                except Exception:
                    self.metrics["errors"] = int(self.metrics["errors"]) + 1
                last_refresh = now
            batch = self.queue.batch()
            if batch:
                try:
                    response = self.http.post(
                        "/api/v1/ingest/dns", json={"events": [item[1] for item in batch]}
                    )
                    response.raise_for_status()
                    self.queue.remove([item[0] for item in batch])
                except Exception:
                    self.metrics["errors"] = int(self.metrics["errors"]) + 1
            if now - last_heartbeat >= 30:
                try:
                    response = self.http.post(
                        "/api/v1/agents/heartbeat",
                        json={
                            "metrics": {
                                **self.metrics,
                                "queue_size": self.queue.size(),
                                "queue_dropped": self.queue.dropped,
                            }
                        },
                    )
                    response.raise_for_status()
                except Exception:
                    self.metrics["errors"] = int(self.metrics["errors"]) + 1
                last_heartbeat = now
            time.sleep(2)
