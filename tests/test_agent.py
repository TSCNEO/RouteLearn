from pathlib import Path

import dns.message
import dns.rrset
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

import routelearn.agent as agent_module
from routelearn.agent import OfflineQueue
from routelearn.config import Settings


def test_offline_queue_survives_restart_and_drops_oldest(tmp_path: Path) -> None:
    path = tmp_path / "queue.db"
    queue = OfflineQueue(path, max_events=2)
    queue.put({"id": 1})
    queue.put({"id": 2})
    queue.put({"id": 3})
    assert queue.dropped == 1
    assert [item[1]["id"] for item in queue.batch()] == [2, 3]
    again = OfflineQueue(path, max_events=2)
    assert [item[1]["id"] for item in again.batch()] == [2, 3]
    again.remove([row[0] for row in again.batch()])
    assert again.size() == 0


def test_sensor_only_queues_local_resolver_reply(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(
        agent_module,
        "settings",
        Settings(
            data_dir=tmp_path,
            server_url="http://localhost:8080",
            agent_token="test-token",
            interface="lo",
            resolver_ips="192.0.2.53",
            dns_port=53,
        ),
    )
    runtime = agent_module.AgentRuntime()
    runtime.patterns = {1: ["*.googlevideo.com"]}
    query = dns.message.make_query("edge.googlevideo.com.", "A")
    response = dns.message.make_response(query)
    response.answer.append(dns.rrset.from_text("edge.googlevideo.com.", 240, "IN", "A", "8.8.8.8"))
    wire = response.to_wire()
    local = IP(src="192.0.2.53", dst="192.0.2.10") / UDP(sport=53, dport=53000) / Raw(load=wire)
    upstream = IP(src="8.8.8.8", dst="192.0.2.53") / UDP(sport=53, dport=53000) / Raw(load=wire)
    runtime.handle_packet(upstream)
    assert runtime.queue.size() == 0
    runtime.handle_packet(local)
    assert runtime.queue.size() == 1
    assert runtime.metrics["client_responses"] == 1
    assert runtime.metrics["last_client_ip"] == "192.0.2.10"
    event = runtime.queue.batch()[0][1]
    assert event["domain"] == "edge.googlevideo.com" and event["client_ip"] == "192.0.2.10"
    incomplete = IP(src="192.0.2.53", dst="192.0.2.10") / TCP(sport=53, dport=53000) / Raw(load=b"\x00\x20x")
    runtime.handle_packet(incomplete)
    assert runtime.metrics["tcp_ignored"] == 1
