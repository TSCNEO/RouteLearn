import dns.message
import dns.rrset
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from routelearn.db import Base, IPClient, IPDomain, LearnedIP, Service, utcnow
from routelearn.learning import (
    Observation,
    active_ips,
    matches,
    parse_dns_response,
    prune_history,
    record_observation,
)


def wire(question: str, *answers: tuple[str, str, str]) -> bytes:
    query = dns.message.make_query(question + ".", "A")
    response = dns.message.make_response(query)
    for owner, kind, value in answers:
        response.answer.append(
            dns.rrset.from_text(owner + ".", 240, "IN", kind, value + "." if kind == "CNAME" else value)
        )
    return response.to_wire()


def test_domain_matching_and_cname_chain() -> None:
    assert matches("rr2.googlevideo.com", "*.googlevideo.com")
    assert not matches("evilgooglevideo.com", "*.googlevideo.com")
    assert not matches("googlevideo.com", "*.googlevideo.com")
    assert matches("YOUTUBE.COM.", "youtube.com")
    packet = wire(
        "youtube.com",
        ("youtube.com", "CNAME", "edge.example.net"),
        ("edge.example.net", "CNAME", "final.example.net"),
        ("final.example.net", "A", "8.8.8.8"),
        ("final.example.net", "AAAA", "2606:4700:4700::1111"),
        ("unrelated.example", "A", "9.9.9.9"),
    )
    result = parse_dns_response(packet, {1: ["youtube.com"]})
    assert len(result) == 2
    assert {row[2] for row in result} == {"8.8.8.8", "2606:4700:4700::1111"}
    assert {row[1] for row in result} == {"youtube.com"}
    assert parse_dns_response(packet, {1: ["*.googlevideo.com"]}) == []


def test_learning_tracks_clients_sources_active_window_and_exclusion() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = Service(name="Video", live_window_hours=168)
        db.add(service)
        db.flush()
        for _ in range(2):
            record_observation(
                db,
                Observation(
                    event_id="abcdefgh",
                    service_id=service.id,
                    domain="EDGE.EXAMPLE.COM.",
                    ip="8.8.8.8",
                    client_ip="192.0.2.10",
                    ttl=240,
                ),
            )
        db.commit()
        row = db.query(LearnedIP).one()
        assert row.hits == 2 and row.last_ttl == 240
        assert db.query(IPDomain).one().domain == "edge.example.com"
        assert db.query(IPClient).one().hits == 2
        assert active_ips(db, service) == ["8.8.8.8"]
        row.excluded = True
        assert active_ips(db, service) == []
        row.excluded = False
        row.last_live_seen = None
        row.last_seen = utcnow()
        row.pinned = True
        assert active_ips(db, service) == ["8.8.8.8"]
        assert prune_history(db) == 0


def test_private_addresses_are_not_learned() -> None:
    packet = wire(
        "youtube.com",
        ("youtube.com", "A", "192.168.1.2"),
        ("youtube.com", "A", "127.0.0.1"),
        ("youtube.com", "A", "169.254.1.1"),
    )
    assert parse_dns_response(packet, {1: ["youtube.com"]}) == []
