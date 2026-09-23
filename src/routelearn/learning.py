"""Domain matching, DNS interpretation, and explainable IP learning."""

from __future__ import annotations

import ipaddress
from datetime import timedelta
from typing import Any

import dns.message
import dns.rdatatype
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import IPClient, IPDomain, IPSource, LearnedIP, Pattern, Service, utcnow


def normalize_domain(value: str) -> str:
    return value.rstrip(".").lower()


def matches(domain: str, pattern: str) -> bool:
    domain, pattern = normalize_domain(domain), normalize_domain(pattern)
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return domain.endswith(suffix) and len(domain) > len(suffix)
    return domain == pattern


def public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


class Observation(BaseModel):
    event_id: str = Field(min_length=8, max_length=64)
    service_id: int
    domain: str
    ip: str
    client_ip: str | None = None
    ttl: int = Field(ge=0, le=604800)
    source: str = "dns-live"


def parse_dns_response(wire: bytes, patterns: dict[int, list[str]]) -> list[tuple[int, str, str, int]]:
    """Walk CNAME chains from the question; never learn unrelated answers."""
    try:
        message = dns.message.from_wire(wire, ignore_trailing=True)
    except Exception:
        return []
    if not (message.flags & 0x8000) or not message.question:
        return []
    records: dict[str, list[tuple[int, str, int]]] = {}
    for rrset in message.answer:
        name = normalize_domain(rrset.name.to_text())
        for rr in rrset:
            if rr.rdtype == dns.rdatatype.CNAME:
                records.setdefault(name, []).append((5, normalize_domain(rr.target.to_text()), rrset.ttl))
            elif rr.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                records.setdefault(name, []).append((rr.rdtype, rr.address, rrset.ttl))
    root = normalize_domain(message.question[0].name.to_text())
    result: set[tuple[int, str, str, int]] = set()

    def walk(name: str, chain: tuple[str, ...], depth: int) -> None:
        if depth > 12 or name in chain:
            return
        chain = (*chain, name)
        for kind, value, ttl in records.get(name, []):
            if kind == 5:
                walk(value, chain, depth + 1)
            elif public_ip(value):
                for service_id, service_patterns in patterns.items():
                    matched_names = [
                        member for member in chain if any(matches(member, p) for p in service_patterns)
                    ]
                    if matched_names:
                        result.add((service_id, matched_names[-1], value, ttl))

    walk(root, (), 0)
    return sorted(result)


def pattern_map(db: Session) -> dict[int, list[str]]:
    out: dict[int, list[str]] = {}
    for row in db.scalars(select(Pattern)):
        out.setdefault(row.service_id, []).append(row.value)
    return out


def record_observation(db: Session, observation: Observation, agent_id: int | None = None) -> LearnedIP:
    if not public_ip(observation.ip):
        raise ValueError("Only globally routable IPs may be learned")
    domain = normalize_domain(observation.domain)
    ip = str(ipaddress.ip_address(observation.ip))
    now = utcnow()
    row = db.scalar(
        select(LearnedIP).where(LearnedIP.service_id == observation.service_id, LearnedIP.ip == ip)
    )
    if row is None:
        row = LearnedIP(service_id=observation.service_id, ip=ip, family=ipaddress.ip_address(ip).version)
        db.add(row)
        db.flush()
    row.last_seen = now
    row.hits += 1
    row.last_ttl = observation.ttl
    if observation.source == "dns-live":
        row.last_live_seen = now
    elif observation.source.startswith("warmup-"):
        row.last_warmup_seen = now
    relation = db.scalar(select(IPDomain).where(IPDomain.learned_ip_id == row.id, IPDomain.domain == domain))
    if relation is None:
        relation = IPDomain(learned_ip_id=row.id, domain=domain, hits=0)
        db.add(relation)
    relation.last_seen = now
    relation.hits += 1
    if observation.client_ip:
        client = db.scalar(
            select(IPClient).where(
                IPClient.learned_ip_id == row.id, IPClient.client_ip == observation.client_ip
            )
        )
        if client is None:
            client = IPClient(learned_ip_id=row.id, client_ip=observation.client_ip, hits=0)
            db.add(client)
        client.last_seen = now
        client.hits += 1
    source = db.scalar(
        select(IPSource).where(
            IPSource.learned_ip_id == row.id,
            IPSource.source == observation.source,
            IPSource.agent_id == agent_id,
        )
    )
    if source is None:
        source = IPSource(learned_ip_id=row.id, source=observation.source, agent_id=agent_id, hits=0)
        db.add(source)
    source.last_seen = now
    source.hits += 1
    other = db.scalar(
        select(LearnedIP).where(LearnedIP.ip == ip, LearnedIP.service_id != observation.service_id)
    )
    if other:
        row.shared_ip_suspected = True
        other.shared_ip_suspected = True
    return row


def active(row: LearnedIP, service: Service) -> bool:
    if row.excluded:
        return False
    now = utcnow()
    return bool(
        row.pinned
        or (row.last_live_seen and row.last_live_seen >= now - timedelta(hours=service.live_window_hours))
        or (
            row.last_warmup_seen
            and row.last_warmup_seen >= now - timedelta(hours=service.warmup_window_hours)
        )
    )


def active_ips(db: Session, service: Service) -> list[str]:
    return sorted(
        row.ip
        for row in db.scalars(select(LearnedIP).where(LearnedIP.service_id == service.id))
        if active(row, service)
    )


def prune_history(db: Session) -> int:
    removed = 0
    for service in db.scalars(select(Service)):
        cutoff = utcnow() - timedelta(days=service.retention_days)
        rows = db.scalars(select(LearnedIP).where(LearnedIP.service_id == service.id)).all()
        for row in rows:
            if not row.pinned and not active(row, service) and row.last_seen < cutoff:
                for model in (IPDomain, IPClient, IPSource):
                    for relation in db.scalars(select(model).where(model.learned_ip_id == row.id)):
                        db.delete(relation)
                db.delete(row)
                removed += 1
    db.commit()
    return removed


def serialize_ip(db: Session, row: LearnedIP, service: Service) -> dict[str, Any]:
    return {
        "id": row.id,
        "ip": row.ip,
        "family": row.family,
        "active": active(row, service),
        "first_seen": row.first_seen.isoformat(),
        "last_seen": row.last_seen.isoformat(),
        "hits": row.hits,
        "last_ttl": row.last_ttl,
        "pinned": row.pinned,
        "excluded": row.excluded,
        "shared_ip_suspected": row.shared_ip_suspected,
        "domains": [x.domain for x in db.scalars(select(IPDomain).where(IPDomain.learned_ip_id == row.id))],
        "clients": [
            x.client_ip for x in db.scalars(select(IPClient).where(IPClient.learned_ip_id == row.id))
        ],
        "sources": [x.source for x in db.scalars(select(IPSource).where(IPSource.learned_ip_id == row.id))],
    }
