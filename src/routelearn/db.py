"""Database schema and session management."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    create_engine,
    event,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

from .config import settings


def utcnow() -> datetime:
    # SQLite stores UTC timestamps without an offset.
    return datetime.now(UTC).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))


class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Service(Base):
    __tablename__ = "services"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    live_window_hours: Mapped[int] = mapped_column(Integer, default=168)
    warmup_window_hours: Mapped[int] = mapped_column(Integer, default=72)
    retention_days: Mapped[int] = mapped_column(Integer, default=90)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    patterns: Mapped[list[Pattern]] = relationship(back_populates="service", cascade="all, delete-orphan")


class Pattern(Base):
    __tablename__ = "service_domain_patterns"
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"))
    value: Mapped[str] = mapped_column(String(255))
    service: Mapped[Service] = relationship(back_populates="patterns")
    __table_args__ = (UniqueConstraint("service_id", "value"),)


class LearnedIP(Base):
    __tablename__ = "learned_ips"
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"))
    ip: Mapped[str] = mapped_column(String(45))
    family: Mapped[int] = mapped_column(Integer)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_live_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_warmup_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_ttl: Mapped[int | None] = mapped_column(Integer)
    hits: Mapped[int] = mapped_column(Integer, default=0)
    pinned: Mapped[bool] = mapped_column(Boolean, default=False)
    excluded: Mapped[bool] = mapped_column(Boolean, default=False)
    shared_ip_suspected: Mapped[bool] = mapped_column(Boolean, default=False)
    __table_args__ = (UniqueConstraint("service_id", "ip"),)


class IPDomain(Base):
    __tablename__ = "learned_ip_domains"
    id: Mapped[int] = mapped_column(primary_key=True)
    learned_ip_id: Mapped[int] = mapped_column(ForeignKey("learned_ips.id"))
    domain: Mapped[str] = mapped_column(String(255))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    hits: Mapped[int] = mapped_column(Integer, default=0)
    __table_args__ = (UniqueConstraint("learned_ip_id", "domain"),)


class IPClient(Base):
    __tablename__ = "learned_ip_clients"
    id: Mapped[int] = mapped_column(primary_key=True)
    learned_ip_id: Mapped[int] = mapped_column(ForeignKey("learned_ips.id"))
    client_ip: Mapped[str] = mapped_column(String(45))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    hits: Mapped[int] = mapped_column(Integer, default=0)
    __table_args__ = (UniqueConstraint("learned_ip_id", "client_ip"),)


class IPSource(Base):
    __tablename__ = "learned_ip_sources"
    id: Mapped[int] = mapped_column(primary_key=True)
    learned_ip_id: Mapped[int] = mapped_column(ForeignKey("learned_ips.id"))
    source: Mapped[str] = mapped_column(String(80))
    agent_id: Mapped[int | None] = mapped_column(ForeignKey("agents.id"))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    hits: Mapped[int] = mapped_column(Integer, default=0)


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    token_hint: Mapped[str] = mapped_column(String(8))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    interface: Mapped[str] = mapped_column(String(80), default="auto")
    resolver_ips: Mapped[list[str]] = mapped_column(JSON, default=list)
    dns_port: Mapped[int] = mapped_column(Integer, default=53)
    last_heartbeat: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    metrics: Mapped[dict] = mapped_column(JSON, default=dict)


class IngestEvent(Base):
    __tablename__ = "ingest_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[str] = mapped_column(String(64), unique=True)
    agent_id: Mapped[int] = mapped_column(ForeignKey("agents.id"))
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Router(Base):
    __tablename__ = "router_connections"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    kind: Mapped[str] = mapped_column(String(30), default="unifi")
    host: Mapped[str] = mapped_column(String(255))
    site: Mapped[str] = mapped_column(String(120), default="default")
    verify_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    api_key_encrypted: Mapped[str] = mapped_column(String(1000))


class RoutePolicy(Base):
    __tablename__ = "route_policies"
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"))
    router_id: Mapped[int] = mapped_column(ForeignKey("router_connections.id"))
    name: Mapped[str] = mapped_column(String(150))
    vpn_network_id: Mapped[str] = mapped_column(String(120))
    vpn_name: Mapped[str] = mapped_column(String(120))
    source_clients: Mapped[list[str]] = mapped_column(JSON, default=list)
    state: Mapped[str] = mapped_column(String(20), default="learning")
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SyncRun(Base):
    __tablename__ = "sync_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[int] = mapped_column(ForeignKey("route_policies.id"))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    desired_count: Mapped[int] = mapped_column(Integer, default=0)
    current_count: Mapped[int] = mapped_column(Integer, default=0)
    added: Mapped[int] = mapped_column(Integer, default=0)
    removed: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(30))
    error: Mapped[str | None] = mapped_column(String(1000))


class WarmupRun(Base):
    __tablename__ = "warmup_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    status: Mapped[str] = mapped_column(String(30), default="running")
    result: Mapped[dict] = mapped_column(JSON, default=dict)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    action: Mapped[str] = mapped_column(String(100))
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class AppSetting(Base):
    __tablename__ = "app_settings"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)


engine = create_engine(settings.database_url, connect_args={"check_same_thread": False})


@event.listens_for(engine, "connect")
def sqlite_pragmas(connection: object, _: object) -> None:
    cursor = connection.cursor()  # type: ignore[attr-defined]
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


SessionLocal = sessionmaker(engine, expire_on_commit=False)
