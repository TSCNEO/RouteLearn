"""HTTP API and static dashboard."""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Any

from argon2.exceptions import VerifyMismatchError
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session as DBSession

from .config import settings
from .db import (
    Agent,
    AuditEvent,
    IngestEvent,
    LearnedIP,
    Pattern,
    RoutePolicy,
    Router,
    Service,
    SessionLocal,
    SyncRun,
    User,
    WarmupRun,
    utcnow,
)
from .db import (
    Session as LoginSession,
)
from .learning import Observation, active_ips, matches, pattern_map, record_observation, serialize_ip
from .routing import RouterError, UniFiBackend, policy_preview, reconcile
from .security import clear_setup_code, encrypt, hasher, new_token, setup_code, token_hash
from .warmup import RESOLVERS, warmup

logger = logging.getLogger(__name__)
_sync_lock = threading.Lock()
_stop = threading.Event()
_desired_fingerprints: dict[int, str] = {}


def _jobs() -> None:
    from .learning import prune_history

    last_prune = 0.0
    while not _stop.wait(5):
        if not _sync_lock.acquire(blocking=False):
            continue
        try:
            with SessionLocal() as db:
                for policy in db.scalars(select(RoutePolicy)):
                    service = db.get(Service, policy.service_id)
                    desired = active_ips(db, service) if service and policy.state == "active" else []
                    fingerprint = hashlib.sha256(json.dumps([policy.state, desired]).encode()).hexdigest()
                    changed = _desired_fingerprints.get(policy.id) != fingerprint
                    latest = db.scalar(
                        select(SyncRun).where(SyncRun.policy_id == policy.id).order_by(SyncRun.id.desc())
                    )
                    age = (utcnow() - latest.started_at).total_seconds() if latest else float("inf")
                    if age < 5 or (not changed and age < 60):
                        continue
                    reconcile(db, policy)
                    _desired_fingerprints[policy.id] = fingerprint
                if time.monotonic() - last_prune > 3600:
                    prune_history(db)
                    last_prune = time.monotonic()
        except Exception:
            logger.exception("background_job_failed")
        finally:
            _sync_lock.release()


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    from alembic import command
    from alembic.config import Config

    command.upgrade(Config(str(Path.cwd() / "alembic.ini")), "head")
    with SessionLocal() as db:
        if db.scalar(select(func.count(User.id))) == 0:
            logger.warning("First-run setup code: %s", setup_code())
    _stop.clear()
    worker = threading.Thread(target=_jobs, daemon=True)
    worker.start()
    yield
    _stop.set()
    worker.join(timeout=3)


app = FastAPI(title="RouteLearn", version="0.1.0", lifespan=lifespan)


def get_db():
    with SessionLocal() as db:
        yield db


DB = Annotated[DBSession, Depends(get_db)]


def _same_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if origin:
        from urllib.parse import urlparse

        if urlparse(origin).netloc != request.headers.get("host"):
            raise HTTPException(403, "Invalid origin")


def current_user(request: Request, db: DB) -> User:
    cookie = request.cookies.get("routelearn_session")
    if not cookie:
        raise HTTPException(401, "Sign in required")
    login = db.scalar(select(LoginSession).where(LoginSession.token_hash == token_hash(cookie)))
    if login is None or login.expires_at < utcnow():
        raise HTTPException(401, "Session expired")
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        _same_origin(request)
        if request.headers.get("x-csrf-token") != request.cookies.get("routelearn_csrf"):
            raise HTTPException(403, "CSRF token missing")
    user = db.get(User, login.user_id)
    if user is None:
        raise HTTPException(401, "Sign in required")
    return user


Admin = Annotated[User, Depends(current_user)]


def audit(db: DBSession, action: str, **details: Any) -> None:
    db.add(AuditEvent(action=action, details=details))


def current_agent(request: Request, db: DB) -> Agent:
    value = request.headers.get("authorization", "")
    if not value.startswith("Bearer "):
        raise HTTPException(401, "Agent token required")
    agent = db.scalar(select(Agent).where(Agent.token_hash == token_hash(value[7:])))
    if agent is None or agent.revoked:
        raise HTTPException(401, "Invalid agent token")
    return agent


AgentAuth = Annotated[Agent, Depends(current_agent)]


class AdminSetup(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=12)
    setup_code: str


@app.get("/api/v1/auth/status")
def auth_status(db: DB) -> dict[str, bool]:
    return {"needs_setup": db.scalar(select(func.count(User.id))) == 0}


@app.post("/api/v1/auth/setup")
def setup_admin(payload: AdminSetup, request: Request, db: DB) -> dict[str, str]:
    _same_origin(request)
    if db.scalar(select(func.count(User.id))) != 0:
        raise HTTPException(409, "Admin already exists")
    import secrets

    if not secrets.compare_digest(payload.setup_code, setup_code()):
        raise HTTPException(403, "Invalid setup code")
    db.add(User(username=payload.username, password_hash=hasher.hash(payload.password)))
    db.commit()
    clear_setup_code()
    return {"status": "created"}


class Credentials(BaseModel):
    username: str
    password: str


_login_attempts: dict[str, list[float]] = {}


@app.post("/api/v1/auth/login")
def login(payload: Credentials, request: Request, response: Response, db: DB) -> dict[str, str]:
    _same_origin(request)
    address = request.client.host if request.client else "unknown"
    recent = [x for x in _login_attempts.get(address, []) if time.monotonic() - x < 300]
    if len(recent) >= 10:
        raise HTTPException(429, "Too many login attempts")
    user = db.scalar(select(User).where(User.username == payload.username))
    try:
        if user is None or not hasher.verify(user.password_hash, payload.password):
            raise VerifyMismatchError()
    except VerifyMismatchError:
        _login_attempts[address] = [*recent, time.monotonic()]
        raise HTTPException(401, "Invalid credentials") from None
    _login_attempts.pop(address, None)
    token, csrf = new_token(), new_token()
    db.add(
        LoginSession(token_hash=token_hash(token), user_id=user.id, expires_at=utcnow() + timedelta(days=7))
    )
    db.commit()
    secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(
        "routelearn_session", token, httponly=True, secure=secure, samesite="strict", max_age=604800
    )
    response.set_cookie(
        "routelearn_csrf", csrf, httponly=False, secure=secure, samesite="strict", max_age=604800
    )
    return {"username": user.username}


@app.get("/api/v1/auth/me")
def me(user: Admin) -> dict[str, str]:
    return {"username": user.username}


@app.post("/api/v1/auth/logout")
def logout(request: Request, response: Response, db: DB, _: Admin) -> dict[str, str]:
    cookie = request.cookies.get("routelearn_session", "")
    login_row = db.scalar(select(LoginSession).where(LoginSession.token_hash == token_hash(cookie)))
    if login_row:
        db.delete(login_row)
        db.commit()
    response.delete_cookie("routelearn_session")
    response.delete_cookie("routelearn_csrf")
    return {"status": "signed out"}


class ServiceCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    patterns: list[str] = Field(min_length=1)


YOUTUBE_PATTERNS = [
    "*.googlevideo.com",
    "*.youtube.com",
    "youtube.com",
    "*.ytimg.com",
    "youtubei.googleapis.com",
    "youtu.be",
    "*.youtube-nocookie.com",
]


def _service_json(service: Service) -> dict[str, Any]:
    return {
        "id": service.id,
        "name": service.name,
        "patterns": [p.value for p in service.patterns],
        "live_window_hours": service.live_window_hours,
        "warmup_window_hours": service.warmup_window_hours,
        "retention_days": service.retention_days,
    }


@app.get("/api/v1/services")
def services(db: DB, _: Admin) -> list[dict[str, Any]]:
    return [_service_json(item) for item in db.scalars(select(Service))]


@app.post("/api/v1/services")
def create_service(payload: ServiceCreate, db: DB, _: Admin) -> dict[str, Any]:
    if db.scalar(select(Service).where(Service.name == payload.name)):
        raise HTTPException(409, "Service name exists")
    values = [x.strip().rstrip(".").lower() for x in payload.patterns]
    if any(not x or " " in x or ("*" in x and not x.startswith("*.")) for x in values):
        raise HTTPException(422, "Invalid domain pattern")
    item = Service(name=payload.name, patterns=[Pattern(value=x) for x in sorted(set(values))])
    db.add(item)
    audit(db, "service.created", name=payload.name)
    db.commit()
    db.refresh(item)
    return _service_json(item)


@app.get("/api/v1/services/templates")
def service_templates(_: Admin) -> dict[str, list[str]]:
    return {"YouTube": YOUTUBE_PATTERNS}


class ServiceUpdate(BaseModel):
    patterns: list[str] | None = None
    live_window_hours: int | None = Field(default=None, ge=1, le=8760)
    warmup_window_hours: int | None = Field(default=None, ge=1, le=8760)
    retention_days: int | None = Field(default=None, ge=1, le=3650)


@app.patch("/api/v1/services/{service_id}")
def update_service(service_id: int, payload: ServiceUpdate, db: DB, _: Admin) -> dict[str, Any]:
    item = db.get(Service, service_id)
    if item is None:
        raise HTTPException(404)
    for key in ("live_window_hours", "warmup_window_hours", "retention_days"):
        value = getattr(payload, key)
        if value is not None:
            setattr(item, key, value)
    if payload.patterns is not None:
        item.patterns = [Pattern(value=value.strip().rstrip(".").lower()) for value in payload.patterns]
    audit(db, "service.updated", service_id=service_id)
    db.commit()
    return _service_json(item)


@app.get("/api/v1/services/{service_id}/ips")
def service_ips(service_id: int, db: DB, _: Admin) -> list[dict[str, Any]]:
    service = db.get(Service, service_id)
    if service is None:
        raise HTTPException(404)
    return [
        serialize_ip(db, ip, service)
        for ip in db.scalars(select(LearnedIP).where(LearnedIP.service_id == service_id))
    ]


class IPUpdate(BaseModel):
    pinned: bool | None = None
    excluded: bool | None = None


@app.patch("/api/v1/ips/{ip_id}")
def update_ip(ip_id: int, payload: IPUpdate, db: DB, _: Admin) -> dict[str, Any]:
    row = db.get(LearnedIP, ip_id)
    if row is None:
        raise HTTPException(404)
    if payload.pinned is not None:
        row.pinned = payload.pinned
    if payload.excluded is not None:
        row.excluded = payload.excluded
    audit(db, "ip.updated", learned_ip_id=ip_id, pinned=row.pinned, excluded=row.excluded)
    db.commit()
    service = db.get(Service, row.service_id)
    if service is None:
        raise HTTPException(404)
    return serialize_ip(db, row, service)


class AgentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    interface: str = "auto"
    resolver_ips: list[str] = []
    dns_port: int = Field(default=53, ge=1, le=65535)


@app.get("/api/v1/agents")
def agents(db: DB, _: Admin) -> list[dict[str, Any]]:
    return [
        {
            "id": x.id,
            "name": x.name,
            "interface": x.interface,
            "resolver_ips": x.resolver_ips,
            "dns_port": x.dns_port,
            "last_heartbeat": x.last_heartbeat.isoformat() if x.last_heartbeat else None,
            "metrics": x.metrics,
            "revoked": x.revoked,
        }
        for x in db.scalars(select(Agent))
    ]


@app.post("/api/v1/agents")
def create_agent(payload: AgentCreate, db: DB, _: Admin) -> dict[str, Any]:
    import ipaddress

    try:
        for ip in payload.resolver_ips:
            ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(422, "Invalid resolver IP") from None
    if db.scalar(select(Agent.id).where(Agent.name == payload.name)) is not None:
        raise HTTPException(409, "Agent name already exists")
    token = new_token()
    item = Agent(
        name=payload.name,
        token_hash=token_hash(token),
        token_hint=token[-6:],
        interface=payload.interface,
        resolver_ips=payload.resolver_ips,
        dns_port=payload.dns_port,
    )
    db.add(item)
    audit(db, "agent.created", name=payload.name)
    db.commit()
    return {
        "id": item.id,
        "token": token,
        "name": item.name,
        "compose_environment": {
            "ROUTELEARN_SERVER": "http://SERVER_HOST:8080",
            "ROUTELEARN_AGENT_TOKEN": token,
            "ROUTELEARN_INTERFACE": payload.interface,
        },
    }


@app.post("/api/v1/agents/{agent_id}/rotate")
def rotate_agent(agent_id: int, db: DB, _: Admin) -> dict[str, str]:
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(404)
    token = new_token()
    agent.token_hash, agent.token_hint = token_hash(token), token[-6:]
    audit(db, "agent.rotated", agent_id=agent_id)
    db.commit()
    return {"token": token}


@app.post("/api/v1/agents/{agent_id}/revoke")
def revoke_agent(agent_id: int, db: DB, _: Admin) -> dict[str, str]:
    agent = db.get(Agent, agent_id)
    if agent is None:
        raise HTTPException(404)
    agent.revoked = True
    audit(db, "agent.revoked", agent_id=agent_id)
    db.commit()
    return {"status": "revoked"}


@app.get("/api/v1/agents/config")
def agent_config(db: DB, agent: AgentAuth) -> dict[str, Any]:
    return {
        "agent_id": agent.id,
        "patterns": pattern_map(db),
        "interface": agent.interface,
        "resolver_ips": agent.resolver_ips,
        "dns_port": agent.dns_port,
    }


class Heartbeat(BaseModel):
    metrics: dict[str, int | str]


@app.post("/api/v1/agents/heartbeat")
def heartbeat(payload: Heartbeat, db: DB, agent: AgentAuth) -> dict[str, str]:
    agent.last_heartbeat = utcnow()
    agent.metrics = payload.metrics
    db.commit()
    return {"status": "ok"}


class IngestBatch(BaseModel):
    events: list[Observation] = Field(max_length=100)


@app.post("/api/v1/ingest/dns")
def ingest(payload: IngestBatch, db: DB, agent: AgentAuth) -> dict[str, int]:
    patterns = pattern_map(db)
    accepted = 0
    for event in payload.events:
        if db.scalar(select(IngestEvent).where(IngestEvent.event_id == event.event_id)):
            continue
        if event.source != "dns-live" or not any(
            matches(event.domain, p) for p in patterns.get(event.service_id, [])
        ):
            continue
        try:
            record_observation(db, event, agent.id)
        except ValueError:
            continue
        db.add(IngestEvent(event_id=event.event_id, agent_id=agent.id))
        accepted += 1
    db.commit()
    return {"accepted": accepted}


class RouterCreate(BaseModel):
    name: str
    host: str
    site: str = "default"
    verify_tls: bool = True
    api_key: str = Field(min_length=10)


@app.get("/api/v1/routers")
def routers(db: DB, _: Admin) -> list[dict[str, Any]]:
    return [
        {
            "id": r.id,
            "name": r.name,
            "host": r.host,
            "site": r.site,
            "verify_tls": r.verify_tls,
            "kind": r.kind,
        }
        for r in db.scalars(select(Router))
    ]


@app.post("/api/v1/routers")
def create_router(payload: RouterCreate, db: DB, _: Admin) -> dict[str, Any]:
    item = Router(
        name=payload.name,
        host=payload.host,
        site=payload.site,
        verify_tls=payload.verify_tls,
        api_key_encrypted=encrypt(payload.api_key),
    )
    db.add(item)
    audit(db, "router.created", name=payload.name, host=payload.host)
    db.commit()
    return {"id": item.id, "name": item.name}


@app.get("/api/v1/routers/{router_id}/discover")
def discover_router(router_id: int, db: DB, _: Admin) -> dict[str, Any]:
    router = db.get(Router, router_id)
    if router is None:
        raise HTTPException(404)
    try:
        backend = UniFiBackend(router)
        return {
            "sites": backend.discover_sites(),
            "vpn_clients": backend.discover_vpn_clients(),
            "clients": backend.discover_clients(),
        }
    except RouterError as exc:
        raise HTTPException(502, str(exc)) from exc


class PolicyCreate(BaseModel):
    service_id: int
    router_id: int
    vpn_network_id: str
    vpn_name: str
    source_clients: list[str] = []
    state: str = "learning"


@app.get("/api/v1/routes")
def policies(db: DB, _: Admin) -> list[dict[str, Any]]:
    return [
        {
            "id": p.id,
            "name": p.name,
            "service_id": p.service_id,
            "router_id": p.router_id,
            "vpn_name": p.vpn_name,
            "state": p.state,
            "last_synced_at": p.last_synced_at.isoformat() if p.last_synced_at else None,
        }
        for p in db.scalars(select(RoutePolicy))
    ]


@app.post("/api/v1/routes")
def create_policy(payload: PolicyCreate, db: DB, _: Admin) -> dict[str, Any]:
    service = db.get(Service, payload.service_id)
    if service is None or db.get(Router, payload.router_id) is None:
        raise HTTPException(404, "Service or router not found")
    if payload.state not in ("learning", "active", "paused"):
        raise HTTPException(422, "Invalid state")
    name = f"RouteLearn · {service.name}"
    if db.scalar(
        select(RoutePolicy).where(RoutePolicy.router_id == payload.router_id, RoutePolicy.name == name)
    ):
        raise HTTPException(409, "This router already has a managed policy for the service")
    item = RoutePolicy(
        service_id=service.id,
        router_id=payload.router_id,
        name=name,
        vpn_network_id=payload.vpn_network_id,
        vpn_name=payload.vpn_name,
        source_clients=payload.source_clients,
        state=payload.state,
    )
    db.add(item)
    audit(db, "policy.created", name=name, state=payload.state)
    db.commit()
    return {"id": item.id, "name": item.name, "state": item.state}


class PolicyState(BaseModel):
    state: str


@app.patch("/api/v1/routes/{policy_id}")
def update_policy(policy_id: int, payload: PolicyState, db: DB, _: Admin) -> dict[str, str]:
    item = db.get(RoutePolicy, policy_id)
    if item is None:
        raise HTTPException(404)
    if payload.state not in ("learning", "active", "paused"):
        raise HTTPException(422)
    item.state = payload.state
    audit(db, "policy.state_changed", policy_id=policy_id, state=payload.state)
    db.commit()
    with _sync_lock:
        run = reconcile(db, item, manual=payload.state != "active")
    return {"state": item.state, "sync_status": run.status}


@app.get("/api/v1/routes/{policy_id}/preview")
def preview(policy_id: int, db: DB, _: Admin) -> dict[str, Any]:
    item = db.get(RoutePolicy, policy_id)
    if item is None:
        raise HTTPException(404)
    try:
        return policy_preview(db, item)
    except RouterError as exc:
        raise HTTPException(502, str(exc)) from exc


@app.post("/api/v1/routes/{policy_id}/sync")
def sync(policy_id: int, db: DB, _: Admin) -> dict[str, Any]:
    item = db.get(RoutePolicy, policy_id)
    if item is None:
        raise HTTPException(404)
    with _sync_lock:
        run = reconcile(db, item, manual=True)
    audit(db, "policy.manual_sync", policy_id=policy_id, status=run.status)
    db.commit()
    return {"status": run.status, "error": run.error, "added": run.added, "removed": run.removed}


@app.get("/api/v1/sync/runs")
def sync_runs(db: DB, _: Admin) -> list[dict[str, Any]]:
    return [
        {
            "id": r.id,
            "policy_id": r.policy_id,
            "started_at": r.started_at.isoformat(),
            "desired_count": r.desired_count,
            "current_count": r.current_count,
            "added": r.added,
            "removed": r.removed,
            "status": r.status,
            "error": r.error,
        }
        for r in db.scalars(select(SyncRun).order_by(SyncRun.id.desc()).limit(100))
    ]


class WarmupStart(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=20)
    resolvers: list[str] = ["cloudflare", "google"]


@app.post("/api/v1/services/{service_id}/warmup")
def start_warmup(
    service_id: int, payload: WarmupStart, background: BackgroundTasks, db: DB, _: Admin
) -> dict[str, int]:
    if db.get(Service, service_id) is None:
        raise HTTPException(404)
    if not payload.resolvers or any(x not in RESOLVERS for x in payload.resolvers):
        raise HTTPException(422, "Select Cloudflare and/or Google")
    run = WarmupRun(service_id=service_id, status="running", result={})
    db.add(run)
    audit(db, "warmup.started", service_id=service_id, videos=len(payload.urls))
    db.commit()
    background.add_task(warmup, service_id, run.id, payload.urls, payload.resolvers)
    return {"run_id": run.id}


@app.get("/api/v1/warmup/runs")
def warmup_runs(db: DB, _: Admin) -> list[dict[str, Any]]:
    return [
        {"id": x.id, "service_id": x.service_id, "status": x.status, "result": x.result}
        for x in db.scalars(select(WarmupRun).order_by(WarmupRun.id.desc()).limit(100))
    ]


@app.get("/api/v1/audit")
def audit_events(db: DB, _: Admin) -> list[dict[str, Any]]:
    return [
        {"id": x.id, "at": x.created_at.isoformat(), "action": x.action, "details": x.details}
        for x in db.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(100))
    ]


@app.get("/api/v1/dashboard")
def dashboard(db: DB, _: Admin) -> dict[str, Any]:
    services = db.scalars(select(Service)).all()
    agents = db.scalars(select(Agent).where(Agent.revoked.is_(False))).all()
    return {
        "services": len(services),
        "agents": len(agents),
        "agents_online": sum(
            bool(a.last_heartbeat and utcnow() - a.last_heartbeat < timedelta(seconds=90)) for a in agents
        ),
        "learned_ipv4": db.scalar(select(func.count(LearnedIP.id)).where(LearnedIP.family == 4)),
        "learned_ipv6": db.scalar(select(func.count(LearnedIP.id)).where(LearnedIP.family == 6)),
        "active_ipv4": sum(sum("." in ip for ip in active_ips(db, s)) for s in services),
        "active_ipv6": sum(sum(":" in ip for ip in active_ips(db, s)) for s in services),
        "policies": db.scalar(select(func.count(RoutePolicy.id))),
        "last_sync": (lambda x: {"status": x.status, "at": x.started_at.isoformat()} if x else None)(
            db.scalar(select(SyncRun).order_by(SyncRun.id.desc()))
        ),
    }


@app.get("/api/v1/events/stream")
def events(_: Admin) -> StreamingResponse:
    def stream():
        while True:
            yield f"data: {json.dumps({'time': time.time()})}\n\n"
            time.sleep(5)

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/readyz")
def readyz(db: DB) -> dict[str, str]:
    db.execute(select(1))
    return {"status": "ready"}


_static = Path(__file__).parent / "static"
if _static.exists():
    app.mount("/assets", StaticFiles(directory=_static / "assets"), name="assets")


@app.get("/{path:path}", include_in_schema=False)
def frontend(path: str) -> FileResponse:
    index = _static / "index.html"
    if not index.exists():
        raise HTTPException(404, "Frontend not built")
    return FileResponse(index)
