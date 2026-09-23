"""Container entrypoint and diagnostics."""

from __future__ import annotations

import socket
from pathlib import Path

import psutil
import typer
import uvicorn
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, select

from .agent import AgentRuntime, interface_name, local_addresses
from .config import settings
from .db import Router, SessionLocal, engine
from .routing import RouterError, UniFiBackend

app = typer.Typer(no_args_is_help=True)


def _alembic() -> Config:
    return Config(str(Path.cwd() / "alembic.ini"))


@app.command()
def migrate() -> None:
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    command.upgrade(_alembic(), "head")


@app.command()
def server() -> None:
    uvicorn.run(
        "routelearn.api:app",
        host="0.0.0.0",
        port=8080,
        workers=1,
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",
    )


@app.command()
def agent() -> None:
    AgentRuntime().run()


@app.command()
def doctor(role: str = typer.Argument("server")) -> None:
    if role == "agent":
        name = interface_name(settings.interface)
        if name not in psutil.net_if_addrs():
            typer.echo(f"Capture interface {name} does not exist", err=True)
            raise typer.Exit(1)
        typer.echo(f"Interface: {name}")
        typer.echo(f"Local addresses: {', '.join(sorted(local_addresses(name)))}")
        try:
            capture_socket = socket.socket(getattr(socket, "AF_PACKET", 17), socket.SOCK_RAW, socket.htons(3))
            capture_socket.close()
            typer.echo("NET_RAW: available")
        except (PermissionError, OSError) as exc:
            typer.echo(f"Packet capture unavailable: {type(exc).__name__}", err=True)
            raise typer.Exit(1) from exc
        if not settings.agent_token or not settings.server_url:
            typer.echo("Agent bootstrap is incomplete", err=True)
            raise typer.Exit(1)
        try:
            AgentRuntime().refresh()
            typer.echo("Server and agent token: valid")
        except Exception as exc:
            typer.echo(f"Server or agent token failed: {type(exc).__name__}", err=True)
            raise typer.Exit(1) from exc
    else:
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        writable_probe = settings.data_dir / ".writable"
        writable_probe.write_text("ok")
        writable_probe.unlink()
        typer.echo("Database directory writable")
        try:
            socket.gethostbyname("example.com")
            typer.echo("Bootstrap DNS operational")
        except OSError:
            typer.echo("Bootstrap DNS unavailable")
        if inspect(engine).has_table("router_connections"):
            with SessionLocal() as db:
                for router in db.scalars(select(Router)):
                    try:
                        UniFiBackend(router).test_connection()
                        typer.echo(f"Router {router.name}: reachable")
                    except RouterError as exc:
                        typer.echo(f"Router {router.name}: {exc}")
