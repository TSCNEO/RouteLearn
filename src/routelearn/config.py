"""Minimal environment bootstrap; functional settings live in SQLite."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path = Path(os.getenv("ROUTELEARN_DATA_DIR", "/data"))
    server_url: str = os.getenv("ROUTELEARN_SERVER", "")
    agent_token: str = os.getenv("ROUTELEARN_AGENT_TOKEN", "")
    interface: str = os.getenv("ROUTELEARN_INTERFACE", "auto")
    resolver_ips: str = os.getenv("ROUTELEARN_RESOLVER_IPS", "")
    dns_port: int = int(os.getenv("ROUTELEARN_DNS_PORT", "53"))

    @property
    def database_url(self) -> str:
        return f"sqlite:///{self.data_dir / 'routelearn.db'}"


settings = Settings()
