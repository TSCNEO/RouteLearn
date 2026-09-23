"""Optional metadata-only YouTube warm-up with explicit DNS resolution."""

from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import urlparse

import dns.resolver
import yt_dlp
from sqlalchemy import select

from .db import LearnedIP, Pattern, Service, WarmupRun, engine
from .learning import Observation, matches, public_ip, record_observation

RESOLVERS = {"cloudflare": ["1.1.1.1", "1.0.0.1"], "google": ["8.8.8.8", "8.8.4.4"]}


def warmup(service_id: int, run_id: int, urls: list[str], resolvers: list[str]) -> None:
    from sqlalchemy.orm import Session as DBSession

    with DBSession(engine) as db:
        run = db.get(WarmupRun, run_id)
        service = db.get(Service, service_id)
        if run is None or service is None:
            return
        patterns = [p.value for p in db.query(Pattern).filter(Pattern.service_id == service_id)]
        stats: dict[str, Any] = {
            "videos": 0,
            "hostnames": 0,
            "new_ips": 0,
            "already_known": 0,
            "ipv4_discovered": 0,
            "ipv6_discovered": 0,
            "errors": [],
        }
        hosts: set[str] = set()
        ipv4: set[str] = set()
        ipv6: set[str] = set()
        try:
            with yt_dlp.YoutubeDL(
                {
                    "skip_download": True,
                    "quiet": True,
                    "no_warnings": True,
                    "noplaylist": True,
                    "ignoreerrors": True,
                    "socket_timeout": 10,
                }
            ) as downloader:
                for url in urls[:20]:
                    parsed = urlparse(url)
                    if parsed.scheme != "https" or parsed.hostname not in {
                        "youtube.com",
                        "www.youtube.com",
                        "m.youtube.com",
                        "youtu.be",
                    }:
                        stats["errors"].append("Only HTTPS YouTube URLs are supported")
                        continue
                    try:
                        info = downloader.extract_info(url, download=False)
                        if not isinstance(info, dict):
                            continue
                        stats["videos"] = int(stats["videos"]) + 1
                        for item in [info, *info.get("formats", [])]:
                            if isinstance(item, dict) and isinstance(item.get("url"), str):
                                host = urlparse(item["url"]).hostname
                                if host and any(matches(host, pattern) for pattern in patterns):
                                    hosts.add(host)
                    except Exception as exc:
                        stats["errors"].append(type(exc).__name__)
                    run.result = dict(stats)
                    db.commit()
            stats["hostnames"] = len(hosts)
            for name in resolvers:
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = RESOLVERS[name]
                resolver.timeout = 3
                resolver.lifetime = 5
                for host in hosts:
                    for kind in ("A", "AAAA"):
                        try:
                            answers = resolver.resolve(host, kind)
                            for answer in answers:
                                ip = answer.to_text()
                                if not public_ip(ip):
                                    continue
                                known = (
                                    db.scalar(
                                        select(LearnedIP.id).where(
                                            LearnedIP.service_id == service_id, LearnedIP.ip == ip
                                        )
                                    )
                                    is not None
                                )
                                record_observation(
                                    db,
                                    Observation(
                                        event_id=uuid.uuid4().hex,
                                        service_id=service_id,
                                        domain=host,
                                        ip=ip,
                                        ttl=answers.rrset.ttl if answers.rrset else 0,
                                        source=f"warmup-{name}",
                                    ),
                                )
                                stats["already_known" if known else "new_ips"] += 1
                                (ipv6 if ":" in ip else ipv4).add(ip)
                        except dns.exception.DNSException as exc:
                            stats["errors"].append(f"{host}: {type(exc).__name__}")
                    stats["ipv4_discovered"] = len(ipv4)
                    stats["ipv6_discovered"] = len(ipv6)
                    run.result = dict(stats)
                    db.commit()
            db.commit()
            run.status = "complete"
        except Exception as exc:
            run.status = "error"
            stats["errors"].append(type(exc).__name__)
        run.result = stats
        db.commit()
