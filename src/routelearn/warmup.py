"""Optional metadata-only YouTube warm-up with explicit DNS resolution."""

from __future__ import annotations

import random
import re
import uuid
from typing import Any
from urllib.parse import parse_qs, urlparse

import dns.resolver
import yt_dlp
from sqlalchemy import select

from .db import LearnedIP, Pattern, Service, WarmupRun, engine
from .learning import Observation, matches, public_ip, record_observation

RESOLVERS = {"cloudflare": ["1.1.1.1", "1.0.0.1"], "google": ["8.8.8.8", "8.8.4.4"]}
SEARCH_TOPICS = (
    "science documentary",
    "nature wildlife",
    "technology review",
    "cooking recipe",
    "travel guide",
    "music performance",
    "art tutorial",
    "history documentary",
    "sports highlights",
    "space exploration",
    "architecture tour",
    "gaming review",
)
VIDEO_ID = re.compile(r"[A-Za-z0-9_-]{11}\Z")


def normalize_youtube_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.port:
        raise ValueError("Use an HTTPS YouTube video URL")
    if parsed.hostname == "youtu.be":
        video_id = parsed.path.strip("/")
    elif parsed.hostname in {"youtube.com", "www.youtube.com", "m.youtube.com"}:
        if parsed.path == "/watch":
            video_id = parse_qs(parsed.query).get("v", [""])[0]
        elif parsed.path.startswith(("/shorts/", "/live/")):
            video_id = parsed.path.split("/")[2]
        else:
            video_id = ""
    else:
        video_id = ""
    if not VIDEO_ID.fullmatch(video_id):
        raise ValueError("Use a valid YouTube video URL")
    return f"https://www.youtube.com/watch?v={video_id}"


def random_youtube_urls(count: int) -> list[str]:
    candidates: set[str] = set()
    topics = random.sample(SEARCH_TOPICS, 6)
    with yt_dlp.YoutubeDL(
        {
            "quiet": True,
            "no_warnings": True,
            "extract_flat": True,
            "skip_download": True,
            "ignoreerrors": True,
            "socket_timeout": 10,
        }
    ) as downloader:
        for topic in topics:
            try:
                result = downloader.extract_info(f"ytsearch8:{topic}", download=False)
            except Exception:
                continue
            if isinstance(result, dict):
                for entry in result.get("entries") or []:
                    if isinstance(entry, dict) and VIDEO_ID.fullmatch(str(entry.get("id", ""))):
                        candidates.add(str(entry["id"]))
    if len(candidates) < count:
        raise ValueError(f"YouTube search returned only {len(candidates)} videos; try manual URLs")
    chosen = random.sample(sorted(candidates), count)
    return [f"https://www.youtube.com/watch?v={video_id}" for video_id in chosen]


def warmup(
    service_id: int, run_id: int, urls: list[str], resolvers: list[str], random_count: int = 0
) -> None:
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
            selected_urls = random_youtube_urls(random_count) if random_count else urls
            stats["selected_urls"] = selected_urls
            stats["requested_videos"] = len(selected_urls)
            run.result = dict(stats)
            db.commit()
            with yt_dlp.YoutubeDL(
                {
                    "skip_download": True,
                    "quiet": True,
                    "no_warnings": True,
                    "noplaylist": True,
                    "ignoreerrors": False,
                    "socket_timeout": 10,
                }
            ) as downloader:
                for url in selected_urls:
                    try:
                        info = downloader.extract_info(url, download=False)
                        if not isinstance(info, dict):
                            stats["errors"].append(f"{url}: no metadata returned")
                            continue
                        stats["videos"] = int(stats["videos"]) + 1
                        for item in [info, *info.get("formats", [])]:
                            if isinstance(item, dict) and isinstance(item.get("url"), str):
                                host = urlparse(item["url"]).hostname
                                if host and any(matches(host, pattern) for pattern in patterns):
                                    hosts.add(host)
                    except Exception as exc:
                        stats["errors"].append(f"{url}: {type(exc).__name__}")
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
            run.status = "complete" if stats["videos"] else "error"
        except Exception as exc:
            run.status = "error"
            stats["errors"].append(type(exc).__name__)
        run.result = stats
        db.commit()
