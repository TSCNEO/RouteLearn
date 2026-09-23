"""Warm-up discovers only configured hosts through explicit public resolvers."""

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

import routelearn.warmup as module
from routelearn.db import Base, IPSource, Pattern, Service, WarmupRun


def test_warmup_keeps_resolver_provenance_and_does_not_download(monkeypatch) -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = Service(name="Video")
        db.add(service)
        db.flush()
        db.add(Pattern(service_id=service.id, value="*.googlevideo.com"))
        run = WarmupRun(service_id=service.id, status="running", result={})
        db.add(run)
        db.commit()
        service_id, run_id = service.id, run.id

    class Downloader:
        def __init__(self, options):
            assert options["skip_download"] is True

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def extract_info(self, url, *, download):
            assert url == "https://www.youtube.com/watch?v=example" and download is False
            return {
                "formats": [
                    {"url": "https://rr1.googlevideo.com/video"},
                    {"url": "https://unrelated.example/video"},
                ]
            }

    class Answer:
        def __init__(self, ip):
            self.ip = ip

        def to_text(self):
            return self.ip

    class AnswerSet(list):
        rrset = type("RRSet", (), {"ttl": 240})()

    class Resolver:
        def __init__(self, *, configure):
            assert configure is False
            self.nameservers = []

        def resolve(self, host, kind):
            assert host == "rr1.googlevideo.com"
            assert self.nameservers in (module.RESOLVERS["cloudflare"], module.RESOLVERS["google"])
            return AnswerSet([Answer("8.8.8.8")]) if kind == "A" else AnswerSet()

    monkeypatch.setattr(module, "engine", engine)
    monkeypatch.setattr(module.yt_dlp, "YoutubeDL", Downloader)
    monkeypatch.setattr(module.dns.resolver, "Resolver", Resolver)
    module.warmup(service_id, run_id, ["https://www.youtube.com/watch?v=example"], ["cloudflare", "google"])

    with Session(engine) as db:
        result = db.get(WarmupRun, run_id)
        assert result is not None and result.status == "complete", result.result["errors"] if result else None
        assert result.result["new_ips"] == 1
        assert result.result["already_known"] == 1
        assert {row.source for row in db.scalars(select(IPSource))} == {
            "warmup-cloudflare",
            "warmup-google",
        }
