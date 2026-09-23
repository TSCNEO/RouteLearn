from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from routelearn.db import Base, LearnedIP, RoutePolicy, Router, Service, utcnow
from routelearn.routing import RouteSnapshot, reconcile, route_diff


def test_diff_exact_ips() -> None:
    assert route_diff(["8.8.8.8", "1.1.1.1"], ["8.8.8.8", "2606:4700:4700::1111"]) == {
        "added": ["2606:4700:4700::1111"],
        "removed": ["1.1.1.1"],
    }


def test_mass_removal_is_held_before_router_mutation(monkeypatch) -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        service = Service(name="Video")
        router = Router(name="Router", host="router.example.test", api_key_encrypted="unused")
        db.add_all([service, router])
        db.flush()
        policy = RoutePolicy(
            service_id=service.id,
            router_id=router.id,
            name="RouteLearn · Video",
            vpn_network_id="vpn",
            vpn_name="VPN",
            state="active",
        )
        db.add(policy)
        db.add(LearnedIP(service_id=service.id, ip="8.8.8.8", family=4, last_live_seen=utcnow()))
        db.commit()

        class FakeBackend:
            mutations = 0

            def __init__(self, router):
                pass

            def get_managed_route(self, name):
                ips = [f"8.8.8.{x}" for x in range(1, 31)]
                return RouteSnapshot("id", True, ips, {}, "/routes")

            def set_destinations(self, *args):
                FakeBackend.mutations += 1

        monkeypatch.setattr("routelearn.routing.UniFiBackend", FakeBackend)
        run = reconcile(db, policy)
        assert run.status == "safety-hold"
        assert FakeBackend.mutations == 0
