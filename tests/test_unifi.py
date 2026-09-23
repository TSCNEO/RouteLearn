import httpx
import pytest

from routelearn.db import Router
from routelearn.routing import RouterError, UniFiBackend
from routelearn.security import encrypt


def test_unifi_discovery_and_exact_destination_update() -> None:
    writes = []

    def respond(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/api/self/sites"):
            return httpx.Response(200, json={"data": [{"name": "default"}]})
        if path.endswith("/rest/networkconf"):
            return httpx.Response(
                200, json={"data": [{"_id": "vpn-1", "name": "Exit", "purpose": "vpn-client"}]}
            )
        if path.endswith("/trafficroutes"):
            return httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "_id": "route-1",
                            "description": "RouteLearn · Video",
                            "enabled": True,
                            "ip_addresses": [{"ip_or_subnet": "8.8.8.8", "ip_version": "v4"}],
                        }
                    ]
                },
            )
        if path.endswith("/rest/trafficroute"):
            return httpx.Response(404)
        if path.endswith("/trafficroutes/route-1") and request.method == "PUT":
            writes.append(request.content)
            return httpx.Response(200, json={"data": {}})
        return httpx.Response(404)

    router = Router(
        name="test", host="controller.example.test", site="default", api_key_encrypted=encrypt("fake-key")
    )
    backend = UniFiBackend(router)
    backend.client.close()
    backend.client = httpx.Client(
        base_url="https://controller.example.test", transport=httpx.MockTransport(respond)
    )
    assert backend.discover_vpn_clients()[0]["_id"] == "vpn-1"
    route = backend.get_managed_route("RouteLearn · Video")
    assert route is not None and route.destinations == ["8.8.8.8"]
    backend.set_destinations(route, ["8.8.8.8", "2606:4700:4700::1111"])
    assert len(writes) == 1
    assert b'"ip_or_subnet":"2606:4700:4700::1111"' in writes[0]
    backend.client.close()


def test_unsupported_destination_shape_never_writes() -> None:
    router = Router(name="test", host="controller.example.test", api_key_encrypted=encrypt("fake-key"))
    backend = UniFiBackend(router)
    backend.client.close()
    with pytest.raises(RouterError, match="cannot be updated safely"):
        from routelearn.routing import RouteSnapshot

        backend.set_destinations(RouteSnapshot("x", True, [], {"other": []}, "/routes"), ["8.8.8.8"])
