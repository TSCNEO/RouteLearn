"""Router backend contract, UniFi adapter, and safe reconciliation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from .db import RoutePolicy, Router, Service, SyncRun, utcnow
from .learning import active_ips
from .security import decrypt


class RouterError(Exception):
    pass


@dataclass
class RouteSnapshot:
    id: str
    enabled: bool
    destinations: list[str]
    raw: dict[str, Any]
    endpoint: str


class RouterBackend(Protocol):
    def test_connection(self) -> dict[str, Any]: ...
    def discover_sites(self) -> list[dict[str, Any]]: ...
    def discover_vpn_clients(self) -> list[dict[str, Any]]: ...
    def discover_clients(self) -> list[dict[str, Any]]: ...
    def get_managed_route(self, name: str) -> RouteSnapshot | None: ...
    def ensure_managed_route(
        self, name: str, vpn_network_id: str, clients: list[str], ips: list[str]
    ) -> RouteSnapshot: ...
    def set_destinations(self, route: RouteSnapshot, ips: list[str]) -> None: ...
    def set_enabled(self, route: RouteSnapshot, enabled: bool) -> None: ...


def _records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("data", "items", "results"):
            if isinstance(payload.get(key), list):
                return _records(payload[key])
    return []


def _ip_entries(ips: list[str]) -> list[dict[str, Any]]:
    return [
        {"ip_or_subnet": ip, "ip_version": "v6" if ":" in ip else "v4", "ports": [], "port_ranges": []}
        for ip in ips
    ]


def _destinations(route: dict[str, Any]) -> list[str]:
    entries = route.get("ip_addresses")
    if entries is None:
        entries = route.get("destinations")
    if entries is None and isinstance(route.get("destination"), dict):
        entries = route["destination"].get("ip_addresses", route["destination"].get("ips"))
    if not isinstance(entries, list):
        raise RouterError("Unsupported UniFi route destination shape; no changes applied")
    values = []
    for item in entries:
        value = (
            item
            if isinstance(item, str)
            else item.get("ip_or_subnet", item.get("ip"))
            if isinstance(item, dict)
            else None
        )
        if not isinstance(value, str):
            raise RouterError("Unsupported UniFi destination entry; no changes applied")
        values.append(value)
    return sorted(set(values))


class UniFiBackend:
    """Local API-key adapter, following StopLiga's v2/legacy route discovery strategy."""

    def __init__(self, router: Router):
        parsed = urlparse(router.host if "://" in router.host else f"https://{router.host}")
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise RouterError("UniFi host must be an HTTPS hostname or IP")
        self.router = router
        self.base = f"https://{parsed.netloc}".rstrip("/")
        self.client = httpx.Client(
            base_url=self.base,
            verify=router.verify_tls,
            timeout=10,
            follow_redirects=False,
            headers={"X-API-Key": decrypt(router.api_key_encrypted), "Accept": "application/json"},
        )
        self.prefix: str | None = None
        self.route_endpoint: str | None = None

    def _request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        try:
            response = self.client.request(method, path, json=payload)
            response.raise_for_status()
            return response.json() if response.content else {}
        except (httpx.HTTPError, ValueError) as exc:
            raise RouterError(f"UniFi {method} {path} failed: {type(exc).__name__}") from exc

    def _network_prefix(self) -> str:
        if self.prefix is None:
            for prefix in ("/proxy/network", ""):
                try:
                    try:
                        self._request("GET", f"{prefix}/api/self/sites")
                    except RouterError:
                        self._request("GET", f"{prefix}/integration/v1/sites")
                    self.prefix = prefix
                    break
                except RouterError:
                    continue
            if self.prefix is None:
                raise RouterError("Cannot reach UniFi Network API with this key")
        return self.prefix

    def discover_sites(self) -> list[dict[str, Any]]:
        prefix = self._network_prefix()
        try:
            return _records(self._request("GET", f"{prefix}/api/self/sites"))
        except RouterError:
            return _records(self._request("GET", f"{prefix}/integration/v1/sites"))

    def test_connection(self) -> dict[str, Any]:
        sites = self.discover_sites()
        return {"connected": True, "sites": sites}

    def discover_vpn_clients(self) -> list[dict[str, Any]]:
        prefix = self._network_prefix()
        records = _records(self._request("GET", f"{prefix}/api/s/{self.router.site}/rest/networkconf"))
        return [x for x in records if x.get("purpose") == "vpn-client"]

    def discover_clients(self) -> list[dict[str, Any]]:
        prefix = self._network_prefix()
        return _records(self._request("GET", f"{prefix}/api/s/{self.router.site}/stat/sta"))

    def _route_collections(self) -> list[tuple[str, list[dict[str, Any]]]]:
        prefix = self._network_prefix()
        candidates = (
            f"{prefix}/v2/api/site/{self.router.site}/trafficroutes",
            f"{prefix}/api/s/{self.router.site}/rest/trafficroute",
        )
        found = []
        for path in candidates:
            try:
                found.append((path, _records(self._request("GET", path))))
            except RouterError:
                continue
        if not found:
            raise RouterError("No supported UniFi traffic route endpoint is available")
        return found

    def _route_collection(self) -> tuple[str, list[dict[str, Any]]]:
        if self.route_endpoint:
            return self.route_endpoint, _records(self._request("GET", self.route_endpoint))
        return self._route_collections()[0]

    def get_managed_route(self, name: str) -> RouteSnapshot | None:
        collections = [self._route_collection()] if self.route_endpoint else self._route_collections()
        found = [
            (endpoint, r)
            for endpoint, routes in collections
            for r in routes
            if r.get("description", r.get("name")) == name
        ]
        ids = {str(r.get("_id", r.get("id"))) for _, r in found}
        if len(ids) > 1:
            raise RouterError("Duplicate managed route names; no changes applied")
        if not found:
            return None
        endpoint, route = found[0]
        self.route_endpoint = endpoint
        route_id = route.get("_id", route.get("id"))
        if not isinstance(route_id, str):
            raise RouterError("Managed route has no ID")
        return RouteSnapshot(route_id, bool(route.get("enabled")), _destinations(route), route, endpoint)

    def ensure_managed_route(
        self, name: str, vpn_network_id: str, clients: list[str], ips: list[str]
    ) -> RouteSnapshot:
        existing = self.get_managed_route(name)
        if existing:
            return existing
        if not ips:
            raise RouterError("Cannot create an empty managed route")
        endpoint, _ = self._route_collection()
        payload = {
            "description": name,
            "domains": [],
            "enabled": True,
            "ip_addresses": _ip_entries(ips),
            "ip_ranges": [],
            "kill_switch_enabled": False,
            "matching_target": "IP",
            "network_id": vpn_network_id,
            "next_hop": "",
            "regions": [],
            "target_devices": [{"type": "CLIENT", "client_mac": mac} for mac in clients]
            if clients
            else [{"type": "ALL_CLIENTS"}],
        }
        self._request("POST", endpoint, payload)
        created = self.get_managed_route(name)
        if created is None:
            raise RouterError("Created route could not be verified")
        return created

    def _update(self, route: RouteSnapshot, payload: dict[str, Any]) -> None:
        allowed = {
            "description",
            "enabled",
            "ip_addresses",
            "destinations",
            "destination",
            "network_id",
            "target_devices",
            "matching_target",
            "domains",
            "ip_ranges",
            "kill_switch_enabled",
            "next_hop",
            "regions",
        }
        body = {key: value for key, value in route.raw.items() if key in allowed}
        body.update(payload)
        self._request("PUT", f"{route.endpoint}/{route.id}", body)

    def set_destinations(self, route: RouteSnapshot, ips: list[str]) -> None:
        if "ip_addresses" in route.raw:
            self._update(route, {"ip_addresses": _ip_entries(ips)})
        elif "destinations" in route.raw:
            self._update(route, {"destinations": ips})
        elif isinstance(route.raw.get("destination"), dict) and "ip_addresses" in route.raw["destination"]:
            self._update(
                route, {"destination": {**route.raw["destination"], "ip_addresses": _ip_entries(ips)}}
            )
        else:
            raise RouterError("This UniFi route shape cannot be updated safely")

    def set_enabled(self, route: RouteSnapshot, enabled: bool) -> None:
        self._update(route, {"enabled": enabled})


def route_diff(current: list[str], desired: list[str]) -> dict[str, list[str]]:
    return {"added": sorted(set(desired) - set(current)), "removed": sorted(set(current) - set(desired))}


def policy_preview(db: Session, policy: RoutePolicy) -> dict[str, Any]:
    service = db.get(Service, policy.service_id)
    router = db.get(Router, policy.router_id)
    if service is None or router is None:
        raise RouterError("Policy dependencies missing")
    desired = active_ips(db, service) if policy.state == "active" else []
    backend = UniFiBackend(router)
    current = backend.get_managed_route(policy.name)
    current_ips = current.destinations if current else []
    diff = route_diff(current_ips, desired)
    return {
        "desired": desired,
        "current": current_ips,
        "added": diff["added"],
        "removed": diff["removed"],
        "enabled": bool(current and current.enabled),
        "ipv6_learned": sum(":" in ip for ip in desired),
        "ipv6_routed": sum(":" in ip for ip in current_ips) if current and current.enabled else 0,
    }


def reconcile(db: Session, policy: RoutePolicy, *, manual: bool = False) -> SyncRun:
    run = SyncRun(policy_id=policy.id, status="pending")
    db.add(run)
    db.commit()
    try:
        service = db.get(Service, policy.service_id)
        router = db.get(Router, policy.router_id)
        if service is None or router is None:
            raise RouterError("Policy dependencies missing")
        desired = active_ips(db, service) if policy.state == "active" else []
        if len(desired) > 16384:
            raise RouterError("Safety hold: destination limit exceeded")
        backend = UniFiBackend(router)
        current = backend.get_managed_route(policy.name)
        previous = current.destinations if current else []
        diff = route_diff(previous, desired)
        run.desired_count, run.current_count = len(desired), len(previous)
        run.added, run.removed = len(diff["added"]), len(diff["removed"])
        if len(previous) >= 20 and run.removed > len(previous) * 0.8 and not manual:
            raise RouterError("Safety hold: more than 80% of destinations would be removed")
        if not current and not desired:
            run.status = "no-op"
        elif not current:
            created = backend.ensure_managed_route(
                policy.name, policy.vpn_network_id, policy.source_clients, desired
            )
            if sorted(created.destinations) != sorted(desired) or not created.enabled:
                raise RouterError("Created route did not retain the requested destinations")
            run.status = "applied"
        else:
            if not desired:
                if current.enabled:
                    backend.set_enabled(current, False)
                    verified = backend.get_managed_route(policy.name)
                    if verified is None or verified.enabled:
                        raise RouterError("UniFi did not disable the managed route")
                    run.status = "applied"
                else:
                    run.status = "no-op"
            elif diff["added"] or diff["removed"] or not current.enabled:
                mutated = False
                try:
                    if diff["added"] or diff["removed"]:
                        backend.set_destinations(current, desired)
                        mutated = True
                    refreshed = backend.get_managed_route(policy.name)
                    if refreshed is None:
                        raise RouterError("Managed route disappeared")
                    if not refreshed.enabled:
                        backend.set_enabled(refreshed, True)
                        mutated = True
                    verified = backend.get_managed_route(policy.name)
                    if (
                        verified is None
                        or sorted(verified.destinations) != sorted(desired)
                        or not verified.enabled
                    ):
                        raise RouterError("UniFi did not retain the requested destinations")
                except RouterError:
                    if mutated:
                        try:
                            backend.set_destinations(current, previous)
                            backend.set_enabled(current, current.enabled)
                        except RouterError:
                            pass
                    raise
                run.status = "applied"
            else:
                run.status = "no-op"
        if run.status == "applied":
            policy.last_synced_at = utcnow()
    except RouterError as exc:
        run.status = "safety-hold" if str(exc).startswith("Safety hold") else "error"
        run.error = str(exc)
    except Exception as exc:
        run.status = "error"
        run.error = type(exc).__name__
    db.commit()
    return run
