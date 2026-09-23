# RouteLearn

RouteLearn learns service IP addresses from DNS responses sent to real clients and maintains optional router policy routes. It is **not a DNS server**, does not intercept DNS, and never sits in the request path.

```text
Clients → existing DNS / optional AdGuard Home
                         │ passive response observation
                         ▼
                    Docker agent → Docker server → UniFi policy route → VPN
```

The server and every agent run in Docker. The agent requires a **Linux Docker host** with access to the resolver's LAN interface. The resolver itself can be a host process or another container. If clients only use a router's built-in DNS, another host cannot observe their unicast responses: the optional AdGuard deployment provides a local DNS alternative. RouteLearn never changes DHCP; point clients at AdGuard only if you choose to use it.

## Start the server

```sh
docker compose -f compose.yml up -d --build
docker compose -f compose.yml logs routelearn
```

Open `http://SERVER_HOST:8080`. The one-time admin setup code appears in the server logs. Set a username and a password of at least 12 characters. The first-run wizard does not require a router. Add a service (or use the editable YouTube template), then register an agent.

The server stores SQLite, encryption key, and setup material in the persistent Docker volume `routelearn_routelearn_data`. **Back up this entire volume**; the encryption key is needed to recover the UniFi API key. No functional settings or secrets belong in Compose. `ROUTELEARN_BOOTSTRAP_DNS_1` and `_2` change the server container's DNS for metadata requests; the warm-up UI separately selects explicit resolvers for discovered hosts. The defaults are Cloudflare and Google, not the host's DNS.

## Observe an existing DNS server

On each **Linux DNS host**, clone the repository, copy the one-time token from the Agents page, then run:

```sh
ROUTELEARN_SERVER=http://SERVER_HOST:8080 \
ROUTELEARN_AGENT_TOKEN=TOKEN_FROM_UI \
ROUTELEARN_INTERFACE=auto \
docker compose -f compose.agent.yml up -d --build
```

In practice store these values in an ignored `.env` file with mode `0600` instead of shell history. The generated token is shown only once. `ROUTELEARN_INTERFACE` may be `eth0`, `eno1`, a bond, or `auto`. The agent defaults to the interface's local addresses and DNS port 53; adjust the per-agent resolver IPs and port in the UI if necessary. The agent only sends observations matching configured service patterns. Its bounded SQLite queue in the persistent `agent_data` Docker volume survives server outages; a full queue drops oldest events.

The agent uses host networking and `CAP_NET_RAW`, with a read-only root filesystem. Upstream DoH/DoQ is fine when the resolver answers clients via classic DNS. Client DoH/DoT traffic is encrypted and cannot be parsed by this sensor. Responses split across TCP packets are counted and skipped. Run diagnostics in the container:

```sh
docker compose -f compose.agent.yml run --rm routelearn-agent doctor agent
```

While `doctor agent` watches for 15 seconds, query that resolver from a client. It reports whether a local DNS response was seen and the client IP observed on the wire. Use `--observe-seconds 60` for a longer window.

For a Docker bridge resolver, select the **host LAN egress interface** and verify the agent's matching counter rises after a client query. NAT and virtualization vary; confirm that the UI shows the true client IP before enabling routes. On Docker Desktop, passive LAN capture may not work because the agent is inside a VM; use a Linux DNS host.

## Optional AdGuard Home

Run AdGuard alongside the server (only if port 53 is available):

```sh
ROUTELEARN_SERVER=http://SERVER_HOST:8080 ROUTELEARN_AGENT_TOKEN=TOKEN_FROM_UI \
docker compose -f compose.yml -f compose.adguard.yml up -d --build
```

Or on a secondary Linux DNS host:

```sh
ROUTELEARN_SERVER=http://SERVER_HOST:8080 ROUTELEARN_AGENT_TOKEN=SECOND_TOKEN \
docker compose -f compose.dns-node.yml up -d --build
```

AdGuard's setup UI is on port 3000 by default; its later web UI is exposed on port 8081. Set `ADGUARD_BIND_IP` to bind DNS to a specific host IP. These optional Compose files run the official AdGuard Home image in bridge mode and expose only DNS and web setup ports, not AdGuard DHCP. They do not alter existing resolvers or client DNS settings.

## Router setup

RouteLearn works indefinitely in learning mode. For routing, create an existing VPN Client in UniFi, then add a UniFi router using a local API key in the UI. Test discovery, select its VPN client, create a policy, preview the diff, and switch to active. Credentials are encrypted at rest; TLS verification is on by default. For a self-signed gateway, you can disable verification in the UI after deciding to trust that network path.

Managed routes are named `RouteLearn · SERVICE`. Empty active sets do not create routes; when a managed route becomes empty it is disabled. RouteLearn refuses more than 16,384 destinations and holds automatic updates that would remove over 80% of a list with at least 20 entries. Manual Sync now can apply that diff. Router outages leave the existing route untouched and do not stop learning. UniFi Network versions have different route API shapes; unsupported shapes fail closed. A real gateway smoke test is in [docs/unifi-smoke-test.md](docs/unifi-smoke-test.md).

## What to expect

- The first connection to a newly resolved IP may use the ordinary WAN. RouteLearn learns passively, then later connections can use the route.
- Routing by exact IP can affect another service sharing that IP. Shared IPs are flagged when observed under multiple configured services.
- DNS TTL is retained as evidence but does not control route expiry. Defaults: live 7 days, warm-up 72 hours, history 90 days.
- IPv6 observations are retained and shown separately. Confirm that the chosen UniFi VPN client actually routes IPv6; RouteLearn does not disable IPv6 to hide a mismatch.
- If the server or agent stops, existing DNS and Internet continue working.
- The warm-up uses yt-dlp metadata only, without cookies or media download. It accepts HTTPS YouTube URLs and resolves matching hosts explicitly through the chosen Cloudflare and/or Google resolvers. Direct outbound DNS must be permitted.

## Development

```sh
python3.12 -m venv .venv
.venv/bin/pip install -e '.[dev]'
cd frontend && npm ci && npm run build && cd ..
.venv/bin/pytest
.venv/bin/ruff check src tests
.venv/bin/ruff format --check src tests
.venv/bin/mypy src
docker build -t routelearn:local .
```

To verify the packaged server and SQLite persistence in an isolated Compose project:

```sh
docker build -t routelearn:ci .
python3 tests/docker_server.py
```

On Linux, `tests/docker_capture.py` and `tests/docker_adguard.py` additionally verify passive capture from a host resolver, a bridged resolver, and both optional AdGuard stacks. These tests create and remove only their own Docker projects and volumes.

The local API is under `/api/v1`, with OpenAPI at `/docs`. Health endpoints are `/healthz` and `/readyz`. Docker images are published only for tagged releases.
