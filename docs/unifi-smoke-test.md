# UniFi real-gateway smoke test

Use a noncritical service and a VPN Client already configured in UniFi. Run these steps after a UniFi Network upgrade as well.

1. Save the local API key in RouteLearn, retain TLS verification when possible, and run **Test & discover**. Confirm the site and expected VPN Client are listed.
2. Keep the policy in **learning**. Generate DNS traffic and verify exact IPs, domains, clients, and agent provenance in the service view.
3. Preview the route diff. Check that no unrelated existing route is selected and that IPv4/IPv6 counts match the gateway's capabilities.
4. Switch to **active**. Click **Sync now**. In UniFi, confirm a single managed route named `RouteLearn · SERVICE`, the VPN client, source clients, and exact IP destinations.
5. Repeat Sync now without DNS changes. It should report no change. Add one new DNS observation and verify only the expected destination is added.
6. Pause the policy. Confirm RouteLearn disables its managed route without deleting it. Restore active and confirm it re-enables.
7. Stop the RouteLearn server and agents. DNS and Internet should continue working. Restart and confirm reconciliation recovers.

If discovery or a route shape differs, capture redacted JSON from the local UniFi API and open an issue. Never include an API key, token, client name, or household IP in an issue.
