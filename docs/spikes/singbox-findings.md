# U1 — sing-box capability spike (findings)

Date: 2026-07-13 · Engine: **sing-box v1.13.14** (windows-amd64, official release, CGO disabled,
tags include `with_gvisor,with_quic,with_clash_api,with_wireguard`).

Test proxy fixture: **`192.0.2.10:1080`**, SOCKS5, **no-auth** (confirmed), **UDP ASSOCIATE supported**.

## Verified here (no admin / no TUN required)

| # | Item | Verdict | Evidence |
|---|------|---------|----------|
| a | Config schema (polite) passes `sing-box check` | ✅ CONFIRMED | `check` exit 0 after fix below |
| b | Config schema (greedy, no `route_address`) passes `sing-box check` | ✅ CONFIRMED | `check` exit 0 |
| c | SOCKS5 proxy changes egress IP | ✅ CONFIRMED | direct `176.106.249.19` → via proxy `213.155.13.17` |
| d | sing-box `socks` outbound forwards to proxy (real traffic) | ✅ CONFIRMED | loopback `mixed`→`proxy`, egress `213.155.13.17` (== proxy) |
| e | SOCKS5 **UDP ASSOCIATE** on the proxy | ✅ CONFIRMED | protocol probe REP=0x00, relay returned |
| f | `sing-box check` / `format` are usable pre-launch gates | ✅ CONFIRMED | both run standalone, no admin |

## Schema finding (important, 1.12+)

`sing-box check` **fails fatally** without `route.default_domain_resolver` (deprecated-missing since
1.12, removed in 1.14). **Resolution:** every generated config MUST set
`route.default_domain_resolver` (object form used: `{ "server": "<dns-server-tag>" }`). This is now
baked into both reference configs and is a hard requirement for the U5 generator.

Other confirmed current keys (1.12+ schema):
- DNS fakeip = a **server object** `{ "type": "fakeip", "inet4_range": "...", "inet6_range": "..." }`
  (NOT the legacy `dns.fakeip { enabled: true }`).
- System resolver = DNS server `{ "type": "local" }`.
- Per-process DNS routing = DNS rule `{ "process_name": [...], "action": "route", "server": "<fakeip-tag>" }`.
- Route rule actions = `{ "action": "route", "outbound": "..." }`, plus `{ "action": "sniff" }` and
  `{ "protocol": "dns", "action": "hijack-dns" }`.
- Polite capture = TUN `route_address: ["198.18.0.0/15","fc00::/18"]`; greedy = omit it. `strict_route: false`.
- Anti-loop = route rule `{ "ip_cidr": ["<proxy-ip>/32"], "action": "route", "outbound": "direct" }`.

Reference configs: `docs/spikes/reference-configs/polite-allowlist.json`, `greedy-allowlist.json`.

## Deferred to owner-run live verification (needs admin + real Win10/11 TUN)

- **AE1/AE2** — live `process_name`/`process_path` attribution with `stack: system` (KTD2; gVisor
  regression #2823 not applicable since we pin `system`). Confirm a listed process egresses via proxy
  and a non-listed one stays direct.
- **AE3** — kill-switch: stop engine, confirm proxied app drops (fake-ip unreachable) while direct
  app / other traffic is unaffected.
- **AE4** — network switch (Wi-Fi↔Ethernet) self-heal.
- **AE5** — polite `route_address` coexistence with a running WireGuard VPN (default route untouched).
- **IP-literal gap** — confirm a proxied app connecting to a raw IP bypasses in polite mode and is
  captured in greedy mode (validates R6/R21 framing).

## Conclusion

Datapath design is **validated at the schema + outbound + proxy-capability level**; the only fix
required vs. the plan's assumptions was the mandatory `default_domain_resolver`. Version pin
**v1.13.14** stands. No blockers to proceeding with U2+; live TUN acceptance is owner-run per the
plan's Delivery / Rollout Notes.
