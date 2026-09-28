# Nullroute — project specification

**Status:** design, version 1.0, 2026-09-28. This is the implementation contract for the separate `Kayyo321/nullroute` repository. It specifies software that has **not** been implemented, tested, audited, or deployed. Do not describe it as providing proven anonymity.

## 1. Purpose and fixed decisions

Nullroute is a local daemon and an independently operated I2P exit service for public-web browsing from [Nullpath](https://github.com/Kayyo321/nullpath/tree/build/windows-native). Nullpath is a LibreWolf/Firefox-based, currently Windows-only browser. Its `build/windows-native` branch currently has three separate profiles: I2P sites, public web through a conventional I2P outproxy, and direct web. Nullroute will eventually **replace the direct-web profile's network path**, while leaving the I2P-sites and existing outproxy profiles available. Browser integration belongs in the separate Nullpath repository; this repository contains the daemon, exit service, protocol, test fixtures, and their documentation.

The chosen design uses an existing I2P router's tunnels and garlic-routing machinery through **SAM v3**. Nullroute does not implement a new router, cryptosystem, or mix network. The client accepts only a loopback HTTP proxy connection from Nullpath, opens an I2P streaming connection to a selected Nullroute exit Destination, and asks that exit to make the final TCP connection to the public website. An exit is a deliberately installed service with its own I2P Destination and clearnet connection. Ordinary I2P relay participants do **not** become exits.

```
Nullpath "Public web via Nullroute" profile
  -> 127.0.0.1:14500 HTTP proxy (nullroute client)
  -> 127.0.0.1:7656 SAM v3 (local I2P router; configurable)
  -> I2P client tunnels -> I2P exit tunnels
  -> Nullroute exit service -> exit-side DNS -> TCP 80/443 -> website
```

There is no usable exit network until an independent operator deploys an exit and the user explicitly configures its Destination. Running the client alone does not supply an exit. Running the exit on the same machine/network as the browser does not create an independent anonymity boundary. One exit does not provide Tor-like diversity, anonymity-set size, or censorship resistance. Multiple configured exits improve availability but do not by themselves justify a Tor-equivalence claim.

### Version 1 scope

| Area | Decision |
| --- | --- |
| Platform | Windows 10/11 x64 client and exit first; architecture must keep platform-specific IPC and packaging separate so Linux support can follow. |
| Language | Rust stable; one workspace with `nullroute-client`, `nullroute-exit`, `nullroute-protocol`, and `nullroute-testkit` crates. No unsafe Rust in protocol, proxy, or policy code. |
| Router | Reuse a user-managed or Nullpath-managed I2P router exposing SAM v3 on loopback. SAM is never opened to a LAN or public interface by Nullroute. Nullroute does not alter router configuration without an explicit setup action in Nullpath. |
| Transport | One SAM `STYLE=STREAM` session per running client; one persistent exit `STYLE=STREAM` session. One I2P stream per browser TCP connection. The router selects and maintains I2P tunnels. |
| Public-web protocol | HTTP/1.1 forward proxy for `http://` and `CONNECT` for `https://`; TCP ports 80 and 443 only. No UDP, QUIC/HTTP3, generic SOCKS, mail, arbitrary ports, or remote DNS from the client. |
| Exit discovery | Manual, explicit list of pinned `.b32.i2p` exit Destinations. No automatic directory, fallback to conventional outproxy, or clearnet bootstrap URL in v1. |
| Default state | Disabled at launch. Proxy listener starts only after explicit connect; if a saved list has no usable exit, requests fail. Never silently use a direct socket or system proxy. |
| Browser split | Nullpath owns profile separation and its existing channel filter/request blocker. Nullroute owns proxy-to-I2P transport and exit policy. Neither component's own tests substitute for end-to-end leak tests. |

## 2. Threat model and claims

**Intended protection:** a website and its network see the selected exit's public IP instead of the user's IP; an ordinary local access provider sees I2P router traffic rather than each website connection. The exit is an explicit trust boundary. Browser fingerprint, account login, cookies, uploaded data, URL contents visible to the website, malware, traffic correlation, compromised client/router/exit, and a global observer are outside this guarantee. The exit knows the requested host and port; for plaintext HTTP it can read and alter the full exchange. For HTTPS it can see metadata such as target host, timing, volume, and potentially TLS SNI, but must not terminate or forge browser TLS. A compromised exit can block, delay, or route traffic maliciously; browser certificate validation is essential.

I2P routers must contact peers and possibly reseed services over ordinary network connections. That is router traffic, not a website request escaping Nullroute. A user-operated exit or colluding exit and network observer may correlate the user. Exit operators face abuse complaints and legal/operational risk; exit installation must be opt-in and separately documented. Product copy must say **"public web through I2P and a selected Nullroute exit"**, not "anonymous", "untraceable", or "like Tor" as a safety promise. Do not claim anonymity before independent review and real network measurements.

### Invariants (required in every release)

1. The client process has no code path that opens a public-web socket or resolves a public-web hostname. Its outbound sockets are limited to its configured loopback SAM endpoint and local control channel. On SAM or exit failure, browser traffic fails closed.
2. Proxy listener binds exactly `127.0.0.1` and `::1` only when the corresponding address is explicitly enabled; v1 defaults to IPv4 `127.0.0.1` only. Never bind `0.0.0.0` or `::`.
3. A hostname cannot be handed to Windows/system DNS on the client. The exit resolves names after validating them. The browser must use the proxy for both HTTP and HTTPS, with proxy DNS behavior verified by packet capture.
4. Exit Destination is pinned by its full 52-character `.b32.i2p` name (or full I2P Destination internally). No DNS-like short name or unverified substitution is accepted for an exit.
5. Any route, session, proxy, policy, or exit change closes existing client proxy connections before new settings take effect. There is no connection reuse across exit changes.
6. Web content, extensions, and ordinary local processes cannot issue privileged daemon control requests. Loopback proxy is not a general-purpose local forward proxy in production; see access control below.
7. Local process, browser, and exit logs never store requested hostnames, URLs, HTTP headers/bodies, peer Destination, or user IP by default.

## 3. Repository layout and deliverables

The initial repository contains only this `PROJECT.md`. Implementation must later add:

```
Cargo.toml                    workspace, locked dependencies
Cargo.lock
crates/protocol/              wire parser/serializer and limits
crates/client/                loopback proxy, SAM adapter, exit selection, control IPC
crates/exit/                  SAM acceptor, egress policy, DNS, TCP relay
crates/testkit/               fake SAM, fake exit, local HTTP/TLS origin
tests/                        integration and fault-injection tests
docs/                         operator guide, browser integration, threat model, release evidence
packaging/windows/            signed-binary/service packaging scripts
```

`PROJECT.md` remains the normative architecture. Protocol changes require a version bump and an interoperability test. Generated artifacts, router keys, logs, and user configuration must never be committed. The exit is a separate executable and **must not be installed or enabled by the ordinary browser/client installer**.

## 4. Client configuration and lifecycle

Use a versioned TOML configuration file under `%LOCALAPPDATA%\Nullroute\client\config.toml`, created with user-only ACLs. Values and defaults:

```toml
schema_version = 1
enabled = false
proxy_bind = "127.0.0.1:14500"
sam_address = "127.0.0.1:7656"
connect_timeout_ms = 15000
idle_timeout_ms = 120000
max_connections = 128
max_connections_per_exit = 64
exit_selection = "sticky_per_browser_session"
exits = [] # array of { destination = "<52-char>.b32.i2p", enabled = true, label = "..." }
```

Reject invalid or unknown security-sensitive keys, out-of-range values, wildcard/non-loopback addresses, duplicate Destinations, and malformed `.b32.i2p` values. Never treat configuration parse failure as permission to choose permissive defaults. Write updates atomically (temporary file, flush, rename) and keep ACLs restricted. No proxy credentials or router private keys in this file. The exit list is entered via privileged Nullpath UI or a local administrative CLI, never received from a website.

**Lifecycle:** `STOPPED -> STARTING -> READY -> DEGRADED -> STOPPING -> STOPPED`. `READY` requires a working SAM HELLO/session plus a successful Nullroute protocol health check through at least one pinned exit; a TCP port listening is not sufficient. `DEGRADED` blocks new proxy requests when no exit passes health checks. On process start, do not create the proxy listener unless `enabled=true` was set by the user's explicit prior choice; the browser itself still starts disconnected as specified in Nullpath. Nullpath's connect action starts or enables the client only after the router is ready. Stop cancels active requests, closes the listener and SAM session, and reports `STOPPED`. Router disappearance enters `DEGRADED` within 5 seconds and does not trigger direct fallback. Retry SAM with bounded exponential backoff (1, 2, 4, 8, 16, 30 seconds, capped at 30, with jitter) while enabled. Any retry remains on the configured loopback endpoint.

### Local control interface

Use a Windows named pipe `\\.\pipe\nullroute-control-<user SID>` with an ACL permitting only the current user and LocalSystem. Control messages are length-prefixed UTF-8 JSON, at most 16 KiB, with request IDs and `protocol_version=1`. Implement exactly `status`, `start`, `stop`, `set_exits`, and `shutdown`; unknown commands/fields fail. `status` returns state, selected exit **label and pinned Destination**, SAM readiness, active connection count, and a stable reason code, never browsing destinations. Reject connections from another SID. Browser UI must call this through its privileged parent process, not a page/extension or exposed HTTP endpoint. The proxy listener also validates local peer ownership where supported; because loopback alone does not authenticate a Windows process, v1 packaging must restrict it with a per-launch random 256-bit `Proxy-Authorization: Basic` secret supplied only to the dedicated Nullpath profile. The daemon checks it in constant time on **every** proxy request and `CONNECT`, sends `407` on failure, never forwards it, rotates it on restart, and never logs it. If Firefox cannot reliably supply this secret without exposing it to pages/extensions or storing it on disk, integration is blocked: do not ship an unauthenticated local proxy as the default.

## 5. Browser integration contract (implemented in `nullpath`, not here)

Replace **only** the Direct web profile with a new `Public web via Nullroute` profile. Do not modify I2P-site or conventional-outproxy behavior as part of this change. Reuse Nullpath's separate profile storage and fail-closed channel filter. New profile: fixed HTTP and HTTPS proxy `127.0.0.1:14500`, no proxy bypass list except browser-internal pages that make no network requests, no system proxy fallback, no automatic proxy discovery, no direct DNS/DoH, no speculative connections, no WebRTC direct UDP, and no HTTP/3/QUIC direct path. Browser background services, downloads, redirects, service workers, WebSockets, extensions, updates, and privileged browser requests must be either routed through the same proxy or disabled in that profile. `localhost`, LAN, `.i2p`, IP literals, and router-admin addresses are blocked in this profile; accessing an I2P site requires the I2P-sites profile. Keep a user-visible state label and exit identity. The router button must show Nullroute client readiness separately from router readiness. A blocked or failed page explains the specific layer (router, SAM, exit, policy, destination) and offers retry, never an implicit switch to direct web. Do not relabel an existing direct profile before its traffic paths pass the release tests in §11.

Nullpath currently uses a request blocker plus final proxy channel filter for I2P profiles, and its [network diagram](https://github.com/Kayyo321/nullpath/blob/build/windows-native/docs/nullpath/NETWORK.md) describes `127.0.0.1:14444` for I2P sites and `127.0.0.1:14450` for its managed public-web outproxy. `14500` is reserved here for Nullroute to avoid collision. Nullpath's [router control specification](https://github.com/Kayyo321/nullpath/blob/build/windows-native/docs/nullpath/I2P-ROUTER-TOGGLE.md) starts disconnected and manages i2pd; enabling SAM for a managed router needs an explicit, local-only config change and health check. For a user-managed router, show instructions and require the user to enable SAM themselves. Never assume SAM is enabled merely because its HTTP proxy works.

## 6. I2P/SAM session rules

Connect to configured SAM endpoint over loopback TCP, negotiate `HELLO VERSION MIN=3.0 MAX=3.3`, reject unsupported versions, and create `STYLE=STREAM` sessions. The client uses a transient Destination for the lifetime of the daemon session; restart creates a new one. The exit stores a persistent I2P Destination private key in a user-selected file with restrictive ACLs and never replaces it silently. The public `.b32.i2p` identifier is derived from that Destination and displayed to the operator. The client creates a new SAM `STREAM CONNECT ID=<session> DESTINATION=<pinned-exit>` socket for each browser TCP connection. The exit keeps pending `STREAM ACCEPT` sockets and replenishes them up to its concurrency limit. Parse SAM status lines and timeouts strictly; never send application bytes until `RESULT=OK`. If SAM supplies the peer Destination on accept, treat it as a pseudonymous transport identifier, not a real-world identity; do not persist it in logs.

I2P's unidirectional tunnels and garlic routing are provided by the router. Do **not** invent a second hop layer inside Nullroute, claim that one extra application relay is a new garlic hop, or reuse a single client Destination as a promise of unlinkability across sessions. Do not tune tunnel quantity/length without router-specific compatibility and performance tests; v1 uses supported router defaults. Limit SAM endpoints to loopback. A non-loopback SAM deployment is outside v1 because SAM itself does not provide the transport authentication expected across untrusted hosts.

## 7. Nullroute wire protocol v1

All integers are unsigned network byte order. Each I2P stream carries exactly one request and then raw bidirectional TCP bytes. The protocol has no compression, encryption layer, multiplexing, or renegotiation; I2P supplies transport privacy to the exit and HTTPS supplies browser-to-site content confidentiality. Never interpret exit-supplied bytes as configuration.

**Open frame, client to exit (fixed prefix plus host):**

| Offset | Size | Field | Rule |
| --- | ---: | --- | --- |
| 0 | 4 | magic | ASCII `NR01` |
| 4 | 1 | version | `1` |
| 5 | 1 | command | `1=CONNECT_TCP`, `2=HEALTH` |
| 6 | 2 | host length | 0 for HEALTH, 1–253 for CONNECT_TCP |
| 8 | 2 | port | 0 for HEALTH, 80 or 443 for CONNECT_TCP |
| 10 | N | hostname | ASCII lower-case IDNA A-label, without trailing dot |

There are no extra headers. HEALTH must have exactly the 10-byte frame, return status 0, then close. For CONNECT_TCP, reject embedded NUL, whitespace, percent escapes, `@`, slash, backslash, colon, empty labels, IP literals, `.i2p`, `.localhost`, `.local`, `.internal`, and single-label names. Validate IDNA in one shared parser on client and exit; reject mismatched canonical encoding. Read the entire frame within 10 seconds and cap it at 263 bytes; malformed or extra pre-reply data closes the stream. The exit resolves the validated host and enforces §9 before sending success.

**Reply frame, exit to client:** ASCII `NR01` (4), version `1` (1), status (1), then reason length (2), then UTF-8 reason bytes of 0–256 bytes. Statuses: `0=OK`, `1=BAD_REQUEST`, `2=POLICY_DENIED`, `3=DNS_FAILURE`, `4=CONNECT_FAILURE`, `5=BUSY`, `6=INTERNAL_ERROR`, `7=UNSUPPORTED_VERSION`. Reason is a fixed human-readable class, not resolved IP or private operational data. Once `OK` is sent, both peers switch to opaque, full-duplex byte relay until EOF, timeout, quota, or error. Half-close propagates in both directions. A non-OK reply closes the I2P stream immediately. Client maps statuses to stable local proxy errors and UI reason codes. Unknown versions/statuses fail closed.

Maximum pre-open buffered browser data: 64 KiB per connection. Maximum relay buffer: 64 KiB in each direction, with backpressure. Do not buffer full responses. Timeouts: SAM connect 15 seconds, exit reply 20 seconds, egress DNS 5 seconds, egress TCP connect 10 seconds, idle relay 120 seconds. Active connection hard cap: 30 minutes; limits are configurable downward but not upward without a new reviewed release. Limit overall process memory via connection caps and bounded buffers.

## 8. Browser-facing proxy behavior

Accept HTTP/1.1 only. Reject HTTP/2 prior knowledge, malformed request lines, request smuggling ambiguity (conflicting `Content-Length`, transfer encodings, duplicate `Host`, whitespace before colon), userinfo, and absolute URIs with unsupported schemes. Keep at most one browser request per accepted local TCP connection in v1; send `Connection: close` for HTTP responses. For `CONNECT`, require authority form `host:443` and a matching valid host; open exit stream; reply `HTTP/1.1 200 Connection Established\r\n\r\n` only after exit `OK`, then relay opaque TLS bytes. The client never intercepts TLS, modifies certificate validation, or injects a root certificate.

For plain HTTP, accept only absolute-form `http://host[:80]/path?query`. Require `Host` to match the URI authority after canonicalization. Open exit stream to host:80. Forward an origin-form request line, preserve end-to-end headers/body, remove hop-by-hop headers named by RFC 9110 `Connection` as well as `Proxy-Authorization`, `Proxy-Connection`, `Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding` only when re-framing is performed, and `Upgrade` unless WebSocket handling is explicitly enabled. V1 deliberately rejects chunked browser request bodies and `Expect: 100-continue`; content-length bodies are streamed with bounded buffers. Never add `Via`, `X-Forwarded-For`, or client IP headers. For HTTP response, pass bytes through without rewriting and close after one response; the parser must recognize framing to avoid response/request desynchronization. WebSocket over HTTPS works inside CONNECT. Plain `ws://` is out of scope and fails explicitly. HTTP origin requests and HTTPS CONNECT must receive the same exit policy. No transparent downgrade from HTTPS to HTTP.

Map proxy failures to `502 Bad Gateway` (exit/destination), `503 Service Unavailable` (router/exit not ready), `504 Gateway Timeout` (timeouts), `403 Forbidden` (policy), or `407 Proxy Authentication Required` (missing local proxy credential). Include a short static error body and `Cache-Control: no-store`; never echo the requested host, credential, URL, or raw exit error in a page visible to websites. Connection errors do not trigger another network path. If multiple exits are configured, one retry may choose another enabled exit **before** any payload bytes are forwarded; never replay a request/body after forwarding begins.

## 9. Exit service and egress policy

The exit is a separately installed, opt-in process. It listens only through its I2P SAM session; it does not expose a public TCP proxy. Operator config lives in `%PROGRAMDATA%\Nullroute\exit\config.toml` when run as a Windows service, with service-account-only ACLs. It contains `schema_version=1`, loopback `sam_address`, persistent destination key path, `max_connections=256`, `max_connections_per_client_destination=16`, `max_new_connections_per_minute=120`, `max_bytes_per_connection=1073741824`, `idle_timeout_ms=120000`, and an explicit public egress interface or default-route policy. Operator must explicitly set `accept_clients=true`; default is false. Apply global and per-client limits; a client Destination is a rate-limit key only, not an account or identity. No paid access or billing in v1.

Allow **TCP only, ports 80 and 443**. Exit performs DNS resolution locally, independently of the client. Reject IP literals, CNAME chains or final A/AAAA answers in loopback, link-local, RFC1918/ULA, carrier-grade NAT, multicast, broadcast, documentation, reserved, unspecified, or other non-global ranges. Check every returned address, select only globally routable addresses, and connect to the exact checked numeric address so DNS rebinding cannot change the destination between check and connect. Recheck on every new connection. Block `.i2p`, `.onion`, `.localhost`, `.local`, `.internal`, and single-label names before DNS. Disable system proxy and proxy environment variables in the exit connector. No cloud metadata service, LAN, router admin, or non-public target may be reached. Redirects are browser requests and must pass the same validation on the next connection.

Use OS DNS as configured on the exit host. An exit operator and their DNS provider can observe DNS queries. No client-side DNS request or DoH endpoint is used. The exit cannot promise that the destination site will accept its traffic. Operators need a documented abuse contact, bandwidth cap, rotation/revocation procedure, and firewall restricting unrelated inbound access. Exit key compromise requires immediate removal of the Destination from client configs; there is no automatic trust rollover. Logs contain counts, aggregate byte totals, error classes, and process health only; no client Destinations, hostnames, URLs, IPs, or payload. Rotate logs and publish the retention period in the operator guide.

## 10. Exit selection, failure, and user experience

V1 ships with an empty exit list. The UI requires the user to enter a full Destination, displays the operator-supplied label as **unverified text**, and warns that the operator can observe metadata/plain HTTP. Health checks verify protocol reachability and exit response, not operator trust, bandwidth, honesty, or ability to reach every site. Choose one healthy exit per browser session and keep it sticky until disconnect, exit failure, or manual change; this reduces surprise IP changes during login. On failure, close affected connections and show a prompt to reconnect or choose a different configured exit. Never automatically choose an exit that the user did not enable. Display the active exit Destination and a short fingerprint; allow copying the full value. Labels are never security identifiers.

Nullpath's router toggle remains the top-level I2P connection control. When router is off, Nullroute is unavailable. When router is on but SAM is off, show `SAM_UNAVAILABLE`. Other stable reason codes: `EXIT_NOT_CONFIGURED`, `EXIT_UNREACHABLE`, `EXIT_REJECTED`, `EXIT_BUSY`, `DESTINATION_DENIED`, `DESTINATION_FAILED`, `LOCAL_PROXY_AUTH_FAILED`, `ROUTER_DISCONNECTED`, and `INTERNAL_ERROR`. All transitions must be conveyed by text and accessible status, not color alone. The browser continues to start disconnected, as its current specification requires.

## 11. Verification and release gates

Implementation is complete only when automated tests and a human-readable network trace cover:

1. Protocol golden vectors, version mismatch, truncation, oversized frames, invalid IDNA, malformed replies, half-close, cancellation, buffering, and slow-peer resource limits.
2. Local proxy parsing: HTTP GET/POST, HTTPS CONNECT, nested redirects, downloads, service workers, HTTPS WebSocket, header smuggling attempts, malformed authority, proxy authentication, absent exit, and each status mapping.
3. Exit policy: blocked private/reserved IPv4 and IPv6, CNAME to private space, DNS rebinding, mixed public/private answers, DNS failure, ports other than 80/443, IP literals, invalid hostnames, exhausted quotas, and concurrency races.
4. Router/SAM faults: absent SAM, wrong version, session rejection, bridge restart, stream timeout, exit disappearance mid-transfer, exit change while connected, client crash/restart, and router shutdown. Every case must fail closed.
5. End-to-end Nullpath integration for each browser request class: address bar, iframe/subresources, redirects, downloads, service workers, extensions, updates/background fetch, WebRTC, DoH, prefetch, WebSocket, localhost/LAN attempts, router admin, and `.i2p` handling. Capture traffic at the client host and assert **no public-website DNS or TCP/UDP from `nullpath.exe` or `nullroute-client.exe`**. Router peer/reseed connections are separately identified and explained.
6. Independent external observation: controlled website logs show only the exit IP; controlled DNS logs show queries at the exit and none at the client. HTTPS certificate warnings remain effective under a malicious exit; no TLS interception occurs.
7. Windows installer/service tests: standard-user installation, separate exit consent, ACLs, upgrade, rollback, process ownership, port collision, uninstallation, and no stale proxy configuration that enables direct fallback.

CI must run unit/integration tests with fake SAM and local fake origins without touching the public internet. A separate, explicitly enabled staging job exercises real I2P against a dedicated test exit. Do not advertise or enable the new browser mode by default until leak tests, exit policy tests, independent security review, and operator documentation are complete. Publish exact release versions, test commands/results, packet-capture methodology, known limitations, and a reproducible-build or signed-binary provenance record. Never equate passing tests with a mathematical anonymity guarantee.

## 12. Implementation order and acceptance criteria

1. **Protocol/testkit:** implement shared parsers, golden vectors, fake SAM and fake exit; accept only when malformed inputs cannot panic or allocate unbounded memory.
2. **Exit:** persistent Destination handling, SAM accept, DNS/egress policy, quotas, relay; accept only when private targets and rebind cases fail in tests and no public listener exists.
3. **Client:** loopback authenticated proxy, SAM connect, protocol handshake, health/state/IPC, bounded relay; accept only when no direct website socket or DNS lookup is possible in fault tests.
4. **Windows packaging:** client installer and separately consented exit service, ACLs, upgrade/removal; accept only after standard-user and service-account tests.
5. **Nullpath integration in its own repository:** replace direct profile, wire status/controls, enforce proxy and request policy; accept only after the full §11 network trace passes.
6. **Review and limited release:** security review, threat-model correction, operator documentation, staging exit, performance and abuse monitoring; enable for testers with explicit experimental wording before any broad release.

For all ambiguous implementation details, choose the behavior that refuses the request and records a non-sensitive reason code. Changes to the fixed security decisions, wire protocol, or trust model require a documented revision to this file before code is changed.

## 13. Primary references

- [Nullpath browser branch](https://github.com/Kayyo321/nullpath/tree/build/windows-native), [network paths](https://github.com/Kayyo321/nullpath/blob/build/windows-native/docs/nullpath/NETWORK.md), [router control specification](https://github.com/Kayyo321/nullpath/blob/build/windows-native/docs/nullpath/I2P-ROUTER-TOGGLE.md).
- [I2P FAQ](https://i2p.net/en/docs/overview/faq/) — outproxies are opt-in services and I2P is primarily an internal network.
- [I2P SAM v3 specification](https://i2p.net/en/docs/api/samv3/) — session creation and streaming connect/accept semantics.
- [I2P garlic routing](https://i2p.net/en/docs/overview/garlic-routing/) and [tunnel routing](https://i2p.net/en/docs/overview/tunnel-routing/) — I2P's existing routing model.
- [RFC 9110 HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110) and [RFC 9112 HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112) — proxy request forms, CONNECT, headers, and framing.
