# Nullroute — native Tor client daemon for Nullpath

**Status:** design specification v3.2, 2026-09-28. This repository contains only this specification. No daemon, browser integration, test suite, audit, or proven anonymity has been delivered.

## 1. Architecture and hard compatibility boundary

Nullroute will be a **new Rust daemon implemented here** and bundled with Nullpath. It will implement the public Tor client protocol itself: authenticated directory bootstrap, guard and path selection, TLS channels, circuit creation, onion encryption, relay cells, stream multiplexing, and flow control. It will not embed Arti or launch C Tor. It may use audited TLS and cryptographic primitives; “from the ground up” means owning the Tor client protocol logic, not inventing ciphers.

For clearnet, Nullroute will automatically choose a Tor exit from the verified consensus. For a v3 `.onion` address, it will use Tor's onion-service introduction and rendezvous protocol **without a clearnet exit**. Users will not choose an I2P outproxy, Tor exit, country, or pinned route. Ordinary Tor infrastructure must accept Nullroute's **standard Tor protocol cells**.

**Public-web Tor circuits use onion routing, not I2P garlic routing.** Existing Tor relays remove one specified layer from each relay cell; exits expect Tor stream commands. Replacing either with garlic cloves would break interoperability. Putting a garlic envelope inside a Tor stream would need a cooperating gateway to unpack it before clearnet access; ordinary Tor exits do not do that. Nullpath's separate `.i2p` profile continues using I2P garlic routing. Tor stream multiplexing is not to be renamed garlic routing. A genuine hybrid would require a custom gateway or Tor protocol change and would not satisfy the requirement to work with all existing Tor infrastructure.

```
Nullpath public-web profile
  -> authenticated SOCKS5, 127.0.0.1:14500
  -> nullroute.exe, our Tor client implementation
  -> TLS channel to persistent Tor guard
  -> clearnet: standard Tor circuit -> automatic exit -> site
  -> .onion: introduction + rendezvous circuits -> onion service

Nullpath I2P-sites profile
  -> existing I2P router and garlic-routed tunnels -> .i2p destination
```

Nullroute is a client, not a relay, directory authority, exit, I2P router, or VPN. No private Tor network, modified exit, I2P-to-Tor gateway, or designated outproxy is required.

| Scope | Fixed decision |
| --- | --- |
| Initial platform | Windows 10/11 x64, per-user daemon, no elevated service. |
| Language | Rust stable. Deny unsafe code in project-owned parser, protocol, proxy, policy, and state crates. |
| Tor compatibility | Conform to the versioned Tor specifications in §13. Unknown mandatory protocol features fail closed. |
| Browser transport | Authenticated SOCKS5 CONNECT with DNS names or validated v3 `.onion` names; TCP 443 and 80 under the target-specific policy in §10. No BIND, UDP, IP literals, or generic proxy service. |
| Exit choice | Verified consensus, Tor guard rules, path constraints, bandwidth weights, and exit policies. No manual exit or fallback. |
| Startup | Nullpath starts disconnected. Explicit connect initiates bootstrap. |

## 2. Security model and claims

A correctly routed connection exposes a Tor exit IP to the website, not the user's IP. The guard can see the user's IP, while the exit can see the destination and traffic metadata. HTTPS protects browser-to-site content after the exit. A Tor exit can inspect or alter plaintext HTTP and can block or fail a request. Local network observers may recognize Tor traffic.

This is **not a guarantee of anonymity**. Accounts, cookies, fingerprints, extensions, external applications opening downloads, uploaded data, malware, compromised relays, and traffic correlation can identify or link activity. A new Tor client has substantial protocol risk. A browser is not equivalent to Tor Browser merely because it uses Tor; the Tor Project warns of DNS, WebRTC, and fingerprint leaks in other browsers. The UI must say **experimental** until implementation, leak tests, protocol conformance, independent cryptographic/security review, and fingerprint review pass. Do not advertise “anonymous browsing,” “untraceable,” or “Tor Browser equivalent.”

### Non-negotiable invariants

1. Nullpath public-web processes send no browsing-related non-loopback DNS, TCP, or UDP. Their only public-web proxy is Nullroute on loopback. Failure never activates direct networking, a system proxy, an I2P outproxy, or another browser profile.
2. Nullroute never resolves a requested website with Windows DNS or opens a direct website socket. It sends clearnet hostnames through Tor exit streams for exit-side DNS. It resolves `.onion` identities only through Tor's HSDir and rendezvous protocol; an onion address is never sent to ordinary DNS or a clearnet exit.
3. Nullroute's non-loopback sockets contact only Tor directory and relay endpoints as required by verified directory data. Built-in fallback addresses are contact hints for obtaining **validated** directory material, not authority to trust an exit.
4. The SOCKS listener binds only `127.0.0.1:14500` while ready and authenticates every connection. Web content and extensions cannot read its secret or use the control pipe.
5. Separate top-level browsing contexts cannot share Tor circuits or browser connection pools. Guard state persists across launches.
6. Failed signatures, certificates, handshakes, relay digests, flow-control checks, and protocol state transitions destroy the affected channel or circuit; they never trigger permissive parsing.
7. Default logs never contain hostnames, URLs, requested IPs, proxy credentials, context IDs, circuit paths, or content.

### Nullroute-specific protections and usability features

These are requirements for our daemon and browser integration, not claims that Tor lacks them or that adding them guarantees anonymity:

| Feature | Exact behavior and benefit | Boundary |
| --- | --- | --- |
| Target-aware routing | Classify a validated destination as `CLEARNET` or `ONION_V3` before circuit selection. Clearnet gets an exit circuit and exit-side DNS; onion gets HSDir, introduction, and rendezvous circuits. Wrong-class circuit attachment is a fatal request error. | Prevents onion names from reaching DNS or exits. |
| Context-bound circuit pools | One random browser context ID maps to a separate circuit pool; no circuits, stream IDs, HTTP connections, TLS sessions, or browser storage cross contexts. Rotate on top-level navigation and identity reset. | Reduces cross-site linkage; it does not defeat login or fingerprint tracking. |
| Authenticated local handoff | Per-launch SOCKS and control secrets, process-bound IPC, strict loopback binding, replay protection, and session rotation. | Prevents webpages and unauthenticated local clients from commandeering the Tor client. |
| Fail-closed route monitor | Browser channel filter and daemon state jointly block traffic whenever Tor is unavailable, the proxy owner changes, or a target cannot be classified. Record a reason code, never a destination. | A local administrator or compromised browser remains outside this boundary. |
| Verified directory and durable guards | Reject unsigned/stale consensus data, validate descriptors, preserve guard state, and do not rotate guards for a failed page. | Reduces directory substitution and needless guard exposure. |
| Onion identity verification | Decode v3 addresses, verify version/checksum and descriptor signatures, derive the correct blinded identity and subcredential, and authenticate the service rendezvous handshake. | A syntactically valid address does not prove the site's human-readable identity. |
| Bounded resource behavior | Limit concurrent streams, context count, handshake time, buffers, descriptor sizes, and retry work; cancel slow or malformed peers. | Protects the local daemon from resource exhaustion; it does not prevent network-wide denial of service. |
| Privacy-preserving diagnostics | Report bootstrap stage, destination class, and stable failure code; suppress hostnames, paths, circuits, and payload in default logs. | Diagnostic detail is intentionally limited. |
| Secure update and recovery | Verify signed bundle manifest and daemon version before launching; fail closed on browser/daemon protocol mismatch; keep last valid guard state and validated directory cache across updates. | Software update signing and host compromise remain trust boundaries. |
| Accessible error handling | Show separate Tor bootstrap, onion descriptor, onion introduction/rendezvous, exit-policy, and site failures, with a retry action that never changes routing mode. | A failure explanation is not proof that a site is safe or reachable. |
| Bounded reachability retry | If a clearnet stream is refused before payload, try at most one other eligible exit on a new circuit within the same isolation context and guard policy. If an onion introduction point fails before rendezvous, try at most one other verified point from the descriptor. | Improves availability without reusing or replaying browser data; it cannot force a blocked site to accept Tor. |

Neither extra encryption around ordinary Tor cells nor arbitrary cover traffic is a default feature. Either could make Nullroute traffic more distinctive or impair compatibility. Any padding or timing change must use negotiated Tor protocol mechanisms and pass network-load and fingerprint review before release.

## 3. Repository ownership

```
Cargo.toml
Cargo.lock
crates/daemon/             lifecycle, control pipe, SOCKS5, bounded relay
crates/tor-directory/      consensus, certificates, descriptors, cache
crates/tor-path/           guard state, path constraints, exit policies
crates/tor-channel/        TLS, link negotiation, cells, channel state
crates/tor-circuit/        ntor, hop keys, onion layers, circuit state
crates/tor-stream/         BEGIN/DATA/END, SENDME, stream multiplexing
crates/tor-onion/          v3 address, HSDir, descriptor, intro/rendezvous client
crates/policy/             IDNA and target restrictions
crates/testkit/            fake authorities, relays, exits, origins
tests/                     conformance and fault-injection tests
docs/                      threat model, browser contract, release evidence
packaging/windows/         signed bundle and per-user installation
```

This repository owns the Tor client. `Kayyo321/nullpath` owns browser patches and installer integration. No `arti-client`, C Tor runtime, `nullroute-exit`, SAM connector, or I2P outproxy directory belongs in this design. Pin dependency and Tor-spec source revisions in the lockfile and release manifest. Never commit user state, keys, secrets, captures, or logs.

## 4. Directory bootstrap and trust

Bundle Tor's maintained directory authority identity keys and fallback endpoints with source revision and hash in the signed build manifest. Change authority keys only through a signed Nullpath update. Do not accept key or directory overrides from websites, environment variables, unsigned local files, or downloaded configuration. A fallback endpoint's IP is not proof of its directory answer.

On explicit `start`:

1. Load cached consensus, certificates, microdescriptors, and guard state from `%LOCALAPPDATA%\Nullroute\state\` with strict length, schema, signature, and time validation. Ignore corrupt directory cache; treat corrupt guard state as a blocking error until documented recovery. Never use an expired consensus for new exit streams.
2. Fetch directory data over the Tor directory transport supported by the pinned Tor specification. Enforce byte, decompression, and time limits before parsing. Verify authority identity/signing certificates, a sufficient consensus signature set under current directory rules, validity times, and clock tolerance. A single unsigned server response never authorizes relays.
3. Fetch microdescriptors by digest; verify each against the consensus. Reject missing identity/onion keys and incompatible protocol versions. Accept consensus parameters only within reviewed bounds.
4. Persist verified objects by atomic replace under current-user-only ACLs. Never put requested website hosts in directory cache.

`READY` requires valid directory state, a usable guard, and the ability to build compatible circuits, not just directory reachability. Track `clearnet_available` and `onion_available` separately. The SOCKS listener opens if either capability is available; a request for an unavailable capability gets a class-specific failure. Wrong clock, missing signatures, unrecognized mandatory protocol versions, or no usable guard blocks both. No eligible exit blocks clearnet only; failure to reach HSDirs or rendezvous points blocks onion only. Refresh directory data under the Tor specification's freshness rules. Test rollover, certificate rotation, invalid signatures, stale caches, and malicious responses.

## 5. Guard, path, and automatic exit selection

Implement the Tor guard specification's sampled, confirmed, primary, retry, and persistence rules. A website failure must not rotate the guard. Store guard state under the current user's ACL; migrate it only with a versioned converter.

For an exit circuit, choose the exit **first** from verified, running, valid relays whose exit policy permits the requested port and whose protocol versions are compatible. Choose middle and guard under Tor's path rules: no repeated relay, declared family overlap, or disallowed subnet overlap; honor consensus bandwidth weights and restrictions. Use an OS-seeded cryptographic RNG with unbiased sampling. If no valid path exists, fail. Do not permit country selection, exit pinning, or a Nullroute-operated preference list.

A clearnet circuit may carry multiple streams only when their browser isolation context matches and its exit supports each target port. Onion descriptor, introduction, and rendezvous circuits are separate from clearnet exit circuits and from other context IDs. Retire circuits under Tor's specified age and failure rules; do not promise a fresh IP per page. “New identity” closes streams and rotates browser isolation contexts, but does not erase guard history or guarantee a new exit IP. The first release does not tune circuit length or network weights.

## 6. Tor channel and circuit protocol

A channel is a TLS connection to a consensus-identified guard. Implement Tor link negotiation: TLS setup, `VERSIONS`, relay `CERTS` verified against the consensus identity, applicable `AUTH_CHALLENGE`, `NETINFO`, negotiated cell framing, and required link padding. Reject identity mismatch, oversized variable cells, duplicate/out-of-order handshake cells, and unsupported mandatory versions. Ordinary TLS certificate validation alone is not Tor relay identity validation.

Parse cell lengths before allocation. Key circuits by channel and circuit ID; scope stream IDs to a circuit. Use typed states for negotiating/open/closed channels and handshaking/open/closed circuits. An invalid cell for a state closes the affected resource. A restarted channel never reuses old cipher state, counters, or stream mappings. Use OS CSPRNG output through audited libraries; never log keys or nonces.

Build a three-hop exit circuit with `CREATE2`/`CREATED2` and `RELAY_EXTEND2`/`RELAY_EXTENDED2`, using the specified ntor handshake. Authenticate each hop's consensus identity and onion key, derive independent forward/backward keys and digest state, and validate every response. Wrap outgoing relay-cell bodies in hop encryption layers in reverse path order; remove incoming layers in path order and validate recognition/digest at the addressed hop. A digest or handshake mismatch destroys the circuit. No extra garlic clove, custom cell command, or substituted encryption is sent to a standard Tor relay.

## 7. Tor streams, DNS, and flow control

For a validated **clearnet** hostname, open `RELAY_BEGIN` with the hostname and permitted port on an exit circuit. Wait for `RELAY_CONNECTED` before replying SOCKS success. For an onion target, follow §7A and open the application stream only after service rendezvous authentication. Relay bounded `RELAY_DATA`; process `RELAY_END` as stream closure. Implement circuit and stream `SENDME` flow control, including authenticated forms and negotiated parameters required by the supported network. Never permit an unacknowledging peer to grow queues without bound.

Each browser socket maps to one Tor stream. Caps: 128 streams globally, 32 per isolation context, 256 contexts, 64 KiB application buffer in each stream direction. Timeouts: 5-second SOCKS handshake, 30-second Tor stream open including retries, 120-second idle, 30-minute hard lifetime. Propagate half-close and cancellation. A refused clearnet stream may try **one** other consensus-eligible exit on a new circuit, preserving the same context and guard rules, only before SOCKS success or browser payload. A failed onion introduction may try **one** other verified introduction point before rendezvous. Never replay HTTP bodies after forwarding starts or loop through exits until a site accepts traffic. Unknown relay errors become generic SOCKS failures.

For clearnet, the Tor exit resolves hostnames and applies its exit policy. Nullroute cannot inspect the exit's eventual DNS answer and cannot claim to prevent every exit-side DNS rebinding case. Nullroute blocks literals and special-use names locally. For `.onion`, there is no exit-side DNS or clearnet exit. TLS, when used, stays end-to-end between Nullpath and the destination; Nullroute never installs a root CA or intercepts certificates.

## 7A. Version 3 onion-service client

Support **public v3 onion services** in the first release. The 56-character address label plus `.onion` is parsed as lower-case base32, decoded into the 32-byte Ed25519 identity public key, two-byte checksum, and version byte. Require version 3 and verify the checksum formula in the Tor onion-address specification before any network request. Reject legacy 16-character v2 addresses, subdomains of onion addresses, malformed base32, mixed encodings, and IP-literal lookalikes. An onion address is an identity key, not a DNS hostname; it must never be passed to `RELAY_BEGIN` on a clearnet exit circuit or to the OS resolver.

For a valid address, derive the current time-period blinded key and subcredential under the pinned v3 rendezvous specification. Fetch descriptors only from the responsible consensus-derived HSDir set through Tor circuits, with length/time caps. Validate descriptor signatures, lifetime, revision counter, encrypted layers, introduction-point keys, and onion identity binding before using an introduction point. A bad or stale descriptor is never accepted because one HSDir returned it. Cache validated descriptors in memory by onion identity and time period for at most their specified validity; clear them on identity reset and shutdown, and never log addresses or write descriptor queries to disk.

Choose a rendezvous relay under Tor's path rules and establish a dedicated rendezvous circuit. Build a separate introduction circuit to a verified introduction point; send the standard `INTRODUCE1` payload containing a fresh random rendezvous cookie and the required ntor handshake material. Verify introduction acknowledgement and the service's `RENDEZVOUS2` response, derive the end-to-end service keys, and only then attach a stream. For service streams use the onion-service `RELAY_BEGIN` target encoding required by the specification, not the clearnet hostname. Never return SOCKS success before the service accepts the stream. Intro and rendezvous circuits are not reused across different browser context IDs or onion identities. The rendezvous relay is **not** a clearnet exit and does not resolve the name.

Onion service client authorization is **out of scope for v3.1**. A descriptor requiring restricted discovery returns `ONION_AUTH_REQUIRED`; the daemon must not attempt a clearnet fallback or pretend the service is missing. A later revision may add protected credential import and storage. Onion pages may use `http://<v3-address>.onion` on port 80 because Tor's onion-service protocol provides end-to-end identity-bound encryption; Nullpath must identify this as an onion origin and must not grant a clearnet HTTP exception. Onion HTTPS on port 443 still receives normal browser certificate validation. No downgrade from `https://` to `http://` happens automatically.

## 8. Authenticated SOCKS and privileged control

Accept only SOCKS5 `CONNECT` with RFC 1929 username/password authentication and domain-name address type. Classify the domain as clearnet or v3 onion before opening any circuit. Reject no-auth, SOCKS4, BIND, UDP, IP address types, malformed length, pre-connect extra bytes, and ports other than 443/80. Bind only `127.0.0.1:14500` in `READY`; a port collision blocks startup. Replies use a generic bound address and no circuit/exit details.

Nullpath's privileged parent launches the daemon with an inherited one-time handle containing independent random 256-bit proxy and control secrets. Secrets stay in memory. The browser network process receives only the proxy secret through privileged IPC. For each top-level document the browser generates a random 128-bit context ID; subresources, frames, workers, redirects, and downloads inherit it. A new top-level navigation creates a new ID. SOCKS username is `n3.` plus the 22-character unpadded base64url context ID. SOCKS password is the 43-character unpadded base64url HMAC-SHA-256 of `"nullroute-socks-v3" || browser_session_id || context_id` under the proxy secret. Verify in constant time and map each ID to an isolated circuit pool. Expire a context after 10 idle minutes with no streams. Browser restart rotates secrets and invalidates old streams.

Control uses `\\.\pipe\nullroute-control-<user SID>` with current-user/LocalSystem ACLs, remote clients disabled, verified peer SID, and per-message HMAC under the control secret. Frames are 4-byte big-endian length plus UTF-8 JSON, maximum 16 KiB. Each message has protocol version, request ID, increasing sequence number, and MAC over canonical typed fields. Reject replay, unknown fields, duplicate keys, wrong MAC, and version mismatch. Commands are exactly `status`, `start`, `stop`, `register_browser`, and `shutdown`. `status` returns state, bootstrap category, stream count, and build ID only. `register_browser` installs a random 128-bit session ID and closes old streams. No command sets exits, authority keys, paths, or target policy.

The daemon is a same-user child of the privileged Nullpath parent and exits with it. Only one daemon per user SID exists; a second browser window delegates to the owner. It is not elevated or a service. Config and state directories use owner-only ACLs and reject reparse-point redirection.

## 9. Configuration, lifecycle, and errors

Use `%LOCALAPPDATA%\Nullroute\config.toml`, owner-only ACL. Values are fixed for v3; changed or unknown keys fail validation:

```toml
schema_version = 3
socks_bind = "127.0.0.1:14500"
max_streams = 128
max_streams_per_context = 32
max_contexts = 256
socks_handshake_timeout_ms = 5000
tor_stream_timeout_ms = 30000
idle_timeout_ms = 120000
```

No exit list, authority override, router key, proxy secret, or website host is stored. Use atomic same-directory temporary-file/flush/rename writes. Tor directory/guard state resides under `%LOCALAPPDATA%\Nullroute\state\`; aggregate logs under `%LOCALAPPDATA%\Nullroute\logs\`.

States are `STOPPED` (no process), `STARTING` (local checks, no network), `BOOTSTRAPPING` (directory/circuits), `READY` (SOCKS listener), `DEGRADED` (listener closed, streams cancelled), and `STOPPING` (cancel, flush safe state, exit). `stop` ends retries and streams within 5 seconds. Retry transient bootstrap errors after 1, 2, 4, 8, 16, then 30 seconds plus jitter while user intent remains connected. Never fall back to direct, I2P, system proxy, or unverified directory data.

Stable codes: `DIRECTORY_UNAVAILABLE`, `DIRECTORY_INVALID`, `CLOCK_INVALID`, `GUARD_UNAVAILABLE`, `NO_ELIGIBLE_EXIT`, `TOR_CHANNEL_FAILED`, `TOR_CIRCUIT_FAILED`, `EXIT_POLICY_REJECTED`, `SITE_CONNECT_FAILED`, `ONION_ADDRESS_INVALID`, `ONION_DESCRIPTOR_FAILED`, `ONION_AUTH_REQUIRED`, `ONION_INTRO_FAILED`, `ONION_RENDEZVOUS_FAILED`, `CONNECT_TIMEOUT`, `TARGET_DENIED`, `PROXY_AUTH_FAILED`, `INTERNAL_ERROR`. Do not echo raw relay text, hostname, URL, onion address, or secret in an error page. SOCKS failures follow RFC 1928/1929; unknown errors map to general failure. One destination failure need not degrade the daemon.

## 10. Target policy and Nullpath integration

Classify the SOCKS domain before ordinary IDNA validation. A name ending exactly in `.onion` must pass §7A's v3 address parser; it is never treated as clearnet. A clearnet name must be canonical lowercase ASCII IDNA A-label, 1–253 bytes, at least two labels, each 1–63 bytes, no trailing dot, NUL, whitespace, percent escape, slash, colon, userinfo, or numeric-host ambiguity. Reject IPv4/IPv6 literals and clearnet `.i2p`, `.localhost`, `.local`, `.internal`, `.test`, `.invalid`, `localhost`, and single-label names. Port 443 is allowed for either class. Port 80 is allowed for onion HTTP; for clearnet it needs a browser-managed, origin-scoped, session-only insecure-HTTP exception explicitly confirmed by the user. Redirects/scripts cannot create the exception. Nullroute validates class, host, and port; Nullpath enforces scheme and exception. `wss://` uses 443; clearnet `ws://`, UDP, and arbitrary TCP ports are unsupported.

In `Kayyo321/nullpath`, replace only Direct web with **Public web through Tor**, supporting clearnet and v3 onion addresses. Keep I2P-sites and conventional I2P-outproxy profiles separate. Use fixed authenticated SOCKS5 `127.0.0.1:14500` for HTTP/HTTPS, proxy-side DNS for clearnet, no bypass list/discovery, and no system fallback. Apply the request blocker and final channel filter to every browser request. Block LAN/router targets, `.i2p`, IP literals, unsupported schemes, and malformed/legacy `.onion` names before socket creation. I2P and Tor controls show separate readiness and separate clearnet/onion capability status.

Partition cookies, cache, TLS sessions, HSTS, storage, service workers, HTTP authentication, and connection pools by top-level context ID and from other profiles. Disable an unpartitionable store or feature. Disable telemetry, suggestions, captive portal probes, DNS/DoH, prefetch/preconnect, safe-browsing network feeds, WebRTC, external protocol handlers, automatic opening of downloads, and network-capable extensions. Route signed browser/security update checks and downloads through Tor in a dedicated maintenance isolation context that never shares browsing circuits; fail closed if Tor is unavailable. Route required certificate checks, workers, `wss://`, user-initiated downloads, and built-in PDF viewing through authenticated SOCKS with the initiating context or block them. No network request uses a shared/unattributed context except the privileged, isolated maintenance updater.

Implement and independently review fingerprint resistance for user agent, platform, fonts, canvas, WebGL, screen size, locale, timezone, media devices, and storage. Compare with Tor Browser; proxy settings alone are insufficient. UI shows disconnected, bootstrapping, connected through Tor, or a stable failure. It never asks for an outproxy/exit or silently switches modes.

## 10A. Hostile-site containment and security maintenance

The daemon cannot inspect web content or prevent a malicious `.onion` page from exploiting a browser vulnerability. Nullpath must treat **every** onion and clearnet page as hostile. Keep Firefox/LibreWolf content-process sandboxing and site isolation enabled at the upstream supported strength; never weaken them to make proxy or onion integration work. The browser parent process alone holds control capability. Content/renderer, extension, media, GPU, and file-handling processes receive no daemon control secret, Tor state files, unrestricted filesystem access, or direct network exception. Audit every new IPC method for privilege escalation and reject renderer-supplied context IDs or route choices; the privileged network code assigns those values.

The Tor profile defaults to a **global Safest-style security level** for both onion and clearnet: JavaScript and WebAssembly disabled, active media click-to-play, and high-risk document/font features disabled according to a version-locked test matrix. The setting applies uniformly across sites so an onion-specific exception does not create a distinctive fingerprint. A user may change the whole Tor profile to a reviewed Safer-style level after an explicit warning and browser restart; no silent site-triggered downgrade or per-site script exception is permitted in the first release. The exact upstream Firefox/LibreWolf switches and their regression tests must be recorded for every browser version; a renamed or ineffective switch blocks release.

Downloads never execute or open automatically. Require an explicit user action for each download; throttle or prompt for repeated downloads from one page. The built-in PDF viewer stays sandboxed and network-restricted. Files handed to external applications are **outside Tor protection**; display that warning at the handoff and never launch an external handler directly from a page. Block native plugins, executable content activation, custom protocol handlers, and extension installation from web content in the Tor profile. Onion address authenticity is cryptographic, but it does not establish that a page is harmless or that a human-readable name belongs to the expected operator.

Ship browser, Nullroute, and cryptographic dependencies as one signed, version-matched bundle. Check upstream browser advisories and dependency advisories at least daily. Triage a reported critical or actively exploited issue within 24 hours; publish a fixed signed bundle within 72 hours when a fix is available, or disable the affected feature/profile until a fix passes tests. Verify update signatures before installation, reject rollback to a known vulnerable build, and preserve a recovery path for a failed update. Never turn off certificate verification, content sandboxing, or update checks as a workaround for site compatibility.

Before public testing, obtain an independent review of the daemon protocol and cryptography **and** the browser's sandbox/IPC changes. Maintain a private vulnerability-report channel, a patch and disclosure process, reproducible or independently verifiable builds, SBOM, dependency audit, and signed release provenance. Fuzz all network-facing parsers continuously and run memory/resource-fault tests against malformed relays, descriptors, and hostile websites. No audit or test result guarantees that a user cannot be hacked; the release claim is that specified boundaries were tested for a specified build.

## 11. Verification and release gates

CI uses fake directory authorities, relays, exits, origins, and fault injection without contacting the public Tor network. Required evidence:

1. Golden vectors and differential tests against current upstream Tor behavior for directory signatures, TLS/link negotiation, cells, ntor, hop keys, relay encryption/digests, `SENDME`, streams, v3 onion-address checksums, blinded identities, descriptors, introduction, and rendezvous. Fuzz truncation, size limits, invalid order, and cancellation.
2. Guard/path tests for weights, family/subnet constraints, exit policy, protocol versions, persistence, guard failure, consensus rollover, and no eligible exit. Contexts must not share circuits. Onion introduction/rendezvous circuits must never become clearnet exit circuits.
3. Leak tests showing zero website or onion-name DNS/direct TCP/UDP from Nullpath or Nullroute. Nullroute non-loopback packets must be explainable as directory/relay traffic. Test IPv4/IPv6, crashes, offline, stale/forged consensus, clock error, channel/circuit failure, exit disappearance, HSDir failure, bad onion descriptor, and failed rendezvous. Every fault fails closed.
4. Browser matrix: address bar, redirects, frames, workers, downloads, extensions, updates, WebRTC, DoH, prefetch, WebSocket, OCSP, local/LAN/router targets, `.i2p`, valid/malformed/legacy `.onion`, onion HTTP/HTTPS, login state, new identity, and all profile transitions. Check proxy secret exposure, context storage, and direct packets.
5. Windows tests for signed binaries/manifest, standard-user installation, ACLs, process ownership, second window, port collision, update/rollback, uninstall, and crash recovery.
6. Opt-in real-network staging with controlled clearnet HTTPS/DNS observers and a controlled public v3 onion service. The clearnet site must see only a Tor exit IP; client DNS must see neither website nor onion name. The onion service must work without a clearnet exit, and a deliberately invalid onion descriptor must fail. HTTPS warnings remain effective. Record build ID, pinned Tor-spec revision, commands, sanitized capture method, SBOM, dependency audit, failures, and limitations.
7. Hostile-content tests with controlled onion and clearnet pages: script/Wasm disabled in the default security level, content process sandbox and site isolation active, renderer cannot call control IPC or pick a context ID, file and custom-protocol handoffs require explicit user action, repeated downloads are limited, and external viewers receive no implicit Tor guarantee. Validate signed update checks through a separate maintenance circuit and failure without direct fallback. Repeat after every upstream browser rebase.
8. Security maintenance drill: simulate a critical browser advisory, dependency advisory, malicious update, rollback attempt, and compromised release artifact. Verify triage ownership, version matching, signature checks, mode-disable mechanism, and documented remediation timing.

Release is blocked until the live Tor network accepts the client, conformance tests pass, independent review covers protocol/crypto/state code, and Nullpath leak and fingerprint reviews pass. Passing tests does not prove perfect anonymity.

## 12. Implementation order

1. Pin Tor-spec revision and supported protocol versions; build parsers, golden vectors, and fuzz/testkit.
2. Implement authenticated directory bootstrap and guard/path state. No browser proxy yet.
3. Implement TLS channel, ntor circuit, onion layers, relay cells, flow control, and clearnet streams against fake relays, then differential and real-network interoperability tests.
4. Implement v3 onion-address validation, HSDir descriptor verification, introduction, rendezvous, and service streams against fake services, then controlled real-network onion interoperability tests.
5. Add authenticated SOCKS5, control IPC, target policy, bounded relay, and lifecycle. Prove there is no direct website or onion-name DNS/socket path.
6. Bundle with Nullpath and implement context credentials, state partitioning, content sandbox preservation, Safest-style default, guarded downloads, signed Tor-routed updates, and fail-closed routing in its repository.
7. Complete independent daemon and browser security reviews, hostile-content tests, staging evidence, and experimental release review.

Ambiguous input, signature, cell, state, or route is rejected with a non-sensitive reason. New protocol features require a versioned specification update and conformance tests.

## 13. Primary references

- [Tor protocol introduction](https://spec.torproject.org/intro/), [channel negotiation](https://spec.torproject.org/tor-spec/negotiating-channels.html), [circuit creation](https://spec.torproject.org/tor-spec/creating-circuits.html), [relay cells](https://spec.torproject.org/tor-spec/relay-cells.html), [relay-cell encryption](https://spec.torproject.org/tor-spec/routing-relay-cells.html), and [flow control](https://spec.torproject.org/tor-spec/flow-control.html).
- [Tor directory specification](https://spec.torproject.org/dir-spec/), [path selection](https://spec.torproject.org/path-spec/), [guard selection](https://spec.torproject.org/guard-spec/guard-selection/), and [stream isolation](https://spec.torproject.org/path-spec/stream-isolation.html).
- [Tor v3 onion-service protocol](https://spec.torproject.org/rend-spec/), [onion-address encoding](https://spec.torproject.org/rend-spec/encoding-onion-addresses.html), [introduction](https://spec.torproject.org/rend-spec/introduction-protocol.html), and [rendezvous](https://spec.torproject.org/rend-spec/rendezvous-protocol.html).
- [I2P garlic routing and cloves](https://i2p.net/en/docs/overview/garlic-routing/); this distinguishes layered encryption from multi-message bundling.
- [Tor warning about other browsers](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/) and [Tor Browser fingerprint protections](https://support.torproject.org/tor-browser/features/fingerprinting-protections/).
- [SOCKS5 RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) and [username/password RFC 1929](https://www.rfc-editor.org/rfc/rfc1929).
- [Nullpath branch](https://github.com/Kayyo321/nullpath/tree/build/windows-native), [network paths](https://github.com/Kayyo321/nullpath/blob/build/windows-native/docs/nullpath/NETWORK.md), and [router controls](https://github.com/Kayyo321/nullpath/blob/build/windows-native/docs/nullpath/I2P-ROUTER-TOGGLE.md).
