# OmaBridge — architecture and feasibility study

Research date: 2026-10-17. Status: proposal, not an approved implementation design.

## Executive recommendation

Build a reusable **private service-connectivity SDK**, not a new VPN, blockchain, or cryptographic transport. Separate account identity, device membership, discovery, secure transport, service authorization, and UI. Prefer an existing transport; evaluate **iroh first**, with **Tailcat as a serious competing candidate**, before choosing one. Do not ship both transports initially.

This is a design recommendation, not a benchmark result. No application code, tunnel, mobile build, or connectivity experiment was executed during this study.

The working directory was empty and not a Git repository when inspected. There was no associated project history to recover. This document starts from the project brief, not an existing implementation.

## 1. Product interpretation

The proposed experience is:

1. A desktop creates a local cryptographic identity, without requiring a hosted account.
2. A phone generates its own device keys and joins through an approved QR invitation.
3. Additional devices join the same private device group.
4. Authorized devices discover and connect to named services, such as a web application or an existing SSH server.
5. Other projects embed the same SDK instead of rebuilding enrollment, connectivity, and permissions.

Assumptions to confirm: the first release serves personal device groups; the desktop remains powered on when hosting; synchronous connections are sufficient; offline messaging and internet-wide public publishing are not initial requirements. The phone operating system and the four consuming projects' languages are not yet known.

### Three promises that must not be confused

- **No mandatory vendor account:** achievable through locally generated identities and peer-approved enrollment.
- **No mandatory central authority:** achievable with signed device membership and replaceable discovery/relay services.
- **No reachable supporting nodes under any network conditions:** not a universal connectivity promise we should make. NAT traversal can fail and require relaying. A DHT solves discovery, not every firewall problem.[2][37]

Decentralization means distributing roles and avoiding exclusive control, not that state and infrastructure exist nowhere. Signed state would live on devices; a discovery network would retain routing records; a relay would forward encrypted packets.

## 2. Existing systems and fit

### Tailscale

Tailscale separates a coordination/control plane from a device-side data plane. Its control service handles identity, policy, and device coordination.[24] Data may travel directly, through DERP, or through a peer relay; those paths use WireGuard encryption.[2]

**Fit:** excellent reference for device UX and connection diagnostics. Adopting normal Tailscale would mean relying on its network model and control service rather than delivering the proposed standalone SDK.

### Headscale

Headscale is a self-hosted implementation of the Tailscale control server, focused on a single tailnet.[15]

**Fit:** a practical alternative if the real requirement becomes a personally operated VPN. It replaces the operator of the control plane, rather than removing that architectural role. It is not the preferred foundation for this SDK-first brief.

### T3 Connect

The upstream documentation describes Clerk-based identity, a trusted relay broker, and managed Cloudflare tunnels. Normal HTTP/WebSocket sessions use the environment tunnel hostname rather than being proxied by the relay Worker itself. The broker remains a security trust boundary.[42]

T3 also supports direct pairing over a reachable LAN/private address and QR/one-time pairing links; pairing alone does not make an unreachable host reachable.[5]

**Fit:** reuse the ideas of explicit authorization, persistent device bindings, multiple routes, and distinguishing offline from unauthorized. Do not treat its managed Connect path as decentralized transport or as a generic SSH network.

### OpenTunnel

The referenced site describes temporary, encrypted remote command sessions through a relay, with revocable invitations and no interactive PTY in its stated first-major-version scope.[4]

**Fit:** a useful reference for tightly scoped remote access, not the same persistent multi-device service fabric. It is distinct from Tailscale and T3 Connect.

### Tailcat — strong contender

Tailscale announced Tailcat on **August 31, 2026** as a Go library and CLI using its data-plane components without its hosted control plane or account model.[25]

The current README describes userspace operation without TUN/routing changes, WireGuard encryption, DERP bootstrap/fallback, local TCP forwarding, and saved or ephemeral identities. Public relay service is rate-limited and an operator can run a separate DERP. Browser support is currently relay-only. An address can contain credential material; it must not be treated as a harmless public device identifier.[33]

The repository declares BSD-3-Clause licensing.[41]

**Assessment:** particularly attractive for an early desktop HTTP/SSH bridge or Go-oriented consumers. Before selecting it, prove native Android/iOS packaging, lifecycle behavior, resource cost, and persistent group authorization. No native mobile SDK was validated in this study. It supplies transport primitives, not the proposed complete user/device trust model.

### iroh — preferred initial evaluation

Iroh is a Rust connectivity library with public-key-addressed endpoints, authenticated QUIC streams and datagrams, NAT traversal, and relay fallback. Its source is dual MIT/Apache-2.0.[43]

Its official FFI project exposes Swift, Kotlin, Node.js, and Python bindings. The current FFI README scopes bindings to stabilized transport APIs rather than all higher-level protocols.[34] The platform/language matrix must be checked per target: a language binding existing does not mean all CPU/OS combinations are shipped. Flutter/Dart is not listed as an official binding in the examined overview; a maintained wrapper remains work to evaluate.[40]

**Assessment:** strongest starting point for an embeddable, multi-language, application-layer product. It avoids making IP routing the public API. Rust and mobile FFI are advantages only if the real target projects can absorb their packaging and lifecycle costs.

**Important default:** iroh is not infrastructure-free by default. Its documentation describes shared relay and DNS/Pkarr infrastructure, encrypted payloads but visible connection metadata, and no production availability/privacy guarantee for shared public relays.[20]

An optional address-lookup component can use the BitTorrent Mainline DHT for signed endpoint records instead of hosted DNS lookup. It is not enabled by default and does not eliminate relay requirements.[21]

### HyperDHT / Hyperswarm / Holesail

HyperDHT provides public-key connections over encrypted Noise streams, discovery and hole punching. It documents configurable bootstrap nodes and says an isolated operational DHT needs at least one persistent node. HyperDHT is MIT-licensed.[9]

Holesail packages TCP/UDP tunneling with a JavaScript API and declares AGPLv3 licensing.[10]

**Assessment:** relevant for JavaScript/Bare-based applications and decentralized discovery. Evaluate mobile runtime integration and restrictive-network behavior, rather than inferring reliability from 'no port forwarding' claims. Record licensing for each chosen package and dependency; this study is not a legal compatibility determination.

### libp2p / WebRTC

libp2p's DCUtR protocol coordinates direct-connection attempts over an existing relay; if the attempt fails, the relay path remains available subject to its limits.[37] Its browser connectivity documentation includes WebRTC and the extra discovery/signaling/relay pieces needed for browser peers.[35][36]

**Assessment:** a stronger candidate if direct browser P2P becomes mandatory, or if the product needs a broad interoperable network protocol stack. For a small personal-device service SDK, I assess the configuration and integration surface as greater than the current needs.

### ZeroTier and Nebula

ZeroTier combines a cryptographically addressed P2P layer with virtual Ethernet, network controllers, and root infrastructure.[17] Nebula is an encrypted overlay using certificate-based enrollment and lighthouse discovery.[39]

**Assessment:** credible network overlays, but lower fit when the primary deliverable is a small application SDK rather than a virtual network. Neither should be mistaken for an accountless, infrastructureless connectivity primitive simply because some data flows directly.

## 3. Recommended architecture — proposed, not implemented

### 3.1 Identity and account model

Use separate concepts:

- **Account identity:** a self-certifying identifier derived from a root public key. It is not a global human-readable username or a UUID used as authentication.
- **Device identity:** an independent key pair for each installation. Never copy one root private key into every device as the ordinary enrollment mechanism.
- **Transport identity:** the selected library's endpoint identity, cryptographically bound to the device membership record.
- **Display name:** editable local metadata, not a globally exclusive claim.

The initial device creates the account and enrollment authority locally. An encrypted recovery export is offered before the identity becomes valuable. Use platform-protected key storage appropriate to each target; verify its actual key/algorithm support rather than promising hardware backing for every transport key.

Only explicitly authorized administrator devices may enroll others. A server, relay, DHT node, or readable public record must never become an enrollment authority by accident.

Changing the account root is a security event. Recovery from device loss and recovery from root-key compromise are different designs; simply replacing a private key must not silently retain the old trusted identity.

### 3.2 QR pairing and membership

Proposed flow:

1. An authorized desktop creates a short-lived, single-use invitation with a nonce and the expected desktop identity, plus rendezvous hints.
2. The phone scans it, generates its own device keys, and establishes an authenticated encrypted pairing session.
3. Both sides bind the invitation, device keys, intended account, and session transcript. Use established authenticated protocols rather than inventing cryptography.
4. The desktop displays the joining device and asks for approval. A short verification code can help detect an unintended joining session.
5. The enrolling authority issues a signed membership record with role and expiry. The phone proves possession of the device private key before receiving privileges.
6. The invitation is consumed; other devices receive a signed membership update through the existing private network.

The QR must not contain an account root secret or a permanent unrestricted SSH credential. Single-use and expiry must be enforced by the invitation issuer, not merely by a timestamp in a UI. A captured QR must not authorize unlimited future enrollments.

Pairing A with B is not enough to authorize C implicitly. The account membership policy must explicitly decide which devices may communicate and which may grant membership. Devices should validate membership locally rather than contacting a privileged central API on every service connection.

### 3.3 Discovery and path selection

Separate three mechanisms:

- **Discovery:** find the endpoint associated with an already-trusted device.
- **Rendezvous / hole punching:** exchange reachability information and coordinate a direct attempt.
- **Relaying:** carry encrypted traffic if a usable direct path cannot be established.

Proposed route preference: local known addresses / LAN discovery, public reachability where available, coordinated NAT traversal, then an explicitly configured relay fallback. Transport libraries may negotiate paths in parallel or start through a relay; do not implement a competing path-selection engine without evidence it is needed.

Cache successful routes, retry on interface changes, and expose the actual selected path. Do not equate an unsuccessful direct attempt with an unauthorized peer.

Use at least these deployment policies:

- **Strict direct/private mode:** no external public discovery or relay dependencies; use configured peers/LAN. Accept unavailable paths.
- **Independent internet mode:** no vendor identity authority; configurable or community-operated discovery and relays. Requires reachable supporting nodes, but not one exclusive operator.
- **Convenience mode:** shared third-party infrastructure for onboarding. Explicit disclosure of metadata, service limits, and dependency.

The second mode is the recommended interpretation of the project goal. Running two self-owned relays improves redundancy but is still self-hosted infrastructure, not automatically a decentralized network. Likewise, a public DHT remains an external network dependency even without one central vendor.

### 3.4 Service authorization

Authorize **a device to use a named service**, not a device to access every port because it joined the group.

A service record should identify its owner, application namespace, protocol version, required capability, and local target. Initially, target only explicitly configured loopback listeners. Do not accept a client-provided arbitrary host/port: that turns a bridge into a LAN pivot or open proxy.

Default-deny rules should distinguish use, publish, administer, invite, and relay privileges. A transport's successful peer authentication does not replace application authorization.

For SSH, forward an existing SSH connection and retain host-key checking and server authentication. Do not implement a shell service or disable SSH authentication just because the outer connection is encrypted.

For web access, a transparent local TCP bridge is preferable to rewriting arbitrary HTTP pages. Validate WebSockets, redirects, cookies, Host/Origin handling, absolute URLs, and certificate expectations with the actual applications. Encryption of the underlying stream does not automatically give the browser a valid HTTPS origin.

### 3.5 SDK and packaging

Proposed SDK responsibilities:

- Create/import/export a local identity safely.
- Create and accept invitations; enroll and revoke devices.
- List trusted devices and permitted services.
- Publish a service and open an authorized stream.
- Open a local port bridge where the platform permits it.
- Report connection path, reconnection state, and actionable failures.

Keep transport types behind a small internal boundary. This allows later replacement without exposing vendor tickets as the permanent account or service identifier. Do not build a generic multi-transport framework in the first release.

Use a shared protocol specification and conformance fixtures for all bindings: encoding, size limits, identifiers, version negotiation, authorization decisions, and error categories. Cryptography, QUIC/WireGuard, and NAT traversal should remain supplied by maintained upstream libraries.

**Desktop:** consider a per-user background agent with authenticated local IPC and a thin SDK client. This can share device membership and transport connections across four applications. It is a local process, not a mandatory cloud server. Running without elevated privileges is a goal, not a claim of tested installation.

**Mobile:** favor an embedded library in each app, sharing account membership through explicit enrollment. Do not promise a universal background daemon shared freely across sandboxed apps. Per-app namespaces and permissions must prevent application A from inheriting application B's SSH capability merely because the account is the same.

**Flutter:** first establish the real target platforms; then evaluate a narrow Rust bridge or native Swift/Kotlin bridge. Verify lifecycle, cancellation, backpressure, memory ownership, packaging, and upgrade support before standardizing an FFI API.

### 3.6 State, revocation, and recovery

Replicate only small signed membership/policy records between trusted devices. Keep the initial authority model simple: one account authority with explicit administrator delegation, monotonic policy revisions, and deterministic update rules. Avoid arbitrary multi-writer policy editing or introducing consensus/blockchain without a demonstrated need.

Revoking a device should reject new connections and terminate existing authorized streams on peers that receive the update. An offline or partitioned peer cannot know about a revocation it has not received. Select an explicit freshness/expiry policy: fail-closed freshness improves revocation bounds but reduces offline availability. Clock skew and expired administrator credentials require deliberate handling.

A DHT is not the source of authorization truth. Do not publish account rosters, enrollment secrets, service catalogs, or revocation authority as public plaintext there. Signed address records still disclose metadata; signatures provide integrity, not confidentiality or freshness by themselves.

## 4. Phone and browser constraints

This is the most important open product decision.

### Native phone application

Iroh exposes official Swift and Kotlin bindings, with platform-specific coverage.[34][40] A native client can use the transport directly, but that is not permission to run perpetually in the background.

Apple documents suspension after normal background transition and bounded additional execution for finishing tasks.[44] Android requires an appropriate foreground-service type and permissions where such a service is used.[22]

**Consequence for the proposal:** start with the phone as an interactive client. Do not promise that it will be an always-reachable relay or server when locked. Test battery, lifecycle, Wi-Fi/mobile handover, suspend, and process death explicitly.

### Phone browser only

Current iroh browser documentation says browser connections use relays because its direct UDP traversal is unavailable in the sandbox.[19] Tailcat's current browser implementation has the same relay-only limitation.[33]

WebRTC/libp2p offers a different browser P2P path, but still needs supporting discovery/signaling infrastructure and fallback design.[35][36]

**Consequence:** 'open any browser, no installed client, no reachable relay, arbitrary web/SSH access' must not be promised as one universal feature. A browser client can speak an application protocol; it cannot transparently give the whole phone's networking stack access to a private device.

### Existing browser or SSH app on the phone

A local bridge may work while its owning process is alive, but opening Safari or another client can background the bridge application. iOS lifecycle limits make that a distinct integration problem, not something resolved by choosing a P2P transport.[44]

Possible product choices are an integrated WebView/SSH client, a tested platform-specific networking extension, or a separately justified OS-level network integration. The last choice moves toward the VPN-like solution the initial brief wanted to avoid. Resolve this before committing to a mobile UX.

## 5. Security boundaries and abuse controls — proposed requirements

- Treat discovery nodes and relays as untrusted for application contents and membership decisions.
- Keep payload encryption end-to-end through fallback paths; authenticate endpoints against approved keys.
- Display that encrypted is not anonymous: direct peers learn addresses and relay operators observe metadata.[20]
- Bound unauthenticated work, connection attempts, stream counts, memory, frame sizes, and invitation attempts.
- Redact secrets and service data from diagnostics. Never log full pairing QR payloads or bearer-style connection tickets.
- Prevent invitation replay, rollback to old membership policies, cross-application capability use, arbitrary target forwarding, and device identity substitution.
- Do not silently expose local bridges on all network interfaces. Default to loopback and require explicit authorization for any wider bind.
- Keep relays from becoming open internet proxies. Specify admission, quotas, expiry, and who pays bandwidth costs.
- Use independent protocol/security review before trusting persistent enrollment or granting remote shell access.

These are design requirements, not claims that a proposed implementation already meets them.

## 6. Evaluation plan before implementation commitment

No experiment below has been run. These are acceptance scenarios for a later, explicitly authorized spike.

### Stage A — settle requirements

Identify the four consuming applications, their languages, OS/CPU targets, native versus browser-only phone access, existing-client requirements, offline behavior, and acceptable supporting infrastructure. Decide whether a stable human-readable name is local or requires a namespace service.

### Stage B — compare upstream transports using minimal existing examples

Run iroh and Tailcat through the same real network matrix, without developing the full product first:

- Two devices on one LAN with external services blocked.
- Desktop broadband to phone on mobile data.
- Different NATs, including a verified restrictive topology.
- UDP blocked with an allowed relay path.
- IPv6 available and unavailable.
- Wi-Fi/mobile transition, desktop sleep/resume, phone background/foreground, and process restart.
- Loss of one discovery provider or relay; strict mode with all configured support paths unavailable.

Measure connection success, time to usable first byte, path chosen, reconnection, throughput, latency, memory, CPU, mobile energy behavior, and package size. Separate failed configurations from successful direct or relayed paths. Do not use shared public relays for load tests without permission.

Proposed deterministic checks: an unauthorized device cannot open a service; an expired or reused invitation fails; a revoked online peer loses access after policy delivery; HTTP and WebSocket work through an allowed bridge; SSH host-key checks remain intact; adding a third device gives only its granted rights; key persistence survives an ordinary restart.

### Stage C — prove portability before freezing the SDK

Demonstrate one native phone-to-desktop service session and one real consuming-application integration. For a Flutter consumer, include the actual Dart/native boundary, not only two Rust or Go command-line peers. Exercise a web application and existing SSH service separately.

Choose one transport after these results. Document failures and operating limits. Do not advertise '100% NAT traversal', 'zero infrastructure', perpetual mobile availability, or production readiness from a successful LAN demo.

### Stage D — product specification and incremental build

After requirements and spike evidence, write protocol/UX contracts; then implement identity enrollment, one service, permissions, restart/reconnect, revocation/recovery, and a second consuming application. Prove the second application can reuse the SDK without copying connectivity code before broadening scope.

## 7. What not to build first

No blockchain, token economy, custom cryptography, full-mesh permanent socket requirement, general subnet router, custom DNS system, generic public reverse proxy, offline mailbox, file replication engine, or both transport backends at once.

No public global usernames without a defined naming authority/conflict policy. No copies of one master private key on every device. No assumption that 'known public key' means 'authorized for SSH'.

## 8. Decision summary

**Proposed baseline:** accountless private service SDK, independent device keys, QR-approved signed membership, application-scoped capabilities, native phone client first, reusable desktop agent, configurable discovery/relay support, and clear direct/private mode with reduced reachability.

**Transport shortlist:** iroh first for SDK and mobile fit; Tailcat as a direct competitor for simple HTTP/SSH and Go integration. Reconsider libp2p/WebRTC if direct browser P2P is mandatory. Use Tailscale/Headscale instead if the actual priority becomes whole-device access from arbitrary existing applications.

**Not yet decided:** final transport, phone OS, UI framework, persistent authority/recovery format, exact FFI API, relay operation/funding, dependency pin, or compatibility with the four consuming projects.

**Recommended next user decision:** identify those four projects and whether phone access means an installed native app, an integrated browser, or Safari/Chrome and existing SSH clients. Then approve a small comparative connectivity spike, not the full build.

## 9. Evidence quality and limitations

Sources below are primary project repositories, official documentation, and the official Tailcat announcement. This is document/source research, not an independent security audit. Upstream statements were not treated as measured local performance.

Some documentation endpoints moved; the old libp2p documentation URLs returned 404 and were replaced with the current official site. Apple's rendered page needed its official documentation JSON endpoint for readable content; a forum request returned a bot-verification page and was not used as body evidence. A Flutter-specific search failed, so no inference of the absence of community bindings is made. No source retrieval failure was replaced with fabricated measurements.

The source manifest records retrieved content hashes and observed upstream commits. An observed branch tip is metadata, not proof that a separately fetched mutable URL was read at precisely that commit. Pin exact reviewed versions during a future spike.

## Sources

[2] https://tailscale.com/docs/reference/connection-types
[4] https://opentunnel.sh
[5] https://raw.githubusercontent.com/pingdotgg/t3code/main/docs/user/remote-access.md
[9] https://raw.githubusercontent.com/holepunchto/hyperdht/main/README.md
[10] https://raw.githubusercontent.com/holesail/holesail/main/README.md
[15] https://headscale.net/stable
[17] https://docs.zerotier.com/protocol
[19] https://docs.iroh.computer/languages/wasm-browser.md
[20] https://docs.iroh.computer/concepts/security-privacy.md
[21] https://docs.iroh.computer/connecting/dht-address-lookup.md
[22] https://developer.android.com/develop/background-work/services/fgs/service-types
[24] https://tailscale.com/docs/concepts/control-data-planes
[25] https://tailscale.com/blog/tailcat
[33] https://raw.githubusercontent.com/tailscale/tailcat/main/README.md
[34] https://raw.githubusercontent.com/n0-computer/iroh-ffi/main/README.md
[35] https://libp2p.io/docs/browser-connectivity
[36] https://libp2p.io/docs/webrtc-browser-connectivity
[37] https://raw.githubusercontent.com/libp2p/specs/master/relay/DCUtR.md
[39] https://raw.githubusercontent.com/slackhq/nebula/master/README.md
[40] https://docs.iroh.computer/deployment/other-languages.md
[41] https://raw.githubusercontent.com/tailscale/tailcat/main/LICENSE
[42] https://raw.githubusercontent.com/pingdotgg/t3code/main/docs/internals/t3-connect.md
[43] https://raw.githubusercontent.com/n0-computer/iroh/main/README.md
[44] https://developer.apple.com/tutorials/data/documentation/uikit/extending-your-app-s-background-execution-time.json
