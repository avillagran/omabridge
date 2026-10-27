# Native runtime and optional management GUI

OmaBridge's reusable Rust library drives the `omabridge` CLI/runtime and the optional `omabridge-gui` management executable. The bridge, pairing, fixed-origin HTTPS gateway and private relay server are linked into the single CLI/runtime binary. The GUI links the same library directly, not a shell or second gateway process. Python files under `tests/` are optional lab orchestration. The `t3` adapter still requires the separately installed T3 application that it launches; T3 is not bundled.

## Management GUI

Build with `cargo build --locked --features gui --bin omabridge-gui`. This pins eframe 0.32.3 behind the opt-in `gui` feature; ordinary CLI builds do not compile it. The GUI reads the same private device directory as the CLI (`--state-dir` or the same XDG default), never parses a secret directly for presentation, and shares the library's atomic snapshot/approval/revocation logic. It is a separate executable, not a claim that every interface is one window or process.

The window exposes the public endpoint ID, currently verified published services, pending requests with exact peer ID and service grant, authorized peers, short-lived 0600 invitation-file creation and confirmation-gated approval/revocation. A missing active publisher is shown as *unverified*, not silently declared connected. Spanish/English labels follow the configured locale and offer an in-window switch. `--check` outputs only public identity and counts for an isolated smoke test without opening a window. Pairing *from* a received invitation and starting/stopping services still require the CLI. Omarchy theme-token synchronization, QR scanning and a distribution installer remain future work.

## HTTPS egress

On the exit host, for a public no-key test:

```sh
omabridge --state-dir "$HOME/.local/share/omabridge-egress" \
  --bind 0.0.0.0:41234 egress --origin https://api.ipify.org
```

This single process owns both the internal loopback HTTP listener and its encrypted named `egress` service. Do not start a separate gateway or a second `serve` process. Create a scoped invitation using the same state directory, pair the requesting device, approve it on the exit host, and pair again. Then on the requesting host:

```sh
omabridge --state-dir "$HOME/.local/share/omabridge-client" forward \
  --peer '<exit-host-endpoint-id>' --service egress --listen 127.0.0.1:0
```

The readiness line gives the local listener address for the consuming application. Requests sent to that loopback address travel through OmaBridge; the exit process resolves the fixed origin and opens the external HTTPS connection. This does not alter the requesting host's default route or block unrelated applications from accessing the Internet directly.

For a provider credential, provision a low-limit test key privately in the exit process's environment, then select it by **name**:

```sh
omabridge --state-dir "$HOME/.local/share/omabridge-egress" egress \
  --origin https://api.openai.com --key-env OPENAI_API_KEY
```

Never substitute a literal key for the environment-variable name. No credential is written into invitations, readiness JSON or the OmaBridge state. Client `Authorization`, `Proxy-Authorization`, cookies, and arbitrary target headers are not forwarded; the exit host injects its own Bearer header. No real provider key or paid model request was used in verification.

### Bounds and trust

- One fixed public HTTPS DNS origin on port 443; no arbitrary target, HTTP CONNECT or SOCKS support.
- GET/POST only; 1 MiB request, 2 MiB response, 15-second request deadline, up to 16 active loopback connections. Chunked input is rejected. Responses are buffered, not SSE/streaming.
- All exit-side DNS answers must pass a conservative global-unicast filter. Addresses are pinned for the request; TLS verifies the configured hostname. Redirects and environment proxies are disabled.
- Only content type and the configured credential are copied to the provider. Request URLs and upstream errors are not logged or echoed as error details.
- Any trusted process on the exit host can access its loopback listener. A device granted `egress` can use supported paths at the origin under the configured key. There are no path-specific permissions, spend budgets or provider account controls yet. Do not use a production/high-spend key.
- SIGTERM/SIGINT stops both the bridge and gateway. Failed or duplicate startup must not leave a helper daemon.

## Private relay in the same binary

A relay forwards encrypted iroh traffic; it is **not** the HTTPS API exit gateway. Initialize device identities first (`omabridge init`) and explicitly allow their public endpoint IDs:

```sh
omabridge relay --listen 0.0.0.0:4443 \
  --tls-cert /private/relay-cert.pem --tls-key /private/relay-key.pem \
  --allow-peer '<device-a-id>' --allow-peer '<device-b-id>'
```

The certificate must be valid for the relay hostname and trusted by the clients. The private key must be a private regular PEM file (0600); symlinks and oversized files are refused. The binary does not issue or renew certificates. An existing private TLS reverse proxy may instead terminate TLS in front of a **loopback-only** `omabridge relay --listen 127.0.0.1:3340 ...`; its upgrade configuration is the operator's responsibility. Public plaintext listeners and empty allowlists are refused. Admitted client receive traffic is limited to 1 MiB/s per connection; admission is based on cryptographically authenticated endpoint IDs, not display names or source IPs.

Devices choose it with `omabridge manage` (`{"action":"relay-set","relay":"https://relay-host:4443","confirmed":true}`, as the Omarchy Control Panel does) or per command with `--relay https://relay-host:4443`; they are then reached through that relay. Without a choice they use n0's public relays. A relay allowlist does not replace OmaBridge service approval: allow both device IDs at the relay and separately grant the requested service on its publisher. Changing this standalone relay's allowlist or certificate requires a restart.

A device's own server can also host a relay for the devices paired with it, without a separate process or allowlist (`relay-host` in `omabridge manage`; see the README).

The Rust suite forces two peers to communicate through the embedded TLS relay with **all direct IP transports disabled**, verifies a byte round trip, and rejects an unlisted peer. This is stronger than inferring relay use from connectivity with a relay merely configured. That self-hosted relay has been verified locally, not deployed as a permanent WAN service. The exit-host/VPS reverse lab still explicitly uses a third-party relay; see `verification.md`.

## Distribution

The deliverable is one executable per CPU architecture, not a universal or fully static binary. Linux system libraries and a working TLS trust store are still required. Rust is needed to build, not to run. No release installer, system service, firewall automation or certificate provisioning is included yet.
