<img src="docs/omabridge.svg" width="72" alt="OmaBridge logo: two square links crossed on the diagonal">

# OmaBridge

Private, encrypted device-to-service bridges for your own machines, starting with [T3 Code](https://github.com/pingdotgg/t3code).

OmaBridge pairs devices with short-lived invitations and explicit approval, then carries named services (T3 Code, SSH, an HTTPS API, an MCP gateway) between them over authenticated QUIC ([iroh](https://www.iroh.computer/)). There is no account, no VPN interface and no vendor control plane. Each device keeps its own identity and decides what it publishes and to whom.

> **Status: experimental (0.x).** The wire and on-disk formats may still change between releases. It is not a full mesh VPN and not a Tailscale replacement. Read [What does not work yet](#what-does-not-work-yet) before relying on it.

One Rust library backs two executables:

- `omabridge`: the CLI and runtime. It covers pairing, bridges, the HTTPS egress gateway, a private relay and the T3 MCP gateway, all in a single process with no Python or helper daemons.
- `omabridge-gui` (optional `gui` feature): a local management window that uses the same state and library as the CLI.

## Features

- **Device identity and pairing.** Each device has a persistent iroh identity and private on-disk state (0700/0600). Pairing uses single-use invitations with a TTL plus explicit administrator approval. Grants are per device and per service, with expiry and immediate revocation, which also closes active streams.
- **Service bridges.** `serve` publishes explicitly configured loopback TCP services under names (`t3=127.0.0.1:3773`, `ssh=127.0.0.1:22`). On an approved peer, `forward` opens a loopback-only listener for one of them.
- **T3 Code.** It bridges a loopback T3 HTTP/WebSocket server. T3's own pairing and session authentication still apply; OmaBridge never replaces them. It can optionally launch and own an isolated headless T3 home.
- **Networking.** Devices behind NAT or with private IPs reach each other without opening ports: by default they use n0's public iroh relays, which carry only end-to-end encrypted traffic and see endpoint IDs and IP addresses, and connections upgrade to direct paths when possible. Each device can instead use **its own relay** (`--relay https://…`) or **direct connections only** (`--relay none`); the choice is saved per device. The same binary can host a **private relay** (`omabridge relay`) restricted to an allowlist of endpoint IDs, with TLS mandatory for public listeners. There is no public discovery: peers learn each other's address only from invitations.
- **HTTPS API egress.** `omabridge egress` publishes a bounded, fixed-origin HTTPS gateway. A paired device calls a loopback URL, and the exit host performs DNS, TLS and the request, optionally injecting a Bearer key taken from its own environment. The key never leaves the exit host.
- **MCP gateway for T3 Code** (`omabridge mcp …`). It gives remote MCP clients, such as ChatGPT or another machine through an OmaBridge forward, scoped access to **existing T3 Code sessions**:
  - OAuth 2.1 with DCR, PKCE S256 and RFC 9207/9728.
  - Per-project and per-session grants, approved with a one-time link code.
  - An audit log that contains no secrets.
  - A minimal `t3_*` tool surface. T3 Code remains the only conversation history.

  See [docs/chatgpt-mcp.md](docs/chatgpt-mcp.md).
- **GUI** (`omabridge-gui`): device identity, pairing from an invitation file, approval and revocation, remote routes with a reachability and latency probe, background `systemd --user` units it renders and manages, and the active Omarchy theme palette. It never displays private keys or invitation tokens.

## Install

When available, prebuilt Linux binaries (x86_64 and aarch64) are attached to [GitHub releases](https://github.com/avillagran/omabridge/releases). Verify them with the published `SHA256SUMS`, then place `omabridge` somewhere on your `PATH`.

To build from source you need Rust 1.91+ on Linux. Dependencies are pinned in `Cargo.lock`.

```sh
cargo build --locked --release                                        # omabridge
cargo build --locked --release --features gui --bin omabridge-gui     # optional GUI
cargo test --locked --all-targets
```

## Quick start: reach a T3 Code server on another machine

On the **host** that runs T3 Code on loopback port 3773 (use your T3's actual port):

```sh
omabridge --name host --bind 0.0.0.0:41234 serve --service t3=127.0.0.1:3773
```

While it runs, create a single-use invitation. The file is a secret and is written with mode 0600:

```sh
omabridge invite --service t3 --ttl 300 --output ~/laptop.invite.json
```

Move the file to the **client** over a private channel, then request pairing:

```sh
omabridge --name laptop pair --invite-file ~/laptop.invite.json   # → "pending"
```

Approve the request on the host, then run `pair` again on the client to receive the grant:

```sh
omabridge pending
omabridge approve '<client-endpoint-id>'
```

On the client, open a loopback forward:

```sh
omabridge forward --peer '<host-endpoint-id>' --service t3 --listen 127.0.0.1:0
```

The JSON readiness line prints the local `listen` address. When this device's own server runs (`serve` or the published unit), `forward` asks it over its private control socket to open the listener with the server's endpoint, so the device keeps one identity on the relay; the forward lasts until the `forward` process ends. Point a T3 client at it and complete **T3's own pairing**: an OmaBridge grant does not authenticate a T3 session. To revoke the client later:

```sh
omabridge revoke '<client-endpoint-id>'
```

Global flags: `--state-dir` (default: XDG data dir), `--name`, `--bind`, `--relay` (`public`, `none` or an HTTPS URL; default: the device's saved choice, else `public`; `--relay-url URL` still works). If one device claimed several live invitations, `approve` requires `--invitation-id`. `invite --qr` prints the invitation as a terminal QR code, which you must treat as a secret.

### SSH without open ports

`connect` joins stdin and stdout to a service a paired device granted, so SSH can use it as its ProxyCommand. `--peer` takes the endpoint ID or the device's name when no other paired device has it (case does not matter, and a trailing `.omabridge` is ignored):

```sh
ssh -o ProxyCommand='omabridge connect --peer server --service ssh' user@server
```

Or once in `~/.ssh/config`, for every paired device:

```
Host *.omabridge
    ProxyCommand omabridge connect --peer %n --service ssh
```

Then `ssh user@server.omabridge`. Like `forward`, it goes through this device's running server when there is one. Errors are codes on stderr (`omabridge_peer_not_found`, `omabridge_peer_ambiguous`, `omabridge_service_not_granted`, `omabridge_peer_unreachable`); stdout carries only the service's bytes. SSH still checks the host key and authenticates the user as usual.

### Owned headless T3

Instead of `serve`, the `t3` subcommand starts a separate T3 headless home owned by OmaBridge and publishes it:

```sh
omabridge --name host --bind 0.0.0.0:41234 t3 --t3-binary "$(command -v t3)" \
  --t3-home ~/.local/share/omabridge-managed-t3 --t3-port 43773
```

That home starts empty: it has no threads and no provider logins. T3's startup pairing URL is stored in a private `t3-*.private.log` under the state directory.

## Adding a shared T3 Code to the other device's catalog

A device that holds your `t3` grant can ask for a one-use native T3 pairing over
the bridge, with nothing else open between the two machines (no SSH, port or
account):

```sh
omabridge t3-pair --peer host    # {"environmentId":…,"credential":…,"label":"omabridge:<this device's id>"}
```

The serving device answers only a device whose authenticated endpoint id holds
its current `t3` grant. It checks that the T3 behind its published `t3` service is
this user's own T3 Code (`~/.t3`, or the owned home of `omabridge t3`), then issues
the pairing with that T3's CLI (`t3 auth pairing create --ttl 2m --label
omabridge:<peer>`). The asking device exchanges it through its `t3` forward for
T3's own session, as T3 Connect does for an account's environments. Granting `t3`
is the consent: from then on that device can act in your T3 Code with T3's
default scopes. Withdrawing the grant stops new pairings at once. Sessions
already issued are T3's, labelled `omabridge:<peer>`, and are revoked with
`t3 auth session revoke` (Omarchy T3 Code does this by itself). Treat the
command's output as secret. See [docs/t3-pairing.md](docs/t3-pairing.md).

## Authorized remote T3 catalog enrollment

An opt-in selected bridge can delegate bounded read-only Android enrollment to a
remote host's own T3 issuer, using explicit upstream/environment/client consent.
Android retains one selected bridge and its existing API. See
[delegated enrollment](docs/delegated-enrollment.md) for configuration, trust,
limits and isolated verification. No authority is enabled by default.

## One invitation for all hosts

`omabridge invite --service t3 --all-hosts` lets a phone reach, after one approval
on the inviting device, every host that allowed this bridge with `omabridge
bridge-consent --peer <bridge>`. `omabridge catalog-publish --auto` keeps its catalog
current, leaving out and reporting hosts without a verified HTTPS route. The
read-only enrollment above is unchanged. See
[all-hosts invitations](docs/delegated-enrollment.md#all-hosts-invitations).

## Managing a device from other front ends

T3 Code, the Omarchy Control Panel and bar widgets manage OmaBridge through one command, so validation, confirmation, secrets and the background unit stay in OmaBridge itself:

```sh
echo '{"action":"read"}' | omabridge manage
```

`omabridge manage` reads one JSON request on stdin (at most 64 KiB, never on the command line) and prints the device snapshot: `available`, `version`, `features` (what this build supports, e.g. `forward-through-server`, `connect-stdio`), `identity`, `device` (`{id,name}` or null), `peers` (`id`, `name`, `services` it can reach here, `remoteServices` you can reach there, `admin`: it may manage this device, `managed`: this device may manage it), `pending` (`id`, `name`, `services`, `expires`), `awaiting` (`id`, `name`, `expires`), `published`, `relay` (`mode`: `public`, `custom` or `none`, and `url` for `custom`), `relayHost` (`enabled`, `url`, `running`, `error` and, from `read` while none is hosted, `suggested`), `gateways` (`peer`, `name`, `service`, `url`, `running`, `error`), `gatewayZones` (zones this device holds a wildcard certificate for) and `error`. `read` never creates an identity. Every other action needs `"confirmed":true`, which a front end sends only after the user confirms:

| `action` | Fields | Adds to the snapshot |
| --- | --- | --- |
| `endpoints` (no confirmation) | — | Returns only `{endpoints: [{service, url}]}`: fresh, locally consented gateway routes; no identity creation or network calls. |
| `identity-create` | — | — |
| `invite` | `services`, `qr` (bool), optional `ttl` (60–3600 s, default 600), `directory` (default `~/Downloads`) and `manage` (bool: ask to manage the device that accepts) | `created`: `path`, `expires`, `services`, `manage`, `qrImage` (SVG data URI or null). A secret: show it once and drop it. |
| `invite-inspect` (no confirmation) | `path` of an invitation file | `invitation`: `name`, `expires`, `manage`; never its token or address |
| `invite-discard` | `path` of an `omabridge-invite-*.json` this user created | — |
| `pair` | `path` of an invitation file; `allowManage` (bool) is required when the invitation asks to manage this device | `paired`: `status` (`pending` or `approved`), `name`, while pending `id`, and once approved `admin` |
| `pair-retry` / `pair-discard` | `id` from `awaiting` | `paired` (retry only) |
| `approve` | `peer`, plus `expires` from `pending` | — |
| `revoke` | `peer` | — |
| `publish` | `ssh` (bool), optional `t3` (bool, default: when T3 Code is running), optional `mcp` (bool: true requires the local MCP listener, false removes it, omitted preserves an existing managed MCP publication) | — |
| `unpublish` | — | — |
| `relay-set` | `relay`: `public`, `none` or an `https://` URL | — |
| `rename` | `name` (1–80 characters) | `renamed`: `via` (`service` or `direct`) and, when direct, `reached` and `total` |
| `sync` (no confirmation) | — | `synced`, as `renamed` |
| `admin-set` | `peer`, `allowed` (bool) | — |
| `grant-set` | `peer`, `services`: the published services that device may reach here, and `public`: those it may also expose through its public gateways (never from a managing device) | `announced` |
| `gateway-domain-set` (local administrator only) | `enabled`; when enabled, `domain` and optional `port` (default 443); requires a matching wildcard certificate. Disabling the policy retains existing gateways and name reservations. | `gatewayDomain` |
| `gateway-set` | `peer`, `service`, `enabled` (bool); optional `host` (a name of its own) and `port` | `gateway`: `url`, `port`, `dns` (whether the name already points here) |
| `gateway-check` (no confirmation) | `url` | `gatewayCheck`: `reachable`, `sameEnvironment` (it answers with this device's own T3 Code) |
| `relay-host` | `enabled` (bool); optional `url` (default: the suggestion), and `cert`/`key` paths (default: a Let's Encrypt certificate here that covers the URL's host) | — |
| `remote` (no confirmation for `read`) | `peer` that lets this device manage it, `command`: one of `read`, `rename`, `relay-set`, `publish`, `unpublish`, `revoke`, `approve`, `relay-host` (without `cert`/`key`), `gateway-set`, with that action's fields | `remote`: the managed device's snapshot, without its `awaiting` pairings |

Publishing writes and restarts the single `omabridge-serve.service` user unit, the same one `omabridge-gui` manages; it is off by default. `published` reports `enabled` (the unit exists), `active` (this device is being served), `external` (served by something other than that unit), `stale` (a legacy fixed-port unit no longer matches T3 Code), `followsT3` (the managed unit follows T3's runtime port), `services`, `sshAvailable` and `t3Available`. A unit OmaBridge did not write is never replaced or removed. Managed T3 publications automatically include the runtime file in the unit: new connections follow T3 when it changes port, without restarting the bridge or changing grants. A missing or invalid runtime refuses new T3 streams until it returns, rather than falling back to a stale port; existing streams are left alone. Existing fixed-port units retain their configuration until regenerated by `publish`; updating the binary alone does not rewrite installed units. Explicit `serve --service` targets remain fixed unless `--t3-runtime /absolute/path/to/server-runtime.json` is supplied.

Paired devices keep each other's names, addresses and grants current: whenever a device serves, it announces its name and current address to every paired device it can reach, at start, within seconds of a local network address change, a rename or pairing with a device it can dial, and every five minutes, retrying sooner when a device did not answer, and stores their answers. `rename` and `sync` on a device that does not serve dial its peers once instead. Announcements from unknown or revoked devices are refused. Announced addresses keep only direct addresses that are not link-local, multicast or unspecified, and HTTPS relays with a public host; names cannot contain characters that hide or reorder text.

### Hosting a private relay

A device with a public address can host a private relay for the devices paired with it, inside its running server: `relay-host` with `enabled: true`. Only that device and the devices paired with it may use the relay, checked against its state at every connection, so pairing or revoking takes effect at once. It needs a TLS certificate for the relay's host name. Without a URL, OmaBridge suggests `https://<name>:3341/` for a readable Let's Encrypt certificate in `/etc/letsencrypt/live` whose name resolves to one of the device's public addresses, and uses that certificate; the relay reloads it within seconds when it is renewed. The port must be reachable through the device's firewall. Devices then choose the relay with `relay-set`; a device using a relay must be paired with the device that hosts it.

With a custom relay a device is reached through that relay, and it reaches other devices through whatever relay they announce, so devices keep reaching each other while they move from one relay to another.

### Public gateways for unmodified clients

For stable subdomains on your own server, follow [One HTTPS name per host](docs/host-domains.md): wildcard DNS/TLS, a restricted system service, explicit public consent, and automatic names reserved to device identities. No Android changes are required.

For an unchanged Android app, use a stable HTTPS origin for each T3 environment. OmaBridge on the hosts maintains the tunnel and follows the local T3 runtime port; ot3 manages the paired devices and gateway configuration. The app continues using ordinary T3 HTTP/WebSocket authentication at the same address. Automatic route discovery described below is optional and is not a prerequisite for this deployment model.

Keeping an already configured mobile address requires control of that address's DNS, TLS termination or existing reverse proxy. Installing OmaBridge on another host alone cannot redirect the app's existing connection. A phone network outage or a broken WebSocket still requires the app's existing reconnect/resume behavior; the bridge does not replay application requests or promise uninterrupted sockets across server restarts.

Apps that cannot run OmaBridge, such as the T3 Code mobile and desktop apps, reach a device's service through a gateway: a public HTTPS address on a device with a public IP that pipes each connection into one fixed service of one paired device. The device that owns the service grants it to the gateway device and consents to its public exposure (`grant-set` with `public`), and the gateway device opens the address (`gateway-set`). A device that manages the gateway device may open addresses only for its own services. For now only `t3` can be exposed, and both devices enforce it: a service whose own sign-in protects it, and which grants nothing extra to loopback callers (gateway clients reach the service from loopback).

- **Address.** Each device gets its own address. A device that manages the gateway device may only use a name in one of its wildcard zones (or its public name), never its other domains. With a name of its own (`host`, for example `laptop.vpn.example.net` under a wildcard certificate `*.vpn.example.net` and a wildcard DNS record), names share one port; without it, the gateway's own name gets a random high port. T3 Code clients ignore URL paths, so a path cannot tell devices apart.
- **TLS.** The gateway presents a certificate only for the names it was given, chosen from the name the client asks for (SNI). Scans, plain HTTP, IP-only clients and unknown names never complete a handshake. Certificates are found and reloaded as for a hosted relay.
- **Target.** Fixed by the gateway device's configuration, never by the request, so a gateway is not a proxy. Gateway streams are marked public, and the owning device checks both the grant and its consent to public exposure on every stream, every 250 ms: revoking the gateway device or withdrawing either closes the address at once; the gateway stops listening for it once it learns, within seconds.
- **Authentication.** The service's own: T3 Code's pairing codes and sessions. Anyone who finds the address reaches T3's sign-in, as with T3's own remote access. `gateway-check` confirms an address answers with this device's own T3 Code.
- **Limits.** 16 gateways per device; per port, 128 connections and 16 per client address; per gateway target, 16 streams; 10 s for the TLS handshake, 15 s for the client's first bytes (before anything reaches the owning device) and 2 minutes without traffic. A device's server accepts at most 32 of its 64 connections from any single paired device, and 8 at a time from devices it has not paired with, which get 2 s to state their request. The port must be open in the gateway device's firewall.

Paired gateways automatically announce their service addresses to the owning device. `omabridge manage` with `{"action":"endpoints"}` exports only routes for which that device still grants public access; announcements expire after ten minutes and withdrawn consent clears them immediately. Gateway configuration changes trigger a new announcement. This does not grant T3 access or create a new public gateway.

The companion T3 server integration discovers these addresses through that CLI contract, verifies the public T3 environment descriptor without a credential, and includes matching HTTPS addresses in its native `directEndpoints`. The shared client runtime learns them using its existing pairing or T3 Connect authorization. This requires the companion server/contracts build; installing OmaBridge alone does not add discovery to an older mobile client. No new pairing or manual route entry is needed for an already connected environment after both components support discovery.

Several gateway devices can open addresses for the same service; T3 Code clients keep several routes to one environment. Repeating `gateway-set` with `enabled: true` preserves an existing gateway's host and port when omitted, and accepts its own already-bound port. Reconciliation keeps gateway ordering stable so it does not restart a shared listener merely by reordering its configuration. A gateway retries a failed listener every five seconds, so a transient port conflict recovers without changing its configuration. Local forwards also follow newly learned peer addresses on the same listener. Neither mechanism replays application bytes or restores a broken WebSocket: the client must reconnect and resume its application session.

### Managing other devices

A device can let a paired device manage it. Only the managed device grants or withdraws this, either when it accepts an invitation that asks for it (`pair` then needs an explicit `allowManage`, so a front end must warn first) or later with `admin-set`. A managing device sends `remote` commands, which the managed device checks against its own state: only the actions listed above run there. It can rename the device, publish or stop publishing T3 Code and SSH, approve pairings the device itself invited (granting only what those invitations offered), revoke devices other than managing ones, and switch its relay between public relays and a public HTTPS relay. It cannot create invitations or identities, read secrets, pair the device elsewhere, or change who manages it. A remote relay change is undone after two minutes unless a managing device reaches the device again. Every remote change, and every refused attempt by a device that may manage it, is appended to `manage-audit.jsonl` (0600) in the managed device's state directory, with no secrets; requests from other devices are not recorded, so they cannot flood it. The managed device must be published to receive commands. While the managing device is published, its own front ends send remote commands and announcements through its running server, over a private `control.sock` (0600) in the state directory, so the identity never connects twice and peers keep reaching it.

Managing a device is close to administering it: with publishing and approval, a managing device decides what that device exposes to the devices you approve. Grant it only to devices you control.

`relay-set` saves the device's relay (`relay.json` in the state directory) and restarts its own publishing unit, so new invitations carry the new relay; the unit reads the saved choice instead of a `--relay` flag. With `public` the device is reached through n0's relays, with a URL through that relay; either way it reaches peers through the relay they announce. Peers learn the new address from the next announcement, which a serving device sends when it restarts; devices this one cannot dial (because they never served) keep the old address until they announce themselves.

On failure it prints `{"error":"<code>"}` and exits 1, with nothing on stderr. Codes: `invalid_command`, `invalid_action`, `confirmation_required`, `local_error`, `omabridge_identity_missing`, `omabridge_not_published`, `omabridge_service_not_published`, `omabridge_ssh_unavailable`, `omabridge_t3_unavailable`, `omabridge_nothing_to_publish`, `omabridge_already_running`, `omabridge_unit_foreign`, `omabridge_path_unsupported`, `omabridge_publish_failed`, `omabridge_invite_directory`, `omabridge_invite_unreadable`, `omabridge_invite_invalid`, `omabridge_invite_expired`, `omabridge_pair_denied`, `omabridge_peer_unreachable`, `omabridge_peer_not_found`, `omabridge_request_changed`, `omabridge_relay_invalid`, `omabridge_name_invalid`, `omabridge_manage_consent_required`, `omabridge_not_managed`, `omabridge_not_admin`, `omabridge_remote_forbidden`, `omabridge_peer_is_admin`, `omabridge_remote_unsupported`, `omabridge_remote_failed` and `omabridge_command_failed`.

## HTTPS API egress

Provision the API key privately in the exit host's environment. Then publish a fixed origin:

```sh
OPENAI_API_KEY=… omabridge egress --origin https://api.openai.com --key-env OPENAI_API_KEY
```

Pair a device for the `egress` service, then `forward --service egress`. Requests sent to the local listener go out from the exit host, which injects the Bearer key. Never put a real key in arguments, invitations, logs or issues.

Limits:
- Only bounded GET and POST requests: 1 MiB in, 2 MiB out, 16 concurrent connections.
- No streaming/SSE, redirects, dynamic destinations or `x-api-key` headers.
- The origin must be public HTTPS. Resolved addresses must be public, and they are pinned for TLS.
- API paths are not restricted and there are no budgets, so any granted device can spend the configured key. **Do not use a production or high-spend key.**

See [docs/native-runtime.md](docs/native-runtime.md) for the full flow and for running a private relay.

## Security model

- **Explicit trust.** Every peer is approved by hand, every service is granted separately, and revocation takes effect immediately. Letting a device manage this one is a separate, explicit grant that only this device can give or withdraw.
- **Loopback only.** Forwards listen on loopback. Published targets must be explicit loopback addresses.
- **Secrets stay out of view.** Invitations, keys and tokens are never printed to logs. Private state is mode 0700/0600.
- **Relays see only ciphertext.** A relay only forwards encrypted QUIC and is never an enrollment authority. It does see endpoint IDs and IP addresses; use `--relay none` or your own relay to avoid n0's.
- **A `t3` grant is T3 access.** A device holding it can obtain a one-use native T3 pairing (`t3-pair`) with T3's default scopes. Grant `t3` only to your own devices.
- **All-hosts invitations are opt-in on both ends.** `invite --all-hosts` gives a device write access to every host that consented, once approved. Each host consents once per bridge with `bridge-consent`; a `t3` grant does not imply it, no managing device can set it or approve such an invitation, and the host checks it on every request. A consented bridge is a trusted broker: it can see the one-use pairings it passes on. Withdrawing consent stops new credentials and removes the host from the catalog; sessions already issued (30 days, labelled `omabridge-delegated:<bridge>:<client>`) stay until revoked in T3.
- **No port attestation.** A published loopback port is trusted by address; OmaBridge does not verify which process owns it. Do not publish an untrusted local service under a well-known name such as `t3`.

## What does not work yet

- There is no OmaBridge Android/iOS client or phone QR scanner. An unchanged T3 Android client was reported by the user to reconnect across Wi-Fi/mobile-data switching through the HTTPS gateway; broader mobile reliability is not yet established.
- There is no automatic roster of devices across a group, and no hosted rendezvous or relay service.
- Peers that cannot reach each other at all (neither serves, or both changed relay at once) keep stale names and addresses until one of them can announce itself.
- The egress gateway is not a general HTTP CONNECT/SOCKS proxy, and tunnel compression is off by default. Optional `--compress-t3` on both peers negotiates bounded T3 compression; read the security tradeoff in [the host guide](docs/host-domains.md#performance-and-compression).
- The GUI does not scan QR codes.
- Upstream T3 Code has no OmaBridge integration. A native integration with [omarchy-t3-code](https://github.com/avillagran/omarchy-t3-code) is in progress.

## Documentation

- [Native runtime](docs/native-runtime.md): GUI, egress and private relay.
- [T3 pairing over the bridge](docs/t3-pairing.md)
- [MCP gateway for T3 Code](docs/chatgpt-mcp.md)
- [Verification](docs/verification.md): what has been tested and how, including the multi-machine lab harnesses.
- [Connectivity and performance](docs/connectivity-performance.md)
- [Research](docs/research/README.md): architecture study and SDK contract proposal.

## License

[MIT](LICENSE)
