# One HTTPS name per host on your own server

Use a domain you control, for example `hosts.example.com`. A gateway on your own
public server assigns `node.hosts.example.com`, `laptop.hosts.example.com`, and
other stable names to paired T3 hosts. All names can share TCP 443. Android uses
normal T3 HTTPS/WebSocket connections and its normal authentication; it needs no
OmaBridge library or modified app.

This feature requires a build advertising `gateway-domain` in `manage read`.
It is implemented in this source tree; do not assume an older release has it.
Upgrade and restart the gateway daemon, not only its CLI: setup checks the live
daemon capability and refuses an older writer. Do not downgrade a gateway with
reserved names to a version that does not enforce ownership.
Domain setup uses the shared management API. Existing ot3 gateway-open operations
that omit a hostname use this server policy automatically for **new** T3 gateways.
There is not yet a graphical domain-setup wizard or a DNS-provider provisioning API.

## Security and trust model

- Pairing alone never publishes a service. The host must grant the gateway `t3`
  access **and** consent to public exposure; an operator then enables its gateway.
- The gateway is Internet-facing. T3 must require authentication even for loopback
  callers. Check this before publishing; the tunnel reaches T3 from loopback.
- TLS terminates on your gateway. That server can see application traffic before
  forwarding it over authenticated, encrypted QUIC to the host. Only use a gateway
  you trust. This is not TLS end-to-end from the phone to the host.
- SNI selects a configured, fixed host/service. Unknown names fail the TLS
  handshake; wildcard DNS/certificates do not make a catch-all proxy.
- Hostnames are pinned to peer identities and services in `gateway-domain.json`.
  Disabling a route, revoking a peer, renaming a device, or changing the domain
  does not release its old name. Another device with the same display name gets
  an identity suffix. Explicit attempts to take a reserved name are rejected.
- Only the gateway's local administrator can configure its domain. A remotely
  managing device can open only its own service and cannot change the namespace.
- Revocation still closes active streams. Names are not credentials and do not
  bypass T3 login. Do not disable authentication, expose SSH through HTTPS, or
  enable anonymous upstream access to make a failing setup appear to work.
- Back up the private gateway state, including identity, pairings, gateways and
  name reservations. Losing reservations can allow unsafe reuse of cached URLs.
  There is deliberately no automatic name-recycling operation.

## 1. Prepare the server and DNS

You need a public server you administer, Linux/systemd, an OmaBridge build with
this feature, control over DNS, and an automatically renewable TLS certificate.
Use a dedicated unprivileged account, for example `omabridge`. Verify release
checksums or build from the source you reviewed; install the binary root-owned at
`/usr/local/bin/omabridge`. The daemon account must not be able to replace it.

Create a wildcard DNS record:

```text
*.hosts.example.com.  A  YOUR_SERVER_IPV4
```

Start with DNS-only records (no CDN proxy). Publish AAAA only when your entire
listener/firewall path supports IPv6. The current OmaBridge gateway listener is
IPv4; do not publish an AAAA pointing at an unreachable IPv6 service.

Reserve TCP 443 for this gateway and permit inbound 443 in the host and provider
firewalls. Keep administrative SSH restricted according to your server policy.
Do not stop or replace an existing web server automatically. If Nginx/Caddy
already owns 443, use a dedicated gateway IP/server for this standalone setup,
or retain an explicit high port until you design a separately tested front proxy.
The API does not yet model different internal and external listener ports.

## 2. Obtain and renew the wildcard certificate

Obtain a certificate for `*.hosts.example.com` through an ACME client's automated
DNS-01 integration. A wildcard covers one label (`node.hosts.example.com`), not
`a.node.hosts.example.com`. Follow your DNS provider's supported ACME plugin
instructions; there is no universal safe API-token command for every provider.

Use a token restricted to the required DNS zone/challenge records, or delegate
`_acme-challenge.hosts.example.com` to a separate validation zone. Keep DNS API
credentials outside OmaBridge's state, outside the daemon's readable files, and
out of command-line arguments, Git and logs. The ACME client manages renewal.
Let's Encrypt documents [DNS-01 and narrowly scoped credentials](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge).

Make the renewed certificate available in this layout:

```text
/etc/omabridge/certs/hosts/fullchain.pem
/etc/omabridge/certs/hosts/privkey.pem
```

Directories should be owned by root with group `omabridge`, mode `0750`; the
private key should be root-owned, group `omabridge`, mode `0640`. The daemon needs
read access, never write access. A root-owned ACME deploy hook should atomically
replace the files after successful renewal. Test renewal with your ACME client
and monitor its failures. OmaBridge checks for renewed certificates and reloads
its listeners; it does not issue certificates itself. Replacing a certificate may
briefly reconnect streams, so verify the result with an external HTTPS request.

## 3. Run a persistent, restricted gateway

Create `/var/lib/omabridge` owned by `omabridge`, mode `0700`. Initialize its identity:

```sh
sudo -u omabridge /usr/local/bin/omabridge \
  --state-dir /var/lib/omabridge --name gateway init
```

Install `/etc/systemd/system/omabridge-gateway.service`:

```ini
[Unit]
Description=OmaBridge HTTPS host gateway
Wants=network-online.target
After=network-online.target

[Service]
User=omabridge
Group=omabridge
Environment=OMABRIDGE_CERT_DIR=/etc/omabridge/certs
ExecStart=/usr/local/bin/omabridge --state-dir /var/lib/omabridge --name gateway serve --service ssh=127.0.0.1:22
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/omabridge

[Install]
WantedBy=multi-user.target
```

The CLI currently requires a named local service. Declaring SSH above makes it
eligible for **explicit private grants**, but does not grant it to peers. The
pairing flow below grants no reverse access, and public SSH gateways are rejected.
Do not issue SSH invitations from this gateway unless you intend that access.

The [systemd capability settings](https://www.freedesktop.org/software/systemd/man/devel/systemd.exec.html#Capabilities)
allow the non-root process to bind 443 without giving it general root privileges.
Adapt filesystem restrictions if your distribution needs a different layout.

```sh
sudo systemd-analyze verify /etc/systemd/system/omabridge-gateway.service
sudo systemctl daemon-reload
sudo systemctl enable --now omabridge-gateway.service
```

`active` alone is not endpoint readiness: inspect gateway status and test HTTPS
once a host has been published.

## 4. Configure your namespace once

Run management commands as the same account, against the same state directory,
with the same certificate environment as the daemon:

```sh
printf '%s\n' '{"action":"gateway-domain-set","enabled":true,"domain":"hosts.example.com","port":443,"confirmed":true}' |
  sudo -u omabridge env OMABRIDGE_CERT_DIR=/etc/omabridge/certs \
  /usr/local/bin/omabridge --state-dir /var/lib/omabridge manage
```

A readable, currently valid wildcard certificate for exactly this domain is
required. This does not change DNS, open firewall ports, publish any peer, migrate
existing gateways, or prove reachability. Those are deliberate administrator steps.
Use `manage read` to check `features`, `gatewayDomain`, `gateways` and their status.
A hostname without `:443` is returned when the selected port is 443.

## 5. Enroll and authorize each host

On the host, publish T3 with `--t3-runtime /absolute/path/to/server-runtime.json`
so new connections follow T3's current port. Managed publication from a compatible
ot3/OmaBridge build already uses this setting. Preserve existing T3 authentication.

Use the existing [pairing workflow](../README.md#quick-start-reach-a-t3-code-server-on-another-machine):
create an invitation **on the host**, limited to `t3`; transfer the private file
over an authenticated channel; have the gateway accept it; approve the gateway
on the host; complete pairing. Use `manage pair`/`pair-retry` when a device is
already serving so its existing endpoint performs enrollment. Remove temporary
invitation files when done. Do not put invitation contents in tickets or chat.

On the host, explicitly consent to public T3 exposure for this gateway:

```json
{"action":"grant-set","peer":"GATEWAY_ENDPOINT_ID","services":["t3"],"public":["t3"],"confirmed":true}
```

`grant-set` replaces the supplied lists. Preserve any existing grants you actually
intend to keep; do not copy this example over unrelated access decisions blindly.

On the gateway, enable the paired host, omitting `host` and `port`:

```json
{"action":"gateway-set","peer":"HOST_ENDPOINT_ID","service":"t3","enabled":true,"confirmed":true}
```

A host named `Worker` gets `https://worker.hosts.example.com/` when the name is free.
Another Worker gets a suffix from its peer identity. Later device renames and
repeated enables retain the reserved hostname. Existing gateways retain their
old URLs until explicitly migrated; naming policy never silently disconnects them.

ot3 can perform its existing grant/open flow when the gateway permits it to
manage its own exposure. Giving remote management is an additional trust decision,
not a requirement for the manual enrollment above. The hostname configuration
itself remains local to the gateway administrator.

## 6. Verify before using a phone

- Confirm `gateways[].running` is true and `error` is empty.
- Fetch `https://HOST.hosts.example.com/.well-known/t3/environment` with normal
  certificate verification. Compare `environmentId` with the intended host's
  local descriptor. Never use `curl -k` as an acceptance test.
- Without credentials, `/api/auth/session` must not report authenticated access.
- Connect Android using that URL and the normal T3 pairing flow. Verify Wi-Fi to
  mobile-data recovery. The same public URL works from both networks; it is not
  a promise that LAN traffic bypasses the public gateway.
- Test revocation and certificate renewal in a maintenance window. Check your
  service after a planned reboot; do not infer boot readiness from an active PID.

## Operations and limits

Disable a gateway with `gateway-set` and `enabled:false`. Withdraw `public` consent
on the host to close public access even when the gateway is unreachable. Domain
policy `enabled:false` disables future automatic naming, **not existing routes**.
No action automatically deletes name reservations. Maximums: 16 active gateways,
1024 reserved names per state directory. Backups contain private device state.

A shared port can briefly reconnect existing streams when its configured target
set or certificates change. The client uses its existing reconnect mechanism;
OmaBridge never replays application writes. Host outages and loss of phone Internet
cannot be hidden completely. No new domain is deployed by merely building this code.

## Performance and compression

OmaBridge forwards HTTP and WebSocket bytes without buffering full responses or
changing the application protocol. T3's negotiated HTTP compression and WebSocket
`permessage-deflate` pass through, including compressed streaming frames. Android remains unchanged.

For additional compression on the encrypted OmaBridge-to-OmaBridge hop, explicitly
add `--compress-t3` to **both** running peers (host and gateway). This is off by
default and does not alter Android or T3. Managed units/UI do not enable it
automatically; add the flag to their actual ExecStart configuration if appropriate.
A peer without the option or an older peer uses the existing raw stream.

The negotiated `deflate-block-v1` transport uses independent blocks up to 32 KiB,
fast DEFLATE, and no dictionary shared between blocks, users, or connections.
Messages below 256 bytes bypass compression; a compressed block is used only
when it saves more than 32 bytes. Incompressible/precompressed data can still
incur compression CPU cost and nine bytes of framing per read. No full response
is buffered and no timer delays sending a partial block. Decoding checks both
lengths, complete stream termination and trailing bytes before forwarding.
Revocation checks remain active during transfers. Library users must use
`Pipe::transfer` / `write_prefix`; exposed `send` and `recv` are raw wire streams.

**Security tradeoff:** opaque tunnel compression cannot distinguish authentication
secrets from attacker-controlled bytes within one block. Independent dictionaries
limit history but do not eliminate compression length side channels. Keep this
option disabled when those can be combined and observed, especially on public
authenticated applications. See [RFC 7692 section 8](https://www.rfc-editor.org/rfc/rfc7692.html#section-8).
Compression reduces bytes for suitable traffic; it does not guarantee lower latency.

The smoke harness verifies gzip and deflate forwarding with isolated fixtures.
Measure transferred bytes, first-byte latency, reconnect latency and CPU under
representative load. Record direct/relay path, payload, concurrency and network
conditions. A small payload saving or one faster request is not a throughput or
latency guarantee. This version still establishes a QUIC connection per forwarded
TCP connection; safe multiplexing would require a separately negotiated protocol
change, not silently enabling replayable 0-RTT or caching authorization.

A bounded credential-free probe is available for your own endpoint:

```sh
python3 -I tools/probe_gateway.py \
  --url https://node.hosts.example.com/ \
  --environment-id EXPECTED_ENVIRONMENT_ID --samples 5
```

It validates TLS and the expected public environment descriptor, refuses redirects,
limits response/decompression size, and reports p50/p95 complete-request latency
plus transferred response bytes. It does not measure authenticated WebSocket
interaction or replace a physical mobile network-switch test.

### Tunnel wire compatibility

The existing `omabridge/service/1` setup adds the optional Open field
`"compression":"deflate-block-v1"`. Only a T3 request offered by an enabled
initiator and accepted by an enabled receiver returns `ready_compressed`.
Missing/unknown offers or disabled receivers return the unchanged `ready`.
Old receivers ignore the new request field; old initiators never receive the new
response. Pair, Hello, Manage and non-T3 services are not compressed.

After acceptance, each direction consists of independent frames: one kind byte
(0 raw, 1 raw-DEFLATE), a four-byte big-endian wire length, a four-byte big-endian
plain length, then the payload. Both lengths must be 1..32768; raw lengths must
match. Compressed payloads must consume the complete input and produce exactly
the declared output. EOF is valid only between frames. QUIC authenticates the
framing and payload; there is no new application replay or credential storage.
