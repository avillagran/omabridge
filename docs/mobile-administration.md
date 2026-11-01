# Mobile administration v1

The mobile SDK reuses authenticated QUIC `Manage` requests and the host's existing
explicit per-peer `admin` grant (`manage` in the UI). Pairing, `t3`, all-hosts or
`drafts` permission alone cannot administer a device. The grant is checked by the
receiving device on every request. Do not infer it from cached announcements.

C ABI stays v1: signatures and existing operations are unchanged. Query
`{"op":"capabilities"}` (no handle) for `{abi:1,features:["mobile-admin-v1","shared-drafts-v1","service-request-v1","host-refresh-v1","route-fallback-v1"]}`.
Then use the normal `open`/`pair` flow. All following calls use that handle:

* `{"op":"peers","handle":N}` returns the phone's identity and paired peers,
  including their announced `managed`, service grants and routes. This is a local
  read, not permission to manage them.
* `{"op":"manage","handle":N,"peer":"<device-id>","command":{"action":"read"}}`
  reads the managed device's snapshot: identity, peers, grants/public sharing,
  publications, gateway/domain policy, relay, pending approvals and route metadata.
* Changes require outer `confirmed:true` after the app's user confirmation. Use
  Desktop's same command objects for `rename`, `publish`, `unpublish`, `relay-set`,
  `relay-host`, `gateway-set`, `approve`, `revoke` and now `invite`. `endpoints` is
  also a permitted read without confirmation. Check receiving `features` before
  presenting new capabilities to work with older bridges.
* An invitation command is `{"action":"invite","services":["t3"],"ttl":600,"allHosts":true}`.
  It can delegate only services currently granted to the managing phone. The
  response's `created.invitation` is a **one-time secret JSON invitation** suitable
  for the existing QR/deep-link encoder. Display/share only on explicit user
  action; do not log, put in diagnostics, or persist it as ordinary UI state.
  Remote issuance never accepts `directory`, writes an invitation file or returns
  host paths; `manage:true` is refused. Non-all-hosts issuance works the same way.

The SDK returns the standard `{ok:<remote-result>}` envelope. A host refusal is
`{ok:{error:"omabridge_…"}}`, while input, confirmation and transport failures use
outer `{error:...}`. Handle both. Never display or serialize native error strings.

## Actions that remain on the managed host

| Desktop action | Why it stays host-local |
| --- | --- |
| `identity-create` | A remote peer cannot replace/create the host's identity. |
| `pair`, `pair-retry`, `pair-discard`, `invite-inspect`, `invite-discard` | Local invitation files, outbound pairing intent and filesystem lifecycle belong to that device. Remote invitations use the separate inline result above. |
| `admin-set` | Only the device owner chooses administrators; managers cannot delegate management or revoke another administrator. |
| `grant-set` (including public exposure and `drafts` grants) | Service and public sharing are the owner's decision; manage access must not turn into permission escalation. |
| `bridge-consent-set` | Brokering full T3 access requires the host owner's local consent. It is deliberately absent from `REMOTE_ACTIONS`. |
| Approval of an all-hosts pending request | Only the owner at the inviting device approves broad multi-host access. Remote `approve` checks the actual selected pending invitation, not an earlier UI snapshot. Normal approvals remain remotely manageable. |
| `gateway-domain-set` | Wildcard policy, DNS namespace and name ownership are local authority choices. |
| Explicit `cert`/`key` on `relay-host` | A manager cannot select/read arbitrary files on the host; remote hosting uses certificates discovered there. |
| Direct-only/local-address `relay-set` | Remote relay changes cannot intentionally strand the manager. Public/custom public HTTPS choices retain existing timed rollback. |
| Arbitrary gateway targets/domains, revoking administrators | Remote gateways can expose only the managing device's own services under allowed names; administrators are owner-managed. |
| `sync`, `gateway-check`, nested `remote` forwarding | Local route refresh/probing and orchestration remain local operations. A phone can call the chosen device directly and read authenticated endpoints instead. |

`publish`/`unpublish` still affect only the unit owned by OmaBridge, never foreign
units. Gateway/public grant constraints and relay rollback are unchanged. Neither
mobile administration nor shared drafts enables bridge consent, automatic
all-hosts approval, or changes to deployed services by installing this code.

## Android wiring

Pin/build this commit using `mobile-sdk/build-jni.sh` and the consumer's existing
JNI symbol. Keep the existing catalog handle; call `peers`, then `manage read`
for an explicitly selected device. The owner first enables `admin-set` locally
for the phone's endpoint ID. Bind Desktop-compatible command fields to the mobile
manage panel, require confirmation before mutations, disable host-local controls,
and show those reasons. Render inline invitation JSON with the existing invitation
QR/share flow, and discard it after use. All-hosts approval must direct the user
to the owner device. See [shared drafts](shared-drafts.md) for the separate grant
and composer repository integration; no Android application code is changed here.

## Bridge address refresh (host-refresh-v1)

A phone keeps the address it paired with, and a bridge can move: another relay, a
new home relay, new interfaces. `hostRefresh` asks the bridge for its current
address, without pairing again:

```json
{"op":"hostRefresh","handle":1}
{"op":"hostRefresh","handle":1,"peer":"<device-id>"}
```

Without `peer` it asks the selected bridge (`bridge_not_selected` if there is none).
The result is `{ok:{reachable:bool,changed:bool}}`. It never contains an address.
`reachable:false` covers a bridge out of reach, one that refused and one whose
answer was rejected; what is stored stays as it was in all three. It is a routine
result, not an error.

* It is one authenticated `Hello` on the phone's own endpoint, bounded by the usual
  8-second setup deadline, with no retry. Bridges since the first `Hello` already
  answer it with their live address, so **bridges need no update**.
* **Identity stays the paired key.** The answer is stored only when the QUIC
  connection authenticated that key and the announced address names it. An address
  is a hint: it can only say where to dial, the dial is authenticated again, and it
  never adds a grant or a peer. Addresses go through the same filter as any
  announcement.
* **It cannot lose the way back.** An answer with nothing usable changes nothing,
  and one without a relay keeps the known relay.
* It updates the running catalog manager, so `refresh`, `enroll` and `hostPair`
  (hence renewal) dial the new address at once, and it survives a restart.
* A refused `Hello` learns nothing: a revoked phone gets no address.
* An admin phone's `hostRefresh` is a `Hello` like any other, so it also confirms a
  pending remote `relay-set`.

A phone has to reach the bridge once to learn from it. Move a bridge while the phone
can still dial it, usually on the LAN, and let it refresh before it leaves. Call this
from a worker thread after a catalog failure or recovery, on a network change and
every few minutes while connected, with jitter: SDK calls are serialized.

## Authenticated service HTTP (service-request-v1)

The unchanged C ABI v1 advertises `service-request-v1` in `capabilities.features`.
This production operation is independent of `lab-tls`; `labRequest` remains a
feature-gated laboratory helper. It opens one authenticated bridge tunnel to one
explicit service on one paired peer. The receiving peer checks its current service
grant on every open. An admin, `t3` or enrollment grant does not substitute for a
`desktop-snapshots` grant. The host owner must configure that service separately.

```json
{"op":"serviceRequest","handle":1,"requestId":"snapshot-1","peer":"<device-id>","service":"desktop-snapshots","method":"GET","path":"/v1/session","bearer":"<phone-T3-token>","headers":{"accept":"application/json"},"timeoutMs":15000}
```

* `method`: exactly `GET` or `POST`. `path`: origin-form, at most 4096 bytes,
  beginning with one `/`, with no fragment, scheme or authority.
* `bearer`: required, nonempty ASCII graphic characters, at most 8192 bytes.
  Passed directly as `Authorization: Bearer …`; never written to state, diagnostics
  or logs. The caller must likewise exclude input JSON from logging/persistence.
* Optional `bodyBase64`: standard base64 of at most 512 KiB decoded bytes. GET
  requires an empty body. Optional `headers` is an object permitting only lowercase
  `accept`, `content-type`, `x-t3-orchestration-protocol`; at most 32 entries and
  16 KiB including authorization/framing allowance. Framing/routing/authentication
  headers are SDK-owned. No cookies, proxies, URL credentials or redirects.
* `timeoutMs`: required, 1–120000, covering tunnel setup, send and response read.
  One HTTP/1.1 request per tunnel, no connection pool and no automatic retries,
  including GET, POST, redirects and connection failures.
* Response body is bounded to 512 KiB; response headers to 16 KiB and 64 entries.
  Binary bodies use base64. `headersBase64` is an array of `[lowercase-name,
  base64-value]` pairs preserving repeated headers; authorization, proxy
  authorization and Set-Cookie are excluded.

The usual outer `{ok:…}` envelope contains one of:

```json
{"outcome":"http","httpStatus":403,"headersBase64":[],"bodyBase64":"e30="}
{"outcome":"notSent","reason":"transport"}
{"outcome":"unknown","reason":"timeout"}
```

`http` means a complete, bounded HTTP response, including non-2xx or 3xx status;
Android decides how to handle the status. `notSent` means no application HTTP send
was started (including refused service grants). `unknown` conservatively means the
request may have reached the application but a complete response was not obtained.
The SDK crosses this boundary immediately before handing the request to HTTP,
so even a send error can be unknown. Never automatically repeat a maintenance
POST after unknown; refresh/reconcile application state or ask the user.
Reasons are fixed `transport`, `timeout`, `cancelled`, `response_too_large` codes,
never raw network/parser errors. Invalid inputs use outer `{error:…}` as before.

Call from an Android worker thread. While it is active, another thread can call
`{"op":"cancelServiceRequest","handle":1,"requestId":"snapshot-1"}`. It returns
`{ok:{cancelled:true}}` if cancellation was signalled to an active request, false
if absent/already completed; a completion racing cancellation may still win.
The request's result reports `cancelled` with `notSent` or `unknown` according to
its send boundary. Cancellation closes/drops the tunnel; it cannot roll back a
POST. Request IDs must be nonempty and at most 128 bytes. They are local transient
correlation IDs, never server idempotency keys. Existing calls remain serialized
by the SDK registry; cancellation bypasses that lock. Cancel only after dispatch;
queued requests are not registered yet. `close` waits for the active call; cancel
first when shutting down. Keep bearer and result bodies out of crash reports.

Android integration: pin/build this PR's SDK with the existing JNI C ABI wrapper,
query capabilities, use the paired handle and selected peer from `peers`, then
call `serviceRequest` with service `desktop-snapshots` and the phone's current T3
bearer. Decode `bodyBase64` only for `http`, check `httpStatus`, then parse the
broker JSON. Use POST bodies encoded as UTF-8 JSON/base64 with content-type
`application/json`. Connect coroutine cancellation to `cancelServiceRequest`
from another worker thread. Do not use `labRequest` or persist the bearer in
OmaBridge state. This change does not configure services or change any grants.
