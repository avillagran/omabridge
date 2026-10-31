# Mobile administration v1

The mobile SDK reuses authenticated QUIC `Manage` requests and the host's existing
explicit per-peer `admin` grant (`manage` in the UI). Pairing, `t3`, all-hosts or
`drafts` permission alone cannot administer a device. The grant is checked by the
receiving device on every request. Do not infer it from cached announcements.

C ABI stays v1: signatures and existing operations are unchanged. Query
`{"op":"capabilities"}` (no handle) for `{abi:1,features:["mobile-admin-v1","shared-drafts-v1"]}`.
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
