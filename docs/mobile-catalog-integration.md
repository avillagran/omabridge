# Native mobile catalog candidate

This companion builds on PR2, without deploying services or changing existing grants.
It is not a claim that production synchronization or physical Android has been verified.

## Desktop publication

`omabridge catalog-publish --desktop-client /absolute/path/to/omarchy-t3-client
--policy /private/policy.json` polls the fixed `connections-view` command every 30s.
`--once` publishes once. The command is local configuration, never remote input;
no shell is involved. Policy is private/bounded and denies unknown fields:

```json
{"aliases":{"local-primary":"00000000-0000-4000-8000-000000000001"},
 "routes":[{"environmentId":"00000000-0000-4000-8000-000000000001","id":"gateway","url":"https://gateway.example.com/","priority":0}],
 "clients":{"<paired-client-endpoint-id>":["00000000-0000-4000-8000-000000000001"]}}
```

Aliases map local-primary/local IDs to explicit canonical UUIDs; labels never identify
hosts. `localEnabled:false` excludes the primary. Routes must pass the shared portable
HTTPS policy before a no-proxy, no-redirect TLS descriptor request. The descriptor must
match the UUID. An unavailable probe keeps a previously verified route for that identity;
new unverified routes are omitted. Explicit removals still apply during an outage.
Only current paired T3-granted clients in the explicit policy receive environments.
Publication change detection and monotonic revision allocation share the file lock;
unchanged polls do not consume revisions. Desktop read failure preserves publication.
No native/Electron credentials are read by this adapter.

## Mobile SDK

`mobile-sdk` is a separate static library plus JNI wrapper, depending on OmaBridge,
which depends on lib-t3-rust. There is no dependency cycle and no replacement of the
Android application's pinned T3 AAR. `build-jni.sh <host|x86_64|arm64-v8a> <output>`
requires `OMABRIDGE_JNI_SYMBOL` to be set to the consumer's JNI entry point, plus
clean committed source, and records source SHA/ABI/hash. There is no application
namespace default. For a reserved example class `org.example.mobile.NativeBridge`,
set `OMABRIDGE_JNI_SYMBOL=Java_org_example_mobile_NativeBridge_call`; the real
consumer supplies its own value in local build configuration. JNI exports are isolated
from the T3 JNI library to avoid Rust symbol interposition. No release or tag is created.

JSON C ABI operations: `open(stateDir,directOnly?)`, `pair(invitation)`,
`selectBridge(bridgeId)`, `refresh`, `cached`, `projection(local)`,
`enroll(environmentId)`, `close`. All but open take the returned opaque handle.
The selected paired bridge is restored across process restarts. Freshness is checked
at receipt after network I/O; automatic enrollment is projected only after a fresh
authenticated catalog read. State directories must be private app-owned paths; network JSON never selects one.
An identity can be open once in a process. Call from a worker thread. Errors never
include request bodies, invitation secrets or native error strings. The host persists
returned enrollment credentials only in its secure credential store.

Catalog validation uses the pinned Rust reducer's fixed 30-second tolerance for a
publisher's future `issuedAt`, without extending its original absolute expiry or
ten-minute declared lifetime. Safe SDK diagnostics distinguish
`bridge_catalog_invalid_window`, `bridge_catalog_ttl_exceeded`,
`bridge_catalog_from_future`, `bridge_catalog_expired`, and
`bridge_catalog_revision_reused`. This tolerance is discovery-only.

`CatalogManager` persists a reconciled cache, separate manifest TTL and denial flag.
It distinguishes authenticated Denied from transport/source unavailability; cached discovery never
authorizes a T3 connection. Projection keys by stable UUID + bridge/client provenance,
preserves existing managed local IDs, skips independent rows, and supplies stop IDs on
withdrawal/expiry/route change. Host-owned drafts/cursors/selections never enter Rust.

## Enrollment boundary

`EnrollmentAuthority` is an explicit native embedding interface. Default/CLI nodes have
no authority and deny enrollment. Request arguments contain only an environment UUID;
remote endpoint identity and current catalog grant are checked before and after issuance.
An authority must issue a distinct T3 bootstrap per client/environment, enforce read-only
scope, <=5min session expiry and revocation at T3, and never return a desktop bearer.
The SDK redeems via existing lib-t3-rust `/oauth/token`, checking descriptor identity,
read-only scope and bounded issued lifetime. It rejects unbounded/over-scoped sessions.
The SDK samples millisecond wall time again after the QUIC enrollment response,
instead of reusing a timestamp truncated to seconds before the request. Redemption
adds monotonic elapsed time to that receipt timestamp for checks after descriptor
and session reads; credentials expiring during a read are rejected. An expired
enrollment detected after descriptor discovery is rejected before sending its bearer.
Relative pairing TTLs remain anchored before the request, so response latency cannot
extend the local session deadline. There is no clock-skew grace for credentials.

Source evidence: ot3 `src/connection_access.rs` uses `/api/auth/pairing-token` and
scope checks; lib-t3-rust `src/pairing.rs` uses the environment-bootstrap token exchange.
That evidence does NOT establish productive server support for per-client bounded
issuance/revocation. No productive authority implementation is enabled here.

## Evidence tiers

- TLS publisher test -> real QUIC -> native manager/projection: GATEWAY+HOST, alias mapping,
  idempotent polling, rename, withdrawal/recover, descriptor outage, persistent denial.
- Enrollment test -> real QUIC -> fake T3 authority/backend -> real lib-t3-rust pairing
  and HTTP reads: distinct GATEWAY/HOST thread shells, denied cross-environment tokens,
  denied writes, other-client denial and backend + bridge revocation. Backend HTTP is
  isolated loopback; it is not a portable Android route or deployed T3 authority.
- `examples/catalog_mobile_lab.rs` is an opt-in loopback-only emulator fixture for
  JNI/Room testing. Its routes are synthetic `.invalid` values, not live T3 access.
- Android/emulator/JNI build and execution evidence is recorded in the Android HANDOFF.
- No physical device or productive configuration has been inspected/changed.

## Isolated subject-binding witness

T3 nightly3754 (`d2c440312e5f39d59827ed466838a623516454d6`) defines
`AuthSessionState` without a subject, while administrative `AuthClientSession`
records include it (`packages/contracts/src/auth.ts:285,392`). The Android lab
must not assume a subject in `/api/auth/session` or grant its read-only client
administrative access. Its loopback fixture compares the presented bearer's real
session scope/expiry against exactly one administrative client record across all
subjects, then checks the expected desktop/downstream subject. Ambiguous matches
are denied; the witness returns only a boolean. Wrong-host tokens
must fail that witness. Raw client metadata and administrator credentials stay in
the fresh isolated fixture. This changes test evidence, not production enrollment.

## Additive mobile features

The v1 call/free ABI also supports `capabilities`, `peers`, `manage` and `drafts`.
See [mobile administration](mobile-administration.md) and [shared drafts](shared-drafts.md)
for exact grants, security boundaries and client integration. Catalog enrollment
does not confer either management or draft access.
