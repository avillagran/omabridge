# Delegated T3 enrollment (opt-in)

A selected desktop bridge can publish an authorized remote HOST environment and
ask HOST's own issuer for a new Android session. Android keeps its existing
catalog/Enroll API and pairs only with the selected bridge. No desktop T3 token
is read or copied. This source change does not install, configure or deploy either
bridge; an installed binary must support `delegated-enrollment-v1`.

The owner must consent on each issuing host. An existing `t3` service grant,
management rights, a matching descriptor UUID or desktop discovery alone does
not authorize delegation. This consent is the JSON policy below and covers the
read-only path only. The write-capable all-hosts path has its own per-bridge bit,
which never widens this one: see [All-hosts invitations](#all-hosts-invitations). The selected desktop is trusted to assert the
allowlisted downstream endpoint identity, and sees the freshly issued bearer.
This is a trusted broker, not end-to-end proof of possession by Android.

## Configuration

Run `serve --enrollment-config /absolute/private/authority.json` on both bridges.
The file must be a bounded regular non-symlink file with mode 0600. Replace all
endpoint/UUID placeholders below with canonical values. Remote peer addresses
come exclusively from the existing paired state, never a client's URL.

Desktop policy (local issuance may also be configured under `local`):

```json
{
  "version": 1,
  "remote": { "HOST_ENVIRONMENT_UUID": "HOST_ISSUER_ENDPOINT_ID" }
}
```

HOST issuer policy:

```json
{
  "version": 1,
  "local": {
    "t3Binary": "/absolute/path/to/t3",
    "ttlSeconds": 120,
    "environments": {
      "HOST_ENVIRONMENT_UUID": {
        "baseDir": "/absolute/owned/t3-directory",
        "descriptorUrl": "http://127.0.0.1:<t3-port>/"
      }
    }
  },
  "delegates": {
    "DESKTOP_ENDPOINT_ID": {
      "HOST_ENVIRONMENT_UUID": ["ANDROID_ENDPOINT_ID"]
    }
  }
}
```

HOST must have paired/granted `t3` to the desktop; desktop must have remembered
that approved issuer peer. This host trust step is distinct from Android pairing.
The existing publisher policy must independently grant that Android endpoint the
HOST environment and a descriptor-verified portable HTTPS route. Desktop
`connections-view` is credential-free discovery; it cannot grant either right.
Unknown issuers, environments, clients and absent authority configuration deny.
A UUID cannot have both local and remote issuers in the same policy. Delegated
policies permit only local HOST issuance, never another delegation hop.

Legacy unversioned `LocalT3Authority` JSON remains accepted. Versioned policy
files reload before and after issuance; atomic replacement withdraws consent
without restarting. Any semantic policy change during an in-flight request
rejects its receipt. Legacy local-only configuration retains its existing
startup-loading behavior and TTL ceiling.

## Bounds and revocation

HOST checks authenticated QUIC upstream identity, its current `t3` grant, and the
explicit upstream/environment/downstream tuple. It verifies its own literal
loopback T3 descriptor, invokes only its configured T3 executable with fixed
`auth session issue` arguments, and requests exactly `orchestration:read` for
at most 120 seconds. T3's subject and label include both bridge and Android
identities (`omabridge:<desktop>:<android>` for subject). The receipt must match
that subject, scope and bounded expiry. Android still verifies the selected HTTPS
descriptor and the actual T3 session scope/expiry before accepting a credential.
No command, base directory, URL, scope or TTL is accepted from a network request.

Each composite authority allows four concurrent requests, with sixteen allowed
attempts per minute per explicitly configured upstream on an issuer. Counters
use monotonic time and bounded keys. Busy requests fail without waiting for a
slot. The transport uses desktop's existing endpoint through its private control
socket; no second endpoint claims the running desktop identity. Both bridges
recheck authorization after awaited issuance. Errors do not contain receipts,
private subprocess output or tokens.

Withdrawing desktop catalog access, host delegation policy or the relevant peer
grant prevents new delivery. **It does not revoke an already issued T3 bearer.**
A rejected in-flight receipt can also leave an undelivered T3 session until its
natural expiry. Existing sessions last at most the configured TTL; immediate
revocation requires T3's own session revocation. There is no issuance ledger or
cross-host immediate-revocation promise in this change. Reconfigure trust using
atomic files; as with normal grant checks, a revoke-and-regrant entirely between
checks is not a historical revocation event log.

## All-hosts invitations

One invitation can opt in to every consenting host, with T3's default scopes
(write access, including `orchestration:operate`) and no per-host QR. It is a
separate path: `Enroll`, `DelegatedEnroll` and `redeem` stay bounded read-only.

**Host consent.** On each host, once per bridge:

```sh
omabridge bridge-consent --peer <bridge>             # allow
omabridge bridge-consent --peer <bridge> --withdraw
```

or the local manage action `{"action":"bridge-consent-set","peer":"<id>","allowed":true,"confirmed":true}`.
It means "allow this bridge to invite devices with full access". It needs a `t3`
grant, but a `t3` grant never implies it. Losing `t3` clears it and a new grant
does not bring it back. Hosts without it are left out. No managing device can set
it (the action is not in `REMOTE_ACTIONS`), and `Hello` only tells the bridge what
the host reported: the host checks its own bit on every request.

**Invitation.** `omabridge invite --service t3 --all-hosts`, or `"allHosts":true`
on the `invite` action. The choice stays on the inviting device, in its `Invite`,
never in the wire `Invitation`, whose unknown fields older devices refuse. Pending
requests show `allHosts` so the approval screen can say what is being given. Only
the owner at this device approves one: remote `approve` answers
`omabridge_remote_forbidden`. A later approval replaces the flag, as it does the
services.

**Requests.** Both are refused with `Denied` and hold no credential in errors.

| Who | Request | Checked |
| --- | --- | --- |
| phone → bridge | `{"op":"t3_host_pair","environment_id":"<uuid>"}` | phone's `all_hosts` flag, `t3` grant, environment in its catalog |
| bridge → host | `{"op":"t3_delegated_pair","environment_id":"<uuid>","client_id":"<phone id>"}` | bridge's consent bit, `t3` grant, environment is this host's |

Both answer `{"result":"t3_host_pairing","pairing":{"environmentId","credential","label"}}`.
Each side checks again after its I/O, so withdrawal during issuance keeps the
pairing from leaving, and allows four at once and sixteen a minute per
authenticated peer. A first enrollment of more than sixteen hosts completes on the
following refreshes. The pairing is T3's own one-use two-minute credential; the
phone exchanges it at the host's HTTPS route (`redeem_pairing`), so the bridge
never holds a session. The bridge does see the pairing in transit, and could
redeem it first: as with the read-only path it is a trusted broker, which is what
the host consented to.

The bridge's own T3 goes through the same request, as an ordinary peer pairing
labelled `omabridge:<phone>`: the phone is a real peer there.

**Label and revocation.** Hosts label these pairings, and the sessions they become,
`omabridge-delegated:<bridge>:<client>`. T3 gives the session the grant's label
whatever the client presents. The prefix deliberately does not start with
`omabridge:`: Omarchy T3 Code revokes every `omabridge:<id>` session whose id is
not a current `t3` peer, and the phone is not a peer of the host, so a plain label
would be revoked within minutes. In turn, **that matcher does not revoke these
sessions**. Omarchy T3 Code must learn to revoke, on the host, each session
labelled `omabridge-delegated:<bridge>:*` whose `bridge` no longer has `t3` and
`bridgeConsent` (from `manage` `read`). Until it does, withdrawing consent stops
new credentials and removes the host from the catalog, but sessions already
issued live on for up to 30 days unless revoked with `t3 auth session revoke`. The
phone stops using a withdrawn row, but that is the phone's own courtesy.

**Routes.** A host tells only consented bridges its own public T3 routes
(`host_routes` in `Hello`, kept as `Peer.remote_routes`). They must be HTTPS on a
public name with no path; anything else rejects the announcement. A route is a
hint: nothing is published before its descriptor answers over HTTPS.

**Publishing.** `omabridge catalog-publish --auto [--once] [--interval N]` needs no
policy or desktop view, and replaces the policy mode on that device. Hosts are the
peers with `t3` that reported consent, plus this device; each UUID comes from the
host's descriptor; clients are the `all_hosts` peers holding `t3`. It writes the
environment → issuer table `all-hosts-issuers.json` and prints a report, one line
per pass:

```json
{"catalogChanged":true,"published":[{"host":"<id>","environmentId":"<uuid>"}],
 "retained":[],"skipped":[{"host":"<id>","reason":"no_route"}],"clientsLeftOut":[]}
```

`skipped` reasons: `no_route`, `descriptor_mismatch` (a malformed identity, or
routes of one host disagreeing), `descriptor_unavailable`, `environment_conflict`
(two hosts naming one UUID; neither is believed), `route_not_portable`, `limit`.
Unlike policy mode, a mismatch skips that host instead of aborting. A failed probe
of a host already published is an outage, not a withdrawal: it stays, under
`retained`.

**Phone.** The JNI op `{"op":"hostPair","handle":H,"environmentId":"<uuid>"}` asks,
redeems and returns `{accessToken, environmentId, expiresAt, renewAfter, scope,
status:"native_authorized", baseUrl, provenance}`. `pair` also returns `allHosts`.
`projection` adds to its plan:

- `hostEnroll`: new environments of an all-hosts bridge. Use `hostPair`, not `enroll`.
- `renew`: native rows within seven days of ending, or already ended. Use `hostPair`
  again: T3 sessions last 30 days and do not extend, so a renewal is a new session.

Rows must pass their local `status`. A row with `native_authorized` or
`native_expired`, with `authorizationExpiresAt`, is exempt from the five-minute
rule: projection never turns it `discovered` or `expired`, never lists it in
`enroll` (a read-only token would overwrite the write token) and stops it only on
withdrawal (`revoked`) or when its session has ended (`native_expired`).

## Verification

`cargo test --locked --test all_hosts` runs the all-hosts path over three real
QUIC endpoints, with fixture T3 CLIs and descriptors.

`cargo test --locked --test delegated_enrollment` exercises two distinct real
QUIC endpoints with an isolated fake T3 CLI/descriptor: original downstream
binding, explicit host consent, host/client boundaries, scope/TTL/subject
rejection, concurrency/rate bounds and revocation during issuance.

The existing `catalog_t3_lab` example now hosts a second issuer for the remote host;
GATEWAY remains local to the selected bridge. Its public lab responses add
`issuerBridgeId`, `delegatedEnvironmentId` and `/delegation-status` with a
completed issuance count, never credentials. The two IDs must differ. Existing
Android lab consumers keep their API. Issuance count measures successful issuer
completion, not proof of receipt by Android.

An optional native smoke test uses fresh isolated T3 homes and normal Enroll:

```sh
cargo build --locked --example catalog_t3_lab
# NEW_ABSOLUTE_LAB_DIR must not exist. Remove its private state after the run.
target/debug/examples/catalog_t3_lab NEW_ABSOLUTE_LAB_DIR /absolute/t3 --self-test
```

It verifies two host shells, read-only write denial, cross-host bearer denial,
T3 subject, withdrawal blocking new issuance while an existing bearer remains
valid, and natural expiry. It prints only fixed boolean evidence. It does not
run providers. Android/JNI integration remains a separate required acceptance
step, as do any consented production configuration and physical-device checks.

## Independent phone administration and shared drafts

[Mobile administration](mobile-administration.md) requires the receiving device's
explicit manage grant; all-hosts approval and bridge consent remain owner-local.
[Shared drafts](shared-drafts.md) use a separate `drafts` service grant to one
explicitly selected bridge authority. Neither API widens catalog/enrollment scopes.
