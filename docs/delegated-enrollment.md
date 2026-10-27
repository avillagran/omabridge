# Delegated T3 enrollment (opt-in)

A selected desktop bridge can publish an authorized remote HOST environment and
ask HOST's own issuer for a new Android session. Android keeps its existing
catalog/Enroll API and pairs only with the selected bridge. No desktop T3 token
is read or copied. This source change does not install, configure or deploy either
bridge; an installed binary must support `delegated-enrollment-v1`.

The owner must consent on each issuing host. An existing `t3` service grant,
management rights, a matching descriptor UUID or desktop discovery alone does
not authorize delegation. The selected desktop is trusted to assert the
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

## Verification

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
