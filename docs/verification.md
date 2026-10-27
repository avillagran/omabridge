# Verification

Use disposable state, fixture providers and loopback listeners for automated
checks. Keep live deployment receipts, host inventories and measured results in
private operator records, not in this source tree.

## Rust and CLI gates

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
python3 -I tests/cli_smoke.py --binary target/debug/omabridge
```

The optional GUI requires its build dependencies and `--features gui`. A build
alone is not visual or physical-device evidence. The mobile SDK and JNI wrapper
have independent packaging requirements in [the mobile guide](mobile-catalog-integration.md).

## Recovery, naming and compression

The Rust tests cover service grants, reconnecting forwards, publication following
the official runtime port, fail-closed missing runtime, stable gateway hostnames,
route withdrawal and explicitly negotiated bounded compression. Existing streams
stay on their accepted targets; recovery never replays an application write.
Compression remains opt-in and defaults off. See [host domains](host-domains.md)
and [performance methodology](connectivity-performance.md).

## Catalog and enrollment

`catalog`, `enrollment` and `delegated_enrollment` integration tests use real QUIC
endpoints with deterministic fixture authorities. They verify peer/environment
binding, explicit consent, expiry, concurrent issuance and revocation. They do not
establish production authority or physical Android access.

The opt-in `catalog_t3_lab` example uses fresh T3 homes and can test two isolated
native T3 instances, cross-host denial, read-only behavior, withdrawal and expiry.
Never point the fixture at personal T3 homes or import provider credentials.

## MCP federation and managed selection

The Rust MCP suites verify project/session/environment isolation, read ceilings,
static grants, managed policy revisions, known IDs/idempotency, callback policy,
concurrent withdrawal, identity changes and OAuth revocation.

```sh
python3 -I tests/mcp_managed_policy_cli.py /absolute/path/to/omabridge
OMABRIDGE_TEST_MANAGED_CATALOG=1 python3 -I tests/mcp_federation_live.py /absolute/path/to/omabridge /absolute/path/to/t3
```

The federation harness runs only fresh isolated T3 homes; optional second-host
configuration must be explicitly provided through its documented environment
variables. Fixtures may end provider runs as failed without a provider login;
this is not a model response. Signed webhook delivery and OAuth are independently
verified; HTTP200/401, process liveness or a test fixture cannot prove access from
an external client. See [managed consent](managed-catalog.md).

## Multi-machine and physical acceptance

The Python standard-library harnesses in `tests/` expose configuration through
environment variables; read each harness before running it. LAN, relay-only, WAN,
JNI/emulator and physical-phone results are distinct. Measure the actual selected
path and canonical identity. Record source/build hash and scope privately. Never
publish URLs bearing secrets, pairing codes, user conversation content or tokens.
