# T3 pairing over the bridge

`t3-pair` lets a paired device add your T3 Code to its own connection catalog
with OmaBridge alone, like T3 Connect lists an account's environments. Omarchy
T3 Code calls it by itself when a device shares `t3` with it.

## Protocol

A control request `{"op":"t3_pair"}` on the authenticated QUIC connection, with
no arguments. The serving device:

1. Requires the connection's remote endpoint id to hold its current `t3` grant.
   Otherwise it answers `Denied` and T3 is never asked.
2. Resolves the published `t3` target (fixed, or followed through
   `--t3-runtime`) and reads the issuer's environment id from
   `<base>/userdata/environment-id`. The descriptor at that loopback target must
   name the same environment, so a different process on the port cannot be
   paired for.
3. Runs `t3 auth pairing create --base-dir <base> --ttl 2m --label
   omabridge:<peer id> --json` (stdin closed, stderr dropped, 20 s limit) and
   checks the receipt's label.
4. Checks the grant again, then answers `{environmentId, credential, label}`.

The issuer is this user's own T3 Code: `~/.t3`, with the CLI in `~/.t3/bin/t3`,
`~/.local/bin/t3` or the `PATH`. Under `omabridge t3` it is that owned home and
binary. A server without a published `t3` service, or without a T3 CLI, denies
every request.

The asking side checks that the label names its own endpoint id. Errors are
codes only: `omabridge_t3_pair_refused` (denied), `omabridge_t3_pair_unavailable`
(unreachable, or a peer without this request), `omabridge_service_not_granted`,
`omabridge_peer_not_found`, `omabridge_peer_ambiguous`.

## CLI

```sh
omabridge t3-pair --peer <id or name>
```

It goes through this identity's running server when one runs (like `connect`), so
the device keeps one endpoint, and otherwise opens a client endpoint. It prints one
JSON line holding the credential. Pass it to T3's pairing exchange over the `t3`
forward, and do not log it. The `capabilities` answer and `manage` snapshot list
the feature as `t3-pair-v1`.

## Trust and revocation

Granting `t3` is the consent. The pairing becomes a T3 session with T3's default
scopes, the same access as pairing that device by hand. Withdrawing the grant (or
revoking the peer) stops new pairings immediately. Existing sessions belong to
T3: list them with `t3 auth session list` and revoke the ones labelled
`omabridge:<peer>`. Omarchy T3 Code does this on the host on every pass.

A device that never paired with a host can get its T3 through a bridge the host
consented to, under a different label: see
[all-hosts invitations](delegated-enrollment.md#all-hosts-invitations).

## Tests

`cargo test --release --test t3_pair` covers the following over real loopback
QUIC, with a fixture T3 CLI and descriptor:

- a granted device gets a labelled two-minute pairing with T3's default scopes;
- a device granted only `ssh`, or an unpaired one, is refused before T3 runs;
- revocation stops issuance;
- a descriptor naming another environment, or no issuer, is refused;
- a front end gets the pairing through the device's running server.
