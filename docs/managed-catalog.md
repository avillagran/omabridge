# Managed catalogs with one OAuth connection

A managed catalog lets an administrator change the selected environments,
projects and sessions without recreating a connector or issuing another OAuth
token for each selection change. The client explicitly consents to this mode
once, with a fixed `read` or `operate` ceiling. Existing static grants retain
their original restrictions and never migrate automatically.

## Authorization contract

OAuth registration, resource URL, bearer token, tool names and input schemas
remain stable while policy changes. `t3_list_environments` and
`t3_list_projects` return current data. Every managed tool call requires an
`environment_id`, even when the selection is empty. An empty selection grants
nothing; it never falls back to the legacy local upstream.

Policy selects exact environment UUID → project ID → session IDs tuples.
`--all-sessions` is an explicit per-project choice. `--all-projects` is not a
substitute for selective administration. No MCP tool can change policy, link
credentials, issue grants or answer T3 approvals.

Effective access intersects the initial OAuth ceiling, policy ceiling, current
selection, any attached native catalog permission, independent T3 MCP consent,
credential expiry and verified environment identity. A policy entry does not
create a peer grant or T3 credential. The existing native catalog remains the
discovery source; policy is an authorization selection, not another host registry
or conversation history.

Policy is re-read for tools, subscriptions, watcher polls and callback attempts.
Revision snapshots are checked around reads and sends and before results leave
the gateway. A guard runs after descriptor I/O immediately before authenticated
T3 POSTs, including initialization and retries. Callbacks recheck authorization
and subscription state after DNS resolution. A changed revision cancels queued
webhook payloads, including across removal and re-addition. Known session/run
IDs and idempotency receipts do not bypass current authorization.

A message already accepted by T3, an accepted queued message, or a callback
already transmitted cannot be undone by later withdrawal. Whole-policy revisions
conservatively cancel pending webhook retries even for unrelated additions.
Subscriptions retain their filters and may receive newly authorized future
events; payloads from an older revision are not replayed.

## Administrator CLI

Supply all installation-specific values through local configuration. The names
below are shell parameters, not defaults or example credentials:

```sh
BIN="${OMABRIDGE_BIN:?Select the validated binary}"
STATE="${OMABRIDGE_MCP_STATE:?Select the existing private MCP state}"
POLICY="${OMABRIDGE_POLICY_ID:?Choose a policy identifier}"
ENVIRONMENT="${T3_ENVIRONMENT_ID:?Use the verified environment UUID}"
PROJECT="${T3_PROJECT_ID:?Select an authorized project ID}"
SESSION="${T3_SESSION_ID:?Select an authorized session ID}"

# Bootstrap only: do not recreate an existing policy.
"$BIN" --state-dir "$STATE" mcp policy-create --policy "$POLICY" --access operate
"$BIN" --state-dir "$STATE" mcp policy-allow --policy "$POLICY" \
  --environment "$ENVIRONMENT" --project "$PROJECT" --session "$SESSION"
"$BIN" --state-dir "$STATE" mcp policy-show --policy "$POLICY"
```

`policy-allow` atomically replaces one project's session selection. Repeat
`--session` for an explicit list, or use `--all-sessions` deliberately. It leaves
other projects unchanged. Remove one project with:

```sh
"$BIN" --state-dir "$STATE" mcp policy-remove --policy "$POLICY" \
  --environment "$ENVIRONMENT" --project "$PROJECT"
```

Omit `--project` to remove the whole environment. Further administrator changes
use the same client token while it remains valid. The policy ceiling is fixed
at creation. Changing the initial OAuth ceiling or migrating a static grant
requires new explicit consent.

Updates use the existing private gateway lock and atomic fsynced writes in
`managed-policies.json` (0600). `policy-show` prints only IDs, access and revision.
Missing, corrupt or unsafe policy denies managed operations; static grants keep
their original behavior. Do not edit policy JSON or restore older grants as an
implicit permission renewal.

## Initial private OAuth consent

Configure the connector once with the gateway's public HTTPS MCP URL, for
example the reserved illustrative URL `https://gateway.example.com/mcp`.
Use the actual URL from private deployment configuration. After reviewing the
policy, the owner runs this in a private terminal, never an agent transcript:

```sh
scripts/mcp-private-consent.sh "$BIN" "$STATE" grant-managed "$POLICY" \
  --access operate --label managed-client --ttl-days 1 --code-ttl 600
```

The helper explains mutable selection and displays the consent command for
local review. It refuses non-TTY execution. Enter the resulting single-use code
only into the gateway's official OAuth form; do not paste codes, tokens or return
URLs into chat, screenshots, logs or source control. Use the MCP client's own
supported OAuth login flow for its existing connector name, without recreating
configuration on each policy edit.

Natural token expiry and revocation remain effective. The gateway has no
refresh-token flow; this feature does not promise a permanent bearer. Verify
actual tool availability and a scoped round trip in the intended client after
initial consent. A different client's native host tools are not evidence of
this gateway's OAuth authorization or asynchronous callback capability.

## Validation and rollout

`tests/mcp_gateway.rs` covers the same token across project/host changes, known-ID
withdrawal, stable tools after restart, read ceilings, static compatibility,
native catalog withdrawal, concurrent policy edits and authorization races,
subscription verification withdrawal, signed retry cancellation and revocation.
`tests/mcp_managed_policy_cli.py` checks administrator commands in fresh private
state without issuing OAuth codes. `tests/mcp_federation_live.py` supports
`OMABRIDGE_TEST_MANAGED_CATALOG=1` for isolated real-T3 same-token validation.
Fixtures are not evidence of a production client connection.

Follow the [generic deployment procedure](mcp-federation-deployment.md). Keep
actual endpoint addresses, inventories, hashes, policy selections and deployment
receipts in private operator state or an access-controlled journal, never here.
