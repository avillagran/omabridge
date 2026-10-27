# Scoped MCP environments

For one connection with dynamic administrator selection, see
[Managed catalog consent](managed-catalog.md). This mode requires explicit initial
consent; existing static grants described below never adopt it automatically.

The gateway can select between separately authorized T3 MCP upstreams using a
stable environment UUID. Routes can follow an existing native remote catalog; MCP authorization remains explicit.
T3 remains the only source of history. Existing grants with no `environments`
field remain local-only; `--all-projects` never discovers or authorizes hosts.

## Authorization and routing

`mcp link-t3 --environment <uuid> --t3-url http://127.0.0.1:<port>` links one
credential slot through T3's existing OAuth. Supply pairing codes only through
the existing secure stdin flow. A remote T3 needs an explicitly authorized
OmaBridge loopback forward; the MCP client cannot supply a URL. The public T3
descriptor must match the UUID before linking and before authenticated calls.
Missing, expired or revoked credentials are not automatically recreated.

`mcp grant --environment <uuid> [--environment <another-uuid>] --project <id>
--session <thread-id> --access operate` creates an explicit grant over those
environments, with the same project/session restrictions on each. Use
`--all-projects` only when every project in each listed environment is intended.
The existing one-time link code and OAuth PKCE approval still apply. Never paste
the code or resulting token into a chat or commit it. Refresh the connector after
changing the tool catalog or authorizing a federated grant.

Federated clients receive `t3_list_environments`. Every other tool requires
`environment_id`; results include it. Keep the environment with session IDs, run
IDs and cursors. Unknown environments are rejected before network calls.
Environment-specific ledger keys and T3 command keys isolate colliding IDs and
retries. The upstream runtime ceiling, client access level and project/session
restriction all apply. Sends always use `queue`. No tool answers approvals.

Grants and credential files are re-read between requests. Client revocation is
checked before and after each T3 operation; a revoked read is withheld. A write
already accepted by T3 cannot be undone by subsequently revoking a grant.

## Existing native catalog

On the host running the existing catalog publisher, `mcp use-catalog
--device-state <existing-device-state> --client-id <paired-endpoint-id>` attaches
a reference to its private `client-catalog.json`. No environment registry is
copied. Each call intersects the OAuth scope with the current native peer's T3
grant, environment allowlist, enabled state and descriptor-verified route entry.
This does not mint MCP credentials or turn the catalog's short-lived read-only
enrollment session into an operate grant. Invalid or missing attached policy
fails closed. Without a catalog binding, only explicit local MCP provisioning
and OAuth grants define the available environments.

## Remote catalog and automatic route reconciliation

`mcp use-remote-catalog --device-state <existing-device-state> --bridge-id
<paired-endpoint-id>` selects the existing authenticated QUIC catalog publisher.
It is mutually exclusive with the local publisher binding. The native
`CatalogManager` owns discovery, revision reconciliation, expiry and withdrawal;
there is no second registry. The running device's private control socket performs
catalog reads with its existing identity. If no device is serving, a temporary
endpoint holds the identity runtime lock; a running old controller is never
replaced. Upgrade that controller if it lacks catalog support.

Every tool selection refreshes the peer-scoped catalog, then selects its current
preferred public HTTPS origin. Route changes and renames need no credential-file
rewrite or manual forward restart. DNS is validated and pinned per selection,
redirects are refused, and the environment descriptor is checked before sending
MCP credentials. The credential slot must already have independent MCP consent
for the same environment. Discovery and Android read-only enrollment never mint
MCP operate permission. Cached/offline rows remain visible in native discovery
but cannot authorize a tool or event delivery. A remote catalog is refreshed
again before returning a tool result. An unavailable publisher fails closed.

## Federated webhook events

With events enabled, federated subscriptions require one `environment_id` plus
optional authorized project/session filters. Each host is polled independently
through T3's MCP tools. Baselines and idempotency are namespaced by environment;
colliding project/thread/run IDs cannot mix results. Payloads and detail/status
tool arguments retain `environment_id`. Summaries use the subscriber's scoped
ToolContext and never answer approvals.

Each callback attempt rechecks the current grant, project/session scope,
catalog membership, credential expiry and descriptor identity. Revocation,
withdrawal, identity changes or an unavailable catalog stop queued deliveries.
Callbacks retain the existing public-HTTPS-only, DNS-pinned, redirect-free
Standard Webhooks signing policy. Delivery has bounded retries; this is not an
exactly-once or durable event queue.

## Current boundaries

- Tool calls, run waits/results, incremental `t3_get_events` and webhook events
  route per environment. Linking MCP credentials and consenting OAuth grants are
  explicit setup, never inferred from SSH, admin permission or catalog discovery.
- Automatic remote routing uses the native catalog's verified public HTTPS
  origins. It does not create arbitrary TCP forwards or substitute credentials.
- A linked slot is reported as `linked`, not proof of readiness. Descriptor and
  upstream errors are distinct from an empty project list.
- Real ChatGPT/Dot OAuth, acknowledgement and host communication remain a
  separate acceptance gate. Local fake clients and isolated real T3 tests do not
  establish Dot access or capabilities such as mail, calendar or VM control.

Deployment evidence and rollback: [candidate deployment](mcp-federation-deployment.md).

## Following the official local runtime

After existing MCP consent, `mcp follow-t3-runtime --runtime <absolute official
server-runtime.json> --environment <uuid>` verifies descriptor and authentication
before saving only nonsecret routing metadata. Add `--environment-slot` for a
separately linked slot. Every authenticated POST verifies identity and expiry;
port changes reuse consent, while replacements fail closed. Missing/invalid
runtime metadata never falls back to an old port. An explicitly granted local
UUID may use the primary runtime-pinned local consent in memory; credentials are
never copied to a new slot and a revoked/expired explicit slot is not bypassed.
