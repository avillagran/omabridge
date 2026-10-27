# Universal setup and federated MCP

OmaBridge combines native catalog discovery, verified routes and explicit MCP
consent. A [managed catalog](managed-catalog.md) supports one stable OAuth
connection with administrator-selected environments, projects and sessions.
Existing static grants remain static. Follow the
[generic deployment procedure](mcp-federation-deployment.md) and keep actual
installation state and acceptance evidence in private operator records.

## User contract

The user selects the service host and the reachable gateway. OmaBridge should
discover capabilities, prepare the connection, request only missing authorization,
verify the complete path, and reconcile it after network or service changes.
No Android client changes, mandatory LLM account, vendor-specific domain, or
manual port maintenance should be necessary.

Existing transport grants, remote administration grants, T3 credentials, and MCP
client grants are distinct. Having SSH access or pairing two devices must never
silently give an external MCP client access to conversations.

## Reuse the native contracts

The catalog publisher, client manager and enrollment authority already provide
peer allowlists, descriptor-verified routes, revisions and explicit consent.
Reuse those modules instead of introducing a second host registry or history
store. Discovery does not issue MCP operate permission. `--all-projects` extends
projects only within the explicitly authorized environments; it does not discover
or authorize arbitrary devices.

A listener and peer grant alone do not establish a published service. Diagnose
the complete publication/transport/OAuth path. Explicitly restoring a previously
authorized publication is distinct from issuing external client consent.
Publication updates from older clients should preserve an omitted MCP field;
explicit removal must remain effective. A listener never enables publication by
itself.

## Desired implementation

1. **Discover and diagnose.** Read the selected hosts' existing management
   capabilities and consent, service publication, T3 runtime identity/port, MCP
   linkage and expiry, public TLS/OAuth metadata, and connector tool catalog.
   Return per-layer states: healthy, offline, unsupported, consent required,
   expired credential, wrong origin, and connector refresh required. Never label
   an offline host as an empty project list.
2. **Plan and reconcile.** Persist desired host identities, services and public
   routes separately from observed health. Produce an idempotent change plan,
   validate capability versions, and apply through existing management APIs.
   Preserve unrelated services. Use backoff, bounded probes and rollback; never
   recreate revoked grants or replay application writes as a recovery action.
3. **Federate MCP.** Expose one stable OAuth resource with an explicit environment
   selector. List only environments authorized for that client. Route subsequent
   calls by stable environment identity, never caller-supplied URLs. Intersect
   client environment/project/session/access scope with the selected upstream's
   own grant. Recheck authorization on every call and event delivery.
4. **Isolate identities.** Qualify session/run/event cursors and idempotency
   records by environment to prevent collisions. Bind credentials to the verified
   environment. Keep each host's T3 as its sole history source and use its MCP
   contract; do not read SQLite or invent a second conversation database.
5. **Finish onboarding.** Verify authenticated project listing through the same
   public resource the client will use. Report the exact remaining user action
   if client-side OAuth consent or metadata refresh is needed. Do not report
   success based only on a running unit, open port, or cached connector name.

Keep unrelated service tools and their approval policies separate from T3
access. Federation requires its own scoped, revocable client authorization;
existing access to another service does not grant conversation access.

## Optional LLM assistance

The deterministic setup path comes first. When a provider or reverse proxy is
unsupported, generate a portable handoff containing the desired outcome,
verified capabilities, sanitized diagnostic codes, authorized actions, pending
consents, and acceptance checks. Never include credentials, codes, private keys,
conversation bodies, or secret-bearing URLs.

An optional configured LLM may propose a structured plan. It must not execute
arbitrary commands as root or expand scopes. OmaBridge validates the plan against
its allowlisted operations and existing permissions before applying it. DNS or
OAuth credentials are supplied directly to the relevant secure local interface,
not pasted into the prompt. Selecting a remote LLM requires explicit disclosure
of the diagnostic data sent to it.

## Acceptance gates

- Clean setup with a user-owned gateway/domain, without hard-coded personal hosts.
- Two environments with colliding project/session IDs remain isolated.
- Read grants cannot write; unknown environments reveal no project metadata.
- Revoke a grant during a request/event: reject further access, never auto-regrant.
- Restart T3 on another port: recover the same verified environment and fail
  closed on a missing/invalid runtime or changed identity.
- Update publication from an older client: retain explicitly configured MCP.
- One environment down: other environments remain usable; partial status is explicit.
- A stale connector catalog produces a concrete refresh action, not a false
  claim that the project or host does not exist.
- Android LAN/mobile reconnection and public TLS/OAuth checked independently.
- The LLM handoff is secret-free and cannot turn returned content into permission.
