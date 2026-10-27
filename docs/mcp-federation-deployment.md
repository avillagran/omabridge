# Deploying the MCP gateway

This procedure is independent of any installation. All addresses, identities,
paths, unit names and selected scopes come from private operator configuration.
A reserved illustrative MCP URL is `https://gateway.example.com/mcp`; it is not
a default. Never commit real inventories, deployment receipts, endpoint IDs,
policy selections, credentials or private environment files.

## Prepare a candidate

1. Identify the exact source revision, existing MCP units/state and native T3
   runtime through supported management interfaces. Coordinate any shared units.
2. Validate the source with format, Clippy and the relevant test suites. Real
   isolated-T3 fixtures must use fresh private homes, never a personal T3 home.
   Distinguish fixture results from an authenticated production client.
3. Build separately for each target architecture. Run one Cargo build per host.
   Install the artifact at a versioned location without replacing unrelated
   global binaries. Record source, architecture and SHA256 privately.
4. Back up existing private state, unit/drop-ins, required environment files and
   local consent wrappers while preserving permissions. Do not print or publish
   their contents. Record protected process metadata without conversation data.

## Install conservatively

Supply local values explicitly:

```sh
BIN="${OMABRIDGE_BIN:?Select the validated binary}"
STATE="${OMABRIDGE_MCP_STATE:?Select the existing private MCP state}"
RUNTIME="${T3_RUNTIME_FILE:?Select the official local runtime descriptor}"
ENVIRONMENT="${T3_ENVIRONMENT_ID:?Use the verified environment UUID}"
```

When existing consent should follow a local runtime, the supported command
verifies descriptor identity and authenticates before saving nonsecret routing
metadata. It does not renew or copy credentials:

```sh
"$BIN" --state-dir "$STATE" mcp follow-t3-runtime \
  --runtime "$RUNTIME" --environment "$ENVIRONMENT"
```

Preserve the unit's state path, listener, public issuer, environment and event
settings. Change only the executable path in its managed override. Reload the
appropriate service manager and restart only the authorized MCP unit. Leave T3,
client profiles, native publishers and shared transports untouched unless the
operator explicitly includes them in the rollout. Preserve a transient unit's
lifecycle rather than silently enabling it at boot.

On start/readiness failure, restore the previous executable override, reload
and restart only that MCP unit. Do not automatically roll back evolving state or
recreate revoked grants. Keep the candidate and previous binary for recovery.

## Verify the actual runtime

Check all relevant layers; a running process or HTTP200 is insufficient:

- Actual service PID, executable path and SHA256 of the running executable.
- Local listener, TLS and certificate validation on the public URL.
- HTTPS OAuth issuer, authorization/token/registration origins and protected
  resource metadata consistent with the configured public MCP resource.
- Unauthenticated MCP **POST401**. GET may return 405; it is not an auth test.
- Status and authenticated native T3 metadata using existing consent, without
  reading conversation history or issuing test messages to unrelated sessions.
- Fixed environment UUID before authenticated POSTs and the official current
  runtime route. A different identity must never receive the credential.
- Credential, runtime binding and existing grant/config preservation through
  private internal comparisons that never display secret bytes.
- Protected process metadata and shared transport continuity.

A public endpoint without an external OAuth grant is transport-ready only.
Native upstream authentication does not prove the intended MCP client is logged
in, can call the gateway tools, or can receive asynchronous callbacks.

## Policy and initial consent

Create only the administrator-approved initial selection using
[managed catalog administration](managed-catalog.md). A policy is not an external
OAuth grant. Do not infer permission for another host/project from SSH access,
a native discovery row or a different connector's capabilities. Each T3 upstream
still requires its own consent and verified identity.

If an installation uses a private owner-only consent wrapper, configure its
binary/state/connector/policy values locally. It should check the running binary,
validated hash, selected policy, upstream ceiling and expected identity before
issuing a code. Validate its syntax and non-TTY refusal without performing the
secret-bearing interaction in an agent tool transcript. Never embed that
installation's actual values in public scripts or examples.

The owner completes one initial explicit managed OAuth consent through the
client's supported login and official gateway form. Do not recreate its
connector merely to change selections. Verify actual `t3_*` tools, a correlated
round trip to an approved session and revocation behavior. Claim host-to-client
push only after an authorized callback/subscription actually delivers; polling
is a separate capability.

## Private receipt and rollback

Store a bounded receipt in private operator state (0600), recording source,
architecture, running hash, unit/listener references, nonsecret policy metadata,
verification results and unresolved acceptance checks. Store actual installation
history only in an access-controlled journal. Keep the receipt free of tokens,
codes, message text, private keys and secret-bearing URLs.

For rollback, restore only the prior executable override, reload the service
manager and restart the MCP unit. Do not overwrite current OAuth state with an
older backup. A binary without managed-catalog support must be considered
unavailable to managed clients during rollback. Owner wrappers should fail closed
if the active binary or expected policy no longer matches their reviewed setup.
