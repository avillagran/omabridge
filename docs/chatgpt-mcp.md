# ChatGPT ↔ T3 Code: the OmaBridge MCP gateway

Status: working, verified against a real T3 Code with Codex. Connecting ChatGPT itself needs a public HTTPS origin (section 6), which you provide.

ChatGPT is one client. Any MCP client that speaks OAuth 2.1 with dynamic client registration (DCR) and PKCE works the same way. For example, a remote machine can reach the gateway through an OmaBridge `mcp` service forward instead of a public origin (section 6.1).

## 1. What T3 Code provides

Reference: T3 Code 0.0.46 nightly, running as `t3 serve` on `127.0.0.1:3773`.

| Topic | What exists in T3 |
|---|---|
| Conversations | Threads (`threadId`) inside projects (`projectId`). Each user message creates a run (`runId`, `ordinal`). The model is event-sourced in SQLite (`userdata/statev2.sqlite`, `orchestration_v2_*` tables). |
| Persistence | Threads, runs, messages and command receipts are durable. On restart, T3 cancels half-finished runs and keeps the queue. |
| Sending to Codex | The `message.dispatch` command reaches `CodexAdapterV2` and then `codex app-server` (`turn/start`, `turn/steer`, `turn/interrupt`). |
| Events | WebSocket `/ws` with Effect RPC (`subscribeThread`/`subscribeShell` with `afterSequence`). |
| Idempotency | Every command carries a `commandId` and is recorded in the receipts table. The MCP `clientRequestId` derives a stable `commandId`. |
| Concurrency | When a thread is busy, a new message is queued, steered into the active turn, or restarts it, depending on the mode. It is never rejected for being busy. |
| MCP | Streamable HTTP at `/mcp` (protocol 2025-06-18). Offers `t3_thread_list/read/send/wait/interrupt`, `t3_pending_request_*`, `t3_project_*`, and more. |
| External auth | T3 has OAuth for MCP (`/.well-known/oauth-*`, `/oauth/mcp/*`), approved with a pairing code (`t3 auth pairing create`). It issues a 30-day `mcp-client` session with a runtime-mode ceiling, revocable in Settings → Connections. |

**Why not connect ChatGPT directly to T3's `/mcp`.** Checked live: a T3 OAuth client receives **all ~85 tools**, including `t3_project_delete`, `t3_project_create`, `schedule_task`, `t3_thread_configure` and `t3_worktree_handoff`, with access to **every** project. T3 also keeps no audit trail of external actions. Exposing it as-is would give the client far more privilege than it needs.

## 2. Architecture

For one stable OAuth connection with mutable administrator-selected hosts,
projects and sessions, see [Managed catalog consent](managed-catalog.md).
This requires explicit initial consent and does not migrate existing grants.

Explicit multi-environment grants and credential slots are documented in
[Scoped MCP environments](mcp-federation.md). Existing grants remain local-only.
Federated tools and webhook subscriptions require `environment_id`; subscriptions
are reauthorized against the same environment/project/session grant.

```
MCP client ──HTTPS (TLS)──► omabridge mcp serve ──loopback HTTP──► T3 Code /mcp ──► Codex app-server
OAuth 2.1 + PKCE            │ transport   (src/mcp/server.rs)        (business logic,
                            │ authn/OAuth (src/mcp/server.rs+store)   history, queue,
                            │ authz+map   (src/mcp/tools.rs)          approvals)
                            │ upstream    (src/mcp/upstream.rs)
                            └ private state <state-dir>/mcp/ (0700)
```

Each layer has one job:

- **T3's internal API.** The gateway only calls T3's public MCP tools with its own `mcp-client` credential. It never touches SQLite or the WebSocket and does not duplicate business rules.
- **MCP adapter** (`tools.rs`). Maps `t3_*` tools to T3's tools, normalizes statuses and always sends in `queue` mode, which never interrupts or steers.
- **Authentication and authorization** (`server.rs`, `store.rs`). Its own OAuth server. Each grant is bound to projects, optionally to specific sessions, and to a `read` or `operate` level.
- **Transport** (`server.rs`). Streamable HTTP with JSON responses and no SSE stream (GET `/mcp` returns 405, as the spec allows). Without TLS it only listens on loopback; a public listener requires `--tls-cert/--tls-key`.

**Single history.** The gateway stores no conversations. It only keeps a ledger (`gateway.json`) of which `client_request_id` produced which `run_id`, to answer retries and reconnects.

## 3. MCP tools

OpenAI requires function names to match `^[A-Za-z0-9_-]+$`, so a tool such as `t3.list_projects` is published as `t3_list_projects`, and likewise for the rest.

| Tool | Access | T3 equivalent | Purpose |
|---|---|---|---|
| `t3_list_projects` | read | `t3_project_list` (filtered by grant) | authorized projects |
| `t3_list_sessions` | read | `t3_thread_list` | sessions with title, agent, model, status and last activity |
| `t3_get_session` | read | `t3_thread_read` | detail and recent runs |
| `t3_get_session_status` | read | `t3_thread_read` | normalized status, active run and pending requests |
| `t3_get_messages` | read | `t3_thread_read` | paginated history (`cursor` → `next_cursor`; `item_id` + `text_offset` for long texts) |
| `t3_get_run_status` | read | `t3_thread_read` (recentRuns) | status of one run |
| `t3_wait_run` | read | `t3_thread_wait` | waits up to 50 s; on timeout the run is not cancelled |
| `t3_get_run_result` | read | `t3_thread_read` (messages) | `final_text` and the messages of that run |
| `t3_get_events` | read | `t3_thread_read` (activity) | incremental events, resumable by cursor |
| `t3_list_pending_requests` | read | `t3_pending_request_list/read` | agent questions and approvals waiting |
| `t3_send_message` | operate | `t3_thread_send` `mode:"queue"` | continues the same session |
| `t3_cancel_run` | operate | `t3_thread_interrupt` | cancels a run |

ChatGPT does not keep server streams open, and T3 offers no push over MCP. For a single conversation, use `t3_get_events` with a cursor and `t3_wait_run` for short waits. To be told when something happens, subscribe to the MCP Events in section 3.1.

### 3.1 MCP Events

With protocol `2026-07-28`, the gateway answers `server/discover` with the `events` capability and serves `events/list`, `events/subscribe` and `events/unsubscribe` on the same authenticated `/mcp` endpoint. ChatGPT Work chats and [dots](https://learn.chatgpt.com/docs/dots) use them: they subscribe with a callback URL and a `whsec_` signing secret, and the gateway posts each matching event there ([OpenAI: MCP Events](https://developers.openai.com/plugins/build/mcp-events)).

| Event | When | Filters |
|---|---|---|
| `t3.run.finished` | A run ended: `completed`, `failed` or `cancelled`. | `project_id`, `session_id`, `statuses` |
| `t3.session.attention_required` | A session started waiting for its owner's approval or answer. | `project_id`, `session_id` |

Without `project_id`, a subscription covers every project of its grant. Every payload carries `host` (the device, `--events-host`, the hostname by default), `project_id`, `session_id`, `session_title`, `run_id`, `session_status`, `pending_request_count`, a `status_check` (`t3_get_session_status`) and a `detail` tool with its arguments. A finished run adds `status`, `t3_status`, `completed_at`, up to 500 characters of the final answer in `summary`, and `started_by_this_connection`. The detail stays in T3 and is read through the tools. An event is a notice, not an authorization: the server instructions ask the client to check the current status before continuing.

How it behaves:

- **Detection.** While subscriptions exist, the gateway polls T3's `t3_thread_list` every `--events-poll-seconds` (5 by default) and reads only the threads whose status, latest run or last update changed. What it saw lives in `<state-dir>/mcp/events.json`, so a gateway restart neither repeats nor loses events. The first poll of a project is a baseline: runs that ended before the subscription are not reported. With no subscription left, the baseline is dropped.
- **Subscribing.** The subscription ID is derived from the grant, callback URL, event and canonical arguments, so a repeated or refreshed request updates the same subscription. Filters are checked against the grant. The callback must be public HTTPS. Before the first subscription for a grant and URL, the gateway posts a signed `{"type":"verification","challenge":…}` and requires the challenge back (`-32015` with `data.reason` otherwise). A success is remembered for 24 hours. The lifetime is 24 hours by default, from 5 minutes to 7 days on request (`ttlMs`), and never beyond the grant. `refreshBefore` is that expiry. Events are not replayable, so `cursor` is `null`.
- **Delivery.** One event per POST, signed with Standard Webhooks (`webhook-id` = `eventId`, `webhook-timestamp`, `webhook-signature`, `X-MCP-Subscription-Id`). Event IDs are stable, and failed deliveries are retried with backoff for about 13 minutes. `410` ends the subscription, and other `4xx` answers are not retried. After a secret rotation, both secrets sign for 10 minutes. Each delivery is authorized again: revoking a grant deletes its subscriptions, and a session outside the grant is never reported.
- **Egress.** Each request resolves the callback host and connects only to a public address, pinned so a second lookup cannot redirect it, with the original hostname for TLS. Redirects are not followed. Requests time out after 10 seconds.
- **Audit.** Subscriptions, verifications and every delivery outcome are recorded, without secrets or payloads.

`--no-events` serves tools only. `omabridge mcp serve` takes the same flags behind a tunnel or with its own TLS.

### Normalized statuses

`t3_status` always carries T3's original value as well.

| T3 | Contract |
|---|---|
| `idle` | `idle` |
| `preparing`, `queued` | `queued` |
| `starting`, `running` | `running` (or `waiting_for_approval` when requests are pending) |
| `waiting` | `waiting_for_approval` |
| `completed` | `completed` |
| `failed` | `failed` |
| `interrupted`, `cancelled`, `rolled_back` | `cancelled` |

### Contracts (from the end-to-end test, identifiers replaced)

`t3_send_message`:
```json
{"session_id":"mcp:<thread-id>",
 "message":"OmaBridge test. Do not run commands or edit files. Reply only with: E2E-CHATGPT-OK",
 "client_request_id":"e2e-<random>"}
```
→
```json
{"session_id":"mcp:<thread-id>",
 "run_id":"run:thread:mcp%3A<thread-id>:ordinal:2",
 "message_id":"message:mcp:client%3A…:thread-send:omabridge%3Agrant_…%3Ae2e-…",
 "delivery":"started","status":"running","t3_status":"starting","duplicate":false}
```
Repeating the call with the same `client_request_id` returns the same `run_id` with `"duplicate":true` and sends no second message. Reusing that ID with different text returns `{"error":{"code":"conflict"}}`.

`t3_get_run_result` → `{"run":{"status":"completed","terminal":true,…},"complete":true,"final_text":"E2E-CHATGPT-OK","messages":[…]}`

`t3_get_messages` (read through the gateway after continuing the thread from T3):
```
0 user_message      OmaBridge connectivity test… E2E-UI-OK          (T3)
2 assistant_message E2E-UI-OK                                         (Codex)
4 user_message      OmaBridge test from ChatGPT… E2E-CHATGPT-OK      (MCP client)
5 assistant_message E2E-CHATGPT-OK                                    (Codex)
7 user_message      Continued from T3 Code… E2E-T3-CONTINUE-OK       (T3)
8 assistant_message E2E-T3-CONTINUE-OK                                (Codex)
```

Real authorization (Codex in `approval-required` asking to run `ls`): `t3_wait_run` returned `waiting_for_approval`, and `t3_list_pending_requests` returned `{"approvals_waiting":1,"how_to_answer":"Open this session in T3 Code to approve or answer; this connection cannot grant approvals."}`. Then `t3_cancel_run` answered `interrupt_requested` and the run ended `cancelled`.

Errors arrive as a tool result with `isError:true` and `{"error":{"code":…,"message":…}}`. The codes are `forbidden`, `not_found`, `invalid_arguments`, `conflict`, `rejected_by_t3`, `t3_<T3 code>`, `upstream_unavailable` and `gateway_not_linked`. A session in an unauthorized project returns `not_found`, so its existence is not revealed.

## 4. Security

- **Authentication is mandatory.** Any `POST /mcp` without a token gets `401` with `WWW-Authenticate: Bearer resource_metadata=…`.
- **ChatGPT-compatible OAuth 2.1.** Includes RFC 9728 (`/.well-known/oauth-protected-resource[/mcp]`), RFC 8414, dynamic client registration with an HMAC-signed stateless `client_id`, mandatory PKCE S256, `iss` on every redirect (RFC 9207, `authorization_response_iss_parameter_supported:true`) and `resource` validation (the token is bound to `<origin>/mcp`).
- **Human approval.** The authorization page requires a single-use **link code** of 100 bits, valid for 10 minutes by default, generated by the administrator on the host. The code fixes the projects, sessions and access level. There is no unrestricted administrative access.
- **Redirects.** Only `chatgpt.com`, `chat.openai.com` and loopback are accepted. Other hosts can be added with `--allow-redirect-host`.
- **Additional defenses.** After 20 failed attempts in 10 minutes it locks temporarily. `Origin` is checked against DNS rebinding, and bodies are bounded (1 MiB for MCP, 64 KiB for OAuth).
- **Revocable tokens.** Stored only as SHA-256. `omabridge mcp revoke <grant>` deletes the tokens with immediate effect. The T3 credential can also be revoked in Settings → Connections or with `t3 auth session revoke`.
- **Two permission ceilings.** The grant decides which projects and sessions are visible and whether writing is allowed. The gateway's T3 session (default `approval-required`) prevents writing to threads with a broader mode (`runtime_mode_escalation_denied`).
- **Codex approvals.** Resolved only in T3 Code. By design, the gateway offers no approval tool.
- **Audit.** `audit.jsonl` (0600) records grant issuance and approval, tokens, rejections and every tool call with grant, client, session, `run_id`, `client_request_id`, result and error code. It stores no message text (only its length and SHA-256), tokens or codes.
- **Secrets.** They live only in the state directory (0700/0600), never in the repository. The T3 pairing code is read from stdin, not argv.
- **No escalation through content.** Scope is fixed in the grant at approval time. Nothing returned by repositories or history can change it, and the server instructions tell the client to treat that content as data.

## 5. Setup

Link the gateway to your local T3 once. The pairing code goes straight from T3 to the gateway through a pipe and is never printed. Granting only the orchestration scopes is enough:

```sh
S=$HOME/.local/share/omabridge-mcp
t3 auth pairing create --ttl 5m --label omabridge-mcp-gateway \
    --scope orchestration:read --scope orchestration:operate --json \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["credential"])' \
  | omabridge --state-dir "$S" mcp link-t3 --t3-url http://127.0.0.1:3773 --access approval-required
omabridge --state-dir "$S" mcp status
```

To authorize a project, and optionally only some sessions:
```sh
omabridge --state-dir "$S" mcp grant --project <projectId> [--session <threadId>]... --access operate --label chatgpt
# → {"link_code":"XXXXX-XXXXX-XXXXX-XXXXX","code_expires":…,"scope":{…}}
```
To authorize every project, including ones created later, use `--all-projects` instead of `--project`. Tools then need `project_id` where they would otherwise default to the only project, and event subscriptions without `project_id` cover every project.

The code is secret and single-use. It is entered on the authorization page the client opens.

Administration:
```sh
omabridge --state-dir "$S" mcp grants
omabridge --state-dir "$S" mcp revoke <grant_id>
omabridge --state-dir "$S" mcp audit --limit 50
```

## 6. Connecting ChatGPT

ChatGPT connects from its own servers, so the gateway needs a stable **public HTTPS origin**. A stdio or loopback-only server does not work for it. The public URL is part of the OAuth `resource`: if it changes, reconnect.

1. **Publish HTTPS** with one of these options:
   - A tunnel that terminates TLS outside, with the gateway on loopback, for example a named Cloudflare tunnel to `http://127.0.0.1:8787`, or Tailscale Funnel.
     ```sh
     omabridge --state-dir "$S" mcp serve --listen 127.0.0.1:8787 --public-url https://t3-mcp.example.com
     ```
   - Your own TLS, with a domain and certificate:
     ```sh
     omabridge --state-dir "$S" mcp serve --listen 0.0.0.0:8443 --public-url https://t3-mcp.example.com:8443 \
       --tls-cert /path/fullchain.pem --tls-key /path/privkey.pem   # key 0600
     ```
   Ephemeral URLs (`trycloudflare.com`) work for a test but change on every restart.
2. **Generate the link code** with `mcp grant` (section 5) for the projects or sessions to expose.
3. **In ChatGPT**, go to Settings → Apps/Connectors → Developer mode (or "Create app") → custom MCP server.
   - URL: `https://t3-mcp.example.com/mcp`
   - Authentication: **OAuth**. No client ID or secret is needed: ChatGPT uses DCR.
4. ChatGPT opens the **"Authorize access to T3 Code"** page. Check that the destination is `chatgpt.com`, paste the code and press **Approve**.
5. ChatGPT lists the 12 tools, or 10 for a `read` grant. Write tools without `readOnlyHint` ask for confirmation in ChatGPT.
6. When the tools change, refresh the connector in ChatGPT, because it freezes the metadata at creation.

A typical flow: `t3_list_sessions`, then `t3_get_messages`, then `t3_send_message` (keeping the `run_id`), then `t3_wait_run` repeatedly or `t3_get_run_status` later, and finally `t3_get_run_result`.

### 6.1 Other MCP clients over OmaBridge

A machine you control does not need a public origin. Serve the gateway on loopback on the T3 host, publish it as an OmaBridge service granted only to that machine, and forward it there on the same port so the origin matches:

```sh
# T3 host
omabridge --state-dir "$S" mcp serve --listen 127.0.0.1:8787
omabridge --state-dir <bridge-state> serve --service mcp=127.0.0.1:8787
# remote machine, after pairing and approval
omabridge --state-dir <client-state> forward --peer <host-endpoint-id> --service mcp --listen 127.0.0.1:8787
```

The remote client then runs the same OAuth flow against `http://127.0.0.1:8787/mcp` (loopback redirects are allowed) and enters a link code from `mcp grant`. `tests/chatgpt_client.py` is a standard-library client that does exactly this.

## 7. Reconnection and long runs

- A long run keeps going in T3 even if the client disconnects. Keep `session_id` and `run_id` and query later.
- `t3_get_events` only advances `next_cursor` over **finished** items. An in-progress item of the active run is returned in `in_progress` without being consumed, so reconnecting with the last cursor neither loses nor duplicates anything.
- Retrying `t3_send_message` with the same `client_request_id` returns the original `run_id`. The ledger survives gateway restarts, and T3 also deduplicates in its receipts table.
- If T3 restarts, the gateway reopens its MCP session automatically. While T3 is down, calls fail with `upstream_unavailable` instead of hanging.

## 8. Development and tests

| Test | Covers | How to run |
|---|---|---|
| `tests/mcp_gateway.rs` (10) | In-process fake T3: discovery, rejection without auth, single-use code, foreign origin and redirect, project and session scope, pagination, read-only, deduplication, ID conflict, queue without steer, `waiting_for_approval`, lossless events, gateway restart, cancellation, revocation, secret-free audit, mandatory TLS; protocol 2026-07-28 headers and discovery; MCP Events subscription, verification, signed delivery, filters, restart, `410` and revocation | `cargo test --locked --test mcp_gateway` |
| `tests/mcp_events_live.py` (13) | **Isolated real T3** with a local signature-checking receiver: discovery, verified subscription, a real run end delivered once, unsubscribe | `python3 -I tests/mcp_events_live.py <omabridge> <t3>` |
| `tests/mcp_t3_live.py` (19) | **Isolated real T3** (temporary `--base-dir`, never `~/.t3`): real OAuth with T3, foreign project rejected, history, real deduplication, real terminal status, single message in the canonical thread, T3 down and restart, gateway restart, revocation | `python3 -I tests/mcp_t3_live.py <omabridge> <t3>` |
| `tests/mcp_e2e_codex.py` | **Real end-to-end**: ChatGPT-like client → gateway → T3 → Codex → T3 → gateway | `python3 -I tests/mcp_e2e_codex.py <omabridge> <state> <projectId> <threadId>` |
| `tests/chatgpt_client.py` | MCP + OAuth client equivalent to ChatGPT (401 → PRM → AS → DCR → authorize → token+resource → initialize) | library |

## 9. Known limitations

- One gateway links one T3 upstream. `--all-projects` does not federate devices.
  The [universal setup design](universal-setup.md) describes the missing discovery,
  reconciliation and per-environment authorization work. It is not deployed.

- The gateway does not publish a public origin by itself; you provide a domain or tunnel (section 6). Exposing it to the internet is your decision.
- There is no tool to answer questions (`user_input`) or approvals from the client, by security design: they are answered in T3.
- `t3_send_message` does not support attachments, model changes, `steer` or `restart`. It only queues. There is no tool to create a new session; it works on existing ones.
- No refresh tokens: when the grant expires (30 days by default) it must be approved again. T3's `mcp-client` session also lasts 30 days; then repeat `link-t3`.
- Events are not replayable. An event that cannot be delivered within the retries is lost, and the client reads the current state through the tools. Up to the last 10 runs of a thread are checked per poll.
- No CIMD, only DCR. ChatGPT uses DCR when the server does not advertise `client_id_metadata_document_supported`.
- `t3_get_events` uses T3's timeline positions. An already consumed item that T3 later modifies, which is rare, is not emitted again.
