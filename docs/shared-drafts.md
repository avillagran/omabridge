# Shared drafts protocol v1

An explicitly selected OmaBridge device is the single authority for its owner's
private drafts across T3 hosts. Its persistent endpoint ID is the owner/account
namespace; it is not a T3 environment ID, device display name or repository path.
Every authorized peer sees the same namespace, including drafts whose source T3
host is offline. Independent bridge identities have independent stores. This is
not replication between arbitrary T3 servers.

## Authorization and discovery

Pair to the authority normally. On that device, the owner must explicitly grant
`drafts` to each client. Neither `t3`, all-hosts consent nor `admin` implies this
permission. Revocation is checked on every operation, including reads and receipt
lookups, under the same state lock as the draft transaction. There is no public
HTTP endpoint, filesystem path supplied by a peer, or public gateway for drafts.

The local owner can use `omabridge manage` with `grant-set` to add `drafts` to an
existing peer's `services` (preserve its other services and public grants). A
running bridge is required by that management action. Invitations can include
`drafts` too; accepting them still needs local approval. `drafts` is a virtual
protocol service, not a loopback TCP publication, so it needs no additional port
or systemd unit. Run the usual `serve` with at least one loopback service.

`manage read` advertises feature `shared-drafts-v1` and
`draftStore: {owner, service:"drafts", protocol:1}`. Remote grant announcements and
SDK `peers` identify granted services. A drafts-only client can confirm the owner
with `list` without a manage grant. Persist the explicitly chosen authority ID;
never silently choose another paired bridge or infer identity from a host name.

## API entry points

All use the identical command JSON below:

* Local owner CLI: `echo '<command>' | omabridge drafts`.
* Paired CLI client: `echo '<command>' | omabridge drafts --peer <authority-id>`.
* Desktop: `{"action":"drafts","peer":"<authority-id>","command":<command>}`
  on stdin to `omabridge manage`. Omit `peer` for the local owner. Mutations need
  outer `confirmed:true`; reads (`get/list/watch/receipt`) do not. The CLI drafts
  subcommand treats invocation as confirmation. A serving Desktop uses its
  existing private control socket rather than opening a competing iroh identity.
* Mobile ABI: `{"op":"drafts","handle":N,"peer":"<authority-id>","command":<command>}`.
  The authenticated phone identity must hold the authority's `drafts` grant.

Management/CLI return the protocol result directly. Mobile wraps it in `ok` as
usual. A protocol error is `{error:"draft_…"}` inside that result; transport/ABI
failures are separate. Never log command JSON or responses.

## Scope and payload

Every scope has exactly four strings:

```json
{"environment":"<stable-source-environment-uuid>","project":"<project-uuid>","kind":"thread","id":"<thread-uuid>"}
```

`kind:"stash"` uses an entry UUID for `id`. Identifiers are 1–128 ASCII
alphanumeric/`-_.` characters. Clients must supply canonical stable IDs, never
local aliases, project paths or device names. Owner identity is implicit in the
authenticated authority, never a caller-supplied account field.

```json
{"schema":1,"text":"plain source text","attachments":[],
 "modelSelection":{"providerId":"provider","modelId":"model","effort":"high"},
 "preferences":{"interactionMode":"default","deliveryMode":"send"},
 "selection":[0,5]}
```

Only schema/text/attachments are required. Text preserves the composer's plain
source references, not rendered chip HTML. Optional selection is two nonnegative
UTF-16 offsets, each <=8192. Options are scalar maps with <=16 entries; accepted
keys are `provider`, `providerId`, `model`, `modelId`, `effort`, `interactionMode`,
`deliveryMode`, `permissionMode`, `reasoningEffort`, `speedMode`. Strings <=256 bytes.
No outbox, composition ranges, pending RPCs, tokens, OS descriptors or content URIs.
Unknown fields are rejected, including in commands.

Attachments (<=16) have exactly `{id,name,sourceEnvironment}`; their environment
must equal the scope's environment. Names <=256 bytes, no control characters.
They describe already durable, authorized source-host resources; they convey no
bytes or grant. A host change must first copy/re-upload through the target host's
existing authenticated upload API and provide replacement target descriptors.
OmaBridge does not upload files or validate resource existence at T3. A transfer
without replacement metadata rejects source-host attachments on a different host
with `draft_attachment_host`; failure leaves every document unchanged. Clients
must keep the target unsendable until its uploads/grants are verified.

## Reads and reconciliation

* `{"op":"get","scope":S}` → `{owner,document,cursor}`. Absent document is null.
* `{"op":"list"}` → `{owner,items,cursor,nextOffset}` including tombstones.
* `{"op":"watch","cursor":C}` → same page shape, with change events as items.
  This is bounded polling replay, not a persistent subscription. Poll again after
  the last page (use a client backoff while idle).
* Continue either page with `offset:nextOffset,snapshot:<first-page-cursor>`.
  Watch continuations also retain their original `cursor` (the lower bound).
  Advance the durable resume cursor to the returned cursor **only after all pages**.
  Snapshots restart with `draft_snapshot_required` if changed between pages;
  watch replay is frozen at the first page's snapshot, so subsequent edits are
  returned on the next poll. Two items per page keep even transfer events bounded.

Revisions are opaque strings. Cursors have the form `<owner>:<sequence>`; use
the numeric component only to anchor a mutation ID, never to merge edits.
Wrong-owner, malformed or future cursors
return `draft_snapshot_required`. Cursors below the persisted compaction floor return
`draft_resync_required`. On either recovery error, fetch every page of a fresh
full snapshot. Keep the original base revision, command/ID and local branch for
**every** unsynced edit. If its original cursor is below the floor, reconcile that
branch as an explicit local conflict against the snapshot (including absence).
Do not automatically send it, rebase its ID/cursor or reset its expected revision.
A missing key might have been deleted while the device was offline. Only explicit
user resolution may create a new mutation using the fresh snapshot cursor. This
also applies to offline create-if-absent and uncertain mutation outcomes.

## Conditional writes and receipts

```json
{"op":"put","scope":S,"expected":null,"baseCursor":"<owner>:<sequence>","mutationId":"<sequence>.<durable-uuid>","payload":P}
```

Null means **create if absent**, not overwrite. Updates supply the last observed
`document.revision` as `expected`. Every stored document is
`{scope,revision,deleted,payload}`. A delete uses
`{op:"delete",scope:S,expected:R,baseCursor:C,mutationId:M}` and commits a tombstone with null
payload. A stale create/edit cannot resurrect it. Intentional restoration can
CAS against the tombstone's current revision.

Success is `{status:"applied",mutationId,event:{sequence,revision,mutationId,changes}}`.
All changes in a transaction share a revision. A mismatch returns
`{status:"conflict",mutationId,local:<original-command>,conflicts:[{key,latest}]}`.
It preserves both the submitted branch and server contents in a durable receipt;
no document changes, timestamp ordering, automatic merge or last-writer-wins.
The client must retain its own branch, surface the conflict, and use a **new**
mutation ID for a user-resolved operation based on the chosen current revision.

Mutation IDs are scoped by authenticated client endpoint. New commands must use
`mutationId:"<sequence>.<durable-uuid>"` and `baseCursor:"<owner>:<sequence>"`,
where sequence comes from the completed snapshot/watch on which the edit was
based. Keep both fields unchanged on retry; the ID embeds its original cursor.
An ID/cursor mismatch returns `draft_mutation_reused`. An expired ID returns
`draft_resync_required` plus `{status:"conflict",local:<original-command>,floor,
mutationId}` without applying it. A changed cursor cannot make an old ID reusable.
Legacy IDs without a cursor have an implicit zero anchor and are rejected after
the first compaction. This is a required adapter update for long-lived clients.
Before sending, persist
the exact command, original expected revision and mutation ID durably. Retry the
same command after an uncertain outcome, or query
`{op:"receipt",mutationId:M}`. A known receipt returns the original result; an
unknown ID returns `{found:false}` before any compaction and
`draft_resync_required` afterward (absence no longer proves non-application). Reusing an ID for changed command fields
returns `draft_mutation_reused`. Object key order is normalized by JSON parsing;
command values must match. A conflict receipt is deduplicated too. Receipt lookup
and retry remain authorized by the current grant.

## Atomic stash, restore and transfer

```json
{"op":"transfer","scope":SOURCE,"expected":"<source-revision>",
 "target":TARGET,"targetExpected":null,
 "baseCursor":"<owner>:<sequence>","mutationId":"<sequence>.<durable-uuid>"}
```

For stash, SOURCE is the thread and TARGET is a new stash entry. For restore,
SOURCE is the stash entry and TARGET is the thread. For other moves, scopes are
explicit. Source must exist and be live. CAS checks cover source and target.
If the target is live (including empty content), `backup` is required: a fresh
`kind:"stash"` scope in the target's environment/project. It is conditioned on
absence, and receives the original target payload. Only after all checks and
quotas pass does one transaction back up the target, write the target and tombstone
the source. A backup collision, stale revision, upload metadata or quota error
never partially clears the source. Retry/recover the same mutation after an
interruption. `payload` optionally supplies explicitly prepared replacement
content for a host transfer. To clone while retaining the source, explicitly
read that source revision and `put` its prepared copy create-if-absent in the new
scope; do not reinterpret attachment IDs.

## Privacy, persistence and quotas

`shared-drafts.json` is 0600 under the existing 0700 private state directory;
symlink/nonregular/public files are refused. The existing state flock serializes
grant checks and writes across processes. A commit writes a private unique temp
file, fsyncs it, renames over the entire database and fsyncs the directory.
Transactions/receipts/events commit together. Nothing enters `manage-audit.jsonl`
or application logs. Local clients must likewise omit drafts from diagnostics.
This is private plaintext state with the same protection as identity state,
not encryption at rest.

Limits: command 32 KiB, payload 8 KiB, **1024 live document keys**, 2048
retained receipts including conflicts, total serialized store **16 MiB**. Live
content is never evicted. Exceeding the live-key limit returns `draft_live_limit`;
byte quota failure returns `draft_quota`. Neither applies a partial transaction.
Deletes remain available at the live cap, and transfers count their net live-key
change (source deletion can make room for the target or backup).

Every authorized operation checks retention under the existing state lock. After
30 days, the oldest expired transaction prefix is compacted. Receipt/byte pressure
can compact the oldest retained prefix sooner. Compaction removes receipts,
events and tombstones in that prefix together and persists a monotonically
increasing cursor floor in the same atomic file. No tombstone disappears without
invalidating older cursors and mutation IDs. Conflict receipts also have sequence
and retention metadata. List pagination is invalidated when compaction changes a
snapshot. Already-present receipts still deduplicate exact retries; compacted IDs
never apply again. Receipt lookup after compaction conservatively requires resync
when unknown. No background service or wall-clock sleeps are needed: the next
operation performs maintenance. Tests can inject a shared atomic draft clock via
`Store::with_drafts_clock`, independent of pairing/authorization time. Existing
stores acquire retention timestamps on first access; existing receipts remain
usable until their prefix is compacted. Never delete the database to reclaim space.

## Exact Desktop integration

1. Persist a user-selected authority endpoint ID. Ask the owner to grant the
   Desktop's endpoint `drafts`; keep management grants separate. Detect
   `shared-drafts-v1`, then fetch all list pages and start watch polling.
2. Replace the local `draft-load`/`draft-save` adapter behind `T3Backend.qml` and
   `T3Composer.qml` with `manage action:drafts` (use `peer` for another bridge).
   Map local environment aliases to the real source environment UUID first.
   Keep a private local journal of base revision, local content/edit generation,
   exact mutation JSON/anchored ID and resume cursor before issuing writes.
   Handle `draft_resync_required` by fetching a full snapshot and retaining each
   unsynced branch as a local conflict, even when its key is absent.
3. Import legacy draft files and prompt stash create-if-absent. Preserve files
   until acknowledged; on conflict retain both and ask the user to resolve it.
   Do not blindly overwrite shared content on first run.
4. Route `T3ProjectDrafts.qml` list/delete to stash scopes and stash/restore to
   `transfer`. A live target requires a new backup entry. Preserve existing
   recovery UI and retry the same mutation after an unknown outcome.
5. Guard late callbacks by authority/scope/base revision/local generation/mutation
   ID. Keep queue editing, approval/question recovery, send attempts and outbox
   local. After send acknowledgment, clear only with the submitted revision;
   another device's later edit returns conflict and survives. Surface remote
   conflicts instead of replacing active editor text.
6. Integrate the source/target hosts' authenticated file upload APIs before
   presenting cross-host attachment copies as sendable. No changes to T3 server
   contracts or lib-t3-rust are needed for **draft storage** over OmaBridge.

## Exact Android integration

1. Build/pin this OmaBridge commit in the existing JNI pipeline; keep the T3 AAR.
   Query `op:capabilities`. C ABI stays v1: the existing call/free signatures and
   old JSON operations are unchanged. `mobile-admin-v1`/`shared-drafts-v1` are
   additive capability names, not a breaking ABI bump.
2. Persist the explicit draft authority ID. Pair normally; the authority owner
   grants that phone `drafts`. Use `op:drafts,handle,peer,command` on a worker
   thread with the same open handle as catalog/enrollment. A catalog selection
   does not itself confer draft access or change the chosen draft authority.
3. Add a shared repository alongside Room's `DraftRepository`: persist pending
   command/base revision/local branch/mutation ID and cursor in a Room transaction
   before network I/O. Import Room rows create-if-absent, retaining conflicts.
   Consume snapshot/watch before replaying conditional offline commands; on
   `draft_resync_required`, preserve all unsynced branches as local conflicts and
   require explicit resolution with a new anchored ID. Query
   receipts or retry unchanged IDs for unknown outcomes.
4. Inject that repository into the exported composer VM/screen. Persist model and
   delivery preferences in the payload, keep local URI/outbox state private,
   and apply generation/scope guards to asynchronous callbacks. Route project
   stash/restore to the same `transfer` operation used by Desktop.
5. Reuse authenticated uploads for durable attachment descriptors. Keep queue
   edits and send identities local; conditional shared clear uses the revision
   actually submitted, never the newest revision fetched after sending.

These steps describe the client work still required in the Desktop/Android
repositories. This PR implements and tests the OmaBridge authority, transport,
CLI/manage/mobile entry points; it does not change those applications or deployed
services and does not claim physical-phone end-to-end composer verification.
