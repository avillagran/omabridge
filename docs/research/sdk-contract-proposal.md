# OmaBridge — SDK contract and decision gates

Status: design proposal only. This document does not authorize implementation or select a transport. It continues the [architecture study](architecture-study.md); upstream facts and references remain there. Everything below is a proposed product contract, security assumption, or acceptance scenario, not a report of executed behavior.

## 1. Define the deliverable before the transport

The proposed deliverable is a reusable library for approved devices to open named private services. The clarified primary consumer is T3 Code mobile connecting to desktop/headless installations; SSH is an optional later extension. A standalone general-purpose connectivity application and transparent access from unrelated phone apps are not initial-release prerequisites. The reusable-core goal remains, but requiring all future consuming projects must not block validating the first T3 integration.

Separate three product levels:

- **Embedded connectivity:** a consuming application opens streams using the SDK. This is the proposed core.
- **Service bridges:** a local listener forwards an existing protocol to an approved remote service. This is an optional adapter, not account identity or discovery.
- **Whole-system connectivity:** unrelated applications access private devices without integrating the SDK. This is a separate product requirement, not a hidden promise of the first two levels.

Do not finalize the mobile architecture until it is decided which of these levels is required on the phone.

## 2. Stable logical objects

### Account

A cryptographic trust domain, not a hosted user record. Proposed fields: account identifier, root public-key reference, supported protocol versions, current authority epoch, and recovery-policy identifier.

Display names and avatars are local/private profile data. They do not establish global uniqueness or grant permissions. An account identifier is an identifier, not a password.

### Device

An installation with an independent device key and a signed membership binding that key to an account. Proposed properties: device identifier, bound transport key, member role, membership validity, issuer, and applicable policy revision.

A process restart should retain the same installation identity. A reinstall that loses the private key is a new installation requiring enrollment, not silent identity recovery from a familiar display name.

### Application namespace

A stable logical owner of services and grants. A human-readable namespace string is not proof that a local process owns it. Local authentication and namespace registration need a separate contract.

Two applications under the same account may have different grants. The SDK must not accept an arbitrary caller-supplied namespace as sufficient authority.

### Service

A stable service identifier owned by an application on a device, together with a protocol identifier and explicit publication policy. Local target addresses are private host configuration and are not supplied by the remote caller.

Keep separate:

- service identity;
- published/withdrawn state;
- device reachability;
- service health;
- authorization to use the service.

A device being online must not imply that every service is available or allowed.

### Grant

A scoped authorization with issuer, subject, resource, action, validity and policy epoch. Proposed actions: discover, connect, publish, enroll, administer and operate a relay. None should imply the others automatically.

Connect grants should be bound to an approved device and, where enforced, an application credential. Avoid bearer-only permanent URLs as the account's normal security boundary.

### Route

A temporary way to reach a cryptographically identified device. A route is not the device identity. Losing a relay address or changing Wi-Fi must not create a second device or require granting authority to an unverified replacement endpoint.

## 3. SDK operation contract

These are semantic operations, not final function signatures or code examples. Exact types, encoding and language bindings remain undecided.

### Initialize local installation

Load the existing identity or create a new one explicitly. Return public identity and lifecycle state; never return raw private keys through a normal inspection operation. Report locked storage, unreadable state and missing identity as distinct errors. Do not silently replace corrupted identity state with a new account.

### Create invitation

Require enrollment permission. Return an expiring invitation suitable for QR transfer. Scope it to the intended account, inviter and enrollment role. Support cancellation. Secret material must be redactable independently of non-secret display information.

The durable record must survive an ordinary crash without making a consumed invitation usable again. If durable single-use state cannot be confirmed, reject rather than issue another membership through the same invitation.

### Request and approve enrollment

The joining device submits a request proving possession of its own key. Approval must identify the exact request and keys being approved, not merely whichever connection arrives next.

An approved request does not become an account member until the authorized issuer commits and signs the membership. The inviter is not allowed to grant roles beyond its own explicit delegation.

If enrollment approval and account policy issuance are different roles, expose the pending-issuance state in the UI. Do not claim enrollment succeeded while waiting for an unavailable authority.

### List devices and services

Return only records visible to the caller. Mark cached/stale state separately from live reachability. A directory entry is not an implicit connect grant.

### Publish service

Require namespace ownership and publication permission. Register an explicit approved local endpoint. Provide explicit withdrawal and a defined crash-cleanup behavior. Do not preserve a stale local port mapping across process restart unless the owning application explicitly requested durable publication and revalidated its target.

Treat local target provenance as a separate problem: a saved loopback port number is not proof of the intended application's identity. For SDK-integrated services, evaluate an application-authenticated local handoff or a listener/descriptor whose ownership the bridge controls. For an arbitrary existing service, define how target ownership and process lifetime are checked, and disclose any local-port-reuse race that remains outside the chosen threat model. Do not claim C09 passes just because a TCP connect succeeded.

### Open service

Take a logical device/service reference, not an arbitrary target host/port. Validate account membership, peer key binding, policy freshness and connect grant before forwarding application bytes.

Return an opaque bidirectional stream with cancellation, backpressure, half-close semantics and bounded buffering. Separate connection establishment from application-protocol success: a transport connection is not proof that HTTP or SSH accepted the user.

### Open bridge

An optional adapter creates a loopback listener for one authorized service and returns its actual local address. Its lifetime and ownership must be explicit. Closing the adapter stops new accepts and handles existing streams according to its documented close policy.

Wider network exposure requires a separate explicit permission. A process crash must not leave an independent privileged forwarding process running without an owner.

### Revoke membership or grant

Require appropriate authority. Commit a new signed policy state, record which peers have observed it, reject new affected streams and close affected active streams locally. Return local enforcement and propagation status separately.

Never label global revocation complete merely because the issuer wrote its own policy record. Offline peers may not have received the update.

### Subscribe to events and close

Provide ordered local event delivery with explicit snapshot/resynchronization after gaps. Event consumers must not assume a callback log is an authoritative membership database.

Close must cancel pending operations, release listeners and connections, and flush security-critical state safely. Application-owned payload delivery is not guaranteed just because a local send call completed.

## 4. State machines and failure behavior

### Invitation

Proposed states: created, offered, approval-pending, committed/consumed, cancelled, expired.

Only one approved enrollment may reach committed for an invitation. Consumption and membership issuance need a crash-safe transaction boundary. An interrupted requester should be able to query the already approved result while proving possession of its approved key; it must not require a second admission.

Two concurrent scans are different requests. Display and approve the specific joining key. Reject the losing request rather than making both members.

### Device connection

Proposed observable phases: idle, resolving, dialing, peer-authenticating, policy-checking, connected, retrying, suspended, closed.

Connected should include the selected path: direct or relayed, plus the service session's authorization status. A path switch must not bypass membership checks or silently replace the authenticated peer.

If a connection drops, distinguish re-establishing transport from resuming an application stream. Do not silently replay arbitrary application bytes: a repeated HTTP write, SSH command or other non-idempotent operation may have side effects. Application-level retry/resume needs an explicit contract.

### Error taxonomy

Proposed distinct categories:

- identity missing, locked or invalid;
- invitation expired, consumed, cancelled or awaiting approval;
- peer identity mismatch;
- membership invalid or revoked;
- policy stale or unsupported;
- application/namespace not authorized;
- service unknown, withdrawn or unhealthy;
- no usable route;
- relay unavailable or quota reached;
- operation deadline reached or cancelled;
- incompatible protocol version;
- local endpoint bind/target failure.

User-facing errors must not expose a private service catalog to an unauthorized peer. Internal diagnostic detail and remotely visible failure messages are different interfaces.

## 5. Authority without a permanent central network server

This needs an explicit product choice. A signing authority is not necessarily a permanently online server, but it can still become an administrative availability dependency.

### Conservative first-version candidate

Keep the account root recoverable separately. Nominate one device-held policy issuer, authorized by the root, to serialize membership and revocation state. Existing peers validate cached signed policy locally within a defined freshness policy; normal permitted traffic does not contact the issuer on every request.

Benefits proposed: deterministic policy ordering, simpler rollback checks and a smaller security review surface.

Cost: if that device is unavailable, new memberships or policy changes wait. Moving issuer authority requires a recovery/transfer procedure. This must not be advertised as fully available distributed administration.

### More available alternative

Delegate enrollment or administration to multiple devices with bounded roles and verifiable delegation chains. Before selecting this alternative, define conflicting changes, delegation revocation, policy forks, rollback protection and the behavior of partitioned administrators.

Do not describe 'multiple admins' as a solved feature without those rules. Adding a blockchain or consensus protocol is not a default answer to an unconfirmed requirement.

### Decision gate

Ask whether new devices must be enrollable while the original/administrative desktop is offline. If yes, the conservative candidate may not satisfy the product; design delegated administration before freezing the membership format.

## 6. Cross-application isolation is a separate security boundary

For the proposed desktop agent, distinguish:

- **Logical separation:** avoid accidental service/grant sharing between well-behaved projects.
- **Adversarial isolation:** prevent a malicious process in the same local user environment from impersonating another application or stealing its credentials.

Conservative threat-model assumption: do not treat a namespace string, an application label, or a local user identity alone as strong isolation between mutually hostile applications running as that same user. Validate credential storage and process isolation on each actual target before making stronger claims.

The first version can explicitly target trusted applications sharing one desktop user, while still using default-deny remote service grants. If hostile local applications are in scope, evaluate OS-enforced sandboxing, separate principals and platform-backed credentials. A per-app bearer token stored where another in-scope process can read it does not solve that threat.

On mobile, decide whether the user experience is one companion application with multiple service integrations or several independently installed consuming applications. Sharing one account across those applications does not itself specify key sharing, user consent, background execution or privileged IPC.

## 7. Recovery and lost-device behavior

Specify and test separately:

- losing an ordinary member device;
- losing the sole policy issuer;
- losing all enrolled devices while retaining recovery material;
- losing both devices and recovery material;
- suspected account-root compromise;
- restoring an old backup containing stale policy;
- clock rollback or severe clock disagreement.

A restored backup must not silently overwrite newer observed policy. If authority or membership epochs conflict, surface the conflict and reject affected privileged operations until a specified recovery path resolves it.

No recovery service exists in the proposed baseline. Unless an additional recovery mechanism is chosen, loss of all authorizing keys and recovery material means no automatic way to prove the old account identity. Do not invent email-based recovery for an accountless system.

## 8. Transport evaluation: disqualifiers before scoring

Do not assign invented performance scores. The following gates describe the broader reusable SDK. For the clarified T3-first validation, apply G4 to the actual T3 HTTP/WebSocket workflow and needed web previews; SSH is a follow-on check. G7 and C15 validate later cross-project reuse and must not block the initial T3 experiment. Require evidence on actual targets rather than accepting these proposals as passed tests:

- **G1 — integration:** a real consuming application can use the binding, cancellation and stream API on every mandatory platform.
- **G2 — endpoint authentication:** the application can pin/bind the remote device identity; a reachable address alone is not accepted as authorization.
- **G3 — connectivity policy:** direct/private mode can enforce the promised external-dependency limits; relay mode exposes its dependencies and failures.
- **G4 — protocol fit:** HTTP including WebSockets and existing SSH can traverse the selected adapter without weakening their authentication/origin requirements.
- **G5 — lifecycle:** phone foreground/background and process-restart limits match the advertised UX, with no perpetual-background promise inferred from a desktop demo.
- **G6 — operation:** relay admission, bandwidth responsibility, resource limits, redaction and upgrade behavior have explicit owners.
- **G7 — reuse:** a second consuming project integrates without copying identity, pairing or permission code.

Compare connection time, throughput, latency, package size, resource/energy cost and maintenance effort only after mandatory gates pass. Keep measurements tied to tested versions, topology, devices and run conditions. The first successful LAN connection is not a transport selection decision.

## 9. Proposed conformance scenarios — not executed

These are behavioral acceptance cases, not executable tests or cryptographic test vectors.

### C01 — atomic enrollment

Two devices scan the same invitation concurrently. The approver selects one exact joining key. Expected: at most that key receives committed membership; the other request cannot consume the approved result.

### C02 — enrollment crash recovery

The issuer crashes after recording approval but before responding. Expected: restart never admits a second joining key through the invitation; the approved device can resolve its existing enrollment status safely.

### C03 — peer substitution

A route resolves to a different public key. Expected: no application bytes forwarded; report identity mismatch rather than silently trusting the new key.

### C04 — third-device membership

A and B are enrolled. An authorized issuer adds C. Expected: A, B and C derive access from the signed membership/grants; C does not require every existing device to scan another QR, and does not inherit all service permissions automatically.

### C05 — unauthorized service

A valid member lacks access to a published SSH service. Expected: transport reachability does not grant service access or leak unnecessary private service metadata.

### C06 — active revocation

A peer is using an authorized stream. The enforcing endpoint receives a valid revocation. Expected: affected access is terminated and further opens fail; UI reports which peers have not acknowledged policy delivery.

### C07 — partition and stale policy

A peer is offline during revocation and returns with older policy. Expected: no claim of instantaneous partition-wide revocation; enforce the chosen freshness/expiry rules and reject policy rollback.

### C08 — application namespace impersonation

A local caller claims another application's namespace. Expected: the claim alone grants nothing. Document whether the tested threat model includes a hostile same-user process and what actual boundary enforces that case.

### C09 — crash-owned publication

The publishing application exits unexpectedly. Expected: stale publication cannot silently connect to an unrelated process that later reuses the same local port.

### C10 — bridge exposure

A loopback bridge is created. Expected: no wider bind or arbitrary remote-selected LAN target without a separate explicit grant. Closing the owning handle has the documented effect on listener and active streams.

### C11 — stream interruption

A network change interrupts an application write. Expected: explicit failure or documented resumable behavior; the SDK does not replay arbitrary non-idempotent bytes invisibly.

### C12 — unavailable infrastructure

Direct connection fails and all configured relays are unreachable. Expected: bounded retries, actionable no-route/unavailable state, and no undocumented switch to a public provider forbidden by policy.

### C13 — lifecycle mismatch

A phone hands control to an external browser/client and the bridge-owning app stops executing. Expected: behavior matches the advertised supported mode; this case must not be accepted merely because the integrated foreground UI worked.

### C14 — identity persistence and recovery

Restart an installation, then separately restore an old backup and simulate total key loss. Expected: ordinary restart preserves identity; old state cannot roll back newer policy; total loss follows the declared recovery limits.

### C15 — cross-project reuse

Two real projects publish different services through the same SDK contract. Expected: no duplicated enrollment logic; grants and lifecycle remain explicit; one project's service withdrawal does not grant or terminate unrelated access.

## 10. Outstanding user decisions

For the T3-first validation, confirm the actual T3 client/server repositories and mobile platforms, the administrator-offline enrollment requirement, and the acceptable relay/discovery policy. Use the integrated T3 client as the initial consumer rather than requiring compatibility with every unrelated phone app.

The four-project inventory and adversarial cross-application isolation remain requirements for a broader reusable release, not blockers for the first T3 connectivity experiment. Do not guess project paths or silently treat SSH as a required initial deliverable.

Proposed defaults for discussion, not approved requirements: native interactive mobile first; named services rather than whole-system routing; no hosted account requirement; optional replaceable supporting nodes; trusted local desktop consumers; one policy issuer until offline administration is shown necessary.

## 11. Readiness and authorization boundary

This contract is ready for user review, not implementation. No transport has passed G1–G7, no C01–C15 case has been executed, and no binding or platform has been approved from this document.

After the missing requirements are supplied, propose the smallest comparative spike that can reject a transport early. Request approval before implementing, installing a client/daemon, opening a service, using a phone or remote lab, deploying a relay, creating Git history, or publishing anything.
