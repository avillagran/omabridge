# Embedding

Default features include `cli`, preserving the existing binary and standalone behavior.
Hosts use `default-features = false, features = ["embed"]`.

`Node::start_configured` accepts explicit `Target`s, `PairingIssuer`, runtime reservation,
optional enrollment authority and `NodeConfig`. It does not discover a CLI issuer or
read a default identity directory. Legacy constructors retain their existing behavior.

Implement `LocalService::serve` to handle a raw byte stream. The bridge supplies a
bounded 32 KiB Tokio duplex and authenticated `PeerInfo`. The service must still enforce
its own application authentication. TCP services remain available as `Target::Tcp`.
Authorization, public consent, compression and ongoing grant revocation are shared by
both transports.

`NodeConfig::embedded()` enables the private control socket and disables sync, gateway
and relay-host loops. A requested control socket must bind successfully. Use an explicit
state directory and retain the runtime reservation for the Node's lifetime.

Pass an `EmbeddedBackend` in `NodeConfig.backend` to enable in-process remote management
and publication. `services.json` is private and atomically replaced; corrupt policy fails
closed. Publish/unpublish applies to both new and existing streams. A backend restart
cancels accepted service sessions while preserving the endpoint and control socket.
`Manager::embedded` supplies explicit local paths. The standalone CLI detects embedded
policy when managing local state, so publish/unpublish does not install a unit.

Embedded relay/gateway mutation is explicitly unsupported; configure networking when
starting the host. Embedded capabilities omit those features. `UnitsBackend` provides
publication through the existing unit abstraction; standalone Manager constructors retain
their previous defaults. The existing standalone relay rollback path remains unchanged;
do not enable it for an embedded host without a host-aware restart supervisor.

`Node::attach_task` ties host-owned background work to shutdown/Drop. Fine-grained Cargo
pruning of relay/gateway/MCP modules is still pending: disabled runtime tasks are not
spawned, but their dependencies currently compile. `gui` remains optional.
