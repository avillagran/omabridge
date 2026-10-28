use crate::{PairDecision, RuntimeReservation, Store, valid_service};
use anyhow::{Context, Result, bail, ensure};
use iroh::{
    Endpoint, EndpointAddr, RelayMode, RelayUrl, TransportAddr,
    endpoint::{Connection, RecvStream, SendStream, presets},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::{JoinHandle, JoinSet},
    time::timeout,
};

const ALPN: &[u8] = b"omabridge/service/1";
const HEADER_LIMIT: usize = 64 * 1024;
const SETUP_TIMEOUT: Duration = Duration::from_secs(8);

/// How a device reaches peers it cannot dial directly, e.g. behind NAT or a private IP.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Relay {
    /// n0's public relays. Traffic stays end-to-end encrypted; the relay sees
    /// only endpoint IDs and IP addresses. Peers may advertise any relay.
    #[default]
    Public,
    /// Only this HTTPS relay, e.g. one hosted with `omabridge relay`.
    Custom(RelayUrl),
    /// Direct addresses only: peers must be reachable on the network.
    Disabled,
}

/// File in the state directory holding the device's relay choice.
const RELAY_FILE: &str = "relay.json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayDocument {
    relay: String,
}

impl Relay {
    /// `public`, `none` or an `https://` relay URL.
    pub fn parse(text: &str) -> Result<Self> {
        match text.trim() {
            "public" => Ok(Self::Public),
            "none" => Ok(Self::Disabled),
            url => {
                ensure!(
                    url.starts_with("https://"),
                    "relay must be public, none or an HTTPS URL"
                );
                Ok(Self::Custom(url.parse().context("invalid relay URL")?))
            }
        }
    }

    /// The `--relay` value that selects this relay again.
    pub fn arg(&self) -> String {
        match self {
            Self::Public => "public".to_owned(),
            Self::Disabled => "none".to_owned(),
            Self::Custom(url) => url.to_string(),
        }
    }

    /// The device's saved choice; public relays when none was saved.
    pub fn load(state_dir: &Path) -> Result<Self> {
        let path = state_dir.join(RELAY_FILE);
        if std::fs::symlink_metadata(&path).is_err() {
            return Ok(Self::default());
        }
        Self::parse(&crate::read_document::<RelayDocument>(&path)?.relay)
    }

    pub fn save(&self, state_dir: &Path) -> Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(state_dir)?;
        crate::write_document(
            &state_dir.join(RELAY_FILE),
            &RelayDocument { relay: self.arg() },
            true,
        )
    }
}

impl std::str::FromStr for Relay {
    type Err = anyhow::Error;
    fn from_str(text: &str) -> Result<Self> {
        Self::parse(text)
    }
}

#[derive(Clone)]
pub struct NetOptions {
    pub bind: SocketAddr,
    pub relay: Relay,
    /// Opt-in independent-block compression for T3 streams. Both peers must enable it.
    pub compress_t3: bool,
}
impl NetOptions {
    pub fn loopback() -> Self {
        Self {
            bind: "127.0.0.1:0".parse().expect("literal socket"),
            relay: Relay::Disabled,
            compress_t3: false,
        }
    }
    /// Routes this device may use to reach `addr`: direct addresses always, and
    /// the relay the peer announces unless relays are off. A custom relay is
    /// where this device is reached; requiring it for every peer would strand
    /// devices while they move from one relay to another.
    fn address(&self, addr: &EndpointAddr) -> EndpointAddr {
        let mut allowed = addr.clone();
        allowed.addrs.retain(|a| match (a, &self.relay) {
            (TransportAddr::Ip(_), _) => true,
            (TransportAddr::Relay(_), Relay::Disabled) => false,
            (TransportAddr::Relay(_), _) => true,
            _ => false,
        });
        allowed
    }
}

/// How long a new endpoint waits for its home relay before publishing an address.
const RELAY_WAIT: Duration = Duration::from_secs(10);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invitation {
    pub version: u8,
    pub address: EndpointAddr,
    pub token: String,
    pub name: String,
    pub expires: u64,
    /// The inviting device asks to manage the device that accepts. Only a
    /// request: the accepting device decides, after warning its user.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub manage: bool,
}

#[derive(Serialize, Deserialize)]
// Unknown fields are ignored, so newer devices can add some without breaking older ones.
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    /// Credential-free catalog, scoped to the authenticated peer identity.
    Catalog,
    Enroll {
        environment_id: String,
    },
    /// Separate host-approved delegation; never inferred from ordinary grants.
    DelegatedEnroll {
        environment_id: String,
        client_id: String,
    },
    Pair {
        token: String,
        name: String,
    },
    Open {
        service: String,
        /// The stream carries a public gateway's anonymous client.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        public: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        compression: Option<String>,
    },
    /// A paired device announces its name, whether the receiver may manage it
    /// and, when it serves, its current address.
    Hello {
        name: String,
        address: Option<EndpointAddr>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        admin: bool,
        /// Services the receiver may reach on the sender, and those it may expose publicly.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grants: Option<Grants>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        routes: Option<Vec<crate::routes::ServiceRoute>>,
    },
    /// One `omabridge manage` command from a device this one lets manage it.
    Manage {
        command: serde_json::Value,
    },
    /// A one-use native T3 pairing for a device this one shares `t3` with.
    T3Pair,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
enum Response {
    Enrollment {
        enrollment: crate::enrollment::Enrollment,
    },
    Catalog {
        manifest: serde_json::Value,
    },
    Pair {
        decision: PairDecision,
    },
    Ready,
    ReadyCompressed,
    Denied,
    Unavailable,
    Hello {
        name: String,
        address: EndpointAddr,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        admin: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grants: Option<Grants>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        routes: Option<Vec<crate::routes::ServiceRoute>>,
    },
    Managed {
        outcome: serde_json::Value,
    },
    T3Pairing {
        pairing: crate::t3_pair::T3Pairing,
    },
}

/// What one device lets another reach, as announced in `Hello`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Grants {
    services: Vec<String>,
    public: Vec<String>,
}

impl Grants {
    fn of(peer: &crate::Peer) -> Self {
        Self {
            services: peer.services.iter().cloned().collect(),
            public: peer.public.iter().cloned().collect(),
        }
    }
    fn pair(&self) -> (&[String], &[String]) {
        (&self.services, &self.public)
    }
}

/// Connections one remote device may hold open at once, out of the 64.
const PER_PEER: usize = 32;
/// Connections from devices that are not paired (pairing requests) at once.
const UNKNOWN_SLOTS: usize = 8;
const UNKNOWN_SETUP: Duration = Duration::from_secs(2);
/// How long a refused request waits for its answer to be delivered.
const DENIED_LINGER: Duration = Duration::from_secs(1);

/// How often a serving device re-announces itself to peers it can reach; a
/// rename is announced within seconds.
pub const SYNC_INTERVAL: Duration = Duration::from_secs(300);
const NAME_CHECK: Duration = Duration::from_secs(2);
const RETRY_FIRST: Duration = Duration::from_secs(10);
const RETRY_MAX: Duration = Duration::from_secs(160);

/// Private socket in the state directory through which this user's own front
/// ends reach peers with the running server's endpoint. A second endpoint with
/// the same identity would take over its relay connection meanwhile, leaving
/// the server unreachable.
pub const CONTROL_SOCKET: &str = "control.sock";

/// The address peers should dial: the endpoint's own, plus a custom relay that
/// iroh does not list until it is connected.
fn advertised(endpoint: &Endpoint, relay: Option<&RelayUrl>) -> EndpointAddr {
    let mut address = endpoint.addr();
    if let Some(relay) = relay {
        address.addrs.insert(TransportAddr::Relay(relay.clone()));
    }
    address
}

/// Opens one control stream to `addr` over the routes `options` allows.
async fn request(
    endpoint: &Endpoint,
    options: &NetOptions,
    addr: &EndpointAddr,
    request: &Request,
) -> Result<(Pipe, Response)> {
    let address = options.address(addr);
    ensure!(
        !address.addrs.is_empty(),
        "no route allowed by local relay policy"
    );
    timeout(SETUP_TIMEOUT, async {
        let connection = endpoint.connect(address, ALPN).await?;
        let (mut send, mut recv) = connection.open_bi().await?;
        write_header(&mut send, request).await?;
        let response = read_header(&mut recv).await?;
        Ok::<_, anyhow::Error>((
            Pipe {
                send,
                recv,
                connection,
                compressed: false,
            },
            response,
        ))
    })
    .await
    .context("connection setup deadline reached")?
}

/// Exchanges names and addresses with one paired device and stores its answer.
async fn hello(
    endpoint: &Endpoint,
    options: &NetOptions,
    store: &Store,
    peer: &crate::Peer,
    own: Option<EndpointAddr>,
) -> Result<()> {
    let addr = peer.address.as_ref().context("peer address unknown")?;
    let (_pipe, response) = request(
        endpoint,
        options,
        addr,
        &Request::Hello {
            name: store.name()?,
            address: own,
            admin: peer.admin,
            grants: Some(Grants::of(peer)),
            routes: Some(crate::routes::for_peer(store, &peer.id)),
        },
    )
    .await?;
    match response {
        Response::Hello {
            name,
            address,
            admin,
            grants,
            routes,
        } => {
            ensure!(address.id == addr.id, "peer answered for another device");
            store.refresh_peer(
                &peer.id,
                &name,
                Some(&address),
                admin,
                grants.as_ref().map(Grants::pair),
            )?;
            if let Some(routes) = routes {
                store.refresh_routes(&peer.id, &routes, unix_time()?)?;
            }
            Ok(())
        }
        _ => bail!("peer refused the announcement"),
    }
}

/// Announces this device to every paired device with a known address, at once;
/// returns how many answered out of how many were tried.
async fn hello_all(
    endpoint: &Endpoint,
    options: &NetOptions,
    store: &Store,
    own: Option<EndpointAddr>,
) -> Result<(usize, usize)> {
    let targets: Vec<crate::Peer> = store
        .peers()?
        .into_iter()
        .filter(|peer| peer.address.is_some())
        .collect();
    let tried = targets.len();
    let mut tasks = JoinSet::new();
    for peer in targets {
        let (endpoint, options, store, own) = (
            endpoint.clone(),
            options.clone(),
            store.clone(),
            own.clone(),
        );
        tasks.spawn(async move {
            let answered = hello(&endpoint, &options, &store, &peer, own).await.is_ok();
            (answered, peer.admin)
        });
    }
    let (mut reached, mut admins) = (0, 0);
    while let Some(result) = tasks.join_next().await {
        let (answered, admin) = result.unwrap_or((false, false));
        reached += usize::from(answered);
        admins += usize::from(answered && admin);
    }
    // A managing device answering proves a remote relay change kept it in reach.
    if admins > 0 {
        crate::manage::confirm_relay(store.root());
    }
    Ok((reached, tried))
}

/// What an announcement depends on: this device's name, the paired devices it
/// can dial, which of them may manage it and what each may reach.
type SyncEntry = (String, bool, Vec<String>, Vec<String>);

fn sync_key(store: &Store) -> Option<(String, Vec<SyncEntry>, Vec<crate::gateway::Gateway>)> {
    let mut reachable: Vec<SyncEntry> = store
        .peers()
        .ok()?
        .into_iter()
        .filter(|peer| peer.address.is_some())
        .map(|peer| {
            (
                peer.id,
                peer.admin,
                peer.services.into_iter().collect(),
                peer.public.into_iter().collect(),
            )
        })
        .collect();
    reachable.sort();
    Some((
        store.name().ok()?,
        reachable,
        crate::gateway::load(store.root()),
    ))
}

/// While serving: announce at start, within seconds of a rename or a new
/// reachable pairing, and every SYNC_INTERVAL.
async fn sync_loop(endpoint: Endpoint, options: NetOptions, store: Store, relay: Option<RelayUrl>) {
    let mut announced = None;
    let mut announced_address = None;
    let mut last = tokio::time::Instant::now();
    // A peer that missed an announcement is tried again soon, backing off.
    let mut retry: Option<tokio::time::Instant> = None;
    let mut backoff = RETRY_FIRST;
    loop {
        if crate::manage::rollback_due(store.root(), &crate::units::Systemctl) {
            // The unit restarts with the previous relay.
            return;
        }
        let key = sync_key(&store);
        let own = advertised(&endpoint, relay.as_ref());
        let changed = key != announced || announced_address.as_ref() != Some(&own);
        let due = retry.is_some_and(|at| tokio::time::Instant::now() >= at);
        if key.is_some() && (changed || due || last.elapsed() >= SYNC_INTERVAL) {
            if changed {
                backoff = RETRY_FIRST;
            }
            // Refresh invitations too, without publishing a library-only node.
            if let Ok((_, services)) = store.active_endpoint() {
                let _ = store.publish_endpoint(&own, &services);
            }
            let missed = hello_all(&endpoint, &options, &store, Some(own.clone()))
                .await
                .map_or(true, |(reached, tried)| reached < tried);
            announced_address = Some(own);
            retry = missed.then(|| tokio::time::Instant::now() + backoff);
            backoff = if missed {
                (backoff * 2).min(RETRY_MAX)
            } else {
                RETRY_FIRST
            };
            // Answers may update addresses but not which peers are reachable.
            announced = sync_key(&store);
            last = tokio::time::Instant::now();
        }
        tokio::time::sleep(NAME_CHECK).await;
    }
}

/// One JSON request per connection on CONTROL_SOCKET: `{"peer":id,"command":{…}}`
/// sends a management command, `{"announce":true}` announces to every peer and
/// `{"forward":{…}}` forwards a loopback port to a peer while the connection stays open
/// and `{"connect":{…}}` carries one stream to a peer over the connection itself.
/// Bound before the server reports itself started, so front ends find it at once.
fn control_socket(store: &Store) -> Option<tokio::net::UnixListener> {
    let path = store.root().join(CONTROL_SOCKET);
    // This server holds the identity's runtime lock, so a socket left here is stale.
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path).ok()?;
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).ok()?;
    Some(listener)
}

async fn control_loop(
    listener: Option<tokio::net::UnixListener>,
    endpoint: Endpoint,
    options: NetOptions,
    store: Store,
    relay: Option<RelayUrl>,
) {
    use tokio::io::AsyncBufReadExt;
    let Some(listener) = listener else {
        return;
    };
    let mut workers = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((socket, _)) = accepted else { continue };
                let (endpoint, options, store, relay) = (endpoint.clone(), options.clone(), store.clone(), relay.clone());
                workers.spawn(async move {
                    let (read, mut write) = socket.into_split();
                    let mut line = String::new();
                    let mut reader = tokio::io::BufReader::new(read.take(HEADER_LIMIT as u64));
                    if timeout(SETUP_TIMEOUT, reader.read_line(&mut line)).await.is_err() {
                        return;
                    }
                    let request = serde_json::from_str::<serde_json::Value>(&line).unwrap_or_default();
                    if let Some(spec) = request.get("forward") {
                        let read = reader.into_inner().into_inner();
                        serve_forward(&endpoint, &options, &store, spec, read, write).await;
                        return;
                    }
                    if let Some(spec) = request.get("connect") {
                        let buffered = reader.buffer().to_vec();
                        let read = reader.into_inner().into_inner();
                        serve_connect(&endpoint, &options, &store, spec, buffered, read, write).await;
                        return;
                    }
                    let own = advertised(&endpoint, relay.as_ref());
                    let answer = control_request(&endpoint, &options, &store, own, &line).await;
                    let _ = write.write_all(format!("{answer}\n").as_bytes()).await;
                });
            }
            _ = workers.join_next(), if !workers.is_empty() => {}
        }
    }
}

async fn control_request(
    endpoint: &Endpoint,
    options: &NetOptions,
    store: &Store,
    own: EndpointAddr,
    line: &str,
) -> serde_json::Value {
    use serde_json::json;
    let Ok(request) = serde_json::from_str::<serde_json::Value>(line) else {
        return json!({ "error": "invalid_command" });
    };
    if request["capabilities"] == true {
        return json!({"features": crate::manage::FEATURES});
    }
    if let Some(id) = request["catalog"].as_str() {
        let result = async {
            let addr = store
                .peers()?
                .into_iter()
                .find(|p| p.id == id)
                .and_then(|p| p.address)
                .context("unknown catalog peer")?;
            let (_pipe, response) = request_catalog(endpoint, options, store, &addr).await?;
            Ok::<_, anyhow::Error>(response)
        }
        .await;
        return match result {
            Ok(manifest) => json!({"manifest":manifest}),
            Err(e)
                if e.downcast_ref::<crate::catalog_client::CatalogDenied>()
                    .is_some() =>
            {
                json!({"denied":true})
            }
            Err(_) => json!({"error":"catalog_unavailable"}),
        };
    }
    // Pairing from the server's endpoint: `{"pair": "<private invitation file>"}`.
    if let Some(path) = request["pair"].as_str() {
        let Ok(invite) = crate::read_document::<Invitation>(std::path::Path::new(path)) else {
            return json!({ "error": "omabridge_invite_invalid" });
        };
        let (Ok(name), Ok(now)) = (store.name(), unix_time()) else {
            return json!({ "error": "local_error" });
        };
        return match pair_with(endpoint, options, store, &invite, &name, now).await {
            Ok(PairDecision::Pending) => json!({ "status": "pending" }),
            Ok(PairDecision::Approved { services }) => {
                json!({ "status": "approved", "services": services })
            }
            Err(error) => {
                let message = format!("{error:#}");
                json!({ "error": if message.contains("expired") {
                    "omabridge_invite_expired"
                } else if message.contains("denied") {
                    "omabridge_pair_denied"
                } else {
                    "omabridge_peer_unreachable"
                }})
            }
        };
    }
    // `{"t3Pair":"<peer id>"}`: a one-use T3 pairing from a peer that shares `t3`.
    if let Some(peer) = request["t3Pair"].as_str() {
        let result = async {
            let (_, addr) = forward_target(store, peer, "t3", None).map_err(anyhow::Error::msg)?;
            t3_pair_with(endpoint, options, &addr).await
        }
        .await;
        return match result {
            Ok(pairing) => json!({ "pairing": pairing }),
            Err(error) => json!({ "error": t3_pair_error(&error) }),
        };
    }
    if let Some(spec) = request.get("delegatedEnroll") {
        let result: Result<crate::enrollment::Enrollment> = async {
            let peer = spec["peer"].as_str().context("missing peer")?;
            let client = spec["clientId"].as_str().context("missing client")?;
            let environment = spec["environmentId"]
                .as_str()
                .context("missing environment")?;
            let (_, addr) = forward_target(store, peer, "t3", None).map_err(anyhow::Error::msg)?;
            let enrollment =
                delegated_enroll_with(endpoint, options, &addr, client, environment).await?;
            forward_target(store, peer, "t3", None).map_err(anyhow::Error::msg)?;
            Ok(enrollment)
        }
        .await;
        return match result {
            Ok(enrollment) => json!({"enrollment": enrollment}),
            Err(_) => json!({"error": "omabridge_enrollment_refused"}),
        };
    }
    if request["announce"] == true {
        return match hello_all(endpoint, options, store, Some(own)).await {
            Ok((reached, total)) => json!({ "reached": reached, "total": total }),
            Err(_) => json!({ "error": "omabridge_command_failed" }),
        };
    }
    let peer = request["peer"].as_str().unwrap_or("");
    let Some(addr) = store
        .peers()
        .ok()
        .and_then(|peers| peers.into_iter().find(|item| item.id == peer))
        .and_then(|item| item.address)
    else {
        return json!({ "error": "omabridge_peer_unreachable" });
    };
    match request_manage(endpoint, options, &addr, &request["command"]).await {
        Ok(outcome) => json!({ "outcome": outcome }),
        Err(error) if format!("{error:#}").contains("management refused") => {
            json!({ "error": "omabridge_remote_unsupported" })
        }
        Err(_) => json!({ "error": "omabridge_peer_unreachable" }),
    }
}

/// `{"forward":{"peer","service","listen","address"?}}`: bridges a loopback
/// listener to a peer's service through this server's own endpoint for as long
/// as the requesting connection stays open, so local clients share the
/// device's identity instead of starting a second endpoint with it.
async fn serve_forward(
    endpoint: &Endpoint,
    options: &NetOptions,
    store: &Store,
    spec: &serde_json::Value,
    mut read: tokio::net::unix::OwnedReadHalf,
    mut write: tokio::net::unix::OwnedWriteHalf,
) {
    use serde_json::json;
    let setup = async {
        let peer = spec["peer"].as_str().unwrap_or_default();
        let service = spec["service"].as_str().unwrap_or_default();
        let listen = spec["listen"]
            .as_str()
            .unwrap_or("127.0.0.1:0")
            .parse::<SocketAddr>()
            .map_err(|_| "omabridge_forward_invalid")?;
        if !listen.ip().is_loopback() || !valid_service(service) {
            return Err("omabridge_forward_invalid");
        }
        let address = match spec.get("address") {
            Some(value) if !value.is_null() => Some(
                serde_json::from_value::<EndpointAddr>(value.clone())
                    .map_err(|_| "omabridge_forward_invalid")?,
            ),
            _ => None,
        };
        let (_, addr) = forward_target(store, peer, service, address)?;
        // Verify the grant and target now; never report a usable listener on a failed setup.
        drop(
            open_with(endpoint, options, &addr, service, false)
                .await
                .map_err(|_| "omabridge_peer_unreachable")?,
        );
        let listener = TcpListener::bind(listen)
            .await
            .map_err(|_| "omabridge_port_unavailable")?;
        let local = listener
            .local_addr()
            .map_err(|_| "omabridge_port_unavailable")?;
        Ok((listener, addr, service.to_owned(), local))
    };
    let (listener, addr, service, local) = match setup.await {
        Ok(ready) => ready,
        Err(code) => {
            let _ = write
                .write_all(format!("{}\n", json!({ "error": code })).as_bytes())
                .await;
            return;
        }
    };
    let answer = json!({ "forwarding": { "listen": local.to_string() } });
    if write
        .write_all(format!("{answer}\n").as_bytes())
        .await
        .is_err()
    {
        return;
    }
    let closed = async {
        let mut sink = [0u8; 64];
        while matches!(read.read(&mut sink).await, Ok(read) if read > 0) {}
    };
    tokio::select! {
        _ = forward_with(endpoint.clone(), options.clone(), store.clone(), addr, service, listener) => {}
        _ = closed => {}
    }
}

/// The paired device `query` names: its endpoint ID, else its name when no
/// other paired device has it (ignoring case and a trailing `.omabridge`, so
/// an SSH `Host *.omabridge` pattern can pass the host name as it is).
pub fn find_peer(store: &Store, query: &str) -> Result<crate::Peer, &'static str> {
    let peers = store.peers().map_err(|_| "omabridge_command_failed")?;
    if let Some(peer) = peers.iter().find(|peer| peer.id == query) {
        return Ok(peer.clone());
    }
    let named = |name: &str| -> Vec<&crate::Peer> {
        peers
            .iter()
            .filter(|peer| peer.name.eq_ignore_ascii_case(name))
            .collect()
    };
    let mut found = named(query);
    if found.is_empty()
        && let Some(stem) = query
            .len()
            .checked_sub(".omabridge".len())
            .filter(|&at| {
                query.is_char_boundary(at) && query[at..].eq_ignore_ascii_case(".omabridge")
            })
            .map(|at| &query[..at])
    {
        found = named(stem);
    }
    match found.as_slice() {
        [peer] => Ok((*peer).clone()),
        [] => Err("omabridge_peer_not_found"),
        _ => Err("omabridge_peer_ambiguous"),
    }
}

/// The paired device `peer` (an ID or a unique name) and the address to dial
/// for `service` on it, once it grants that service. `address` replaces the
/// saved one after an address change.
pub fn forward_target(
    store: &Store,
    peer: &str,
    service: &str,
    address: Option<EndpointAddr>,
) -> Result<(String, EndpointAddr), &'static str> {
    if !valid_service(service) {
        return Err("omabridge_forward_invalid");
    }
    let trusted = find_peer(store, peer)?;
    if !trusted.remote_services.iter().any(|item| item == service) {
        return Err("omabridge_service_not_granted");
    }
    let address = match address {
        Some(address) if address.id.to_string() == trusted.id => address,
        Some(_) => return Err("omabridge_forward_invalid"),
        None => trusted.address.ok_or("omabridge_peer_unreachable")?,
    };
    Ok((trusted.id, address))
}

/// Sends one request to this identity's running server over its control
/// socket and reads the answer line. None when no server with a control
/// socket runs; otherwise the still open socket and the answer, or the
/// server's error code.
async fn server_request(
    store: &Store,
    request: serde_json::Value,
) -> Option<
    Result<(
        tokio::io::BufReader<tokio::net::UnixStream>,
        serde_json::Value,
    )>,
> {
    store.active_endpoint().ok()?;
    server_socket_request(store, request).await
}
async fn server_socket_request(
    store: &Store,
    request: serde_json::Value,
) -> Option<
    Result<(
        tokio::io::BufReader<tokio::net::UnixStream>,
        serde_json::Value,
    )>,
> {
    use tokio::io::AsyncBufReadExt;
    let socket = tokio::net::UnixStream::connect(store.root().join(CONTROL_SOCKET))
        .await
        .ok()?;
    Some(
        async {
            let mut reader = tokio::io::BufReader::new(socket);
            reader
                .get_mut()
                .write_all(format!("{request}\n").as_bytes())
                .await?;
            let mut line = String::new();
            // The server dials the peer before answering.
            timeout(Duration::from_secs(60), reader.read_line(&mut line))
                .await
                .context("server did not answer")??;
            let answer: serde_json::Value =
                serde_json::from_str(&line).context("server did not answer")?;
            if answer.get("error").is_some() {
                bail!(
                    "{}",
                    answer["error"]
                        .as_str()
                        .unwrap_or("omabridge_peer_unreachable")
                );
            }
            Ok((reader, answer))
        }
        .await,
    )
}

/// Asks a peer that shares `t3` for a one-use native T3 pairing.
async fn t3_pair_with(
    endpoint: &Endpoint,
    options: &NetOptions,
    addr: &EndpointAddr,
) -> Result<crate::t3_pair::T3Pairing> {
    let (_pipe, response) = request(endpoint, options, addr, &Request::T3Pair)
        .await
        .map_err(|_| anyhow::Error::msg("omabridge_t3_pair_unavailable"))?;
    match response {
        Response::T3Pairing { pairing } => {
            pairing.validate()?;
            ensure!(
                pairing.label == format!("{}{}", crate::t3_pair::LABEL_PREFIX, endpoint.id()),
                "T3 pairing label mismatch"
            );
            Ok(pairing)
        }
        Response::Denied => bail!("omabridge_t3_pair_refused"),
        _ => bail!("omabridge_t3_pair_unavailable"),
    }
}
fn t3_pair_error(error: &anyhow::Error) -> &'static str {
    let text = format!("{error}");
    [
        "omabridge_t3_pair_refused",
        "omabridge_t3_pair_unavailable",
        "omabridge_service_not_granted",
        "omabridge_peer_unreachable",
        "omabridge_peer_not_found",
        "omabridge_peer_ambiguous",
    ]
    .into_iter()
    .find(|code| text == *code)
    .unwrap_or("omabridge_t3_pair_unavailable")
}
/// A one-use T3 pairing through this identity's running server. None when no
/// server runs.
pub async fn t3_pair_through_server(
    store: &Store,
    peer: &str,
) -> Option<Result<crate::t3_pair::T3Pairing>> {
    let answered = server_request(store, serde_json::json!({ "t3Pair": peer })).await?;
    Some(answered.and_then(|(_, answer)| {
        let pairing: crate::t3_pair::T3Pairing = serde_json::from_value(answer["pairing"].clone())
            .map_err(|_| anyhow::Error::msg("omabridge_t3_pair_unavailable"))?;
        pairing.validate()?;
        Ok(pairing)
    }))
}

/// Use only the already running endpoint: never create a duplicate identity.
pub async fn delegated_enroll_through_server(
    store: &Store,
    peer: &str,
    client: &str,
    environment: &str,
) -> Result<crate::enrollment::Enrollment> {
    let (_, answer) = server_socket_request(
        store,
        serde_json::json!({"delegatedEnroll": {
            "peer": peer, "clientId": client, "environmentId": environment
        }}),
    )
    .await
    .context("issuer requires running bridge")??;
    let enrollment: crate::enrollment::Enrollment =
        serde_json::from_value(answer["enrollment"].clone())
            .map_err(|_| anyhow::anyhow!("invalid issuer response"))?;
    enrollment.validate(client, environment, enrollment_now()?)?;
    Ok(enrollment)
}
async fn delegated_enroll_with(
    endpoint: &Endpoint,
    options: &NetOptions,
    addr: &EndpointAddr,
    client: &str,
    environment: &str,
) -> Result<crate::enrollment::Enrollment> {
    client.parse::<iroh::EndpointId>()?;
    let (_, response) = request(
        endpoint,
        options,
        addr,
        &Request::DelegatedEnroll {
            environment_id: environment.into(),
            client_id: client.into(),
        },
    )
    .await?;
    match response {
        Response::Enrollment { enrollment } => {
            let now = enrollment_now()?;
            enrollment.validate(client, environment, now)?;
            ensure!(
                enrollment.expires_at <= enrollment_now()?.saturating_add(120_000),
                "delegated session exceeds limit"
            );
            Ok(enrollment)
        }
        _ => bail!("delegation refused"),
    }
}

/// Asks this identity's running server to forward `listen` to `service` on
/// `peer`. None when no server with a control socket runs; otherwise the open
/// socket, which keeps the forward alive until it closes, and the listener's
/// address.
pub async fn forward_through_server(
    store: &Store,
    peer: &str,
    service: &str,
    listen: SocketAddr,
    address: Option<&EndpointAddr>,
) -> Option<Result<(tokio::net::UnixStream, SocketAddr)>> {
    let request = serde_json::json!({ "forward": {
        "peer": peer, "service": service, "listen": listen.to_string(), "address": address,
    }});
    let answered = server_request(store, request).await?;
    Some(answered.and_then(|(reader, answer)| {
        let local = answer["forwarding"]["listen"]
            .as_str()
            .context("omabridge_peer_unreachable")?;
        Ok((reader.into_inner(), local.parse()?))
    }))
}

/// Asks this identity's running server for one stream to `service` on `peer`.
/// None when no server with a control socket runs; otherwise the socket,
/// which carries the stream's bytes both ways from then on.
pub async fn connect_through_server(
    store: &Store,
    peer: &str,
    service: &str,
) -> Option<Result<tokio::io::BufReader<tokio::net::UnixStream>>> {
    let request = serde_json::json!({ "connect": { "peer": peer, "service": service } });
    let answered = server_request(store, request).await?;
    Some(answered.and_then(|(reader, answer)| {
        ensure!(answer["connected"] == true, "omabridge_peer_unreachable");
        // The reader may already hold the service's first bytes.
        Ok(reader)
    }))
}

/// `{"connect":{"peer","service"}}`: one stream to a peer's service through
/// this server's own endpoint, carried over the requesting connection, which
/// is how `omabridge connect` serves as an SSH ProxyCommand.
async fn serve_connect(
    endpoint: &Endpoint,
    options: &NetOptions,
    store: &Store,
    spec: &serde_json::Value,
    buffered: Vec<u8>,
    read: tokio::net::unix::OwnedReadHalf,
    mut write: tokio::net::unix::OwnedWriteHalf,
) {
    use serde_json::json;
    let peer = spec["peer"].as_str().unwrap_or_default();
    let service = spec["service"].as_str().unwrap_or_default();
    let opened = match forward_target(store, peer, service, None) {
        Ok((_, addr)) => open_with(endpoint, options, &addr, service, false)
            .await
            .map_err(|_| "omabridge_peer_unreachable"),
        Err(code) => Err(code),
    };
    let answer = match &opened {
        Ok(_) => json!({ "connected": true }),
        Err(code) => json!({ "error": code }),
    };
    if write
        .write_all(format!("{answer}\n").as_bytes())
        .await
        .is_err()
    {
        return;
    }
    if let Ok(mut pipe) = opened {
        // Bytes the client sent right after its request were read with it.
        let local = tokio::io::join(std::io::Cursor::new(buffered).chain(read), write);
        let _ = pipe.transfer(local).await;
    }
}

/// Bridges each connection on the loopback `listener` to `service` on `addr`,
/// at most 64 at a time.
pub(crate) async fn forward_with(
    endpoint: Endpoint,
    options: NetOptions,
    store: Store,
    addr: EndpointAddr,
    service: String,
    listener: TcpListener,
) -> Result<()> {
    ensure!(
        listener.local_addr()?.ip().is_loopback(),
        "local bridge must bind loopback"
    );
    let peer_id = addr.id.to_string();
    // Keep an explicit address override until the paired peer advertises a new
    // address. Never keep using an obsolete route after learning its replacement.
    let initial_address = find_peer(&store, &peer_id)
        .ok()
        .and_then(|peer| peer.address);
    let capacity = Arc::new(Semaphore::new(64));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (socket, _) = accepted?;
                let Ok(permit) = capacity.clone().try_acquire_owned() else { drop(socket); continue };
                let Ok(peer) = find_peer(&store, &peer_id) else { continue };
                if !peer.remote_services.contains(&service) { continue; }
                let current = if peer.address != initial_address {
                    let Some(address) = peer.address else { continue };
                    address
                } else {
                    addr.clone()
                };
                let (endpoint, options, addr, service) = (endpoint.clone(), options.clone(), current, service.clone());
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Ok(mut pipe) = open_with(&endpoint, &options, &addr, &service, false).await {
                        let _ = pipe.transfer(socket).await;
                    }
                });
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}

/// Opens one stream to a service a peer granted this device.
pub(crate) async fn open_with(
    endpoint: &Endpoint,
    options: &NetOptions,
    addr: &EndpointAddr,
    service: &str,
    public: bool,
) -> Result<Pipe> {
    ensure!(valid_service(service), "invalid service name");
    let (mut pipe, response) = request(
        endpoint,
        options,
        addr,
        &Request::Open {
            service: service.to_owned(),
            public,
            compression: (options.compress_t3 && service == "t3")
                .then(|| "deflate-block-v1".into()),
        },
    )
    .await?;
    ensure!(
        matches!(response, Response::Ready)
            || (matches!(response, Response::ReadyCompressed)
                && options.compress_t3
                && service == "t3"),
        "service denied or unavailable"
    );
    pipe.compressed = matches!(response, Response::ReadyCompressed);
    Ok(pipe)
}

/// Uses an invitation from `endpoint` and remembers the inviting device once approved.
async fn pair_with(
    endpoint: &Endpoint,
    options: &NetOptions,
    store: &Store,
    invite: &Invitation,
    name: &str,
    now: u64,
) -> Result<PairDecision> {
    ensure!(
        invite.version == 1 && invite.expires > now,
        "unsupported or expired invitation"
    );
    let (_pipe, response) = request(
        endpoint,
        options,
        &invite.address,
        &Request::Pair {
            token: invite.token.clone(),
            name: name.to_owned(),
        },
    )
    .await?;
    match response {
        Response::Pair { decision } => {
            if let PairDecision::Approved { services } = &decision {
                store.remember_peer(&invite.address, &invite.name, services)?;
            }
            Ok(decision)
        }
        _ => bail!("pairing denied"),
    }
}

async fn request_manage(
    endpoint: &Endpoint,
    options: &NetOptions,
    addr: &EndpointAddr,
    command: &serde_json::Value,
) -> Result<serde_json::Value> {
    let (_pipe, response) = request(
        endpoint,
        options,
        addr,
        &Request::Manage {
            command: command.clone(),
        },
    )
    .await?;
    match response {
        Response::Managed { outcome } => Ok(outcome),
        _ => bail!("management refused"),
    }
}

pub(crate) fn enrollment_now() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

pub fn unix_time() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

async fn endpoint(store: &Store, options: &NetOptions, incoming: bool) -> Result<Endpoint> {
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(store.secret_key()?)
        .clear_ip_transports()
        .clear_address_lookup()
        .bind_addr(options.bind)?;
    builder = builder.relay_mode(match &options.relay {
        Relay::Custom(url) => {
            ensure!(url.as_str().starts_with("https://"), "relay must use HTTPS");
            RelayMode::Custom(url.clone().into())
        }
        Relay::Public => RelayMode::Default,
        Relay::Disabled => RelayMode::Disabled,
    });
    if incoming {
        builder = builder.alpns(vec![ALPN.to_vec()]);
    }
    Ok(builder.bind().await?)
}

async fn write_header<T: Serialize>(send: &mut SendStream, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= HEADER_LIMIT, "control header too large");
    send.write_u32(bytes.len() as u32).await?;
    send.write_all(&bytes).await?;
    Ok(())
}

async fn read_header<T: DeserializeOwned>(recv: &mut RecvStream) -> Result<T> {
    let size = recv.read_u32().await? as usize;
    ensure!(
        (1..=HEADER_LIMIT).contains(&size),
        "invalid control header length"
    );
    let mut bytes = vec![0; size];
    recv.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).context("invalid control header")
}

pub struct Node {
    endpoint: Endpoint,
    relay: Option<RelayUrl>,
    task: JoinHandle<()>,
    sync: JoinHandle<()>,
    control: JoinHandle<()>,
    hosting: JoinHandle<()>,
    gateways: JoinHandle<()>,
    _runtime_lock: RuntimeReservation,
}
impl Node {
    pub async fn start(
        store: Store,
        services: BTreeMap<String, SocketAddr>,
        options: NetOptions,
    ) -> Result<Self> {
        let reservation = store.reserve_runtime()?;
        Self::start_reserved(store, services, options, reservation).await
    }
    /// Keep the same published service and grants while T3 changes its port.
    /// Only new streams resolve the runtime; established streams are never replayed.
    pub async fn start_tracking_t3(
        store: Store,
        services: BTreeMap<String, SocketAddr>,
        options: NetOptions,
        runtime: PathBuf,
    ) -> Result<Self> {
        ensure!(
            runtime.is_absolute() && services.contains_key("t3"),
            "T3 tracking requires an absolute runtime path and a published t3 service"
        );
        let reservation = store.reserve_runtime()?;
        Self::start_reserved_with_configuration(
            store,
            services,
            options,
            reservation,
            None,
            Some(runtime),
        )
        .await
    }
    pub async fn start_reserved(
        store: Store,
        services: BTreeMap<String, SocketAddr>,
        options: NetOptions,
        reservation: RuntimeReservation,
    ) -> Result<Self> {
        Self::start_reserved_with_authority(store, services, options, reservation, None).await
    }
    /// Explicit opt-in embedding point; unconfigured nodes deny enrollment.
    pub async fn start_reserved_with_authority(
        store: Store,
        services: BTreeMap<String, SocketAddr>,
        options: NetOptions,
        reservation: RuntimeReservation,
        authority: Option<Arc<dyn crate::enrollment::EnrollmentAuthority>>,
    ) -> Result<Self> {
        Self::start_reserved_with_configuration(
            store,
            services,
            options,
            reservation,
            authority,
            None,
        )
        .await
    }
    /// Compose explicit enrollment authority and optional runtime tracking without widening either.
    /// T3 pairings come from this user's own T3 Code (`~/.t3`) when `t3` is published.
    pub async fn start_reserved_with_configuration(
        store: Store,
        services: BTreeMap<String, SocketAddr>,
        options: NetOptions,
        reservation: RuntimeReservation,
        authority: Option<Arc<dyn crate::enrollment::EnrollmentAuthority>>,
        t3_runtime: Option<PathBuf>,
    ) -> Result<Self> {
        Self::start_with_t3_issuer(
            store,
            services,
            options,
            reservation,
            authority,
            t3_runtime,
            None,
        )
        .await
    }
    /// As above, with the T3 Code that issues pairings: `Some(None)` issues none.
    pub async fn start_with_t3_issuer(
        store: Store,
        services: BTreeMap<String, SocketAddr>,
        options: NetOptions,
        reservation: RuntimeReservation,
        authority: Option<Arc<dyn crate::enrollment::EnrollmentAuthority>>,
        t3_runtime: Option<PathBuf>,
        t3_issuer: Option<Option<crate::t3_pair::T3Issuer>>,
    ) -> Result<Self> {
        if let Some(runtime) = &t3_runtime {
            ensure!(
                runtime.is_absolute() && services.contains_key("t3"),
                "T3 tracking requires an absolute runtime path and a published t3 service"
            );
        }
        ensure!(
            reservation.belongs_to(&store),
            "server reservation belongs to another identity"
        );
        ensure!(
            !services.is_empty() && services.len() <= 32,
            "publish 1..32 services"
        );
        for (name, target) in &services {
            ensure!(
                valid_service(name) && target.ip().is_loopback() && target.port() != 0,
                "services require a valid name and explicit loopback TCP target"
            );
        }
        let endpoint = endpoint(&store, &options, true).await?;
        // Invitations copy this address, so wait (bounded) until it names the
        // home relay; peers behind NAT can only reach this device through it.
        if options.relay != Relay::Disabled {
            let _ = timeout(RELAY_WAIT, endpoint.online()).await;
        }
        let relay = match &options.relay {
            Relay::Custom(url) => Some(url.clone()),
            _ => None,
        };
        let sync = tokio::spawn(sync_loop(
            endpoint.clone(),
            options.clone(),
            store.clone(),
            relay.clone(),
        ));
        let control = tokio::spawn(control_loop(
            control_socket(&store),
            endpoint.clone(),
            options.clone(),
            store.clone(),
            relay.clone(),
        ));
        let hosting = tokio::spawn(crate::hosting::host_loop(store.clone()));
        let gateways = tokio::spawn(crate::gateway::gateway_loop(
            store.clone(),
            endpoint.clone(),
            options.clone(),
        ));
        let announce = relay.clone();
        let listener = endpoint.clone();
        let t3_issuer = match t3_issuer {
            Some(issuer) => issuer,
            None if services.contains_key("t3") => crate::t3_pair::T3Issuer::detect(),
            None => None,
        };
        let services = Arc::new(ServiceTargets {
            fixed: services,
            t3_runtime,
            t3_issuer,
        });
        let capacity = Arc::new(Semaphore::new(64));
        let open: Arc<std::sync::Mutex<std::collections::HashMap<iroh::EndpointId, usize>>> =
            Arc::default();
        let unknown = Arc::new(Semaphore::new(UNKNOWN_SLOTS));
        let compress_t3 = options.compress_t3;
        let task = tokio::spawn(async move {
            let mut workers = JoinSet::new();
            loop {
                tokio::select! {
                    incoming = listener.accept() => {
                        let Some(incoming) = incoming else { break };
                        let Ok(permit) = capacity.clone().try_acquire_owned() else { incoming.refuse(); continue };
                        let store = store.clone(); let services = services.clone(); let authority = authority.clone();
                        let own = advertised(&listener, announce.as_ref());
                        let open = open.clone();
                        let unknown = unknown.clone();
                        workers.spawn(async move {
                            let _permit = permit;
                            if let Ok(Ok(connection)) = timeout(SETUP_TIMEOUT, incoming).await {
                                // One device cannot hold every slot (a busy gateway included).
                                let remote = connection.remote_id();
                                let known = store
                                    .peers()
                                    .is_ok_and(|peers| peers.iter().any(|peer| peer.id == remote.to_string()));
                                let unknown_slot = if known {
                                    None
                                } else {
                                    match unknown.clone().try_acquire_owned() {
                                        Ok(slot) => Some(slot),
                                        Err(_) => {
                                            connection.close(0u32.into(), b"busy");
                                            return;
                                        }
                                    }
                                };
                                let _unknown_slot = unknown_slot;
                                let admitted = {
                                    let mut open = open.lock().expect("open connections");
                                    let count = open.entry(remote).or_insert(0);
                                    *count += 1;
                                    *count <= PER_PEER
                                };
                                if admitted {
                                    // Deliberately discard error text: requests can contain invitation secrets.
                                    let _ = serve_connection(connection, store, services, own, known, authority, compress_t3).await;
                                } else {
                                    connection.close(0u32.into(), b"busy");
                                }
                                let mut open = open.lock().expect("open connections");
                                if let Some(count) = open.get_mut(&remote) {
                                    *count -= 1;
                                    if *count == 0 {
                                        open.remove(&remote);
                                    }
                                }
                            }
                        });
                    }
                    _ = workers.join_next(), if !workers.is_empty() => {}
                }
            }
        });
        Ok(Self {
            endpoint,
            relay,
            task,
            sync,
            control,
            hosting,
            gateways,
            _runtime_lock: reservation,
        })
    }
    pub fn addr(&self) -> EndpointAddr {
        advertised(&self.endpoint, self.relay.as_ref())
    }
    pub async fn shutdown(self) {
        self.task.abort();
        self.sync.abort();
        self.control.abort();
        self.hosting.abort();
        self.gateways.abort();
        self.endpoint.close().await;
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        self.task.abort();
        self.sync.abort();
        self.control.abort();
        self.hosting.abort();
        self.gateways.abort();
    }
}

struct ServiceTargets {
    fixed: BTreeMap<String, SocketAddr>,
    t3_runtime: Option<PathBuf>,
    t3_issuer: Option<crate::t3_pair::T3Issuer>,
}

impl ServiceTargets {
    fn resolve(&self, service: &str) -> Option<SocketAddr> {
        let fixed = *self.fixed.get(service)?;
        if service != "t3" {
            return Some(fixed);
        }
        let Some(path) = &self.t3_runtime else {
            return Some(fixed);
        };
        // Deserialize only the public port field, with a bounded read. A missing
        // or invalid runtime fails closed; the old port may now belong to another app.
        use std::io::Read;
        #[derive(Deserialize)]
        struct Runtime {
            port: u16,
        }
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .ok()?
            .take(64 * 1024 + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        if bytes.len() > 64 * 1024 {
            return None;
        }
        let runtime: Runtime = serde_json::from_slice(&bytes).ok()?;
        (runtime.port != 0).then(|| SocketAddr::from(([127, 0, 0, 1], runtime.port)))
    }
}

async fn serve_connection(
    connection: Connection,
    store: Store,
    services: Arc<ServiceTargets>,
    own: EndpointAddr,
    known: bool,
    authority: Option<Arc<dyn crate::enrollment::EnrollmentAuthority>>,
    compress_t3: bool,
) -> Result<()> {
    // Devices this one has never paired with get little time to say what they want.
    let setup = if known { SETUP_TIMEOUT } else { UNKNOWN_SETUP };
    let (mut send, mut recv) = timeout(setup, connection.accept_bi()).await??;
    let request: Request = timeout(setup, read_header(&mut recv)).await??;
    let peer = connection.remote_id().to_string();
    match request {
        Request::DelegatedEnroll {
            environment_id,
            client_id,
        } => {
            let result: Result<crate::enrollment::Enrollment> = async {
                ensure!(store.authorized(&peer, "t3")?, "delegation refused");
                client_id.parse::<iroh::EndpointId>()?;
                let now = enrollment_now()?;
                let enrollment = authority
                    .as_ref()
                    .context("delegation unavailable")?
                    .issue_delegated(&peer, &client_id, &environment_id, now)
                    .await?;
                ensure!(store.authorized(&peer, "t3")?, "delegation withdrawn");
                enrollment.validate(&client_id, &environment_id, enrollment_now()?)?;
                ensure!(
                    enrollment.expires_at <= enrollment_now()?.saturating_add(120_000),
                    "delegated session exceeds limit"
                );
                Ok(enrollment)
            }
            .await;
            let response = match result {
                Ok(enrollment) => Response::Enrollment { enrollment },
                Err(_) => Response::Denied,
            };
            write_header(&mut send, &response).await?;
            send.finish()?;
            let _ = timeout(DENIED_LINGER, connection.closed()).await;
        }
        Request::Enroll { environment_id } => {
            let now = enrollment_now()?;
            let result: Result<crate::enrollment::Enrollment> = async {
                let manifest = crate::catalog::read_for_peer(&store, &peer, now)?;
                ensure!(
                    manifest["environments"].as_array().is_some_and(|rows| rows
                        .iter()
                        .any(|e| e["environmentId"] == environment_id)),
                    "enrollment refused"
                );
                let authority = authority.as_ref().context("enrollment unavailable")?;
                let enrollment = authority.issue(&peer, &environment_id, now).await?;
                enrollment.validate(&peer, &environment_id, now)?;
                // Recheck current grant after an issuance that may have awaited I/O.
                let current = crate::catalog::read_for_peer(&store, &peer, enrollment_now()?)?;
                ensure!(
                    current["environments"].as_array().is_some_and(|rows| rows
                        .iter()
                        .any(|e| e["environmentId"] == environment_id)),
                    "enrollment refused"
                );
                Ok(enrollment)
            }
            .await;
            let response = match result {
                Ok(enrollment) => Response::Enrollment { enrollment },
                Err(_) => Response::Denied,
            };
            write_header(&mut send, &response).await?;
            send.finish()?;
            let _ = timeout(DENIED_LINGER, connection.closed()).await;
        }
        Request::Catalog => {
            let response = match crate::catalog::read_for_peer(
                &store,
                &peer,
                unix_time()?.saturating_mul(1000),
            ) {
                Ok(manifest) => Response::Catalog { manifest },
                Err(error)
                    if error
                        .downcast_ref::<crate::catalog_client::CatalogDenied>()
                        .is_some() =>
                {
                    Response::Denied
                }
                Err(_) => Response::Unavailable,
            };
            write_header(&mut send, &response).await?;
            send.finish()?;
            let _ = timeout(DENIED_LINGER, connection.closed()).await;
        }
        Request::Pair { token, name } => {
            let response = match store.claim(&token, &peer, &name, unix_time()?) {
                Ok(decision) => Response::Pair { decision },
                Err(_) => Response::Denied,
            };
            write_header(&mut send, &response).await?;
            send.finish()?;
            let _ = timeout(DENIED_LINGER, connection.closed()).await;
        }
        Request::Hello {
            name,
            address,
            admin,
            grants,
            routes,
        } => {
            let refreshed = store.refresh_peer(
                &peer,
                &name,
                address.as_ref(),
                admin,
                grants.as_ref().map(Grants::pair),
            );
            let refreshed = refreshed.and_then(|()| match routes {
                Some(routes) => store.refresh_routes(&peer, &routes, unix_time()?),
                None => Ok(()),
            });
            let entry = store.peers()?.into_iter().find(|item| item.id == peer);
            let response = match refreshed {
                Ok(())
                    if store
                        .peers()?
                        .iter()
                        .any(|item| item.id == peer && item.admin) =>
                {
                    crate::manage::confirm_relay(store.root());
                    Response::Hello {
                        name: store.name()?,
                        address: own,
                        admin: true,
                        grants: entry.as_ref().map(Grants::of),
                        routes: Some(crate::routes::for_peer(&store, &peer)),
                    }
                }
                Ok(()) => Response::Hello {
                    name: store.name()?,
                    address: own,
                    admin: entry.as_ref().is_some_and(|item| item.admin),
                    grants: entry.as_ref().map(Grants::of),
                    routes: Some(crate::routes::for_peer(&store, &peer)),
                },
                Err(_) => Response::Denied,
            };
            write_header(&mut send, &response).await?;
            send.finish()?;
            let _ = timeout(DENIED_LINGER, connection.closed()).await;
        }
        Request::Manage { command } => {
            // Authorization, the allowed actions and the audit live in `manage`.
            let (result, deferred) = crate::manage::serve_remote(&store, &peer, &command).await;
            write_header(&mut send, &Response::Managed { outcome: result }).await?;
            send.finish()?;
            let _ = timeout(DENIED_LINGER, connection.closed()).await;
            // Restarting or stopping this service waits until the answer is out.
            deferred.flush();
        }
        Request::T3Pair => {
            let result: Result<crate::t3_pair::T3Pairing> = async {
                ensure!(store.authorized(&peer, "t3")?, "T3 pairing refused");
                let issuer = services
                    .t3_issuer
                    .as_ref()
                    .context("T3 pairing unavailable")?;
                let target = services.resolve("t3").context("T3 unavailable")?;
                let pairing = issuer.issue(target, &peer).await?;
                // Recheck the grant after an issuance that awaited I/O.
                ensure!(store.authorized(&peer, "t3")?, "T3 pairing withdrawn");
                Ok(pairing)
            }
            .await;
            let response = match result {
                Ok(pairing) => Response::T3Pairing { pairing },
                Err(_) => Response::Denied,
            };
            write_header(&mut send, &response).await?;
            send.finish()?;
            let _ = timeout(DENIED_LINGER, connection.closed()).await;
        }
        Request::Open {
            service,
            public,
            compression,
        } => {
            // A gateway's anonymous client needs this device's consent to public exposure too.
            let allowed = |store: &Store| -> Result<bool> {
                Ok(store.authorized(&peer, &service)?
                    && (!public
                        || (crate::gateway::PUBLIC_SERVICES.contains(&service.as_str())
                            && store.public_allowed(&peer, &service)?)))
            };
            let target = allowed(&store)
                .unwrap_or(false)
                .then(|| services.resolve(&service))
                .flatten();
            let Some(target) = target else {
                write_header(&mut send, &Response::Denied).await?;
                send.finish()?;
                let _ = timeout(DENIED_LINGER, connection.closed()).await;
                return Ok(());
            };
            let socket = match timeout(SETUP_TIMEOUT, TcpStream::connect(target)).await {
                Ok(Ok(socket)) => socket,
                _ => {
                    write_header(&mut send, &Response::Denied).await?;
                    send.finish()?;
                    let _ = timeout(DENIED_LINGER, connection.closed()).await;
                    return Ok(());
                }
            };
            let compressed = compress_t3
                && service == "t3"
                && compression.as_deref() == Some("deflate-block-v1");
            write_header(
                &mut send,
                &if compressed {
                    Response::ReadyCompressed
                } else {
                    Response::Ready
                },
            )
            .await?;
            let mut pipe = Pipe {
                send,
                recv,
                connection,
                compressed,
            };
            let transfer = pipe.transfer(socket);
            tokio::pin!(transfer);
            let mut check = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    result = &mut transfer => { result?; break },
                    _ = check.tick() => { if !allowed(&store)? { break } }
                }
            }
        }
    }
    Ok(())
}

pub struct Client {
    endpoint: Endpoint,
    store: Store,
    options: NetOptions,
}
pub struct Pipe {
    /// Raw wire stream. Use transfer/write_prefix when compression is negotiated.
    pub send: SendStream,
    /// Raw wire stream; compressed frames are not application bytes.
    pub recv: RecvStream,
    connection: Connection,
    compressed: bool,
}
impl Drop for Pipe {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"session closed");
    }
}
impl Pipe {
    /// Write initial application bytes using the negotiated transport format.
    pub async fn write_prefix(&mut self, bytes: &[u8]) -> Result<()> {
        if self.compressed {
            crate::compression::encode(&mut &bytes[..], &mut self.send).await?;
        } else {
            self.send.write_all(bytes).await?;
        }
        Ok(())
    }
    pub fn is_compressed(&self) -> bool {
        self.compressed
    }
    pub async fn transfer<S>(&mut self, socket: S) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let (mut read, mut write) = tokio::io::split(socket);
        let upstream = async {
            if self.compressed {
                crate::compression::encode(&mut read, &mut self.send).await?;
            } else {
                tokio::io::copy(&mut read, &mut self.send).await?;
            }
            self.send.finish()?;
            Ok::<_, anyhow::Error>(())
        };
        let downstream = async {
            if self.compressed {
                crate::compression::decode(&mut self.recv, &mut write).await?;
            } else {
                tokio::io::copy(&mut self.recv, &mut write).await?;
            }
            write.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        };
        tokio::try_join!(upstream, downstream)?;
        // Finishing a QUIC stream only queues its FIN. Keep the connection alive
        // until the peer acknowledges the final bytes; otherwise Drop truncates it.
        self.send.stopped().await?;
        Ok(())
    }
}
impl Client {
    pub async fn new(store: Store, options: NetOptions) -> Result<Self> {
        Ok(Self {
            endpoint: endpoint(&store, &options, false).await?,
            store,
            options,
        })
    }
    /// Sends one `omabridge manage` command to a device that lets this one manage
    /// it; returns its result: a snapshot or `{"error":code}`.
    pub async fn manage(
        &self,
        addr: &EndpointAddr,
        command: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        request_manage(&self.endpoint, &self.options, addr, command).await
    }
    /// Read only this paired device's explicitly allowed environment catalog.
    /// This does not grant T3 access or return any desktop credentials.
    pub async fn catalog(&self, addr: &EndpointAddr) -> Result<serde_json::Value> {
        let (_pipe, response) =
            request(&self.endpoint, &self.options, addr, &Request::Catalog).await?;
        match response {
            Response::Catalog { manifest } => {
                ensure!(
                    manifest["bridgeId"] == addr.id.to_string()
                        && manifest["clientId"] == self.store.id()?,
                    "catalog identity mismatch"
                );
                Ok(manifest)
            }
            Response::Denied => Err(crate::catalog_client::CatalogDenied.into()),
            _ => bail!("catalog refused"),
        }
    }
    pub async fn enroll(
        &self,
        addr: &EndpointAddr,
        environment_id: &str,
    ) -> Result<crate::enrollment::Enrollment> {
        let (_pipe, response) = request(
            &self.endpoint,
            &self.options,
            addr,
            &Request::Enroll {
                environment_id: environment_id.into(),
            },
        )
        .await?;
        match response {
            Response::Enrollment { enrollment } => {
                enrollment.validate(&self.store.id()?, environment_id, enrollment_now()?)?;
                Ok(enrollment)
            }
            _ => bail!("enrollment refused"),
        }
    }
    /// A one-use native T3 pairing from a device that shares `t3` with this one.
    pub async fn t3_pair(&self, addr: &EndpointAddr) -> Result<crate::t3_pair::T3Pairing> {
        t3_pair_with(&self.endpoint, &self.options, addr).await
    }
    /// Announces this device's name to every paired device with a known address
    /// and stores their current names and addresses. `own` is this device's
    /// address when it serves. Returns (answered, tried).
    pub async fn announce(&self, own: Option<EndpointAddr>) -> Result<(usize, usize)> {
        hello_all(&self.endpoint, &self.options, &self.store, own).await
    }
    pub async fn pair(&self, invite: &Invitation, name: &str, now: u64) -> Result<PairDecision> {
        pair_with(
            &self.endpoint,
            &self.options,
            &self.store,
            invite,
            name,
            now,
        )
        .await
    }
    pub async fn open(&self, addr: &EndpointAddr, service: &str) -> Result<Pipe> {
        open_with(&self.endpoint, &self.options, addr, service, false).await
    }
    pub async fn forward(
        self: Arc<Self>,
        addr: EndpointAddr,
        service: String,
        listener: TcpListener,
    ) -> Result<()> {
        forward_with(
            self.endpoint.clone(),
            self.options.clone(),
            self.store.clone(),
            addr,
            service,
            listener,
        )
        .await
    }
    pub async fn close(&self) {
        self.endpoint.close().await;
    }
}

async fn request_catalog(
    endpoint: &Endpoint,
    options: &NetOptions,
    store: &Store,
    addr: &EndpointAddr,
) -> Result<(Pipe, serde_json::Value)> {
    let (pipe, response) = request(endpoint, options, addr, &Request::Catalog).await?;
    match response {
        Response::Catalog { manifest } => {
            ensure!(
                manifest["bridgeId"] == addr.id.to_string()
                    && manifest["clientId"] == store.id()?,
                "catalog identity mismatch"
            );
            Ok((pipe, manifest))
        }
        Response::Denied => Err(crate::catalog_client::CatalogDenied.into()),
        _ => bail!("catalog unavailable"),
    }
}
/// Obtain a native catalog through the running identity, falling back only when no identity is serving.
pub async fn remote_catalog(store: &Store, addr: &EndpointAddr) -> Result<serde_json::Value> {
    if let Some(answer) =
        server_request(store, serde_json::json!({"catalog":addr.id.to_string()})).await
    {
        let (_, answer) = answer?;
        if answer["denied"] == true {
            return Err(crate::catalog_client::CatalogDenied.into());
        }
        return Ok(answer["manifest"].clone());
    }
    ensure!(
        store.active_endpoint().is_err(),
        "running device has no supported catalog controller"
    );
    let _reservation = store.reserve_runtime()?;
    let client = Client::new(
        store.clone(),
        NetOptions {
            bind: "0.0.0.0:0".parse()?,
            relay: Relay::load(store.root())?,
            compress_t3: false,
        },
    )
    .await?;
    let result = client.catalog(addr).await;
    client.close().await;
    result
}
#[cfg(test)]
mod recovery_tests {
    use super::*;

    #[test]
    fn compression_preserves_legacy_wire_negotiation() -> Result<()> {
        #[derive(Deserialize)]
        #[serde(tag = "op", rename_all = "snake_case")]
        enum LegacyRequest {
            Open {
                service: String,
                #[serde(default)]
                public: bool,
            },
        }
        let offer = Request::Open {
            service: "t3".into(),
            public: true,
            compression: Some("deflate-block-v1".into()),
        };
        let LegacyRequest::Open { service, public } =
            serde_json::from_value(serde_json::to_value(offer)?)?;
        assert_eq!(service, "t3");
        assert!(public);
        assert!(matches!(
            serde_json::from_str::<Response>(r#"{"result":"ready"}"#)?,
            Response::Ready
        ));
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"op":"open","service":"t3"}"#)?,
            Request::Open {
                compression: None,
                ..
            }
        ));
        Ok(())
    }

    #[tokio::test]
    async fn published_t3_follows_runtime_port_and_recovers_after_missing_runtime() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let owner = Store::open(&dir.path().join("owner"), "owner")?;
        let guest = Store::open(&dir.path().join("guest"), "guest")?;
        let first = TcpListener::bind("127.0.0.1:0").await?;
        let second = TcpListener::bind("127.0.0.1:0").await?;
        let first_addr = first.local_addr()?;
        let second_addr = second.local_addr()?;
        let runtime = dir.path().join("server-runtime.json");
        let write_runtime = |port: u16| std::fs::write(&runtime, format!("{{\"port\":{port}}}"));
        write_runtime(first_addr.port())?;
        let node = Node::start_tracking_t3(
            owner.clone(),
            BTreeMap::from([("t3".into(), first_addr)]),
            NetOptions::loopback(),
            runtime.clone(),
        )
        .await?;
        let client = Client::new(guest.clone(), NetOptions::loopback()).await?;
        let now = unix_time()?;
        let token = owner.create_invite(&["t3".into()], Duration::from_secs(60), now)?;
        owner.claim(&token, &guest.id()?, "guest", now)?;
        owner.approve(&guest.id()?, now)?;
        let mut original = client.open(&node.addr(), "t3").await?;
        let (mut old_socket, _) = timeout(Duration::from_secs(2), first.accept()).await??;
        write_runtime(second_addr.port())?;
        let mut next = client.open(&node.addr(), "t3").await?;
        let (mut new_socket, _) = timeout(Duration::from_secs(2), second.accept()).await??;
        original.send.write_all(b"old").await?;
        next.send.write_all(b"new").await?;
        let mut bytes = [0; 3];
        timeout(Duration::from_secs(2), old_socket.read_exact(&mut bytes)).await??;
        assert_eq!(
            &bytes, b"old",
            "existing streams stay on their original target"
        );
        timeout(Duration::from_secs(2), new_socket.read_exact(&mut bytes)).await??;
        assert_eq!(&bytes, b"new");
        for invalid in ["{}", "{\"port\":0}", "{\"port\":65536}", "not json"] {
            std::fs::write(&runtime, invalid)?;
            assert!(client.open(&node.addr(), "t3").await.is_err());
        }
        std::fs::remove_file(&runtime)?;
        assert!(client.open(&node.addr(), "t3").await.is_err());
        assert!(
            timeout(Duration::from_millis(100), first.accept())
                .await
                .is_err(),
            "missing runtime must not use the stale port"
        );
        write_runtime(second_addr.port())?;
        drop(client.open(&node.addr(), "t3").await?);
        timeout(Duration::from_secs(2), second.accept()).await??;
        owner.revoke(&guest.id()?)?;
        assert!(client.open(&node.addr(), "t3").await.is_err());
        drop(original);
        drop(next);
        client.close().await;
        node.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn forward_recovers_on_the_same_listener_after_learning_a_new_address() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let owner = Store::open(&dir.path().join("owner"), "owner")?;
        let guest = Store::open(&dir.path().join("guest"), "guest")?;
        let tcp = TcpListener::bind("127.0.0.1:0").await?;
        let target = tcp.local_addr()?;
        let echo = tokio::spawn(async move {
            while let Ok((mut socket, _)) = tcp.accept().await {
                tokio::spawn(async move {
                    let (mut read, mut write) = socket.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                    let _ = write.shutdown().await;
                });
            }
        });
        let node = Node::start(
            owner.clone(),
            BTreeMap::from([("t3".into(), target)]),
            NetOptions::loopback(),
        )
        .await?;
        let client = Arc::new(Client::new(guest.clone(), NetOptions::loopback()).await?);
        let now = unix_time()?;
        let token = owner.create_invite(&["t3".into()], Duration::from_secs(60), now)?;
        owner.claim(&token, &guest.id()?, "guest", now)?;
        owner.approve(&guest.id()?, now)?;
        guest.remember_peer(&node.addr(), "owner", &["t3".into()])?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local = listener.local_addr()?;
        let forward = tokio::spawn(client.clone().forward(node.addr(), "t3".into(), listener));
        async fn exchange(local: SocketAddr) -> Result<Vec<u8>> {
            let mut socket = TcpStream::connect(local).await?;
            socket.write_all(b"recover without reconfiguration").await?;
            socket.shutdown().await?;
            let mut bytes = Vec::new();
            socket.read_to_end(&mut bytes).await?;
            Ok(bytes)
        }
        assert_eq!(
            timeout(Duration::from_secs(3), exchange(local)).await??,
            b"recover without reconfiguration"
        );
        node.shutdown().await;
        let node = Node::start(
            owner.clone(),
            BTreeMap::from([("t3".into(), target)]),
            NetOptions::loopback(),
        )
        .await?;
        guest.remember_peer(&node.addr(), "owner", &["t3".into()])?;
        let result = timeout(Duration::from_secs(3), exchange(local)).await;
        forward.abort();
        client.close().await;
        node.shutdown().await;
        echo.abort();
        assert_eq!(
            result.context("forward kept the obsolete route")??,
            b"recover without reconfiguration"
        );
        Ok(())
    }
}
