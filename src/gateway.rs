//! Public HTTPS entry points on a device with a public address, one port per
//! paired device's service (for example the T3 Code server of a laptop behind
//! NAT), so unmodified clients can reach it.
//!
//! Each gateway terminates TLS with this device's own certificate and pipes
//! the bytes, uninterpreted, into one fixed service of one fixed paired
//! device over OmaBridge. It is never an open proxy: the target comes from
//! this device's configuration, not from the request, and the target device
//! still checks its grant on every stream, so revoking or withdrawing the
//! grant there closes the gateway at once. Authentication is the service's
//! own (T3 Code's pairing and sessions).
use crate::{NetOptions, Store, network::open_with, read_document, write_document};
use anyhow::{Result, ensure};
use iroh::Endpoint;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinHandle, time::timeout};

const CONFIG: &str = "gateways.json";
const STATUS: &str = "gateways.status.json";
pub const MAX_GATEWAYS: usize = 16;
/// Concurrent client connections per gateway.
const MAX_CONNECTIONS: usize = 128;
const HANDSHAKE: Duration = Duration::from_secs(10);
/// Concurrent connections from one client address per gateway port.
const PER_ADDRESS: usize = 16;
/// A client that sends nothing after the handshake is let go.
const FIRST_DATA: Duration = Duration::from_secs(15);
/// A connection with no traffic either way for this long is closed (T3 Code
/// pings its WebSocket every 15 s).
const IDLE: Duration = Duration::from_secs(120);
/// Streams one gateway target may hold at once, so anonymous clients can
/// never use up the target device's allowance for this device.
const PER_TARGET: usize = 16;
/// Services a gateway may open: the ones whose own sign-in protects them
/// (T3 Code's pairing, and the MCP gateway's OAuth with one-time link codes).
pub const PUBLIC_SERVICES: [&str; 2] = ["t3", "mcp"];
const OPEN: Duration = Duration::from_secs(15);
const CHECK: Duration = Duration::from_secs(5);
/// Ports picked when none is given: high and random, so less easy to find.
pub const RANDOM_PORTS: std::ops::RangeInclusive<u16> = 20000..=60999;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gateway {
    /// Name clients use, covered by this device's certificate.
    pub host: String,
    pub port: u16,
    /// Paired device whose service is reached.
    pub peer: String,
    pub service: String,
}

impl Gateway {
    pub fn url(&self) -> String {
        if self.port == 443 {
            format!("https://{}/", self.host)
        } else {
            format!("https://{}:{}/", self.host, self.port)
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    gateways: Vec<Gateway>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayStatus {
    pub running: bool,
    /// `certificate`, `port` or `failed`.
    pub error: Option<String>,
}

pub fn load(state_dir: &Path) -> Vec<Gateway> {
    read_document::<Config>(&state_dir.join(CONFIG))
        .map(|config| config.gateways)
        .unwrap_or_default()
}

pub fn save(state_dir: &Path, gateways: &[Gateway]) -> Result<()> {
    ensure!(gateways.len() <= MAX_GATEWAYS, "too many gateways");
    write_document(
        &state_dir.join(CONFIG),
        &Config {
            gateways: gateways.to_vec(),
        },
        true,
    )
}

/// Status by gateway URL.
pub fn status(state_dir: &Path) -> BTreeMap<String, GatewayStatus> {
    read_document(&state_dir.join(STATUS)).unwrap_or_default()
}

/// Picks the certificate for the name the client asked for; an unknown or
/// missing name gets none, so the handshake fails before anything is reached.
#[derive(Debug)]
struct ByName(BTreeMap<String, Arc<rustls::sign::CertifiedKey>>);
impl rustls::server::ResolvesServerCert for ByName {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let name = hello
            .server_name()?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        self.0.get(&name).cloned()
    }
}

/// What a running port was started from; a change means restart it, which
/// also drops its open connections.
type Signature = Vec<(Gateway, Option<SystemTime>, Option<PathBuf>, bool)>;

fn signature(gateways: &[Gateway], store: &Store) -> Signature {
    let peers = store.peers().unwrap_or_default();
    gateways
        .iter()
        .map(|gateway| {
            // Revoking the target or withdrawing its public grant ends the gateway.
            let allowed = peers.iter().any(|peer| {
                peer.id == gateway.peer
                    && peer.remote_services.contains(&gateway.service)
                    && peer.remote_public.contains(&gateway.service)
            });
            let cert = crate::hosting::certificate_for(&gateway.host).map(|(cert, _)| cert);
            let modified = cert.as_ref().and_then(|cert| {
                std::fs::metadata(cert)
                    .and_then(|meta| meta.modified())
                    .ok()
            });
            (
                gateway.clone(),
                modified,
                cert.and_then(|cert| std::fs::canonicalize(cert).ok()),
                allowed,
            )
        })
        .collect()
}

/// One listener per port; the requested name selects both the certificate and
/// the target. Returns the task and, per gateway URL, whether it can serve.
async fn start_port(
    port: u16,
    gateways: &[Gateway],
    store: &Store,
    endpoint: &Endpoint,
    options: &NetOptions,
) -> (Option<JoinHandle<()>>, BTreeMap<String, GatewayStatus>) {
    let mut keys = BTreeMap::new();
    let mut targets: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut statuses = BTreeMap::new();
    let peers = store.peers().unwrap_or_default();
    for gateway in gateways {
        // Only while the target device lets this one expose the service publicly.
        let allowed = peers.iter().any(|peer| {
            peer.id == gateway.peer
                && peer.remote_services.contains(&gateway.service)
                && peer.remote_public.contains(&gateway.service)
        });
        if !allowed || !PUBLIC_SERVICES.contains(&gateway.service.as_str()) {
            statuses.insert(
                gateway.url(),
                GatewayStatus {
                    running: false,
                    error: Some("grant".to_owned()),
                },
            );
            continue;
        }
        let key = crate::hosting::certificate_for(&gateway.host).and_then(|(cert, key)| {
            let (cert, key) = (
                std::fs::canonicalize(cert).ok()?,
                std::fs::canonicalize(key).ok()?,
            );
            crate::relay::certified_key(&cert, &key).ok()
        });
        match key {
            Some(key) => {
                keys.insert(gateway.host.clone(), key);
                targets.insert(
                    gateway.host.clone(),
                    (gateway.peer.clone(), gateway.service.clone()),
                );
            }
            None => {
                statuses.insert(
                    gateway.url(),
                    GatewayStatus {
                        running: false,
                        error: Some("certificate".to_owned()),
                    },
                );
            }
        }
    }
    let failed = |statuses: &mut BTreeMap<String, GatewayStatus>, reason: &str| {
        for gateway in gateways {
            statuses.entry(gateway.url()).or_insert(GatewayStatus {
                running: false,
                error: Some(reason.to_owned()),
            });
        }
    };
    if keys.is_empty() {
        return (None, statuses);
    }
    let Ok(config) = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions() else {
        failed(&mut statuses, "failed");
        return (None, statuses);
    };
    let config = config
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(ByName(keys)));
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let Ok(listener) = TcpListener::bind(("0.0.0.0", port)).await else {
        failed(&mut statuses, "port");
        return (None, statuses);
    };
    failed(&mut statuses, "unused");
    for gateway in gateways {
        if targets.contains_key(&gateway.host) {
            statuses.insert(
                gateway.url(),
                GatewayStatus {
                    running: true,
                    error: None,
                },
            );
        }
    }
    let (store, endpoint, options) = (store.clone(), endpoint.clone(), options.clone());
    let streams: Arc<BTreeMap<String, Arc<Semaphore>>> = Arc::new(
        targets
            .keys()
            .map(|host| (host.clone(), Arc::new(Semaphore::new(PER_TARGET))))
            .collect(),
    );
    let targets = Arc::new(targets);
    let per_address: Arc<std::sync::Mutex<BTreeMap<std::net::IpAddr, usize>>> = Arc::default();
    let task = tokio::spawn(async move {
        let capacity = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let mut workers = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((socket, client)) = accepted else { continue };
                    let Ok(permit) = capacity.clone().try_acquire_owned() else { continue };
                    let client = client.ip();
                    {
                        let mut counts = per_address.lock().expect("per-address counts");
                        let count = counts.entry(client).or_insert(0);
                        if *count >= PER_ADDRESS {
                            continue;
                        }
                        *count += 1;
                    }
                    let (acceptor, targets, store, endpoint, options, per_address, streams) =
                        (acceptor.clone(), targets.clone(), store.clone(), endpoint.clone(), options.clone(), per_address.clone(), streams.clone());
                    workers.spawn(async move {
                        let _permit = permit;
                        let _slot = AddressSlot(per_address, client);
                        let _ = socket.set_nodelay(true);
                        // Plain HTTP, a stalled handshake, an unknown name or a scan ends here.
                        let Ok(Ok(mut tls)) = timeout(HANDSHAKE, acceptor.accept(socket)).await else { return };
                        let Some(name) = tls.get_ref().1.server_name().map(|name| name.to_ascii_lowercase()) else { return };
                        let Some((peer, service)) = targets.get(name.trim_end_matches('.')) else { return };
                        let Some(Ok(_stream)) = streams.get(name.trim_end_matches('.')).map(|limit| limit.clone().try_acquire_owned()) else { return };
                        // The target device's address comes from this device's own state.
                        let Some(addr) = store.peers().ok().and_then(|peers| {
                            peers.into_iter().find(|item| &item.id == peer).and_then(|item| item.address)
                        }) else { return };
                        // Nothing reaches the target until the client says something.
                        let mut first = vec![0u8; 16 * 1024];
                        let Ok(Ok(read)) = timeout(FIRST_DATA, tokio::io::AsyncReadExt::read(&mut tls, &mut first)).await else { return };
                        if read == 0 {
                            return;
                        }
                        let Ok(Ok(mut pipe)) = timeout(OPEN, open_with(&endpoint, &options, &addr, service, true)).await else { return };
                        if pipe.write_prefix(&first[..read]).await.is_err() {
                            return;
                        }
                        let activity = Arc::new(std::sync::atomic::AtomicU64::new(0));
                        let started = tokio::time::Instant::now();
                        let watched = Watched { inner: tls, activity: activity.clone(), started };
                        let transfer = pipe.transfer(watched);
                        tokio::pin!(transfer);
                        let mut check = tokio::time::interval(Duration::from_secs(10));
                        loop {
                            tokio::select! {
                                _ = &mut transfer => break,
                                _ = check.tick() => {
                                    let last = Duration::from_millis(activity.load(std::sync::atomic::Ordering::Relaxed));
                                    if started.elapsed().saturating_sub(last) > IDLE {
                                        break;
                                    }
                                }
                            }
                        }
                    });
                }
                _ = workers.join_next(), if !workers.is_empty() => {}
            }
        }
    });
    (Some(task), statuses)
}

/// A port's listener (none when nothing on it can serve), what it was started
/// from, and the status of each of its gateways.
type Running = (
    Option<JoinHandle<()>>,
    Signature,
    BTreeMap<String, GatewayStatus>,
);

/// A client stream that records when bytes last moved either way.
struct Watched<S> {
    inner: S,
    activity: Arc<std::sync::atomic::AtomicU64>,
    started: tokio::time::Instant,
}

impl<S> Watched<S> {
    fn touch(&self) {
        let elapsed = self.started.elapsed().as_millis() as u64;
        self.activity
            .store(elapsed, std::sync::atomic::Ordering::Relaxed);
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Watched<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.touch();
        }
        poll
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Watched<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let poll = std::pin::Pin::new(&mut self.inner).poll_write(cx, data);
        if matches!(poll, std::task::Poll::Ready(Ok(written)) if written > 0) {
            self.touch();
        }
        poll
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Frees a client address's slot when its connection ends.
struct AddressSlot(
    Arc<std::sync::Mutex<BTreeMap<std::net::IpAddr, usize>>>,
    std::net::IpAddr,
);
impl Drop for AddressSlot {
    fn drop(&mut self) {
        let mut counts = self.0.lock().expect("per-address counts");
        if let Some(count) = counts.get_mut(&self.1) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.1);
            }
        }
    }
}

/// Runs inside a device's server: starts, stops and reloads gateways within
/// seconds of a configuration change or a renewed certificate.
pub async fn gateway_loop(store: Store, endpoint: Endpoint, options: NetOptions) {
    let root = store.root().to_path_buf();
    let mut running: BTreeMap<u16, Running> = BTreeMap::new();
    let mut reported: Option<BTreeMap<String, GatewayStatus>> = None;
    loop {
        let mut wanted: BTreeMap<u16, Vec<Gateway>> = BTreeMap::new();
        for gateway in load(&root).into_iter().take(MAX_GATEWAYS) {
            wanted.entry(gateway.port).or_default().push(gateway);
        }
        let obsolete: Vec<u16> = running
            .iter()
            .filter_map(|(port, (task, sig, _))| {
                let keep = task.as_ref().is_some_and(|task| !task.is_finished())
                    && wanted
                        .get(port)
                        .is_some_and(|gateways| signature(gateways, &store) == *sig);
                (!keep).then_some(*port)
            })
            .collect();
        for port in obsolete {
            if let Some((Some(task), _, _)) = running.remove(&port) {
                task.abort();
                // Wait for the old listener to release its port before rebinding.
                // Otherwise a reload races its own socket and costs another CHECK.
                let _ = task.await;
            }
        }
        for (port, gateways) in &wanted {
            if !running.contains_key(port) {
                let sig = signature(gateways, &store);
                let (task, statuses) =
                    start_port(*port, gateways, &store, &endpoint, &options).await;
                running.insert(*port, (task, sig, statuses));
            }
        }
        let statuses: BTreeMap<String, GatewayStatus> = running
            .values()
            .flat_map(|(_, _, statuses)| statuses.clone())
            .collect();
        if reported.as_ref() != Some(&statuses) {
            let _ = write_document(&root.join(STATUS), &statuses, true);
            reported = Some(statuses);
        }
        tokio::time::sleep(CHECK).await;
    }
}
