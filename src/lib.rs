pub mod catalog;
pub mod catalog_client;
pub mod catalog_publisher;
mod compression;
pub mod delegated_enrollment;
pub mod desktop;
pub mod egress;
pub mod enrollment;
pub mod gateway;
pub mod gateway_domain;
pub mod hosting;
pub mod manage;
pub mod mcp;
pub(crate) mod network;
pub mod relay;
pub mod routes;
pub mod theme;
pub mod units;
pub use network::{
    Client, Invitation, NetOptions, Node, Pipe, Relay, SYNC_INTERVAL, connect_through_server,
    find_peer, forward_target, forward_through_server, unix_time,
};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use fs2::FileExt;
use iroh::{EndpointAddr, EndpointId, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub fn state_dir_from(xdg_data_home: Option<&Path>, home: Option<&Path>) -> PathBuf {
    if let Some(path) = xdg_data_home.filter(|path| path.is_absolute()) {
        return path.join("omabridge");
    }
    home.filter(|path| path.is_absolute())
        .unwrap_or_else(|| Path::new("."))
        .join(".local/share/omabridge")
}

pub fn default_state_dir() -> PathBuf {
    let xdg = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from);
    let home = std::env::var_os("HOME").map(PathBuf::from);
    state_dir_from(xdg.as_deref(), home.as_deref())
}

const MAX_STATE: u64 = 1024 * 1024;

/// Exclusive device-server lifetime; cannot be cloned or reused by another store.
pub struct RuntimeReservation {
    root: PathBuf,
    _lock: File,
}
impl RuntimeReservation {
    pub(crate) fn belongs_to(&self, store: &Store) -> bool {
        self.root == store.root
    }
}

#[derive(Clone, Debug)]
pub struct Store {
    root: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    name: String,
    secret: [u8; 32],
    #[serde(default)]
    invites: BTreeMap<String, Invite>,
    #[serde(default)]
    peers: BTreeMap<String, Peer>,
}

#[derive(Serialize, Deserialize)]
struct Invite {
    expires: u64,
    services: BTreeSet<String>,
    pending: Option<(String, String)>,
    approved: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Peer {
    pub id: String,
    pub name: String,
    pub services: BTreeSet<String>,
    #[serde(default)]
    pub remote_services: BTreeSet<String>,
    pub address: Option<EndpointAddr>,
    /// Services the peer may also expose publicly through its gateways; a
    /// subset of `services`, decided only by this device.
    #[serde(default)]
    pub public: BTreeSet<String>,
    /// Services of the peer this device may expose publicly, as it announced.
    #[serde(default)]
    pub remote_public: BTreeSet<String>,
    /// This device let the peer manage it; only this device changes it.
    #[serde(default)]
    pub admin: bool,
    /// The peer announced that this device may manage it.
    #[serde(default)]
    pub managed: bool,
    #[serde(default)]
    pub gateway_routes: Vec<routes::ServiceRoute>,
    #[serde(default)]
    pub routes_updated: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct PendingInvitation {
    #[serde(flatten)]
    pub peer: Peer,
    pub invitation_id: String,
    pub expires: u64,
}

/// Public, consistent device state for management frontends; never includes signing keys or bearer tokens.
#[derive(Debug, Serialize)]
pub struct DeviceSnapshot {
    pub id: String,
    pub name: String,
    pub peers: Vec<Peer>,
    pub pending: Vec<PendingInvitation>,
}

fn pending_invitations(invites: BTreeMap<String, Invite>) -> Vec<PendingInvitation> {
    invites
        .into_iter()
        .filter(|(_, invite)| !invite.approved)
        .filter_map(|(invitation_id, invite)| {
            invite.pending.map(|(id, name)| PendingInvitation {
                peer: Peer {
                    id,
                    name,
                    services: invite.services,
                    remote_services: BTreeSet::new(),
                    address: None,
                    public: BTreeSet::new(),
                    remote_public: BTreeSet::new(),
                    admin: false,
                    managed: false,
                    gateway_routes: Vec::new(),
                    routes_updated: 0,
                },
                invitation_id,
                expires: invite.expires,
            })
        })
        .collect()
}

/// Names shown to other devices: 1–80 characters, no control characters.
pub fn valid_device_name(name: &str) -> bool {
    !name.trim().is_empty()
        && name.len() <= 80
        && !name.chars().any(|c| c.is_control() || invisible(c))
}

/// Characters that hide or reorder text (bidirectional controls, zero-width
/// and other format characters): a name using them could pass for another.
fn invisible(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}' | '\u{1160}' | '\u{17B4}' | '\u{17B5}'
        | '\u{180B}'..='\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206F}' | '\u{3164}' | '\u{FE00}'..='\u{FE0F}'
        | '\u{FEFF}' | '\u{FFA0}' | '\u{FFF9}'..='\u{FFFB}' | '\u{1D173}'..='\u{1D17A}'
        | '\u{E0000}'..='\u{E007F}' | '\u{E0100}'..='\u{E01EF}')
}

/// Keeps only routes a peer may sensibly announce: direct addresses that are
/// not link-local, multicast or unspecified (loopback stays, for several
/// identities on one machine), and HTTPS relays whose host is not a local or
/// private literal. (A public name that resolves to a private address is not
/// caught here; the relay connection is TLS-authenticated either way.)
pub(crate) fn sanitize_address(address: &EndpointAddr) -> EndpointAddr {
    let mut clean = address.clone();
    clean.addrs.retain(|addr| match addr {
        iroh::TransportAddr::Ip(socket) => {
            let ip = match socket.ip() {
                std::net::IpAddr::V6(v6) => v6
                    .to_ipv4_mapped()
                    .map(std::net::IpAddr::V4)
                    .unwrap_or(std::net::IpAddr::V6(v6)),
                ip => ip,
            };
            let local = match ip {
                std::net::IpAddr::V4(v4) => {
                    v4.is_link_local()
                        || v4.is_unspecified()
                        || v4.is_multicast()
                        || v4.is_broadcast()
                }
                std::net::IpAddr::V6(v6) => {
                    v6.is_unspecified()
                        || v6.is_multicast()
                        || (v6.segments()[0] & 0xffc0) == 0xfe80
                }
            };
            !local && socket.port() != 0
        }
        iroh::TransportAddr::Relay(url) => {
            url.scheme() == "https" && crate::hosting::public_host(url)
        }
        _ => false,
    });
    clean
}

pub fn valid_service(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

pub fn write_document<T: Serialize>(path: &Path, value: &T, replace: bool) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temporary = parent.join(format!(".omabridge-{:016x}", rand::random::<u64>()));
    let data = serde_json::to_vec_pretty(value)?;
    ensure!(data.len() <= 65536, "document too large");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| -> Result<()> {
        file.write_all(&data)?;
        file.sync_all()?;
        if replace {
            fs::rename(&temporary, path)?;
        } else {
            fs::hard_link(&temporary, path)?;
            fs::remove_file(&temporary)?;
        }
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

pub fn read_document<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.len() <= 65536 && meta.permissions().mode() & 0o077 == 0,
        "document must be a private bounded regular file (0600)"
    );
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 65536, "document too large");
    Ok(serde_json::from_slice(&bytes)?)
}

fn token_hash(token: &str) -> Result<String> {
    ensure!(token.len() <= 64, "invalid invitation");
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .context("invalid invitation")?;
    ensure!(bytes.len() == 32, "invalid invitation");
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PairDecision {
    Pending,
    Approved { services: Vec<String> },
}

impl Store {
    pub fn snapshot(&self) -> Result<DeviceSnapshot> {
        let _lock = self.lock()?;
        let State {
            name,
            secret,
            invites,
            peers,
            ..
        } = self.read()?;
        Ok(DeviceSnapshot {
            id: SecretKey::from_bytes(&secret).public().to_string(),
            name,
            peers: peers.into_values().collect(),
            pending: pending_invitations(invites),
        })
    }
    pub fn name(&self) -> Result<String> {
        let _lock = self.lock()?;
        Ok(self.read()?.name)
    }
    pub fn peers(&self) -> Result<Vec<Peer>> {
        let _lock = self.lock()?;
        Ok(self.read()?.peers.into_values().collect())
    }
    pub fn pending(&self) -> Result<Vec<PendingInvitation>> {
        let _lock = self.lock()?;
        Ok(pending_invitations(self.read()?.invites))
    }
    pub fn publish_endpoint(&self, address: &EndpointAddr, services: &[String]) -> Result<()> {
        ensure!(
            address.id.to_string() == self.id()?,
            "endpoint identity mismatch"
        );
        write_document(
            &self.root.join("endpoint.json"),
            &serde_json::json!({"address":address,"services":services}),
            true,
        )
    }
    pub fn active_endpoint(&self) -> Result<(EndpointAddr, Vec<String>)> {
        // Serialize with reserve_runtime so stale endpoint metadata can never
        // be read in the gap between acquiring the runtime lock and unlinking it.
        let _state_lock = self.lock()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.root.join("runtime.lock"))
            .context("server not running")?;
        match FileExt::try_lock_exclusive(&file) {
            Ok(()) => anyhow::bail!("server not running"),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
        #[derive(Deserialize)]
        struct Info {
            address: EndpointAddr,
            services: Vec<String>,
        }
        let info: Info = read_document(&self.root.join("endpoint.json"))?;
        ensure!(
            info.address.id.to_string()
                == SecretKey::from_bytes(&self.read()?.secret)
                    .public()
                    .to_string(),
            "endpoint identity mismatch"
        );
        Ok((info.address, info.services))
    }

    pub fn reserve_runtime(&self) -> Result<RuntimeReservation> {
        // Inviter operations hold the same state lock: no process can observe
        // a new runtime lock with the endpoint address from a previous run.
        let _state_lock = self.lock()?;
        let runtime_lock = self.runtime_lock()?;
        match fs::remove_file(self.root.join("endpoint.json")) {
            Ok(()) => File::open(&self.root)?.sync_all()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(RuntimeReservation {
            root: self.root.clone(),
            _lock: runtime_lock,
        })
    }

    fn runtime_lock(&self) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.root.join("runtime.lock"))?;
        FileExt::try_lock_exclusive(&file)
            .context("another server is using this device identity")?;
        Ok(file)
    }

    fn remember_peer(&self, address: &EndpointAddr, name: &str, services: &[String]) -> Result<()> {
        ensure!(valid_device_name(name), "invalid device name");
        let address = &sanitize_address(address);
        ensure!(
            services.len() <= 32 && services.iter().all(|s| valid_service(s)),
            "invalid remote services"
        );
        self.update(|state| {
            let id = address.id.to_string();
            ensure!(
                state.peers.len() < 256 || state.peers.contains_key(&id),
                "peer capacity reached"
            );
            let peer = state.peers.entry(id.clone()).or_insert_with(|| Peer {
                id,
                name: name.to_owned(),
                services: BTreeSet::new(),
                remote_services: BTreeSet::new(),
                address: None,
                public: BTreeSet::new(),
                remote_public: BTreeSet::new(),
                admin: false,
                managed: false,
                gateway_routes: Vec::new(),
                routes_updated: 0,
            });
            peer.name = name.to_owned();
            peer.remote_services = services.iter().cloned().collect();
            peer.address = Some(address.clone());
            Ok(())
        })
    }

    pub fn set_name(&self, name: &str) -> Result<()> {
        ensure!(valid_device_name(name), "invalid device name");
        self.update(|state| {
            state.name = name.to_owned();
            Ok(())
        })
    }

    /// Sets which published services a paired device may reach here. Only this
    /// device's own front ends call this; a managing device never can.
    pub fn set_services(&self, peer: &str, services: &[String], public: &[String]) -> Result<()> {
        ensure!(
            services.len() <= 32 && services.iter().all(|s| valid_service(s)),
            "invalid services"
        );
        ensure!(
            public
                .iter()
                .all(|s| services.contains(s)
                    && crate::gateway::PUBLIC_SERVICES.contains(&s.as_str())),
            "public services must also be granted, and be services safe to expose"
        );
        self.update(|state| {
            let entry = state.peers.get_mut(peer).context("peer not found")?;
            entry.services = services.iter().cloned().collect();
            entry.public = public.iter().cloned().collect();
            entry.gateway_routes.retain(|route| {
                entry.services.contains(&route.service) && entry.public.contains(&route.service)
            });
            Ok(())
        })
    }

    /// The peer may reach `service` here on behalf of anyone (a public gateway).
    pub fn public_allowed(&self, peer: &str, service: &str) -> Result<bool> {
        let _lock = self.lock()?;
        Ok(self
            .read()?
            .peers
            .get(peer)
            .is_some_and(|p| p.services.contains(service) && p.public.contains(service)))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Lets a paired device manage this one, or stops it. Only this device's own
    /// front ends call this; a managing device never can.
    pub fn set_admin(&self, peer: &str, allowed: bool) -> Result<()> {
        self.update(|state| {
            state.peers.get_mut(peer).context("peer not found")?.admin = allowed;
            Ok(())
        })
    }

    /// Applies a paired device's announcement of its name, whether it lets this
    /// device manage it and, when it is reachable, its current address. Unknown
    /// devices change nothing.
    pub(crate) fn refresh_peer(
        &self,
        id: &str,
        name: &str,
        address: Option<&EndpointAddr>,
        managed: bool,
        grants: Option<(&[String], &[String])>,
    ) -> Result<()> {
        ensure!(valid_device_name(name), "invalid device name");
        if let Some(address) = address {
            ensure!(
                address.id.to_string() == id && address.addrs.len() <= 16,
                "address does not belong to this peer"
            );
        }
        if let Some((services, public)) = grants {
            ensure!(
                services.len() <= 32
                    && public.len() <= 32
                    && services.iter().chain(public).all(|s| valid_service(s)),
                "invalid announced services"
            );
        }
        let address = address.map(sanitize_address);
        self.update(|state| {
            let peer = state.peers.get_mut(id).context("unknown peer")?;
            peer.name = name.to_owned();
            peer.managed = managed;
            if let Some(address) = address {
                peer.address = Some(address);
            }
            // Older devices do not announce grants; then what is known stays.
            if let Some((services, public)) = grants {
                peer.remote_services = services.iter().cloned().collect();
                peer.remote_public = public
                    .iter()
                    .filter(|s| services.contains(s))
                    .cloned()
                    .collect();
            }
            Ok(())
        })
    }

    pub fn revoke(&self, peer: &str) -> Result<()> {
        self.update(|state| {
            ensure!(state.peers.remove(peer).is_some(), "peer not found");
            state
                .invites
                .retain(|_, i| i.pending.as_ref().is_none_or(|(id, _)| id != peer));
            Ok(())
        })
    }
    pub fn create_invite(&self, services: &[String], ttl: Duration, now: u64) -> Result<String> {
        ensure!(
            !services.is_empty() && services.iter().all(|s| valid_service(s)),
            "invalid service grant"
        );
        ensure!(
            (1..=3600).contains(&ttl.as_secs()),
            "invitation lifetime must be 1..3600 seconds"
        );
        let token = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
        let hash = token_hash(&token)?;
        self.update(|state| {
            state.invites.retain(|_, i| i.expires > now);
            ensure!(state.invites.len() < 1024, "invitation capacity reached");
            state.invites.insert(
                hash,
                Invite {
                    expires: now.checked_add(ttl.as_secs()).context("expiry overflow")?,
                    services: services.iter().cloned().collect(),
                    pending: None,
                    approved: false,
                },
            );
            Ok(())
        })?;
        Ok(token)
    }

    pub fn claim(&self, token: &str, peer: &str, name: &str, now: u64) -> Result<PairDecision> {
        ensure!(valid_device_name(name), "invalid device name");
        let _: EndpointId = peer.parse().context("invalid peer identity")?;
        let hash = token_hash(token)?;
        self.update(|state| {
            let invite = state
                .invites
                .get_mut(&hash)
                .context("invitation unavailable")?;
            if let Some((bound, _)) = &invite.pending {
                ensure!(bound == peer, "invitation already claimed");
            }
            ensure!(invite.expires > now, "invitation expired");
            if invite.approved {
                let grant = state.peers.get(peer).context("membership unavailable")?;
                return Ok(PairDecision::Approved {
                    services: grant.services.iter().cloned().collect(),
                });
            }
            if invite.pending.is_none() {
                invite.pending = Some((peer.to_owned(), name.to_owned()));
            }
            Ok(PairDecision::Pending)
        })
    }

    pub fn approve(&self, peer: &str, now: u64) -> Result<()> {
        self.approve_selected(peer, None, now)
    }

    pub fn approve_selected(
        &self,
        peer: &str,
        invitation_id: Option<&str>,
        now: u64,
    ) -> Result<()> {
        self.update(|state| {
            ensure!(
                state.peers.len() < 256 || state.peers.contains_key(peer),
                "peer capacity reached"
            );
            let live: Vec<_> = state
                .invites
                .iter()
                .filter(|(_, invite)| {
                    !invite.approved
                        && invite.expires > now
                        && invite.pending.as_ref().is_some_and(|(id, _)| id == peer)
                })
                .map(|(id, _)| id.clone())
                .collect();
            let chosen = if let Some(id) = invitation_id {
                ensure!(
                    live.iter().any(|candidate| candidate == id),
                    "selected invitation is not pending for this peer"
                );
                id.to_owned()
            } else {
                ensure!(
                    live.len() == 1,
                    "expected one live pending invitation; select its invitation_id explicitly"
                );
                live[0].clone()
            };
            let invite = state
                .invites
                .get_mut(&chosen)
                .context("selected invitation unavailable")?;
            let (_, name) = invite.pending.as_ref().context("request unavailable")?;
            if let Some(existing) = state.peers.get_mut(peer) {
                // Reciprocal enrollment changes inbound rights, never the learned outbound route.
                existing.services = invite.services.clone();
            } else {
                state.peers.insert(
                    peer.to_owned(),
                    Peer {
                        id: peer.to_owned(),
                        name: name.clone(),
                        services: invite.services.clone(),
                        remote_services: BTreeSet::new(),
                        address: None,
                        public: BTreeSet::new(),
                        remote_public: BTreeSet::new(),
                        admin: false,
                        managed: false,
                        gateway_routes: Vec::new(),
                        routes_updated: 0,
                    },
                );
            }
            invite.approved = true;
            // A second claimed invite must not later silently replace the selected grant.
            state.invites.retain(|key, invite| {
                key == &chosen || invite.pending.as_ref().is_none_or(|(id, _)| id != peer)
            });
            Ok(())
        })
    }

    pub fn authorized(&self, peer: &str, service: &str) -> Result<bool> {
        let _lock = self.lock()?;
        Ok(self
            .read()?
            .peers
            .get(peer)
            .is_some_and(|p| p.services.contains(service)))
    }

    fn update<T>(&self, operation: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        let _lock = self.lock()?;
        let mut state = self.read()?;
        let value = operation(&mut state)?;
        self.write(&state)?;
        Ok(value)
    }

    pub fn open(path: &Path, name: &str) -> Result<Self> {
        ensure!(
            !name.is_empty() && name.len() <= 80 && !name.chars().any(char::is_control),
            "invalid device name"
        );
        if !path.exists() {
            fs::create_dir_all(path)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        let meta = fs::symlink_metadata(path)?;
        ensure!(
            meta.is_dir() && meta.permissions().mode() & 0o077 == 0,
            "state directory must be a private non-symlink directory (0700)"
        );
        let store = Self {
            root: path.to_path_buf(),
        };
        let lock = store.lock()?;
        if store.root.join("state.json").symlink_metadata().is_err() {
            store.write(&State {
                version: 1,
                name: name.to_owned(),
                secret: SecretKey::generate().to_bytes(),
                invites: BTreeMap::new(),
                peers: BTreeMap::new(),
            })?;
        }
        store.read()?;
        drop(lock);
        Ok(store)
    }

    pub fn id(&self) -> Result<String> {
        Ok(self.secret_key()?.public().to_string())
    }

    pub fn secret_key(&self) -> Result<SecretKey> {
        let _lock = self.lock()?;
        Ok(SecretKey::from_bytes(&self.read()?.secret))
    }

    fn lock(&self) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.root.join("state.lock"))?;
        FileExt::lock_exclusive(&file)?;
        Ok(file)
    }

    fn read(&self) -> Result<State> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.root.join("state.json"))?;
        let meta = file.metadata()?;
        ensure!(
            meta.is_file() && meta.permissions().mode() & 0o077 == 0 && meta.len() <= MAX_STATE,
            "invalid state file permissions or size"
        );
        let mut data = Vec::new();
        file.take(MAX_STATE + 1).read_to_end(&mut data)?;
        ensure!(data.len() as u64 <= MAX_STATE, "state too large");
        let state: State =
            serde_json::from_slice(&data).context("invalid state; refusing to replace identity")?;
        ensure!(state.version == 1, "unsupported state version");
        Ok(state)
    }

    fn write(&self, state: &State) -> Result<()> {
        let path = self
            .root
            .join(format!(".state-{:016x}", rand::random::<u64>()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        let result = (|| -> Result<()> {
            let bytes = serde_json::to_vec_pretty(state)?;
            ensure!(bytes.len() as u64 <= MAX_STATE, "state too large");
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&path, self.root.join("state.json"))?;
            File::open(&self.root)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(path);
        }
        result
    }
}

#[cfg(test)]
mod announced {
    use super::sanitize_address;
    use iroh::{EndpointAddr, SecretKey, TransportAddr};

    #[test]
    fn only_sensible_routes_are_kept() {
        let id = SecretKey::generate().public();
        let addrs = [
            "https://relay.example.net/",
            "http://relay.example.net/",
            "https://127.0.0.1:9/",
            "https://169.254.169.254/",
            "https://[::ffff:10.0.0.1]/",
            "https://localhost:443/",
        ]
        .into_iter()
        .map(|url| TransportAddr::Relay(url.parse().unwrap()))
        .chain(
            [
                "10.0.0.10:4000",
                "127.0.0.1:4000",
                "169.254.1.1:4000",
                "0.0.0.0:4000",
                "[fe80::1]:4000",
                "224.0.0.1:4000",
                "8.8.8.8:0",
            ]
            .into_iter()
            .map(|addr| TransportAddr::Ip(addr.parse().unwrap())),
        );
        let clean = sanitize_address(&EndpointAddr {
            id,
            addrs: addrs.collect(),
        });
        let kept: Vec<String> = clean
            .addrs
            .iter()
            .map(|addr| match addr {
                TransportAddr::Relay(url) => url.to_string(),
                TransportAddr::Ip(ip) => ip.to_string(),
                _ => String::new(),
            })
            .collect();
        assert_eq!(kept.len(), 3, "{kept:?}");
        assert!(kept.contains(&"https://relay.example.net/".to_owned()));
        assert!(
            kept.contains(&"10.0.0.10:4000".to_owned()),
            "LAN peers stay reachable"
        );
        assert!(kept.contains(&"127.0.0.1:4000".to_owned()));
    }
}
