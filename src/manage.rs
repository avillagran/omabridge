//! One-request JSON management API shared by every OmaBridge front end
//! (`omabridge manage`): T3 Code, the Omarchy Control Panel, bar widgets. Each
//! call reads one request, applies it to this device's store and to the single
//! background unit that publishes it, and returns the public snapshot.
//!
//! Private keys, invitation tokens and invitation contents never leave this
//! module. A created invitation's path and QR image are returned once and are
//! secrets for the caller: show them, then drop them.
use crate::{
    Client, Invitation, NetOptions, Relay, Store,
    desktop::{Desktop, PairStatus},
    read_document,
    units::{self, Runner as _, UnitContext, UnitSpec, Units},
    unix_time, valid_service, write_document,
};
use base64::{Engine, engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::{Ipv4Addr, SocketAddr, TcpStream},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

/// The one unit that publishes this device, shared with `omabridge-gui`.
pub const SERVE_UNIT: &str = "omabridge-serve.service";
/// Largest accepted request on stdin.
pub const REQUEST_LIMIT: usize = 64 * 1024;
/// What this build supports, for front ends that must work with older ones.
pub const FEATURES: &[&str] = &[
    "control-socket",
    "forward-through-server",
    "connect-stdio",
    "remote-manage",
    "relay-host",
    "gateways",
    "delegated-enrollment-v1",
    "t3-pair-v1",
    "mcp-service",
    "service-routes",
    "gateway-domain",
    "all-hosts-invite-v1",
    "mobile-admin-v1",
    "shared-drafts-v1",
];

const ACTIONS: [&str; 19] = [
    "identity-create",
    "invite",
    "invite-discard",
    "pair",
    "pair-retry",
    "pair-discard",
    "approve",
    "revoke",
    "publish",
    "unpublish",
    "relay-set",
    "rename",
    "admin-set",
    "remote",
    "relay-host",
    "gateway-set",
    "grant-set",
    "gateway-domain-set",
    "bridge-consent-set",
];

/// What a managing device may ask: never identities or pairing
/// from this device, who else may manage it or which bridge may broker it.
pub const REMOTE_ACTIONS: [&str; 11] = [
    "read",
    "invite",
    "endpoints",
    "rename",
    "relay-set",
    "publish",
    "unpublish",
    "revoke",
    "approve",
    "relay-host",
    "gateway-set",
];

/// Codes a managed device may answer with; anything else is reported generically.
const REMOTE_CODES: &[&str] = &[
    "invalid_command",
    "omabridge_service_not_published",
    "omabridge_invite_directory",
    "local_error",
    "omabridge_not_admin",
    "omabridge_remote_forbidden",
    "omabridge_peer_is_admin",
    "omabridge_name_invalid",
    "omabridge_relay_invalid",
    "omabridge_ssh_unavailable",
    "omabridge_mcp_unavailable",
    "omabridge_t3_unavailable",
    "omabridge_nothing_to_publish",
    "omabridge_already_running",
    "omabridge_unit_foreign",
    "omabridge_path_unsupported",
    "omabridge_publish_failed",
    "omabridge_peer_not_found",
    "omabridge_request_changed",
    "omabridge_identity_missing",
    "omabridge_command_failed",
    "omabridge_not_published",
    "omabridge_relay_host_unavailable",
    "omabridge_relay_certificate",
    "omabridge_service_not_granted",
    "omabridge_port_unavailable",
    "omabridge_gateway_host_invalid",
    "omabridge_gateway_busy",
    "omabridge_gateway_name_reserved",
    "omabridge_gateway_names_full",
    "omabridge_gateway_domain_invalid",
];

/// A stable, redacted error code for front ends; never a message.
pub type Code = &'static str;
type Outcome<T> = std::result::Result<T, Code>;

pub struct Manager {
    pub state_dir: PathBuf,
    pub options: NetOptions,
    pub units: Units,
    /// `omabridge` executable written into the publishing unit.
    pub binary: PathBuf,
    /// Invitation copies kept while the other device has not approved this one.
    pub awaiting_dir: PathBuf,
    /// Default folder for new invitation files.
    pub invite_dir: PathBuf,
    pub ssh_target: SocketAddr,
    /// Where `omabridge mcp serve` listens when it is published as `mcp`.
    pub mcp_target: SocketAddr,
    /// T3 Code's `server-runtime.json`, which names its loopback port.
    pub t3_runtime: PathBuf,
    /// How long `publish` waits for the published service to come up.
    pub publish_wait: Duration,
    pub pair_timeout: Duration,
    /// Commands come from a managing device, not this device's own user. Such a
    /// device approves nothing that reaches beyond this one.
    pub remote: bool,
}

fn home() -> Outcome<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or("local_error")
}

fn xdg(variable: &str, fallback: &str) -> Outcome<PathBuf> {
    match std::env::var_os(variable)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
    {
        Some(path) => Ok(path),
        None => Ok(home()?.join(fallback)),
    }
}

/// 64 lowercase hex digits, as printed by `init` and `peers`.
pub fn valid_peer(peer: &str) -> bool {
    peer.len() == 64 && peer.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn valid_awaiting_id(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

fn random_id() -> String {
    let hex = format!("{:032x}", rand::random::<u128>());
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or("")
}

fn local_path(raw: &str) -> PathBuf {
    PathBuf::from(raw.strip_prefix("file://").unwrap_or(raw))
}

fn listening(target: SocketAddr) -> bool {
    TcpStream::connect_timeout(&target, Duration::from_millis(300)).is_ok()
}

/// A name usable both as an identity name and as a unit argument.
fn device_name() -> String {
    let raw = fs::read_to_string("/etc/hostname").unwrap_or_default();
    let name = raw.trim();
    if !name.is_empty()
        && name.len() <= 63
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        name.to_owned()
    } else {
        "device".to_owned()
    }
}

/// Public fields of an invitation file: never its token or address.
fn invitation_summary(path: &Path) -> Outcome<(String, u64)> {
    invitation_details(path).map(|(name, expires, _)| (name, expires))
}

/// The inviting device's ID, read from an invitation copy.
fn invitation_peer(path: &Path) -> Outcome<String> {
    let invite: Invitation = read_document(path).map_err(|_| "omabridge_invite_invalid")?;
    Ok(invite.address.id.to_string())
}

/// Name, expiry and whether the inviting device asks to manage this one.
fn invitation_details(path: &Path) -> Outcome<(String, u64, bool)> {
    invitation_identity(path).map(|(name, expires, manage, _)| (name, expires, manage))
}

/// As `invitation_details`, plus the inviting device's ID.
fn invitation_identity(path: &Path) -> Outcome<(String, u64, bool, String)> {
    let meta = fs::symlink_metadata(path).map_err(|_| "omabridge_invite_unreadable")?;
    if !meta.is_file() {
        return Err("omabridge_invite_unreadable");
    }
    let invite: Invitation = read_document(path).map_err(|_| "omabridge_invite_invalid")?;
    // A name that hides or reorders text could pass for another device.
    if invite.version != 1 || !crate::valid_device_name(&invite.name) {
        return Err("omabridge_invite_invalid");
    }
    Ok((
        invite.name.clone(),
        invite.expires,
        invite.manage,
        invite.address.id.to_string(),
    ))
}

/// The invitation QR as an SVG data URI, dark on light with a quiet zone.
fn qr_svg(invite: &Invitation) -> Outcome<String> {
    let body = serde_json::to_vec(invite).map_err(|_| "local_error")?;
    let uri = format!("omabridge://pair/{}", URL_SAFE_NO_PAD.encode(body));
    let code = qrcode::QrCode::new(uri.as_bytes()).map_err(|_| "local_error")?;
    let width = code.width();
    let size = width + 8;
    let mut rects = String::new();
    for (index, color) in code.to_colors().iter().enumerate() {
        if *color == qrcode::Color::Dark {
            let (x, y) = (index % width + 4, index / width + 4);
            rects.push_str(&format!("<rect x='{x}' y='{y}' width='1' height='1'/>"));
        }
    }
    let svg = format!(
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {size} {size}' shape-rendering='crispEdges'><rect width='{size}' height='{size}' fill='#fff'/><g fill='#000'>{rects}</g></svg>"
    );
    Ok(format!(
        "data:image/svg+xml;base64,{}",
        STANDARD.encode(svg)
    ))
}

fn private_dir(path: &Path) -> Outcome<()> {
    fs::create_dir_all(path).map_err(|_| "local_error")?;
    let meta = fs::symlink_metadata(path).map_err(|_| "local_error")?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } {
        return Err("local_error");
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| "local_error")
}

/// `service=127.0.0.1:port` pairs from an OmaBridge-written serve unit.
fn unit_services(path: &Path) -> Option<Vec<(String, SocketAddr)>> {
    let unit = fs::read_to_string(path).ok()?;
    if unit.lines().next() != Some(units::MARKER) {
        return None;
    }
    let exec = unit.lines().find(|line| line.starts_with("ExecStart="))?;
    let words: Vec<&str> = exec.split_whitespace().collect();
    if !words.contains(&"serve") {
        return None;
    }
    Some(
        words
            .windows(2)
            .filter(|pair| pair[0] == "--service")
            .filter_map(|pair| {
                let (name, target) = pair[1].split_once('=')?;
                Some((name.to_owned(), target.parse().ok()?))
            })
            .collect(),
    )
}

impl Manager {
    /// The real user environment: systemd `--user`, XDG directories and this executable.
    /// `relay` overrides the device's saved relay for this request (`--relay`).
    pub fn from_env(state_dir: PathBuf, bind: SocketAddr, relay: Option<Relay>) -> Outcome<Self> {
        let relay = match relay {
            Some(relay) => relay,
            None => Relay::load(&state_dir).map_err(|_| "omabridge_relay_invalid")?,
        };
        let options = NetOptions {
            bind,
            relay,
            compress_t3: false,
        };
        let home = home()?;
        let t3_home = std::env::var_os("T3CODE_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .unwrap_or_else(|| home.join(".t3"));
        Ok(Self {
            state_dir,
            options,
            units: Units::user().map_err(|_| "local_error")?,
            binary: std::env::current_exe().map_err(|_| "local_error")?,
            awaiting_dir: xdg("XDG_STATE_HOME", ".local/state")?.join("omabridge-pairing"),
            invite_dir: [home.join("Downloads"), home.clone()]
                .into_iter()
                .find(|path| path.is_dir())
                .unwrap_or(home),
            ssh_target: SocketAddr::from((Ipv4Addr::LOCALHOST, 22)),
            mcp_target: SocketAddr::from((Ipv4Addr::LOCALHOST, 8787)),
            t3_runtime: t3_home.join("userdata/server-runtime.json"),
            publish_wait: Duration::from_secs(5),
            pair_timeout: Duration::from_secs(30),
            remote: false,
        })
    }

    /// Mutating actions require `"confirmed": true`; discovery is read-only.
    pub async fn execute(&self, request: &Value) -> Outcome<Value> {
        if !request.is_object() {
            return Err("invalid_command");
        }
        let action = text(request, "action");
        if action == "read" {
            let mut snapshot = self.snapshot();
            snapshot["relayHost"]["suggested"] = self.relay_suggestion().await;
            return Ok(snapshot);
        }
        if action == "drafts" {
            let command = &request["command"];
            if !["get", "list", "watch", "receipt"].contains(&text(command, "op"))
                && request["confirmed"] != true
            {
                return Err("confirmation_required");
            }
            let store = self.store()?;
            let peer = text(request, "peer");
            if peer.is_empty() {
                return Ok(crate::drafts::execute(&store, None, command));
            }
            let target = crate::find_peer(&store, peer)?;
            let address = target.address.ok_or("omabridge_peer_unreachable")?;
            if let Some(reply) = self
                .through_service(&store, json!({"peer":target.id,"drafts":command}))
                .await
            {
                let reply = reply?;
                return Ok(reply.get("outcome").cloned().unwrap_or(reply));
            }
            let client = Client::new(store, self.options.clone())
                .await
                .map_err(|_| "local_error")?;
            let outcome = client.drafts(&address, command).await;
            client.close().await;
            return outcome.map_err(|_| "omabridge_peer_unreachable");
        }
        // Reading an invitation the user chose shows what accepting it means.
        if action == "invite-inspect" {
            let (name, expires, manage, inviter) =
                invitation_identity(&local_path(text(request, "path")))?;
            let mut snapshot = self.snapshot();
            snapshot["invitation"] =
                json!({ "name": name, "expires": expires, "manage": manage, "id": inviter });
            return Ok(snapshot);
        }
        // A bounded local route snapshot; never starts an endpoint or creates identity.
        if action == "endpoints" {
            let endpoints = match self.existing_store() {
                Some(store) => store
                    .service_routes(unix_time().map_err(|_| "local_error")?)
                    .map_err(|_| "omabridge_command_failed")?,
                None => Vec::new(),
            };
            return Ok(json!({ "endpoints": endpoints }));
        }
        // Checking a public address only reads.
        if action == "gateway-check" {
            let mut snapshot = self.snapshot();
            snapshot["gatewayCheck"] = self.gateway_check(text(request, "url")).await;
            return Ok(snapshot);
        }
        // Reading a managed device changes nothing there.
        if action == "remote" && text(&request["command"], "action") == "read" {
            let mut snapshot = self.snapshot();
            snapshot["remote"] = self.remote(request).await?;
            return Ok(snapshot);
        }
        // Refreshing names and addresses of paired devices changes no trust.
        if action == "sync" {
            let synced = self.announce().await?;
            let mut snapshot = self.snapshot();
            snapshot["synced"] = synced;
            return Ok(snapshot);
        }
        if !ACTIONS.contains(&action) {
            return Err("invalid_action");
        }
        if request["confirmed"] != true {
            return Err("confirmation_required");
        }
        let extra = match action {
            "identity-create" => {
                self.ensure_identity()?;
                json!({})
            }
            "invite" => json!({ "created": self.invite(request)? }),
            "invite-discard" => {
                self.invite_discard(text(request, "path"))?;
                json!({})
            }
            "pair" => json!({ "paired": self.pair(request).await? }),
            "pair-retry" => json!({ "paired": self.pair_copy(text(request, "id")).await? }),
            "pair-discard" => {
                let id = text(request, "id");
                if !valid_awaiting_id(id) {
                    return Err("invalid_command");
                }
                let _ = fs::remove_file(self.awaiting_dir.join(format!("{id}.json")));
                let _ = fs::remove_file(self.awaiting_dir.join(format!("{id}.admin")));
                json!({})
            }
            "admin-set" => {
                let peer = text(request, "peer");
                let Some(allowed) = request["allowed"].as_bool() else {
                    return Err("invalid_command");
                };
                if !valid_peer(peer) {
                    return Err("invalid_command");
                }
                self.store()?
                    .set_admin(peer, allowed)
                    .map_err(|_| "omabridge_peer_not_found")?;
                json!({})
            }
            "remote" => json!({ "remote": self.remote(request).await? }),
            "approve" => {
                self.approve(request)?;
                json!({})
            }
            "revoke" => {
                let peer = text(request, "peer");
                if !valid_peer(peer) {
                    return Err("invalid_command");
                }
                self.store()?
                    .revoke(peer)
                    .map_err(|_| "omabridge_peer_not_found")?;
                json!({})
            }
            "publish" => {
                self.publish(request).await?;
                json!({})
            }
            "rename" => json!({ "renamed": self.rename(text(request, "name")).await? }),
            "relay-host" => {
                self.relay_host(request).await?;
                json!({})
            }
            "gateway-domain-set" => {
                self.gateway_domain_set(request).await?;
                json!({})
            }
            "gateway-set" => json!({ "gateway": self.gateway_set(request).await? }),
            "grant-set" => {
                self.grant_set(request)?;
                // The device learns its new grants within seconds.
                json!({ "announced": self.announce().await.unwrap_or(Value::Null) })
            }
            "bridge-consent-set" => {
                let peer = text(request, "peer");
                let Some(allowed) = request["allowed"].as_bool() else {
                    return Err("invalid_command");
                };
                if !valid_peer(peer) {
                    return Err("invalid_command");
                }
                let store = self.store()?;
                let known = store
                    .peers()
                    .map_err(|_| "omabridge_command_failed")?
                    .into_iter()
                    .find(|item| item.id == peer)
                    .ok_or("omabridge_peer_not_found")?;
                if allowed && !known.services.contains("t3") {
                    return Err("omabridge_service_not_granted");
                }
                store
                    .set_bridge_consent(peer, allowed)
                    .map_err(|_| "omabridge_command_failed")?;
                json!({ "announced": self.announce().await.unwrap_or(Value::Null) })
            }
            "relay-set" => {
                self.relay_set(text(request, "relay"))?;
                json!({})
            }
            _ => {
                self.unpublish()?;
                json!({})
            }
        };
        let mut snapshot = self.snapshot();
        if let (Some(target), Some(fields)) = (snapshot.as_object_mut(), extra.as_object()) {
            for (key, value) in fields {
                target.insert(key.clone(), value.clone());
            }
        }
        Ok(snapshot)
    }

    /// The store, only if an identity already exists; reading never creates one.
    fn existing_store(&self) -> Option<Store> {
        if fs::symlink_metadata(self.state_dir.join("state.json")).is_err() {
            return None;
        }
        Store::open(&self.state_dir, "device").ok()
    }

    fn store(&self) -> Outcome<Store> {
        self.existing_store().ok_or("omabridge_identity_missing")
    }

    fn ensure_identity(&self) -> Outcome<Store> {
        if let Some(store) = self.existing_store() {
            return Ok(store);
        }
        Store::open(&self.state_dir, &device_name()).map_err(|_| "omabridge_command_failed")
    }

    pub fn snapshot(&self) -> Value {
        let store = self.existing_store();
        let mut error = "";
        let device = store
            .as_ref()
            .and_then(|store| Some(json!({ "id": store.id().ok()?, "name": store.name().ok()? })));
        let peers = match &store {
            Some(store) => store.peers().unwrap_or_else(|_| {
                error = "omabridge_command_failed";
                Vec::new()
            }),
            None => Vec::new(),
        };
        let pending = match &store {
            Some(store) => store.pending().unwrap_or_else(|_| {
                error = "omabridge_command_failed";
                Vec::new()
            }),
            None => Vec::new(),
        };
        json!({
            "available": true,
            "version": env!("CARGO_PKG_VERSION"),
            "features": FEATURES,
            "identity": store.is_some(),
            "draftStore": device.as_ref().map(|d| json!({"owner":d["id"],"service":crate::drafts::SERVICE,"protocol":1})),
            "device": device,
            "peers": peers.iter().map(|peer| json!({
                "id": peer.id, "name": peer.name,
                "services": peer.services, "remoteServices": peer.remote_services,
                "admin": peer.admin, "managed": peer.managed,
                "public": peer.public, "remotePublic": peer.remote_public,
                "allHosts": peer.all_hosts, "remoteAllHosts": peer.remote_all_hosts,
                "bridgeConsent": peer.bridge_consent,
                "remoteBridgeConsent": peer.remote_bridge_consent,
                "remoteRoutes": peer.remote_routes,
            })).collect::<Vec<_>>(),
            "pending": pending.iter().map(|item| json!({
                "id": item.peer.id, "name": item.peer.name,
                "services": item.peer.services, "expires": item.expires,
                "allHosts": item.peer.all_hosts,
            })).collect::<Vec<_>>(),
            "awaiting": self.awaiting(),
            "published": self.published(store.as_ref()),
            "relay": self.relay(),
            "relayHost": self.relay_host_state(),
            "gateways": self.gateways_state(&peers),
            "gatewayZones": crate::hosting::wildcard_zones(),
            "gatewayDomain": match crate::gateway_domain::Config::load(&self.state_dir) {
                Ok(config) => json!({"domain": config.domain, "port": config.port, "error": null}),
                Err(code) => json!({"domain": null, "port": null, "error": code}),
            },
            "error": error,
        })
    }

    fn t3_port(&self) -> Option<u16> {
        let runtime: Value = serde_json::from_slice(&fs::read(&self.t3_runtime).ok()?).ok()?;
        let port = u16::try_from(runtime["port"].as_u64()?)
            .ok()
            .filter(|port| *port > 0)?;
        listening(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).then_some(port)
    }

    /// `enabled`: the unit exists. `active`: this device is being served, by the
    /// unit or, when `external`, by another program (an older front end's unit or
    /// a manual `serve`). `services` are what is served now, else what the unit names.
    fn published(&self, store: Option<&Store>) -> Value {
        let unit = unit_services(&self.units.dir().join(SERVE_UNIT));
        let unit_active = unit.is_some()
            && self
                .units
                .status(SERVE_UNIT)
                .is_ok_and(|status| status.active == "active");
        let running = store
            .and_then(|store| store.active_endpoint().ok())
            .map(|(_, services)| services);
        let t3 = self.t3_port();
        let follows_t3 = fs::read_to_string(self.units.dir().join(SERVE_UNIT))
            .ok()
            .filter(|text| text.lines().next() == Some(units::MARKER))
            .is_some_and(|text| {
                text.lines()
                    .filter(|line| line.starts_with("ExecStart="))
                    .any(|line| {
                        line.split_whitespace()
                            .collect::<Vec<_>>()
                            .windows(2)
                            .any(|pair| {
                                pair[0] == "--t3-runtime" && Path::new(pair[1]) == self.t3_runtime
                            })
                    })
            });
        let stale = !follows_t3
            && unit.as_ref().is_some_and(|services| {
                services.iter().any(|(name, target)| {
                    name == "t3" && t3.is_some_and(|port| target.port() != port)
                })
            });
        let services: Vec<String> = match (&running, &unit) {
            (Some(running), _) => running.clone(),
            (None, Some(unit)) => unit.iter().map(|(name, _)| name.clone()).collect(),
            (None, None) => Vec::new(),
        };
        json!({
            "enabled": unit.is_some(),
            "active": running.is_some(),
            "external": running.is_some() && !unit_active,
            "stale": stale,
            "followsT3": follows_t3,
            "services": services,
            "sshAvailable": listening(self.ssh_target),
            "mcpAvailable": listening(self.mcp_target),
            "t3Available": t3.is_some(),
        })
    }

    /// Pairings sent from this device that the other one has not approved yet.
    fn awaiting(&self) -> Vec<Value> {
        let now = unix_time().unwrap_or(0);
        let mut out: Vec<(u64, Value)> = fs::read_dir(&self.awaiting_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| {
                let path = entry.path();
                let id = path.file_stem()?.to_str()?.to_owned();
                if !valid_awaiting_id(&id) || path.extension()?.to_str()? != "json" {
                    return None;
                }
                match invitation_summary(&path) {
                    Ok((name, expires)) if expires > now => Some((
                        expires,
                        json!({ "id": id, "name": name, "expires": expires }),
                    )),
                    // Expired or damaged copies are secrets with no further use.
                    _ => {
                        let _ = fs::remove_file(&path);
                        let _ = fs::remove_file(path.with_extension("admin"));
                        None
                    }
                }
            })
            .collect();
        out.sort_by_key(|(expires, _)| *expires);
        out.into_iter().map(|(_, value)| value).collect()
    }

    fn invite(&self, request: &Value) -> Outcome<Value> {
        let services: Vec<String> = request["services"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        if services.is_empty() || services.len() > 32 || services.iter().any(|s| !valid_service(s))
        {
            return Err("invalid_command");
        }
        let all_hosts = request["allHosts"] == true;
        if all_hosts && !services.iter().any(|service| service == "t3") {
            return Err("invalid_command");
        }
        let ttl = request["ttl"].as_u64().unwrap_or(600);
        if !(60..=3600).contains(&ttl) {
            return Err("invalid_command");
        }
        if self.remote && (request.get("directory").is_some() || request["manage"] == true) {
            return Err("omabridge_remote_forbidden");
        }
        let directory = match text(request, "directory") {
            "" => self.invite_dir.clone(),
            raw => local_path(raw),
        };
        if !self.remote
            && (!directory.is_absolute()
                || !fs::metadata(&directory).is_ok_and(|meta| meta.is_dir()))
        {
            return Err("omabridge_invite_directory");
        }
        let store = self.store()?;
        let (address, published) = store
            .active_endpoint()
            .map_err(|_| "omabridge_not_published")?;
        if services
            .iter()
            .any(|service| service != crate::drafts::SERVICE && !published.contains(service))
        {
            return Err("omabridge_service_not_published");
        }
        let now = unix_time().map_err(|_| "local_error")?;
        let path = directory.join(format!(
            "omabridge-invite-{now}-{:04x}.json",
            rand::random::<u16>()
        ));
        let lifetime = Duration::from_secs(ttl);
        let token = if all_hosts {
            store.create_all_hosts_invite(&services, lifetime, now)
        } else {
            store.create_invite(&services, lifetime, now)
        }
        .map_err(|_| "omabridge_command_failed")?;
        let invite = Invitation {
            version: 1,
            address,
            token,
            name: store.name().map_err(|_| "local_error")?,
            expires: now + ttl,
            manage: request["manage"] == true,
        };
        if self.remote {
            return Ok(
                json!({"invitation":invite,"expires":invite.expires,"services":services,"allHosts":all_hosts}),
            );
        }
        write_document(&path, &invite, false).map_err(|_| "omabridge_invite_directory")?;
        let qr = if request["qr"] == true {
            Some(qr_svg(&invite)?)
        } else {
            None
        };
        Ok(json!({
            "path": path.display().to_string(),
            "expires": invite.expires,
            "services": services,
            "manage": invite.manage,
            "allHosts": all_hosts,
            "qrImage": qr,
        }))
    }

    /// Deletes an invitation file this user created: only an `omabridge-invite-*.json`
    /// owned by us, private (0600) and still a valid invitation.
    fn invite_discard(&self, raw: &str) -> Outcome<()> {
        let path = local_path(raw);
        let named = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("omabridge-invite-") && name.ends_with(".json"));
        if !path.is_absolute() || !named {
            return Err("invalid_command");
        }
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err("local_error"),
        };
        if !meta.is_file()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o077 != 0
            || invitation_summary(&path).is_err()
        {
            return Err("invalid_command");
        }
        fs::remove_file(&path).map_err(|_| "local_error")
    }

    /// Pairs from a private copy of the invitation, kept only while approval is pending.
    async fn pair(&self, request: &Value) -> Outcome<Value> {
        let source = local_path(text(request, "path"));
        if !source.is_absolute() {
            return Err("omabridge_invite_unreadable");
        }
        invitation_details(&source)?;
        // Read once: what is checked here is exactly what gets copied and used.
        let body = {
            use std::io::Read;
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&source)
                .map_err(|_| "omabridge_invite_unreadable")?;
            let mut body = Vec::new();
            Read::by_ref(&mut file)
                .take(64 * 1024 + 1)
                .read_to_end(&mut body)
                .map_err(|_| "omabridge_invite_unreadable")?;
            if body.len() > 64 * 1024 {
                return Err("omabridge_invite_invalid");
            }
            body
        };
        let invitation: Invitation =
            serde_json::from_slice(&body).map_err(|_| "omabridge_invite_invalid")?;
        if !crate::valid_device_name(&invitation.name) {
            return Err("omabridge_invite_invalid");
        }
        // The front end may say which device it showed the user; a file swapped
        // since then is refused.
        let expected = text(request, "expect");
        if !expected.is_empty() && expected != invitation.address.id.to_string() {
            return Err("omabridge_invite_changed");
        }
        let asks_to_manage = invitation.manage;
        // An invitation that asks to manage this device needs an explicit answer,
        // so every front end has to show the warning first.
        let allow_manage = match request["allowManage"].as_bool() {
            Some(allowed) => asks_to_manage && allowed,
            None if asks_to_manage => return Err("omabridge_manage_consent_required"),
            None => false,
        };
        private_dir(&self.awaiting_dir)?;
        let id = random_id();
        let copy = self.awaiting_dir.join(format!("{id}.json"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&copy)
            .map_err(|_| "local_error")?;
        if file.write_all(&body).and_then(|_| file.sync_all()).is_err() {
            let _ = fs::remove_file(&copy);
            return Err("local_error");
        }
        if allow_manage {
            fs::write(self.awaiting_dir.join(format!("{id}.admin")), b"")
                .map_err(|_| "local_error")?;
        }
        self.pair_copy(&id).await
    }

    async fn pair_copy(&self, id: &str) -> Outcome<Value> {
        if !valid_awaiting_id(id) {
            return Err("invalid_command");
        }
        let path = self.awaiting_dir.join(format!("{id}.json"));
        let (name, expires) = invitation_summary(&path)?;
        if expires <= unix_time().map_err(|_| "local_error")? {
            let _ = fs::remove_file(&path);
            let _ = fs::remove_file(self.awaiting_dir.join(format!("{id}.admin")));
            return Err("omabridge_invite_expired");
        }
        let store = self.ensure_identity()?;
        let consent = self.awaiting_dir.join(format!("{id}.admin"));
        // While this device serves, its running server pairs, so peers keep reaching it.
        if let Some(reply) = self
            .through_service(&store, json!({ "pair": path.display().to_string() }))
            .await
        {
            let reply = reply?;
            if let Some(code) = reply["error"].as_str() {
                let code = REMOTE_CODES
                    .iter()
                    .chain(&[
                        "omabridge_invite_expired",
                        "omabridge_invite_invalid",
                        "omabridge_pair_denied",
                        "omabridge_peer_unreachable",
                    ])
                    .find(|known| **known == code)
                    .copied()
                    .unwrap_or("omabridge_peer_unreachable");
                if code == "omabridge_invite_expired" {
                    let _ = fs::remove_file(&path);
                    let _ = fs::remove_file(&consent);
                }
                return Err(code);
            }
            if reply["status"] == "approved" {
                let peer = invitation_peer(&path)?;
                let _ = fs::remove_file(&path);
                let managed =
                    fs::remove_file(&consent).is_ok() && store.set_admin(&peer, true).is_ok();
                return Ok(
                    json!({ "status": "approved", "name": name, "peer": peer, "admin": managed }),
                );
            }
            return Ok(json!({ "status": "pending", "id": id, "name": name, "expires": expires }));
        }
        let desktop = Desktop::with_options(store.clone(), self.options.clone());
        let outcome = tokio::time::timeout(self.pair_timeout, desktop.pair(&path, true))
            .await
            .map_err(|_| "omabridge_peer_unreachable")?;
        match outcome {
            Ok(outcome) if outcome.status == PairStatus::Approved => {
                let _ = fs::remove_file(&path);
                // The user consented when accepting an invitation that asked for it.
                let managed = fs::remove_file(&consent).is_ok()
                    && store.set_admin(&outcome.peer_id, true).is_ok();
                Ok(
                    json!({ "status": "approved", "name": name, "peer": outcome.peer_id, "admin": managed }),
                )
            }
            Ok(_) => Ok(json!({ "status": "pending", "id": id, "name": name, "expires": expires })),
            // The copy stays for "Check again": a network failure is often temporary.
            Err(error) => {
                let message = format!("{error:#}");
                if message.contains("expired") {
                    let _ = fs::remove_file(&path);
                    let _ = fs::remove_file(&consent);
                    Err("omabridge_invite_expired")
                } else if message.contains("denied") {
                    Err("omabridge_pair_denied")
                } else {
                    Err("omabridge_peer_unreachable")
                }
            }
        }
    }

    fn approve(&self, request: &Value) -> Outcome<()> {
        let peer = text(request, "peer");
        if !valid_peer(peer) {
            return Err("invalid_command");
        }
        let store = self.store()?;
        let claims: Vec<_> = store
            .pending()
            .map_err(|_| "omabridge_command_failed")?
            .into_iter()
            .filter(|item| item.peer.id == peer)
            .collect();
        // A peer that claimed several invitations is approved for the one the user saw.
        let chosen = match claims.as_slice() {
            [] => return Err("omabridge_peer_not_found"),
            [one] => one,
            many => many
                .iter()
                .find(|item| request["expires"].as_u64() == Some(item.expires))
                .ok_or("omabridge_request_changed")?,
        };
        // Checked on the invitation being approved, so a claim arriving after any
        // earlier look cannot slip through.
        if self.remote && chosen.peer.all_hosts {
            return Err("omabridge_remote_forbidden");
        }
        store
            .approve_selected(
                peer,
                Some(&chosen.invitation_id),
                unix_time().map_err(|_| "local_error")?,
            )
            .map_err(|_| "omabridge_request_changed")
    }

    async fn publish(&self, request: &Value) -> Outcome<()> {
        let mut services = Vec::new();
        let t3 = self.t3_port();
        match (request["t3"].as_bool(), t3) {
            (Some(true), None) => return Err("omabridge_t3_unavailable"),
            (Some(true) | None, Some(port)) => services.push((
                "t3".to_owned(),
                SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            )),
            _ => {}
        }
        if request["ssh"] == true {
            if !listening(self.ssh_target) {
                return Err("omabridge_ssh_unavailable");
            }
            services.push(("ssh".to_owned(), self.ssh_target));
        }
        match request.get("mcp") {
            Some(Value::Bool(true)) => {
                if !listening(self.mcp_target) {
                    return Err("omabridge_mcp_unavailable");
                }
                services.push(("mcp".to_owned(), self.mcp_target));
            }
            Some(Value::Bool(false)) => {}
            Some(_) => return Err("invalid_command"),
            None => {
                // Older front ends do not know about MCP. Preserve an existing
                // publication, including its target, even during a gateway restart.
                // Never infer consent merely from a listening local MCP server.
                if let Some(existing) = unit_services(&self.units.dir().join(SERVE_UNIT)) {
                    services.extend(existing.into_iter().filter(|(name, _)| name == "mcp"));
                }
            }
        }
        if services.is_empty() {
            return Err("omabridge_nothing_to_publish");
        }
        let store = self.ensure_identity()?;
        let unit_path = self.units.dir().join(SERVE_UNIT);
        let unit_active = unit_services(&unit_path).is_some()
            && self
                .units
                .status(SERVE_UNIT)
                .is_ok_and(|status| status.active == "active");
        if !unit_active && store.active_endpoint().is_ok() {
            return Err("omabridge_already_running");
        }
        let context = UnitContext {
            binary: self.binary.clone(),
            state_dir: self.state_dir.clone(),
            name: device_name(),
            bind: None,
        };
        let spec = if services.iter().any(|(name, _)| name == "t3") {
            UnitSpec::ServeTracked {
                services: services.clone(),
                t3_runtime: self.t3_runtime.clone(),
            }
        } else {
            UnitSpec::Serve {
                services: services.clone(),
            }
        };
        if fs::symlink_metadata(&unit_path).is_ok() && unit_services(&unit_path).is_none() {
            return Err("omabridge_unit_foreign");
        }
        if units::render(&context, &spec).is_err() {
            return Err("omabridge_path_unsupported");
        }
        self.units
            .install(&context, &spec)
            .map_err(|_| "omabridge_publish_failed")?;
        self.units
            .restart(SERVE_UNIT)
            .map_err(|_| "omabridge_publish_failed")?;
        let wanted: Vec<String> = services.into_iter().map(|(name, _)| name).collect();
        let deadline = tokio::time::Instant::now() + self.publish_wait;
        while tokio::time::Instant::now() < deadline {
            if store
                .active_endpoint()
                .is_ok_and(|(_, served)| wanted.iter().all(|name| served.contains(name)))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok(())
    }

    /// Sends one request to the running server of this identity over its
    /// private control socket, so its relay connection is never taken over by
    /// a second endpoint. None when no server with a control socket runs.
    async fn through_service(&self, store: &Store, request: Value) -> Option<Outcome<Value>> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        store.active_endpoint().ok()?;
        let path = self.state_dir.join(crate::network::CONTROL_SOCKET);
        let mut socket = tokio::net::UnixStream::connect(&path).await.ok()?;
        let exchange = async {
            socket
                .write_all(format!("{request}\n").as_bytes())
                .await
                .ok()?;
            let mut line = String::new();
            tokio::io::BufReader::new(socket)
                .read_line(&mut line)
                .await
                .ok()?;
            serde_json::from_str::<Value>(&line).ok()
        };
        Some(
            tokio::time::timeout(self.pair_timeout, exchange)
                .await
                .ok()
                .flatten()
                .ok_or("omabridge_peer_unreachable"),
        )
    }

    /// This device is served by its own active publishing unit.
    fn serves_itself(&self) -> bool {
        unit_services(&self.units.dir().join(SERVE_UNIT)).is_some()
            && self
                .units
                .status(SERVE_UNIT)
                .is_ok_and(|status| status.active == "active")
    }

    /// Renames this device and tells its paired devices.
    async fn rename(&self, raw: &str) -> Outcome<Value> {
        let name = raw.trim();
        if !crate::valid_device_name(name) {
            return Err("omabridge_name_invalid");
        }
        self.store()?
            .set_name(name)
            .map_err(|_| "omabridge_command_failed")?;
        self.announce().await
    }

    /// Exchanges names and addresses with paired devices. A running server
    /// does it itself within seconds; a second endpoint with the same identity
    /// would compete with it for the relay, so only an unserved device dials.
    async fn announce(&self) -> Outcome<Value> {
        let store = self.store()?;
        if let Some(reply) = self
            .through_service(&store, json!({ "announce": true }))
            .await
        {
            let reply = reply?;
            return Ok(json!({
                "via": "service",
                "reached": reply["reached"].as_u64().unwrap_or(0),
                "total": reply["total"].as_u64().unwrap_or(0),
            }));
        }
        if store.active_endpoint().is_ok() {
            // An older server without a control socket announces by itself.
            return Ok(json!({ "via": "service" }));
        }
        let client = Client::new(store, self.options.clone())
            .await
            .map_err(|_| "local_error")?;
        let result = client.announce(None).await;
        client.close().await;
        let (reached, total) = result.map_err(|_| "omabridge_command_failed")?;
        Ok(json!({ "via": "direct", "reached": reached, "total": total }))
    }

    /// Sends one command to a paired device that lets this one manage it.
    async fn remote(&self, request: &Value) -> Outcome<Value> {
        let peer = text(request, "peer");
        let command = &request["command"];
        if !valid_peer(peer) || !command.is_object() {
            return Err("invalid_command");
        }
        if !REMOTE_ACTIONS.contains(&text(command, "action")) {
            return Err("omabridge_remote_forbidden");
        }
        let store = self.store()?;
        let target = store
            .peers()
            .map_err(|_| "omabridge_command_failed")?
            .into_iter()
            .find(|item| item.id == peer && item.managed)
            .ok_or("omabridge_not_managed")?;
        let address = target.address.ok_or("omabridge_peer_unreachable")?;
        let answer = if let Some(reply) = self
            .through_service(&store, json!({ "peer": peer, "command": command }))
            .await
        {
            let reply = reply?;
            match reply["error"].as_str() {
                Some(code) => Ok(Err(anyhow::anyhow!(
                    if code == "omabridge_remote_unsupported" {
                        "management refused"
                    } else {
                        "unreachable"
                    }
                ))),
                None => Ok(Ok(reply["outcome"].clone())),
            }
        } else {
            let client = Client::new(store, self.options.clone())
                .await
                .map_err(|_| "local_error")?;
            let answer =
                tokio::time::timeout(self.pair_timeout, client.manage(&address, command)).await;
            client.close().await;
            answer
        };
        match answer {
            Ok(Ok(result)) => match result["error"].as_str() {
                Some(code) if !code.is_empty() && result.get("available").is_none() => {
                    Err(REMOTE_CODES
                        .iter()
                        .find(|known| **known == code)
                        .copied()
                        .unwrap_or("omabridge_remote_failed"))
                }
                _ => Ok(result),
            },
            Ok(Err(error)) if format!("{error:#}").contains("management refused") => {
                Err("omabridge_remote_unsupported")
            }
            _ => Err("omabridge_peer_unreachable"),
        }
    }

    /// Public entry points this device offers for its paired devices' services.
    fn gateways_state(&self, peers: &[crate::Peer]) -> Value {
        let status = crate::gateway::status(&self.state_dir);
        crate::gateway::load(&self.state_dir)
            .into_iter()
            .map(|gateway| {
                let state = status.get(&gateway.url()).cloned().unwrap_or_default();
                json!({
                    "peer": gateway.peer,
                    "name": peers.iter().find(|peer| peer.id == gateway.peer).map(|peer| peer.name.clone()),
                    "service": gateway.service,
                    "url": gateway.url(),
                    "running": state.running,
                    "error": state.error,
                })
            })
            .collect::<Vec<_>>()
            .into()
    }

    /// The host name for public entry points: the hosted relay's, else the suggestion's.
    async fn public_host(&self) -> Option<String> {
        let url = match crate::hosting::load(&self.state_dir) {
            Some(config) => config.url,
            None => crate::hosting::suggest(&self.public_addresses()).await?.url,
        };
        let url: iroh::RelayUrl = url.parse().ok()?;
        Some(url.host_str()?.trim_end_matches('.').to_owned())
    }

    /// Only the local server administrator chooses the namespace. Never a remote action.
    async fn gateway_domain_set(&self, request: &Value) -> Outcome<()> {
        let store = self.store()?;
        let _lock = crate::gateway_domain::lock(&self.state_dir)?;
        let mut config = crate::gateway_domain::Config::load(&self.state_dir)?;
        let enabled = request["enabled"].as_bool().ok_or("invalid_command")?;
        if enabled {
            // A new CLI must not configure ownership policy while an old daemon
            // still accepts remote writes that do not enforce that policy.
            let capabilities = self
                .through_service(&store, json!({"capabilities": true}))
                .await
                .ok_or("omabridge_not_published")??;
            if !capabilities["features"]
                .as_array()
                .is_some_and(|features| features.iter().any(|feature| feature == "gateway-domain"))
            {
                return Err("omabridge_gateway_upgrade_required");
            }
            let domain = text(request, "domain")
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if !crate::gateway_domain::valid_domain(&domain) {
                return Err("omabridge_gateway_domain_invalid");
            }
            let port = match request.get("port") {
                None => 443,
                Some(value) => value
                    .as_u64()
                    .and_then(|p| u16::try_from(p).ok())
                    .filter(|p| *p == 443 || *p >= 1024)
                    .ok_or("invalid_command")?,
            };
            if !crate::hosting::wildcard_zones().contains(&domain) {
                return Err("omabridge_relay_certificate");
            }
            config.domain = Some(domain);
            config.port = Some(port);
            config.import(&crate::gateway::load(&self.state_dir))?;
        } else {
            // Existing endpoints and all ownership reservations remain intact.
            config.domain = None;
            config.port = None;
        }
        config.save(&self.state_dir)
    }

    /// Opens or closes a public HTTPS entry point here for one service of a
    /// paired device, which must have granted that service to this device. With
    /// `host`, a name of its own (a subdomain this device has a certificate
    /// for), sharing a port with other names; without it, this device's public
    /// name on a port of its own.
    async fn gateway_set(&self, request: &Value) -> Outcome<Value> {
        let store = self.store()?;
        let peer = text(request, "peer");
        let service = text(request, "service");
        let Some(enabled) = request["enabled"].as_bool() else {
            return Err("invalid_command");
        };
        if !valid_peer(peer) || !valid_service(service) {
            return Err("invalid_command");
        }
        if request.get("port").is_some_and(|port| !port.is_u64()) {
            return Err("invalid_command");
        }
        let _lock = crate::gateway_domain::lock(&self.state_dir)?;
        let mut gateways = crate::gateway::load(&self.state_dir);
        let existing = gateways
            .iter()
            .position(|gateway| gateway.peer == peer && gateway.service == service);
        if !enabled {
            if let Some(index) = existing {
                gateways.remove(index);
            }
            crate::gateway::save(&self.state_dir, &gateways).map_err(|_| "local_error")?;
            return Ok(Value::Null);
        }
        let mut domain = crate::gateway_domain::Config::load(&self.state_dir)?;
        domain.import(&gateways)?;
        if store.active_endpoint().is_err() {
            return Err("omabridge_not_published");
        }
        if !crate::gateway::PUBLIC_SERVICES.contains(&service) {
            return Err("omabridge_remote_forbidden");
        }
        // The device that owns the service must have let this one expose it.
        let granted = store
            .peers()
            .map_err(|_| "omabridge_command_failed")?
            .into_iter()
            .find(|item| {
                item.id == peer
                    && item.remote_services.contains(service)
                    && item.remote_public.contains(service)
            })
            .ok_or("omabridge_service_not_granted")?;
        let previous = existing.map(|index| gateways[index].clone());
        let own_name = !text(request, "host").is_empty();
        let host = if own_name {
            let host = text(request, "host")
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if !crate::hosting::valid_host(&host) {
                return Err("omabridge_gateway_host_invalid");
            }
            host
        } else if let Some(previous) = &previous {
            // Reconciliation must retain the address clients already know, even
            // while public address discovery is unavailable after a network change.
            previous.host.clone()
        } else if domain.domain.is_some() && service == "t3" {
            domain.hostname(peer, service, &granted.name)?
        } else {
            self.public_host()
                .await
                .ok_or("omabridge_relay_host_unavailable")?
        };
        domain.check(&host, peer, service)?;
        if crate::hosting::certificate_for(&host).is_none() {
            return Err("omabridge_relay_certificate");
        }
        if let Some(index) = existing {
            gateways.remove(index);
        }
        let relay_port = crate::hosting::load(&self.state_dir).map(|config| config.listen.port());
        // A port is shared by different names; the same name appears once per port.
        let taken = |port: u16| {
            Some(port) == relay_port
                || gateways
                    .iter()
                    .any(|gateway| gateway.port == port && gateway.host == host)
        };
        let in_use = |port: u16| gateways.iter().any(|gateway| gateway.port == port);
        let free = |port: u16| match std::net::TcpListener::bind(("0.0.0.0", port)) {
            Ok(_) => true,
            // The unprivileged management caller does not inherit the daemon's
            // CAP_NET_BIND_SERVICE. Readiness remains the daemon's bind result.
            Err(error) => {
                port == 443
                    && domain.contains(&host)
                    && error.kind() == std::io::ErrorKind::PermissionDenied
            }
        };
        let selected_port = request["port"].as_u64().or_else(|| {
            if previous.is_none() && domain.contains(&host) {
                domain.port.map(u64::from)
            } else {
                None
            }
        });
        let port = match selected_port {
            Some(port) => {
                let port = u16::try_from(port)
                    .ok()
                    .filter(|port| *port >= 1024 || (*port == 443 && domain.contains(&host)))
                    .ok_or("invalid_command")?;
                if taken(port)
                    || !(previous
                        .as_ref()
                        .is_some_and(|gateway| gateway.port == port)
                        || in_use(port)
                        || free(port))
                {
                    return Err("omabridge_port_unavailable");
                }
                port
            }
            None if previous
                .as_ref()
                .is_some_and(|gateway| !taken(gateway.port)) =>
            {
                previous.as_ref().expect("checked previous gateway").port
            }
            None => {
                // A name of its own joins the port other names already share.
                let shared = own_name
                    .then(|| {
                        gateways
                            .iter()
                            .map(|gateway| gateway.port)
                            .find(|port| !taken(*port))
                    })
                    .flatten();
                match shared {
                    Some(port) => port,
                    None => (0..64)
                        .map(|_| rand::random_range(crate::gateway::RANDOM_PORTS))
                        .find(|port| !taken(*port) && !in_use(*port) && free(*port))
                        .ok_or("omabridge_port_unavailable")?,
                }
            }
        };
        if gateways.len() >= crate::gateway::MAX_GATEWAYS {
            return Err("omabridge_port_unavailable");
        }
        let gateway = crate::gateway::Gateway {
            host,
            port,
            peer: peer.to_owned(),
            service: service.to_owned(),
        };
        if domain.contains(&gateway.host) {
            domain.reserve(&gateway.host, peer, service)?;
            // Reserve before publishing: failure can retain an unused name but
            // can never publish a name without its durable ownership binding.
            domain.save(&self.state_dir)?;
        }
        // Preserve ordering too: the listener signature includes every gateway
        // on the port, so moving an unchanged entry would interrupt clients.
        gateways.insert(existing.unwrap_or(gateways.len()), gateway.clone());
        crate::gateway::save(&self.state_dir, &gateways).map_err(|_| "local_error")?;
        // Whether the name already points here; a new DNS record may still be on its way.
        let own = self.public_addresses();
        let dns = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::lookup_host((gateway.host.as_str(), gateway.port)),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .is_some_and(|mut addrs| addrs.any(|addr| own.contains(&addr.ip())));
        Ok(json!({ "url": gateway.url(), "port": gateway.port, "dns": dns }))
    }

    /// Sets which of this device's published services a paired device may
    /// reach: the owner's decision, never a managing device's.
    fn grant_set(&self, request: &Value) -> Outcome<()> {
        let store = self.store()?;
        let peer = text(request, "peer");
        let list = |key: &str| -> Outcome<Vec<String>> {
            match &request[key] {
                Value::Null => Ok(Vec::new()),
                Value::Array(items) => items
                    .iter()
                    .map(|item| item.as_str().map(str::to_owned).ok_or("invalid_command"))
                    .collect(),
                _ => Err("invalid_command"),
            }
        };
        let services = list("services")?;
        // Services the device may also expose publicly through its gateways.
        let public = list("public")?;
        if public.iter().any(|s| s == crate::drafts::SERVICE) {
            return Err("invalid_command");
        }
        if !valid_peer(peer)
            || services
                .iter()
                .chain(&public)
                .any(|service| !valid_service(service))
            || public.iter().any(|service| !services.contains(service))
        {
            return Err("invalid_command");
        }
        let (_, published) = store
            .active_endpoint()
            .map_err(|_| "omabridge_not_published")?;
        if services
            .iter()
            .any(|service| service != crate::drafts::SERVICE && !published.contains(service))
        {
            return Err("omabridge_service_not_published");
        }
        store
            .set_services(peer, &services, &public)
            .map_err(|_| "omabridge_peer_not_found")
    }

    /// Whether a public HTTPS address reaches this device's own T3 Code: both
    /// answer T3's public descriptor with the same environment.
    async fn gateway_check(&self, url: &str) -> Value {
        let Ok(base) = url.parse::<iroh::RelayUrl>() else {
            return json!({ "reachable": false, "sameEnvironment": null });
        };
        if base.scheme() != "https" {
            return json!({ "reachable": false, "sameEnvironment": null });
        }
        let Ok(client) = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
        else {
            return json!({ "reachable": false, "sameEnvironment": null });
        };
        let environment = |base: String| {
            let client = client.clone();
            async move {
                let response = client
                    .get(format!(
                        "{}/.well-known/t3/environment",
                        base.trim_end_matches('/')
                    ))
                    .send()
                    .await
                    .ok()?;
                let body: Value = response.json().await.ok()?;
                body["environmentId"].as_str().map(str::to_owned)
            }
        };
        let remote = environment(base.to_string()).await;
        let local = match self.t3_port() {
            Some(port) => environment(format!("http://127.0.0.1:{port}")).await,
            None => None,
        };
        json!({
            "reachable": remote.is_some(),
            "sameEnvironment": match (&remote, &local) {
                (Some(remote), Some(local)) => Value::Bool(remote == local),
                _ => Value::Null,
            },
        })
    }

    /// The private relay this device hosts for its paired devices, if any.
    fn relay_host_state(&self) -> Value {
        let config = crate::hosting::load(&self.state_dir);
        let status = crate::hosting::status(&self.state_dir);
        json!({
            "enabled": config.is_some(),
            "url": config.map(|config| config.url),
            "running": status.running,
            "error": status.error,
            "suggested": null,
        })
    }

    fn public_addresses(&self) -> Vec<std::net::IpAddr> {
        self.existing_store()
            .and_then(|store| store.active_endpoint().ok())
            .map(|(address, _)| {
                address
                    .addrs
                    .iter()
                    .filter_map(|addr| match addr {
                        iroh::TransportAddr::Ip(ip) => Some(ip.ip()),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The URL proposed for hosting a relay here, while none is hosted.
    async fn relay_suggestion(&self) -> Value {
        if crate::hosting::load(&self.state_dir).is_some() {
            return Value::Null;
        }
        match crate::hosting::suggest(&self.public_addresses()).await {
            Some(suggestion) => json!(suggestion.url),
            None => Value::Null,
        }
    }

    /// Starts or stops hosting a private relay in this device's server. Without
    /// a URL it uses the suggestion; certificate paths are this device's own
    /// choice (a managing device can only use a certificate found here).
    async fn relay_host(&self, request: &Value) -> Outcome<()> {
        let store = self.store()?;
        let Some(enabled) = request["enabled"].as_bool() else {
            return Err("invalid_command");
        };
        if !enabled {
            return crate::hosting::save(&self.state_dir, None).map_err(|_| "local_error");
        }
        if store.active_endpoint().is_err() {
            return Err("omabridge_not_published");
        }
        let suggestion = crate::hosting::suggest(&self.public_addresses()).await;
        let url = match text(request, "url") {
            "" => suggestion
                .as_ref()
                .map(|suggestion| suggestion.url.clone())
                .ok_or("omabridge_relay_host_unavailable")?,
            url => url.to_owned(),
        };
        let parsed: iroh::RelayUrl = url.parse().map_err(|_| "omabridge_relay_invalid")?;
        let host = parsed
            .host_str()
            .ok_or("omabridge_relay_invalid")?
            .to_owned();
        let (cert, key) = match (text(request, "cert"), text(request, "key")) {
            ("", "") => {
                crate::hosting::certificate_for(&host).ok_or("omabridge_relay_certificate")?
            }
            (cert, key) if !cert.is_empty() && !key.is_empty() => {
                (local_path(cert), local_path(key))
            }
            _ => return Err("invalid_command"),
        };
        let config = crate::hosting::config_for(&url, &cert, &key)
            .map_err(|_| "omabridge_relay_certificate")?;
        crate::hosting::save(&self.state_dir, Some(&config)).map_err(|_| "local_error")
    }

    /// The device's saved relay: `mode` is public, custom or none.
    fn relay(&self) -> Value {
        match Relay::load(&self.state_dir) {
            Ok(Relay::Public) => json!({ "mode": "public", "url": null }),
            Ok(Relay::Custom(url)) => json!({ "mode": "custom", "url": url.to_string() }),
            Ok(Relay::Disabled) => json!({ "mode": "none", "url": null }),
            Err(_) => json!({ "mode": "invalid", "url": null }),
        }
    }

    /// Saves how this device reaches peers behind NAT and restarts its own
    /// publishing unit so new invitations carry the new relay.
    fn relay_set(&self, raw: &str) -> Outcome<()> {
        if raw.len() > 512 {
            return Err("omabridge_relay_invalid");
        }
        let relay = Relay::parse(raw).map_err(|_| "omabridge_relay_invalid")?;
        relay.save(&self.state_dir).map_err(|_| "local_error")?;
        let unit_path = self.units.dir().join(SERVE_UNIT);
        let ours_active = unit_services(&unit_path).is_some()
            && self
                .units
                .status(SERVE_UNIT)
                .is_ok_and(|status| status.active == "active");
        if ours_active {
            self.units
                .restart(SERVE_UNIT)
                .map_err(|_| "omabridge_publish_failed")?;
        }
        Ok(())
    }

    fn unpublish(&self) -> Outcome<()> {
        let path = self.units.dir().join(SERVE_UNIT);
        if fs::symlink_metadata(&path).is_err() {
            return Ok(());
        }
        if unit_services(&path).is_none() {
            return Err("omabridge_unit_foreign");
        }
        self.units
            .remove(SERVE_UNIT)
            .map_err(|_| "omabridge_publish_failed")
    }
}

/// systemctl for remote commands: the publishing unit is the process answering,
/// so restarting or stopping it waits until the managing device has its answer.
#[derive(Default)]
pub struct Deferred {
    queued: std::sync::Mutex<Vec<Vec<String>>>,
    stopping: std::sync::atomic::AtomicBool,
}

impl units::Runner for Deferred {
    fn run(&self, args: &[&str]) -> anyhow::Result<units::RunOutput> {
        use std::sync::atomic::Ordering;
        let held = |args: &[&str]| {
            self.queued
                .lock()
                .expect("queue lock")
                .push(args.iter().map(|arg| (*arg).to_owned()).collect());
            Ok(units::RunOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            })
        };
        match args {
            ["restart", SERVE_UNIT] => held(args),
            ["disable", "--now", SERVE_UNIT] => {
                self.stopping.store(true, Ordering::SeqCst);
                let _ = held(&["stop", SERVE_UNIT]);
                units::Systemctl.run(&["disable", SERVE_UNIT])
            }
            ["is-active", SERVE_UNIT] if self.stopping.load(Ordering::SeqCst) => {
                Ok(units::RunOutput {
                    success: false,
                    stdout: "inactive\n".to_owned(),
                    stderr: String::new(),
                })
            }
            _ => units::Systemctl.run(args),
        }
    }
}

impl Deferred {
    /// Runs what was held back, without waiting, after the answer was sent.
    pub fn flush(&self) {
        let queued = std::mem::take(&mut *self.queued.lock().expect("queue lock"));
        for args in queued {
            let mut all = vec!["--no-block"];
            all.extend(args.iter().map(String::as_str));
            let _ = units::Systemctl.run(&all);
        }
    }
}

/// Answers one command from a paired device. Only devices this device lets
/// manage it are served, only `REMOTE_ACTIONS` run, other managing devices
/// cannot be revoked, and every change is written to `manage-audit.jsonl`.
pub async fn serve_remote(
    store: &Store,
    peer: &str,
    command: &Value,
) -> (Value, std::sync::Arc<Deferred>) {
    let deferred = std::sync::Arc::new(Deferred::default());
    let action = text(command, "action");
    // Only listed action names reach the audit, never caller-chosen text.
    let action = REMOTE_ACTIONS
        .iter()
        .find(|known| **known == action)
        .copied()
        .unwrap_or("other");
    let result = run_remote(store, peer, command, deferred.clone()).await;
    if result.is_ok() && action != "relay-set" {
        confirm_relay(store.root());
    }
    // Requests from devices that may not manage this one are not recorded, so
    // nobody can flood the log away.
    if action != "read" && result != Err("omabridge_not_admin") {
        audit(store.root(), peer, action, result.as_ref().err().copied());
    }
    let value = result.unwrap_or_else(|code| json!({ "error": code }));
    (value, deferred)
}

async fn run_remote(
    store: &Store,
    peer: &str,
    command: &Value,
    deferred: std::sync::Arc<Deferred>,
) -> Outcome<Value> {
    let peers = store.peers().map_err(|_| "omabridge_command_failed")?;
    if !peers.iter().any(|item| item.id == peer && item.admin) {
        return Err("omabridge_not_admin");
    }
    // A managing device may open a public gateway only to its own services,
    // and only under a name of its own in a wildcard zone of this device (or
    // this device's public name): never under this device's other domains.
    if text(command, "action") == "gateway-set" {
        if text(command, "peer") != peer {
            return Err("omabridge_remote_forbidden");
        }
        let host = text(command, "host")
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let in_zone = crate::hosting::wildcard_zones().iter().any(|zone| {
            host.strip_suffix(zone.as_str())
                .and_then(|label| label.strip_suffix('.'))
                .is_some_and(|label| !label.is_empty() && !label.contains('.'))
        });
        if !host.is_empty() && !in_zone {
            return Err("omabridge_remote_forbidden");
        }
    }
    let action = text(command, "action");
    if !command.is_object() || !REMOTE_ACTIONS.contains(&action) {
        return Err("omabridge_remote_forbidden");
    }
    // Who may manage this device is decided only here, so no managing device
    // can remove one, itself included.
    if action == "revoke"
        && peers
            .iter()
            .any(|item| item.id == text(command, "peer") && item.admin)
    {
        return Err("omabridge_peer_is_admin");
    }
    if action == "invite" {
        let actor = peers
            .iter()
            .find(|p| p.id == peer)
            .ok_or("omabridge_not_admin")?;
        let services = command["services"].as_array().ok_or("invalid_command")?;
        if services
            .iter()
            .any(|s| !s.as_str().is_some_and(|s| actor.services.contains(s)))
        {
            return Err("omabridge_service_not_granted");
        }
    }
    if action == "relay-set" {
        remote_relay_allowed(text(command, "relay"))?;
    }
    // Which files serve as a certificate is the managed device's own choice.
    if action == "relay-host" && (command.get("cert").is_some() || command.get("key").is_some()) {
        return Err("omabridge_remote_forbidden");
    }
    // A managing device opens a public entry point only to services granted here.
    if action == "gateway-set" && command.get("port").is_some_and(|port| !port.is_u64()) {
        return Err("invalid_command");
    }
    if action == "relay-host" && !text(command, "url").is_empty() {
        remote_relay_allowed(text(command, "url"))?;
    }
    let mut manager = Manager::from_env(
        store.root().to_path_buf(),
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        None,
    )?;
    manager.units = Units::new(units::user_unit_dir().map_err(|_| "local_error")?, deferred);
    manager.publish_wait = Duration::ZERO;
    manager.remote = true;
    let previous = Relay::load(store.root()).unwrap_or_default();
    let mut command = command.clone();
    command["confirmed"] = json!(true);
    let mut snapshot = manager.execute(&command).await?;
    if action == "relay-set" && manager.serves_itself() {
        // Undone unless a managing device reaches this one again in time.
        let rollback = json!({ "relay": previous.arg(), "deadline": unix_time().unwrap_or(0) + ROLLBACK_SECS });
        write_document(&store.root().join(ROLLBACK_FILE), &rollback, true)
            .map_err(|_| "local_error")?;
    }
    if let Some(fields) = snapshot.as_object_mut() {
        // Pairings this device started are its own business.
        fields.remove("awaiting");
    }
    Ok(snapshot)
}

const ROLLBACK_FILE: &str = "relay-rollback.json";
/// How long a remotely changed relay waits for a managing device to come back.
const ROLLBACK_SECS: u64 = 120;

/// A managing device may switch between public relays and a relay with a public
/// HTTPS name, never to direct-only or a local address: either would cut it off.
fn remote_relay_allowed(raw: &str) -> Outcome<()> {
    if raw == "public" {
        return Ok(());
    }
    let relay = Relay::parse(raw).map_err(|_| "omabridge_relay_invalid")?;
    let Relay::Custom(url) = relay else {
        return Err("omabridge_remote_forbidden");
    };
    if !crate::hosting::public_host(&url) {
        return Err("omabridge_relay_invalid");
    }
    Ok(())
}

/// A managing device reached this one after a remote relay change: keep it.
pub fn confirm_relay(state_dir: &Path) {
    let _ = fs::remove_file(state_dir.join(ROLLBACK_FILE));
}

/// Called while serving: restores the previous relay when a remote change was
/// not confirmed in time, and restarts the publishing unit to apply it.
pub fn rollback_due(state_dir: &Path, systemctl: &dyn units::Runner) -> bool {
    let path = state_dir.join(ROLLBACK_FILE);
    let Ok(pending) = read_document::<Value>(&path) else {
        return false;
    };
    if pending["deadline"].as_u64().unwrap_or(0) > unix_time().unwrap_or(0) {
        return false;
    }
    let restored = Relay::parse(text(&pending, "relay"))
        .and_then(|relay| relay.save(state_dir))
        .is_ok();
    let _ = fs::remove_file(&path);
    if restored {
        let _ = systemctl.run(&["--no-block", "restart", SERVE_UNIT]);
    }
    restored
}

/// One line per remote change: when, who, what and the outcome; never secrets.
fn audit(state_dir: &Path, peer: &str, action: &str, error: Option<Code>) {
    let path = state_dir.join("manage-audit.jsonl");
    if fs::metadata(&path).is_ok_and(|meta| meta.len() > 1024 * 1024) {
        // Several rotations, so one managing device's chatter cannot hide much.
        for index in (1..4).rev() {
            let _ = fs::rename(
                state_dir.join(format!("manage-audit.{index}.jsonl")),
                state_dir.join(format!("manage-audit.{}.jsonl", index + 1)),
            );
        }
        let _ = fs::rename(&path, state_dir.join("manage-audit.1.jsonl"));
    }
    let line = json!({
        "id": format!("{:016x}", rand::random::<u64>()),
        "time": unix_time().unwrap_or(0),
        "peer": peer,
        "action": action,
        "error": error,
    });
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    {
        let _ = writeln!(file, "{line}");
    }
}
