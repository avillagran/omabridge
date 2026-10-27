//! A private relay hosted by a device's own server for the devices paired with
//! it. The choice lives in `relay-host.json`; the running server starts, stops
//! or reloads the relay within seconds of a change, and again when the
//! certificate is renewed, and reports how it went in `relay-host.status.json`.
use crate::{Store, read_document, relay::RelayServer, write_document};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

const CONFIG: &str = "relay-host.json";
const STATUS: &str = "relay-host.status.json";
/// Port suggested for a hosted relay, beside a web server on 443.
pub const DEFAULT_PORT: u16 = 3341;
const CHECK: Duration = Duration::from_secs(5);
const CERT_DIRS: &str = "/etc/letsencrypt/live";

/// Where certificates are looked for: Let's Encrypt's, unless the server was
/// started with `OMABRIDGE_CERT_DIR` (tests and non-standard layouts).
fn cert_dirs() -> PathBuf {
    std::env::var_os("OMABRIDGE_CERT_DIR")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| PathBuf::from(CERT_DIRS))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    /// What devices put in `--relay`: `https://name:port/`.
    pub url: String,
    pub listen: SocketAddr,
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostStatus {
    pub running: bool,
    /// Short reason when it could not start: `certificate`, `port` or `failed`.
    pub error: Option<String>,
}

/// A relay this device could host: a certificate it can read for a name that
/// points at one of its public addresses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Suggestion {
    pub url: String,
    #[serde(skip)]
    pub cert: PathBuf,
    #[serde(skip)]
    pub key: PathBuf,
}

pub fn load(state_dir: &Path) -> Option<HostConfig> {
    read_document(&state_dir.join(CONFIG)).ok()
}

pub fn save(state_dir: &Path, config: Option<&HostConfig>) -> Result<()> {
    match config {
        Some(config) => write_document(&state_dir.join(CONFIG), config, true),
        None => match std::fs::remove_file(state_dir.join(CONFIG)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
            _ => Ok(()),
        },
    }
}

pub fn status(state_dir: &Path) -> HostStatus {
    read_document(&state_dir.join(STATUS)).unwrap_or_default()
}

fn set_status(state_dir: &Path, status: &HostStatus) {
    let _ = write_document(&state_dir.join(STATUS), status, true);
}

/// DNS names a PEM certificate chain's first certificate covers, if it is
/// currently valid. Wildcards are left out: a relay needs one concrete name.
pub fn certificate_names(cert: &Path) -> Vec<String> {
    certificate_patterns(cert)
        .into_iter()
        .filter(|name| !name.contains('*'))
        .collect()
}

/// Every DNS name a currently valid certificate covers, wildcards included.
pub fn certificate_patterns(cert: &Path) -> Vec<String> {
    let Ok(pem) = std::fs::read(cert) else {
        return Vec::new();
    };
    let Some(Ok(der)) = rustls_pemfile::certs(&mut pem.as_slice()).next() else {
        return Vec::new();
    };
    let Ok((_, parsed)) = x509_parser::parse_x509_certificate(&der) else {
        return Vec::new();
    };
    if !parsed.validity().is_valid() {
        return Vec::new();
    }
    let Ok(Some(names)) = parsed.subject_alternative_name() else {
        return Vec::new();
    };
    names
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            x509_parser::extensions::GeneralName::DNSName(dns) => Some(dns.to_ascii_lowercase()),
            _ => None,
        })
        .collect()
}

/// A relay URL whose host is a public name or a public address, never
/// `localhost` or a loopback, private or link-local literal.
pub fn public_host(url: &iroh::RelayUrl) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase();
    match host.parse::<IpAddr>() {
        Ok(ip) => public(ip),
        Err(_) => host.contains('.') && host != "localhost" && !host.ends_with(".localhost"),
    }
}

/// A globally routable address; IPv4-mapped IPv6 is judged as IPv4.
pub fn public(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        ip => ip,
    };
    public_unmapped(ip)
}

fn public_unmapped(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, ..] = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_broadcast()
                || a == 0
                || a >= 240
                || (a == 100 && (b & 0xc0) == 64)
                || (a == 198 && (b & 0xfe) == 18))
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            // Addresses that carry an IPv4 address are judged by it.
            let embedded = match segments {
                [0x64, 0xff9b, 0, 0, 0, 0, high, low] | [0, 0, 0, 0, 0, 0, high, low] => Some(
                    std::net::Ipv4Addr::from((u32::from(high) << 16) | u32::from(low)),
                ),
                [0x2002, high, low, ..] => Some(std::net::Ipv4Addr::from(
                    (u32::from(high) << 16) | u32::from(low),
                )),
                _ => None,
            };
            if let Some(v4) = embedded {
                return public_unmapped(IpAddr::V4(v4));
            }
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] & 0xffc0) == 0xfec0)
        }
    }
}

/// The relay to propose: a readable Let's Encrypt certificate whose name
/// resolves to one of this device's public addresses, on DEFAULT_PORT.
pub async fn suggest(own: &[IpAddr]) -> Option<Suggestion> {
    let own: Vec<IpAddr> = own.iter().copied().filter(|ip| public(*ip)).collect();
    if own.is_empty() {
        return None;
    }
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(cert_dirs())
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .collect();
    dirs.sort();
    for dir in dirs {
        let (cert, key) = (dir.join("fullchain.pem"), dir.join("privkey.pem"));
        if std::fs::File::open(&key).is_err() {
            continue;
        }
        for name in certificate_names(&cert) {
            let resolved = tokio::time::timeout(
                Duration::from_secs(2),
                tokio::net::lookup_host((name.as_str(), DEFAULT_PORT)),
            )
            .await;
            if let Ok(Ok(addrs)) = resolved
                && addrs.map(|addr| addr.ip()).any(|ip| own.contains(&ip))
            {
                return Some(Suggestion {
                    url: format!("https://{name}:{DEFAULT_PORT}/"),
                    cert,
                    key,
                });
            }
        }
    }
    None
}

/// A readable Let's Encrypt certificate that covers `host`.
pub fn certificate_for(host: &str) -> Option<(PathBuf, PathBuf)> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let mut candidates: Vec<(PathBuf, PathBuf)> = std::fs::read_dir(cert_dirs())
        .ok()?
        .flatten()
        .map(|entry| {
            (
                entry.path().join("fullchain.pem"),
                entry.path().join("privkey.pem"),
            )
        })
        .filter(|(_, key)| std::fs::File::open(key).is_ok())
        .collect();
    candidates.sort();
    // A certificate naming the host itself wins over a wildcard covering it.
    let exact = candidates
        .iter()
        .find(|(cert, _)| certificate_names(cert).contains(&host));
    exact
        .or_else(|| {
            candidates.iter().find(|(cert, _)| {
                certificate_patterns(cert)
                    .iter()
                    .any(|pattern| covers(pattern, &host))
            })
        })
        .cloned()
}

/// Whether a certificate name covers `host`: equal, or `*.zone` for exactly one
/// more label, as TLS clients check it.
pub fn covers(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(zone) => host
            .strip_suffix(zone)
            .and_then(|label| label.strip_suffix('.'))
            .is_some_and(|label| !label.is_empty() && !label.contains('.')),
        None => pattern == host,
    }
}

/// A DNS host name: lowercase labels of letters, digits and inner hyphens.
pub fn valid_host(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    host.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// Zones this device holds a readable wildcard certificate for, so each
/// device can get its own name, like `laptop.<zone>`.
pub fn wildcard_zones() -> Vec<String> {
    let mut zones: Vec<String> = std::fs::read_dir(cert_dirs())
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| std::fs::File::open(entry.path().join("privkey.pem")).is_ok())
        .flat_map(|entry| certificate_patterns(&entry.path().join("fullchain.pem")))
        .filter_map(|pattern| pattern.strip_prefix("*.").map(str::to_owned))
        .collect();
    zones.sort();
    zones.dedup();
    zones
}

/// Builds the configuration for `url` with a certificate that covers its host.
pub fn config_for(url: &str, cert: &Path, key: &Path) -> Result<HostConfig> {
    let parsed: iroh::RelayUrl = url.parse().context("invalid relay URL")?;
    ensure!(parsed.scheme() == "https", "relay must use HTTPS");
    let host = parsed
        .host_str()
        .context("relay URL needs a host name")?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    ensure!(
        certificate_patterns(cert)
            .iter()
            .any(|pattern| covers(pattern, &host)),
        "certificate does not cover {host}"
    );
    let port = parsed.port().unwrap_or(443);
    Ok(HostConfig {
        url: parsed.to_string(),
        listen: SocketAddr::from(([0, 0, 0, 0], port)),
        cert: cert.to_path_buf(),
        key: key.to_path_buf(),
    })
}

/// What a running relay was started from: a change means restart it. The
/// paired devices are part of it, so a revoked device loses its session.
type HostSignature = (
    HostConfig,
    Option<SystemTime>,
    Option<SystemTime>,
    Option<PathBuf>,
    Vec<String>,
);

fn signature(config: &HostConfig, store: &Store) -> HostSignature {
    let modified = |path: &Path| {
        std::fs::metadata(path)
            .and_then(|meta| meta.modified())
            .ok()
    };
    let mut peers: Vec<String> = store
        .peers()
        .unwrap_or_default()
        .into_iter()
        .map(|peer| peer.id)
        .collect();
    peers.sort();
    (
        config.clone(),
        modified(&config.cert),
        modified(&config.key),
        std::fs::canonicalize(&config.cert).ok(),
        peers,
    )
}

/// Runs inside a device's server for as long as it serves.
pub async fn host_loop(store: Store) {
    let root = store.root().to_path_buf();
    let mut running: Option<(RelayServer, _)> = None;
    loop {
        let wanted = load(&root);
        let current = wanted.as_ref().map(|config| signature(config, &store));
        if running.as_ref().map(|(_, sig)| sig) != current.as_ref() {
            if let Some((server, _)) = running.take() {
                let _ = server.shutdown().await;
            }
            let status = match (&wanted, current) {
                (Some(config), Some(sig)) => {
                    match RelayServer::start_hosted(
                        config.listen,
                        store.clone(),
                        &config.cert,
                        &config.key,
                    )
                    .await
                    {
                        Ok(server) => {
                            running = Some((server, sig));
                            HostStatus {
                                running: true,
                                error: None,
                            }
                        }
                        Err(error) => {
                            let message = format!("{error:#}");
                            let reason = if message.contains("TLS")
                                || message.contains("certificate")
                                || message.contains("key")
                            {
                                "certificate"
                            } else if message.contains("ddress") || message.contains("bind") {
                                "port"
                            } else {
                                "failed"
                            };
                            HostStatus {
                                running: false,
                                error: Some(reason.to_owned()),
                            }
                        }
                    }
                }
                _ => HostStatus::default(),
            };
            set_status(&root, &status);
        }
        tokio::time::sleep(CHECK).await;
    }
}
