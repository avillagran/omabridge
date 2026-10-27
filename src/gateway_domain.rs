//! Administrator-selected DNS zone and durable hostname ownership.
//! Names survive withdrawal/revocation: a cached URL must never silently become
//! another peer's service. This file contains no credentials and grants no access.
use crate::{gateway::Gateway, hosting, read_document, write_document};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

const CONFIG: &str = "gateway-domain.json";
const MAX_CLAIMS: usize = 1024;
pub type Result<T> = std::result::Result<T, &'static str>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    peer: String,
    service: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub domain: Option<String>,
    pub port: Option<u16>,
    claims: BTreeMap<String, Owner>,
}

/// Serialize all management writes, including ordinary gateway-set. Refuse
/// contention rather than block an async worker while another writer awaits DNS.
pub fn lock(root: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join("gateway-config.lock"))
        .map_err(|_| "local_error")?;
    fs2::FileExt::try_lock_exclusive(&file).map_err(|_| "omabridge_gateway_busy")?;
    Ok(file)
}

pub fn valid_domain(domain: &str) -> bool {
    hosting::valid_host(domain)
        && domain.len() <= 189
        && domain.parse::<std::net::IpAddr>().is_err()
        && domain != "localhost"
        && !domain.ends_with(".localhost")
}

pub fn child_of(host: &str, domain: &str) -> bool {
    host.strip_suffix(domain)
        .and_then(|prefix| prefix.strip_suffix('.'))
        .is_some_and(|label| !label.is_empty() && !label.contains('.'))
}

impl Config {
    pub fn load(root: &Path) -> Result<Self> {
        let path = root.join(CONFIG);
        match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Ok(meta) if meta.file_type().is_file() => {}
            _ => return Err("omabridge_gateway_domain_invalid"),
        }
        let config: Self = read_document(&path).map_err(|_| "omabridge_gateway_domain_invalid")?;
        if config.claims.len() > MAX_CLAIMS
            || config.domain.as_ref().is_some_and(|d| !valid_domain(d))
            || config.domain.is_some() != config.port.is_some()
            || config.port.is_some_and(|p| p != 443 && p < 1024)
            || config.claims.iter().any(|(host, owner)| {
                !hosting::valid_host(host)
                    || owner.peer.len() != 64
                    || !owner.peer.bytes().all(|b| b.is_ascii_hexdigit())
                    || !crate::gateway::PUBLIC_SERVICES.contains(&owner.service.as_str())
            })
        {
            return Err("omabridge_gateway_domain_invalid");
        }
        Ok(config)
    }

    pub fn save(&self, root: &Path) -> Result<()> {
        write_document(&root.join(CONFIG), self, true).map_err(|_| "local_error")
    }

    pub fn contains(&self, host: &str) -> bool {
        self.domain
            .as_ref()
            .is_some_and(|domain| child_of(host, domain))
    }

    /// Check historical ownership even after a zone has been changed/disabled.
    pub fn check(&self, host: &str, peer: &str, service: &str) -> Result<()> {
        if self
            .claims
            .get(host)
            .is_some_and(|o| o.peer != peer || o.service != service)
        {
            return Err("omabridge_gateway_name_reserved");
        }
        Ok(())
    }

    pub fn reserve(&mut self, host: &str, peer: &str, service: &str) -> Result<()> {
        self.check(host, peer, service)?;
        if !self.claims.contains_key(host) && self.claims.len() >= MAX_CLAIMS {
            return Err("omabridge_gateway_names_full");
        }
        self.claims.insert(
            host.into(),
            Owner {
                peer: peer.into(),
                service: service.into(),
            },
        );
        Ok(())
    }

    pub fn import(&mut self, gateways: &[Gateway]) -> Result<()> {
        for g in gateways {
            if self.contains(&g.host) {
                self.reserve(&g.host, &g.peer, &g.service)?;
            }
        }
        Ok(())
    }

    pub fn hostname(&self, peer: &str, service: &str, name: &str) -> Result<String> {
        let domain = self
            .domain
            .as_ref()
            .ok_or("omabridge_gateway_domain_invalid")?;
        if let Some((host, _)) = self
            .claims
            .iter()
            .find(|(host, o)| self.contains(host) && o.peer == peer && o.service == service)
        {
            return Ok(host.clone());
        }
        let slug: String = name
            .to_ascii_lowercase()
            .chars()
            .map(|c| {
                if c.is_ascii_lowercase() || c.is_ascii_digit() {
                    c
                } else {
                    '-'
                }
            })
            .take(48)
            .collect();
        let slug = slug.trim_matches('-');
        let slug = if slug.is_empty() { "device" } else { slug };
        let host = format!("{slug}.{domain}");
        if self.check(&host, peer, service).is_ok() {
            return Ok(host);
        }
        let suffix = peer.get(..12).ok_or("invalid_command")?;
        let host = format!("{slug}-{suffix}.{domain}");
        self.check(&host, peer, service)?;
        Ok(host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names_are_stable_and_never_change_owner() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let mut c = Config {
            domain: Some("hosts.example.com".into()),
            port: Some(443),
            ..Default::default()
        };
        let host = c.hostname(&a, "t3", "Node").unwrap();
        assert_eq!(host, "node.hosts.example.com");
        c.reserve(&host, &a, "t3").unwrap();
        assert_eq!(c.hostname(&a, "t3", "renamed").unwrap(), host);
        assert_eq!(
            c.hostname(&b, "t3", "Node").unwrap(),
            "node-bbbbbbbbbbbb.hosts.example.com"
        );
        assert_eq!(
            c.reserve(&host, &b, "t3"),
            Err("omabridge_gateway_name_reserved")
        );
        assert!(c.reserve(&host, &a, "mcp").is_err());
        c.domain = None;
        c.port = None;
        assert!(c.reserve(&host, &b, "t3").is_err());
        assert!(!child_of("a.b.hosts.example.com", "hosts.example.com"));
        assert!(!child_of("evilhosts.example.com", "hosts.example.com"));
        assert!(!valid_domain("127.0.0.1"));
        assert!(!valid_domain("example.localhost"));
    }
    #[test]
    fn storage_fails_closed_and_writers_are_exclusive() {
        let root = tempfile::tempdir().unwrap();
        let guard = lock(root.path()).unwrap();
        assert!(lock(root.path()).is_err());
        drop(guard);
        assert!(lock(root.path()).is_ok());
        std::fs::write(root.path().join(CONFIG), "{").unwrap();
        assert!(Config::load(root.path()).is_err());
    }
}
