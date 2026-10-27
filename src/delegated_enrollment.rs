//! Explicit, reloadable host consent for issuing through another bridge.
//! No route, executable, scope or TTL is taken from a network request.
use crate::{
    Store,
    enrollment::{Enrollment, EnrollmentAuthority, LocalT3Authority},
};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

#[derive(Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompositeConfig {
    pub version: u32,
    #[serde(default)]
    pub local: Option<LocalT3Authority>,
    /// Environment UUID -> pinned issuer peer. Its address comes from paired state.
    #[serde(default)]
    pub remote: BTreeMap<String, String>,
    /// Upstream peer -> environment UUID -> downstream endpoint IDs.
    #[serde(default)]
    pub delegates: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}
impl CompositeConfig {
    fn validate(&self) -> Result<()> {
        ensure!(self.version == 1, "unsupported authority policy");
        ensure!(
            self.remote.len() <= 128 && self.delegates.len() <= 128,
            "authority policy too large"
        );
        if let Some(local) = &self.local {
            local.validate()?;
        }
        for (environment, peer) in &self.remote {
            valid_environment(environment)?;
            peer.parse::<iroh::EndpointId>()?;
            ensure!(
                !self
                    .local
                    .as_ref()
                    .is_some_and(|l| l.environments.contains_key(environment)),
                "ambiguous issuer"
            );
        }
        for (peer, environments) in &self.delegates {
            peer.parse::<iroh::EndpointId>()?;
            ensure!(environments.len() <= 128, "authority policy too large");
            for (environment, clients) in environments {
                valid_environment(environment)?;
                ensure!(clients.len() <= 128, "authority policy too large");
                for client in clients {
                    client.parse::<iroh::EndpointId>()?;
                }
                let local = self
                    .local
                    .as_ref()
                    .context("delegation needs a local issuer")?;
                ensure!(
                    local.ttl_seconds <= 120 && local.environments.contains_key(environment),
                    "delegation needs bounded local issuer"
                );
            }
        }
        Ok(())
    }
    fn allows(&self, upstream: &str, environment: &str, client: &str) -> bool {
        self.delegates
            .get(upstream)
            .and_then(|e| e.get(environment))
            .is_some_and(|clients| clients.iter().any(|id| id == client))
    }
}
fn valid_environment(id: &str) -> Result<()> {
    ensure!(
        id.len() == 36
            && id
                .bytes()
                .enumerate()
                .all(|(i, c)| if [8, 13, 18, 23].contains(&i) {
                    c == b'-'
                } else {
                    c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
                }),
        "invalid environment identity"
    );
    Ok(())
}

/// Remote issuer pinned to a paired endpoint, reached through this running bridge.
/// The caller still owns downstream authorization (CompositeAuthority reloads it).
pub struct RemoteT3Authority {
    pub store: Store,
    pub peer: String,
}
impl EnrollmentAuthority for RemoteT3Authority {
    fn issue<'a>(
        &'a self,
        client: &'a str,
        environment: &'a str,
        now: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Enrollment>> + Send + 'a>> {
        Box::pin(async move {
            let enrollment = crate::network::delegated_enroll_through_server(
                &self.store,
                &self.peer,
                client,
                environment,
            )
            .await?;
            enrollment.validate(client, environment, now)?;
            ensure!(
                enrollment.expires_at <= crate::network::enrollment_now()?.saturating_add(120_000),
                "delegated session exceeds limit"
            );
            Ok(enrollment)
        })
    }
}

/// Policy is read before and after I/O. Withdrawing consent needs no restart.
/// Four in-flight requests and sixteen attempts/minute per configured upstream;
/// rejected strangers cannot allocate rate entries. Limits use monotonic time.
pub struct CompositeAuthority {
    store: Store,
    path: PathBuf,
    concurrent: Semaphore,
    attempts: Mutex<BTreeMap<String, (Instant, u32)>>,
}
impl CompositeAuthority {
    pub fn open(store: Store, path: &Path) -> Result<Self> {
        ensure!(path.is_absolute(), "absolute authority policy required");
        let config: CompositeConfig = crate::read_document(path)?;
        config.validate()?;
        Ok(Self {
            store,
            path: path.into(),
            concurrent: Semaphore::new(4),
            attempts: Mutex::new(BTreeMap::new()),
        })
    }
    fn config(&self) -> Result<CompositeConfig> {
        let config: CompositeConfig = crate::read_document(&self.path)?;
        config.validate()?;
        Ok(config)
    }
    fn rate(&self, upstream: &str, config: &CompositeConfig) -> Result<()> {
        let mut attempts = self
            .attempts
            .lock()
            .map_err(|_| anyhow::anyhow!("issuer unavailable"))?;
        attempts.retain(|peer, _| config.delegates.contains_key(peer));
        let entry = attempts
            .entry(upstream.into())
            .or_insert((Instant::now(), 0));
        if entry.0.elapsed() >= Duration::from_secs(60) {
            *entry = (Instant::now(), 0);
        }
        ensure!(entry.1 < 16, "issuer rate exceeded");
        entry.1 += 1;
        Ok(())
    }
}
/// Retain legacy local-only CLI configuration; versioned policies opt into delegation.
pub fn load_authority(
    store: Store,
    path: &Path,
) -> Result<std::sync::Arc<dyn EnrollmentAuthority>> {
    let value: serde_json::Value = crate::read_document(path)?;
    if value.get("version").is_some() {
        Ok(std::sync::Arc::new(CompositeAuthority::open(store, path)?))
    } else {
        let local: LocalT3Authority = serde_json::from_value(value)?;
        local.validate()?;
        Ok(std::sync::Arc::new(local))
    }
}
impl EnrollmentAuthority for CompositeAuthority {
    fn issue<'a>(
        &'a self,
        client: &'a str,
        environment: &'a str,
        now: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Enrollment>> + Send + 'a>> {
        Box::pin(async move {
            let _permit = self.concurrent.try_acquire().context("issuer busy")?;
            let config = self.config()?;
            if let Some(peer) = config.remote.get(environment) {
                let enrollment = RemoteT3Authority {
                    store: self.store.clone(),
                    peer: peer.clone(),
                }
                .issue(client, environment, now)
                .await?;
                ensure!(self.config()? == config, "issuer withdrawn");
                enrollment.validate(client, environment, now)?;
                ensure!(
                    enrollment.expires_at
                        <= crate::network::enrollment_now()?.saturating_add(120_000),
                    "delegated session exceeds limit"
                );
                Ok(enrollment)
            } else {
                let local = config.local.as_ref().context("issuer unavailable")?;
                let enrollment = local.issue(client, environment, now).await?;
                // Any local configuration change invalidates an in-flight receipt.
                ensure!(self.config()? == config, "issuer withdrawn");
                Ok(enrollment)
            }
        })
    }
    fn issue_delegated<'a>(
        &'a self,
        upstream: &'a str,
        client: &'a str,
        environment: &'a str,
        now: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Enrollment>> + Send + 'a>> {
        Box::pin(async move {
            let config = self.config()?;
            ensure!(
                config.allows(upstream, environment, client)
                    && self.store.authorized(upstream, "t3")?,
                "delegation refused"
            );
            self.rate(upstream, &config)?;
            let _permit = self.concurrent.try_acquire().context("issuer busy")?;
            // Encode both identities in T3's own subject, retaining local receipt checks.
            let subject = format!("{upstream}:{client}");
            let mut enrollment = config
                .local
                .as_ref()
                .context("issuer unavailable")?
                .issue(&subject, environment, now)
                .await?;
            ensure!(
                self.config()? == config && self.store.authorized(upstream, "t3")?,
                "delegation withdrawn"
            );
            enrollment.client_id = client.into();
            enrollment.validate(client, environment, now)?;
            ensure!(
                enrollment.expires_at <= crate::network::enrollment_now()?.saturating_add(120_000),
                "delegated session exceeds limit"
            );
            Ok(enrollment)
        })
    }
}
