//! Management facade shared by native desktop frontends. The Store owns all policy and secrets.
use crate::{
    Client, DeviceSnapshot, Invitation, NetOptions, PairDecision, Store, read_document, unix_time,
    valid_service, write_document,
};
use anyhow::{Context, Result, anyhow, ensure};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Debug)]
pub struct InviteReceipt {
    pub path: PathBuf,
    pub expires: u64,
    pub service: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairStatus {
    Pending,
    Approved,
}

/// Public result of using an invitation; never contains the bearer token.
#[derive(Clone, Debug)]
pub struct PairOutcome {
    pub peer_id: String,
    pub peer_name: String,
    pub status: PairStatus,
    /// Services granted to this device on the peer (empty while pending).
    pub services: Vec<String>,
    /// True when the invitation file was deleted after approval.
    pub invite_removed: bool,
}

/// A paired peer that granted this device at least one service.
#[derive(Clone, Debug)]
pub struct RemoteRoute {
    pub peer_id: String,
    pub peer_name: String,
    pub services: Vec<String>,
    pub has_address: bool,
}

#[derive(Clone)]
pub struct Desktop {
    store: Store,
    options: NetOptions,
}

impl Desktop {
    /// Same network defaults as the CLI: any local address and public relays.
    pub fn new(store: Store) -> Self {
        Self::with_options(
            store,
            NetOptions {
                compress_t3: false,
                bind: "0.0.0.0:0".parse().expect("literal socket"),
                relay: Default::default(),
            },
        )
    }

    pub fn with_options(store: Store, options: NetOptions) -> Self {
        Self { store, options }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn refresh(&self) -> Result<DeviceSnapshot> {
        self.store.snapshot()
    }

    pub fn published_services(&self) -> Result<Vec<String>> {
        self.store.active_endpoint().map(|(_, services)| services)
    }

    pub fn issue_invitation(&self, service: &str, ttl: Duration) -> Result<InviteReceipt> {
        ensure!(valid_service(service), "invalid service name");
        let (address, published) = self.store.active_endpoint()?;
        ensure!(
            published.iter().any(|candidate| candidate == service),
            "service not currently published"
        );
        let now = unix_time()?;
        let token = self.store.create_invite(&[service.to_owned()], ttl, now)?;
        let expires = now
            .checked_add(ttl.as_secs())
            .ok_or_else(|| anyhow!("expiry overflow"))?;
        let invite = Invitation {
            version: 1,
            address,
            token,
            name: self.store.name()?,
            expires,
            manage: false,
        };
        let path = self.store.root.join(format!(
            "invite-{:016x}.private.json",
            rand::random::<u64>()
        ));
        write_document(&path, &invite, false)?;
        Ok(InviteReceipt {
            path,
            expires,
            service: service.to_owned(),
        })
    }

    pub fn approve(&self, peer: &str, invitation_id: &str) -> Result<DeviceSnapshot> {
        self.store
            .approve_selected(peer, Some(invitation_id), unix_time()?)?;
        self.refresh()
    }

    pub fn revoke(&self, peer: &str) -> Result<DeviceSnapshot> {
        self.store.revoke(peer)?;
        self.refresh()
    }

    /// Use an invitation file on this (receiving) device, exactly like `omabridge pair`.
    /// The file is deleted only when `discard_when_approved` is set and the grant is
    /// approved; a pending invitation must be reused after the host approves it.
    pub async fn pair(
        &self,
        invite_path: &Path,
        discard_when_approved: bool,
    ) -> Result<PairOutcome> {
        // Never surface parser detail: it could quote invitation contents.
        let invite: Invitation = read_document(invite_path)
            .map_err(|_| anyhow!("invitation file unreadable, invalid or not private (0600)"))?;
        let client = Client::new(self.store.clone(), self.options.clone()).await?;
        let name = self.store.name()?;
        let result = client.pair(&invite, &name, unix_time()?).await;
        client.close().await;
        let (status, services) = match result? {
            PairDecision::Pending => (PairStatus::Pending, Vec::new()),
            PairDecision::Approved { services, .. } => (PairStatus::Approved, services),
        };
        let invite_removed = status == PairStatus::Approved
            && discard_when_approved
            && std::fs::remove_file(invite_path).is_ok();
        Ok(PairOutcome {
            peer_id: invite.address.id.to_string(),
            peer_name: invite.name,
            status,
            services,
            invite_removed,
        })
    }

    /// Peers whose grants let this device reach their services.
    pub fn remote_routes(&self) -> Result<Vec<RemoteRoute>> {
        Ok(self
            .store
            .peers()?
            .into_iter()
            .filter(|peer| !peer.remote_services.is_empty())
            .map(|peer| RemoteRoute {
                peer_id: peer.id,
                peer_name: peer.name,
                services: peer.remote_services.into_iter().collect(),
                has_address: peer.address.is_some(),
            })
            .collect())
    }

    /// Open and immediately close one authenticated stream, like `forward`'s setup check.
    pub async fn probe(&self, peer: &str, service: &str) -> Result<Duration> {
        ensure!(valid_service(service), "invalid service name");
        let trusted = self
            .store
            .peers()?
            .into_iter()
            .find(|candidate| candidate.id == peer)
            .context("peer not paired")?;
        ensure!(
            trusted.remote_services.contains(service),
            "service not granted by peer"
        );
        let address = trusted.address.context("no saved address for peer")?;
        let client = Client::new(self.store.clone(), self.options.clone()).await?;
        let started = Instant::now();
        // Dropping the pipe closes the probe stream; no payload is sent.
        let result = client.open(&address, service).await.map(drop);
        let elapsed = started.elapsed();
        client.close().await;
        result?;
        Ok(elapsed)
    }
}
