//! Public service routes announced by already paired gateway devices.
//! Routes do not grant access. The owning device's current public consent is
//! checked again when exporting them, and old announcements expire.
use crate::{Store, gateway};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

pub const ROUTE_TTL: u64 = 600;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRoute {
    pub service: String,
    pub url: String,
}

impl ServiceRoute {
    fn valid(&self) -> bool {
        if !gateway::PUBLIC_SERVICES.contains(&self.service.as_str()) || self.url.len() > 2048 {
            return false;
        }
        let Ok(url) = self.url.parse::<iroh::RelayUrl>() else {
            return false;
        };
        url.scheme() == "https"
            && crate::hosting::public_host(&url)
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/"
            && url.port() != Some(0)
    }
}

/// Never reveal another owner's gateways to the peer receiving this hello.
pub(crate) fn for_peer(store: &Store, peer: &str) -> Vec<ServiceRoute> {
    gateway::load(store.root())
        .into_iter()
        .filter(|gateway| gateway.peer == peer)
        .map(|gateway| ServiceRoute {
            service: gateway.service.clone(),
            url: gateway.url(),
        })
        .filter(ServiceRoute::valid)
        .take(gateway::MAX_GATEWAYS)
        .collect()
}

impl Store {
    pub(crate) fn refresh_routes(&self, id: &str, routes: &[ServiceRoute], now: u64) -> Result<()> {
        ensure!(
            routes.len() <= gateway::MAX_GATEWAYS && routes.iter().all(ServiceRoute::valid),
            "invalid gateway routes"
        );
        self.update(|state| {
            let peer = state.peers.get_mut(id).context("unknown peer")?;
            peer.gateway_routes = routes
                .iter()
                .filter(|route| {
                    peer.services.contains(&route.service) && peer.public.contains(&route.service)
                })
                .cloned()
                .collect();
            peer.routes_updated = now;
            Ok(())
        })
    }

    /// Read-only discovery for local consumers. No network calls or secrets.
    pub fn service_routes(&self, now: u64) -> Result<Vec<ServiceRoute>> {
        let mut routes: Vec<_> = self
            .peers()?
            .into_iter()
            .filter(|peer| peer.routes_updated <= now && now - peer.routes_updated < ROUTE_TTL)
            .flat_map(|peer| {
                peer.gateway_routes.into_iter().filter(move |route| {
                    peer.services.contains(&route.service)
                        && peer.public.contains(&route.service)
                        && route.valid()
                })
            })
            .collect();
        routes.sort();
        routes.dedup();
        routes.truncate(64);
        Ok(routes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn routes_require_current_consent_expire_and_cannot_cross_owners() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let owner = Store::open(&dir.path().join("owner"), "owner")?;
        let gateway = Store::open(&dir.path().join("gateway"), "gateway")?;
        let id = gateway.id()?;
        let route = ServiceRoute {
            service: "t3".into(),
            url: "https://desktop.example.net:2345/".into(),
        };
        assert!(
            owner
                .refresh_routes(&id, std::slice::from_ref(&route), 100)
                .is_err()
        );
        let token = owner.create_invite(&["t3".into()], Duration::from_secs(60), 100)?;
        owner.claim(&token, &id, "gateway", 100)?;
        owner.approve(&id, 100)?;
        owner.refresh_routes(&id, std::slice::from_ref(&route), 100)?;
        assert!(
            owner.service_routes(100)?.is_empty(),
            "pairing alone grants no public consent"
        );
        owner.set_services(&id, &["t3".into()], &["t3".into()])?;
        owner.refresh_routes(&id, std::slice::from_ref(&route), 100)?;
        assert_eq!(owner.service_routes(100)?, vec![route.clone()]);
        assert!(
            owner.service_routes(99)?.is_empty(),
            "future timestamp is not fresh"
        );
        assert!(owner.service_routes(100 + ROUTE_TTL)?.is_empty());
        for url in [
            "http://example.net/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://user:pass@example.net/",
            "https://example.net/path",
            "https://example.net/?token=x",
            "https://example.net/#x",
        ] {
            let invalid = ServiceRoute {
                url: url.into(),
                ..route.clone()
            };
            assert!(owner.refresh_routes(&id, &[invalid], 101).is_err());
        }
        assert_eq!(
            owner.service_routes(101)?,
            vec![route.clone()],
            "malformed announcement must not overwrite accepted routes"
        );
        owner.refresh_routes(&id, &[], 102)?;
        assert!(
            owner.service_routes(102)?.is_empty(),
            "withdrawn route disappears"
        );
        owner.refresh_routes(&id, std::slice::from_ref(&route), 103)?;
        owner.set_services(&id, &["t3".into()], &[])?;
        assert!(
            owner.service_routes(103)?.is_empty(),
            "local withdrawal is immediate"
        );
        owner.set_services(&id, &["t3".into()], &["t3".into()])?;
        assert!(
            owner.service_routes(103)?.is_empty(),
            "renewed consent needs a fresh announcement"
        );
        owner.revoke(&id)?;
        assert!(owner.service_routes(103)?.is_empty());
        crate::gateway::save(
            gateway.root(),
            &[
                crate::gateway::Gateway {
                    host: "desktop.example.net".into(),
                    port: 2345,
                    peer: owner.id()?,
                    service: "t3".into(),
                },
                crate::gateway::Gateway {
                    host: "other.example.net".into(),
                    port: 2345,
                    peer: "other".into(),
                    service: "t3".into(),
                },
            ],
        )?;
        assert_eq!(for_peer(&gateway, &owner.id()?), vec![route]);
        Ok(())
    }
}
