//! Public service routes announced by already paired gateway devices.
//! Routes do not grant access. The owning device's current public consent is
//! checked again when exporting them, and old announcements expire.
use crate::{Peer, Store, gateway};
use anyhow::{Result, ensure};
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

/// Routes to this device's own T3, for a bridge it consented to. Other peers
/// learn nothing: a route is a hint, but still names a host.
pub(crate) fn own_for_peer(store: &Store, peer: &crate::Peer) -> Vec<ServiceRoute> {
    if !peer.bridge_consent || !peer.services.contains("t3") {
        return Vec::new();
    }
    let now = crate::unix_time().unwrap_or(0);
    let mut routes = store.service_routes(now).unwrap_or_default();
    routes.retain(|route| route.service == "t3");
    routes.truncate(gateway::MAX_GATEWAYS);
    routes
}

/// The same routes are announced over and over. Their age is written again only after this
/// long, well inside `ROUTE_TTL` even for a device that announces every `SYNC_INTERVAL`, so a
/// repeated `Hello` costs no durable write and live routes do not expire.
const ROUTE_REFRESH: u64 = ROUTE_TTL / 4;

pub(crate) fn check_host_routes(routes: &[ServiceRoute]) -> Result<()> {
    ensure!(
        routes.len() <= gateway::MAX_GATEWAYS
            && routes
                .iter()
                .all(|route| route.service == "t3" && route.valid()),
        "invalid host routes"
    );
    Ok(())
}

pub(crate) fn check_gateway_routes(routes: &[ServiceRoute]) -> Result<()> {
    ensure!(
        routes.len() <= gateway::MAX_GATEWAYS && routes.iter().all(ServiceRoute::valid),
        "invalid gateway routes"
    );
    Ok(())
}

/// A host's announcement to its bridge. Only ever writes what the host reported; this
/// device's own consent bit is out of reach here.
pub(crate) fn apply_host_routes(peer: &mut Peer, consent: bool, routes: &[ServiceRoute]) {
    peer.remote_bridge_consent = consent;
    peer.remote_routes = if consent { routes.to_vec() } else { Vec::new() };
}

pub(crate) fn apply_gateway_routes(peer: &mut Peer, routes: &[ServiceRoute], now: u64) {
    let routes: Vec<_> = routes
        .iter()
        .filter(|route| {
            peer.services.contains(&route.service) && peer.public.contains(&route.service)
        })
        .cloned()
        .collect();
    let aged = peer.routes_updated > now || now - peer.routes_updated >= ROUTE_REFRESH;
    if routes != peer.gateway_routes || (aged && !routes.is_empty()) {
        peer.gateway_routes = routes;
        peer.routes_updated = now;
    }
}

impl Store {
    #[cfg(test)]
    pub(crate) fn refresh_host(
        &self,
        id: &str,
        consent: bool,
        routes: &[ServiceRoute],
    ) -> Result<()> {
        check_host_routes(routes)?;
        self.update_peer(id, |peer| apply_host_routes(peer, consent, routes))
    }

    #[cfg(test)]
    pub(crate) fn refresh_routes(&self, id: &str, routes: &[ServiceRoute], now: u64) -> Result<()> {
        check_gateway_routes(routes)?;
        self.update_peer(id, |peer| apply_gateway_routes(peer, routes, now))
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
    use crate::Announcement;
    use anyhow::Context;
    use iroh::{EndpointAddr, TransportAddr};
    use std::{os::unix::fs::MetadataExt, time::Duration};

    const PUBLIC_ROUTE: &str = "https://desktop.example.net:2345/";

    fn route(url: &str) -> ServiceRoute {
        ServiceRoute {
            service: "t3".into(),
            url: url.into(),
        }
    }

    /// `owner` paired with a device that publishes t3 through it.
    fn paired(dir: &std::path::Path) -> Result<(Store, String)> {
        let owner = Store::open(&dir.join("owner"), "owner")?;
        let gateway = Store::open(&dir.join("gateway"), "gateway")?;
        let id = gateway.id()?;
        let token = owner.create_invite(&["t3".into()], Duration::from_secs(60), 100)?;
        owner.claim(&token, &id, "gateway", 100)?;
        owner.approve(&id, 100)?;
        owner.set_services(&id, &["t3".into()], &["t3".into()])?;
        Ok((owner, id))
    }

    /// `state.json` is replaced by rename, so any durable write gives it a new inode.
    fn written(store: &Store) -> Result<u64> {
        Ok(std::fs::metadata(store.root().join("state.json"))?.ino())
    }

    fn snapshot(store: &Store, id: &str) -> Result<serde_json::Value> {
        let peers = store.peers()?;
        let peer = peers.iter().find(|peer| peer.id == id);
        Ok(serde_json::to_value(peer.context("unknown peer")?)?)
    }

    #[test]
    fn a_rejected_announcement_changes_nothing() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (owner, id) = paired(dir.path())?;
        let address = EndpointAddr {
            id: id.parse()?,
            addrs: [TransportAddr::Ip("203.0.113.7:4433".parse()?)].into(),
        };
        let good = [route(PUBLIC_ROUTE)];
        let bad = [route("http://desktop.example.net/")];
        let services = vec!["t3".to_string()];
        let invalid = vec!["not a service!".to_string()];
        let valid = Announcement {
            name: "renamed",
            address: Some(&address),
            managed: true,
            grants: Some((&services, &services)),
            routes: Some(&good),
            bridge_consent: true,
            host_routes: &good,
        };
        let before = (snapshot(&owner, &id)?, written(&owner)?);
        for rejected in [
            Announcement { name: "", ..valid },
            Announcement {
                grants: Some((&invalid, &services)),
                ..valid
            },
            Announcement {
                routes: Some(&bad),
                ..valid
            },
            Announcement {
                host_routes: &bad,
                ..valid
            },
        ] {
            assert!(owner.refresh_announcement(&id, &rejected, 200).is_err());
            assert_eq!((snapshot(&owner, &id)?, written(&owner)?), before);
        }
        owner.refresh_announcement(&id, &valid, 200)?;
        let applied = snapshot(&owner, &id)?;
        assert_eq!(applied["name"], "renamed");
        assert_eq!(applied["managed"], true);
        assert_eq!(owner.service_routes(200)?, good);
        Ok(())
    }

    #[test]
    fn a_repeated_announcement_writes_nothing_and_keeps_its_routes_alive() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let (owner, id) = paired(dir.path())?;
        let routes = [route(PUBLIC_ROUTE)];
        let hello = Announcement {
            name: "gateway",
            address: None,
            managed: false,
            grants: None,
            routes: Some(&routes),
            bridge_consent: false,
            host_routes: &[],
        };
        owner.refresh_announcement(&id, &hello, 1000)?;
        let first = written(&owner)?;

        // A burst, as a phone's network changes make: nothing new, nothing written.
        for second in 1..ROUTE_REFRESH {
            owner.refresh_announcement(&id, &hello, 1000 + second)?;
        }
        assert_eq!(written(&owner)?, first);

        // A real change is written at once.
        let moved = [route("https://other.example.net:2345/")];
        let changed = Announcement {
            routes: Some(&moved),
            ..hello
        };
        owner.refresh_announcement(&id, &changed, 1000 + ROUTE_REFRESH - 1)?;
        assert_ne!(written(&owner)?, first);

        // A device announcing at its usual pace never lets its routes lapse.
        let mut now = 2000;
        owner.refresh_announcement(&id, &hello, now)?;
        for _ in 0..4 {
            now += crate::SYNC_INTERVAL.as_secs();
            assert_eq!(owner.service_routes(now)?, routes, "live at {now}");
            owner.refresh_announcement(&id, &hello, now)?;
        }

        // Silence still expires them, from the last time their age was written.
        let settled = now;
        for second in 1..ROUTE_REFRESH {
            owner.refresh_announcement(&id, &hello, settled + second)?;
        }
        assert!(owner.service_routes(settled + ROUTE_TTL)?.is_empty());
        Ok(())
    }

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

    #[test]
    fn host_routes_need_consent_https_and_never_touch_local_consent() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let bridge = Store::open(&dir.path().join("bridge"), "bridge")?;
        let host = Store::open(&dir.path().join("host"), "host")?;
        let id = host.id()?;
        let token = bridge.create_invite(&["t3".into()], Duration::from_secs(60), 100)?;
        bridge.claim(&token, &id, "host", 100)?;
        bridge.approve(&id, 100)?;
        let route = ServiceRoute {
            service: "t3".into(),
            url: "https://host.example.net/".into(),
        };
        for url in [
            "http://host.example.net/",
            "https://127.0.0.1/",
            "https://host.example.net/x",
        ] {
            let invalid = ServiceRoute {
                url: url.into(),
                ..route.clone()
            };
            assert!(bridge.refresh_host(&id, true, &[invalid]).is_err());
        }
        let mcp = ServiceRoute {
            service: "mcp".into(),
            ..route.clone()
        };
        assert!(bridge.refresh_host(&id, true, &[mcp]).is_err());
        assert!(!bridge.peers()?[0].remote_bridge_consent);

        bridge.refresh_host(&id, true, std::slice::from_ref(&route))?;
        let peer = &bridge.peers()?[0];
        assert!(peer.remote_bridge_consent);
        assert_eq!(peer.remote_routes, vec![route.clone()]);
        assert!(
            !peer.bridge_consent && !bridge.bridge_consented(&id)?,
            "an announcement sets only what the peer reported"
        );
        bridge.refresh_host(&id, false, std::slice::from_ref(&route))?;
        assert!(bridge.peers()?[0].remote_routes.is_empty());
        assert!(bridge.refresh_host("stranger", true, &[]).is_err());
        Ok(())
    }

    #[test]
    fn own_routes_go_only_to_a_consented_bridge() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let host = Store::open(&dir.path().join("host"), "host")?;
        let bridge = Store::open(&dir.path().join("bridge"), "bridge")?;
        let id = bridge.id()?;
        let token = host.create_invite(&["t3".into()], Duration::from_secs(60), 100)?;
        host.claim(&token, &id, "bridge", 100)?;
        host.approve(&id, 100)?;
        host.set_services(&id, &["t3".into()], &["t3".into()])?;
        let route = ServiceRoute {
            service: "t3".into(),
            url: "https://host.example.net/".into(),
        };
        host.refresh_routes(&id, std::slice::from_ref(&route), crate::unix_time()?)?;
        let peer = |store: &Store| store.peers().map(|peers| peers[0].clone());
        assert!(own_for_peer(&host, &peer(&host)?).is_empty());
        host.set_bridge_consent(&id, true)?;
        assert_eq!(own_for_peer(&host, &peer(&host)?), vec![route]);
        Ok(())
    }
}
