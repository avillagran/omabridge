//! Native catalog lifecycle shared by mobile bindings and native callers.
//! No bearer credentials are stored here. Cached discovery is never permission.
use crate::{Client, Store, read_document, write_document};
use anyhow::{Context, Result};
use iroh::EndpointAddr;
use serde_json::{Value, json};
use std::time::Duration;

/// Local status of a row holding a native long-lived T3 session, from
/// `Client::t3_host_pair`. Discovery never replaces it with a read-only session.
pub const NATIVE_AUTHORIZED: &str = "native_authorized";
/// That session ended; the row stays native and waits for a renewal.
pub const NATIVE_EXPIRED: &str = "native_expired";
/// Asking again this long before a native session ends leaves room to be offline.
pub const NATIVE_RENEW_BEFORE_MS: u64 = 7 * 24 * 60 * 60 * 1000;

#[derive(Debug)]
pub struct CatalogDenied;
impl std::fmt::Display for CatalogDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("catalog denied")
    }
}
impl std::error::Error for CatalogDenied {}

pub struct CatalogManager {
    store: Store,
    bridge: EndpointAddr,
    cache: Value,
    denied: bool,
    expires_at: u64,
    available: bool,
}
impl CatalogManager {
    pub fn open(store: Store, bridge: EndpointAddr) -> Result<Self> {
        let path = store
            .root()
            .join(format!("catalog-cache-{}.json", bridge.id));
        let document: Value = if path.exists() {
            read_document(&path)?
        } else {
            Value::Null
        };
        let cache = document["cache"].clone();
        let expires_at = document["expiresAt"].as_u64().unwrap_or(0);
        if !cache.is_null() {
            anyhow::ensure!(
                cache["bridgeId"] == bridge.id.to_string() && cache["clientId"] == store.id()?,
                "cache identity mismatch"
            );
        }
        let denial = store
            .root()
            .join(format!("catalog-denied-{}.json", bridge.id));
        let denied = if denial.exists() {
            read_document(&denial)?
        } else {
            false
        };
        Ok(Self {
            store,
            bridge,
            cache,
            denied,
            expires_at,
            available: false,
        })
    }
    pub fn cached(&self, now: u64) -> Value {
        let expired = self.expires_at <= now;
        json!({"status":if self.denied {"revoked"} else if expired {"expired"} else {"offline"},"catalog":self.cache,"accessAllowed":false})
    }
    pub async fn refresh(&mut self, client: &Client) -> Result<Value> {
        self.available = false;
        let incoming =
            tokio::time::timeout(Duration::from_secs(15), client.catalog(&self.bridge)).await;
        self.accept(incoming).await
    }
    /// MCP consumers reuse the device's active endpoint instead of opening another identity.
    pub async fn refresh_remote(&mut self) -> Result<Value> {
        self.available = false;
        let incoming = tokio::time::timeout(
            Duration::from_secs(15),
            crate::network::remote_catalog(&self.store, &self.bridge),
        )
        .await;
        self.accept(incoming).await
    }
    async fn accept(
        &mut self,
        incoming: std::result::Result<Result<Value>, tokio::time::error::Elapsed>,
    ) -> Result<Value> {
        // Validate freshness at receipt, not before a possibly slow network read.
        let now: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis()
            .try_into()?;
        match incoming {
            Ok(Ok(incoming)) => {
                let context = json!({"bridgeId":self.bridge.id.to_string(),"clientId":self.store.id()?,"now":now});
                let next = t3_protocol::bridge_catalog::reconcile(&incoming, &self.cache, &context)
                    .map_err(anyhow::Error::msg)?;
                write_document(
                    &self
                        .store
                        .root()
                        .join(format!("catalog-cache-{}.json", self.bridge.id)),
                    &json!({"cache":next,"expiresAt":incoming["expiresAt"]}),
                    true,
                )?;
                self.cache = next;
                self.expires_at = incoming["expiresAt"].as_u64().context("invalid expiry")?;
                write_document(
                    &self
                        .store
                        .root()
                        .join(format!("catalog-denied-{}.json", self.bridge.id)),
                    &false,
                    true,
                )?;
                self.denied = false;
                self.available = true;
                Ok(json!({"status":"available","catalog":self.cache,"accessAllowed":false}))
            }
            Ok(Err(error)) if error.downcast_ref::<CatalogDenied>().is_some() => {
                self.denied = true;
                // An authenticated Denied is distinct from an unreachable peer.
                // Persist a fail-closed withdrawal, retaining row identities.
                // Do not overwrite a signed/reconciled cache with invented revisions.
                // Persist denial independently so restart cannot revive cached access.
                write_document(
                    &self
                        .store
                        .root()
                        .join(format!("catalog-denied-{}.json", self.bridge.id)),
                    &json!(true),
                    true,
                )?;
                Ok(self.cached(now))
            }
            _ => {
                if self
                    .store
                    .root()
                    .join(format!("catalog-denied-{}.json", self.bridge.id))
                    .exists()
                {
                    self.denied = read_document(
                        &self
                            .store
                            .root()
                            .join(format!("catalog-denied-{}.json", self.bridge.id)),
                    )?;
                }
                Ok(self.cached(now))
            }
        }
    }
    pub fn enrollment_route(&self, environment_id: &str, now: u64) -> Result<String> {
        anyhow::ensure!(!self.denied && self.expires_at > now, "catalog unavailable");
        let row = self.cache["environments"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|e| e["environmentId"] == environment_id && e["removed"] == false)
            .context("environment unavailable")?;
        row["routes"]
            .as_array()
            .into_iter()
            .flatten()
            .min_by_key(|r| r["priority"].as_u64().unwrap_or(u64::MAX))
            .and_then(|r| r["url"].as_str())
            .map(str::to_owned)
            .context("route unavailable")
    }
    pub fn bridge(&self) -> &EndpointAddr {
        &self.bridge
    }
    /// Build a native projection. Independent rows win by stable environment id;
    /// managed rows keep their local id across rename/route change/withdrawal.
    /// A native row (its `status` is `NATIVE_AUTHORIZED` or `NATIVE_EXPIRED`) keeps
    /// its session while the catalog is merely stale; only withdrawal stops it.
    /// `hostEnroll` lists new environments of an all-hosts bridge and `renew` the
    /// native rows due: both are served by `Client::t3_host_pair`, never `enroll`.
    pub fn projection(&self, local: &Value, now: u64) -> Result<Value> {
        let rows = local.as_array().context("invalid local environments")?;
        let mut upserts = Vec::new();
        let mut stop = Vec::new();
        let mut enroll = Vec::new();
        let mut host_enroll = Vec::new();
        let mut renew = Vec::new();
        let bridge = self.bridge.id.to_string();
        let all_hosts = self
            .store
            .peers()?
            .iter()
            .any(|peer| peer.id == bridge && peer.remote_all_hosts);
        for entry in self.cache["environments"].as_array().into_iter().flatten() {
            let id = entry["environmentId"]
                .as_str()
                .context("invalid cached identity")?;
            let provenance = format!("bridge:{}:{}", self.bridge.id, self.store.id()?);
            let row = rows.iter().find(|r| r["environmentId"] == id);
            // A row this client got from a previous bridge moves here and enrolls anew,
            // or it would keep that bridge's label with no credential. Only a bridge
            // that can issue write access replaces a long-lived credential.
            let adopted = row.is_some_and(|r| {
                let native = r["status"] == NATIVE_AUTHORIZED || r["status"] == NATIVE_EXPIRED;
                r["provenance"] != provenance
                    && (all_hosts || !native)
                    && r["provenance"].as_str().is_some_and(|origin| {
                        origin.starts_with("bridge:")
                            && origin.rsplit(':').next() == provenance.rsplit(':').next()
                    })
            });
            if !adopted && row.is_some_and(|r| r["provenance"] != provenance) {
                continue;
            }
            let existing = row.filter(|_| !adopted);
            let local_id = row
                .and_then(|r| r["id"].as_str())
                .map(str::to_owned)
                .unwrap_or_else(|| format!("{}:{}", provenance, id));
            let removed = self.denied || entry["removed"] == true;
            let native_expiry = existing
                .filter(|r| r["status"] == NATIVE_AUTHORIZED || r["status"] == NATIVE_EXPIRED)
                .map(|r| r["authorizationExpiresAt"].as_u64().unwrap_or(0));
            let native_live = native_expiry.is_some_and(|expiry| expiry > now);
            let authorization_expires_at = if native_expiry.is_some() {
                native_expiry.filter(|_| native_live && !removed)
            } else {
                existing
                    .and_then(|r| r["authorizationExpiresAt"].as_u64())
                    .filter(|expiry| *expiry > now && *expiry <= now.saturating_add(300_000))
            };
            let status = if removed {
                "revoked"
            } else if native_live {
                NATIVE_AUTHORIZED
            } else if native_expiry.is_some() {
                NATIVE_EXPIRED
            } else if self.expires_at <= now {
                "expired"
            } else {
                if authorization_expires_at.is_some() {
                    "authorized"
                } else {
                    "discovered"
                }
            };
            let route = if removed {
                Value::Null
            } else {
                entry["routes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .min_by_key(|r| r["priority"].as_u64().unwrap_or(u64::MAX))
                    .map(|r| r["url"].clone())
                    .unwrap_or(Value::Null)
            };
            let keeps_running = status == "authorized" || status == NATIVE_AUTHORIZED;
            if !keeps_running || existing.is_some_and(|r| r["baseUrl"] != route) {
                stop.push(json!(local_id));
            }
            if self.available && status == "discovered" && !route.is_null() {
                if all_hosts {
                    host_enroll.push(json!(id));
                } else {
                    enroll.push(json!(id));
                }
            }
            let renewal_due = status == NATIVE_EXPIRED
                || (status == NATIVE_AUTHORIZED
                    && native_expiry.is_some_and(|expiry| {
                        expiry <= now.saturating_add(NATIVE_RENEW_BEFORE_MS)
                    }));
            if self.available && renewal_due && !route.is_null() {
                renew.push(json!(id));
            }
            upserts.push(json!({"id":local_id,"environmentId":id,"label":entry["label"],"baseUrl":route,"provenance":provenance,"status":status,"authorizationExpiresAt":authorization_expires_at}));
        }
        Ok(
            json!({"upserts":upserts,"stop":stop,"enroll":enroll,"hostEnroll":host_enroll,"renew":renew}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ENV: &str = "00000000-0000-4000-8000-000000000002";
    const DAY: u64 = 24 * 60 * 60 * 1000;
    const NOW: u64 = 1_000_000_000_000;

    fn manager(
        dir: &std::path::Path,
        all_hosts: bool,
        removed: bool,
        fresh: bool,
    ) -> CatalogManager {
        let store = Store::open(&dir.join("phone"), "phone").unwrap();
        let bridge = Store::open(&dir.join("bridge"), "bridge").unwrap();
        let address = EndpointAddr::new(bridge.id().unwrap().parse().unwrap());
        store
            .remember_peer(&address, "bridge", &["t3".into()], all_hosts)
            .unwrap();
        let mut manager = CatalogManager::open(store, address).unwrap();
        manager.cache = json!({"environments":[{"environmentId":ENV,"label":"host","removed":removed,
            "routes":[{"id":"r","url":"https://host.example.net/","priority":0}]}]});
        manager.available = fresh;
        manager.expires_at = if fresh { NOW + 600_000 } else { NOW - 1 };
        manager
    }

    fn native(manager: &CatalogManager, status: &str, expires: u64) -> Value {
        let provenance = format!(
            "bridge:{}:{}",
            manager.bridge.id,
            manager.store.id().unwrap()
        );
        json!([{"id":"row","environmentId":ENV,"provenance":provenance,"status":status,
            "baseUrl":"https://host.example.net/","authorizationExpiresAt":expires}])
    }

    fn untouched(plan: &Value) {
        assert_eq!(plan["upserts"][0]["status"], NATIVE_AUTHORIZED);
        assert_eq!(plan["stop"], json!([]), "must keep running");
        assert_eq!(
            plan["enroll"],
            json!([]),
            "read-only enrollment would overwrite it"
        );
        assert_eq!(plan["hostEnroll"], json!([]));
    }

    #[test]
    fn a_row_from_a_previous_bridge_moves_here_and_enrolls() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let fresh = manager(dir.path(), false, false, true);
        let client = fresh.store.id()?;
        let row = |provenance: String, status: &str| {
            json!([{"id":"row","environmentId":ENV,"provenance":provenance,"status":status,
                "baseUrl":"https://host.example.net/","authorizationExpiresAt":NOW + 1000}])
        };
        let plan = fresh.projection(&row(format!("bridge:old:{client}"), "authorized"), NOW)?;
        assert_eq!(plan["upserts"][0]["id"], "row");
        assert_eq!(plan["upserts"][0]["status"], "discovered");
        assert_eq!(plan["stop"], json!(["row"]));

        // Another client's row, an independent row, and a native credential stay as they are.
        for rows in [
            row("bridge:old:someone-else".into(), "authorized"),
            row("independent".into(), "authorized"),
            row(format!("bridge:old:{client}"), NATIVE_AUTHORIZED),
        ] {
            assert_eq!(fresh.projection(&rows, NOW)?["upserts"], json!([]));
        }
        Ok(())
    }

    #[test]
    fn a_long_lived_credential_survives_projection_until_withdrawn() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let expires = NOW + 29 * DAY;
        let fresh = manager(dir.path(), true, false, true);
        let rows = native(&fresh, NATIVE_AUTHORIZED, expires);
        let plan = fresh.projection(&rows, NOW)?;
        untouched(&plan);
        assert_eq!(plan["upserts"][0]["authorizationExpiresAt"], expires);
        assert_eq!(plan["renew"], json!([]), "not due yet");

        // A stale catalog is not a withdrawal.
        let dir = tempfile::tempdir()?;
        let stale = manager(dir.path(), true, false, false);
        let rows = native(&stale, NATIVE_AUTHORIZED, expires);
        let plan = stale.projection(&rows, NOW)?;
        untouched(&plan);
        assert_eq!(plan["upserts"][0]["authorizationExpiresAt"], expires);

        // Due for renewal: still running, listed once, through the same request.
        let dir = tempfile::tempdir()?;
        let fresh = manager(dir.path(), true, false, true);
        let rows = native(&fresh, NATIVE_AUTHORIZED, NOW + DAY);
        let plan = fresh.projection(&rows, NOW)?;
        untouched(&plan);
        assert_eq!(plan["renew"], json!([ENV]));

        // Ended: stopped and renewed, never downgraded to read-only.
        let rows = native(&fresh, NATIVE_AUTHORIZED, NOW - 1);
        let plan = fresh.projection(&rows, NOW)?;
        assert_eq!(plan["upserts"][0]["status"], NATIVE_EXPIRED);
        assert_eq!(plan["stop"], json!(["row"]));
        assert_eq!(plan["enroll"], json!([]));
        assert_eq!(plan["renew"], json!([ENV]));
        let plan = fresh.projection(&native(&fresh, NATIVE_EXPIRED, NOW - 1), NOW)?;
        assert_eq!(plan["upserts"][0]["status"], NATIVE_EXPIRED);
        assert_eq!(plan["enroll"], json!([]));

        // Withdrawal stops it, and drops the expiry.
        let dir = tempfile::tempdir()?;
        let gone = manager(dir.path(), true, true, true);
        let rows = native(&gone, NATIVE_AUTHORIZED, expires);
        let plan = gone.projection(&rows, NOW)?;
        assert_eq!(plan["upserts"][0]["status"], "revoked");
        assert_eq!(plan["stop"], json!(["row"]));
        assert!(plan["upserts"][0]["authorizationExpiresAt"].is_null());
        assert_eq!(plan["renew"], json!([]));
        Ok(())
    }

    #[test]
    fn new_rows_take_the_path_of_their_bridge() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let plan = manager(dir.path(), true, false, true).projection(&json!([]), NOW)?;
        assert_eq!(plan["hostEnroll"], json!([ENV]));
        assert_eq!(plan["enroll"], json!([]));
        let dir = tempfile::tempdir()?;
        let plan = manager(dir.path(), false, false, true).projection(&json!([]), NOW)?;
        assert_eq!(plan["enroll"], json!([ENV]), "plain grants stay read-only");
        assert_eq!(plan["hostEnroll"], json!([]));
        // A short read-only row keeps its existing behaviour.
        let dir = tempfile::tempdir()?;
        let plain = manager(dir.path(), false, false, true);
        let provenance = format!("bridge:{}:{}", plain.bridge.id, plain.store.id()?);
        let plan = plain.projection(
            &json!([{"id":"row","environmentId":ENV,"provenance":provenance,
                "baseUrl":"https://host.example.net/","authorizationExpiresAt":NOW+DAY}]),
            NOW,
        )?;
        assert_eq!(plan["upserts"][0]["status"], "discovered");
        assert_eq!(plan["enroll"], json!([ENV]));
        Ok(())
    }
}
