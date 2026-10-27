//! Native catalog lifecycle shared by mobile bindings and native callers.
//! No bearer credentials are stored here. Cached discovery is never permission.
use crate::{Client, Store, read_document, write_document};
use anyhow::{Context, Result};
use iroh::EndpointAddr;
use serde_json::{Value, json};
use std::time::Duration;

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
    pub fn projection(&self, local: &Value, now: u64) -> Result<Value> {
        let rows = local.as_array().context("invalid local environments")?;
        let mut upserts = Vec::new();
        let mut stop = Vec::new();
        let mut enroll = Vec::new();
        for entry in self.cache["environments"].as_array().into_iter().flatten() {
            let id = entry["environmentId"]
                .as_str()
                .context("invalid cached identity")?;
            let provenance = format!("bridge:{}:{}", self.bridge.id, self.store.id()?);
            let existing = rows.iter().find(|r| r["environmentId"] == id);
            if existing.is_some_and(|r| r["provenance"] != provenance) {
                continue;
            }
            let local_id = existing
                .and_then(|r| r["id"].as_str())
                .map(str::to_owned)
                .unwrap_or_else(|| format!("{}:{}", provenance, id));
            let removed = self.denied || entry["removed"] == true;
            let authorization_expires_at = existing
                .and_then(|r| r["authorizationExpiresAt"].as_u64())
                .filter(|expiry| *expiry > now && *expiry <= now.saturating_add(300_000));
            let status = if removed {
                "revoked"
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
            if status != "authorized" || existing.is_some_and(|r| r["baseUrl"] != route) {
                stop.push(json!(local_id));
            }
            if self.available && status == "discovered" && !route.is_null() {
                enroll.push(json!(id));
            }
            upserts.push(json!({"id":local_id,"environmentId":id,"label":entry["label"],"baseUrl":route,"provenance":provenance,"status":status,"authorizationExpiresAt":authorization_expires_at}));
        }
        Ok(json!({"upserts":upserts,"stop":stop,"enroll":enroll}))
    }
}
