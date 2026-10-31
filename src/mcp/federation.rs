//! Environment selection is authorization, never a caller-supplied network route.
use anyhow::{Result, ensure};
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::Mutex;

use super::{
    store::{GatewayStore, Grant, UpstreamCredential, sha256_b64},
    tools::{Denied, ToolContext, definitions},
    upstream::Upstream,
};

/// Reuse protocol sessions, but never reuse a credential after its slot changes.
#[derive(Default)]
pub struct Router {
    catalog: Mutex<()>,
    upstreams: Mutex<BTreeMap<String, (String, Arc<Upstream>)>>,
}

impl Router {
    /// Refresh the authenticated native catalog before selecting any credential.
    /// Offline discovery is retained by CatalogManager but never enables a call.
    pub async fn credential(
        &self,
        store: &GatewayStore,
        environment: &str,
    ) -> Result<UpstreamCredential> {
        let route = if let Some(binding) = store.remote_catalog_binding()? {
            let _guard = self.catalog.lock().await;
            let device = crate::Store {
                drafts_clock: None,
                root: binding.device_state,
            };
            let address = device
                .peers()?
                .into_iter()
                .find(|p| p.id == binding.bridge_id)
                .and_then(|p| p.address)
                .ok_or_else(|| Denied("forbidden", "catalog peer revoked".into()))?;
            let mut manager = crate::catalog_client::CatalogManager::open(device, address)?;
            let state = manager.refresh_remote().await?;
            ensure!(
                state["status"] == "available",
                Denied(
                    "catalog_unavailable",
                    "fresh catalog authorization required".into()
                )
            );
            Some(manager.enrollment_route(environment, super::store::now().saturating_mul(1000))?)
        } else {
            None
        };
        ensure!(
            store.catalog_allows(environment)?,
            Denied("forbidden", "environment withdrawn".into())
        );
        let (credential, expected) = store.environment_store(environment)?.upstream_routed()?;
        ensure!(
            expected.as_deref().is_none_or(|id| id == environment),
            Denied(
                "forbidden",
                "runtime environment differs from selected environment".into()
            )
        );
        let credential = match credential {
            Some(credential) => Some(credential),
            None => {
                // Reuse existing local consent only for its explicitly pinned UUID.
                // No token copy, new consent, or implicit host addition occurs.
                let (local, identity) = store.upstream_routed()?;
                if identity.as_deref() == Some(environment) {
                    local
                } else {
                    None
                }
            }
        };
        let mut credential = credential.ok_or_else(|| {
            Denied(
                "environment_not_linked",
                "This environment requires its own T3 MCP authorization.".into(),
            )
        })?;
        if let Some(route) = route {
            credential.url = route;
        }
        Ok(credential)
    }

    pub async fn upstream(
        &self,
        credential: &UpstreamCredential,
        environment: Option<&str>,
    ) -> Result<Arc<Upstream>> {
        // Remote origins are pinned afresh per selection; never retain a DNS answer indefinitely.
        if credential.url.starts_with("https://") {
            return Ok(Arc::new(
                Upstream::for_remote_environment(
                    credential,
                    environment
                        .ok_or_else(|| Denied("forbidden", "remote environment required".into()))?,
                )
                .await?,
            ));
        }
        let key = environment.unwrap_or("local");
        let fingerprint = sha256_b64(&serde_json::to_vec(credential)?);
        let mut cache = self.upstreams.lock().await;
        if let Some((current, upstream)) = cache.get(key)
            && current == &fingerprint
        {
            return Ok(upstream.clone());
        }
        let upstream = Arc::new(match environment {
            Some(id) => Upstream::for_environment(credential, id)?,
            None => Upstream::new(credential)?,
        });
        if cache.len() >= 129 {
            cache.clear();
        }
        cache.insert(key.into(), (fingerprint, upstream.clone()));
        Ok(upstream)
    }
}

pub fn tool_definitions(grant: &Grant) -> Vec<Value> {
    let mut tools = definitions(grant.scope.access);
    if !grant.federated() {
        return tools;
    }
    for tool in &mut tools {
        tool["inputSchema"]["properties"]["environment_id"] = json!({"type":"string", "description":"Authorized stable environment identity from t3_list_environments. Always retain this with session, run and cursor IDs."});
        tool["inputSchema"]["required"]
            .as_array_mut()
            .unwrap()
            .push(json!("environment_id"));
    }
    tools.push(json!({"name":"t3_list_environments", "title":"List authorized T3 environments",
        "description":"List only explicitly authorized environments. An unlinked or offline environment is not an empty project list. IDs are environment-scoped; use environment_id on every subsequent call.",
        "inputSchema":{"type":"object","properties":{},"additionalProperties":false},
        "annotations":{"readOnlyHint":true,"idempotentHint":true,"openWorldHint":false}}));
    tools
}

pub async fn call(
    router: &Router,
    store: &GatewayStore,
    grant: &Grant,
    name: &str,
    args: &Map<String, Value>,
) -> Result<Value> {
    let resolved =
        store.resolve_grant(grant, args.get("environment_id").and_then(Value::as_str))?;
    let grant = &resolved;
    ensure!(
        store.grant_unchanged(grant)?,
        Denied("forbidden", "grant revoked or expired".into())
    );
    if name == "t3_list_environments" {
        let mut environments = Vec::new();
        for id in &grant.scope.environments {
            let status = match router.credential(store, id).await {
                Ok(c) if c.expires <= super::store::now() => "credential_expired",
                Ok(_) => "linked",
                Err(e)
                    if e.downcast_ref::<Denied>()
                        .is_some_and(|d| d.0 == "environment_not_linked") =>
                {
                    "authorization_required"
                }
                Err(_) => "unavailable",
            };
            environments.push(json!({"environment_id":id,"status":status}));
        }
        ensure!(
            store.grant_unchanged(grant)?,
            Denied("forbidden", "grant revoked or expired".into())
        );
        return Ok(json!({"environments":environments}));
    }
    let selected = match args.get("environment_id") {
        None => None,
        Some(Value::String(value)) => Some(value.as_str()),
        _ => {
            return Err(Denied(
                "invalid_arguments",
                "environment_id must be a string".into(),
            )
            .into());
        }
    };
    let (credential, scoped_store, upstream) = if !grant.federated() {
        ensure!(
            selected.is_none(),
            Denied("forbidden", "this grant is local-only".into())
        );
        let (credential, environment) = store.upstream_routed()?;
        let credential = credential.ok_or_else(|| {
            Denied(
                "gateway_not_linked",
                "Link the gateway to T3 Code first.".into(),
            )
        })?;
        let upstream = router.upstream(&credential, environment.as_deref()).await?;
        (credential, store.clone(), upstream)
    } else {
        let environment = selected
            .ok_or_else(|| Denied("invalid_arguments", "environment_id is required".into()))?;
        ensure!(
            grant.scope.environments.iter().any(|id| id == environment),
            Denied("forbidden", "environment not authorized".into())
        );
        let credential = router.credential(store, environment).await?;
        let upstream = router.upstream(&credential, Some(environment)).await?;
        (credential, store.for_environment(environment)?, upstream)
    };
    // Enforce T3's linked ceiling locally too. T3 remains authoritative.
    ensure!(
        !(credential.access == "read-only" && matches!(name, "t3_send_message" | "t3_cancel_run")),
        Denied("forbidden", "environment credential is read-only".into())
    );
    let mut arguments = args.clone();
    arguments.remove("environment_id");
    let mut value = ToolContext {
        router,
        grant,
        store: &scoped_store,
        upstream: &upstream,
    }
    .call(name, &arguments)
    .await?;
    ensure!(
        store.grant_unchanged(grant)?,
        Denied("forbidden", "grant revoked or expired".into())
    );
    if let Some(environment) = selected {
        let credential = router.credential(store, environment).await?;
        ensure!(
            credential.expires > super::store::now(),
            Denied("forbidden", "credential expired".into())
        );
        router
            .upstream(&credential, Some(environment))
            .await?
            .verify_environment()
            .await?;
        ensure!(
            store.grant_unchanged(grant)?,
            Denied("forbidden", "policy changed during request".into())
        );
        value["environment_id"] = json!(environment);
    }
    Ok(value)
}
