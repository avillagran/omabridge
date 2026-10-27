//! Operator-only read-only metadata inventory. Credentials remain in GatewayStore.
use anyhow::{Context, Result, ensure};
use omabridge::mcp::{
    store::{GatewayStore, now},
    upstream::Upstream,
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::Path, time::Duration};

#[tokio::main]
async fn main() -> Result<()> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let state = arguments
        .first()
        .context("usage: mcp_inventory STATE_DIR [SESSION_ID ...]")?;
    ensure!(
        Path::new(state).join("mcp").is_dir(),
        "existing MCP state required"
    );
    let store = GatewayStore::open(Path::new(state))?;
    let grants = store.grants()?;
    let subscriptions = store.subscriptions()?;
    let (credential, bound_environment) = store.upstream_routed()?;
    let mut credential = credential.context("no existing upstream MCP consent")?;
    let selected_origin = std::env::var("OMABRIDGE_INVENTORY_ORIGIN").ok();
    let expected_environment = std::env::var("OMABRIDGE_INVENTORY_EXPECT_ENV")
        .ok()
        .or(bound_environment);
    if let Some(origin) = selected_origin {
        ensure!(
            expected_environment.is_some(),
            "explicit environment required for a route override"
        );
        credential.url = origin;
    }
    let upstream = match expected_environment.as_deref() {
        Some(id) => Upstream::for_environment(&credential, id)?,
        None => Upstream::new(&credential)?,
    };
    let mut expected: BTreeSet<String> = arguments.iter().skip(1).cloned().collect();
    for grant in &grants {
        expected.extend(grant.scope.sessions.iter().flatten().cloned());
    }
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?;
    let origin = omabridge::mcp::upstream::t3_base(&credential.url)?;
    let descriptor: Value = serde_json::from_slice(
        &http
            .get(origin.join(".well-known/t3/environment")?)
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?,
    )?;
    let mut projects = Vec::new();
    let mut cursor = Some(0);
    let mut project_count = 0;
    for _ in 0..20 {
        let Some(position) = cursor.take() else { break };
        let listed = upstream
            .call(
                "t3_project_list",
                json!({"cursor":position,"limit":100}),
                Duration::from_secs(20),
            )
            .await?;
        for project in listed["projects"].as_array().into_iter().flatten() {
            if !project["deletedAt"].is_null() {
                continue;
            }
            project_count += 1;
            let id = project["id"].as_str().context("invalid project identity")?;
            let title = project["title"].as_str().unwrap_or_default();
            let mut sessions = Vec::new();
            let mut thread_cursor = Some(0);
            for _ in 0..20 {
                let Some(position) = thread_cursor.take() else {
                    break;
                };
                let listed = upstream
                    .call(
                        "t3_thread_list",
                        json!({"projectId":id,"cursor":position,"limit":100}),
                        Duration::from_secs(20),
                    )
                    .await?;
                for thread in listed["threads"].as_array().into_iter().flatten() {
                    if thread["threadId"]
                        .as_str()
                        .is_some_and(|s| expected.contains(s))
                    {
                        sessions.push(json!({"session_id":thread["threadId"],"title":thread["title"],"status":thread["status"],"pending_requests":thread["pendingRequestCount"]}));
                    }
                }
                thread_cursor = listed["nextCursor"].as_u64();
            }
            projects.push(json!({"project_id":id,"title":title,"selected_sessions":sessions}));
        }
        cursor = listed["nextCursor"].as_u64();
    }
    println!(
        "{}",
        json!({"environment_id":descriptor["environmentId"],"upstream_mcp_authenticated":true,"upstream_access_ceiling":credential.access,"upstream_expires":credential.expires,"upstream_expired":credential.expires<=now(),"active_external_grants":grants.iter().filter(|g|g.active(now())).count(),"historical_external_grants":grants.len(),"active_subscriptions":subscriptions.len(),"upstream_project_count":project_count,"relevant_projects":projects,"history_read":false,"writes":false})
    );
    Ok(())
}
