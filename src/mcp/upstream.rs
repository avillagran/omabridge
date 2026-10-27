//! Client for T3 Code's own Streamable-HTTP MCP server (`/mcp`).
//!
//! All conversation, run, queue and approval semantics stay in T3. This client only
//! forwards tool calls with T3's `mcp-client` credential and decodes the results.
use anyhow::{Context, Result, anyhow, bail, ensure};
use reqwest::{StatusCode, Url};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::sync::Mutex;

use super::store::{UpstreamCredential, random_token, sha256_b64};

pub const PROTOCOL_VERSION: &str = "2025-06-18";
const MAX_RESPONSE: usize = 16 * 1024 * 1024;

/// A T3 MCP tool failure, e.g. `thread_not_found`, `runtime_mode_escalation_denied`.
#[derive(Debug)]
pub struct ToolFailure {
    pub code: String,
    pub message: String,
}
impl std::fmt::Display for ToolFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "T3 {}: {}", self.code, self.message)
    }
}
impl std::error::Error for ToolFailure {}

pub struct Upstream {
    endpoint: Url,
    authorization: String,
    http: reqwest::Client,
    session: Mutex<Option<String>>,
    environment: Option<String>,
    expires: u64,
}

/// Loopback T3 only: the gateway is the public edge, T3 stays private.
pub fn t3_base(raw: &str) -> Result<Url> {
    let url = Url::parse(raw).context("invalid T3 URL")?;
    ensure!(
        url.scheme() == "http"
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")),
        "T3 URL must be a loopback http:// origin, e.g. http://127.0.0.1:3773"
    );
    Ok(url.join("/")?)
}

fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .build()?)
}

async fn bounded_body(mut response: reqwest::Response) -> Result<(StatusCode, String, String)> {
    let status = response.status();
    let kind = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= MAX_RESPONSE,
            "T3 response too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok((status, kind, String::from_utf8_lossy(&bytes).into_owned()))
}

/// Picks the JSON-RPC response with `id` from a JSON or SSE response body.
fn rpc_message(kind: &str, body: &str, id: u64) -> Result<Value> {
    let candidates: Vec<Value> = if kind.starts_with("text/event-stream") {
        body.lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .filter_map(|data| serde_json::from_str(data.trim()).ok())
            .collect()
    } else {
        vec![serde_json::from_str(body).context("T3 returned invalid JSON")?]
    };
    candidates
        .into_iter()
        .find(|message| message.get("id").and_then(Value::as_u64) == Some(id))
        .context("T3 returned no matching JSON-RPC response")
}

/// Decodes `structuredContent` (or JSON text content) and T3's failure envelope.
pub fn tool_value(result: &Value) -> Result<Value> {
    let structured = result.get("structuredContent").cloned().or_else(|| {
        result
            .get("content")?
            .as_array()?
            .iter()
            .find_map(|part| part.get("text")?.as_str())
            .and_then(|text| serde_json::from_str(text).ok())
    });
    let failed = result.get("isError").and_then(Value::as_bool) == Some(true);
    let value = structured.unwrap_or(Value::Null);
    let failure = value
        .get("code")
        .and_then(Value::as_str)
        .zip(value.get("message").and_then(Value::as_str));
    if failed || (failure.is_some() && value.as_object().is_some_and(|o| o.len() <= 3)) {
        let (code, message) = failure.unwrap_or(("tool_error", "T3 tool call failed"));
        return Err(ToolFailure {
            code: code.into(),
            message: message.into(),
        }
        .into());
    }
    Ok(value)
}

impl Upstream {
    pub fn new(credential: &UpstreamCredential) -> Result<Self> {
        let endpoint = t3_base(&credential.url)?.join("mcp")?;
        Ok(Self {
            endpoint,
            authorization: format!("Bearer {}", credential.token),
            http: client()?,
            session: Mutex::new(None),
            environment: None,
            expires: credential.expires,
        })
    }

    pub fn for_environment(credential: &UpstreamCredential, environment: &str) -> Result<Self> {
        ensure!(
            super::store::valid_environment(environment),
            "invalid environment identity"
        );
        let mut upstream = Self::new(credential)?;
        upstream.environment = Some(environment.into());
        Ok(upstream)
    }

    /// Check the public descriptor before sending any credential to a selected route.
    /// Only called with a route from a freshly authenticated native catalog.
    pub async fn for_remote_environment(
        credential: &UpstreamCredential,
        environment: &str,
    ) -> Result<Self> {
        use super::webhook::{self, CallbackPolicy};
        ensure!(
            super::store::valid_environment(environment),
            "invalid environment identity"
        );
        let url = webhook::callback_url(&credential.url, CallbackPolicy::default())
            .map_err(|_| anyhow!("invalid catalog route"))?;
        ensure!(
            url.path() == "/" && url.query().is_none(),
            "catalog route must be an origin"
        );
        let address = webhook::destination(&url, CallbackPolicy::default())
            .await
            .map_err(|_| anyhow!("catalog route unavailable"))?;
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10));
        if let Some(host) = url
            .host_str()
            .filter(|h| h.parse::<std::net::IpAddr>().is_err())
        {
            builder = builder.resolve(host, address);
        }
        let upstream = Self {
            endpoint: url.join("mcp")?,
            authorization: format!("Bearer {}", credential.token),
            http: builder.build()?,
            session: Mutex::new(None),
            environment: Some(environment.into()),
            expires: credential.expires,
        };
        upstream.verify_environment().await?;
        Ok(upstream)
    }

    pub async fn verify_environment(&self) -> Result<()> {
        if let Some(expected) = &self.environment {
            let response = self
                .http
                .get(self.endpoint.join("/.well-known/t3/environment")?)
                .timeout(Duration::from_secs(10))
                .send()
                .await
                .context("environment descriptor unavailable")?;
            let (status, _, body) = bounded_body(response).await?;
            ensure!(status.is_success(), "environment descriptor unavailable");
            let descriptor: Value =
                serde_json::from_str(&body).context("invalid environment descriptor")?;
            ensure!(
                descriptor["environmentId"].as_str() == Some(expected),
                "environment identity mismatch"
            );
        }
        Ok(())
    }

    async fn post(
        &self,
        session: Option<&str>,
        body: &Value,
        timeout: Duration,
        authorized: &(dyn Fn() -> Result<()> + Sync),
    ) -> Result<(StatusCode, Option<String>, String, String)> {
        ensure!(
            self.expires > super::store::now(),
            "T3 credential expired; explicit consent required"
        );
        // Includes initialize/notification/retries: identity is checked before every bearer request.
        self.verify_environment().await?;
        let mut request = self
            .http
            .post(self.endpoint.clone())
            .timeout(timeout)
            .header("authorization", &self.authorization)
            .header("accept", "application/json, text/event-stream")
            .header("content-type", "application/json")
            .body(serde_json::to_vec(body)?);
        if let Some(session) = session {
            request = request
                .header("mcp-session-id", session)
                .header("mcp-protocol-version", PROTOCOL_VERSION);
        }
        authorized()?;
        let response = request.send().await.context("T3 MCP unreachable")?;
        let session = response
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let (status, kind, text) = bounded_body(response).await?;
        Ok((status, session, kind, text))
    }

    async fn initialize(&self, authorized: &(dyn Fn() -> Result<()> + Sync)) -> Result<String> {
        let (status, session, kind, body) = self
            .post(
                None,
                &json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{
                    "protocolVersion":PROTOCOL_VERSION,"capabilities":{},
                    "clientInfo":{"name":"omabridge-mcp-gateway","version":env!("CARGO_PKG_VERSION")}}}),
                Duration::from_secs(20),
                authorized,
            )
            .await?;
        if status == StatusCode::UNAUTHORIZED {
            bail!("T3 rejected the gateway credential; run `omabridge mcp link-t3` again");
        }
        ensure!(status.is_success(), "T3 MCP initialize failed: {status}");
        let message = rpc_message(&kind, &body, 0)?;
        ensure!(message.get("error").is_none(), "T3 MCP initialize error");
        let session = session.context("T3 MCP returned no session")?;
        let (status, _, _, _) = self
            .post(
                Some(&session),
                &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                Duration::from_secs(20),
                authorized,
            )
            .await?;
        ensure!(
            status.is_success(),
            "T3 MCP initialized notification failed"
        );
        Ok(session)
    }

    /// Calls one T3 tool, re-initializing once if T3 forgot the MCP session.
    pub async fn call(&self, tool: &str, arguments: Value, timeout: Duration) -> Result<Value> {
        self.call_checked(tool, arguments, timeout, &|| Ok(()))
            .await
    }

    /// Recheck caller authority after descriptor I/O, before every authenticated POST.
    pub async fn call_checked(
        &self,
        tool: &str,
        arguments: Value,
        timeout: Duration,
        authorized: &(dyn Fn() -> Result<()> + Sync),
    ) -> Result<Value> {
        authorized()?;
        ensure!(
            self.expires > super::store::now(),
            "T3 credential expired; relink this environment"
        );
        let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":tool,"arguments":arguments}});
        for attempt in 0..2 {
            let session = {
                let mut guard = self.session.lock().await;
                if guard.is_none() {
                    *guard = Some(self.initialize(authorized).await?);
                }
                guard.clone().unwrap()
            };
            let (status, _, kind, text) = self
                .post(Some(&session), &body, timeout, authorized)
                .await?;
            if attempt == 0 && matches!(status, StatusCode::NOT_FOUND | StatusCode::BAD_REQUEST) {
                *self.session.lock().await = None;
                continue;
            }
            if status == StatusCode::UNAUTHORIZED {
                bail!("T3 rejected the gateway credential; it may have been revoked in T3");
            }
            ensure!(status.is_success(), "T3 MCP call failed: {status}");
            let message = rpc_message(&kind, &text, 1)?;
            if let Some(error) = message.get("error") {
                return Err(anyhow!(ToolFailure {
                    code: "protocol_error".into(),
                    message: error
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("T3 MCP error")
                        .chars()
                        .take(500)
                        .collect(),
                }));
            }
            return tool_value(message.get("result").context("T3 MCP result missing")?);
        }
        bail!("T3 MCP session could not be re-established")
    }
}

fn query(url: &Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// Links this gateway to T3 through T3's own MCP OAuth with a T3 pairing code.
///
/// The pairing code comes from T3 Settings → Connections or `t3 auth pairing create`.
/// `access` is T3's runtime-mode ceiling (`read-only`, `approval-required`, ...); T3
/// enforces it on every thread the gateway messages.
pub async fn link(t3_url: &str, pairing_code: &str, access: &str) -> Result<UpstreamCredential> {
    ensure!(
        matches!(
            access,
            "read-only" | "approval-required" | "auto-accept-edits" | "auto" | "full-access"
        ),
        "invalid T3 access level"
    );
    let base = t3_base(t3_url)?;
    let origin = base.as_str().trim_end_matches('/').to_owned();
    let resource = format!("{origin}/mcp");
    let http = client()?;
    let redirect = "http://127.0.0.1/omabridge-gateway/callback";
    let registered: Value = serde_json::from_str(
        &bounded_body(
            http.post(base.join("oauth/mcp/register")?)
                .json(&json!({"client_name":"OmaBridge MCP gateway","redirect_uris":[redirect]}))
                .send()
                .await
                .context("T3 unreachable")?,
        )
        .await?
        .2,
    )?;
    let client_id = registered["client_id"]
        .as_str()
        .context("T3 registration failed")?
        .to_owned();
    let verifier = random_token();
    let state = random_token();
    let authorization = json!({
        "response_type":"code","client_id":client_id,"redirect_uri":redirect,
        "code_challenge":sha256_b64(verifier.as_bytes()),"code_challenge_method":"S256",
        "state":state,"resource":resource,
    });
    let (status, _, decided) = bounded_body(
        http.post(base.join("oauth/mcp/decision")?)
            .json(&json!({"authorization":authorization,
                "decision":{"_tag":"pairing-code","access":access,"code":pairing_code.trim()}}))
            .send()
            .await?,
    )
    .await?;
    ensure!(
        status.is_success(),
        "T3 refused the pairing code (it may be used, expired or lack the scopes for {access})"
    );
    let decided: Value = serde_json::from_str(&decided)?;
    let target = Url::parse(
        decided["redirectTo"]
            .as_str()
            .context("T3 gave no redirect")?,
    )?;
    ensure!(
        query(&target, "state").as_deref() == Some(state.as_str()),
        "T3 OAuth state mismatch"
    );
    ensure!(
        query(&target, "iss").as_deref() == Some(origin.as_str()),
        "T3 OAuth issuer mismatch"
    );
    let code = query(&target, "code").context("T3 denied the approval")?;
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", redirect),
        ("client_id", client_id.as_str()),
        ("code_verifier", verifier.as_str()),
        ("resource", resource.as_str()),
    ];
    let encoded = form
        .iter()
        .map(|(k, v)| format!("{k}={}", super::server::percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let (status, _, token) = bounded_body(
        http.post(base.join("oauth/mcp/token")?)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(encoded)
            .send()
            .await?,
    )
    .await?;
    ensure!(status.is_success(), "T3 token exchange failed: {status}");
    let token: Value = serde_json::from_str(&token)?;
    Ok(UpstreamCredential {
        url: origin,
        token: token["access_token"]
            .as_str()
            .context("T3 issued no token")?
            .to_owned(),
        access: access.to_owned(),
        expires: super::store::now() + token["expires_in"].as_u64().unwrap_or(0),
    })
}
