//! Gateway integration tests against an in-process fake of T3 Code's `/mcp` contract.
//! The fake mirrors T3's tool shapes (t3_thread_read/list/send/wait/interrupt, ...)
//! so ordering, idempotency, approvals and restarts are deterministic.
use anyhow::Result;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Bytes, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use omabridge::mcp::{
    server::{self, RunningServer, ServerConfig},
    store::{Access, GatewayStore, GrantScope, UpstreamCredential},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;

#[derive(Default)]
struct Thread {
    project: String,
    title: String,
    runs: Vec<Value>,
    items: Vec<Value>,
    active: Option<String>,
    pending: u64,
    /// Bumped on every change, so `updatedAt` moves as it does in T3.
    revision: u64,
}

#[derive(Default)]
struct Fake {
    environment: String,
    credential_requests: usize,
    revoke_on_read: Option<(GatewayStore, String)>,
    withdraw_on_read: Option<(GatewayStore, String, String)>,
    withdraw_on_descriptor: Option<(GatewayStore, String, String)>,
    threads: HashMap<String, Thread>,
    requests: HashMap<String, Value>,
    sends: usize,
    modes: Vec<String>,
}

impl Fake {
    fn push_item(thread: &mut Thread, run: &str, kind: &str, status: &str, text: &str) {
        let position = thread.items.len();
        thread.items.push(json!({"position":position,"visibility":"local","sourceThreadId":"x",
            "itemId":format!("item-{position}"),"runId":run,"messageId":null,"createdBy":if kind=="user_message"{"user"}else{"agent"},
            "creationSource":"web","type":kind,"status":status,"title":null,"text":text,"textTruncated":false,
            "nextTextOffset":null,"updatedAt":"2026-10-18T00:00:00Z"}));
    }
    fn run_mut<'a>(thread: &'a mut Thread, run: &str) -> &'a mut Value {
        thread.runs.iter_mut().find(|r| r["runId"] == run).unwrap()
    }
    /// Completes the active run with an assistant reply and starts the next queued one.
    fn complete(&mut self, thread_id: &str, text: &str) {
        let thread = self.threads.get_mut(thread_id).unwrap();
        let run = thread.active.take().unwrap();
        Self::push_item(thread, &run, "assistant_message", "completed", text);
        Self::run_mut(thread, &run)["status"] = "completed".into();
        thread.pending = 0;
        thread.revision += 1;
        if let Some(next) = thread.runs.iter_mut().find(|r| r["status"] == "queued") {
            next["status"] = "running".into();
            thread.active = next["runId"].as_str().map(str::to_owned);
        }
    }
    fn detail(&self, id: &str) -> Value {
        let t = &self.threads[id];
        let status = t
            .active
            .as_ref()
            .map(|run| t.runs.iter().find(|r| r["runId"] == *run).unwrap()["status"].clone())
            .unwrap_or_else(|| "idle".into());
        json!({"threadId":id,"projectId":t.project,"title":t.title,"createdBy":"user","creationSource":"web",
            "status":status,"latestRunId":t.runs.last().map(|r| r["runId"].clone()),"activeRunId":t.active,
            "providerInstanceId":"codex","model":"gpt-5.5-codex","runtimeMode":"approval-required","interactionMode":"default",
            "linkedPullRequest":null,"titleRegeneration":null,"branch":null,"worktreePath":null,"parentThreadId":null,
            "relationshipToParent":null,"runCount":t.runs.len(),"itemCount":t.items.len(),"pendingRequestCount":t.pending,
            "archived":false,"settled":false,"settledAt":null,"snoozed":false,"snoozedUntil":null,
            "createdAt":"2026-10-18T00:00:00Z","updatedAt":format!("2026-10-18T00:00:00.{:03}Z", t.revision)})
    }
    fn tool(
        &mut self,
        name: &str,
        a: &Value,
    ) -> std::result::Result<Value, (&'static str, String)> {
        if name == "t3_thread_read"
            && let Some((store, grant)) = self.revoke_on_read.take()
        {
            store.revoke(&grant).unwrap();
        }
        if name == "t3_thread_read"
            && let Some((store, policy, environment)) = self.withdraw_on_read.take()
        {
            store
                .select_managed_project(&policy, &environment, None, None, true)
                .unwrap();
        }
        let thread_id = a["threadId"].as_str().unwrap_or_default().to_owned();
        let missing = || {
            (
                "thread_not_found",
                format!("Thread {thread_id} is no longer available."),
            )
        };
        match name {
            "t3_project_list" => Ok(json!({"projects":[
                {"id":"p1","title":"Example Project","repositoryIdentity":{"displayName":"example/project"},"updatedAt":"x","deletedAt":null},
                {"id":"p2","title":"Other","repositoryIdentity":null,"updatedAt":"x","deletedAt":null}],"nextCursor":null})),
            "t3_thread_list" => {
                let project = a["projectId"].as_str().unwrap();
                let mut ids: Vec<_> = self
                    .threads
                    .iter()
                    .filter(|(_, t)| t.project == project)
                    .map(|(id, _)| id.clone())
                    .collect();
                ids.sort();
                let threads: Vec<_> = ids.iter().map(|id| {
                    let d = self.detail(id);
                    json!({"threadId":id,"title":d["title"],"status":d["status"],"latestRunId":d["latestRunId"],
                        "providerInstanceId":"codex","model":d["model"],"runtimeMode":d["runtimeMode"],"parentThreadId":null,
                        "itemCount":d["itemCount"],"createdAt":d["createdAt"],"updatedAt":d["updatedAt"]})
                }).collect();
                Ok(
                    json!({"projectId":project,"currentThreadId":null,"total":threads.len(),"threads":threads,"nextCursor":null}),
                )
            }
            "t3_thread_read" => {
                let detail = self
                    .threads
                    .contains_key(&thread_id)
                    .then(|| self.detail(&thread_id))
                    .ok_or_else(missing)?;
                let t = &self.threads[&thread_id];
                let messages = a["view"].as_str().unwrap_or("messages") == "messages";
                let after = a["afterPosition"].as_i64().unwrap_or(-1);
                let limit = a["limit"].as_u64().unwrap_or(50) as usize;
                let matching: Vec<_> = t
                    .items
                    .iter()
                    .filter(|i| i["position"].as_i64().unwrap() > after)
                    .filter(|i| {
                        !messages
                            || matches!(
                                i["type"].as_str(),
                                Some("user_message" | "assistant_message" | "proposed_plan")
                            )
                    })
                    .cloned()
                    .collect();
                let items: Vec<_> = matching.iter().take(limit).cloned().collect();
                let mut runs = t.runs.clone();
                runs.reverse();
                Ok(json!({"thread":detail,"recentRuns":runs,"items":items,
                    "nextPosition":items.last().map(|i| i["position"].clone()),"hasMore":matching.len()>items.len()}))
            }
            "t3_thread_send" => {
                self.modes
                    .push(a["mode"].as_str().unwrap_or("auto").to_owned());
                let key = a["clientRequestId"].as_str().unwrap().to_owned();
                if let Some(previous) = self.requests.get(&key) {
                    return Ok(previous.clone());
                }
                self.sends += 1;
                let thread = self.threads.get_mut(&thread_id).ok_or_else(missing)?;
                let run = format!("run:{thread_id}:{}", thread.runs.len() + 1);
                let busy = thread.active.is_some();
                thread.revision += 1;
                thread.runs.push(json!({"runId":run,"ordinal":thread.runs.len()+1,"status":if busy {"queued"} else {"running"},
                    "providerInstanceId":"codex","model":"gpt-5.5-codex","requestedAt":"t","startedAt":null,"completedAt":null}));
                if !busy {
                    thread.active = Some(run.clone());
                }
                Self::push_item(
                    thread,
                    &run,
                    "user_message",
                    "completed",
                    a["message"].as_str().unwrap(),
                );
                let result = json!({"threadId":thread_id,"messageId":format!("m-{run}"),"runId":run,
                    "status":if busy {"queued"} else {"running"},"delivery":if busy {"queued"} else {"started"}});
                self.requests.insert(key, result.clone());
                Ok(result)
            }
            "t3_thread_wait" => {
                let detail = self
                    .threads
                    .contains_key(&thread_id)
                    .then(|| self.detail(&thread_id))
                    .ok_or_else(missing)?;
                Ok(
                    json!({"threadId":thread_id,"runId":a["runId"],"status":detail["status"],"timedOut":true}),
                )
            }
            "t3_thread_interrupt" => {
                let thread = self.threads.get_mut(&thread_id).ok_or_else(missing)?;
                let run = a["runId"].as_str().unwrap().to_owned();
                let status = Self::run_mut(thread, &run)["status"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                if !matches!(status.as_str(), "running" | "queued" | "waiting") {
                    return Ok(json!({"threadId":thread_id,"runId":run,"status":"no_active_run"}));
                }
                Self::run_mut(thread, &run)["status"] = "interrupted".into();
                thread.revision += 1;
                if thread.active.as_deref() == Some(run.as_str()) {
                    thread.active = None;
                    thread.pending = 0;
                }
                Ok(json!({"threadId":thread_id,"runId":run,"status":"interrupt_requested"}))
            }
            "t3_pending_request_list" => Ok(json!({"requestIds":[]})),
            _ => Err(("capability_denied", format!("{name} not allowed"))),
        }
    }
}

async fn fake_t3(fake: Arc<Mutex<Fake>>) -> Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let fake = fake.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                    let fake = fake.clone();
                    async move {
                        if request.uri().path() == "/.well-known/t3/environment" {
                            if let Some((store, policy, environment)) =
                                fake.lock().unwrap().withdraw_on_descriptor.take()
                            {
                                store
                                    .select_managed_project(&policy, &environment, None, None, true)
                                    .unwrap();
                            }
                            return Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                                Bytes::from(
                                    json!({"environmentId":fake.lock().unwrap().environment})
                                        .to_string(),
                                ),
                            )));
                        }
                        let authorized = request
                            .headers()
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            == Some("Bearer upstream-secret");
                        if request.headers().contains_key("authorization") {
                            fake.lock().unwrap().credential_requests += 1;
                        }
                        let body: Value = serde_json::from_slice(
                            &request.into_body().collect().await.unwrap().to_bytes(),
                        )
                        .unwrap_or(Value::Null);
                        let mut response = Response::new(Full::new(Bytes::new()));
                        if !authorized {
                            *response.status_mut() = hyper::StatusCode::UNAUTHORIZED;
                            return Ok::<_, std::convert::Infallible>(response);
                        }
                        let Some(id) = body.get("id").cloned() else {
                            *response.status_mut() = hyper::StatusCode::ACCEPTED;
                            return Ok(response);
                        };
                        let result = match body["method"].as_str().unwrap() {
                            "initialize" => {
                                response
                                    .headers_mut()
                                    .insert("mcp-session-id", "fake-session".parse().unwrap());
                                json!({"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"T3 Code","version":"0"}})
                            }
                            _ => {
                                let name = body["params"]["name"].as_str().unwrap();
                                match fake
                                    .lock()
                                    .unwrap()
                                    .tool(name, &body["params"]["arguments"])
                                {
                                    Ok(value) => {
                                        json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":false})
                                    }
                                    Err((code, message)) => {
                                        json!({"content":[{"type":"text","text":json!({"_tag":"OrchestratorMcpFailure","code":code,"message":message}).to_string()}],"isError":true})
                                    }
                                }
                            }
                        };
                        response
                            .headers_mut()
                            .insert("content-type", "application/json".parse().unwrap());
                        *response.body_mut() = Full::new(Bytes::from(
                            json!({"jsonrpc":"2.0","id":id,"result":result}).to_string(),
                        ));
                        Ok(response)
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    Ok(format!("http://{address}"))
}

fn encode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", server::percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn seeded() -> Arc<Mutex<Fake>> {
    let mut fake = Fake::default();
    for (id, project, title) in [
        (
            "t-essential",
            "p1",
            "Evaluación de cargos: nivel 3 factores",
        ),
        ("t-other-session", "p1", "Otra sesión"),
        ("t-foreign", "p2", "Fuera de alcance"),
    ] {
        fake.threads.insert(
            id.into(),
            Thread {
                project: project.into(),
                title: title.into(),
                ..Thread::default()
            },
        );
    }
    // Existing history created from the T3 UI.
    let thread = fake.threads.get_mut("t-essential").unwrap();
    thread.runs.push(
        json!({"runId":"run:ui:1","ordinal":1,"status":"completed","providerInstanceId":"codex",
        "model":"gpt-5.5-codex","requestedAt":"t","startedAt":"t","completedAt":"t"}),
    );
    Fake::push_item(
        thread,
        "run:ui:1",
        "user_message",
        "completed",
        "Revisa el módulo de evaluación de cargos",
    );
    Fake::push_item(
        thread,
        "run:ui:1",
        "command_execution",
        "completed",
        "$ rg nivel",
    );
    Fake::push_item(
        thread,
        "run:ui:1",
        "assistant_message",
        "completed",
        "Listo, revisé el módulo.",
    );
    Arc::new(Mutex::new(fake))
}

struct Env {
    _dir: tempfile::TempDir,
    store: GatewayStore,
    server: Option<RunningServer>,
    issuer: String,
    base: String,
    fake: Arc<Mutex<Fake>>,
    http: reqwest::Client,
    events: bool,
}

impl Env {
    fn federated_grant(&self, environments: &[&str], access: Access) -> String {
        self.store
            .create_link_code(
                GrantScope {
                    managed_catalog: None,
                    environments: environments.iter().map(|id| (*id).into()).collect(),
                    label: "federation".into(),
                    projects: vec!["p1".into()],
                    all_projects: false,
                    sessions: Some(vec!["t-essential".into()]),
                    access,
                    ttl: 3600,
                },
                300,
            )
            .unwrap()
            .0
    }
    fn managed_grant(&self, policy: &str, access: Access) -> String {
        self.store
            .create_link_code(
                GrantScope {
                    managed_catalog: Some(policy.into()),
                    environments: vec![],
                    projects: vec![],
                    all_projects: false,
                    sessions: None,
                    label: "managed-test".into(),
                    access,
                    ttl: 3600,
                },
                300,
            )
            .unwrap()
            .0
    }
    async fn new() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        std::fs::set_permissions(
            dir.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )?;
        let fake = seeded();
        let t3 = fake_t3(fake.clone()).await?;
        let store = GatewayStore::open(&dir.path().join("state"))?;
        store.set_upstream(&UpstreamCredential {
            url: t3,
            token: "upstream-secret".into(),
            access: "approval-required".into(),
            expires: u64::MAX,
        })?;
        let mut env = Self {
            _dir: dir,
            store,
            server: None,
            issuer: String::new(),
            base: String::new(),
            fake,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            events: false,
        };
        env.restart().await?;
        Ok(env)
    }
    /// A gateway that also offers MCP Events, polling T3 every 100 ms and allowed
    /// to deliver to plain-http loopback callbacks.
    async fn with_events() -> Result<Self> {
        let mut env = Self::new().await?;
        env.events = true;
        env.restart().await?;
        Ok(env)
    }
    async fn restart(&mut self) -> Result<()> {
        self.server = None;
        // A restart keeps the same public origin, as a stable public URL does in production.
        let public_url = (!self.issuer.is_empty()).then(|| self.issuer.clone());
        let server = server::start(
            self.store.clone(),
            ServerConfig {
                listen: "127.0.0.1:0".parse()?,
                public_url,
                tls: None,
                redirect_hosts: vec![],
                events: self.events.then(|| server::EventsConfig {
                    poll: std::time::Duration::from_millis(100),
                    policy: omabridge::mcp::webhook::CallbackPolicy {
                        allow_loopback: true,
                    },
                    host: "example-host".into(),
                }),
            },
        )
        .await?;
        self.issuer = server.issuer.clone();
        self.base = format!("http://{}", server.address);
        self.server = Some(server);
        Ok(())
    }
    fn grant(&self, projects: &[&str], sessions: Option<&[&str]>, access: Access) -> String {
        self.store
            .create_link_code(
                GrantScope {
                    managed_catalog: None,
                    environments: Vec::new(),
                    label: "chatgpt".into(),
                    projects: projects.iter().map(|s| s.to_string()).collect(),
                    // No project listed: every project, including later ones.
                    all_projects: projects.is_empty(),
                    sessions: sessions.map(|s| s.iter().map(|s| s.to_string()).collect()),
                    access,
                    ttl: 3600,
                },
                300,
            )
            .unwrap()
            .0
    }
    /// The ChatGPT flow: DCR, authorize page + link code, PKCE token exchange.
    async fn connect(&self, link_code: &str) -> Result<Option<String>> {
        let redirect = "https://chatgpt.com/connector_platform_oauth_redirect";
        let registered: Value = self
            .http
            .post(format!("{}/oauth/register", self.base))
            .json(&json!({"client_name":"ChatGPT","redirect_uris":[redirect]}))
            .send()
            .await?
            .json()
            .await?;
        let client_id = registered["client_id"].as_str().unwrap().to_owned();
        let verifier = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 40]>());
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let resource = format!("{}/mcp", self.issuer);
        let params = [
            ("response_type", "code"),
            ("client_id", client_id.as_str()),
            ("redirect_uri", redirect),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("state", "st4te"),
            ("resource", resource.as_str()),
            ("link_code", link_code),
            ("action", "approve"),
        ];
        let response = self
            .http
            .post(format!("{}/oauth/authorize", self.base))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(encode(&params))
            .send()
            .await?;
        if response.status() != 303 {
            return Ok(None);
        }
        let location = reqwest::Url::parse(response.headers()["location"].to_str()?)?;
        let query: HashMap<_, _> = location.query_pairs().into_owned().collect();
        assert_eq!(query["state"], "st4te");
        assert_eq!(query["iss"], self.issuer);
        let token: Value = self
            .http
            .post(format!("{}/oauth/token", self.base))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(encode(&[
                ("grant_type", "authorization_code"),
                ("code", query["code"].as_str()),
                ("redirect_uri", redirect),
                ("client_id", client_id.as_str()),
                ("code_verifier", verifier.as_str()),
                ("resource", resource.as_str()),
            ]))
            .send()
            .await?
            .json()
            .await?;
        Ok(token["access_token"].as_str().map(str::to_owned))
    }
    async fn rpc(&self, token: &str, method: &str, params: Value) -> Result<(u16, Value)> {
        let response = self
            .http
            .post(format!("{}/mcp", self.base))
            .bearer_auth(token)
            .json(&json!({"jsonrpc":"2.0","id":7,"method":method,"params":params}))
            .send()
            .await?;
        let status = response.status().as_u16();
        Ok((status, response.json().await.unwrap_or(Value::Null)))
    }
    /// A 2026-07-28 request: version in `_meta`, mirrored with the method in headers.
    async fn modern(&self, token: &str, method: &str, mut params: Value) -> Result<(u16, Value)> {
        params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}});
        let mut request = self
            .http
            .post(format!("{}/mcp", self.base))
            .bearer_auth(token)
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", method);
        if let Some(name) = params["name"].as_str().filter(|_| method == "tools/call") {
            request = request.header("mcp-name", name);
        }
        let response = request
            .json(&json!({"jsonrpc":"2.0","id":9,"method":method,"params":params}))
            .send()
            .await?;
        let status = response.status().as_u16();
        Ok((status, response.json().await.unwrap_or(Value::Null)))
    }
    async fn call(&self, token: &str, tool: &str, args: Value) -> Result<(bool, Value)> {
        let (status, body) = self
            .rpc(token, "tools/call", json!({"name":tool,"arguments":args}))
            .await?;
        assert_eq!(status, 200, "{body}");
        let result = &body["result"];
        Ok((
            result["isError"].as_bool().unwrap(),
            result["structuredContent"].clone(),
        ))
    }
    async fn ok(&self, token: &str, tool: &str, args: Value) -> Value {
        let (failed, value) = self.call(token, tool, args).await.unwrap();
        assert!(!failed, "{tool}: {value}");
        value
    }
}

#[tokio::test]
async fn federation_isolates_colliding_ids_and_permissions() -> Result<()> {
    const A: &str = "11111111-1111-4111-8111-111111111111";
    const B: &str = "22222222-2222-4222-8222-222222222222";
    let env = Env::new().await?;
    let mut hosts = Vec::new();
    for id in [A, B] {
        let fake = seeded();
        fake.lock().unwrap().environment = id.into();
        let url = fake_t3(fake.clone()).await?;
        env.store
            .environment_store(id)?
            .set_upstream(&UpstreamCredential {
                url,
                token: "upstream-secret".into(),
                access: "approval-required".into(),
                expires: u64::MAX,
            })?;
        hosts.push(fake);
    }
    let token = env
        .connect(&env.federated_grant(&[A, B], Access::Operate))
        .await?
        .unwrap();
    let listed = env.ok(&token, "t3_list_environments", json!({})).await;
    assert_eq!(listed["environments"].as_array().unwrap().len(), 2);
    for id in [A, B] {
        let args = json!({"environment_id":id,"session_id":"t-essential", "message":"communication probe", "client_request_id":"same-request"});
        let first = env.ok(&token, "t3_send_message", args.clone()).await;
        assert_eq!(first["environment_id"], id);
        assert_eq!(first["duplicate"], false);
        assert_eq!(
            env.ok(&token, "t3_send_message", args).await["duplicate"],
            true
        );
    }
    assert_eq!(hosts[0].lock().unwrap().sends, 1);
    assert_eq!(hosts[1].lock().unwrap().sends, 1);
    hosts[0]
        .lock()
        .unwrap()
        .complete("t-essential", "reply from A");
    hosts[1]
        .lock()
        .unwrap()
        .complete("t-essential", "reply from B");
    for (id, reply) in [(A, "reply from A"), (B, "reply from B")] {
        let result = env.ok(&token, "t3_get_run_result", json!({"environment_id":id,"session_id":"t-essential","run_id":"run:t-essential:2"})).await;
        assert_eq!(result["final_text"], reply);
    }
    let limited = env
        .connect(&env.federated_grant(&[A], Access::Read))
        .await?
        .unwrap();
    for (name, args) in [
        ("t3_list_projects", json!({"environment_id":B})),
        ("t3_list_projects", json!({})),
        (
            "t3_get_session",
            json!({"environment_id":A,"session_id":"t-other-session"}),
        ),
        (
            "t3_send_message",
            json!({"environment_id":A,"session_id":"t-essential","message":"denied","client_request_id":"denied-send"}),
        ),
    ] {
        assert!(env.call(&limited, name, args).await?.0);
    }
    let local = env
        .connect(&env.grant(&["p1"], None, Access::Operate))
        .await?
        .unwrap();
    assert!(
        env.call(&local, "t3_list_projects", json!({"environment_id":A}))
            .await?
            .0
    );
    // A changed descriptor refuses credentials and writes; B continues working.
    hosts[0].lock().unwrap().environment = B.into();
    assert!(
        env.call(&token, "t3_list_projects", json!({"environment_id":A}))
            .await?
            .0
    );
    env.ok(&token, "t3_list_projects", json!({"environment_id":B}))
        .await;
    assert_eq!(hosts[0].lock().unwrap().sends, 1);
    // Expiry is re-read without restarting the gateway.
    let slot = env.store.environment_store(B)?;
    let mut credential = slot.upstream()?.unwrap();
    credential.expires = 0;
    slot.set_upstream(&credential)?;
    assert!(
        env.call(&token, "t3_list_projects", json!({"environment_id":B}))
            .await?
            .0
    );
    credential.expires = u64::MAX;
    credential.access = "read-only".into();
    slot.set_upstream(&credential)?;
    assert!(env.call(&token, "t3_send_message", json!({"environment_id":B,"session_id":"t-essential","message":"ceiling denied","client_request_id":"ceiling-denied"})).await?.0);
    assert_eq!(hosts[1].lock().unwrap().sends, 1);
    // Federated subscriptions cannot accidentally observe the legacy upstream.
    let (_, discovery) = env.rpc(&token, "server/discover", json!({})).await?;
    assert!(discovery["result"]["capabilities"].get("events").is_none());
    let grant = env
        .store
        .grants()?
        .into_iter()
        .find(|g| g.scope.access == Access::Operate && g.scope.environments.len() == 2)
        .unwrap();
    env.store.revoke(&grant.id)?;
    assert_eq!(env.rpc(&token, "tools/list", json!({})).await?.0, 401);
    Ok(())
}

#[tokio::test]
async fn revocation_during_upstream_read_withholds_history() -> Result<()> {
    let env = Env::new().await?;
    let token = env
        .connect(&env.grant(&["p1"], None, Access::Read))
        .await?
        .unwrap();
    let grant = env.store.grants()?.pop().unwrap();
    env.fake.lock().unwrap().revoke_on_read = Some((env.store.clone(), grant.id));
    let (failed, value) = env
        .call(
            &token,
            "t3_get_messages",
            json!({"session_id":"t-essential"}),
        )
        .await?;
    assert!(failed);
    assert_eq!(value["error"]["code"], "forbidden");
    assert!(!value.to_string().contains("revisé el módulo"));
    Ok(())
}

#[test]
fn federation_intersects_native_catalog_without_copying_registry() -> Result<()> {
    use omabridge::{Store, mcp::store::CatalogBinding};
    const A: &str = "11111111-1111-4111-8111-111111111111";
    let dir = tempfile::tempdir()?;
    let owner = Store::open(&dir.path().join("owner"), "owner")?;
    let guest = Store::open(&dir.path().join("guest"), "gateway")?;
    let now = omabridge::unix_time()?;
    let invite = owner.create_invite(&["t3".into()], std::time::Duration::from_secs(60), now)?;
    owner.claim(&invite, &guest.id()?, "gateway", now)?;
    owner.approve(&guest.id()?, now)?;
    let path = owner.root().join("client-catalog.json");
    let mut source = json!({"version":1,"revision":1,"clients":{guest.id()?:[A]},
        "environments":[{"id":A,"name":"host","enabled":true}],
        "endpoints":[{"environmentId":A,"descriptorEnvironmentId":A,"url":"https://host.example/"}]});
    omabridge::write_document(&path, &source, true)?;
    let gateway = GatewayStore::open(&dir.path().join("gateway"))?;
    gateway.set_catalog_binding(&CatalogBinding {
        device_state: owner.root().into(),
        client_id: guest.id()?,
    })?;
    assert!(gateway.catalog_allows(A)?);
    gateway.create_managed_policy("native-managed", Access::Operate)?;
    gateway.select_managed_project(
        "native-managed",
        A,
        Some("p1"),
        Some(vec!["s1".into()]),
        false,
    )?;
    let (code, _) = gateway.create_link_code(
        GrantScope {
            managed_catalog: Some("native-managed".into()),
            label: "native".into(),
            environments: vec![],
            projects: vec![],
            all_projects: false,
            sessions: None,
            access: Access::Operate,
            ttl: 3600,
        },
        300,
    )?;
    let grant = gateway.redeem_link_code(&code, "fixture", "localhost")?;
    let resolved = gateway.resolve_grant(&grant, Some(A))?;
    assert!(gateway.for_environment(A)?.grant_unchanged(&resolved)?);
    source["environments"][0]["enabled"] = false.into();
    source["revision"] = 2.into();
    omabridge::write_document(&path, &source, true)?;
    assert!(!gateway.catalog_allows(A)?);
    assert!(
        !gateway.for_environment(A)?.grant_unchanged(&resolved)?,
        "managed selection cannot bypass native catalog withdrawal"
    );
    source["environments"][0]["enabled"] = true.into();
    source["revision"] = 3.into();
    omabridge::write_document(&path, &source, true)?;
    assert!(gateway.catalog_allows(A)?);
    owner.revoke(&guest.id()?)?;
    assert!(!gateway.catalog_allows(A)?);
    std::fs::remove_file(&path)?;
    assert!(!gateway.catalog_allows(A)?);
    Ok(())
}

#[tokio::test]
async fn discovery_and_unauthenticated_access_are_rejected() -> Result<()> {
    let env = Env::new().await?;
    let response = env
        .http
        .post(format!("{}/mcp", env.base))
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"initialize"}))
        .send()
        .await?;
    assert_eq!(response.status(), 401);
    let challenge = response.headers()["www-authenticate"].to_str()?.to_owned();
    assert!(challenge.contains(&format!(
        "resource_metadata=\"{}/.well-known/oauth-protected-resource\"",
        env.issuer
    )));
    let prm: Value = env
        .http
        .get(format!("{}/.well-known/oauth-protected-resource", env.base))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(prm["resource"], format!("{}/mcp", env.issuer));
    let meta: Value = env
        .http
        .get(format!(
            "{}/.well-known/oauth-authorization-server",
            env.base
        ))
        .send()
        .await?
        .json()
        .await?;
    assert_eq!(meta["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(meta["authorization_response_iss_parameter_supported"], true);
    // Wrong/forged bearer, wrong link code, foreign redirect host, browser origin.
    assert_eq!(
        env.rpc(
            "not-a-real-token-but-exactly-43-characters-xx",
            "tools/list",
            json!({})
        )
        .await?
        .0,
        401
    );
    assert!(env.connect("AAAAA-BBBBB-CCCCC-DDDDD").await?.is_none());
    let bad = env
        .http
        .post(format!("{}/oauth/register", env.base))
        .json(&json!({"redirect_uris":["https://evil.example/cb"]}))
        .send()
        .await?;
    assert_eq!(bad.status(), 400);
    let cross = env
        .http
        .post(format!("{}/mcp", env.base))
        .header("origin", "https://evil.example")
        .send()
        .await?;
    assert_eq!(cross.status(), 403);
    // A link code is single-use.
    let code = env.grant(&["p1"], None, Access::Read);
    assert!(env.connect(&code).await?.is_some());
    assert!(env.connect(&code).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn lists_projects_sessions_and_paginates_history_within_scope() -> Result<()> {
    let env = Env::new().await?;
    let token = env
        .connect(&env.grant(&["p1"], None, Access::Read))
        .await?
        .unwrap();
    let (_, init) = env
        .rpc(
            &token,
            "initialize",
            json!({"protocolVersion":"2025-06-18"}),
        )
        .await?;
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    let (_, tools) = env.rpc(&token, "tools/list", json!({})).await?;
    let names: Vec<_> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_owned())
        .collect();
    assert!(
        names.contains(&"t3_get_messages".to_owned())
            && !names.contains(&"t3_send_message".to_owned())
    );
    let projects = env.ok(&token, "t3_list_projects", json!({})).await;
    assert_eq!(
        projects["projects"].as_array().unwrap().len(),
        1,
        "only granted projects are listed"
    );
    assert_eq!(projects["projects"][0]["title"], "Example Project");
    let sessions = env.ok(&token, "t3_list_sessions", json!({})).await;
    let ids: Vec<_> = sessions["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["session_id"].clone())
        .collect();
    assert_eq!(
        ids,
        vec![json!("t-essential"), json!("t-other-session")],
        "original T3 IDs are kept"
    );
    assert_eq!(sessions["sessions"][0]["agent"], "codex");
    let (failed, _) = env
        .call(&token, "t3_list_sessions", json!({"project_id":"p2"}))
        .await?;
    assert!(failed, "ungranted project is rejected");
    // Foreign-project session is invisible even by ID.
    let (failed, value) = env
        .call(&token, "t3_get_session", json!({"session_id":"t-foreign"}))
        .await?;
    assert!(failed && value["error"]["code"] == "not_found");
    let session = env
        .ok(
            &token,
            "t3_get_session",
            json!({"session_id":"t-essential"}),
        )
        .await;
    assert_eq!(session["status"], "idle");
    assert_eq!(session["recent_runs"][0]["status"], "completed");
    // History pagination with cursors: messages view skips tool items.
    let first = env
        .ok(
            &token,
            "t3_get_messages",
            json!({"session_id":"t-essential","limit":1}),
        )
        .await;
    assert_eq!(first["items"][0]["type"], "user_message");
    assert_eq!(first["has_more"], true);
    let second = env
        .ok(
            &token,
            "t3_get_messages",
            json!({"session_id":"t-essential","cursor":first["next_cursor"],"limit":5}),
        )
        .await;
    assert_eq!(second["items"].as_array().unwrap().len(), 1);
    assert_eq!(second["items"][0]["text"], "Listo, revisé el módulo.");
    // Read-only grants cannot write, even by calling an unlisted tool directly.
    let (failed, value) = env
        .call(
            &token,
            "t3_send_message",
            json!({"session_id":"t-essential","message":"x","client_request_id":"req-00000001"}),
        )
        .await?;
    assert!(failed && value["error"]["code"] == "forbidden");
    assert_eq!(env.fake.lock().unwrap().sends, 0);
    Ok(())
}

#[tokio::test]
async fn session_restricted_grant_hides_other_sessions() -> Result<()> {
    let env = Env::new().await?;
    let token = env
        .connect(&env.grant(&["p1"], Some(&["t-essential"]), Access::Operate))
        .await?
        .unwrap();
    let sessions = env.ok(&token, "t3_list_sessions", json!({})).await;
    assert_eq!(sessions["sessions"].as_array().unwrap().len(), 1);
    let (failed, _) = env.call(&token, "t3_send_message", json!({"session_id":"t-other-session","message":"hola","client_request_id":"req-00000002"})).await?;
    assert!(failed);
    assert_eq!(env.fake.lock().unwrap().sends, 0);
    Ok(())
}

#[tokio::test]
async fn send_continues_session_dedupes_queues_and_survives_restart() -> Result<()> {
    let mut env = Env::new().await?;
    let token = env
        .connect(&env.grant(&["p1"], None, Access::Operate))
        .await?
        .unwrap();
    let send = |id: &str, text: &str| json!({"session_id":"t-essential","message":text,"client_request_id":id});
    let first = env
        .ok(
            &token,
            "t3_send_message",
            send("chatgpt-req-0001", "Analiza el nivel con 3 factores"),
        )
        .await;
    assert_eq!(first["status"], "running");
    assert_eq!(first["delivery"], "started");
    let run = first["run_id"].as_str().unwrap().to_owned();
    // Duplicate request: same run, no second message in T3.
    let again = env
        .ok(
            &token,
            "t3_send_message",
            send("chatgpt-req-0001", "Analiza el nivel con 3 factores"),
        )
        .await;
    assert_eq!(again["run_id"], run);
    assert_eq!(again["duplicate"], true);
    assert_eq!(env.fake.lock().unwrap().sends, 1);
    // Same ID reused for a different message is a conflict, not a silent resend.
    let (failed, value) = env
        .call(
            &token,
            "t3_send_message",
            send("chatgpt-req-0001", "otro texto"),
        )
        .await?;
    assert!(failed && value["error"]["code"] == "conflict");
    // Concurrency: a second message while Codex is running is queued, never steered.
    let queued = env
        .ok(
            &token,
            "t3_send_message",
            send("chatgpt-req-0002", "Luego agrega pruebas"),
        )
        .await;
    assert_eq!(queued["status"], "queued");
    assert_eq!(queued["delivery"], "queued");
    assert!(env.fake.lock().unwrap().modes.iter().all(|m| m == "queue"));
    // The same session (no new conversation) holds both messages.
    assert_eq!(env.fake.lock().unwrap().threads.len(), 3);
    // Approval request surfaces as waiting_for_approval.
    {
        let mut fake = env.fake.lock().unwrap();
        let thread = fake.threads.get_mut("t-essential").unwrap();
        thread.pending = 1;
        Fake::run_mut(thread, &run)["status"] = "waiting".into();
        Fake::push_item(
            thread,
            &run,
            "approval_request",
            "waiting",
            "Permitir: cargo test",
        );
    }
    let status = env
        .ok(
            &token,
            "t3_get_run_status",
            json!({"session_id":"t-essential","run_id":run}),
        )
        .await;
    assert_eq!(status["run"]["status"], "waiting_for_approval");
    let session = env
        .ok(
            &token,
            "t3_get_session_status",
            json!({"session_id":"t-essential"}),
        )
        .await;
    assert_eq!(session["status"], "waiting_for_approval");
    let pending = env
        .ok(
            &token,
            "t3_list_pending_requests",
            json!({"session_id":"t-essential"}),
        )
        .await;
    assert_eq!(pending["approvals_waiting"], 1);
    // Events: the waiting item is not consumed, so nothing is lost on reconnect.
    let events = env
        .ok(
            &token,
            "t3_get_events",
            json!({"session_id":"t-essential","run_id":run}),
        )
        .await;
    assert_eq!(events["in_progress"]["kind"], "approval_request");
    let cursor = events["next_cursor"].clone();
    {
        let mut fake = env.fake.lock().unwrap();
        let thread = fake.threads.get_mut("t-essential").unwrap();
        let last = thread.items.len() - 1;
        thread.items[last]["status"] = "completed".into();
        Fake::run_mut(thread, &run)["status"] = "running".into();
        drop(fake);
        env.fake.lock().unwrap().complete(
            "t-essential",
            "El nivel no se mostraba porque el resumen exigía 8 factores.",
        );
    }
    // Gateway restart: token, ledger and cursor remain valid.
    env.restart().await?;
    let resumed = env
        .ok(
            &token,
            "t3_get_events",
            json!({"session_id":"t-essential","cursor":cursor}),
        )
        .await;
    let kinds: Vec<_> = resumed["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        kinds,
        vec!["approval_request", "assistant_message"],
        "no loss, no duplicate"
    );
    let again = env
        .ok(
            &token,
            "t3_get_events",
            json!({"session_id":"t-essential","cursor":resumed["next_cursor"]}),
        )
        .await;
    assert!(again["events"].as_array().unwrap().is_empty());
    let result = env
        .ok(
            &token,
            "t3_get_run_result",
            json!({"session_id":"t-essential","run_id":run}),
        )
        .await;
    assert_eq!(result["run"]["status"], "completed");
    assert_eq!(
        result["final_text"],
        "El nivel no se mostraba porque el resumen exigía 8 factores."
    );
    let duplicate_after_restart = env
        .ok(
            &token,
            "t3_send_message",
            send("chatgpt-req-0001", "Analiza el nivel con 3 factores"),
        )
        .await;
    assert_eq!(duplicate_after_restart["run_id"], run);
    assert_eq!(env.fake.lock().unwrap().sends, 2);
    // The queued message started after the first completed, in the same session.
    let queued_status = env
        .ok(
            &token,
            "t3_get_run_status",
            json!({"session_id":"t-essential","run_id":queued["run_id"]}),
        )
        .await;
    assert_eq!(queued_status["run"]["status"], "running");
    // Cancellation.
    let cancelled = env.ok(&token, "t3_cancel_run", json!({"session_id":"t-essential","run_id":queued["run_id"],"client_request_id":"cancel-0001"})).await;
    assert_eq!(cancelled["result"], "interrupt_requested");
    assert_eq!(cancelled["run"]["status"], "cancelled");
    let waited = env
        .ok(
            &token,
            "t3_wait_run",
            json!({"session_id":"t-essential","run_id":queued["run_id"],"timeout_seconds":1}),
        )
        .await;
    assert_eq!(waited["run"]["terminal"], true);
    Ok(())
}

#[tokio::test]
async fn revocation_is_immediate_and_audit_has_no_secrets() -> Result<()> {
    let env = Env::new().await?;
    let token = env
        .connect(&env.grant(&["p1"], None, Access::Operate))
        .await?
        .unwrap();
    env.ok(&token, "t3_send_message", json!({"session_id":"t-essential","message":"secreto del repo: XYZZY","client_request_id":"audit-req-001"})).await;
    let grant = env.store.grants()?.pop().unwrap();
    assert!(env.store.revoke(&grant.id)?);
    assert_eq!(env.rpc(&token, "tools/list", json!({})).await?.0, 401);
    let audit = std::fs::read_to_string(env.store.root().join("audit.jsonl"))?;
    assert!(audit.contains("\"tool\":\"t3_send_message\"") && audit.contains("grant_approved"));
    assert!(
        !audit.contains("XYZZY") && !audit.contains(&token) && !audit.contains("upstream-secret")
    );
    let mode = std::fs::metadata(env.store.root().join("audit.jsonl"))?.permissions();
    assert_eq!(std::os::unix::fs::PermissionsExt::mode(&mode) & 0o077, 0);
    Ok(())
}

#[tokio::test]
async fn public_listener_requires_tls() -> Result<()> {
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )?;
    let store = GatewayStore::open(&dir.path().join("state"))?;
    let result = server::start(
        store,
        ServerConfig {
            listen: "0.0.0.0:0".parse()?,
            public_url: Some("https://t3.example.com".into()),
            tls: None,
            redirect_hosts: vec![],
            events: None,
        },
    )
    .await;
    assert!(result.is_err());
    assert!(server::public_origin("http://t3.example.com").is_err());
    Ok(())
}

/// What a ChatGPT-like webhook receiver saw: one entry per request.
#[derive(Clone, Debug)]
struct Received {
    path: String,
    headers: HashMap<String, String>,
    raw: Vec<u8>,
    body: Value,
}

/// A loopback webhook receiver. `/ok/*` echoes verification challenges,
/// `/wrong/*` answers a different challenge, `/gone/*` answers 410 to events.
async fn receiver() -> Result<(String, Arc<Mutex<Vec<Received>>>)> {
    receiver_with_policy_hook(None).await
}

async fn receiver_with_policy_hook(
    hook: Option<(GatewayStore, String, String)>,
) -> Result<(String, Arc<Mutex<Vec<Received>>>)> {
    let hook = Arc::new(Mutex::new(hook));
    let seen = Arc::new(Mutex::new(Vec::<Received>::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let log = log.clone();
            let hook = hook.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                    let log = log.clone();
                    let hook = hook.clone();
                    async move {
                        let path = request.uri().path().to_owned();
                        let headers = request
                            .headers()
                            .iter()
                            .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap().to_owned()))
                            .collect();
                        let raw = request
                            .into_body()
                            .collect()
                            .await
                            .unwrap()
                            .to_bytes()
                            .to_vec();
                        let body: Value = serde_json::from_slice(&raw).unwrap_or(Value::Null);
                        log.lock().unwrap().push(Received {
                            path: path.clone(),
                            headers,
                            raw,
                            body: body.clone(),
                        });
                        let mut response = Response::new(Full::new(Bytes::new()));
                        if body["type"] == "verification" {
                            if let Some((store, policy, environment)) = hook.lock().unwrap().take()
                            {
                                store
                                    .select_managed_project(&policy, &environment, None, None, true)
                                    .unwrap();
                            }
                            let challenge = if path.starts_with("/wrong") {
                                json!("not-the-challenge")
                            } else {
                                body["challenge"].clone()
                            };
                            *response.body_mut() =
                                Full::new(Bytes::from(json!({"challenge":challenge}).to_string()));
                        } else if path.starts_with("/retry") {
                            *response.status_mut() = hyper::StatusCode::SERVICE_UNAVAILABLE;
                        } else if path.starts_with("/gone") {
                            *response.status_mut() = hyper::StatusCode::GONE;
                        }
                        Ok::<_, std::convert::Infallible>(response)
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });
    Ok((format!("http://{address}"), seen))
}

fn whsec(byte: u8) -> String {
    format!(
        "whsec_{}",
        base64::engine::general_purpose::STANDARD.encode([byte; 32])
    )
}

/// The request carries a valid Standard Webhooks signature for `secret`.
fn signed_with(received: &Received, secret: &str) -> bool {
    let id = &received.headers["webhook-id"];
    let timestamp: u64 = received.headers["webhook-timestamp"].parse().unwrap();
    let expected = omabridge::mcp::webhook::signature(&[secret], id, timestamp, &received.raw);
    received.headers["webhook-signature"]
        .split(' ')
        .any(|signature| signature == expected)
}

async fn wait_for(seen: &Arc<Mutex<Vec<Received>>>, what: impl Fn(&Received) -> bool) -> Received {
    for _ in 0..100 {
        if let Some(found) = seen.lock().unwrap().iter().find(|r| what(r)) {
            return found.clone();
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("expected webhook never arrived");
}

fn events_named(seen: &Arc<Mutex<Vec<Received>>>, name: &str) -> Vec<Received> {
    seen.lock()
        .unwrap()
        .iter()
        .filter(|r| r.body["name"] == name)
        .cloned()
        .collect()
}

#[tokio::test]
async fn modern_protocol_discovers_events_and_validates_headers() -> Result<()> {
    let env = Env::with_events().await?;
    let token = env
        .connect(&env.grant(&["p1"], None, Access::Read))
        .await?
        .unwrap();
    let (status, discover) = env.modern(&token, "server/discover", json!({})).await?;
    assert_eq!(status, 200, "{discover}");
    let result = &discover["result"];
    assert_eq!(result["resultType"], "complete");
    assert!(
        result["supportedVersions"]
            .as_array()
            .unwrap()
            .contains(&json!("2026-07-28"))
    );
    assert_eq!(result["capabilities"]["events"], json!({}));
    assert!(result["capabilities"]["tools"].is_object());

    let (_, listed) = env.modern(&token, "events/list", json!({})).await?;
    let names: Vec<_> = listed["result"]["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(names, ["t3.run.finished", "t3.session.attention_required"]);
    for event in listed["result"]["events"].as_array().unwrap() {
        assert_eq!(event["delivery"], json!(["webhook"]));
        assert_eq!(event["inputSchema"]["additionalProperties"], false);
    }
    let (_, tools) = env.modern(&token, "tools/list", json!({})).await?;
    assert_eq!(tools["result"]["resultType"], "complete");
    let (status, called) = env
        .modern(
            &token,
            "tools/call",
            json!({"name":"t3_list_projects","arguments":{}}),
        )
        .await?;
    assert_eq!(status, 200, "{called}");
    assert_eq!(called["result"]["isError"], false);

    // Mirrored headers must match the body.
    let send = |version: &'static str, method: &'static str, header_method: &'static str| {
        env.http
            .post(format!("{}/mcp", env.base))
            .bearer_auth(&token)
            .header("mcp-protocol-version", version)
            .header("mcp-method", header_method)
            .json(
                &json!({"jsonrpc":"2.0","id":3,"method":method,"params":{"_meta":
                {"io.modelcontextprotocol/protocolVersion":version}}}),
            )
            .send()
    };
    let mismatch = send("2026-07-28", "tools/list", "events/list").await?;
    assert_eq!(mismatch.status(), 400);
    assert_eq!(mismatch.json::<Value>().await?["error"]["code"], -32020);
    let unsupported = send("2099-01-01", "tools/list", "tools/list").await?;
    assert_eq!(unsupported.status(), 400);
    let body: Value = unsupported.json().await?;
    assert_eq!(body["error"]["code"], -32022);
    assert_eq!(body["error"]["data"]["requested"], "2099-01-01");
    let missing_name = env
        .http
        .post(format!("{}/mcp", env.base))
        .bearer_auth(&token)
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "=?base64?dDNfbGlzdF9zZXNzaW9ucw==?=")
        .json(&json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"t3_list_projects",
            "arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}))
        .send()
        .await?;
    assert_eq!(
        missing_name.status(),
        400,
        "encoded Mcp-Name decodes to another tool"
    );
    let (status, unknown) = env.modern(&token, "nothing/here", json!({})).await?;
    assert_eq!(
        (status, unknown["error"]["code"].clone()),
        (404, json!(-32601))
    );
    // Legacy clients keep working, without events in their handshake.
    let (status, init) = env
        .rpc(
            &token,
            "initialize",
            json!({"protocolVersion":"2025-06-18"}),
        )
        .await?;
    assert_eq!(status, 200);
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert!(init["result"].get("resultType").is_none());
    Ok(())
}

#[tokio::test]
async fn subscriptions_verify_callbacks_and_reject_bad_requests() -> Result<()> {
    let env = Env::with_events().await?;
    let (hooks, seen) = receiver().await?;
    let token = env
        .connect(&env.grant(&["p1"], None, Access::Operate))
        .await?
        .unwrap();
    let subscribe = |name: &str, arguments: Value, url: String, secret: String| {
        env.modern(
            &token,
            "events/subscribe",
            json!({"name":name,"arguments":arguments,
                "delivery":{"mode":"webhook","url":url,"secret":secret},"cursor":null}),
        )
    };
    let url = format!("{hooks}/ok/a");
    let (status, first) = subscribe(
        "t3.run.finished",
        json!({"project_id":"p1","statuses":["failed","completed"]}),
        url.clone(),
        whsec(1),
    )
    .await?;
    assert_eq!(status, 200, "{first}");
    let result = &first["result"];
    assert!(result["id"].as_str().unwrap().starts_with("sub_"));
    assert_eq!(result["cursor"], Value::Null);
    assert_eq!(result["truncated"], false);
    assert!(result["refreshBefore"].as_str().unwrap().ends_with('Z'));
    let challenge = wait_for(&seen, |r| r.body["type"] == "verification").await;
    assert!(challenge.headers["webhook-id"].starts_with("msg_verification_"));
    assert_eq!(
        challenge.headers["x-mcp-subscription-id"],
        result["id"].as_str().unwrap()
    );
    assert!(signed_with(&challenge, &whsec(1)));

    // Same identity with reordered keys: same subscription, no second challenge.
    let (_, again) = subscribe(
        "t3.run.finished",
        json!({"statuses":["completed","failed"],"project_id":"p1"}),
        url.clone(),
        whsec(1),
    )
    .await?;
    assert_eq!(again["result"]["id"], result["id"]);
    let challenges = seen
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r.body["type"] == "verification")
        .count();
    assert_eq!(challenges, 1);

    let error = |reply: &Value| {
        (
            reply["error"]["code"].clone(),
            reply["error"]["data"]["reason"].clone(),
        )
    };
    let (_, foreign) = subscribe(
        "t3.run.finished",
        json!({"project_id":"p2"}),
        url.clone(),
        whsec(1),
    )
    .await?;
    assert_eq!(error(&foreign).0, -32602);
    let (_, hidden) = subscribe(
        "t3.run.finished",
        json!({"session_id":"t-foreign"}),
        url.clone(),
        whsec(1),
    )
    .await?;
    assert_eq!(error(&hidden).0, -32602);
    let (_, weak) = subscribe(
        "t3.run.finished",
        json!({}),
        url.clone(),
        "whsec_c2hvcnQ=".into(),
    )
    .await?;
    assert_eq!(error(&weak).0, -32602);
    let (_, unknown) = subscribe("t3.nothing", json!({}), url.clone(), whsec(1)).await?;
    assert_eq!(error(&unknown).0, -32602);
    let (_, wrong) = subscribe(
        "t3.run.finished",
        json!({}),
        format!("{hooks}/wrong/a"),
        whsec(1),
    )
    .await?;
    assert_eq!(error(&wrong), (json!(-32015), json!("challenge_failed")));
    let (_, private) = subscribe(
        "t3.run.finished",
        json!({}),
        "https://10.1.2.3/cb".into(),
        whsec(1),
    )
    .await?;
    assert_eq!(error(&private), (json!(-32015), json!("blocked_address")));
    let (_, plain) = subscribe(
        "t3.run.finished",
        json!({}),
        "http://hooks.example.com/cb".into(),
        whsec(1),
    )
    .await?;
    assert_eq!(error(&plain), (json!(-32015), json!("invalid_url")));

    // Unsubscribe is idempotent and scoped to the connection.
    let unsubscribe = json!({"name":"t3.run.finished","arguments":{"project_id":"p1","statuses":["completed","failed"]},
        "delivery":{"mode":"webhook","url":url}});
    let (status, gone) = env
        .modern(&token, "events/unsubscribe", unsubscribe.clone())
        .await?;
    assert_eq!(
        (status, gone["result"].clone()),
        (200, json!({"resultType":"complete"}))
    );
    assert!(env.store.subscriptions()?.is_empty());
    let (status, _) = env
        .modern(&token, "events/unsubscribe", unsubscribe)
        .await?;
    assert_eq!(status, 200);
    // The audit records subscriptions without the signing secret.
    let audit = serde_json::to_string(&env.store.audit_tail(100)?)?;
    assert!(audit.contains("events_subscribe"));
    assert!(!audit.contains(&whsec(1)[6..]));
    Ok(())
}

#[tokio::test]
async fn finished_runs_and_blocked_sessions_are_delivered_signed_once() -> Result<()> {
    let mut env = Env::with_events().await?;
    let (hooks, seen) = receiver().await?;
    let token = env
        .connect(&env.grant(&["p1"], None, Access::Operate))
        .await?
        .unwrap();
    let subscribe = |name: &str, arguments: Value, path: &str| {
        env.modern(
            &token,
            "events/subscribe",
            json!({"name":name,"arguments":arguments,
                "delivery":{"mode":"webhook","url":format!("{hooks}{path}"),"secret":whsec(2)}}),
        )
    };
    let (_, finished) = subscribe(
        "t3.run.finished",
        json!({"session_id":"t-essential"}),
        "/ok/runs",
    )
    .await?;
    let finished_id = finished["result"]["id"].as_str().unwrap().to_owned();
    let (_, attention) =
        subscribe("t3.session.attention_required", json!({}), "/ok/attention").await?;
    assert!(attention["result"]["id"].is_string(), "{attention}");
    // Let the watcher take its baseline: the run that finished earlier is not news.
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert!(events_named(&seen, "t3.run.finished").is_empty());

    let sent = env
        .ok(
            &token,
            "t3_send_message",
            json!({"session_id":"t-essential",
            "message":"Run the checks","client_request_id":"events-run-0001"}),
        )
        .await;
    let run_id = sent["run_id"].as_str().unwrap().to_owned();
    env.fake
        .lock()
        .unwrap()
        .complete("t-essential", "All checks passed.");
    let delivered = wait_for(&seen, |r| r.body["name"] == "t3.run.finished").await;
    assert_eq!(delivered.path, "/ok/runs");
    assert!(signed_with(&delivered, &whsec(2)));
    assert_eq!(
        delivered.headers["webhook-id"],
        delivered.body["eventId"].as_str().unwrap()
    );
    assert_eq!(delivered.headers["x-mcp-subscription-id"], finished_id);
    assert_eq!(delivered.headers["content-type"], "application/json");
    assert!(
        delivered.body["eventId"]
            .as_str()
            .unwrap()
            .starts_with("evt_")
    );
    assert_eq!(delivered.body["cursor"], Value::Null);
    let data = &delivered.body["data"];
    assert_eq!(data["host"], "example-host");
    assert_eq!(data["project_id"], "p1");
    assert_eq!(data["session_id"], "t-essential");
    assert_eq!(data["run_id"], run_id);
    assert_eq!(data["status"], "completed");
    assert_eq!(data["summary"], "All checks passed.");
    assert_eq!(data["started_by_this_connection"], true);
    assert_eq!(data["detail"]["tool"], "t3_get_run_result");
    assert_eq!(data["status_check"]["tool"], "t3_get_session_status");

    // A run in another session does not match the session filter.
    env.fake
        .lock()
        .unwrap()
        .threads
        .get_mut("t-other-session")
        .unwrap()
        .runs
        .push(json!({
        "runId":"run:other:1","ordinal":1,"status":"completed","completedAt":"t"}));
    env.fake
        .lock()
        .unwrap()
        .threads
        .get_mut("t-other-session")
        .unwrap()
        .revision += 1;

    // A session that starts waiting for its owner raises one attention event.
    env.ok(
        &token,
        "t3_send_message",
        json!({"session_id":"t-essential",
        "message":"Deploy it","client_request_id":"events-run-0002"}),
    )
    .await;
    {
        let mut fake = env.fake.lock().unwrap();
        let thread = fake.threads.get_mut("t-essential").unwrap();
        thread.pending = 1;
        thread.revision += 1;
    }
    let blocked = wait_for(&seen, |r| r.body["name"] == "t3.session.attention_required").await;
    assert_eq!(blocked.path, "/ok/attention");
    assert_eq!(blocked.body["data"]["pending_request_count"], 1);
    assert_eq!(blocked.body["data"]["answer_in"], "T3 Code");
    assert_eq!(
        blocked.body["data"]["detail"]["tool"],
        "t3_list_pending_requests"
    );
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert_eq!(events_named(&seen, "t3.run.finished").len(), 1);
    assert_eq!(
        events_named(&seen, "t3.session.attention_required").len(),
        1
    );

    // A restart neither repeats delivered events nor loses the subscriptions.
    env.restart().await?;
    env.fake
        .lock()
        .unwrap()
        .complete("t-essential", "Deployed.");
    let second = wait_for(&seen, |r| r.body["data"]["summary"] == "Deployed.").await;
    assert_ne!(second.body["eventId"], delivered.body["eventId"]);
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert_eq!(events_named(&seen, "t3.run.finished").len(), 2);

    // Revoking the grant stops delivery and drops its subscriptions.
    let grant = env.store.grants()?[0].id.clone();
    env.store.revoke(&grant)?;
    assert!(env.store.subscriptions()?.is_empty());
    let (status, _) = env.modern(&token, "events/list", json!({})).await?;
    assert_eq!(status, 401);
    env.fake
        .lock()
        .unwrap()
        .threads
        .get_mut("t-essential")
        .unwrap()
        .runs
        .push(json!({
        "runId":"run:late","ordinal":99,"status":"failed","completedAt":"t"}));
    env.fake
        .lock()
        .unwrap()
        .threads
        .get_mut("t-essential")
        .unwrap()
        .revision += 1;
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert_eq!(events_named(&seen, "t3.run.finished").len(), 2);
    Ok(())
}

#[tokio::test]
async fn a_gone_callback_ends_its_subscription() -> Result<()> {
    let env = Env::with_events().await?;
    let (hooks, seen) = receiver().await?;
    let token = env
        .connect(&env.grant(&["p1"], None, Access::Operate))
        .await?
        .unwrap();
    let (_, subscribed) = env
        .modern(
            &token,
            "events/subscribe",
            json!({"name":"t3.run.finished","arguments":{},
            "delivery":{"mode":"webhook","url":format!("{hooks}/gone/x"),"secret":whsec(3)}}),
        )
        .await?;
    assert!(subscribed["result"]["id"].is_string(), "{subscribed}");
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    env.ok(
        &token,
        "t3_send_message",
        json!({"session_id":"t-other-session",
        "message":"go","client_request_id":"events-gone-0001"}),
    )
    .await;
    env.fake.lock().unwrap().complete("t-other-session", "done");
    wait_for(&seen, |r| r.body["name"] == "t3.run.finished").await;
    for _ in 0..40 {
        if env.store.subscriptions()?.is_empty() {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("a 410 answer must remove the subscription");
}

#[tokio::test]
async fn an_all_projects_grant_sees_and_watches_every_project() -> Result<()> {
    let env = Env::with_events().await?;
    let (hooks, seen) = receiver().await?;
    let token = env
        .connect(&env.grant(&[], None, Access::Operate))
        .await?
        .unwrap();
    let projects = env.ok(&token, "t3_list_projects", json!({})).await;
    let ids: Vec<_> = projects["projects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["project_id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids, ["p1", "p2"]);
    let (failed, needs) = env.call(&token, "t3_list_sessions", json!({})).await?;
    assert!(failed);
    assert_eq!(needs["error"]["code"], "invalid_arguments");
    let foreign = env
        .ok(&token, "t3_list_sessions", json!({"project_id":"p2"}))
        .await;
    assert_eq!(foreign["sessions"][0]["session_id"], "t-foreign");

    let (_, subscribed) = env
        .modern(
            &token,
            "events/subscribe",
            json!({"name":"t3.run.finished","arguments":{},
            "delivery":{"mode":"webhook","url":format!("{hooks}/ok/all"),"secret":whsec(4)}}),
        )
        .await?;
    assert!(subscribed["result"]["id"].is_string(), "{subscribed}");
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    env.ok(
        &token,
        "t3_send_message",
        json!({"session_id":"t-foreign",
        "message":"go","client_request_id":"events-all-0001"}),
    )
    .await;
    env.fake
        .lock()
        .unwrap()
        .complete("t-foreign", "Done in p2.");
    let event = wait_for(&seen, |r| r.body["name"] == "t3.run.finished").await;
    assert_eq!(event.body["data"]["project_id"], "p2");
    assert_eq!(event.body["data"]["summary"], "Done in p2.");
    assert!(
        env.store
            .create_link_code(
                GrantScope {
                    managed_catalog: None,
                    environments: Vec::new(),
                    label: "x".into(),
                    projects: vec!["p1".into()],
                    all_projects: true,
                    sessions: None,
                    access: Access::Read,
                    ttl: 60,
                },
                60,
            )
            .is_err(),
        "a list and every project are exclusive"
    );
    Ok(())
}

#[tokio::test]
async fn federated_webhooks_isolate_colliding_runs_and_recheck_identity() -> Result<()> {
    const A: &str = "11111111-1111-4111-8111-111111111111";
    const B: &str = "22222222-2222-4222-8222-222222222222";
    let env = Env::with_events().await?;
    let (hooks, seen) = receiver().await?;
    let mut hosts = Vec::new();
    for id in [A, B] {
        let fake = seeded();
        fake.lock().unwrap().environment = id.into();
        let url = fake_t3(fake.clone()).await?;
        env.store
            .environment_store(id)?
            .set_upstream(&UpstreamCredential {
                url,
                token: "upstream-secret".into(),
                access: "approval-required".into(),
                expires: u64::MAX,
            })?;
        hosts.push(fake);
    }
    let token = env
        .connect(&env.federated_grant(&[A, B], Access::Operate))
        .await?
        .unwrap();
    let (_, discovered) = env.modern(&token, "server/discover", json!({})).await?;
    assert_eq!(discovered["result"]["capabilities"]["events"], json!({}));
    let subscribe = |arguments: Value| {
        env.modern(&token, "events/subscribe", json!({"name":"t3.run.finished","arguments":arguments,"delivery":{"mode":"webhook","url":format!("{hooks}/ok/federation"),"secret":whsec(4)}}))
    };
    for arguments in [
        json!({}),
        json!({"environment_id":"33333333-3333-4333-8333-333333333333"}),
        json!({"environment_id":A,"session_id":"t-other-session"}),
        json!({"environment_id":A,"project_id":"p2"}),
    ] {
        let (_, result) = subscribe(arguments).await?;
        assert!(result["error"].is_object(), "{result}");
    }
    for id in [A, B] {
        let (_, result) =
            subscribe(json!({"environment_id":id,"project_id":"p1","session_id":"t-essential"}))
                .await?;
        assert!(result["result"]["id"].is_string(), "{result}");
    }
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    for (i, id) in [A, B].iter().enumerate() {
        env.ok(&token,"t3_send_message",json!({"environment_id":id,"session_id":"t-essential","message":"probe","client_request_id":"same-event-request"})).await;
        hosts[i]
            .lock()
            .unwrap()
            .complete("t-essential", &format!("Reply {id}"));
    }
    for id in [A, B] {
        let event = wait_for(&seen, |r| {
            r.body["name"] == "t3.run.finished" && r.body["data"]["environment_id"] == id
        })
        .await;
        assert!(signed_with(&event, &whsec(4)));
        assert_eq!(event.body["data"]["summary"], format!("Reply {id}"));
        assert_eq!(
            event.body["data"]["detail"]["arguments"]["environment_id"],
            id
        );
        assert_eq!(event.body["data"]["started_by_this_connection"], true);
    }
    let events = events_named(&seen, "t3.run.finished");
    assert_eq!(events.len(), 2);
    assert_ne!(events[0].body["eventId"], events[1].body["eventId"]);
    // A changed descriptor must withhold the next summary and event. Other host survives.
    hosts[0].lock().unwrap().environment = B.into();
    let credential = env.store.environment_store(A)?.upstream()?.unwrap();
    let upstream = omabridge::mcp::upstream::Upstream::for_environment(&credential, A)?;
    assert!(upstream.verify_environment().await.is_err());
    let grant = env
        .store
        .grants()?
        .into_iter()
        .find(|g| g.scope.environments.len() == 2)
        .unwrap();
    env.store.revoke(&grant.id)?;
    assert!(env.store.subscriptions()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn federated_delivery_retry_stops_after_identity_changes() -> Result<()> {
    const A: &str = "11111111-1111-4111-8111-111111111111";
    let env = Env::with_events().await?;
    let fake = seeded();
    fake.lock().unwrap().environment = A.into();
    let url = fake_t3(fake.clone()).await?;
    env.store
        .environment_store(A)?
        .set_upstream(&UpstreamCredential {
            url,
            token: "upstream-secret".into(),
            access: "approval-required".into(),
            expires: u64::MAX,
        })?;
    let token = env
        .connect(&env.federated_grant(&[A], Access::Operate))
        .await?
        .unwrap();
    let (hooks, seen) = receiver().await?;
    let (_,sub) = env.modern(&token,"events/subscribe",json!({"name":"t3.run.finished","arguments":{"environment_id":A,"session_id":"t-essential"},"delivery":{"mode":"webhook","url":format!("{hooks}/retry/identity"),"secret":whsec(8)}})).await?;
    assert!(sub["result"]["id"].is_string(), "{sub}");
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    env.ok(&token,"t3_send_message",json!({"environment_id":A,"session_id":"t-essential","message":"probe","client_request_id":"identity-retry-0001"})).await;
    fake.lock().unwrap().complete("t-essential", "Scoped reply");
    wait_for(&seen, |r| r.body["name"] == "t3.run.finished").await;
    fake.lock().unwrap().environment = "22222222-2222-4222-8222-222222222222".into();
    tokio::time::sleep(std::time::Duration::from_millis(2400)).await;
    assert_eq!(
        events_named(&seen, "t3.run.finished").len(),
        1,
        "identity-changed host must not deliver queued retries"
    );
    assert!(
        env.store
            .audit_tail(100)?
            .iter()
            .any(|r| r["event"] == "event_delivery" && r["outcome"] == "access_revoked")
    );
    Ok(())
}

#[tokio::test]
async fn runtime_follows_port_with_fixed_identity_and_withholds_credentials_from_replacements()
-> Result<()> {
    use omabridge::mcp::store::RuntimeBinding;
    const A: &str = "11111111-1111-4111-8111-111111111111";
    const B: &str = "22222222-2222-4222-8222-222222222222";
    let env = Env::new().await?;
    env.fake.lock().unwrap().environment = A.into();
    let runtime = env.store.root().join("official-runtime.json");
    let original = env.store.upstream()?.unwrap();
    let port = reqwest::Url::parse(&original.url)?.port().unwrap();
    omabridge::write_document(&runtime, &json!({"port":port}), true)?;
    std::fs::set_permissions(
        &runtime,
        std::os::unix::fs::PermissionsExt::from_mode(0o664),
    )?;
    env.store.set_runtime_binding(&RuntimeBinding {
        runtime: runtime.clone(),
        environment_id: A.into(),
    })?;
    let token = env
        .connect(&env.grant(&["p1"], Some(&["t-essential"]), Access::Read))
        .await?
        .unwrap();
    env.ok(
        &token,
        "t3_get_session_status",
        json!({"session_id":"t-essential"}),
    )
    .await;
    let federated = env
        .connect(&env.federated_grant(&[A], Access::Read))
        .await?
        .unwrap();
    let selected = env
        .ok(
            &federated,
            "t3_get_session_status",
            json!({"environment_id":A,"session_id":"t-essential"}),
        )
        .await;
    assert_eq!(selected["environment_id"], A);
    assert!(
        env.store.environment_store(A)?.upstream()?.is_none(),
        "local credential was copied into a slot"
    );
    let old_requests = env.fake.lock().unwrap().credential_requests;
    let second = seeded();
    second.lock().unwrap().environment = A.into();
    let new_url = fake_t3(second.clone()).await?;
    let new_port = reqwest::Url::parse(&new_url)?.port().unwrap();
    omabridge::write_document(&runtime, &json!({"port":new_port}), true)?;
    env.fake.lock().unwrap().environment = B.into();
    env.ok(
        &token,
        "t3_get_session_status",
        json!({"session_id":"t-essential"}),
    )
    .await;
    assert_eq!(
        env.fake.lock().unwrap().credential_requests,
        old_requests,
        "stale port received a credential"
    );
    let new_requests = second.lock().unwrap().credential_requests;
    second.lock().unwrap().environment = B.into();
    assert!(
        env.call(
            &token,
            "t3_get_session_status",
            json!({"session_id":"t-essential"})
        )
        .await?
        .0
    );
    assert_eq!(
        second.lock().unwrap().credential_requests,
        new_requests,
        "replacement on new port received a credential"
    );
    omabridge::write_document(&runtime, &json!({"port":0}), true)?;
    assert!(
        env.call(&token, "t3_list_projects", json!({})).await?.0,
        "invalid runtime fell back to stale port"
    );
    assert_eq!(
        env.store.upstream()?.unwrap().url,
        original.url,
        "stored consent mutated"
    );
    assert_eq!(env.store.upstream()?.unwrap().expires, original.expires);
    Ok(())
}

#[tokio::test]
async fn legacy_webhook_retry_respects_pinned_runtime_identity() -> Result<()> {
    use omabridge::mcp::store::RuntimeBinding;
    const A: &str = "11111111-1111-4111-8111-111111111111";
    let env = Env::with_events().await?;
    env.fake.lock().unwrap().environment = A.into();
    let runtime = env.store.root().join("official-runtime.json");
    let port = reqwest::Url::parse(&env.store.upstream()?.unwrap().url)?
        .port()
        .unwrap();
    omabridge::write_document(&runtime, &json!({"port":port}), true)?;
    env.store.set_runtime_binding(&RuntimeBinding {
        runtime,
        environment_id: A.into(),
    })?;
    let token = env
        .connect(&env.grant(&["p1"], Some(&["t-essential"]), Access::Operate))
        .await?
        .unwrap();
    let (hooks, seen) = receiver().await?;
    let (_,sub) = env.modern(&token,"events/subscribe",json!({"name":"t3.run.finished","arguments":{"session_id":"t-essential"},"delivery":{"mode":"webhook","url":format!("{hooks}/retry/legacy-runtime"),"secret":whsec(9)}})).await?;
    assert!(sub["result"]["id"].is_string(), "{sub}");
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    env.ok(&token,"t3_send_message",json!({"session_id":"t-essential","message":"probe","client_request_id":"legacy-runtime-0001"})).await;
    env.fake
        .lock()
        .unwrap()
        .complete("t-essential", "Scoped reply");
    wait_for(&seen, |r| r.body["name"] == "t3.run.finished").await;
    env.fake.lock().unwrap().environment = "22222222-2222-4222-8222-222222222222".into();
    tokio::time::sleep(std::time::Duration::from_millis(2400)).await;
    assert_eq!(events_named(&seen, "t3.run.finished").len(), 1);
    Ok(())
}

#[tokio::test]
async fn managed_catalog_changes_selection_with_the_same_oauth_token_and_stable_tools() -> Result<()>
{
    const A: &str = "11111111-1111-4111-8111-111111111111";
    const B: &str = "22222222-2222-4222-8222-222222222222";
    let mut env = Env::new().await?;
    let mut hosts = Vec::new();
    for id in [A, B] {
        let fake = seeded();
        fake.lock().unwrap().environment = id.into();
        env.store
            .environment_store(id)?
            .set_upstream(&UpstreamCredential {
                url: fake_t3(fake.clone()).await?,
                token: "upstream-secret".into(),
                access: "approval-required".into(),
                expires: u64::MAX,
            })?;
        hosts.push(fake);
    }
    env.store.create_managed_policy("dot", Access::Operate)?;
    let token = env
        .connect(&env.managed_grant("dot", Access::Operate))
        .await?
        .unwrap();
    let read_token = env
        .connect(&env.managed_grant("dot", Access::Read))
        .await?
        .unwrap();
    let static_token = env
        .connect(&env.federated_grant(&[A], Access::Read))
        .await?
        .unwrap();
    let tools_before = env.rpc(&token, "tools/list", json!({})).await?.1;
    assert!(
        tools_before["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "t3_list_environments")
    );
    assert!(
        env.ok(&token, "t3_list_environments", json!({})).await["environments"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        env.call(&token, "t3_list_projects", json!({})).await?.0,
        "empty managed catalog must never fall back to legacy local access"
    );
    env.store.select_managed_project(
        "dot",
        A,
        Some("p1"),
        Some(vec!["t-essential".into()]),
        false,
    )?;
    assert_eq!(
        env.ok(&token, "t3_list_environments", json!({})).await["environments"][0]["environment_id"],
        A
    );
    assert_eq!(
        env.ok(&token, "t3_list_projects", json!({"environment_id":A}))
            .await["projects"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let send = json!({"environment_id":A,"session_id":"t-essential","message":"managed selection","client_request_id":"managed-same-token-0001"});
    env.ok(&token, "t3_send_message", send.clone()).await;
    env.store.select_managed_project(
        "dot",
        A,
        Some("p2"),
        Some(vec!["t-foreign".into()]),
        false,
    )?;
    env.store.select_managed_project(
        "dot",
        B,
        Some("p1"),
        Some(vec!["t-other-session".into()]),
        false,
    )?;
    assert_eq!(
        env.ok(&token, "t3_list_environments", json!({})).await["environments"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        env.ok(&token, "t3_list_projects", json!({"environment_id":A}))
            .await["projects"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    env.ok(
        &token,
        "t3_get_session",
        json!({"environment_id":A,"session_id":"t-foreign"}),
    )
    .await;
    assert!(
        env.call(
            &token,
            "t3_get_session",
            json!({"environment_id":B,"session_id":"t-essential"})
        )
        .await?
        .0,
        "same session ID on another host is not implied consent"
    );
    assert!(
        env.call(&read_token, "t3_send_message", send.clone())
            .await?
            .0,
        "policy cannot raise the initial read ceiling"
    );
    assert_eq!(hosts[0].lock().unwrap().sends, 1);
    env.store
        .select_managed_project("dot", A, Some("p1"), None, true)?;
    assert!(
        env.call(
            &token,
            "t3_get_messages",
            json!({"environment_id":A,"session_id":"t-essential"})
        )
        .await?
        .0
    );
    assert!(
        env.call(&token, "t3_send_message", send.clone()).await?.0,
        "withdrawal also denies an existing idempotency receipt"
    );
    env.ok(
        &static_token,
        "t3_get_session",
        json!({"environment_id":A,"session_id":"t-essential"}),
    )
    .await;
    assert!(
        env.call(
            &static_token,
            "t3_get_session",
            json!({"environment_id":B,"session_id":"t-other-session"})
        )
        .await?
        .0,
        "legacy static grant never adopts managed hosts"
    );
    env.store
        .select_managed_project("dot", A, None, None, true)?;
    let requests = hosts[0].lock().unwrap().credential_requests;
    assert!(
        env.call(
            &token,
            "t3_get_session",
            json!({"environment_id":A,"session_id":"t-foreign"})
        )
        .await?
        .0
    );
    assert_eq!(
        hosts[0].lock().unwrap().credential_requests,
        requests,
        "withdrawn host denied before network"
    );
    env.restart().await?;
    assert_eq!(
        env.rpc(&token, "tools/list", json!({})).await?.1,
        tools_before,
        "OAuth and tools survive policy changes and restart"
    );
    let listed = env.ok(&token, "t3_list_environments", json!({})).await;
    assert_eq!(listed["environments"].as_array().unwrap().len(), 1);
    assert_eq!(listed["environments"][0]["environment_id"], B);
    env.store
        .create_managed_policy("read-policy", Access::Read)?;
    env.store.select_managed_project(
        "read-policy",
        B,
        Some("p1"),
        Some(vec!["t-other-session".into()]),
        false,
    )?;
    let policy_read_token = env
        .connect(&env.managed_grant("read-policy", Access::Operate))
        .await?
        .unwrap();
    env.ok(
        &policy_read_token,
        "t3_get_session",
        json!({"environment_id":B,"session_id":"t-other-session"}),
    )
    .await;
    assert!(env.call(&policy_read_token, "t3_send_message", json!({"environment_id":B,"session_id":"t-other-session","message":"read policy denies","client_request_id":"read-policy-deny-0001"})).await?.0);
    let grant = env
        .store
        .authenticate(&token, &format!("{}/mcp", env.issuer))?
        .unwrap();
    env.store.revoke(&grant.id)?;
    assert_eq!(env.rpc(&token, "tools/list", json!({})).await?.0, 401);
    Ok(())
}

#[tokio::test]
async fn managed_withdrawal_during_read_withholds_result_and_during_send_prevents_queueing()
-> Result<()> {
    const A: &str = "11111111-1111-4111-8111-111111111111";
    let env = Env::new().await?;
    env.fake.lock().unwrap().environment = A.into();
    env.store
        .environment_store(A)?
        .set_upstream(&env.store.upstream()?.unwrap())?;
    env.store.create_managed_policy("live", Access::Operate)?;
    let token = env
        .connect(&env.managed_grant("live", Access::Operate))
        .await?
        .unwrap();
    for name in ["t3_get_messages", "t3_send_message"] {
        env.store.select_managed_project(
            "live",
            A,
            Some("p1"),
            Some(vec!["t-essential".into()]),
            false,
        )?;
        env.fake.lock().unwrap().withdraw_on_read =
            Some((env.store.clone(), "live".into(), A.into()));
        let (failed, result) = env.call(&token, name, json!({"environment_id":A,"session_id":"t-essential","message":"must not queue","client_request_id":"withdraw-during-send-0001"})).await?;
        assert!(failed, "{result}");
        assert!(!result.to_string().contains("revisé el módulo"));
        assert_eq!(env.fake.lock().unwrap().sends, 0);
    }
    Ok(())
}

#[test]
fn managed_policy_admin_updates_are_serialized_and_old_scope_deserialization_stays_static()
-> Result<()> {
    const A: &str = "11111111-1111-4111-8111-111111111111";
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )?;
    let store = GatewayStore::open(dir.path())?;
    store.create_managed_policy("concurrent", Access::Read)?;
    let workers: Vec<_> = (0..16)
        .map(|i| {
            let store = store.clone();
            std::thread::spawn(move || {
                store
                    .select_managed_project(
                        "concurrent",
                        A,
                        Some(&format!("p{i}")),
                        Some(vec![format!("s{i}")]),
                        false,
                    )
                    .unwrap()
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(
        store.managed_policy("concurrent")?.unwrap().environments[A].len(),
        16
    );
    let old: GrantScope = serde_json::from_value(
        json!({"label":"old","environments":[],"projects":["p1"],"all_projects":false,"sessions":["s1"],"access":"read","ttl":3600}),
    )?;
    assert!(old.managed_catalog.is_none());
    assert!(
        store
            .create_link_code(
                GrantScope {
                    managed_catalog: Some("concurrent".into()),
                    ..old
                },
                300
            )
            .is_err(),
        "mixed static/managed consent must be rejected"
    );
    Ok(())
}

#[tokio::test]
async fn managed_events_withdraw_filters_and_cancel_queued_retries_without_new_oauth() -> Result<()>
{
    const A: &str = "11111111-1111-4111-8111-111111111111";
    let env = Env::with_events().await?;
    env.fake.lock().unwrap().environment = A.into();
    env.store
        .environment_store(A)?
        .set_upstream(&env.store.upstream()?.unwrap())?;
    env.store.create_managed_policy("events", Access::Operate)?;
    env.store.select_managed_project(
        "events",
        A,
        Some("p1"),
        Some(vec!["t-essential".into()]),
        false,
    )?;
    let token = env
        .connect(&env.managed_grant("events", Access::Operate))
        .await?
        .unwrap();
    let (hooks, seen) = receiver().await?;
    let args = json!({"environment_id":A,"project_id":"p1","session_id":"t-essential"});
    let subscribe = || {
        env.modern(&token, "events/subscribe", json!({"name":"t3.run.finished","arguments":args,"delivery":{"mode":"webhook","url":format!("{hooks}/retry/managed"),"secret":whsec(4)}}))
    };
    assert!(subscribe().await?.1["result"]["id"].is_string());
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    env.ok(&token, "t3_send_message", json!({"environment_id":A,"session_id":"t-essential","message":"event before withdrawal","client_request_id":"managed-event-0001"})).await;
    env.fake
        .lock()
        .unwrap()
        .complete("t-essential", "managed event");
    let first = wait_for(&seen, |r| r.body["name"] == "t3.run.finished").await;
    assert!(signed_with(&first, &whsec(4)));
    env.store
        .select_managed_project("events", A, Some("p1"), None, true)?;
    assert!(
        subscribe().await?.1["error"].is_object(),
        "withdrawn filters cannot subscribe"
    );
    assert!(
        env.call(
            &token,
            "t3_get_events",
            json!({"environment_id":A,"session_id":"t-essential"})
        )
        .await?
        .0
    );
    // Re-add before the retry: a queued payload from the old revision is still cancelled.
    env.store.select_managed_project(
        "events",
        A,
        Some("p1"),
        Some(vec!["t-essential".into()]),
        false,
    )?;
    tokio::time::sleep(std::time::Duration::from_millis(2400)).await;
    assert_eq!(
        events_named(&seen, "t3.run.finished").len(),
        1,
        "old revision payload must never be replayed after remove/re-add"
    );
    assert!(
        subscribe().await?.1["result"]["id"].is_string(),
        "same OAuth token may resubscribe under the current policy"
    );
    Ok(())
}

#[tokio::test]
async fn managed_policy_withdrawn_during_callback_verification_cannot_install_subscription()
-> Result<()> {
    const A: &str = "11111111-1111-4111-8111-111111111111";
    let env = Env::with_events().await?;
    env.fake.lock().unwrap().environment = A.into();
    env.store
        .environment_store(A)?
        .set_upstream(&env.store.upstream()?.unwrap())?;
    env.store
        .create_managed_policy("verify-race", Access::Read)?;
    env.store.select_managed_project(
        "verify-race",
        A,
        Some("p1"),
        Some(vec!["t-essential".into()]),
        false,
    )?;
    let token = env
        .connect(&env.managed_grant("verify-race", Access::Read))
        .await?
        .unwrap();
    let (hooks, _) =
        receiver_with_policy_hook(Some((env.store.clone(), "verify-race".into(), A.into())))
            .await?;
    let (_, result) = env.modern(&token, "events/subscribe", json!({"name":"t3.run.finished","arguments":{"environment_id":A,"session_id":"t-essential"},"delivery":{"mode":"webhook","url":format!("{hooks}/ok/race"),"secret":whsec(2)}})).await?;
    assert!(result["error"].is_object(), "{result}");
    assert!(env.store.subscriptions()?.is_empty());
    assert!(
        env.ok(&token, "t3_list_environments", json!({})).await["environments"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn managed_withdrawal_during_descriptor_check_sends_no_bearer_request() -> Result<()> {
    const A: &str = "11111111-1111-4111-8111-111111111111";
    let env = Env::new().await?;
    env.fake.lock().unwrap().environment = A.into();
    env.store
        .environment_store(A)?
        .set_upstream(&env.store.upstream()?.unwrap())?;
    env.store
        .create_managed_policy("descriptor-race", Access::Operate)?;
    env.store.select_managed_project(
        "descriptor-race",
        A,
        Some("p1"),
        Some(vec!["t-essential".into()]),
        false,
    )?;
    let token = env
        .connect(&env.managed_grant("descriptor-race", Access::Operate))
        .await?
        .unwrap();
    let before = env.fake.lock().unwrap().credential_requests;
    env.fake.lock().unwrap().withdraw_on_descriptor =
        Some((env.store.clone(), "descriptor-race".into(), A.into()));
    assert!(env.call(&token, "t3_send_message", json!({"environment_id":A,"session_id":"t-essential","message":"denied before bearer","client_request_id":"descriptor-race-denied-0001"})).await?.0);
    assert_eq!(env.fake.lock().unwrap().credential_requests, before);
    assert_eq!(env.fake.lock().unwrap().sends, 0);
    Ok(())
}
