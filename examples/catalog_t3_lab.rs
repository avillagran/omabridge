//! Opt-in integration lab: two REAL isolated T3 instances, TLS and QUIC.
//! No fake OAuth or shell handlers. Logs and credentials stay in the private lab.
#[path = "../src/headless.rs"]
mod headless;
use anyhow::{Context, Result, ensure};
use omabridge::{
    Client, Invitation, NetOptions, Node, Store,
    delegated_enrollment::load_authority,
    enrollment::{Enrollment, EnrollmentAuthority, LocalT3Environment},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
struct CountedIssuer {
    inner: Arc<dyn EnrollmentAuthority>,
    completed: Arc<AtomicU64>,
}
impl EnrollmentAuthority for CountedIssuer {
    fn issue<'a>(
        &'a self,
        client: &'a str,
        environment: &'a str,
        now: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Enrollment>> + Send + 'a>> {
        self.inner.issue(client, environment, now)
    }
    fn issue_delegated<'a>(
        &'a self,
        upstream: &'a str,
        client: &'a str,
        environment: &'a str,
        now: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Enrollment>> + Send + 'a>> {
        Box::pin(async move {
            let enrollment = self
                .inner
                .issue_delegated(upstream, client, environment, now)
                .await?;
            self.completed.fetch_add(1, Ordering::SeqCst);
            Ok(enrollment)
        })
    }
}
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

fn write_policy(path: &std::path::Path, value: &Value) -> Result<()> {
    omabridge::write_document(path, value, true)
}
async fn command(binary: &std::path::Path, home: &std::path::Path, args: &[&str]) -> Result<Value> {
    let output = tokio::process::Command::new(binary)
        .args(["auth", "session", "issue", "--base-dir"])
        .arg(home)
        .args(args)
        .arg("--json")
        .kill_on_drop(true)
        .output()
        .await?;
    ensure!(output.status.success(), "lab credential issuance failed");
    serde_json::from_slice(&output.stdout).context("invalid lab issuance receipt")
}
fn free_port() -> Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}
async fn request(
    port: u16,
    token: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<Value> {
    if path == "/api/orchestration/dispatch" {
        let token = token.to_owned();
        let body = body.context("missing command")?;
        return tokio::task::spawn_blocking(move || {
            t3_protocol::Connection::new(
                &format!("http://127.0.0.1:{port}"),
                None,
                t3_protocol::Credential::bearer(&token).map_err(anyhow::Error::msg)?,
            )
            .map_err(anyhow::Error::msg)?
            .rpc(
                if body["type"] == "project.create" {
                    "projects.mutate"
                } else {
                    "orchestration.dispatchCommand"
                },
                body,
            )
            .map_err(anyhow::Error::msg)
        })
        .await?;
    }
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut request = http
        .request(method.parse()?, format!("http://127.0.0.1:{port}{path}"))
        .bearer_auth(token)
        .header("x-t3-orchestration-protocol", "2");
    if let Some(body) = body {
        request = request
            .header("content-type", "application/json")
            .body(body.to_string());
    }
    let response = request.send().await?;
    ensure!(
        response.status().is_success(),
        "real T3 lab request failed: {} {}",
        path,
        response.status()
    );
    serde_json::from_str(&response.text().await?).context("invalid T3 lab response")
}
async fn authenticated(port: u16, token: &str) -> Result<bool> {
    request(port, token, "GET", "/api/auth/session", None)
        .await?
        .get("authenticated")
        .and_then(Value::as_bool)
        .context("missing authentication verdict")
}
#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let root = PathBuf::from(args.next().context("pass a NEW lab directory")?);
    let binary = PathBuf::from(args.next().context("pass absolute T3 binary")?);
    let self_test = args.next().as_deref() == Some("--self-test");
    let session_ttl = if self_test { 6 } else { 30 };
    ensure!(
        !root.exists() && root.is_absolute(),
        "lab directory must be new and absolute"
    );
    std::fs::create_dir_all(&root)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    let owner = Store::open(&root.join("owner"), "RealT3Lab")?;
    let cert = rcgen::generate_simple_self_signed(vec!["10.0.2.2".into(), "127.0.0.1".into()])?;
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
    )?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let mut children = Vec::new();
    let mut environments = Vec::new();
    let mut issuers = BTreeMap::new();
    let mut tasks = Vec::new();
    let mut admins = Vec::new();
    for label in ["GATEWAY", "HOST"] {
        let port = free_port()?;
        let home = root.join(label);
        let mut child = headless::spawn(&binary, &home, port, &owner.id()?, &root)?;
        child.wait_ready(port).await?;
        let _private_log = &child.log;
        let http = reqwest::Client::builder().no_proxy().build()?;
        let descriptor: Value = serde_json::from_str(
            &http
                .get(format!(
                    "http://127.0.0.1:{port}/.well-known/t3/environment"
                ))
                .send()
                .await?
                .text()
                .await?,
        )?;
        let id = descriptor["environmentId"]
            .as_str()
            .context("missing UUID")?
            .to_owned();
        let receipt = command(
            &binary,
            &home,
            &[
                "--scope",
                "orchestration:read",
                "--scope",
                "orchestration:operate",
                "--scope",
                "access:read",
                "--scope",
                "access:write",
                "--ttl",
                "5m",
                "--label",
                "isolated-lab-admin",
            ],
        )
        .await?;
        let token = receipt["token"]
            .as_str()
            .context("missing admin token")?
            .to_owned();
        let project = format!("lab-{label}");
        let workspace = home.join("workspace");
        request(port, &token, "POST", "/api/orchestration/dispatch", Some(json!({"type":"project.create","commandId":format!("project-{label}"),"projectId":project,"title":label,"workspaceRoot":workspace,"createWorkspaceRootIfMissing":false}))).await.context("lab create project")?;
        request(port, &token, "POST", "/api/orchestration/dispatch", Some(json!({"type":"thread.create","commandId":format!("thread-{label}"),"threadId":format!("thread-{label}"),"projectId":project,"title":format!("{label} isolated thread"),"modelSelection":{"instanceId":"codex","model":"gpt-5"},"runtimeMode":"approval-required","interactionMode":"default","branch":null,"worktreePath":null,"createdBy":"user","creationSource":"web"}))).await.context("lab create thread")?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let tls_port = listener.local_addr()?.port();
        let a = acceptor.clone();
        tasks.push(tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let a = a.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = a.accept(socket).await
                        && let Ok(mut upstream) = TcpStream::connect(("127.0.0.1", port)).await
                    {
                        let _ = tokio::io::copy_bidirectional(&mut tls, &mut upstream).await;
                    }
                });
            }
        }));
        issuers.insert(
            id.clone(),
            LocalT3Environment {
                base_dir: home,
                descriptor_url: format!("http://127.0.0.1:{port}/"),
            },
        );
        environments.push(json!({"id":id,"name":label,"url":format!("https://10.0.2.2:{tls_port}/"),"threadId":format!("thread-{label}")}));
        admins.push((
            port,
            token,
            receipt["sessionId"].as_str().unwrap().to_owned(),
        ));
        children.push(child);
    }
    // HOST owns its T3 directory and issues over a second authenticated QUIC
    // endpoint. Android pairs only with the selected desktop bridge.
    let issuer_store = Store::open(&root.join("issuer"), "HostIssuerLab")?;
    let delegated_id = environments[1]["id"]
        .as_str()
        .context("missing HOST")?
        .to_owned();
    let gateway_id = environments[0]["id"]
        .as_str()
        .context("missing GATEWAY")?
        .to_owned();
    let host_environment = issuers.remove(&delegated_id).context("missing issuer")?;
    let local_environment = issuers
        .remove(&gateway_id)
        .context("missing local issuer")?;
    let issuer_path = root.join("issuer-policy.json");
    let mut issuer_policy = json!({"version":1,"local":{"t3Binary":binary,"ttlSeconds":session_ttl,"environments":{
        &delegated_id:{"baseDir":host_environment.base_dir,"descriptorUrl":host_environment.descriptor_url}}},"delegates":{}});
    write_policy(&issuer_path, &issuer_policy)?;
    let issued_count = Arc::new(AtomicU64::new(0));
    let issuer_node = Node::start_reserved_with_authority(
        issuer_store.clone(),
        BTreeMap::from([("t3".into(), "127.0.0.1:9".parse()?)]),
        NetOptions::loopback(),
        issuer_store.reserve_runtime()?,
        Some(Arc::new(CountedIssuer {
            inner: load_authority(issuer_store.clone(), &issuer_path)?,
            completed: issued_count.clone(),
        })),
    )
    .await?;
    let boot = Client::new(owner.clone(), NetOptions::loopback()).await?;
    let now = omabridge::unix_time()?;
    let host_invite = Invitation {
        version: 1,
        address: issuer_node.addr(),
        token: issuer_store.create_invite(&["t3".into()], Duration::from_secs(600), now)?,
        name: "HostIssuerLab".into(),
        expires: now + 600,
        manage: false,
    };
    boot.pair(&host_invite, "RealT3Lab", now).await?;
    issuer_store.approve(&owner.id()?, now)?;
    boot.pair(&host_invite, "RealT3Lab", now).await?;
    boot.close().await;
    let desktop_path = root.join("desktop-policy.json");
    write_policy(
        &desktop_path,
        &json!({"version":1,"local":{"t3Binary":binary,"ttlSeconds":session_ttl,"environments":{
        &gateway_id:{"baseDir":local_environment.base_dir,"descriptorUrl":local_environment.descriptor_url}}},"remote":{&delegated_id:issuer_store.id()?}}),
    )?;
    let node = Node::start_reserved_with_authority(
        owner.clone(),
        BTreeMap::from([("t3".into(), "127.0.0.1:9".parse()?)]),
        NetOptions::loopback(),
        owner.reserve_runtime()?,
        Some(load_authority(owner.clone(), &desktop_path)?),
    )
    .await?;
    ensure!(
        node.addr().id != issuer_node.addr().id,
        "lab requires distinct bridge identities"
    );
    if self_test {
        let result = native_self_test(
            &root,
            &owner,
            &node,
            &issuer_store,
            &issuer_path,
            &mut issuer_policy,
            &delegated_id,
            &environments,
            &admins,
            &cert.cert.pem(),
            &issued_count,
        )
        .await;
        node.shutdown().await;
        issuer_node.shutdown().await;
        for task in tasks {
            task.abort();
        }
        for child in &mut children {
            child.stop().await?;
        }
        result?;
        println!(
            "{}",
            json!({"twoBridgeRealT3":true,"writeDenied":true,"crossHostDenied":true,"expiryDenied":true,"delegationWithdrawalDeniesNewSessions":true,"existingSessionRemainsUntilExpiry":true,"issuedCount":issued_count.load(Ordering::SeqCst)})
        );
        return Ok(());
    }
    let now = omabridge::unix_time()?;
    let token = owner.create_invite(&["t3".into()], Duration::from_secs(600), now)?;
    let port = node.addr().ip_addrs().next().unwrap().port();
    let address = iroh::EndpointAddr::new(node.addr().id)
        .with_ip_addr(format!("10.0.2.2:{port}").parse::<std::net::SocketAddr>()?);
    let invitation = Invitation {
        version: 1,
        address,
        token,
        name: "RealT3Lab".into(),
        expires: now + 600,
        manage: false,
    };
    let control = TcpListener::bind("127.0.0.1:0").await?;
    println!(
        "{}",
        json!({"port":control.local_addr()?.port(),"bridgeId":owner.id()?,"backend":"real-isolated-t3","issuerBridgeId":issuer_store.id()?,"delegatedEnvironmentId":delegated_id})
    );
    let mut phone = String::new();
    loop {
        let (mut socket, _) = control.accept().await?;
        let mut bytes = Vec::new();
        let mut buffer = [0; 8192];
        let header_end;
        loop {
            let n = socket.read(&mut buffer).await?;
            ensure!(
                n > 0 && bytes.len() + n <= 16384,
                "invalid lab control request"
            );
            bytes.extend_from_slice(&buffer[..n]);
            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&bytes[..end]);
                let length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length: ")
                            .and_then(|s| s.parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                if bytes.len() >= end + 4 + length {
                    header_end = end + 4;
                    break;
                }
            }
        }
        let raw = String::from_utf8_lossy(&bytes[..header_end]);
        let path = raw.split_whitespace().nth(1).unwrap_or("");
        let body = if path == "/invitation" {
            json!({"invitation":invitation,"labCaPem":cert.cert.pem(),"environments":environments,"issuerBridgeId":issuer_store.id()?,"delegatedEnvironmentId":delegated_id})
        } else if let Some(client) = path.strip_prefix("/approve/") {
            owner.approve(client, omabridge::unix_time()?)?;
            phone = client.into();
            issuer_policy["delegates"] = json!({owner.id()?:{&delegated_id:[client]}});
            write_policy(&issuer_path, &issuer_policy)?;
            let entries: Vec<Value> = environments
                .iter()
                .map(|e| json!({"id":e["id"],"name":e["name"],"enabled":true}))
                .collect();
            let endpoints: Vec<Value> = environments.iter().map(|e|json!({"environmentId":e["id"],"descriptorEnvironmentId":e["id"],"id":"lab-tls","url":e["url"],"priority":0})).collect();
            let ids: Vec<Value> = environments.iter().map(|e| e["id"].clone()).collect();
            omabridge::catalog::publish_source(
                &owner,
                &json!({"version":1,"revision":1,"environments":entries,"endpoints":endpoints,"clients":{client:ids}}),
            )?;
            json!({})
        } else if path == "/delegation-status" {
            json!({"issuerBridgeId":issuer_store.id()?,"delegatedEnvironmentId":delegated_id,"issuedCount":issued_count.load(Ordering::SeqCst)})
        } else if let Some(index) = path.strip_prefix("/verify-subject/") {
            let index: usize = index.parse()?;
            let (port, admin, _) = admins.get(index).context("unknown lab backend")?;
            let secret: Value = serde_json::from_slice(&bytes[header_end..])?;
            let presented = secret["token"].as_str().context("missing lab session")?;
            let session = request(*port, presented, "GET", "/api/auth/session", None).await?;
            // AuthSessionState intentionally omits subject. Only the isolated
            // administrator may read AuthClientSession metadata; emit a boolean,
            // never the list, subject, session id or credential.
            let valid = session["authenticated"] == true
                && session["scopes"] == json!(["orchestration:read"])
                && environments[index]["id"] == delegated_id;
            let bound = if valid {
                let clients = request(*port, admin, "GET", "/api/auth/clients", None).await?;
                let expected = format!("omabridge:{}:{}", owner.id()?, phone);
                subject_binding(&clients, &session, &expected)?
            } else {
                false
            };
            json!({"subjectBoundToClient":bound})
        } else if let Some(index) = path.strip_prefix("/verify-write/") {
            let index: usize = index.parse()?;
            let port = admins.get(index).context("unknown lab backend")?.0;
            let secret: Value = serde_json::from_slice(&bytes[header_end..])?;
            let token = secret["token"]
                .as_str()
                .context("missing lab session")?
                .to_owned();
            let thread = environments[index]["threadId"].clone();
            let denied = tokio::task::spawn_blocking(move || -> Result<bool> {
                let connection = t3_protocol::Connection::new(&format!("http://127.0.0.1:{port}"), None,
                    t3_protocol::Credential::bearer(&token).map_err(anyhow::Error::msg)?)
                    .map_err(anyhow::Error::msg)?;
                match connection.rpc("orchestration.dispatchCommand", json!({"type":"thread.archive","commandId":"lab-denied-archive","threadId":thread})) {
                    Ok(_) => Ok(false),
                    Err(error) => { let error = error.to_ascii_lowercase(); Ok(error.contains("scope") || error.contains("forbidden") || error.contains("unauthorized")) }
                }
            }).await??;
            json!({"writeDenied":denied})
        } else if path == "/revoke-sessions" {
            for (port, token, _) in &admins {
                let clients = request(*port, token, "GET", "/api/auth/clients", None).await?;
                // List shape is the server contract; never emit it (labels/subjects are private).
                let rows = clients
                    .as_array()
                    .or_else(|| clients["clients"].as_array())
                    .context("invalid clients list")?;
                for client in rows {
                    if client.to_string().contains(&phone) {
                        let id = client["sessionId"]
                            .as_str()
                            .or_else(|| client["id"].as_str())
                            .context("missing session id")?;
                        request(
                            *port,
                            token,
                            "POST",
                            "/api/auth/clients/revoke",
                            Some(json!({"sessionId":id})),
                        )
                        .await?;
                    }
                }
            }
            json!({})
        } else if path == "/revoke" {
            owner.revoke(&phone)?;
            json!({})
        } else if path == "/stop" {
            break;
        } else {
            json!({"error":"unknown"})
        };
        let body = body.to_string();
        socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).as_bytes()).await?;
    }
    node.shutdown().await;
    issuer_node.shutdown().await;
    for (port, token, id) in &admins {
        let _ = request(
            *port,
            token,
            "POST",
            "/api/auth/clients/revoke",
            Some(json!({"sessionId":id})),
        )
        .await;
    }
    for task in tasks {
        task.abort();
    }
    for child in &mut children {
        child.stop().await?;
    }
    Ok(())
}

/// Host-side smoke test using exactly the normal Android Enroll request path.
/// Private tokens remain in memory. The caller removes the fresh lab directory.
#[allow(clippy::too_many_arguments)]
async fn native_self_test(
    root: &std::path::Path,
    owner: &Store,
    node: &Node,
    issuer: &Store,
    issuer_path: &std::path::Path,
    issuer_policy: &mut Value,
    delegated_id: &str,
    environments: &[Value],
    admins: &[(u16, String, String)],
    ca: &str,
    issued_count: &AtomicU64,
) -> Result<()> {
    let phone = Store::open(&root.join("native-phone"), "NativePhoneLab")?;
    let now = omabridge::unix_time()?;
    let invitation = owner.create_invite(&["t3".into()], Duration::from_secs(60), now)?;
    owner.claim(&invitation, &phone.id()?, "NativePhoneLab", now)?;
    owner.approve(&phone.id()?, now)?;
    issuer_policy["delegates"] = json!({owner.id()?:{delegated_id:[phone.id()?]}});
    write_policy(issuer_path, issuer_policy)?;
    omabridge::catalog::publish_source(
        owner,
        &json!({"version":1,"revision":1,
        "environments":environments.iter().map(|e|json!({"id":e["id"],"name":e["name"],"enabled":true})).collect::<Vec<_>>(),
        "endpoints":[],"clients":{phone.id()?:environments.iter().map(|e|e["id"].clone()).collect::<Vec<_>>()}}),
    )?;
    let client = Client::new(phone.clone(), NetOptions::loopback()).await?;
    let result = async {
        let mut sessions = Vec::new();
        for (index, environment) in environments.iter().enumerate() {
            let id = environment["id"].as_str().context("missing identity")?;
            let enrollment = client.enroll(&node.addr(),id).await.context("native bridge enrollment")?;
            let url = environment["url"].as_str().unwrap().replace("10.0.2.2","127.0.0.1");
            let backend_port = admins[index].0;
            let ca = ca.to_owned(); let expected_thread = environment["threadId"].clone();
            let receipt = tokio::task::spawn_blocking(move || -> Result<Value> {
                let http = reqwest012::blocking::Client::builder().no_proxy()
                    .redirect(reqwest012::redirect::Policy::none())
                    .add_root_certificate(reqwest012::Certificate::from_pem(ca.as_bytes())?)
                    .timeout(Duration::from_secs(5)).build()?;
                let receipt = omabridge::enrollment::redeem_with_http(&enrollment,&url,omabridge::unix_time()?*1000,Some(http.clone())).context("native redeem actual session")?;
                let connection = t3_protocol::Connection::with_http_client(http,&url,None,
                    t3_protocol::Credential::bearer(receipt["accessToken"].as_str().unwrap()).map_err(anyhow::Error::msg)?)
                    .map_err(anyhow::Error::msg)?;
                let shell = connection.request_json("GET","/api/orchestration/shell",None,true).map_err(anyhow::Error::msg).context("native real T3 shell")?;
                ensure!(shell["threads"].as_array().is_some_and(|rows|rows.iter().any(|t|t["id"] == expected_thread)), "wrong host shell");
                // The lab TLS frontend proxies HTTP only. Exercise WebSocket authorization
                // on the same isolated T3 backend, without a synthetic TLS trust failure.
                let write_connection = t3_protocol::Connection::new(
                    &format!("http://127.0.0.1:{backend_port}"), None,
                    t3_protocol::Credential::bearer(receipt["accessToken"].as_str().unwrap()).map_err(anyhow::Error::msg)?,
                ).map_err(anyhow::Error::msg)?;
                let error = write_connection.rpc("orchestration.dispatchCommand",json!({"type":"thread.archive","commandId":"lab-write-denied","threadId":expected_thread})).err().context("write unexpectedly accepted")?.to_ascii_lowercase();
                ensure!(error.contains("scope") || error.contains("forbidden") || error.contains("unauthorized"),"write failed for unexpected reason");
                Ok(receipt)
            }).await??;
            // HOST bearer cannot authenticate to GATEWAY (and vice versa).
            let other = admins[1-index].0;
            ensure!(!authenticated(other,receipt["accessToken"].as_str().unwrap()).await?,"cross-host bearer accepted");
            sessions.push(receipt);
        }
        ensure!(issued_count.load(Ordering::SeqCst) >= 1 && owner.id()? != issuer.id()?,"delegated issuer not exercised");
        // Real T3 client metadata records the downstream subject under its issuer.
        let rows = request(admins[1].0,&admins[1].1,"GET","/api/auth/clients",None).await?;
        let current = request(admins[1].0, sessions[1]["accessToken"].as_str().context("missing session")?, "GET", "/api/auth/session", None).await?;
        ensure!(subject_binding(&rows, &current, &format!("omabridge:{}:{}",owner.id()?,phone.id()?))?, "delegated T3 subject missing");
        issuer_policy["delegates"] = json!({}); write_policy(issuer_path, issuer_policy)?;
        ensure!(client.enroll(&node.addr(),delegated_id).await.is_err(),"withdrawn issuer accepted request");
        ensure!(authenticated(admins[1].0,sessions[1]["accessToken"].as_str().unwrap()).await?,"bridge withdrawal unexpectedly revoked bearer");
        let expiry = sessions.iter().filter_map(|s|s["expiresAt"].as_u64()).max().unwrap();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis() as u64;
        tokio::time::sleep(Duration::from_millis(expiry.saturating_sub(now)+250)).await;
        for (i,session) in sessions.iter().enumerate() {
            ensure!(!authenticated(admins[i].0,session["accessToken"].as_str().unwrap()).await?,"expired bearer accepted");
        }
        Ok(())
    }.await;
    client.close().await;
    result
}

// Administrative witness in this isolated fixture only. AuthSessionState omits
// subject; require one exact AuthClientSession with the presented bearer's scope
// and expiry. Never emit the list, session id, subject or credential to Android.
fn subject_binding(clients: &Value, session: &Value, expected: &str) -> Result<bool> {
    let rows = clients
        .as_array()
        .or_else(|| clients["clients"].as_array())
        .context("invalid clients list")?;
    if session["authenticated"] != true
        || session["scopes"] != json!(["orchestration:read"])
        || !session["expiresAt"].is_string()
    {
        return Ok(false);
    }
    let mut candidates = rows.iter().filter(|row| {
        row["expiresAt"] == session["expiresAt"] && row["scopes"] == session["scopes"]
    });
    Ok(candidates
        .next()
        .is_some_and(|row| row["subject"] == expected)
        && candidates.next().is_none())
}

#[cfg(test)]
mod subject_binding_tests {
    use super::*;
    #[test]
    fn witness_requires_exact_subject_scope_expiry_and_unique_record() {
        let session = json!({"authenticated":true,"scopes":["orchestration:read"],"expiresAt":"2030-01-01T00:00:00Z"});
        let row = json!({"subject":"fixture-desktop:fixture-phone","scopes":["orchestration:read"],"expiresAt":"2030-01-01T00:00:00Z"});
        let expected = "fixture-desktop:fixture-phone";
        assert!(subject_binding(&json!([row]), &session, expected).unwrap());
        assert!(!subject_binding(&json!([row]), &session, "other-phone").unwrap());
        assert!(!subject_binding(&json!([row, row]), &session, expected).unwrap());
        let mut other_subject = row.clone();
        other_subject["subject"] = json!("other-phone");
        assert!(!subject_binding(&json!([row, other_subject]), &session, expected).unwrap());
        let mut changed = session.clone();
        changed["expiresAt"] = json!("2030-01-01T00:00:01Z");
        assert!(!subject_binding(&json!([row]), &changed, expected).unwrap());
        changed = session.clone();
        changed["authenticated"] = json!(false);
        assert!(!subject_binding(&json!([row]), &changed, expected).unwrap());
        changed = session.clone();
        changed["scopes"] = json!(["orchestration:write"]);
        assert!(!subject_binding(&json!([row]), &changed, expected).unwrap());
    }
}
