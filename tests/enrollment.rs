//! Isolated T3 authority contract: accepted tokens come from the fake T3 backend,
//! never from catalog metadata. No productive authority is configured/deployed.
use anyhow::{Context, Result};
use omabridge::{
    Client, NetOptions, Node, Store,
    enrollment::{Enrollment, EnrollmentAuthority},
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
const GATEWAY: &str = "00000000-0000-4000-8000-000000000001";
const HOST: &str = "00000000-0000-4000-8000-000000000002";
type Grants = Arc<Mutex<BTreeMap<String, (String, String, u64)>>>;
struct Authority {
    grants: Grants,
    revoked: Arc<Mutex<bool>>,
}
impl EnrollmentAuthority for Authority {
    fn issue<'a>(
        &'a self,
        client: &'a str,
        environment: &'a str,
        now: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Enrollment>> + Send + 'a>> {
        Box::pin(async move {
            anyhow::ensure!(!*self.revoked.lock().unwrap(), "authority revoked");
            let secret = format!("test-{}-{}", client, environment);
            self.grants.lock().unwrap().insert(
                secret.clone(),
                (client.into(), environment.into(), now + 120_000),
            );
            Ok(Enrollment {
                environment_id: environment.into(),
                client_id: client.into(),
                pairing_secret: secret,
                session_token: None,
                expires_at: now + 120_000,
                scopes: vec!["orchestration:read".into()],
            })
        })
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authorized_clients_enroll_read_two_host_shells_and_cannot_cross_or_survive_revocation()
-> Result<()> {
    let dir = tempfile::tempdir()?;
    let owner = Store::open(&dir.path().join("owner"), "desktop")?;
    let phone = Store::open(&dir.path().join("phone"), "android")?;
    let stranger = Store::open(&dir.path().join("stranger"), "other")?;
    let authority = Arc::new(Authority {
        grants: Arc::default(),
        revoked: Arc::default(),
    });
    let mut backends = Vec::new();
    let mut tasks = Vec::new();
    for env in [GATEWAY, HOST] {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        backends.push((env, format!("http://{}", listener.local_addr()?)));
        let grants = authority.grants.clone();
        let revoked = authority.revoked.clone();
        tasks.push(tokio::spawn(async move {while let Ok((mut socket,_))=listener.accept().await {let grants=grants.clone();let revoked=revoked.clone();tokio::spawn(async move {
   let mut raw=Vec::new();let mut buffer=[0;8192];loop {let n=socket.read(&mut buffer).await.unwrap();if n==0{return}raw.extend_from_slice(&buffer[..n]);let text=String::from_utf8_lossy(&raw);if let Some(end)=text.find("\r\n\r\n"){let len=text[..end].lines().find_map(|l|l.to_ascii_lowercase().strip_prefix("content-length: ").and_then(|s|s.parse::<usize>().ok())).unwrap_or(0);if raw.len()>=end+4+len{break}}}
   let request=String::from_utf8(raw).unwrap();let first=request.lines().next().unwrap();let mut status="200 OK";
   let body=if first.starts_with("GET /.well-known/"){json!({"environmentId":env})}
   else if first.starts_with("POST /oauth/token ") {
    let payload=request.split("\r\n\r\n").nth(1).unwrap();let url=reqwest::Url::parse(&format!("http://form/?{payload}")).unwrap();
    let form:BTreeMap<_,_>=url.query_pairs().into_owned().collect();
    let secret=form.get("subject_token").cloned().unwrap_or_default();
    let grant=grants.lock().unwrap().remove(&secret);
    if let Some((client,id,expiry))=grant.filter(|(_,id,expiry)|id==env && *expiry>omabridge::unix_time().unwrap()*1000 && !*revoked.lock().unwrap()) {
     assert_eq!(form["client_label"],format!("OmaBridge {client}"));assert_eq!(id,env);
     let token=format!("fixture-session-{client}-{env}");grants.lock().unwrap().insert(token.clone(),(client,id,expiry));
     json!({"access_token":token,"token_type":"Bearer","scope":"orchestration:read","expires_in":60})
    }else{status="401 Unauthorized";json!({"error":"denied"})}
   }else{
    let bearer=request.lines().find_map(|l|l.strip_prefix("authorization: Bearer ")).unwrap_or("");
    let allowed=grants.lock().unwrap().get(bearer).is_some_and(|(_,id,expiry)|id==env && *expiry>omabridge::unix_time().unwrap()*1000) && !*revoked.lock().unwrap();
    if !allowed {status="401 Unauthorized";json!({"error":"denied"})}
    else if first.starts_with("GET /api/orchestration/shell "){json!({"environmentId":env,"threads":[{"id":format!("{env}-thread"),"title":format!("{env} private shell")} ]})}
    else {status="403 Forbidden";json!({"error":"read_only"})}
   }.to_string();socket.write_all(format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
  });}}));
    }
    let now = omabridge::unix_time()?;
    let invite = owner.create_invite(&["t3".into()], Duration::from_secs(60), now)?;
    owner.claim(&invite, &phone.id()?, "android", now)?;
    owner.approve(&phone.id()?, now)?;
    let reservation = owner.reserve_runtime()?;
    let node = Node::start_reserved_with_authority(
        owner.clone(),
        BTreeMap::from([("t3".into(), "127.0.0.1:9".parse()?)]),
        NetOptions::loopback(),
        reservation,
        Some(authority.clone()),
    )
    .await?;
    omabridge::catalog::publish_source(
        &owner,
        &json!({"version":1,"revision":1,"environments":[{"id":GATEWAY,"name":"GATEWAY","enabled":true},{"id":HOST,"name":"HOST","enabled":true}],"endpoints":[],"clients":{phone.id()?:[GATEWAY,HOST]}}),
    )?;
    let client = Client::new(phone.clone(), NetOptions::loopback()).await?;
    let other = Client::new(stranger, NetOptions::loopback()).await?;
    assert!(other.enroll(&node.addr(), HOST).await.is_err());
    assert!(client.enroll(&node.addr(), "unknown").await.is_err());
    let mut sessions = Vec::new();
    for (env, url) in &backends {
        let enrollment = client.enroll(&node.addr(), env).await?;
        let url = url.clone();
        let receipt = tokio::task::spawn_blocking(move || {
            omabridge::enrollment::redeem(&enrollment, &url, omabridge::unix_time().unwrap() * 1000)
        })
        .await??;
        sessions.push(receipt);
    }
    for (i, (_, url)) in backends.iter().enumerate() {
        let url = url.clone();
        let token = sessions[i]["accessToken"].as_str().unwrap().to_owned();
        let env = backends[i].0;
        tokio::task::spawn_blocking(move || -> Result<()> {
            let connection = t3_protocol::Connection::new(
                &url,
                None,
                t3_protocol::Credential::bearer(&token).map_err(anyhow::Error::msg)?,
            )
            .map_err(anyhow::Error::msg)?;
            let shell = connection
                .request_json("GET", "/api/orchestration/shell", None, false)
                .map_err(anyhow::Error::msg)?;
            assert_eq!(shell["environmentId"], env);
            assert_eq!(shell["threads"][0]["id"], format!("{env}-thread"));
            assert!(
                connection
                    .request_json(
                        "POST",
                        "/api/orchestration/dispatch",
                        Some(&json!({})),
                        false
                    )
                    .is_err()
            );
            Ok(())
        })
        .await??;
    }
    let wrong = sessions[0]["accessToken"].as_str().unwrap().to_owned();
    let url = backends[1].1.clone();
    tokio::task::spawn_blocking(move || {
        let c = t3_protocol::Connection::new(
            &url,
            None,
            t3_protocol::Credential::bearer(&wrong).unwrap(),
        )
        .unwrap();
        assert!(
            c.request_json("GET", "/api/orchestration/shell", None, false)
                .is_err()
        );
    })
    .await?;
    *authority.revoked.lock().unwrap() = true;
    assert!(client.enroll(&node.addr(), HOST).await.is_err());
    let token = sessions[1]["accessToken"].as_str().unwrap().to_owned();
    let url = backends[1].1.clone();
    tokio::task::spawn_blocking(move || {
        let c = t3_protocol::Connection::new(
            &url,
            None,
            t3_protocol::Credential::bearer(&token).unwrap(),
        )
        .unwrap();
        assert!(
            c.request_json("GET", "/api/orchestration/shell", None, false)
                .is_err()
        );
    })
    .await?;
    owner.revoke(&phone.id()?)?;
    assert!(client.enroll(&node.addr(), GATEWAY).await.is_err());
    client.close().await;
    other.close().await;
    node.shutdown().await;
    for task in tasks {
        task.abort();
    }
    Ok(())
}

/// Isolated integration fixture: one endpoint must retain its enrollment authority
/// while runtime recovery and negotiated stream compression are both configured.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enrollment_coexists_with_runtime_recovery_and_compression() -> Result<()> {
    use tokio::time::timeout;
    let dir = tempfile::tempdir()?;
    let owner = Store::open(&dir.path().join("owner"), "owner")?;
    let guest = Store::open(&dir.path().join("guest"), "guest")?;
    let first = TcpListener::bind("127.0.0.1:0").await?;
    let second = TcpListener::bind("127.0.0.1:0").await?;
    let first_addr = first.local_addr()?;
    let second_addr = second.local_addr()?;
    let mut tasks = Vec::new();
    for (listener, label) in [(first, b"first".as_slice()), (second, b"second".as_slice())] {
        tasks.push(tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut data = Vec::new();
                    socket.read_to_end(&mut data).await.unwrap();
                    socket.write_all(label).await.unwrap();
                    socket.write_all(&data).await.unwrap();
                    socket.shutdown().await.unwrap();
                });
            }
        }));
    }
    let now = omabridge::unix_time()?;
    let invite = owner.create_invite(&["t3".into()], Duration::from_secs(60), now)?;
    owner.claim(&invite, &guest.id()?, "guest", now)?;
    owner.approve(&guest.id()?, now)?;
    let runtime = dir.path().join("server-runtime.json");
    let write_runtime = |port| std::fs::write(&runtime, format!("{{\"port\":{port}}}"));
    write_runtime(first_addr.port())?;
    let authority = Arc::new(Authority {
        grants: Arc::default(),
        revoked: Arc::default(),
    });
    let mut options = NetOptions::loopback();
    options.compress_t3 = true;
    let node = Node::start_reserved_with_configuration(
        owner.clone(),
        BTreeMap::from([("t3".into(), first_addr)]),
        options.clone(),
        owner.reserve_runtime()?,
        Some(authority),
        Some(runtime.clone()),
    )
    .await?;
    omabridge::catalog::publish_source(
        &owner,
        &json!({"version":1,"revision":1,
        "environments":[{"id":HOST,"name":"fixture-host","enabled":true}],
        "endpoints":[],"clients":{guest.id()?:[HOST]}}),
    )?;
    let client = Arc::new(Client::new(guest.clone(), options).await?);
    let invitation = omabridge::Invitation {
        version: 1,
        address: node.addr(),
        token: invite,
        name: "owner".into(),
        expires: now + 60,
        manage: false,
    };
    client.pair(&invitation, "guest", now).await?;
    client
        .enroll(&node.addr(), HOST)
        .await
        .context("fixture enrollment before port change")?;
    let mut negotiated = client.open(&node.addr(), "t3").await?;
    assert!(
        negotiated.is_compressed(),
        "combined startup must retain compression negotiation"
    );
    let (mut application, transport) = tokio::io::duplex(64);
    let probe = tokio::spawn(async move { negotiated.transfer(transport).await });
    application.write_all(b"-probe").await?;
    application.shutdown().await?;
    let mut received = Vec::new();
    timeout(
        Duration::from_secs(3),
        application.read_to_end(&mut received),
    )
    .await
    .context("compression probe timeout")??;
    assert_eq!(received, b"first-probe");
    probe.await??;
    let local = TcpListener::bind("127.0.0.1:0").await?;
    let address = local.local_addr()?;
    let forward = tokio::spawn(client.clone().forward(node.addr(), "t3".into(), local));
    async fn exchange(address: std::net::SocketAddr) -> Result<Vec<u8>> {
        let mut socket = tokio::net::TcpStream::connect(address).await?;
        socket.write_all(b"-payload").await?;
        socket.shutdown().await?;
        let mut result = Vec::new();
        socket.read_to_end(&mut result).await?;
        Ok(result)
    }
    assert_eq!(
        timeout(Duration::from_secs(3), exchange(address))
            .await
            .context("fixture forward timeout")?
            .context("fixture compressed forward")?,
        b"first-payload"
    );
    write_runtime(second_addr.port())?;
    assert_eq!(
        timeout(Duration::from_secs(3), exchange(address))
            .await
            .context("fixture forward timeout")?
            .context("fixture compressed forward")?,
        b"second-payload"
    );
    client.enroll(&node.addr(), HOST).await?;
    std::fs::remove_file(&runtime)?;
    assert!(client.open(&node.addr(), "t3").await.is_err());
    write_runtime(second_addr.port())?;
    assert_eq!(
        timeout(Duration::from_secs(3), exchange(address)).await??,
        b"second-payload"
    );
    owner.revoke(&guest.id()?)?;
    assert!(client.enroll(&node.addr(), HOST).await.is_err());
    assert!(client.open(&node.addr(), "t3").await.is_err());
    forward.abort();
    client.close().await;
    node.shutdown().await;
    for task in tasks {
        task.abort();
    }
    Ok(())
}
