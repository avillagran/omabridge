//! Test-only loopback fixture. Never install or point at a productive state dir.
use anyhow::{Result, ensure};
use omabridge::{Invitation, NetOptions, Node, Store};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
const GATEWAY: &str = "00000000-0000-4000-8000-000000000001";
const HOST: &str = "00000000-0000-4000-8000-000000000002";
#[tokio::main]
async fn main() -> Result<()> {
    let root = PathBuf::from(
        std::env::args()
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("pass a new lab directory"))?,
    );
    ensure!(!root.exists(), "lab directory must be new");
    std::fs::create_dir_all(&root)?;
    let owner = Store::open(&root.join("owner"), "IsolatedCatalogLab")?;
    let node = Node::start(
        owner.clone(),
        BTreeMap::from([("t3".into(), "127.0.0.1:9".parse()?)]),
        NetOptions::loopback(),
    )
    .await?;
    let now = omabridge::unix_time()?;
    let token = owner.create_invite(&["t3".into()], Duration::from_secs(600), now)?;
    let port = node.addr().ip_addrs().next().unwrap().port();
    // Host loopback as seen by the Android emulator. Certificate identity is the
    // bridge's endpoint key, not this routing hint.
    let address = iroh::EndpointAddr::new(node.addr().id)
        .with_ip_addr(format!("10.0.2.2:{port}").parse::<std::net::SocketAddr>()?);
    let invitation = Invitation {
        version: 1,
        address,
        token,
        name: "IsolatedCatalogLab".into(),
        expires: now + 600,
        manage: false,
    };
    let http = TcpListener::bind("127.0.0.1:0").await?;
    println!(
        "{}",
        json!({"port":http.local_addr()?.port(),"bridgeId":owner.id()?})
    );
    let mut revision = 0;
    let mut phone = String::new();
    loop {
        let (mut socket, _) = http.accept().await?;
        let mut request = [0; 8192];
        let n = socket.read(&mut request).await?;
        let raw = String::from_utf8_lossy(&request[..n]);
        let path = raw.split_whitespace().nth(1).unwrap_or("");
        let response: Value = if path == "/invitation" {
            serde_json::to_value(&invitation)?
        } else if let Some(client) = path.strip_prefix("/approve/") {
            owner.approve(client, omabridge::unix_time()?)?;
            phone = client.into();
            revision += 1;
            publish(&owner, &phone, revision, false, false)?;
            json!({})
        } else if path == "/withdraw" {
            revision += 1;
            publish(&owner, &phone, revision, true, false)?;
            json!({})
        } else if path == "/change" {
            revision += 1;
            publish(&owner, &phone, revision, false, true)?;
            json!({})
        } else if path == "/revoke" {
            owner.revoke(&phone)?;
            json!({})
        } else if path == "/stop" {
            break;
        } else {
            json!({"error":"unknown"})
        };
        let body = response.to_string();
        socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).as_bytes()).await?;
    }
    node.shutdown().await;
    Ok(())
}
fn publish(store: &Store, phone: &str, revision: u64, withdraw: bool, change: bool) -> Result<()> {
    omabridge::catalog::publish_source(
        store,
        &json!({"version":1,"revision":revision,"environments":[{"id":GATEWAY,"name":"GATEWAY","enabled":true},{"id":HOST,"name":if change{"HOST renamed"}else{"HOST"},"enabled":true}],"endpoints":[{"environmentId":GATEWAY,"descriptorEnvironmentId":GATEWAY,"id":"gateway","url":"https://gateway.fixture.invalid/","priority":0},{"environmentId":HOST,"descriptorEnvironmentId":HOST,"id":"gateway","url":if change{"https://changed-host.fixture.invalid/"}else{"https://host.fixture.invalid/"},"priority":0}],"clients":{phone:if withdraw{vec![GATEWAY]}else{vec![GATEWAY,HOST]}}}),
    )
}
