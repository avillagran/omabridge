//! Two distinct QUIC endpoints. The executable and descriptor below are isolated
//! fixtures; real T3 acceptance/write-denial is covered by catalog_t3_lab.
use anyhow::Result;
use omabridge::{
    Client, Invitation, NetOptions, Node, Store,
    delegated_enrollment::{CompositeAuthority, RemoteT3Authority, load_authority},
    enrollment::EnrollmentAuthority,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap, os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc, time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
fn write_policy(path: &std::path::Path, value: &Value) -> Result<()> {
    omabridge::write_document(path, value, true)
}
const HOST: &str = "00000000-0000-4000-8000-000000000002";
const OTHER: &str = "00000000-0000-4000-8000-000000000003";
fn targets() -> BTreeMap<String, std::net::SocketAddr> {
    BTreeMap::from([("t3".into(), "127.0.0.1:9".parse().unwrap())])
}
fn grant(owner: &Store, client: &Store) -> Result<()> {
    let now = omabridge::unix_time()?;
    let invite = owner.create_invite(&["t3".into()], Duration::from_secs(60), now)?;
    owner.claim(&invite, &client.id()?, "fixture", now)?;
    owner.approve(&client.id()?, now)
}
fn publish(owner: &Store, phone: &Store, environments: &[&str]) -> Result<()> {
    let revision = std::fs::read(owner.root().join("client-catalog.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v["revision"].as_u64())
        .unwrap_or(0)
        + 1;
    omabridge::catalog::publish_source(
        owner,
        &json!({"version":1,"revision":revision,
        "environments":environments.iter().map(|e| json!({"id":e,"name":"fixture","enabled":true})).collect::<Vec<_>>(),
        "endpoints":[],"clients":{phone.id()?:environments}}),
    )?;
    Ok(())
}
struct Lab {
    _dir: tempfile::TempDir,
    owner: Store,
    issuer: Store,
    phone: Store,
    selected: Node,
    host: Node,
    client: Arc<Client>,
    policy: Value,
    policy_path: PathBuf,
    desktop_path: PathBuf,
    home: PathBuf,
    descriptor: JoinHandle<()>,
}
impl Lab {
    async fn new() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let owner = Store::open(&dir.path().join("desktop"), "desktop")?;
        let issuer = Store::open(&dir.path().join("issuer"), "issuer")?;
        let phone = Store::open(&dir.path().join("phone"), "phone")?;
        let home = dir.path().join("t3");
        std::fs::create_dir(&home)?;
        let binary = dir.path().join("t3-fixture");
        std::fs::write(
            &binary,
            r#"#!/usr/bin/python3
import datetime,json,pathlib,sys,time
args=sys.argv
home=pathlib.Path(args[args.index('--base-dir')+1])
(home/'started').touch()
while (home/'block').exists(): time.sleep(.01)
mode=(home/'mode').read_text() if (home/'mode').exists() else ''
ttl=180 if mode=='ttl' else int(args[args.index('--ttl')+1][:-1])
scopes=['orchestration:read','orchestration:operate'] if mode=='scope' else ['orchestration:read']
subject=args[args.index('--subject')+1]
if mode=='subject': subject='another'
print(json.dumps({'token':'fixture-secret','subject':subject,'scopes':scopes,'expiresAt':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=ttl)).isoformat()}))
(home/'subject').write_text(subject)
"#,
        )?;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let descriptor = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut bytes = [0; 4096];
                let _ = socket.read(&mut bytes).await;
                let body = json!({"environmentId":HOST}).to_string();
                let _ = socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await;
            }
        });
        let policy_path = dir.path().join("issuer-policy.json");
        let policy = json!({"version":1,"local":{"t3Binary":binary,"ttlSeconds":120,"environments":{HOST:{"baseDir":home,"descriptorUrl":format!("http://{addr}/")}}},
            "delegates":{owner.id()?:{HOST:[phone.id()?]}}});
        write_policy(&policy_path, &policy)?;
        let authority = Arc::new(CompositeAuthority::open(issuer.clone(), &policy_path)?);
        let host = Node::start_reserved_with_authority(
            issuer.clone(),
            targets(),
            NetOptions::loopback(),
            issuer.reserve_runtime()?,
            Some(authority),
        )
        .await?;
        // Pair desktop to issuer before starting desktop's sole endpoint.
        let boot = Client::new(owner.clone(), NetOptions::loopback()).await?;
        let now = omabridge::unix_time()?;
        let invite = Invitation {
            version: 1,
            address: host.addr(),
            token: issuer.create_invite(&["t3".into()], Duration::from_secs(60), now)?,
            name: "issuer".into(),
            expires: now + 60,
            manage: false,
        };
        boot.pair(&invite, "desktop", now).await?;
        issuer.approve(&owner.id()?, now)?;
        boot.pair(&invite, "desktop", now).await?;
        boot.close().await;
        let desktop_path = dir.path().join("desktop-policy.json");
        write_policy(
            &desktop_path,
            &json!({"version":1,"remote":{HOST:issuer.id()?}}),
        )?;
        let selected = Node::start_reserved_with_authority(
            owner.clone(),
            targets(),
            NetOptions::loopback(),
            owner.reserve_runtime()?,
            Some(load_authority(owner.clone(), &desktop_path)?),
        )
        .await?;
        assert_ne!(selected.addr().id, host.addr().id);
        grant(&owner, &phone)?;
        publish(&owner, &phone, &[HOST, OTHER])?;
        let client = Arc::new(Client::new(phone.clone(), NetOptions::loopback()).await?);
        Ok(Self {
            _dir: dir,
            owner,
            issuer,
            phone,
            selected,
            host,
            client,
            policy,
            policy_path,
            desktop_path,
            home,
            descriptor,
        })
    }
    async fn begin_blocked(&self) -> JoinHandle<bool> {
        let _ = std::fs::remove_file(self.home.join("started"));
        std::fs::write(self.home.join("block"), "").unwrap();
        let client = self.client.clone();
        let addr = self.selected.addr();
        let task = tokio::spawn(async move { client.enroll(&addr, HOST).await.is_ok() });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !self.home.join("started").exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        task
    }
    fn release(&self) {
        std::fs::remove_file(self.home.join("block")).unwrap();
    }
    async fn close(self) {
        self.client.close().await;
        self.selected.shutdown().await;
        self.host.shutdown().await;
        self.descriptor.abort();
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_bridges_bind_original_client_and_enforce_host_policy() -> Result<()> {
    let lab = Lab::new().await?;
    let enrollment = lab.client.enroll(&lab.selected.addr(), HOST).await?;
    assert_eq!(enrollment.client_id, lab.phone.id()?);
    assert_eq!(enrollment.environment_id, HOST);
    assert_eq!(enrollment.scopes, ["orchestration:read"]);
    assert!(enrollment.session_token.is_some());
    assert_eq!(
        std::fs::read_to_string(lab.home.join("subject"))?,
        format!("omabridge:{}:{}", lab.owner.id()?, lab.phone.id()?)
    );
    // Host must reject an environment even when desktop explicitly routes it.
    write_policy(
        &lab.desktop_path,
        &json!({"version":1,"remote":{HOST:lab.issuer.id()?,OTHER:lab.issuer.id()?}}),
    )?;
    assert!(
        lab.client
            .enroll(&lab.selected.addr(), OTHER)
            .await
            .is_err()
    );
    // No direct Android pairing or trust on issuer, even for an allowed client ID.
    assert!(lab.client.enroll(&lab.host.addr(), HOST).await.is_err());
    let other = Store::open(&lab._dir.path().join("other-phone"), "other")?;
    grant(&lab.owner, &other)?;
    publish(&lab.owner, &other, &[HOST])?;
    let other_client = Client::new(other, NetOptions::loopback()).await?;
    assert!(
        other_client
            .enroll(&lab.selected.addr(), HOST)
            .await
            .is_err()
    );
    other_client.close().await;
    publish(&lab.owner, &lab.phone, &[HOST])?;
    for mode in ["scope", "ttl", "subject"] {
        std::fs::write(lab.home.join("mode"), mode)?;
        assert!(
            lab.client.enroll(&lab.selected.addr(), HOST).await.is_err(),
            "{mode}"
        );
    }
    std::fs::remove_file(lab.home.join("mode"))?;
    let mut removed = lab.policy.clone();
    removed["delegates"] = json!({});
    write_policy(&lab.policy_path, &removed)?;
    assert!(lab.client.enroll(&lab.selected.addr(), HOST).await.is_err());
    // Runtime still owns desktop identity; no second endpoint was started.
    assert!(lab.owner.reserve_runtime().is_err());
    lab.close().await;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revocation_is_rechecked_after_issuance_at_both_bridges() -> Result<()> {
    let lab = Lab::new().await?;
    let task = lab.begin_blocked().await;
    let mut removed = lab.policy.clone();
    removed["delegates"] = json!({});
    write_policy(&lab.policy_path, &removed)?;
    lab.release();
    assert!(!task.await?);
    write_policy(&lab.policy_path, &lab.policy)?;
    let task = lab.begin_blocked().await;
    publish(&lab.owner, &lab.phone, &[])?;
    lab.release();
    assert!(!task.await?);
    publish(&lab.owner, &lab.phone, &[HOST])?;
    let task = lab.begin_blocked().await;
    lab.issuer.revoke(&lab.owner.id()?)?;
    lab.release();
    assert!(!task.await?);
    lab.close().await;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrency_and_rate_are_bounded_without_leaking_receipts() -> Result<()> {
    let lab = Lab::new().await?;
    let first = lab.begin_blocked().await;
    let mut tasks = vec![first];
    for _ in 0..3 {
        let c = lab.client.clone();
        let addr = lab.selected.addr();
        tasks.push(tokio::spawn(
            async move { c.enroll(&addr, HOST).await.is_ok() },
        ));
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(lab.client.enroll(&lab.selected.addr(), HOST).await.is_err());
    lab.release();
    for task in tasks {
        assert!(task.await?);
    }
    // Existing requests consume four host attempts; the fifth was rejected by
    // desktop concurrency before reaching the host. Twelve more reach the cap.
    for _ in 0..12 {
        assert!(lab.client.enroll(&lab.selected.addr(), HOST).await.is_ok());
    }
    assert!(lab.client.enroll(&lab.selected.addr(), HOST).await.is_err());
    lab.close().await;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn paired_upstream_without_explicit_delegation_is_denied() -> Result<()> {
    let lab = Lab::new().await?;
    let other = Store::open(&lab._dir.path().join("other-desktop"), "other-desktop")?;
    let boot = Client::new(other.clone(), NetOptions::loopback()).await?;
    let now = omabridge::unix_time()?;
    let invite = Invitation {
        version: 1,
        address: lab.host.addr(),
        token: lab
            .issuer
            .create_invite(&["t3".into()], Duration::from_secs(60), now)?,
        name: "issuer".into(),
        expires: now + 60,
        manage: false,
    };
    boot.pair(&invite, "other-desktop", now).await?;
    lab.issuer.approve(&other.id()?, now)?;
    boot.pair(&invite, "other-desktop", now).await?;
    boot.close().await;
    let node = Node::start(other.clone(), targets(), NetOptions::loopback()).await?;
    let remote = RemoteT3Authority {
        store: other,
        peer: lab.issuer.id()?,
    };
    let error = remote
        .issue(&lab.phone.id()?, HOST, now * 1000)
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(!error.contains("fixture-secret"));
    assert!(!lab.home.join("started").exists());
    node.shutdown().await;
    lab.close().await;
    Ok(())
}
#[test]
fn legacy_config_and_default_delegation_remain_denied() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = Store::open(&dir.path().join("state"), "test")?;
    let path = dir.path().join("policy.json");
    write_policy(&path, &json!({"t3Binary":"/bin/true","environments":{}}))?;
    let authority = load_authority(store.clone(), &path)?;
    let runtime = tokio::runtime::Runtime::new()?;
    assert!(
        runtime
            .block_on(authority.issue_delegated("upstream", "client", HOST, 0))
            .is_err()
    );
    write_policy(&path, &json!({"version":1,"remote":{HOST:"invalid-peer"}}))?;
    assert!(CompositeAuthority::open(store, &path).is_err());
    Ok(())
}
