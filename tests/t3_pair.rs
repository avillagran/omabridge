//! Native T3 pairing over the bridge: only a device holding the `t3` grant gets
//! one, labelled with its authenticated id, from the T3 behind the published
//! service. The executable and descriptor are isolated fixtures.
use anyhow::Result;
use omabridge::{Client, NetOptions, Node, Store, t3_pair::T3Issuer};
use serde_json::json;
use std::{collections::BTreeMap, os::unix::fs::PermissionsExt, path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const HOST: &str = "00000000-0000-4000-8000-000000000002";

fn grant(owner: &Store, client: &Store, services: &[&str]) -> Result<()> {
    let now = omabridge::unix_time()?;
    let services: Vec<String> = services.iter().map(|s| s.to_string()).collect();
    let invite = owner.create_invite(&services, Duration::from_secs(60), now)?;
    owner.claim(&invite, &client.id()?, "fixture", now)?;
    owner.approve(&client.id()?, now)
}

fn fixture(dir: &Path) -> Result<T3Issuer> {
    let base_dir = dir.join("t3");
    std::fs::create_dir_all(base_dir.join("userdata"))?;
    std::fs::write(
        base_dir.join("userdata/environment-id"),
        format!("{HOST}\n"),
    )?;
    let cli = dir.join("t3-fixture");
    std::fs::write(
        &cli,
        r#"#!/usr/bin/python3
import json,pathlib,sys
args=sys.argv[1:]
home=pathlib.Path(args[args.index('--base-dir')+1])
(home/'calls').open('a').write(json.dumps(args)+'\n')
label=args[args.index('--label')+1]
print(json.dumps({'id':'p1','credential':'pairing-secret','label':label,'scopes':['orchestration:read'],'expiresAt':'2099-01-01T00:00:00Z'}))
"#,
    )?;
    std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o700))?;
    Ok(T3Issuer { cli, base_dir })
}

/// A loopback T3 whose descriptor names `environment`.
async fn descriptor(environment: &'static str) -> Result<std::net::SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut bytes = [0; 4096];
            let _ = socket.read(&mut bytes).await;
            let body = json!({"environmentId":environment}).to_string();
            let _ = socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await;
        }
    });
    Ok(addr)
}

async fn node(store: &Store, t3: std::net::SocketAddr, issuer: Option<T3Issuer>) -> Result<Node> {
    Node::start_with_t3_issuer(
        store.clone(),
        BTreeMap::from([("t3".into(), t3)]),
        NetOptions::loopback(),
        store.reserve_runtime()?,
        None,
        None,
        Some(issuer),
    )
    .await
}

fn refused(result: Result<omabridge::t3_pair::T3Pairing>) -> String {
    match result {
        Ok(_) => "issued".into(),
        Err(error) => format!("{error}"),
    }
}

#[tokio::test]
async fn a_device_granted_t3_gets_a_labelled_one_use_pairing_and_others_do_not() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir = tempfile::tempdir()?;
        let owner = Store::open(&dir.path().join("owner"), "host")?;
        let guest = Store::open(&dir.path().join("guest"), "laptop")?;
        let other = Store::open(&dir.path().join("other"), "phone")?;
        let issuer = fixture(dir.path())?;
        let host = node(&owner, descriptor(HOST).await?, Some(issuer.clone())).await?;
        grant(&owner, &guest, &["t3"])?;
        grant(&owner, &other, &["ssh"])?;

        let client = Client::new(guest.clone(), NetOptions::loopback()).await?;
        let pairing = client.t3_pair(&host.addr()).await?;
        assert_eq!(pairing.environment_id, HOST);
        assert_eq!(pairing.credential, "pairing-secret");
        assert_eq!(pairing.label, format!("omabridge:{}", guest.id()?));
        let calls = std::fs::read_to_string(issuer.base_dir.join("calls"))?;
        let args: Vec<String> = serde_json::from_str(calls.lines().next().unwrap())?;
        assert_eq!(&args[..3], ["auth", "pairing", "create"]);
        assert!(
            args.windows(2).any(|w| w == ["--ttl", "2m"]),
            "one-use and short-lived"
        );
        assert!(
            !args.iter().any(|a| a == "--scope"),
            "T3's own default scopes"
        );

        // Only `ssh` granted, or not paired at all: refused before T3 runs.
        let ssh_only = Client::new(other.clone(), NetOptions::loopback()).await?;
        assert_eq!(
            refused(ssh_only.t3_pair(&host.addr()).await),
            "omabridge_t3_pair_refused"
        );
        ssh_only.close().await;
        let stranger = Store::open(&dir.path().join("stranger"), "x")?;
        let stranger = Client::new(stranger, NetOptions::loopback()).await?;
        assert_ne!(refused(stranger.t3_pair(&host.addr()).await), "issued");
        stranger.close().await;
        assert_eq!(
            std::fs::read_to_string(issuer.base_dir.join("calls"))?
                .lines()
                .count(),
            1
        );

        // Withdrawing the grant stops issuance.
        owner.revoke(&guest.id()?)?;
        assert_eq!(
            refused(client.t3_pair(&host.addr()).await),
            "omabridge_t3_pair_refused"
        );
        client.close().await;
        host.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn no_pairing_from_another_t3_or_without_an_issuer() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir = tempfile::tempdir()?;
        let owner = Store::open(&dir.path().join("owner"), "host")?;
        let guest = Store::open(&dir.path().join("guest"), "laptop")?;
        let issuer = fixture(dir.path())?;
        grant(&owner, &guest, &["t3"])?;
        // The published service is some other T3: its descriptor names another environment.
        let wrong = node(
            &owner,
            descriptor("00000000-0000-4000-8000-000000000009").await?,
            Some(issuer.clone()),
        )
        .await?;
        let client = Client::new(guest.clone(), NetOptions::loopback()).await?;
        assert_eq!(
            refused(client.t3_pair(&wrong.addr()).await),
            "omabridge_t3_pair_refused"
        );
        assert!(!issuer.base_dir.join("calls").exists(), "T3 is never asked");
        wrong.shutdown().await;
        // A second identity: the first server's lock may outlive its shutdown briefly.
        let plain = Store::open(&dir.path().join("plain"), "host")?;
        grant(&plain, &guest, &["t3"])?;
        let none = node(&plain, descriptor(HOST).await?, None).await?;
        assert_eq!(
            refused(client.t3_pair(&none.addr()).await),
            "omabridge_t3_pair_refused"
        );
        client.close().await;
        none.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

/// The path front ends use: `omabridge t3-pair` through the device's own
/// running server, which dials the peer with its identity.
#[tokio::test]
async fn a_running_server_asks_for_the_pairing_for_local_front_ends() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir = tempfile::tempdir()?;
        let now = omabridge::unix_time()?;
        let owner = Store::open(&dir.path().join("owner"), "host")?;
        let guest = Store::open(&dir.path().join("guest"), "laptop")?;
        let issuer = fixture(dir.path())?;
        let host = node(&owner, descriptor(HOST).await?, Some(issuer)).await?;
        // Pair over the network so the guest learns what the host grants it.
        let client = Client::new(guest.clone(), NetOptions::loopback()).await?;
        let invite = omabridge::Invitation {
            version: 1,
            address: host.addr(),
            token: owner.create_invite(&["t3".into()], Duration::from_secs(60), now)?,
            name: "host".into(),
            expires: now + 60,
            manage: false,
        };
        client.pair(&invite, "laptop", now).await?;
        owner.approve(&guest.id()?, now)?;
        client.pair(&invite, "laptop", now).await?;
        client.close().await;

        assert!(
            omabridge::t3_pair_through_server(&guest, &owner.id()?)
                .await
                .is_none(),
            "no server yet"
        );
        let server = Node::start_with_t3_issuer(
            guest.clone(),
            BTreeMap::from([("ssh".into(), "127.0.0.1:9".parse()?)]),
            NetOptions::loopback(),
            guest.reserve_runtime()?,
            None,
            None,
            Some(None),
        )
        .await?;
        guest.publish_endpoint(&server.addr(), &["ssh".to_owned()])?;
        let pairing = omabridge::t3_pair_through_server(&guest, &owner.id()?)
            .await
            .expect("server runs")?;
        assert_eq!(pairing.environment_id, HOST);
        assert_eq!(pairing.label, format!("omabridge:{}", guest.id()?));
        let unknown = omabridge::t3_pair_through_server(&guest, &"0".repeat(64))
            .await
            .expect("server runs");
        assert_eq!(refused(unknown), "omabridge_peer_not_found");
        owner.revoke(&guest.id()?)?;
        let withdrawn = omabridge::t3_pair_through_server(&guest, &owner.id()?)
            .await
            .expect("server runs");
        assert_eq!(refused(withdrawn), "omabridge_t3_pair_refused");
        server.shutdown().await;
        host.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}
