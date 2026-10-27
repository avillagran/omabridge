use omabridge::{Invitation, NetOptions, Node, Store, gateway};
use std::{collections::BTreeMap, os::unix::fs::PermissionsExt, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn https(port: u16, name: &str, roots: &rustls::RootCertStore) -> Option<String> {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .ok()?
    .with_root_certificates(roots.clone())
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .ok()?;
    let server = rustls::pki_types::ServerName::try_from(name.to_owned()).ok()?;
    let mut tls = tokio::time::timeout(Duration::from_secs(5), connector.connect(server, socket))
        .await
        .ok()?
        .ok()?;
    tls.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .ok()?;
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(8), tls.read_to_end(&mut answer)).await;
    (!answer.is_empty()).then(|| String::from_utf8_lossy(&answer).into_owned())
}

/// A gateway serves one fixed service of one paired device under the name it
/// was given, refuses other names, and closes once that device withdraws the grant.
#[tokio::test]
async fn a_gateway_reaches_only_its_target_under_its_name() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(60), async {
        let dir = tempfile::tempdir()?;
        let live = dir.path().join("live/vpn");
        std::fs::create_dir_all(&live)?;
        let cert = rcgen::generate_simple_self_signed(vec!["*.vpn.test".to_owned()])?;
        std::fs::write(live.join("fullchain.pem"), cert.cert.pem())?;
        std::fs::write(live.join("privkey.pem"), cert.signing_key.serialize_pem())?;
        std::fs::set_permissions(
            live.join("privkey.pem"),
            std::fs::Permissions::from_mode(0o600),
        )?;
        // SAFETY: this test binary runs this single test.
        unsafe { std::env::set_var("OMABRIDGE_CERT_DIR", dir.path().join("live")) };
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone())?;

        // The target device serves a tiny HTTP "T3" on loopback.
        let target = Store::open(&dir.path().join("target"), "laptop")?;
        let web = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let web_addr = web.local_addr()?;
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = web.accept().await {
                tokio::spawn(async move {
                    let mut buffer = [0u8; 1024];
                    let _ = socket.read(&mut buffer).await;
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        let node_target = Node::start(
            target.clone(),
            BTreeMap::from([("t3".into(), web_addr)]),
            NetOptions { compress_t3: true, ..NetOptions::loopback() },
        )
        .await?;

        // The gateway device pairs with it and is granted t3.
        let host = Store::open(&dir.path().join("gateway"), "vps")?;
        let now = omabridge::unix_time()?;
        let invite = Invitation {
            version: 1,
            address: node_target.addr(),
            token: target.create_invite(&["t3".into()], Duration::from_secs(60), now)?,
            name: "laptop".into(),
            expires: now + 60,
            manage: false,
        };
        let client = omabridge::Client::new(host.clone(), NetOptions { compress_t3: true, ..NetOptions::loopback() }).await?;
        client.pair(&invite, "vps", now).await?;
        target.approve(&host.id()?, now)?;
        client.pair(&invite, "vps", now).await?;
        client.close().await;
        // The owner lets the gateway device expose t3 publicly; it learns so when it announces.
        target.set_services(&host.id()?, &["t3".to_owned()], &["t3".to_owned()])?;
        let ssh = std::net::TcpListener::bind("127.0.0.1:0")?;
        let node_host = Node::start(
            host.clone(),
            BTreeMap::from([("ssh".into(), ssh.local_addr()?)]),
            NetOptions { compress_t3: true, ..NetOptions::loopback() },
        )
        .await?;

        let target_id = target.id()?;
        let learned = |public: bool| {
            host.peers()
                .unwrap()
                .into_iter()
                .any(|peer| peer.id == target_id && peer.remote_public.contains("t3") == public)
        };
        while !learned(true) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let occupied = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = occupied.local_addr()?.port();
        let entry = gateway::Gateway {
            host: "laptop.vpn.test".into(),
            port,
            peer: target.id()?,
            service: "t3".into(),
        };
        gateway::save(host.root(), std::slice::from_ref(&entry))?;
        while gateway::status(host.root())
            .get(&entry.url())
            .and_then(|s| s.error.as_deref())
            != Some("port")
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        drop(occupied);
        // A transient bind failure must heal without rewriting configuration.
        tokio::time::timeout(Duration::from_secs(8), async {
            while !gateway::status(host.root())
                .get(&entry.url())
                .is_some_and(|s| s.running)
            {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("gateway must retry after its port becomes available");
        while !gateway::status(host.root())
            .get(&entry.url())
            .is_some_and(|status| status.running)
        {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        // The gateway automatically advertises this route back to its owner.
        // No management grant or manual URL transfer is needed for discovery.
        let expected_route = omabridge::routes::ServiceRoute { service: "t3".into(), url: entry.url() };
        tokio::time::timeout(Duration::from_secs(8), async {
            while target.service_routes(omabridge::unix_time().unwrap()).unwrap() != vec![expected_route.clone()] {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }).await.expect("owner learns gateway route automatically");

        // Reconciliation of an already configured gateway retains its URL,
        // including when its own live listener makes the port appear occupied.
        struct NoSystemctl;
        impl omabridge::units::Runner for NoSystemctl {
            fn run(&self, _: &[&str]) -> anyhow::Result<omabridge::units::RunOutput> {
                Ok(omabridge::units::RunOutput { success: false, stdout: String::new(), stderr: String::new() })
            }
        }
        host.publish_endpoint(&node_host.addr(), &["ssh".to_owned()])?;
        let manager = omabridge::manage::Manager {
            state_dir: host.root().to_path_buf(),
            options: NetOptions { compress_t3: true, ..NetOptions::loopback() },
            units: omabridge::units::Units::new(dir.path().join("units"), Arc::new(NoSystemctl)),
            binary: dir.path().join("omabridge"),
            awaiting_dir: dir.path().join("awaiting"),
            invite_dir: dir.path().join("invites"),
            ssh_target: "127.0.0.1:9".parse()?,
            mcp_target: "127.0.0.1:9".parse()?,
            t3_runtime: dir.path().join("runtime.json"),
            publish_wait: Duration::ZERO,
            pair_timeout: Duration::from_secs(2),
        };
        let other = gateway::Gateway {
            host: "other.vpn.test".into(),
            peer: host.id()?,
            ..entry.clone()
        };
        let configured = vec![entry.clone(), other];
        gateway::save(host.root(), &configured)?;
        for invalid_port in [serde_json::json!("443"), serde_json::json!(0), serde_json::json!(65536)] {
            let request = serde_json::json!({"action":"gateway-set","peer":target_id,"service":"t3","enabled":true,"confirmed":true,"port":invalid_port});
            assert_eq!(manager.execute(&request).await, Err("invalid_command"));
            assert_eq!(gateway::load(host.root()), configured);
        }
        for explicit_port in [false, true] {
            let mut request = serde_json::json!({"action":"gateway-set","peer":target_id,"service":"t3","enabled":true,"confirmed":true});
            if explicit_port { request["port"] = port.into(); }
            let reconciled = manager.execute(&request).await.map_err(anyhow::Error::msg)?;
            assert_eq!(reconciled["gateway"]["url"], entry.url());
            assert_eq!(gateway::load(host.root()), configured);
        }

        // A server-owned wildcard namespace works through the existing API:
        // no Android changes and no remote authority to change its domain.
        let policy = serde_json::json!({"action":"gateway-domain-set","enabled":true,"domain":"vpn.test","port":port,"confirmed":true});
        let mut unconfirmed = policy.clone(); unconfirmed["confirmed"] = false.into();
        assert_eq!(manager.execute(&unconfirmed).await, Err("confirmation_required"));
        let mut missing_cert = policy.clone(); missing_cert["domain"] = "other.test".into();
        assert_eq!(manager.execute(&missing_cert).await, Err("omabridge_relay_certificate"));
        assert!(manager.execute(&policy).await.is_ok());
        assert_eq!(manager.snapshot()["gatewayDomain"]["domain"], "vpn.test");
        host.set_admin(&target_id, true)?;
        let (denied, _) = omabridge::manage::serve_remote(&host, &target_id, &policy).await;
        assert_eq!(denied["error"], "omabridge_remote_forbidden");
        let hijack = serde_json::json!({"action":"gateway-set","peer":target_id,"service":"t3","enabled":true,"host":"other.vpn.test","confirmed":true});
        assert_eq!(manager.execute(&hijack).await, Err("omabridge_gateway_name_reserved"));
        assert_eq!(gateway::load(host.root()), configured);
        manager.execute(&serde_json::json!({"action":"gateway-set","peer":target_id,"service":"t3","enabled":false,"confirmed":true})).await.map_err(anyhow::Error::msg)?;
        // Name ownership survives removal, and re-enabling needs no host/port.
        let reopened = manager.execute(&serde_json::json!({"action":"gateway-set","peer":target_id,"service":"t3","enabled":true,"confirmed":true})).await.map_err(anyhow::Error::msg)?;
        assert_eq!(reopened["gateway"]["url"], entry.url());
        tokio::time::sleep(Duration::from_secs(6)).await;

        let answer = https(port, "laptop.vpn.test", &roots)
            .await
            .expect("the gateway answers");
        assert!(answer.ends_with("ok"), "{answer}");
        assert!(
            https(port, "other.vpn.test", &roots).await.is_none(),
            "unknown names get no certificate"
        );
        let plain = tokio::net::TcpStream::connect(("127.0.0.1", port)).await;
        assert!(plain.is_ok(), "the port listens");

        // Withdrawing public exposure on the target refuses gateway streams at
        // once, while the device itself still reaches t3; the gateway then stops.
        target.set_services(&host.id()?, &["t3".to_owned()], &[])?;
        assert!(
            https(port, "laptop.vpn.test", &roots).await.is_none(),
            "no public grant, no service"
        );
        while gateway::status(host.root())
            .get(&entry.url())
            .is_some_and(|status| status.running)
        {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert_eq!(
            gateway::status(host.root())[&entry.url()].error.as_deref(),
            Some("grant")
        );
        target.set_services(&host.id()?, &["t3".to_owned()], &["t3".to_owned()])?;
        while !gateway::status(host.root())
            .get(&entry.url())
            .is_some_and(|status| status.running)
        {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(https(port, "laptop.vpn.test", &roots).await.is_some());

        // Removing it from the configuration stops it within seconds.
        gateway::save(host.root(), &[])?;
        while gateway::status(host.root()).contains_key(&entry.url()) {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(
            https(port, "laptop.vpn.test", &roots).await.is_none(),
            "stopped"
        );
        node_host.shutdown().await;
        node_target.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}
