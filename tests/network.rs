use omabridge::{Client, Invitation, NetOptions, Node, PairDecision, Store};
use std::{collections::BTreeMap, time::Duration};
use tokio::io::AsyncReadExt;
use tokio::{io::AsyncWriteExt, net::TcpListener};

#[tokio::test]
async fn unknown_peer_and_ungranted_service_are_denied_before_tcp_connect() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let owner = Store::open(&dir.path().join("owner"), "desktop")?;
    let guest = Store::open(&dir.path().join("guest"), "phone")?;
    let tcp = TcpListener::bind("127.0.0.1:0").await?;
    let node = Node::start(
        owner.clone(),
        BTreeMap::from([
            ("t3".into(), tcp.local_addr()?),
            ("ssh".into(), tcp.local_addr()?),
        ]),
        NetOptions::loopback(),
    )
    .await?;
    let client = Client::new(guest.clone(), NetOptions::loopback()).await?;
    assert!(client.open(&node.addr(), "t3").await.is_err());
    let now = omabridge::unix_time()?;
    let token = owner.create_invite(&["t3".into()], Duration::from_secs(60), now)?;
    owner.claim(&token, &guest.id()?, "phone", now)?;
    owner.approve(&guest.id()?, now)?;
    assert!(client.open(&node.addr(), "ssh").await.is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(150), tcp.accept())
            .await
            .is_err()
    );
    client.close().await;
    node.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn direct_mode_rejects_an_unapproved_relay_only_address() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = Store::open(&dir.path().join("guest"), "phone")?;
    let client = Client::new(store, NetOptions::loopback()).await?;
    let addr = iroh::EndpointAddr {
        id: iroh::SecretKey::generate().public(),
        addrs: [iroh::TransportAddr::Relay("https://127.0.0.1:9".parse()?)].into(),
    };
    let error = client
        .open(&addr, "t3")
        .await
        .err()
        .expect("unconfigured relay must be rejected");
    assert!(error.to_string().contains("no route allowed"));
    client.close().await;
    Ok(())
}

#[test]
fn relay_choice_round_trips_and_defaults_to_public() -> anyhow::Result<()> {
    use omabridge::Relay;
    let dir = tempfile::tempdir()?;
    let state = dir.path().join("device");
    assert_eq!(
        Relay::load(&state)?,
        Relay::Public,
        "nothing saved: public relays"
    );
    for text in ["public", "none", "https://relay.example.net/"] {
        let relay = Relay::parse(text)?;
        assert_eq!(relay.arg(), text);
        relay.save(&state)?;
        assert_eq!(Relay::load(&state)?, relay);
    }
    for bad in [
        "",
        "http://relay.example.net",
        "relay.example.net",
        "https://",
    ] {
        assert!(Relay::parse(bad).is_err(), "{bad:?} must be rejected");
    }
    Ok(())
}

/// A relay-only address (a peer behind NAT) is used unless relays are off, even
/// when this device is reached through another relay; the attempt then fails
/// on the network, not on policy.
#[tokio::test]
async fn relay_policy_follows_the_device_choice() -> anyhow::Result<()> {
    use omabridge::Relay;
    let dir = tempfile::tempdir()?;
    let store = Store::open(&dir.path().join("guest"), "phone")?;
    let addr = iroh::EndpointAddr {
        id: iroh::SecretKey::generate().public(),
        addrs: [iroh::TransportAddr::Relay("https://127.0.0.1:9".parse()?)].into(),
    };
    for (relay, allowed) in [
        (Relay::Disabled, false),
        (Relay::Custom("https://127.0.0.1:8".parse()?), true),
        (Relay::Custom("https://127.0.0.1:9".parse()?), true),
    ] {
        let options = NetOptions {
            compress_t3: false,
            bind: "127.0.0.1:0".parse()?,
            relay,
        };
        let client = Client::new(store.clone(), options).await?;
        let error = client
            .open(&addr, "t3")
            .await
            .err()
            .expect("nothing answers");
        assert_eq!(
            !error.to_string().contains("no route allowed"),
            allowed,
            "{error:#}"
        );
        client.close().await;
    }
    Ok(())
}

#[tokio::test]
async fn configured_relay_is_present_in_an_immediate_invitation_address() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let owner = Store::open(&dir.path().join("owner"), "desktop")?;
    let local = TcpListener::bind("127.0.0.1:0").await?;
    let relay: iroh::RelayUrl = "https://127.0.0.1:9".parse()?;
    let node = Node::start(
        owner,
        BTreeMap::from([("egress".into(), local.local_addr()?)]),
        NetOptions {
            compress_t3: false,
            bind: "127.0.0.1:0".parse()?,
            relay: omabridge::Relay::Custom(relay.clone()),
        },
    )
    .await?;
    assert!(
        node.addr()
            .addrs
            .contains(&iroh::TransportAddr::Relay(relay))
    );
    node.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn only_loopback_service_targets_are_accepted() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = Store::open(&dir.path().join("owner"), "desktop")?;
    assert!(
        Node::start(
            store,
            BTreeMap::from([("t3".into(), "192.0.2.1:80".parse()?)]),
            NetOptions::loopback()
        )
        .await
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn reciprocal_pairing_preserves_outbound_route_and_inbound_grant() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(12), async {
        let dir = tempfile::tempdir()?;
        let a = Store::open(&dir.path().join("a"), "alpha")?;
        let b = Store::open(&dir.path().join("b"), "beta")?;
        let socket_a = TcpListener::bind("127.0.0.1:0").await?;
        let socket_b = TcpListener::bind("127.0.0.1:0").await?;
        let node_a = Node::start(
            a.clone(),
            BTreeMap::from([("t3".into(), socket_a.local_addr()?)]),
            NetOptions::loopback(),
        )
        .await?;
        let node_b = Node::start(
            b.clone(),
            BTreeMap::from([("t3".into(), socket_b.local_addr()?)]),
            NetOptions::loopback(),
        )
        .await?;
        let b_client = Client::new(b.clone(), NetOptions::loopback()).await?;
        let a_client = Client::new(a.clone(), NetOptions::loopback()).await?;
        let now = omabridge::unix_time()?;
        let to_a = Invitation {
            version: 1,
            address: node_a.addr(),
            token: a.create_invite(&["t3".into()], Duration::from_secs(60), now)?,
            name: "alpha".into(),
            expires: now + 60,
            manage: false,
        };
        b_client.pair(&to_a, "beta", now).await?;
        a.approve(&b.id()?, now)?;
        b_client.pair(&to_a, "beta", now).await?;
        let outbound = b
            .peers()?
            .into_iter()
            .find(|p| p.id == a.id().unwrap())
            .unwrap();
        assert!(outbound.address.is_some() && outbound.remote_services.contains("t3"));
        assert!(outbound.services.is_empty());
        let to_b = Invitation {
            version: 1,
            address: node_b.addr(),
            token: b.create_invite(&["t3".into()], Duration::from_secs(60), now)?,
            name: "beta".into(),
            expires: now + 60,
            manage: false,
        };
        a_client.pair(&to_b, "alpha", now).await?;
        b.approve(&a.id()?, now)?;
        let reciprocal = b
            .peers()?
            .into_iter()
            .find(|p| p.id == a.id().unwrap())
            .unwrap();
        assert!(reciprocal.services.contains("t3"));
        assert!(
            reciprocal.remote_services.contains("t3"),
            "outbound grant was erased"
        );
        assert_eq!(reciprocal.address, outbound.address);
        a_client.close().await;
        b_client.close().await;
        node_a.shutdown().await;
        node_b.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn approved_device_can_bridge_a_real_tcp_stream() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let dir = tempfile::tempdir()?;
        let now = omabridge::unix_time()?;
        let owner = Store::open(&dir.path().join("owner"), "desktop")?;
        let guest = Store::open(&dir.path().join("guest"), "phone")?;
        let tcp = TcpListener::bind("127.0.0.1:0").await?;
        let target = tcp.local_addr()?;
        let echo = tokio::spawn(async move {
            let (mut socket, _) = tcp.accept().await?;
            let (mut r, mut w) = socket.split();
            tokio::io::copy(&mut r, &mut w).await?;
            w.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        });
        let node = Node::start(
            owner.clone(),
            BTreeMap::from([("t3".into(), target)]),
            NetOptions::loopback(),
        )
        .await?;
        let client = Client::new(guest.clone(), NetOptions::loopback()).await?;
        let invite = Invitation {
            version: 1,
            address: node.addr(),
            token: owner.create_invite(&["t3".into()], Duration::from_secs(60), now)?,
            name: "desktop".into(),
            expires: now + 60,
            manage: false,
        };
        assert!(matches!(
            client.pair(&invite, "phone", now).await?,
            PairDecision::Pending
        ));
        owner.approve(&guest.id()?, now)?;
        assert!(matches!(
            client.pair(&invite, "phone", now).await?,
            PairDecision::Approved { .. }
        ));
        assert!(
            !guest.authorized(&owner.id()?, "t3")?,
            "pairing must not grant reverse service access"
        );
        let mut pipe = client.open(&node.addr(), "t3").await?;
        pipe.send.write_all(b"encrypted T3 stream").await?;
        pipe.send.finish()?;
        assert_eq!(pipe.recv.read_to_end(1024).await?, b"encrypted T3 stream");
        drop(pipe);
        echo.await??;
        client.close().await;
        node.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

fn peer_named(store: &Store, id: &str) -> Option<omabridge::Peer> {
    store.peers().ok()?.into_iter().find(|peer| peer.id == id)
}

/// Renames travel both ways: a device that only dialled announces itself, a
/// serving device announces within seconds, and a revoked device is ignored.
#[tokio::test]
async fn renames_propagate_between_paired_devices() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir = tempfile::tempdir()?;
        let a = Store::open(&dir.path().join("a"), "alpha")?;
        let b = Store::open(&dir.path().join("b"), "beta")?;
        let socket = TcpListener::bind("127.0.0.1:0").await?;
        let node_a = Node::start(
            a.clone(),
            BTreeMap::from([("t3".into(), socket.local_addr()?)]),
            NetOptions::loopback(),
        )
        .await?;
        let now = omabridge::unix_time()?;
        let invite = Invitation {
            version: 1,
            address: node_a.addr(),
            token: a.create_invite(&["t3".into()], Duration::from_secs(60), now)?,
            name: "alpha".into(),
            expires: now + 60,
            manage: false,
        };
        let b_client = Client::new(b.clone(), NetOptions::loopback()).await?;
        b_client.pair(&invite, "beta", now).await?;
        a.approve(&b.id()?, now)?;
        b_client.pair(&invite, "beta", now).await?;

        // B does not serve: it dials A itself and learns A's current name.
        b.set_name("beta laptop")?;
        a.set_name("alpha desk")?;
        assert_eq!(b_client.announce(None).await?, (1, 1));
        assert_eq!(peer_named(&a, &b.id()?).unwrap().name, "beta laptop");
        assert_eq!(peer_named(&b, &a.id()?).unwrap().name, "alpha desk");
        assert!(
            peer_named(&a, &b.id()?).unwrap().address.is_none(),
            "a device that does not serve announces no address"
        );

        // Once B serves, it gives A its address, and A's later renames reach B.
        let socket_b = TcpListener::bind("127.0.0.1:0").await?;
        let node_b = Node::start(
            b.clone(),
            BTreeMap::from([("ssh".into(), socket_b.local_addr()?)]),
            NetOptions::loopback(),
        )
        .await?;
        while peer_named(&a, &b.id()?).unwrap().address.is_none() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            peer_named(&a, &b.id()?).unwrap().address.unwrap(),
            node_b.addr()
        );
        a.set_name("alpha renamed")?;
        while peer_named(&b, &a.id()?).unwrap().name != "alpha renamed" {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // A revoked device can no longer rename itself on A.
        a.revoke(&b.id()?)?;
        b.set_name("intruder")?;
        assert_eq!(b_client.announce(None).await?, (0, 1));
        assert!(peer_named(&a, &b.id()?).is_none());
        b_client.close().await;
        node_b.shutdown().await;
        node_a.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[test]
fn device_names_are_validated() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = Store::open(&dir.path().join("a"), "alpha")?;
    for bad in ["", "   ", "line\nbreak", &"x".repeat(81)] {
        assert!(store.set_name(bad).is_err(), "{bad:?}");
    }
    for spoof in [
        "desk\u{202E}kcol",
        "desk\u{200B}",
        "\u{2066}laptop\u{2069}",
        "a\u{FEFF}b",
    ] {
        assert!(
            store.set_name(spoof).is_err(),
            "{spoof:?} hides or reorders text"
        );
    }
    store.set_name("Mi equipo · casa")?;
    assert_eq!(store.name()?, "Mi equipo · casa");
    Ok(())
}

/// A device that lets another manage it serves that device's commands, within
/// the allowed actions, until it withdraws the permission.
#[tokio::test]
async fn a_managing_device_runs_only_allowed_commands() -> anyhow::Result<()> {
    use serde_json::json;
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir = tempfile::tempdir()?;
        let admin = Store::open(&dir.path().join("admin"), "admin")?;
        let managed = Store::open(&dir.path().join("managed"), "managed")?;
        let socket = TcpListener::bind("127.0.0.1:0").await?;
        let node_admin = Node::start(
            admin.clone(),
            BTreeMap::from([("t3".into(), socket.local_addr()?)]),
            NetOptions::loopback(),
        )
        .await?;
        let now = omabridge::unix_time()?;
        let invite = Invitation {
            version: 1,
            address: node_admin.addr(),
            token: admin.create_invite(&["t3".into()], Duration::from_secs(60), now)?,
            name: "admin".into(),
            expires: now + 60,
            manage: true,
        };
        let managed_client = Client::new(managed.clone(), NetOptions::loopback()).await?;
        managed_client.pair(&invite, "managed", now).await?;
        admin.approve(&managed.id()?, now)?;
        managed_client.pair(&invite, "managed", now).await?;
        managed_client.close().await;

        // Nothing is granted until the managed device says so; then its service
        // tells the admin, with its address.
        managed.set_admin(&admin.id()?, true)?;
        let socket_m = TcpListener::bind("127.0.0.1:0").await?;
        let node_managed = Node::start(
            managed.clone(),
            BTreeMap::from([("ssh".into(), socket_m.local_addr()?)]),
            NetOptions::loopback(),
        )
        .await?;
        while !peer_named(&admin, &managed.id()?).is_some_and(|p| p.managed && p.address.is_some())
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let address = peer_named(&admin, &managed.id()?).unwrap().address.unwrap();
        let admin_client = Client::new(admin.clone(), NetOptions::loopback()).await?;

        let read = admin_client
            .manage(&address, &json!({"action":"read"}))
            .await?;
        assert_eq!(read["device"]["name"], "managed");
        assert!(
            read.get("awaiting").is_none(),
            "its own pairings stay private"
        );
        let renamed = admin_client
            .manage(
                &address,
                &json!({"action":"rename","name":"renamed remotely"}),
            )
            .await?;
        assert_eq!(renamed["device"]["name"], "renamed remotely");
        assert_eq!(managed.name()?, "renamed remotely");
        // It cannot cut itself off or remove a managing device.
        for (command, code) in [
            (
                json!({"action":"relay-set","relay":"none"}),
                "omabridge_remote_forbidden",
            ),
            (
                json!({"action":"relay-set","relay":"https://127.0.0.1:9"}),
                "omabridge_relay_invalid",
            ),
            (
                json!({"action":"relay-set","relay":"https://localhost"}),
                "omabridge_relay_invalid",
            ),
            (
                json!({"action":"revoke","peer":admin.id()?}),
                "omabridge_peer_is_admin",
            ),
            (
                json!({"action":"gateway-set","peer":"ab".repeat(32),"service":"t3","enabled":true}),
                "omabridge_remote_forbidden",
            ),
        ] {
            let answer = admin_client.manage(&address, &command).await?;
            assert_eq!(answer["error"], code, "{command}");
        }
        assert!(peer_named(&managed, &admin.id()?).is_some_and(|p| p.admin));
        let chosen_files = admin_client
            .manage(&address, &json!({"action":"relay-host","enabled":true,"url":"https://relay.example.net","cert":"/etc/passwd","key":"/etc/passwd"}))
            .await?;
        assert_eq!(chosen_files["error"], "omabridge_remote_forbidden", "certificates are the managed device's choice");
        for forbidden in ["bridge-consent-set", "identity-create", "admin-set", "pair", "remote"] {
            let answer = admin_client
                .manage(&address, &json!({"action":forbidden}))
                .await?;
            assert_eq!(answer["error"], "omabridge_remote_forbidden", "{forbidden}");
        }

        // Withdrawing the permission takes effect at once.
        managed.set_admin(&admin.id()?, false)?;
        let refused = admin_client
            .manage(&address, &json!({"action":"read"}))
            .await?;
        assert_eq!(refused["error"], "omabridge_not_admin");
        let flood = admin_client
            .manage(&address, &json!({"action":"x".repeat(1000)}))
            .await?;
        assert_eq!(flood["error"], "omabridge_not_admin");
        let audit = std::fs::read_to_string(managed.root().join("manage-audit.jsonl"))?;
        assert!(
            audit.contains("\"rename\"") && !audit.contains("renamed remotely"),
            "audit names actions, not values"
        );
        assert!(
            !audit.contains("xxxx"),
            "devices that may not manage it leave nothing to flood the log with"
        );
        assert!(audit.contains("\"other\""), "unknown actions are recorded by kind only");
        admin_client.close().await;
        node_managed.shutdown().await;
        node_admin.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

/// A remote relay change that no managing device confirms is undone.
#[test]
fn unconfirmed_remote_relay_changes_are_rolled_back() -> anyhow::Result<()> {
    use omabridge::{
        Relay,
        units::{RunOutput, Runner},
    };
    use std::sync::Mutex;
    #[derive(Default)]
    struct Calls(Mutex<Vec<String>>);
    impl Runner for Calls {
        fn run(&self, args: &[&str]) -> anyhow::Result<RunOutput> {
            self.0.lock().unwrap().push(args.join(" "));
            Ok(RunOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }
    let dir = tempfile::tempdir()?;
    let state = dir.path().join("device");
    Relay::parse("https://relay.example.net")?.save(&state)?;
    let calls = Calls::default();
    assert!(
        !omabridge::manage::rollback_due(&state, &calls),
        "nothing pending"
    );
    let pending = serde_json::json!({"relay":"public","deadline":omabridge::unix_time()? + 60});
    omabridge::write_document(&state.join("relay-rollback.json"), &pending, true)?;
    assert!(
        !omabridge::manage::rollback_due(&state, &calls),
        "not due yet"
    );
    omabridge::manage::confirm_relay(&state);
    assert!(
        !state.join("relay-rollback.json").exists(),
        "confirmed changes stay"
    );
    let expired = serde_json::json!({"relay":"public","deadline":1});
    omabridge::write_document(&state.join("relay-rollback.json"), &expired, true)?;
    assert!(omabridge::manage::rollback_due(&state, &calls));
    assert_eq!(
        Relay::load(&state)?,
        Relay::Public,
        "the previous relay is back"
    );
    assert_eq!(
        *calls.0.lock().unwrap(),
        ["--no-block restart omabridge-serve.service"]
    );
    Ok(())
}

/// Addresses a peer announces cannot point this device at local web services
/// through relays, nor at link-local or unspecified addresses.
#[tokio::test]
async fn announced_addresses_are_sanitized() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir = tempfile::tempdir()?;
        let a = Store::open(&dir.path().join("a"), "alpha")?;
        let b = Store::open(&dir.path().join("b"), "beta")?;
        let socket = TcpListener::bind("127.0.0.1:0").await?;
        let node_a = Node::start(
            a.clone(),
            BTreeMap::from([("t3".into(), socket.local_addr()?)]),
            NetOptions::loopback(),
        )
        .await?;
        let now = omabridge::unix_time()?;
        let invite = Invitation {
            version: 1,
            address: node_a.addr(),
            token: a.create_invite(&["t3".into()], Duration::from_secs(60), now)?,
            name: "alpha".into(),
            expires: now + 60,
            manage: false,
        };
        let client = Client::new(b.clone(), NetOptions::loopback()).await?;
        client.pair(&invite, "beta", now).await?;
        a.approve(&b.id()?, now)?;
        client.pair(&invite, "beta", now).await?;
        // B serves and announces itself to A; A keeps only sensible routes.
        let socket_b = TcpListener::bind("127.0.0.1:0").await?;
        let node_b = Node::start(
            b.clone(),
            BTreeMap::from([("ssh".into(), socket_b.local_addr()?)]),
            NetOptions::loopback(),
        )
        .await?;
        let seen = || peer_named(&a, &b.id().unwrap()).and_then(|peer| peer.address);
        while seen().is_none() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            seen().unwrap(),
            node_b.addr(),
            "loopback stays for several identities on one machine"
        );
        client.close().await;
        node_b.shutdown().await;
        node_a.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

/// A running server forwards for local clients with its own endpoint, with the
/// same checks as `omabridge forward`, for as long as the request stays open.
#[tokio::test]
async fn a_running_server_forwards_for_local_clients() -> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(Duration::from_secs(20), async {
        let dir = tempfile::tempdir()?;
        let now = omabridge::unix_time()?;
        let owner = Store::open(&dir.path().join("owner"), "desktop")?;
        let guest = Store::open(&dir.path().join("guest"), "phone")?;
        let tcp = TcpListener::bind("127.0.0.1:0").await?;
        let target = tcp.local_addr()?;
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = tcp.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = socket.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                    let _ = w.shutdown().await;
                });
            }
        });
        let node = Node::start(
            owner.clone(),
            BTreeMap::from([("t3".into(), target)]),
            NetOptions::loopback(),
        )
        .await?;
        let client = Client::new(guest.clone(), NetOptions::loopback()).await?;
        let invite = Invitation {
            version: 1,
            address: node.addr(),
            token: owner.create_invite(&["t3".into()], Duration::from_secs(60), now)?,
            name: "desktop".into(),
            expires: now + 60,
            manage: false,
        };
        client.pair(&invite, "phone", now).await?;
        owner.approve(&guest.id()?, now)?;
        client.pair(&invite, "phone", now).await?;
        client.close().await;
        let owner_id = owner.id()?;
        let loopback = "127.0.0.1:0".parse()?;

        // No server for this identity yet: the caller forwards by itself.
        assert!(
            omabridge::forward_through_server(&guest, &owner_id, "t3", loopback, None)
                .await
                .is_none()
        );
        // A server publishes at least one service of its own.
        let server = Node::start(
            guest.clone(),
            BTreeMap::from([("ssh".into(), "127.0.0.1:9".parse()?)]),
            NetOptions::loopback(),
        )
        .await?;
        guest.publish_endpoint(&server.addr(), &["ssh".to_owned()])?;

        let ssh = omabridge::forward_through_server(&guest, &owner_id, "ssh", loopback, None).await;
        assert_eq!(refused(ssh), "omabridge_service_not_granted");
        let stranger = omabridge::forward_through_server(&guest, "x", "t3", loopback, None).await;
        assert_eq!(refused(stranger), "omabridge_peer_not_found");
        let public = "0.0.0.0:0".parse()?;
        let open = omabridge::forward_through_server(&guest, &owner_id, "t3", public, None).await;
        assert_eq!(refused(open), "omabridge_forward_invalid");

        let (socket, local) =
            omabridge::forward_through_server(&guest, &owner_id, "t3", loopback, None)
                .await
                .expect("server runs")?;
        assert!(local.ip().is_loopback() && local.port() != 0);
        for _ in 0..2 {
            let mut stream = tokio::net::TcpStream::connect(local).await?;
            stream.write_all(b"through the server").await?;
            stream.shutdown().await?;
            let mut echoed = Vec::new();
            stream.read_to_end(&mut echoed).await?;
            assert_eq!(echoed, b"through the server");
        }

        // A stream over the request itself, e.g. for an SSH ProxyCommand, with
        // the device named instead of its ID; the client may write at once.
        assert_eq!(
            omabridge::find_peer(&guest, "Desktop.omabridge").map(|peer| peer.id),
            Ok(owner_id.clone())
        );
        assert_eq!(
            omabridge::find_peer(&guest, "laptop").err(),
            Some("omabridge_peer_not_found")
        );
        let mut stream = omabridge::connect_through_server(&guest, "desktop", "t3")
            .await
            .expect("server runs")?;
        stream.write_all(b"over stdio").await?;
        stream.get_mut().shutdown().await?;
        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await?;
        assert_eq!(echoed, b"over stdio");
        let denied = omabridge::connect_through_server(&guest, &owner_id, "ssh").await;
        assert_eq!(refused(denied), "omabridge_service_not_granted");

        // Closing the request ends the forward.
        drop(socket);
        let mut closed = false;
        for _ in 0..50 {
            if tokio::net::TcpStream::connect(local).await.is_err() {
                closed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(closed, "the forward outlived its request");
        server.shutdown().await;
        node.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

/// The error code a server answered, or what happened instead.
fn refused<T>(result: Option<anyhow::Result<T>>) -> String {
    match result {
        Some(Err(error)) => format!("{error:#}"),
        Some(Ok(_)) => "accepted".into(),
        None => "no server".into(),
    }
}

/// Without a server, `omabridge connect` dials by itself; stdout carries only
/// the service's bytes and errors are codes on stderr.
#[tokio::test]
async fn connect_cli_carries_stdio_without_a_server() -> anyhow::Result<()> {
    use std::process::Stdio;
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(Duration::from_secs(20), async {
        let dir = tempfile::tempdir()?;
        let now = omabridge::unix_time()?;
        let owner = Store::open(&dir.path().join("owner"), "desktop")?;
        let guest = Store::open(&dir.path().join("guest"), "phone")?;
        let tcp = TcpListener::bind("127.0.0.1:0").await?;
        let target = tcp.local_addr()?;
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = tcp.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = socket.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                    let _ = w.shutdown().await;
                });
            }
        });
        let node = Node::start(
            owner.clone(),
            BTreeMap::from([("ssh".into(), target)]),
            NetOptions::loopback(),
        )
        .await?;
        let client = Client::new(guest.clone(), NetOptions::loopback()).await?;
        let invite = Invitation {
            version: 1,
            address: node.addr(),
            token: owner.create_invite(&["ssh".into()], Duration::from_secs(60), now)?,
            name: "desktop".into(),
            expires: now + 60,
            manage: false,
        };
        client.pair(&invite, "phone", now).await?;
        owner.approve(&guest.id()?, now)?;
        client.pair(&invite, "phone", now).await?;
        client.close().await;

        let connect = |peer: &str, service: &str| {
            let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_omabridge"));
            command
                .arg("--state-dir")
                .arg(dir.path().join("guest"))
                .args(["--relay", "none", "--bind", "127.0.0.1:0", "connect"])
                .args(["--peer", peer, "--service", service])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            command
        };
        let mut child = connect("desktop", "ssh").spawn()?;
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(b"SSH-2.0-test\r\n").await?;
        drop(stdin);
        let mut echoed = Vec::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut echoed)
            .await?;
        assert_eq!(echoed, b"SSH-2.0-test\r\n");
        assert!(child.wait().await?.success());

        let output = connect("laptop", "ssh").output().await?;
        assert!(!output.status.success() && output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("omabridge_peer_not_found"));
        let output = connect("desktop", "t3").output().await?;
        assert!(String::from_utf8_lossy(&output.stderr).contains("omabridge_service_not_granted"));
        node.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn compression_negotiation_and_bidirectional_prefix() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        for (server_on, client_on) in [(false, true), (true, false), (true, true)] {
            let dir = tempfile::tempdir()?;
            let now = omabridge::unix_time()?;
            let owner = Store::open(&dir.path().join("owner"), "desktop")?;
            let guest = Store::open(&dir.path().join("guest"), "phone")?;
            let tcp = TcpListener::bind("127.0.0.1:0").await?;
            let target = tcp.local_addr()?;
            let echo = tokio::spawn(async move {
                let (mut socket, _) = tcp.accept().await?;
                let (mut r, mut w) = socket.split();
                tokio::io::copy(&mut r, &mut w).await?;
                w.shutdown().await?;
                Ok::<_, anyhow::Error>(())
            });
            let node = Node::start(
                owner.clone(),
                BTreeMap::from([("t3".into(), target)]),
                NetOptions {
                    compress_t3: server_on,
                    ..NetOptions::loopback()
                },
            )
            .await?;
            let client = Client::new(
                guest.clone(),
                NetOptions {
                    compress_t3: client_on,
                    ..NetOptions::loopback()
                },
            )
            .await?;
            let invite = Invitation {
                version: 1,
                address: node.addr(),
                token: owner.create_invite(&["t3".into()], Duration::from_secs(60), now)?,
                name: "desktop".into(),
                expires: now + 60,
                manage: false,
            };
            assert!(matches!(
                client.pair(&invite, "phone", now).await?,
                PairDecision::Pending
            ));
            owner.approve(&guest.id()?, now)?;
            assert!(matches!(
                client.pair(&invite, "phone", now).await?,
                PairDecision::Approved { .. }
            ));
            assert!(
                !guest.authorized(&owner.id()?, "t3")?,
                "pairing must not grant reverse service access"
            );
            let mut pipe = client.open(&node.addr(), "t3").await?;
            assert_eq!(pipe.is_compressed(), server_on && client_on);
            let payload = b"T3 event JSON output repeat\n".repeat(10000);
            pipe.write_prefix(b"prefix").await?;
            let (application, mut remote) = tokio::io::duplex(4096);
            let expected = [b"prefix".as_slice(), payload.as_slice()].concat();
            let traffic = async {
                let (mut read, mut write) = tokio::io::split(&mut remote);
                let sending = async {
                    write.write_all(&payload).await?;
                    write.shutdown().await
                };
                let receiving = async {
                    let mut bytes = Vec::new();
                    read.read_to_end(&mut bytes).await?;
                    assert_eq!(bytes, expected);
                    Ok::<_, std::io::Error>(())
                };
                tokio::try_join!(sending, receiving)?;
                Ok::<_, anyhow::Error>(())
            };
            tokio::try_join!(pipe.transfer(application), traffic)?;
            drop(pipe);
            echo.await??;
            client.close().await;
            node.shutdown().await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}
