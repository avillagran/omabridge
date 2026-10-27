use omabridge::{Store, desktop::Desktop};
use std::os::unix::fs::PermissionsExt;
use std::{fs, time::Duration};

#[test]
fn desktop_management_uses_the_real_store_and_private_invitations() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Store::open(&dir.path().join("owner"), "desktop").unwrap();
    let desktop = Desktop::new(owner.clone());
    let peer = iroh::SecretKey::generate().public().to_string();
    assert!(
        desktop
            .issue_invitation("t3", Duration::from_secs(300))
            .is_err(),
        "inactive service must not be offered"
    );
    let address = iroh::EndpointAddr {
        id: owner.secret_key().unwrap().public(),
        addrs: [iroh::TransportAddr::Ip("127.0.0.1:54321".parse().unwrap())].into(),
    };
    let running = owner.reserve_runtime().unwrap();
    owner.publish_endpoint(&address, &["t3".into()]).unwrap();
    assert_eq!(desktop.published_services().unwrap(), vec!["t3"]);
    assert!(
        desktop
            .issue_invitation("ssh", Duration::from_secs(300))
            .is_err()
    );
    let receipt = desktop
        .issue_invitation("t3", Duration::from_secs(300))
        .unwrap();
    assert_eq!(receipt.service, "t3");
    assert!(receipt.path.starts_with(dir.path().join("owner")));
    assert_eq!(
        fs::metadata(&receipt.path).unwrap().permissions().mode() & 0o077,
        0
    );
    let invite: omabridge::Invitation = omabridge::read_document(&receipt.path).unwrap();
    assert_eq!(invite.address.id.to_string(), owner.id().unwrap());
    assert!(!format!("{receipt:?}").contains(&invite.token));
    owner
        .claim(
            &invite.token,
            &peer,
            "phone",
            omabridge::unix_time().unwrap(),
        )
        .unwrap();
    let selected = desktop.refresh().unwrap().pending[0].invitation_id.clone();
    assert!(desktop.approve(&peer, "wrong-invitation").is_err());
    assert!(!owner.authorized(&peer, "t3").unwrap());
    let snapshot = desktop.approve(&peer, &selected).unwrap();
    assert!(snapshot.pending.is_empty());
    assert!(owner.authorized(&peer, "t3").unwrap());
    let after = desktop.revoke(&peer).unwrap();
    assert!(after.peers.is_empty());
    assert!(!owner.authorized(&peer, "t3").unwrap());
    drop(running);
    assert!(
        desktop
            .issue_invitation("t3", Duration::from_secs(300))
            .is_err()
    );
}

#[tokio::test]
async fn desktop_pairs_from_an_invitation_file_and_probes_remote_routes() -> anyhow::Result<()> {
    use omabridge::desktop::PairStatus;
    use omabridge::{NetOptions, Node};
    use std::collections::BTreeMap;
    let dir = tempfile::tempdir()?;
    let owner = Store::open(&dir.path().join("owner"), "desktop")?;
    let guest = Store::open(&dir.path().join("guest"), "phone")?;
    let host = Desktop::new(owner.clone());
    let device = Desktop::with_options(guest.clone(), NetOptions::loopback());
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let node = Node::start(
        owner.clone(),
        BTreeMap::from([("t3".to_owned(), target.local_addr()?)]),
        NetOptions::loopback(),
    )
    .await?;
    owner.publish_endpoint(&node.addr(), &["t3".to_owned()])?;
    let receipt = host.issue_invitation("t3", Duration::from_secs(300))?;
    assert!(device.remote_routes()?.is_empty());

    // A pending pairing never deletes the invitation: it is needed again after approval.
    let first = device.pair(&receipt.path, true).await?;
    assert_eq!(first.status, PairStatus::Pending);
    assert_eq!(first.peer_id, owner.id()?);
    assert_eq!(first.peer_name, "desktop");
    assert!(first.services.is_empty());
    assert!(receipt.path.exists());
    let invite: omabridge::Invitation = omabridge::read_document(&receipt.path)?;
    assert!(!format!("{first:?}").contains(&invite.token));
    assert!(
        device.probe(&owner.id()?, "t3").await.is_err(),
        "unknown route"
    );

    let pending = host.refresh()?.pending[0].invitation_id.clone();
    host.approve(&guest.id()?, &pending)?;
    let second = device.pair(&receipt.path, true).await?;
    assert_eq!(second.status, PairStatus::Approved);
    assert_eq!(second.services, vec!["t3"]);
    assert!(
        !receipt.path.exists(),
        "approved invite removed when requested"
    );

    let routes = device.remote_routes()?;
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].peer_id, owner.id()?);
    assert_eq!(routes[0].peer_name, "desktop");
    assert_eq!(routes[0].services, vec!["t3"]);
    assert!(routes[0].has_address);
    let latency = device.probe(&owner.id()?, "t3").await?;
    assert!(latency < Duration::from_secs(8));
    assert!(device.probe(&owner.id()?, "ssh").await.is_err());
    assert!(device.probe(&owner.id()?, "bad name!").await.is_err());
    // Revocation on the host makes the same probe fail without changing the guest's route list.
    host.revoke(&guest.id()?)?;
    assert!(device.probe(&owner.id()?, "t3").await.is_err());
    assert_eq!(device.remote_routes()?.len(), 1);
    node.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn desktop_pair_rejects_unreadable_or_public_invitations_without_deleting()
-> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let guest = Store::open(&dir.path().join("guest"), "phone")?;
    let device = Desktop::with_options(guest, omabridge::NetOptions::loopback());
    assert!(
        device
            .pair(&dir.path().join("missing.json"), true)
            .await
            .is_err()
    );
    let public = dir.path().join("public.json");
    fs::write(&public, b"{\"token\":\"not-a-secret\"}")?;
    fs::set_permissions(&public, fs::Permissions::from_mode(0o644))?;
    let error = device.pair(&public, true).await.unwrap_err();
    assert!(!format!("{error:#}").contains("not-a-secret"));
    assert!(public.exists());
    Ok(())
}
