use omabridge::Store;
use std::time::Duration;

#[test]
fn gui_and_cli_resolve_the_same_default_state_directory() {
    let root = std::path::Path::new("/home/tester");
    let xdg = std::path::Path::new("/home/tester/.data");
    assert_eq!(
        omabridge::state_dir_from(Some(xdg), Some(root)),
        xdg.join("omabridge")
    );
    assert_eq!(
        omabridge::state_dir_from(Some(std::path::Path::new("relative")), Some(root)),
        root.join(".local/share/omabridge")
    );
}

#[test]
fn snapshot_is_consistent_and_never_serializes_private_identity_or_invitation() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Store::open(&dir.path().join("owner"), "desktop").unwrap();
    let peer = iroh::SecretKey::generate().public().to_string();
    let token = owner
        .create_invite(&["t3".into()], Duration::from_secs(60), 100)
        .unwrap();
    owner.claim(&token, &peer, "phone", 101).unwrap();
    let snapshot = owner.snapshot().unwrap();
    assert_eq!(snapshot.id, owner.id().unwrap());
    assert_eq!(snapshot.name, "desktop");
    assert!(snapshot.peers.is_empty());
    assert_eq!(snapshot.pending.len(), 1);
    assert_eq!(snapshot.pending[0].peer.id, peer);
    assert!(snapshot.pending[0].peer.services.contains("t3"));
    let public = serde_json::to_string(&snapshot).unwrap();
    assert!(!public.contains(&token));
    assert!(!public.contains("secret"));
    owner.approve(&peer, 102).unwrap();
    let approved = owner.snapshot().unwrap();
    assert!(approved.pending.is_empty());
    assert!(approved.peers.iter().any(|item| item.id == peer));
}

#[test]
fn corrupt_state_is_not_silently_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node");
    Store::open(&path, "desktop").unwrap();
    std::fs::write(path.join("state.json"), b"broken state").unwrap();
    assert!(Store::open(&path, "desktop").is_err());
    assert_eq!(
        std::fs::read(path.join("state.json")).unwrap(),
        b"broken state"
    );
}

#[test]
fn exposed_or_symlinked_state_is_rejected() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node");
    Store::open(&path, "desktop").unwrap();
    std::fs::set_permissions(
        path.join("state.json"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(Store::open(&path, "desktop").is_err());
    let link = dir.path().join("alias");
    symlink(&path, &link).unwrap();
    assert!(Store::open(&link, "desktop").is_err());
}

#[test]
fn reserving_runtime_invalidates_stale_endpoint_until_republished() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Store::open(&dir.path().join("owner"), "desktop").unwrap();
    let address = iroh::EndpointAddr {
        id: owner.secret_key().unwrap().public(),
        addrs: [iroh::TransportAddr::Ip("127.0.0.1:54321".parse().unwrap())].into(),
    };
    owner.publish_endpoint(&address, &["t3".into()]).unwrap();
    let reservation = owner.reserve_runtime().unwrap();
    assert!(
        owner.active_endpoint().is_err(),
        "stale endpoint must not be advertised during startup"
    );
    owner.publish_endpoint(&address, &["t3".into()]).unwrap();
    assert!(owner.active_endpoint().is_ok());
    drop(reservation);
    assert!(owner.active_endpoint().is_err());
}

#[test]
fn device_identity_survives_reopening() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("node");
    let first = Store::open(&path, "desktop").unwrap();
    let id = first.id().unwrap();
    drop(first);
    let second = Store::open(&path, "desktop").unwrap();
    assert_eq!(id, second.id().unwrap());
    assert_eq!(std::fs::read_dir(&path).unwrap().count(), 2);
}
