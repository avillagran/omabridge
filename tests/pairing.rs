use omabridge::Store;
use std::time::Duration;

#[test]
fn explicitly_selected_invitation_grants_only_its_services() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Store::open(&dir.path().join("owner"), "desktop").unwrap();
    let peer = iroh::SecretKey::generate().public().to_string();
    let t3 = owner
        .create_invite(&["t3".into()], Duration::from_secs(60), 100)
        .unwrap();
    let ssh = owner
        .create_invite(&["ssh".into()], Duration::from_secs(60), 100)
        .unwrap();
    owner.claim(&t3, &peer, "phone", 101).unwrap();
    owner.claim(&ssh, &peer, "phone", 101).unwrap();
    let pending = owner.pending().unwrap();
    let chosen = pending
        .iter()
        .find(|item| item.peer.id == peer && item.peer.services.contains("ssh"))
        .unwrap();
    owner
        .approve_selected(&peer, Some(&chosen.invitation_id), 102)
        .unwrap();
    assert!(owner.authorized(&peer, "ssh").unwrap());
    assert!(!owner.authorized(&peer, "t3").unwrap());
    assert!(owner.claim(&t3, &peer, "phone", 103).is_err());
}

#[test]
fn two_pending_invitations_cannot_choose_an_arbitrary_grant() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Store::open(&dir.path().join("owner"), "desktop").unwrap();
    let peer = iroh::SecretKey::generate().public().to_string();
    let t3 = owner
        .create_invite(&["t3".into()], Duration::from_secs(60), 100)
        .unwrap();
    let ssh = owner
        .create_invite(&["ssh".into()], Duration::from_secs(60), 100)
        .unwrap();
    owner.claim(&t3, &peer, "phone", 101).unwrap();
    owner.claim(&ssh, &peer, "phone", 101).unwrap();
    assert!(
        owner.approve(&peer, 102).is_err(),
        "ambiguous grant must require explicit selection"
    );
    assert!(!owner.authorized(&peer, "t3").unwrap());
    assert!(!owner.authorized(&peer, "ssh").unwrap());
}

#[test]
fn expired_pending_invitation_does_not_block_another_valid_one() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Store::open(&dir.path().join("owner"), "desktop").unwrap();
    let peer = iroh::SecretKey::generate().public().to_string();
    let old = owner
        .create_invite(&["ssh".into()], Duration::from_secs(1), 100)
        .unwrap();
    let live = owner
        .create_invite(&["t3".into()], Duration::from_secs(60), 100)
        .unwrap();
    owner.claim(&old, &peer, "phone", 100).unwrap();
    owner.claim(&live, &peer, "phone", 100).unwrap();
    owner.approve(&peer, 101).unwrap();
    assert!(owner.authorized(&peer, "t3").unwrap());
    assert!(!owner.authorized(&peer, "ssh").unwrap());
}

#[test]
fn expired_approved_invite_is_pruned_without_revoking_membership() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("owner");
    let owner = Store::open(&path, "desktop").unwrap();
    let peer = iroh::SecretKey::generate().public().to_string();
    let token = owner
        .create_invite(&["t3".into()], Duration::from_secs(1), 100)
        .unwrap();
    owner.claim(&token, &peer, "phone", 100).unwrap();
    owner.approve(&peer, 100).unwrap();
    assert!(owner.claim(&token, &peer, "phone", 102).is_err());
    owner
        .create_invite(&["t3".into()], Duration::from_secs(60), 102)
        .unwrap();
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path.join("state.json")).unwrap()).unwrap();
    assert_eq!(state["invites"].as_object().unwrap().len(), 1);
    assert!(owner.authorized(&peer, "t3").unwrap());
}

#[test]
fn expired_invitation_never_authorizes_a_device() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Store::open(&dir.path().join("owner"), "desktop").unwrap();
    let peer = iroh::SecretKey::generate().public().to_string();
    let token = owner
        .create_invite(&["t3".into()], Duration::from_secs(1), 100)
        .unwrap();
    assert!(owner.claim(&token, &peer, "phone", 101).is_err());
    assert!(!owner.authorized(&peer, "t3").unwrap());
}

#[test]
fn pending_invitation_cannot_be_approved_after_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Store::open(&dir.path().join("owner"), "desktop").unwrap();
    let peer = iroh::SecretKey::generate().public().to_string();
    let token = owner
        .create_invite(&["t3".into()], Duration::from_secs(2), 100)
        .unwrap();
    owner.claim(&token, &peer, "phone", 101).unwrap();
    assert!(owner.approve(&peer, 102).is_err());
    assert!(!owner.authorized(&peer, "t3").unwrap());
}

#[test]
fn concurrent_claims_have_one_winner() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Store::open(&dir.path().join("owner"), "desktop").unwrap();
    let token = owner
        .create_invite(&["t3".into()], Duration::from_secs(60), 100)
        .unwrap();
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let store = owner.clone();
            let token = token.clone();
            std::thread::spawn(move || {
                store
                    .claim(
                        &token,
                        &iroh::SecretKey::generate().public().to_string(),
                        "phone",
                        101,
                    )
                    .is_ok()
            })
        })
        .collect();
    assert_eq!(
        workers
            .into_iter()
            .filter_map(|w| w.join().ok())
            .filter(|ok| *ok)
            .count(),
        1
    );
}

#[test]
fn revoked_device_cannot_redeem_old_invitation() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Store::open(&dir.path().join("owner"), "desktop").unwrap();
    let guest = Store::open(&dir.path().join("guest"), "phone").unwrap();
    let peer = guest.id().unwrap();
    let token = owner
        .create_invite(&["t3".into()], Duration::from_secs(60), 100)
        .unwrap();
    owner.claim(&token, &peer, "phone", 101).unwrap();
    owner.approve(&peer, 102).unwrap();
    owner.revoke(&peer).unwrap();
    assert!(!owner.authorized(&peer, "t3").unwrap());
    assert!(owner.claim(&token, &peer, "phone", 103).is_err());
}

#[test]
fn invitation_requires_approval_and_is_bound_to_one_device() {
    use omabridge::PairDecision;
    let dir = tempfile::tempdir().unwrap();
    let owner = Store::open(&dir.path().join("owner"), "desktop").unwrap();
    let guest = Store::open(&dir.path().join("guest"), "phone").unwrap();
    let stranger = Store::open(&dir.path().join("other"), "other").unwrap();
    let token = owner
        .create_invite(&["t3".into()], Duration::from_secs(60), 100)
        .unwrap();
    let guest_id = guest.id().unwrap();
    assert!(matches!(
        owner.claim(&token, &guest_id, "phone", 101).unwrap(),
        PairDecision::Pending
    ));
    assert!(!owner.authorized(&guest_id, "t3").unwrap());
    assert!(
        owner
            .claim(&token, &stranger.id().unwrap(), "other", 102)
            .is_err()
    );
    owner.approve(&guest_id, 103).unwrap();
    assert!(matches!(
        owner.claim(&token, &guest_id, "phone", 104).unwrap(),
        PairDecision::Approved { .. }
    ));
    assert!(owner.authorized(&guest_id, "t3").unwrap());
    assert!(!owner.authorized(&guest_id, "ssh").unwrap());
}
