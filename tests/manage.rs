use omabridge::manage::{Manager, SERVE_UNIT};
use omabridge::units::{MARKER, RunOutput, Runner, Units};
use omabridge::{NetOptions, Node, Store};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

/// Stands in for `systemctl --user`; nothing reaches the real user manager.
#[derive(Default)]
struct FakeRunner {
    calls: Mutex<Vec<String>>,
    active: Mutex<bool>,
}
impl Runner for FakeRunner {
    fn run(&self, args: &[&str]) -> anyhow::Result<RunOutput> {
        self.calls.lock().unwrap().push(args.join(" "));
        let mut active = self.active.lock().unwrap();
        match args.first().copied() {
            Some("restart") => *active = true,
            Some("disable") => *active = false,
            _ => {}
        }
        let word = if *active { "active" } else { "inactive" };
        Ok(RunOutput {
            success: args.first() != Some(&"is-active") || *active,
            stdout: match args.first().copied() {
                Some("is-active") => format!("{word}\n"),
                Some("is-enabled") => "enabled\n".to_owned(),
                _ => String::new(),
            },
            stderr: String::new(),
        })
    }
}

fn manager(root: &Path, name: &str, runner: Arc<FakeRunner>) -> Manager {
    let invites = root.join(format!("{name}-invites"));
    fs::create_dir_all(&invites).unwrap();
    Manager {
        state_dir: root.join(format!("{name}-state")),
        options: NetOptions::loopback(),
        units: Units::new(root.join(format!("{name}-units")), runner),
        binary: root.join("bin/omabridge"),
        awaiting_dir: root.join(format!("{name}-awaiting")),
        invite_dir: invites,
        // Nothing listens on port 9 of loopback in the test environment.
        ssh_target: "127.0.0.1:9".parse().unwrap(),
        mcp_target: "127.0.0.1:9".parse().unwrap(),
        t3_runtime: root.join(format!("{name}-t3/server-runtime.json")),
        publish_wait: Duration::ZERO,
        pair_timeout: Duration::from_secs(20),
        remote: false,
    }
}

async fn ok(manager: &Manager, request: Value) -> Value {
    manager
        .execute(&request)
        .await
        .unwrap_or_else(|code| panic!("{request} failed with {code}"))
}

#[tokio::test]
async fn manage_runs_the_whole_pairing_lifecycle_with_confirmation() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let host = manager(dir.path(), "host", Arc::default());
    let guest = manager(dir.path(), "guest", Arc::default());

    // Reading never creates an identity; changes need explicit confirmation.
    assert_eq!(
        ok(&host, json!({"action":"endpoints"})).await,
        json!({"endpoints":[]})
    );
    assert!(
        !host.state_dir.exists(),
        "endpoint discovery must not create identity"
    );
    let fresh = ok(&host, json!({"action":"read"})).await;
    assert_eq!(fresh["identity"], false);
    assert_eq!(fresh["device"], Value::Null);
    assert!(!host.state_dir.exists());
    assert_eq!(
        host.execute(&json!({"action":"identity-create"})).await,
        Err("confirmation_required")
    );
    assert_eq!(
        host.execute(&json!({"action":"set","confirmed":true}))
            .await,
        Err("invalid_action")
    );
    assert_eq!(host.execute(&json!([])).await, Err("invalid_command"));
    let created = ok(&host, json!({"action":"identity-create","confirmed":true})).await;
    let host_id = created["device"]["id"].as_str().unwrap().to_owned();
    assert_eq!(host_id.len(), 64);

    // Inviting needs this device to be served.
    assert_eq!(
        host.execute(&json!({"action":"invite","services":["t3"],"confirmed":true}))
            .await,
        Err("omabridge_not_published")
    );
    let owner = Store::open(&host.state_dir, "unused")?;
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let node = Node::start(
        owner.clone(),
        BTreeMap::from([("t3".to_owned(), target.local_addr()?)]),
        NetOptions::loopback(),
    )
    .await?;
    owner.publish_endpoint(&node.addr(), &["t3".to_owned()])?;
    let served = ok(&host, json!({"action":"read"})).await;
    assert_eq!(served["published"]["active"], true);
    assert_eq!(
        served["published"]["external"], true,
        "not served by the OmaBridge unit"
    );
    assert_eq!(served["published"]["services"], json!(["t3"]));
    assert_eq!(
        host.execute(&json!({"action":"invite","services":["ssh"],"confirmed":true}))
            .await,
        Err("omabridge_service_not_published")
    );
    assert_eq!(
        host.execute(&json!({"action":"invite","services":["t3"],"ttl":5,"confirmed":true}))
            .await,
        Err("invalid_command")
    );

    // The invitation: a private file plus an optional QR, returned once.
    let invited = ok(
        &host,
        json!({"action":"invite","services":["t3"],"qr":true,"confirmed":true}),
    )
    .await;
    let created = &invited["created"];
    let path = created["path"].as_str().unwrap().to_owned();
    assert!(Path::new(&path).starts_with(&host.invite_dir));
    assert!(
        Path::new(&path)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("omabridge-invite-")
    );
    assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o077, 0);
    assert!(
        created["qrImage"]
            .as_str()
            .unwrap()
            .starts_with("data:image/svg+xml;base64,")
    );
    assert_eq!(created["services"], json!(["t3"]));
    let invite: omabridge::Invitation = omabridge::read_document(Path::new(&path))?;
    assert!(
        !invited.to_string().contains(&invite.token),
        "the token never leaves"
    );
    let after = ok(&host, json!({"action":"read"})).await;
    assert!(
        !after.to_string().contains("omabridge-invite-"),
        "a read does not repeat the invitation"
    );

    // Discarding only touches our own invitation files.
    let spare = ok(
        &host,
        json!({"action":"invite","services":["t3"],"confirmed":true}),
    )
    .await;
    assert_eq!(spare["created"]["qrImage"], Value::Null);
    let spare_path = spare["created"]["path"].as_str().unwrap().to_owned();
    assert_eq!(
        host.execute(&json!({"action":"invite-discard","path":"relative.json","confirmed":true}))
            .await,
        Err("invalid_command")
    );
    ok(
        &host,
        json!({"action":"invite-discard","path":spare_path,"confirmed":true}),
    )
    .await;
    assert!(!Path::new(&spare_path).exists());

    // The guest pairs from a private copy and waits for approval.
    let paired = ok(
        &guest,
        json!({"action":"pair","path":format!("file://{path}"),"confirmed":true}),
    )
    .await;
    assert_eq!(paired["paired"]["status"], "pending");
    assert_eq!(paired["awaiting"].as_array().unwrap().len(), 1);
    let waiting = paired["paired"]["id"].as_str().unwrap().to_owned();
    assert_eq!(paired["awaiting"][0]["id"], waiting.as_str());
    assert_eq!(
        fs::metadata(guest.awaiting_dir.join(format!("{waiting}.json")))?
            .permissions()
            .mode()
            & 0o077,
        0
    );
    let guest_id = paired["device"]["id"].as_str().unwrap().to_owned();

    let request = ok(&host, json!({"action":"read"})).await;
    assert_eq!(request["pending"][0]["id"], guest_id.as_str());
    assert_eq!(request["pending"][0]["services"], json!(["t3"]));
    assert_eq!(
        host.execute(&json!({"action":"approve","peer":guest_id}))
            .await,
        Err("confirmation_required")
    );
    let approved = ok(
        &host,
        json!({"action":"approve","peer":guest_id,"expires":request["pending"][0]["expires"],"confirmed":true}),
    )
    .await;
    assert!(approved["pending"].as_array().unwrap().is_empty());
    assert_eq!(approved["peers"][0]["services"], json!(["t3"]));

    // "Check again" completes the pairing and forgets the copy.
    let retried = ok(
        &guest,
        json!({"action":"pair-retry","id":waiting,"confirmed":true}),
    )
    .await;
    assert_eq!(retried["paired"]["status"], "approved");
    assert!(retried["awaiting"].as_array().unwrap().is_empty());
    assert_eq!(retried["peers"][0]["id"], host_id.as_str());
    assert_eq!(retried["peers"][0]["remoteServices"], json!(["t3"]));

    let revoked = ok(
        &host,
        json!({"action":"revoke","peer":guest_id,"confirmed":true}),
    )
    .await;
    assert!(revoked["peers"].as_array().unwrap().is_empty());
    assert_eq!(
        host.execute(&json!({"action":"revoke","peer":guest_id,"confirmed":true}))
            .await,
        Err("omabridge_peer_not_found")
    );
    assert_eq!(
        guest
            .execute(&json!({"action":"pair-retry","id":"not-an-id","confirmed":true}))
            .await,
        Err("invalid_command")
    );
    node.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn manage_pair_rejects_invalid_and_expired_invitations() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let guest = manager(dir.path(), "guest", Arc::default());
    let bogus = dir.path().join("omabridge-invite-bogus.json");
    fs::write(&bogus, "{}")?;
    fs::set_permissions(&bogus, fs::Permissions::from_mode(0o600))?;
    assert_eq!(
        guest
            .execute(&json!({"action":"pair","path":bogus,"confirmed":true}))
            .await,
        Err("omabridge_invite_invalid")
    );
    assert_eq!(
        guest
            .execute(&json!({"action":"pair","path":"relative.json","confirmed":true}))
            .await,
        Err("omabridge_invite_unreadable")
    );
    let owner = Store::open(&dir.path().join("owner"), "desktop")?;
    let address = iroh::EndpointAddr {
        id: owner.secret_key()?.public(),
        addrs: [iroh::TransportAddr::Ip("127.0.0.1:9".parse()?)].into(),
    };
    let expired = dir.path().join("omabridge-invite-expired.json");
    let invite = omabridge::Invitation {
        version: 1,
        address,
        token: "token".to_owned(),
        name: "desktop".to_owned(),
        expires: 1,
        manage: false,
    };
    omabridge::write_document(&expired, &invite, false)?;
    assert_eq!(
        guest
            .execute(&json!({"action":"pair","path":expired,"confirmed":true}))
            .await,
        Err("omabridge_invite_expired")
    );
    assert!(
        ok(&guest, json!({"action":"read"})).await["awaiting"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn manage_publishes_through_the_single_omabridge_unit() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let runner = Arc::new(FakeRunner::default());
    let mut host = manager(dir.path(), "host", runner.clone());
    let ssh = std::net::TcpListener::bind("127.0.0.1:0")?;
    let t3 = std::net::TcpListener::bind("127.0.0.1:0")?;
    fs::create_dir_all(host.t3_runtime.parent().unwrap())?;
    fs::write(
        &host.t3_runtime,
        json!({"port": t3.local_addr()?.port()}).to_string(),
    )?;

    assert_eq!(
        host.execute(&json!({"action":"publish","ssh":true,"confirmed":true}))
            .await,
        Err("omabridge_ssh_unavailable")
    );
    host.ssh_target = ssh.local_addr()?;
    let read = ok(&host, json!({"action":"read"})).await;
    assert_eq!(read["published"]["enabled"], false, "off by default");
    assert_eq!(read["published"]["sshAvailable"], true);
    assert_eq!(read["published"]["t3Available"], true);
    assert_eq!(read["published"]["mcpAvailable"], false);
    assert_eq!(
        host.execute(&json!({"action":"publish","mcp":true,"confirmed":true}))
            .await,
        Err("omabridge_mcp_unavailable")
    );

    let published = ok(
        &host,
        json!({"action":"publish","ssh":true,"confirmed":true}),
    )
    .await;
    assert_eq!(
        published["identity"], true,
        "publishing creates the identity it needs"
    );
    assert_eq!(published["published"]["enabled"], true);
    assert_eq!(published["published"]["services"], json!(["t3", "ssh"]));
    assert_eq!(published["published"]["stale"], false);
    let unit = fs::read_to_string(host.units.dir().join(SERVE_UNIT))?;
    assert_eq!(unit.lines().next(), Some(MARKER));
    assert!(unit.contains(&format!("--service t3={}", t3.local_addr()?)));
    assert!(unit.contains(&format!("--t3-runtime {}", host.t3_runtime.display())));
    assert_eq!(published["published"]["followsT3"], true);
    assert!(unit.contains(&format!("--service ssh={}", ssh.local_addr()?)));
    let calls = runner.calls.lock().unwrap().clone();
    assert!(calls.contains(&"daemon-reload".to_owned()));
    assert!(calls.contains(&format!("enable {SERVE_UNIT}")));
    assert!(calls.contains(&format!("restart {SERVE_UNIT}")));

    // The MCP gateway is published as `mcp` only while it listens.
    let mcp = std::net::TcpListener::bind("127.0.0.1:0")?;
    host.mcp_target = mcp.local_addr()?;
    let with_mcp = ok(
        &host,
        json!({"action":"publish","ssh":true,"mcp":true,"confirmed":true}),
    )
    .await;
    assert_eq!(with_mcp["published"]["mcpAvailable"], true);
    assert_eq!(
        with_mcp["published"]["services"],
        json!(["t3", "ssh", "mcp"])
    );
    let unit = fs::read_to_string(host.units.dir().join(SERVE_UNIT))?;
    assert!(unit.contains(&format!("--service mcp={}", mcp.local_addr()?)));

    // A legacy front end omits MCP; preserve consent and the exact configured
    // target, even while the gateway is temporarily down.
    let mcp_target = mcp.local_addr()?;
    drop(mcp);
    host.mcp_target = "127.0.0.1:9".parse()?;
    ok(
        &host,
        json!({"action":"publish","ssh":true,"confirmed":true}),
    )
    .await;
    let unit = fs::read_to_string(host.units.dir().join(SERVE_UNIT))?;
    assert!(unit.contains(&format!("--service mcp={mcp_target}")));
    assert_eq!(
        host.execute(&json!({"action":"publish","mcp":"false","confirmed":true}))
            .await,
        Err("invalid_command")
    );
    assert_eq!(fs::read_to_string(host.units.dir().join(SERVE_UNIT))?, unit);
    ok(
        &host,
        json!({"action":"publish","mcp":false,"confirmed":true}),
    )
    .await;
    assert!(!fs::read_to_string(host.units.dir().join(SERVE_UNIT))?.contains("--service mcp="));

    // Managed publishing follows T3 across port changes without republishing.
    let moved = std::net::TcpListener::bind("127.0.0.1:0")?;
    fs::write(
        &host.t3_runtime,
        json!({"port": moved.local_addr()?.port()}).to_string(),
    )?;
    assert_eq!(
        ok(&host, json!({"action":"read"})).await["published"]["stale"],
        false
    );
    ok(
        &host,
        json!({"action":"publish","t3":true,"confirmed":true}),
    )
    .await;
    let unit = fs::read_to_string(host.units.dir().join(SERVE_UNIT))?;
    assert!(unit.contains(&format!("--service t3={}", moved.local_addr()?)));
    assert!(!unit.contains("--service ssh="));

    let off = ok(&host, json!({"action":"unpublish","confirmed":true})).await;
    assert_eq!(off["published"]["enabled"], false);
    assert!(!host.units.dir().join(SERVE_UNIT).exists());
    ok(&host, json!({"action":"unpublish","confirmed":true})).await;

    // A unit OmaBridge did not write is never replaced or removed.
    fs::write(
        host.units.dir().join(SERVE_UNIT),
        "[Service]\nExecStart=/bin/true\n",
    )?;
    assert_eq!(
        host.execute(&json!({"action":"publish","confirmed":true}))
            .await,
        Err("omabridge_unit_foreign")
    );
    assert_eq!(
        host.execute(&json!({"action":"unpublish","confirmed":true}))
            .await,
        Err("omabridge_unit_foreign")
    );
    fs::remove_file(host.units.dir().join(SERVE_UNIT))?;
    drop(t3);
    drop(moved);
    fs::remove_file(&host.t3_runtime)?;
    assert_eq!(
        host.execute(&json!({"action":"publish","t3":true,"confirmed":true}))
            .await,
        Err("omabridge_t3_unavailable")
    );
    assert_eq!(
        host.execute(&json!({"action":"publish","confirmed":true}))
            .await,
        Err("omabridge_nothing_to_publish")
    );
    Ok(())
}

#[tokio::test]
async fn manage_saves_the_relay_and_restarts_its_own_unit() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let runner = Arc::new(FakeRunner::default());
    let mut host = manager(dir.path(), "host", runner.clone());
    let read = ok(&host, json!({"action":"read"})).await;
    assert_eq!(
        read["relay"],
        json!({"mode":"public","url":null}),
        "public by default"
    );
    assert_eq!(
        host.execute(&json!({"action":"relay-set","relay":"none"}))
            .await,
        Err("confirmation_required")
    );
    for bad in ["", "http://relay.example.net", "ftp://x", &"x".repeat(600)] {
        assert_eq!(
            host.execute(&json!({"action":"relay-set","relay":bad,"confirmed":true}))
                .await,
            Err("omabridge_relay_invalid"),
            "{bad}"
        );
    }
    let custom = ok(
        &host,
        json!({"action":"relay-set","relay":"https://relay.example.net","confirmed":true}),
    )
    .await;
    assert_eq!(
        custom["relay"],
        json!({"mode":"custom","url":"https://relay.example.net/"})
    );
    assert_eq!(
        custom["identity"], false,
        "choosing a relay creates no identity"
    );
    assert!(
        runner.calls.lock().unwrap().is_empty(),
        "nothing published, nothing restarted"
    );

    let ssh = std::net::TcpListener::bind("127.0.0.1:0")?;
    host.ssh_target = ssh.local_addr()?;
    ok(
        &host,
        json!({"action":"publish","ssh":true,"confirmed":true}),
    )
    .await;
    runner.calls.lock().unwrap().clear();
    let none = ok(
        &host,
        json!({"action":"relay-set","relay":"none","confirmed":true}),
    )
    .await;
    assert_eq!(none["relay"]["mode"], "none");
    assert!(
        runner
            .calls
            .lock()
            .unwrap()
            .contains(&format!("restart {SERVE_UNIT}")),
        "the publishing unit picks up the new relay"
    );
    let unit = fs::read_to_string(host.units.dir().join(SERVE_UNIT))?;
    assert!(!unit.contains("--relay"), "the unit reads the saved choice");
    Ok(())
}

#[tokio::test]
async fn manage_renames_the_device_and_syncs_without_confirmation() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let host = manager(dir.path(), "host", Arc::new(FakeRunner::default()));
    assert_eq!(
        host.execute(&json!({"action":"rename","name":"desk","confirmed":true}))
            .await,
        Err("omabridge_identity_missing")
    );
    ok(&host, json!({"action":"identity-create","confirmed":true})).await;
    assert_eq!(
        host.execute(&json!({"action":"rename","name":"desk"}))
            .await,
        Err("confirmation_required")
    );
    for bad in ["", "  ", "a\nb", &"x".repeat(81)] {
        assert_eq!(
            host.execute(&json!({"action":"rename","name":bad,"confirmed":true}))
                .await,
            Err("omabridge_name_invalid"),
            "{bad:?}"
        );
    }
    let renamed = ok(
        &host,
        json!({"action":"rename","name":"  Desk at home ","confirmed":true}),
    )
    .await;
    assert_eq!(renamed["device"]["name"], "Desk at home");
    assert_eq!(
        renamed["renamed"],
        json!({"via":"direct","reached":0,"total":0}),
        "an unserved device with no reachable peers tells nobody"
    );
    let synced = ok(&host, json!({"action":"sync"})).await;
    assert_eq!(
        synced["synced"]["via"], "direct",
        "sync needs no confirmation"
    );
    Ok(())
}

/// An invitation that asks to manage this device needs the user's explicit
/// answer, and only this device's front end grants or withdraws management.
#[tokio::test]
async fn manage_requires_consent_before_being_managed() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let guest = manager(dir.path(), "guest", Arc::new(FakeRunner::default()));
    ok(&guest, json!({"action":"identity-create","confirmed":true})).await;
    let owner = Store::open(&dir.path().join("owner"), "admin desk")?;
    let invite = omabridge::Invitation {
        version: 1,
        address: iroh::EndpointAddr {
            id: owner.secret_key()?.public(),
            addrs: [iroh::TransportAddr::Ip("127.0.0.1:9".parse()?)].into(),
        },
        token: "token".to_owned(),
        name: "admin desk".to_owned(),
        expires: omabridge::unix_time()? + 600,
        manage: true,
    };
    let path = dir.path().join("omabridge-invite-admin.json");
    omabridge::write_document(&path, &invite, false)?;

    let inspected = ok(&guest, json!({"action":"invite-inspect","path":path})).await;
    assert_eq!(
        inspected["invitation"],
        json!({"name":"admin desk","expires":invite.expires,"manage":true,"id":owner.id()?}),
        "inspecting needs no confirmation and shows the request"
    );
    assert!(inspected["invitation"].get("token").is_none());
    assert_eq!(
        guest
            .execute(&json!({"action":"pair","path":path,"allowManage":true,"expect":"ab".repeat(32),"confirmed":true}))
            .await,
        Err("omabridge_invite_changed"),
        "a file swapped since it was shown is refused"
    );
    assert_eq!(
        guest
            .execute(&json!({"action":"pair","path":path,"confirmed":true}))
            .await,
        Err("omabridge_manage_consent_required")
    );
    // With an answer, pairing goes ahead (here the inviter is unreachable).
    assert_eq!(
        guest
            .execute(&json!({"action":"pair","path":path,"allowManage":true,"confirmed":true}))
            .await,
        Err("omabridge_peer_unreachable")
    );
    let awaiting = ok(&guest, json!({"action":"read"})).await["awaiting"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        guest
            .awaiting_dir
            .join(format!("{awaiting}.admin"))
            .exists(),
        "consent kept for Check again"
    );
    ok(
        &guest,
        json!({"action":"pair-discard","id":awaiting,"confirmed":true}),
    )
    .await;
    assert!(
        !guest
            .awaiting_dir
            .join(format!("{awaiting}.admin"))
            .exists(),
        "and dropped with the pairing"
    );

    assert_eq!(
        guest
            .execute(&json!({"action":"admin-set","peer":"ab".repeat(32),"allowed":true,"confirmed":true}))
            .await,
        Err("omabridge_peer_not_found")
    );
    assert_eq!(
        guest
            .execute(&json!({"action":"admin-set","peer":"ab".repeat(32),"allowed":true}))
            .await,
        Err("confirmation_required")
    );
    assert_eq!(
        guest
            .execute(&json!({"action":"remote","peer":"ab".repeat(32),"command":{"action":"read"}}))
            .await,
        Err("omabridge_not_managed"),
        "only devices that allowed it can be managed"
    );
    assert_eq!(
        guest
            .execute(&json!({"action":"remote","peer":"ab".repeat(32),"command":{"action":"rename","name":"x"}}))
            .await,
        Err("confirmation_required"),
        "remote changes need confirmation; remote reads do not"
    );
    assert_eq!(
        guest
            .execute(&json!({"action":"remote","peer":"ab".repeat(32),"command":{"action":"invite"},"confirmed":true}))
            .await,
        Err("omabridge_remote_forbidden")
    );
    Ok(())
}

/// While this device serves, remote commands and announcements go through its
/// running server, and the managed device's new name comes back within seconds.
#[tokio::test]
async fn manage_reaches_managed_devices_through_the_running_server() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(40), async {
        let dir = tempfile::tempdir()?;
        let host = manager(dir.path(), "host", Arc::new(FakeRunner::default()));
        ok(&host, json!({"action":"identity-create","confirmed":true})).await;
        let admin = Store::open(&host.state_dir, "admin")?;
        let socket = std::net::TcpListener::bind("127.0.0.1:0")?;
        let node_admin = Node::start(
            admin.clone(),
            BTreeMap::from([("t3".to_owned(), socket.local_addr()?)]),
            NetOptions::loopback(),
        )
        .await?;
        admin.publish_endpoint(&node_admin.addr(), &["t3".to_owned()])?;
        assert!(host.state_dir.join("control.sock").exists());

        let managed = Store::open(&dir.path().join("managed"), "managed")?;
        let now = omabridge::unix_time()?;
        let invite = omabridge::Invitation {
            version: 1,
            address: node_admin.addr(),
            token: admin.create_invite(&["t3".into()], Duration::from_secs(60), now)?,
            name: "admin".into(),
            expires: now + 60,
            manage: true,
        };
        let client = omabridge::Client::new(managed.clone(), NetOptions::loopback()).await?;
        client.pair(&invite, "managed", now).await?;
        admin.approve(&managed.id()?, now)?;
        client.pair(&invite, "managed", now).await?;
        client.close().await;
        managed.set_admin(&admin.id()?, true)?;
        let ssh = std::net::TcpListener::bind("127.0.0.1:0")?;
        let node_managed = Node::start(
            managed.clone(),
            BTreeMap::from([("ssh".to_owned(), ssh.local_addr()?)]),
            NetOptions::loopback(),
        )
        .await?;
        let id = managed.id()?;
        let seen = |name: &str| {
            admin
                .peers()
                .unwrap()
                .into_iter()
                .any(|peer| peer.id == id && peer.managed && peer.name == name)
        };
        while !seen("managed") {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let renamed = ok(
            &host,
            json!({"action":"remote","peer":id,"command":{"action":"rename","name":"far away"},"confirmed":true}),
        )
        .await;
        assert_eq!(renamed["remote"]["device"]["name"], "far away");
        while !seen("far away") {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let local = ok(
            &host,
            json!({"action":"rename","name":"admin desk","confirmed":true}),
        )
        .await;
        assert_eq!(
            local["renamed"],
            json!({"via":"service","reached":1,"total":1}),
            "the running server announces at once and reports who answered"
        );
        assert!(
            managed
                .peers()?
                .iter()
                .any(|peer| peer.name == "admin desk")
        );
        // Pairing while published also goes through the running server.
        let third = Store::open(&dir.path().join("third"), "third")?;
        let socket_third = std::net::TcpListener::bind("127.0.0.1:0")?;
        let node_third = Node::start(
            third.clone(),
            BTreeMap::from([("t3".to_owned(), socket_third.local_addr()?)]),
            NetOptions::loopback(),
        )
        .await?;
        let now = omabridge::unix_time()?;
        let to_third = omabridge::Invitation {
            version: 1,
            address: node_third.addr(),
            token: third.create_invite(&["t3".into()], Duration::from_secs(60), now)?,
            name: "third".into(),
            expires: now + 60,
            manage: false,
        };
        let path = dir.path().join("omabridge-invite-third.json");
        omabridge::write_document(&path, &to_third, false)?;
        let pending = ok(&host, json!({"action":"pair","path":path,"confirmed":true})).await;
        assert_eq!(pending["paired"]["status"], "pending");
        third.approve(&admin.id()?, now)?;
        let id = pending["paired"]["id"].as_str().unwrap().to_owned();
        let approved = ok(&host, json!({"action":"pair-retry","id":id,"confirmed":true})).await;
        assert_eq!(approved["paired"]["status"], "approved");
        assert_eq!(approved["paired"]["peer"], third.id()?);
        assert!(approved["peers"].as_array().unwrap().iter().any(|peer| peer["name"] == "third"));
        node_third.shutdown().await;
        node_managed.shutdown().await;
        node_admin.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn manage_hosts_a_relay_only_with_a_matching_certificate() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let host = manager(dir.path(), "host", Arc::new(FakeRunner::default()));
    let enable = json!({"action":"relay-host","enabled":true,"url":"https://relay.example.net:3341","confirmed":true});
    assert_eq!(
        host.execute(&enable).await,
        Err("omabridge_identity_missing")
    );
    ok(&host, json!({"action":"identity-create","confirmed":true})).await;
    assert_eq!(
        host.execute(&enable).await,
        Err("omabridge_not_published"),
        "the running server hosts it"
    );
    let store = Store::open(&host.state_dir, "host")?;
    let socket = std::net::TcpListener::bind("127.0.0.1:0")?;
    let node = Node::start(
        store.clone(),
        BTreeMap::from([("ssh".to_owned(), socket.local_addr()?)]),
        NetOptions::loopback(),
    )
    .await?;
    store.publish_endpoint(&node.addr(), &["ssh".to_owned()])?;
    let read = ok(&host, json!({"action":"read"})).await;
    assert_eq!(
        read["relayHost"],
        json!({"enabled":false,"url":null,"running":false,"error":null,"suggested":null})
    );

    let cert = rcgen::generate_simple_self_signed(vec!["relay.example.net".to_owned()])?;
    let (cert_path, key_path) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
    fs::write(&cert_path, cert.cert.pem())?;
    fs::write(&key_path, cert.signing_key.serialize_pem())?;
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
    let mismatch = json!({"action":"relay-host","enabled":true,"url":"https://other.example.net:3341",
        "cert":cert_path,"key":key_path,"confirmed":true});
    assert_eq!(
        host.execute(&mismatch).await,
        Err("omabridge_relay_certificate")
    );
    let hosted = ok(
        &host,
        json!({"action":"relay-host","enabled":true,"url":"https://relay.example.net:3341",
            "cert":cert_path,"key":key_path,"confirmed":true}),
    )
    .await;
    assert_eq!(hosted["relayHost"]["enabled"], true);
    assert_eq!(
        hosted["relayHost"]["url"],
        "https://relay.example.net:3341/"
    );
    let off = ok(
        &host,
        json!({"action":"relay-host","enabled":false,"confirmed":true}),
    )
    .await;
    assert_eq!(off["relayHost"]["enabled"], false);
    node.shutdown().await;
    Ok(())
}

#[test]
fn manage_cli_reads_stdin_and_reports_codes() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let dir = tempfile::tempdir().unwrap();
    let run = |input: &[u8]| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_omabridge"))
            .args(["--state-dir"])
            .arg(dir.path().join("state"))
            .arg("manage")
            .env_clear()
            .env("HOME", dir.path())
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .env("XDG_STATE_HOME", dir.path().join("xdg-state"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let _ = child.stdin.take().unwrap().write_all(input);
        let output = child.wait_with_output().unwrap();
        assert!(output.stderr.is_empty(), "nothing on stderr");
        let body: Value = serde_json::from_slice(&output.stdout).unwrap();
        (output.status.code(), body)
    };
    let (code, read) = run(br#"{"action":"read"}"#);
    assert_eq!(code, Some(0));
    assert_eq!(read["available"], true);
    assert_eq!(read["identity"], false);
    assert!(!dir.path().join("state").exists(), "a read creates nothing");
    assert_eq!(
        run(br#"{"action":"identity-create"}"#),
        (Some(1), json!({"error":"confirmation_required"}))
    );
    assert_eq!(
        run(b"not json"),
        (Some(1), json!({"error":"invalid_command"}))
    );
    assert_eq!(
        run(&vec![b' '; 70 * 1024]),
        (Some(1), json!({"error":"invalid_command"}))
    );
    let (code, created) = run(br#"{"action":"identity-create","confirmed":true}"#);
    assert_eq!(code, Some(0));
    assert_eq!(created["identity"], true);
}

#[tokio::test]
async fn broken_domain_policy_cannot_prevent_closing_a_gateway() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let manager = manager(dir.path(), "gateway", Arc::default());
    let store = Store::open(&manager.state_dir, "gateway")?;
    let peer = "a".repeat(64);
    let entry = omabridge::gateway::Gateway {
        host: "node.hosts.example.com".into(),
        port: 443,
        peer: peer.clone(),
        service: "t3".into(),
    };
    omabridge::gateway::save(store.root(), &[entry])?;
    fs::write(store.root().join("gateway-domain.json"), "{")?;
    let request =
        json!({"action":"gateway-set","peer":peer,"service":"t3","enabled":true,"confirmed":true});
    assert_eq!(
        manager.execute(&request).await,
        Err("omabridge_gateway_domain_invalid")
    );
    let mut close = request;
    close["enabled"] = false.into();
    assert!(manager.execute(&close).await.is_ok());
    assert!(omabridge::gateway::load(store.root()).is_empty());
    Ok(())
}
