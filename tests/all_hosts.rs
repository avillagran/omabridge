//! All-hosts invitations over real loopback QUIC: a phone, its selected bridge and
//! a host that never paired with the phone. The T3 executable and descriptor are
//! isolated fixtures.
use anyhow::Result;
use omabridge::{
    Client, Invitation, NetOptions, Node, PairDecision, Store, catalog,
    catalog_publisher::write_issuers,
    manage::{self, Manager},
    t3_pair::{DELEGATED_LABEL_PREFIX, LABEL_PREFIX, T3Issuer, delegated_label},
    units::{Runner, Units},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap, os::unix::fs::PermissionsExt, path::Path, sync::Arc, time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

const BRIDGE_ENV: &str = "00000000-0000-4000-8000-000000000001";
const HOST_ENV: &str = "00000000-0000-4000-8000-000000000002";
const LIMIT: Duration = Duration::from_secs(60);

fn issuer(dir: &Path, name: &str, environment: &str) -> Result<T3Issuer> {
    let base_dir = dir.join(name);
    std::fs::create_dir_all(base_dir.join("userdata"))?;
    std::fs::write(
        base_dir.join("userdata/environment-id"),
        format!("{environment}\n"),
    )?;
    let cli = dir.join(format!("{name}-t3"));
    // Waits while `hold` exists, so a test can act in the middle of issuance.
    std::fs::write(
        &cli,
        r#"#!/usr/bin/python3
import json,pathlib,sys,time
args=sys.argv[1:]
home=pathlib.Path(args[args.index('--base-dir')+1])
(home/'calls').open('a').write(json.dumps(args)+'\n')
(home/'started').write_text('1')
while (home/'hold').exists():
    time.sleep(0.02)
label=args[args.index('--label')+1]
print(json.dumps({'id':'p1','credential':'pairing-secret','label':label,'expiresAt':'2099-01-01T00:00:00Z'}))
"#,
    )?;
    std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o700))?;
    Ok(T3Issuer { cli, base_dir })
}

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

async fn node(store: &Store, t3: std::net::SocketAddr, issuer: T3Issuer) -> Result<Node> {
    Node::start_with_t3_issuer(
        store.clone(),
        BTreeMap::from([("t3".into(), t3)]),
        NetOptions::loopback(),
        store.reserve_runtime()?,
        None,
        None,
        Some(Some(issuer)),
    )
    .await
}

struct Lab {
    _dir: tempfile::TempDir,
    bridge: Store,
    host: Store,
    phone: Store,
    bridge_node: Node,
    _host_node: Node,
    /// The phone's endpoint.
    client: Client,
    /// The bridge's identity, to announce to the host on demand.
    announcer: Client,
    host_issuer: T3Issuer,
}

impl Lab {
    /// The bridge paired with the host, which shares `t3` but has not consented.
    async fn new() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let bridge = Store::open(&dir.path().join("bridge"), "bridge")?;
        let host = Store::open(&dir.path().join("host"), "host")?;
        let phone = Store::open(&dir.path().join("phone"), "phone")?;
        let host_issuer = issuer(dir.path(), "host-t3", HOST_ENV)?;
        let bridge_issuer = issuer(dir.path(), "bridge-t3", BRIDGE_ENV)?;
        let host_node = node(&host, descriptor(HOST_ENV).await?, host_issuer.clone()).await?;
        let announcer = Client::new(bridge.clone(), NetOptions::loopback()).await?;
        let now = omabridge::unix_time()?;
        let token = host.create_invite(&["t3".into()], LIMIT, now)?;
        let invitation = Invitation {
            version: 1,
            address: host_node.addr(),
            token,
            name: "host".into(),
            expires: now + 60,
            manage: false,
        };
        announcer.pair(&invitation, "bridge", now).await?;
        host.approve(&bridge.id()?, now)?;
        announcer.pair(&invitation, "bridge", now).await?;
        let bridge_node = node(
            &bridge,
            descriptor(BRIDGE_ENV).await?,
            bridge_issuer.clone(),
        )
        .await?;
        let client = Client::new(phone.clone(), NetOptions::loopback()).await?;
        Ok(Self {
            _dir: dir,
            bridge,
            host,
            phone,
            bridge_node,
            _host_node: host_node,
            client,
            announcer,
            host_issuer,
        })
    }

    fn approve_phone(&self, all_hosts: bool) -> Result<()> {
        let now = omabridge::unix_time()?;
        let services = ["t3".to_owned()];
        let token = if all_hosts {
            self.bridge.create_all_hosts_invite(&services, LIMIT, now)?
        } else {
            self.bridge.create_invite(&services, LIMIT, now)?
        };
        self.bridge.claim(&token, &self.phone.id()?, "phone", now)?;
        self.bridge.approve(&self.phone.id()?, now)
    }

    /// Hello to the host, which answers with its consent and routes.
    async fn sync(&self) -> Result<()> {
        let (reached, _) = self.announcer.announce(None).await?;
        anyhow::ensure!(reached == 1, "host unreachable");
        Ok(())
    }

    /// What auto-publish would have left: the catalog and the issuers.
    fn publish(&self) -> Result<()> {
        let revision = omabridge::unix_time()?;
        catalog::publish_source(
            &self.bridge,
            &json!({"version":1,"revision":revision,
                "environments":[
                    {"id":HOST_ENV,"name":"host","enabled":true},
                    {"id":BRIDGE_ENV,"name":"bridge","enabled":true}],
                "endpoints":[],"clients":{self.phone.id()?:[HOST_ENV,BRIDGE_ENV]}}),
        )?;
        write_issuers(
            &self.bridge,
            &BTreeMap::from([
                (HOST_ENV.to_owned(), self.host.id()?),
                (BRIDGE_ENV.to_owned(), self.bridge.id()?),
            ]),
        )
    }

    async fn ask(&self, environment: &str) -> String {
        match self
            .client
            .t3_host_pair(&self.bridge_node.addr(), environment)
            .await
        {
            Ok(pairing) => pairing.label,
            Err(error) => format!("{error}"),
        }
    }

    fn calls(&self) -> usize {
        std::fs::read_to_string(self.host_issuer.base_dir.join("calls"))
            .map_or(0, |calls| calls.lines().count())
    }

    /// Everything in place: phone approved, host consented and announced.
    async fn ready() -> Result<Self> {
        let lab = Self::new().await?;
        lab.approve_phone(true)?;
        lab.host.set_bridge_consent(&lab.bridge.id()?, true)?;
        lab.sync().await?;
        lab.publish()?;
        Ok(lab)
    }

    async fn close(self) {
        self.client.close().await;
        self.announcer.close().await;
        self.bridge_node.shutdown().await;
        self._host_node.shutdown().await;
    }
}

#[tokio::test]
async fn a_phone_gets_a_consenting_host_it_never_paired_with() -> Result<()> {
    tokio::time::timeout(LIMIT, async {
        let lab = Lab::ready().await?;
        let (bridge, phone) = (lab.bridge.id()?, lab.phone.id()?);
        let peer = lab
            .bridge
            .peers()?
            .into_iter()
            .find(|p| p.id == lab.host.id().unwrap())
            .unwrap();
        assert!(peer.remote_bridge_consent, "reported in Hello");

        let pairing = lab
            .client
            .t3_host_pair(&lab.bridge_node.addr(), HOST_ENV)
            .await?;
        assert_eq!(pairing.environment_id, HOST_ENV);
        assert_eq!(pairing.credential, "pairing-secret");
        assert_eq!(pairing.label, delegated_label(&bridge, &phone));
        assert_eq!(
            pairing.label,
            format!("omabridge-delegated:{bridge}:{phone}")
        );
        // Omarchy T3 Code revokes `omabridge:<id>` sessions of non-peers.
        assert!(pairing.label.starts_with(DELEGATED_LABEL_PREFIX));
        assert!(!pairing.label.starts_with(LABEL_PREFIX));
        let calls = std::fs::read_to_string(lab.host_issuer.base_dir.join("calls"))?;
        let args: Vec<String> = serde_json::from_str(calls.lines().next().unwrap())?;
        assert_eq!(&args[..3], ["auth", "pairing", "create"]);
        assert!(args.windows(2).any(|w| w == ["--ttl", "2m"]));
        assert!(!args.iter().any(|a| a == "--scope"), "T3's default scopes");

        // The same request renews.
        assert_eq!(lab.ask(HOST_ENV).await, delegated_label(&bridge, &phone));
        // The bridge's own T3 is an ordinary peer pairing, revoked as one.
        assert_eq!(lab.ask(BRIDGE_ENV).await, format!("{LABEL_PREFIX}{phone}"));
        lab.close().await;
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn a_host_announces_its_own_routes_only_to_a_consented_bridge() -> Result<()> {
    tokio::time::timeout(LIMIT, async {
        let lab = Lab::new().await?;
        let host_id = lab.host.id()?;
        let bridge_id = lab.bridge.id()?;
        // The bridge is also the public gateway of the host's T3.
        lab.host
            .set_services(&bridge_id, &["t3".into()], &["t3".into()])?;
        omabridge::gateway::save(
            lab.bridge.root(),
            &[omabridge::gateway::Gateway {
                host: "host.example.net".into(),
                port: 8443,
                peer: host_id.clone(),
                service: "t3".into(),
            }],
        )?;
        let reported = || -> Result<(bool, usize)> {
            let peers = lab.bridge.peers()?;
            let host = peers.iter().find(|p| p.id == host_id).unwrap();
            Ok((host.remote_bridge_consent, host.remote_routes.len()))
        };
        lab.sync().await?;
        assert_eq!(reported()?, (false, 0), "no consent, no route");
        lab.host.set_bridge_consent(&bridge_id, true)?;
        lab.sync().await?;
        assert_eq!(reported()?, (true, 1));
        let peers = lab.bridge.peers()?;
        let host = peers.iter().find(|p| p.id == host_id).unwrap();
        assert_eq!(host.remote_routes[0].url, "https://host.example.net:8443/");
        lab.host.set_bridge_consent(&bridge_id, false)?;
        lab.sync().await?;
        assert_eq!(reported()?, (false, 0), "withdrawn with the consent");
        lab.close().await;
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn a_host_without_consent_is_refused_and_t3_never_runs() -> Result<()> {
    tokio::time::timeout(LIMIT, async {
        let lab = Lab::new().await?;
        lab.approve_phone(true)?;
        lab.sync().await?;
        lab.publish()?;
        assert_eq!(lab.ask(HOST_ENV).await, "omabridge_host_pair_refused");
        assert_eq!(lab.calls(), 0, "a plain t3 grant does not imply consent");

        // The host decides, whatever the bridge believes: consent withdrawn but
        // not yet announced.
        lab.host.set_bridge_consent(&lab.bridge.id()?, true)?;
        lab.sync().await?;
        lab.host.set_bridge_consent(&lab.bridge.id()?, false)?;
        assert_eq!(lab.ask(HOST_ENV).await, "omabridge_host_pair_refused");
        assert_eq!(lab.calls(), 0);

        // Announcing a false bit never sets the local one on the other side.
        assert!(lab.bridge.peers()?.iter().all(|p| !p.bridge_consent));
        lab.close().await;
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn consent_withdrawn_during_issuance_stops_delivery() -> Result<()> {
    tokio::time::timeout(LIMIT, async {
        let lab = Lab::ready().await?;
        let home = lab.host_issuer.base_dir.clone();
        std::fs::write(home.join("hold"), "")?;
        let asking = lab.ask(HOST_ENV);
        let withdraw = async {
            while !home.join("started").exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            lab.host.set_bridge_consent(&lab.bridge.id()?, false)?;
            std::fs::remove_file(home.join("hold"))?;
            anyhow::Ok(())
        };
        let (answer, withdrawn) = tokio::join!(asking, withdraw);
        withdrawn?;
        assert_eq!(answer, "omabridge_host_pair_refused");
        assert_eq!(lab.calls(), 1, "T3 did run; the receipt was dropped");
        lab.close().await;
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn the_phone_losing_its_rights_during_issuance_gets_nothing() -> Result<()> {
    tokio::time::timeout(LIMIT, async {
        let lab = Lab::ready().await?;
        let home = lab.host_issuer.base_dir.clone();
        std::fs::write(home.join("hold"), "")?;
        let asking = lab.ask(HOST_ENV);
        let withdraw = async {
            while !home.join("started").exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            lab.bridge.set_services(&lab.phone.id()?, &[], &[])?;
            std::fs::remove_file(home.join("hold"))?;
            anyhow::Ok(())
        };
        let (answer, withdrawn) = tokio::join!(asking, withdraw);
        withdrawn?;
        assert_eq!(answer, "omabridge_host_pair_refused");
        lab.close().await;
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn a_plain_grant_and_foreign_environments_are_refused() -> Result<()> {
    tokio::time::timeout(LIMIT, async {
        let lab = Lab::new().await?;
        lab.approve_phone(false)?;
        lab.host.set_bridge_consent(&lab.bridge.id()?, true)?;
        lab.sync().await?;
        lab.publish()?;
        assert_eq!(lab.ask(HOST_ENV).await, "omabridge_host_pair_refused");
        assert_eq!(lab.calls(), 0);

        // Approved for all hosts, but outside its catalog.
        lab.approve_phone(true)?;
        let other = "00000000-0000-4000-8000-00000000000f";
        assert_eq!(lab.ask(other).await, "omabridge_host_pair_refused");

        // Losing t3 clears the flag: granting t3 again does not bring it back.
        lab.bridge.set_services(&lab.phone.id()?, &[], &[])?;
        lab.bridge
            .set_services(&lab.phone.id()?, &["t3".into()], &[])?;
        assert_eq!(lab.ask(HOST_ENV).await, "omabridge_host_pair_refused");
        assert_eq!(lab.calls(), 0);
        lab.close().await;
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn pairing_through_a_bridge_is_rate_limited_per_device() -> Result<()> {
    tokio::time::timeout(LIMIT, async {
        let lab = Lab::ready().await?;
        for _ in 0..16 {
            assert!(lab.ask(HOST_ENV).await.starts_with(DELEGATED_LABEL_PREFIX));
        }
        assert_eq!(lab.ask(HOST_ENV).await, "omabridge_host_pair_refused");
        assert_eq!(lab.calls(), 16);
        lab.close().await;
        Ok(())
    })
    .await?
}

#[test]
fn consent_follows_the_t3_grant_and_needs_one() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let host = Store::open(&dir.path().join("host"), "host")?;
    let bridge = Store::open(&dir.path().join("bridge"), "bridge")?;
    let now = omabridge::unix_time()?;
    let id = bridge.id()?;
    let token = host.create_invite(&["ssh".into()], LIMIT, now)?;
    host.claim(&token, &id, "bridge", now)?;
    host.approve(&id, now)?;
    assert!(host.set_bridge_consent(&id, true).is_err(), "no t3 grant");
    host.set_services(&id, &["t3".into()], &[])?;
    assert!(!host.bridge_consented(&id)?, "a t3 grant is not consent");
    host.set_bridge_consent(&id, true)?;
    assert!(host.bridge_consented(&id)?);
    host.set_bridge_consent(&id, false)?;
    assert!(!host.bridge_consented(&id)?, "withdrawable");
    host.set_bridge_consent(&id, true)?;
    host.set_services(&id, &["ssh".into()], &[])?;
    host.set_services(&id, &["t3".into()], &[])?;
    assert!(
        !host.bridge_consented(&id)?,
        "a new grant does not revive it"
    );
    assert!(
        host.create_all_hosts_invite(&["ssh".into()], LIMIT, now)
            .is_err(),
        "all hosts means T3"
    );
    Ok(())
}

#[test]
fn pending_shows_all_hosts_and_a_new_approval_replaces_it() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let owner = Store::open(&dir.path().join("owner"), "owner")?;
    let phone = Store::open(&dir.path().join("phone"), "phone")?;
    let now = omabridge::unix_time()?;
    let id = phone.id()?;
    let token = owner.create_all_hosts_invite(&["t3".into()], LIMIT, now)?;
    owner.claim(&token, &id, "phone", now)?;
    let pending = owner.pending()?;
    assert!(pending[0].peer.all_hosts);
    owner.approve(&id, now)?;
    assert!(owner.all_hosts_allowed(&id)?);
    assert!(matches!(
        owner.claim(&token, &id, "phone", now)?,
        PairDecision::Approved {
            all_hosts: true,
            ..
        }
    ));
    // Re-enrollment replaces the rights, as it does for services.
    let token = owner.create_invite(&["t3".into()], LIMIT, now)?;
    owner.claim(&token, &id, "phone", now)?;
    assert!(!owner.pending()?[0].peer.all_hosts);
    owner.approve(&id, now)?;
    assert!(!owner.all_hosts_allowed(&id)?);
    Ok(())
}

#[test]
fn state_and_answers_of_older_devices_still_parse() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let store = Store::open(&dir.path().join("device"), "device")?;
    let path = store.root().join("state.json");
    let mut state: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    // Exactly what the previous release wrote: none of the new fields.
    let peer = "a".repeat(64);
    state["peers"] = json!({peer.clone():{"id":peer,"name":"old","services":["t3"],
        "remote_services":[],"address":null}});
    state["invites"] = json!({"h":{"expires":u64::MAX,"services":["t3"],
        "pending":[peer,"old"],"approved":false}});
    std::fs::write(&path, serde_json::to_vec(&state)?)?;
    let old = store.peers()?.remove(0);
    assert!(!old.all_hosts && !old.bridge_consent && !old.remote_bridge_consent);
    assert!(old.remote_routes.is_empty());
    assert!(
        !store.pending()?[0].peer.all_hosts,
        "old invites stay plain"
    );

    let decision: PairDecision =
        serde_json::from_value(json!({"status":"approved","services":["t3"]}))?;
    assert!(matches!(
        decision,
        PairDecision::Approved {
            all_hosts: false,
            ..
        }
    ));
    // Invitations stay as they were: old peers refuse unknown fields there.
    let invitation = Invitation {
        version: 1,
        address: iroh::EndpointAddr::new(store.id()?.parse()?),
        token: "t".into(),
        name: "n".into(),
        expires: 1,
        manage: false,
    };
    let fields = serde_json::to_value(&invitation)?;
    assert_eq!(
        fields.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["address", "expires", "name", "token", "version"]
    );
    Ok(())
}

struct NoUnits;
impl Runner for NoUnits {
    fn run(&self, _args: &[&str]) -> Result<omabridge::units::RunOutput> {
        anyhow::bail!("no systemd here")
    }
}

fn manager(root: &Path) -> Manager {
    let directory = root.join("units");
    std::fs::create_dir_all(&directory).unwrap();
    Manager {
        state_dir: root.join("device"),
        options: NetOptions::loopback(),
        units: Units::new(directory, Arc::new(NoUnits)),
        binary: "/usr/bin/omabridge".into(),
        awaiting_dir: root.join("awaiting"),
        invite_dir: root.to_path_buf(),
        ssh_target: "127.0.0.1:22".parse().unwrap(),
        mcp_target: "127.0.0.1:8787".parse().unwrap(),
        t3_runtime: root.join("runtime.json"),
        publish_wait: Duration::ZERO,
        pair_timeout: Duration::from_secs(1),
        remote: false,
    }
}

#[tokio::test]
async fn remote_approval_of_an_all_hosts_invite_is_blocked() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut remote = manager(dir.path());
    let store = Store::open(&remote.state_dir, "device")?;
    let (phone, plain) = (
        Store::open(&dir.path().join("p"), "p")?,
        Store::open(&dir.path().join("q"), "q")?,
    );
    let now = omabridge::unix_time()?;
    let token = store.create_all_hosts_invite(&["t3".into()], LIMIT, now)?;
    store.claim(&token, &phone.id()?, "phone", now)?;
    let token = store.create_invite(&["t3".into()], LIMIT, now)?;
    store.claim(&token, &plain.id()?, "plain", now)?;

    let snapshot = remote.snapshot();
    let shown: Vec<_> = snapshot["pending"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["allHosts"].clone())
        .collect();
    assert!(shown.contains(&json!(true)) && shown.contains(&json!(false)));

    let approve = |peer: String| json!({"action":"approve","peer":peer,"confirmed":true});
    remote.remote = true;
    assert_eq!(
        remote.execute(&approve(phone.id()?)).await.unwrap_err(),
        "omabridge_remote_forbidden"
    );
    assert!(!store.all_hosts_allowed(&phone.id()?)?);
    // Ordinary remote approval keeps working.
    remote.execute(&approve(plain.id()?)).await.unwrap();
    assert!(store.authorized(&plain.id()?, "t3")?);
    // The owner, at this device, can.
    remote.remote = false;
    remote.execute(&approve(phone.id()?)).await.unwrap();
    assert!(store.all_hosts_allowed(&phone.id()?)?);
    assert_eq!(
        remote.snapshot()["peers"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["allHosts"] == true)
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn consent_cannot_be_set_by_a_managing_device() -> Result<()> {
    assert!(!manage::REMOTE_ACTIONS.contains(&"bridge-consent-set"));
    let dir = tempfile::tempdir()?;
    let store = Store::open(&dir.path().join("host"), "host")?;
    let admin = Store::open(&dir.path().join("admin"), "admin")?;
    let bridge = Store::open(&dir.path().join("bridge"), "bridge")?;
    let now = omabridge::unix_time()?;
    for peer in [&admin, &bridge] {
        let token = store.create_invite(&["t3".into()], LIMIT, now)?;
        store.claim(&token, &peer.id()?, "peer", now)?;
        store.approve(&peer.id()?, now)?;
    }
    store.set_admin(&admin.id()?, true)?;
    let command = json!({"action":"bridge-consent-set","peer":bridge.id()?,"allowed":true});
    let (answer, _) = manage::serve_remote(&store, &admin.id()?, &command).await;
    assert_eq!(answer["error"], "omabridge_remote_forbidden");
    assert!(!store.bridge_consented(&bridge.id()?)?);

    // The real remote entry point refuses an all-hosts approval too.
    let phone = Store::open(&dir.path().join("phone"), "phone")?;
    let token = store.create_all_hosts_invite(&["t3".into()], LIMIT, now)?;
    store.claim(&token, &phone.id()?, "phone", now)?;
    let command = json!({"action":"approve","peer":phone.id()?});
    let (answer, _) = manage::serve_remote(&store, &admin.id()?, &command).await;
    assert_eq!(answer["error"], "omabridge_remote_forbidden");
    assert!(!store.authorized(&phone.id()?, "t3")?);

    let local = manager(dir.path());
    let command =
        json!({"action":"bridge-consent-set","peer":"zz","allowed":true,"confirmed":true});
    assert_eq!(
        local.execute(&command).await.unwrap_err(),
        "invalid_command"
    );
    Ok(())
}

#[test]
fn delegated_labels_are_not_peer_labels() {
    let label = delegated_label(&"a".repeat(64), &"b".repeat(64));
    assert!(label.strip_prefix(LABEL_PREFIX).is_none());
    assert!(label.len() <= 256);
}

/// T3's token endpoint and descriptor, answering `scope` for `expires_in`.
async fn t3_exchange(scope: &'static str, expires_in: i64) -> Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut bytes = vec![0; 8192];
            let read = socket.read(&mut bytes).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&bytes[..read]);
            let body = if request.starts_with("POST /oauth/token") {
                json!({"access_token":"session-token","token_type":"Bearer","scope":scope,"expires_in":expires_in})
            } else {
                json!({"environmentId":HOST_ENV})
            }
            .to_string();
            let _ = socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await;
        }
    });
    Ok(format!("http://{addr}/"))
}

#[tokio::test(flavor = "multi_thread")]
async fn redeeming_gives_a_long_lived_write_session_and_nothing_less() -> Result<()> {
    const DAY: i64 = 24 * 60 * 60;
    let pairing: omabridge::t3_pair::T3Pairing = serde_json::from_value(json!({
        "environmentId":HOST_ENV,"credential":"pairing-secret","label":delegated_label("a","b")
    }))?;
    let redeem = |url: String| {
        let pairing = serde_json::to_value(&pairing).unwrap();
        tokio::task::spawn_blocking(move || {
            let pairing = serde_json::from_value(pairing)?;
            omabridge::enrollment::redeem_pairing(&pairing, &url, 1_000)
        })
    };
    let url = t3_exchange("orchestration:read orchestration:operate", 30 * DAY).await?;
    let receipt = redeem(url).await??;
    let expires = 1_000 + 30 * DAY as u64 * 1000;
    assert_eq!(receipt["accessToken"], "session-token");
    assert_eq!(receipt["expiresAt"], expires);
    assert_eq!(receipt["renewAfter"], expires - 7 * DAY as u64 * 1000);
    assert_eq!(receipt["status"], "native_authorized");

    // A read-only or unbounded session never passes as the native credential.
    let url = t3_exchange("orchestration:read", 30 * DAY).await?;
    assert!(redeem(url).await?.is_err());
    let url = t3_exchange("orchestration:operate", 365 * DAY).await?;
    assert!(redeem(url).await?.is_err());
    Ok(())
}
