use anyhow::Result;
use omabridge::{Client, Invitation, NetOptions, Node, PairDecision, Store};
use serde_json::{Value, json};
use std::{collections::BTreeMap, os::unix::fs::PermissionsExt, time::Duration};

struct Lab {
    _dir: tempfile::TempDir,
    owner: Store,
    a_store: Store,
    b_store: Store,
    node: Node,
    a: Client,
    b: Client,
}
impl Lab {
    async fn new() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let owner = Store::open(&dir.path().join("bridge"), "bridge")?;
        let a_store = Store::open(&dir.path().join("phone"), "phone")?;
        let b_store = Store::open(&dir.path().join("desktop"), "desktop")?;
        let node = Node::start(
            owner.clone(),
            BTreeMap::from([("t3".into(), "127.0.0.1:9".parse()?)]),
            NetOptions::loopback(),
        )
        .await?;
        owner.publish_endpoint(&node.addr(), &["t3".into()])?;
        let a = Client::new(a_store.clone(), NetOptions::loopback()).await?;
        let b = Client::new(b_store.clone(), NetOptions::loopback()).await?;
        for (client, store) in [(&a, &a_store), (&b, &b_store)] {
            let now = omabridge::unix_time()?;
            let invitation = Invitation {
                version: 1,
                address: node.addr(),
                token: owner.create_invite(
                    &["drafts".into(), "t3".into()],
                    Duration::from_secs(300),
                    now,
                )?,
                name: "bridge".into(),
                expires: now + 300,
                manage: false,
            };
            assert!(matches!(
                client.pair(&invitation, "client", now).await?,
                PairDecision::Pending
            ));
            owner.approve(&store.id()?, now)?;
            assert!(matches!(
                client.pair(&invitation, "client", now).await?,
                PairDecision::Approved { .. }
            ));
        }
        Ok(Self {
            _dir: dir,
            owner,
            a_store,
            b_store,
            node,
            a,
            b,
        })
    }
    async fn call(&self, b: bool, request: Value) -> Result<Value> {
        let answer = if b { &self.b } else { &self.a }
            .drafts(&self.node.addr(), &request)
            .await?;
        Ok(answer)
    }
    async fn stop(self) {
        self.a.close().await;
        self.b.close().await;
        self.node.shutdown().await;
    }
}
fn scope(id: &str) -> Value {
    json!({"environment":"source-host-uuid","project":"project-uuid","kind":"thread","id":id})
}
fn content(text: &str) -> Value {
    json!({"schema":1,"text":text,"attachments":[]})
}
fn put(id: &str, mutation: &str, expected: Value, text: &str) -> Value {
    json!({"op":"put","scope":scope(id),"mutationId":mutation,"expected":expected,"payload":content(text)})
}
fn rev(v: &Value) -> Value {
    v["event"]["revision"].clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_devices_preserve_both_branches_and_deduplicate_lost_receipts() -> Result<()> {
    let lab = Lab::new().await?;
    let first = lab
        .call(false, put("t", "first", Value::Null, "base"))
        .await?;
    let a = put("t", "a", rev(&first), "phone edit");
    let b = put("t", "b", rev(&first), "desktop offline edit");
    let (ar, br) = tokio::try_join!(lab.call(false, a.clone()), lab.call(true, b.clone()))?;
    assert_eq!(
        [&ar, &br]
            .iter()
            .filter(|r| r["status"] == "applied")
            .count(),
        1
    );
    let conflict = if ar["status"] == "conflict" { &ar } else { &br };
    assert!(conflict["local"]["payload"]["text"].is_string());
    assert!(conflict["conflicts"][0]["latest"]["payload"]["text"].is_string());
    assert_eq!(lab.call(false, a.clone()).await?, ar);
    assert_eq!(lab.call(true, b).await?, br);
    assert_eq!(
        lab.call(false, json!({"op":"receipt","mutationId":"a"}))
            .await?,
        ar
    );
    let mut reused = a;
    reused["payload"]["text"] = json!("changed retry");
    assert_eq!(
        lab.call(false, reused).await?["error"],
        "draft_mutation_reused"
    );
    // Same durable receipts survive reopening the authority's store.
    let reopened = Store::open(lab.owner.root(), "bridge")?;
    assert_eq!(
        omabridge::drafts::execute(
            &reopened,
            Some(&lab.a_store.id()?),
            &json!({"op":"receipt","mutationId":"a"})
        ),
        ar
    );
    lab.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_delete_edit_and_clear_after_send_never_overwrite_later_edits() -> Result<()> {
    let lab = Lab::new().await?;
    let base = lab
        .call(false, put("t", "base", Value::Null, "submitted"))
        .await?;
    let newer = lab
        .call(true, put("t", "newer", rev(&base), "typed after send"))
        .await?;
    let clear =
        json!({"op":"delete","scope":scope("t"),"expected":rev(&base),"mutationId":"clear"});
    assert_eq!(lab.call(false, clear).await?["status"], "conflict");
    let deleted = lab
        .call(
            false,
            json!({"op":"delete","scope":scope("t"),"expected":rev(&newer),"mutationId":"delete"}),
        )
        .await?;
    assert_eq!(deleted["event"]["changes"][0]["deleted"], true);
    for (mutation, expected) in [("stale", rev(&newer)), ("recreate", Value::Null)] {
        let r = lab
            .call(true, put("t", mutation, expected, "offline edit"))
            .await?;
        assert_eq!(r["status"], "conflict");
        assert_eq!(r["conflicts"][0]["latest"]["deleted"], true);
        assert_eq!(r["local"]["payload"]["text"], "offline edit");
    }
    lab.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn atomic_stash_restore_preserves_occupied_target_and_retries_exactly() -> Result<()> {
    let lab = Lab::new().await?;
    let initial = lab
        .call(false, put("source", "initial", Value::Null, "restore me"))
        .await?;
    let occupied = lab
        .call(true, put("target", "occupied", Value::Null, "preserve me"))
        .await?;
    let backup = json!({"kind":"stash","id":"backup", "environment":"source-host-uuid","project":"project-uuid"});
    let mut transfer = json!({"op":"transfer","scope":scope("source"),"expected":rev(&initial),"target":scope("target"),"targetExpected":rev(&occupied),"backup":backup,"mutationId":"transfer"});
    // A stale target fails before any source clear or backup write.
    transfer["targetExpected"] = Value::Null;
    assert_eq!(
        lab.call(false, transfer.clone()).await?["status"],
        "conflict"
    );
    assert_eq!(
        lab.call(false, json!({"op":"get","scope":scope("source")}))
            .await?["document"]["deleted"],
        false
    );
    transfer["targetExpected"] = rev(&occupied);
    transfer["mutationId"] = json!("restore");
    let result = lab.call(false, transfer.clone()).await?;
    assert_eq!(result["status"], "applied");
    assert_eq!(result["event"]["changes"].as_array().unwrap().len(), 3);
    assert_eq!(lab.call(false, transfer).await?, result);
    let get = |scope| json!({"op":"get","scope":scope});
    assert_eq!(
        lab.call(true, get(scope("source"))).await?["document"]["deleted"],
        true
    );
    assert_eq!(
        lab.call(true, get(scope("target"))).await?["document"]["payload"]["text"],
        "restore me"
    );
    assert_eq!(
        lab.call(true, get(backup)).await?["document"]["payload"]["text"],
        "preserve me"
    );
    lab.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn attachments_cannot_be_reinterpreted_on_a_different_host() -> Result<()> {
    let lab = Lab::new().await?;
    let mut request = put("source", "attachment", Value::Null, "file");
    request["payload"]["attachments"] =
        json!([{"id":"file1","name":"file.txt","sourceEnvironment":"source-host-uuid"}]);
    let base = lab.call(false, request).await?;
    let mut target = scope("target");
    target["environment"] = json!("another-host-uuid");
    let mut transfer = json!({"op":"transfer","scope":scope("source"),"expected":rev(&base),"target":target,"targetExpected":null,"mutationId":"move"});
    assert_eq!(
        lab.call(false, transfer.clone()).await?["error"],
        "draft_attachment_host"
    );
    assert_eq!(
        lab.call(true, json!({"op":"get","scope":scope("source")}))
            .await?["document"]["deleted"],
        false
    );
    transfer["payload"] = content("explicitly cloned text without files");
    assert_eq!(lab.call(false, transfer).await?["status"], "applied");
    lab.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn independent_grants_revocation_privacy_and_bounded_payloads() -> Result<()> {
    let lab = Lab::new().await?;
    lab.owner
        .set_services(&lab.a_store.id()?, &["t3".into()], &[])?;
    lab.owner.set_admin(&lab.a_store.id()?, true)?;
    assert_eq!(
        lab.call(false, json!({"op":"list"})).await?["error"],
        "draft_forbidden"
    );
    let outsider = Store::open(&lab._dir.path().join("outsider"), "outsider")?;
    let client = Client::new(outsider, NetOptions::loopback()).await?;
    assert_eq!(
        client
            .drafts(&lab.node.addr(), &json!({"op":"list"}))
            .await?["error"],
        "draft_forbidden"
    );
    client.close().await;
    let saved = lab
        .call(
            true,
            put("t", "private", Value::Null, "unique private draft marker"),
        )
        .await?;
    assert_eq!(saved["status"], "applied");
    let meta = std::fs::metadata(lab.owner.root().join("shared-drafts.json"))?;
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert!(!lab.owner.root().join("manage-audit.jsonl").exists());
    let huge = put("huge", "huge", Value::Null, &"x".repeat(9000));
    assert_eq!(lab.call(true, huge).await?["error"], "draft_invalid");
    let mut uri = put("uri", "uri", Value::Null, "unsafe");
    uri["payload"]["contentUri"] = json!("content://private");
    assert_eq!(lab.call(true, uri).await?["error"], "draft_invalid");
    lab.owner.revoke(&lab.b_store.id()?)?;
    // A revoked paired endpoint is refused at the connection or store boundary.
    let revoked = lab.call(true, json!({"op":"list"})).await;
    assert!(revoked.is_err() || revoked?["error"] == "draft_forbidden");
    lab.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn snapshot_and_watch_pages_have_explicit_cursor_recovery() -> Result<()> {
    let lab = Lab::new().await?;
    let empty = lab.call(false, json!({"op":"list"})).await?;
    for i in 0..3 {
        assert_eq!(
            lab.call(
                false,
                put(&format!("t{i}"), &format!("m{i}"), Value::Null, "draft")
            )
            .await?["status"],
            "applied"
        );
    }
    let page = lab.call(false, json!({"op":"list"})).await?;
    assert_eq!(page["items"].as_array().unwrap().len(), 2);
    let next = lab
        .call(
            false,
            json!({"op":"list","offset":page["nextOffset"],"snapshot":page["cursor"]}),
        )
        .await?;
    assert_eq!(next["items"].as_array().unwrap().len(), 1);
    let events = lab
        .call(true, json!({"op":"watch","cursor":empty["cursor"]}))
        .await?;
    assert_eq!(events["items"].as_array().unwrap().len(), 2);
    lab.call(false, put("four", "four", Value::Null, "new"))
        .await?;
    let rest = lab.call(true,json!({"op":"watch","cursor":empty["cursor"],"snapshot":events["cursor"],"offset":events["nextOffset"]})).await?;
    assert_eq!(rest["items"].as_array().unwrap().len(), 1);
    assert_eq!(rest["cursor"], events["cursor"]);
    assert_eq!(
        lab.call(true, json!({"op":"watch","cursor":rest["cursor"]}))
            .await?["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        lab.call(
            false,
            json!({"op":"list","offset":page["nextOffset"],"snapshot":page["cursor"]})
        )
        .await?["error"],
        "draft_snapshot_required"
    );
    assert_eq!(
        lab.call(false, json!({"op":"watch","cursor":"expired-owner:9999"}))
            .await?["error"],
        "draft_snapshot_required"
    );
    lab.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn desktop_manage_uses_serving_identity_control_socket_for_remote_drafts() -> Result<()> {
    let lab = Lab::new().await?;
    lab.a.close().await;
    let desktop_node = Node::start(
        lab.a_store.clone(),
        BTreeMap::from([("t3".into(), "127.0.0.1:9".parse()?)]),
        NetOptions::loopback(),
    )
    .await?;
    lab.a_store
        .publish_endpoint(&desktop_node.addr(), &["t3".into()])?;
    let manager = omabridge::manage::Manager::from_env(
        lab.a_store.root().to_path_buf(),
        "127.0.0.1:0".parse()?,
        Some(omabridge::Relay::Disabled),
    )
    .map_err(anyhow::Error::msg)?;
    let request = json!({"action":"drafts","peer":lab.owner.id()?,"command":put("desktop","desktop",Value::Null,"control socket edit")});
    assert_eq!(
        manager.execute(&request).await,
        Err("confirmation_required")
    );
    let mut request = request;
    request["confirmed"] = json!(true);
    let result = manager
        .execute(&request)
        .await
        .map_err(anyhow::Error::msg)?;
    assert_eq!(result["status"], "applied");
    assert_eq!(
        lab.call(true, json!({"op":"get","scope":scope("desktop")}))
            .await?["document"]["payload"]["text"],
        "control socket edit"
    );
    // No competing client endpoint was created; the same private socket serves a second request.
    assert_eq!(
        manager
            .execute(&json!({"action":"drafts","peer":lab.owner.id()?,"command":{"op":"list"}}))
            .await
            .map_err(anyhow::Error::msg)?["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    desktop_node.shutdown().await;
    lab.stop().await;
    Ok(())
}
