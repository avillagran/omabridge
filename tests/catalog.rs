use omabridge::{Client, NetOptions, Node, Store};
use serde_json::{Value, json};
use std::{collections::BTreeMap, time::Duration};
use tokio::net::TcpListener;
fn source(peer: &str, revision: u64, ids: &[&str]) -> Value {
    json!({"version":1,"revision":revision,"environments":[
        {"id":"gateway","name":"GATEWAY","enabled":true},
        {"id":"host","name":"HOST","enabled":true}
    ],"endpoints":[
        {"environmentId":"gateway","descriptorEnvironmentId":"gateway","id":"public","url":"https://gateway.example.com/","priority":1},
        {"environmentId":"host","descriptorEnvironmentId":"host","id":"public","url":"https://host.example.com/","priority":1}
    ],"clients":{peer:ids}})
}
#[tokio::test]
async fn authenticated_catalog_tracks_gateway_host_and_revocation_over_real_quic()
-> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir = tempfile::tempdir()?;
        let owner = Store::open(&dir.path().join("owner"), "desktop")?;
        let phone = Store::open(&dir.path().join("phone"), "android")?;
        let stranger = Store::open(&dir.path().join("other"), "other")?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let node = Node::start(
            owner.clone(),
            BTreeMap::from([("t3".into(), listener.local_addr()?)]),
            NetOptions::loopback(),
        )
        .await?;
        let client = Client::new(phone.clone(), NetOptions::loopback()).await?;
        let other = Client::new(stranger.clone(), NetOptions::loopback()).await?;
        assert!(client.catalog(&node.addr()).await.is_err());
        let now = omabridge::unix_time()?;
        let invite = owner.create_invite(&["t3".into()], Duration::from_secs(60), now)?;
        owner.claim(&invite, &phone.id()?, "android", now)?;
        owner.approve(&phone.id()?, now)?;
        assert!(
            client.catalog(&node.addr()).await.is_err(),
            "pairing alone must not disclose desktop catalog"
        );
        let mut publication = source(&phone.id()?, 1, &["gateway", "host"]);
        omabridge::catalog::publish_source(&owner, &publication)?;
        let first = client.catalog(&node.addr()).await?;
        assert_eq!(first["clientId"], phone.id()?);
        assert_eq!(first["bridgeId"], owner.id()?);
        assert_eq!(first["environments"].as_array().unwrap().len(), 2);
        assert!(other.catalog(&node.addr()).await.is_err());
        let context = json!({"bridgeId":owner.id()?,"clientId":phone.id()?,"now":omabridge::unix_time()?*1000});
        let cache = t3_protocol::bridge_catalog::reconcile(&first, &Value::Null, &context)
            .map_err(anyhow::Error::msg)?;
        publication["revision"] = json!(2);
        publication["clients"][phone.id()?] = json!(["gateway"]);
        omabridge::catalog::publish_source(&owner, &publication)?;
        let second = client.catalog(&node.addr()).await?;
        assert_eq!(second["environments"].as_array().unwrap().len(), 1);
        let removed = t3_protocol::bridge_catalog::reconcile(&second, &cache, &context)
            .map_err(anyhow::Error::msg)?;
        let withdrawn = removed["environments"].as_array().unwrap().iter()
            .find(|row| row["environmentId"] == "host").unwrap();
        assert_eq!(withdrawn["removed"], true);
        publication["revision"] = json!(3);
        publication["clients"][phone.id()?] = json!(["gateway", "host"]);
        publication["endpoints"][1]["url"] = json!("https://new-host.example.com/");
        omabridge::catalog::publish_source(&owner, &publication)?;
        let third = client.catalog(&node.addr()).await?;
        let restored = t3_protocol::bridge_catalog::reconcile(&third, &removed, &context)
            .map_err(anyhow::Error::msg)?;
        assert_eq!(
            restored["environments"].as_array().unwrap().iter()
                .find(|row| row["environmentId"] == "host").unwrap()["routes"][0]["url"],
            "https://new-host.example.com/"
        );
        assert!(
            omabridge::catalog::publish_source(&owner, &publication).is_err(),
            "revision reuse refused"
        );
        let old_address=node.addr();
        node.shutdown().await;
        let offline=tokio::time::timeout(Duration::from_millis(200),client.catalog(&old_address)).await;
        assert!(!matches!(offline,Ok(Ok(_))),"offline cannot fabricate an empty catalog");
        let node=Node::start(owner.clone(),BTreeMap::from([("t3".into(),listener.local_addr()?)]),NetOptions::loopback()).await?;
        let reconnected=client.catalog(&node.addr()).await?;
        assert_eq!(reconnected["revision"],3,"catalog survives server restart with the same bridge identity");
        owner.revoke(&phone.id()?)?;
        assert!(
            client.catalog(&node.addr()).await.is_err(),
            "revocation applies to next authenticated read"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "catalog never opens a T3 service or copies session credentials"
        );
        client.close().await;
        other.close().await;
        node.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}
#[test]
fn publication_cannot_include_private_desktop_fields_or_wrong_descriptor() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let owner = Store::open(&dir.path().join("owner"), "desktop")?;
    let phone = Store::open(&dir.path().join("phone"), "android")?;
    let now = omabridge::unix_time()?;
    let invite = owner.create_invite(&["t3".into()], Duration::from_secs(60), now)?;
    owner.claim(&invite, &phone.id()?, "android", now)?;
    owner.approve(&phone.id()?, now)?;
    let mut publication = source(&phone.id()?, 1, &["host"]);
    publication["environments"][0]["credentials"] = json!("forbidden");
    assert!(omabridge::catalog::publish_source(&owner, &publication).is_err());
    publication = source(&phone.id()?, 1, &["host"]);
    publication["endpoints"][1]["descriptorEnvironmentId"] = json!("gateway");
    assert!(omabridge::catalog::publish_source(&owner, &publication).is_err());
    publication = source(&phone.id()?, 1, &["host"]);
    publication["endpoints"][1]["url"] = json!("https://127.0.0.1/");
    assert!(omabridge::catalog::publish_source(&owner, &publication).is_err());
    Ok(())
}
