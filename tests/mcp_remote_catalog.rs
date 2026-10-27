use anyhow::Result;
use omabridge::{
    Client, Invitation, NetOptions, Node, Store, catalog,
    mcp::{
        federation::Router,
        store::{GatewayStore, RemoteCatalogBinding, UpstreamCredential},
    },
    unix_time,
};
use serde_json::json;
use std::{collections::BTreeMap, time::Duration};

#[tokio::test]
async fn remote_catalog_uses_running_identity_and_reconciles_routes_and_revocation() -> Result<()> {
    const A: &str = "11111111-1111-4111-8111-111111111111";
    let dir = tempfile::tempdir()?;
    let owner = Store::open(&dir.path().join("owner"), "publisher")?;
    let guest = Store::open(&dir.path().join("guest"), "gateway")?;
    let node = Node::start(
        owner.clone(),
        BTreeMap::from([("t3".into(), "127.0.0.1:9".parse()?)]),
        NetOptions::loopback(),
    )
    .await?;
    let now = unix_time()?;
    let token = owner.create_invite(&["t3".into()], Duration::from_secs(60), now)?;
    let invitation = Invitation {
        version: 1,
        address: node.addr(),
        token,
        name: "publisher".into(),
        expires: now + 60,
        manage: false,
    };
    let client = Client::new(guest.clone(), NetOptions::loopback()).await?;
    client.pair(&invitation, "gateway", now).await?;
    owner.approve(&guest.id()?, now)?;
    client.pair(&invitation, "gateway", now).await?;
    client.close().await;
    let serving = Node::start(
        guest.clone(),
        BTreeMap::from([("t3".into(), "127.0.0.1:9".parse()?)]),
        NetOptions::loopback(),
    )
    .await?;
    guest.publish_endpoint(&serving.addr(), &["t3".into()])?;
    let gateway = GatewayStore::open(&dir.path().join("mcp"))?;
    gateway.set_remote_catalog_binding(&RemoteCatalogBinding {
        device_state: guest.root().into(),
        bridge_id: owner.id()?,
    })?;
    gateway
        .environment_store(A)?
        .set_upstream(&UpstreamCredential {
            url: "http://127.0.0.1:1".into(),
            token: "fixture-not-a-credential".into(),
            access: "read-only".into(),
            expires: u64::MAX,
        })?;
    let mut source = json!({"version":1,"revision":1,"clients":{guest.id()?:[A]},"environments":[{"id":A,"name":"one","enabled":true}],"endpoints":[{"environmentId":A,"descriptorEnvironmentId":A,"id":"gateway","url":"https://one.example.com/","priority":0}]});
    catalog::publish_source(&owner, &source)?;
    let router = Router::default();
    assert_eq!(
        router.credential(&gateway, A).await?.url,
        "https://one.example.com/"
    );
    source["revision"] = json!(2);
    source["environments"][0]["name"] = json!("renamed");
    source["endpoints"][0]["url"] = json!("https://two.example.com/");
    catalog::publish_source(&owner, &source)?;
    assert_eq!(
        router.credential(&gateway, A).await?.url,
        "https://two.example.com/"
    );
    // The permanent credential slot is never rewritten by discovery.
    assert_eq!(
        gateway.environment_store(A)?.upstream()?.unwrap().url,
        "http://127.0.0.1:1"
    );
    source["revision"] = json!(3);
    source["clients"][guest.id()?] = json!([]);
    catalog::publish_source(&owner, &source)?;
    assert!(router.credential(&gateway, A).await.is_err());
    assert!(!gateway.catalog_allows(A)?);
    source["revision"] = json!(4);
    source["clients"][guest.id()?] = json!([A]);
    catalog::publish_source(&owner, &source)?;
    assert!(router.credential(&gateway, A).await.is_ok());
    owner.revoke(&guest.id()?)?;
    assert!(router.credential(&gateway, A).await.is_err());
    assert!(!gateway.catalog_allows(A)?);
    serving.shutdown().await;
    node.shutdown().await;
    Ok(())
}
