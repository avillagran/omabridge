//! Local desktop adapter. Only a fixed, locally selected executable is invoked;
//! no command, argument or credential comes from a remote client.
use crate::{Store, catalog};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path, time::Duration};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Route {
    pub environment_id: String,
    pub id: String,
    pub url: String,
    pub priority: u64,
}
/// Local policy, never a catalog request body. Aliases bind local-primary names
/// to UUIDs; both sides are checked against descriptors before publication.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub aliases: BTreeMap<String, String>,
    pub routes: Vec<Route>,
    pub clients: BTreeMap<String, Vec<String>>,
}

pub struct Publisher {
    http: reqwest::Client,
}
impl Publisher {
    pub fn new() -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(8))
                .build()?,
        })
    }
    /// Input must be the credential-free `connections-view` response. Unknown
    /// desktop fields are discarded rather than serialized into the publication.
    pub async fn publish(&self, store: &Store, desktop: &Value, policy: &Policy) -> Result<bool> {
        let rows = desktop["environments"]
            .as_array()
            .context("invalid desktop view")?;
        ensure!(
            rows.len() <= 128 && policy.routes.len() <= 2048,
            "desktop view too large"
        );
        let mut environments = BTreeMap::<String, Value>::new();
        for row in rows {
            let alias = row["id"].as_str().context("invalid desktop identity")?;
            let id = policy
                .aliases
                .get(alias)
                .map(String::as_str)
                .unwrap_or(alias);
            // Stable identities must be canonical UUIDs, never labels or SSH aliases.
            ensure!(
                canonical_uuid(id),
                "desktop identity requires explicit UUID alias"
            );
            let name = row["name"].as_str().context("invalid desktop label")?;
            ensure!(row["enabled"].is_boolean(), "invalid desktop enabled state");
            ensure!(
                environments
                    .insert(
                        id.into(),
                        json!({"id":id,"name":name,"enabled":row["enabled"]})
                    )
                    .is_none(),
                "duplicate desktop identity"
            );
        }
        // Explicitly configured local-primary alias: connections-view keeps the
        // primary separate via localEnabled. Do not infer its UUID from its name.
        if let Some(id) = policy.aliases.get("local-primary") {
            ensure!(canonical_uuid(id), "invalid primary UUID");
            if desktop["localEnabled"] == true {
                environments
                    .entry(id.clone())
                    .or_insert_with(|| json!({"id":id,"name":"Local","enabled":true}));
            }
        }
        let previous = catalog::read_source(store).ok();
        let mut endpoints = Vec::new();
        for route in &policy.routes {
            if !environments
                .get(&route.environment_id)
                .is_some_and(|e| e["enabled"] == true)
            {
                continue;
            }
            let ep = json!({"environmentId":route.environment_id,"descriptorEnvironmentId":route.environment_id,"id":route.id,"url":route.url,"priority":route.priority});
            // Apply the common portable-route policy BEFORE making any request.
            t3_protocol::bridge_catalog::publish(&json!(environments.values().collect::<Vec<_>>()), &json!([route.environment_id]), &json!([ep]),
                &json!({"bridgeId":store.id()?,"clientId":"publisher-validation","revision":1,"now":0})).map_err(anyhow::Error::msg)?;
            let response = self
                .http
                .get(format!(
                    "{}{}",
                    route.url.trim_end_matches('/'),
                    "/.well-known/t3/environment"
                ))
                .header("Accept", "application/json")
                .send()
                .await;
            // A failed descriptor probe is an outage, NOT a catalog withdrawal.
            // Abort the complete update: the last verified publication survives.
            let mut response = match response {
                Ok(response) if response.status().is_success() => response,
                _ => {
                    // Retain only a previously descriptor-verified route for this
                    // same identity/id. Explicit policy withdrawals still apply.
                    if let Some(old) = previous
                        .as_ref()
                        .and_then(|p| p["endpoints"].as_array())
                        .into_iter()
                        .flatten()
                        .find(|e| e["environmentId"] == route.environment_id && e["id"] == route.id)
                    {
                        endpoints.push(old.clone());
                    }
                    continue;
                }
            };
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|_| anyhow::anyhow!("descriptor unavailable"))?
            {
                ensure!(
                    bytes.len() + chunk.len() <= 64 * 1024,
                    "descriptor too large"
                );
                bytes.extend_from_slice(&chunk);
            }
            let descriptor: Value = serde_json::from_slice(&bytes)
                .map_err(|_| anyhow::anyhow!("invalid descriptor"))?;
            ensure!(
                descriptor["environmentId"] == route.environment_id,
                "descriptor identity mismatch"
            );
            endpoints.push(ep);
        }
        let clients: BTreeMap<_, _> = policy
            .clients
            .iter()
            .filter_map(|(id, grants)| match store.authorized(id, "t3") {
                Ok(true) => Some(Ok((id.clone(), grants.clone()))),
                Ok(false) => None,
                Err(e) => Some(Err(e)),
            })
            .collect::<Result<_>>()?;
        catalog::publish_changed(
            store,
            json!({"version":1,"revision":0,"environments":environments.into_values().collect::<Vec<_>>(),"endpoints":endpoints,"clients":clients}),
        )
    }
    pub async fn poll_once(
        &self,
        store: &Store,
        executable: &Path,
        policy_path: &Path,
    ) -> Result<bool> {
        let policy: Policy = crate::read_document(policy_path)?;
        let mut child = tokio::process::Command::new(executable)
            .arg("connections-view")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("desktop view unavailable")?;
        use tokio::io::AsyncReadExt;
        let mut output = Vec::new();
        let mut stdout = child
            .stdout
            .take()
            .context("desktop view unavailable")?
            .take(1024 * 1024 + 1);
        tokio::time::timeout(Duration::from_secs(15), async {
            stdout.read_to_end(&mut output).await?;
            ensure!(output.len() <= 1024 * 1024, "desktop view too large");
            ensure!(child.wait().await?.success(), "desktop view unavailable");
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("desktop view timeout")??;
        let desktop: Value =
            serde_json::from_slice(&output).map_err(|_| anyhow::anyhow!("invalid desktop view"))?;
        self.publish(store, &desktop, &policy).await
    }
}
fn canonical_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Client, NetOptions, Node, catalog_client::CatalogManager};
    use std::{net::SocketAddr, sync::Arc};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    const GATEWAY: &str = "00000000-0000-4000-8000-000000000001";
    const HOST: &str = "00000000-0000-4000-8000-000000000002";
    #[tokio::test]
    async fn publisher_tls_to_authenticated_catalog_manager_and_projection() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let owner = Store::open(&dir.path().join("owner"), "desktop")?;
        let phone = Store::open(&dir.path().join("phone"), "android")?;
        let now = crate::unix_time()?;
        let invite = owner.create_invite(&["t3".into()], Duration::from_secs(60), now)?;
        owner.claim(&invite, &phone.id()?, "android", now)?;
        owner.approve(&phone.id()?, now)?;
        let cert =
            rcgen::generate_simple_self_signed(vec!["gateway.test".into(), "host.test".into()])?;
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let web = TcpListener::bind("127.0.0.1:0").await?;
        let addr = web.local_addr()?;
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = web.accept().await {
                let a = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut stream) = a.accept(socket).await else {
                        return;
                    };
                    let mut request = vec![0; 8192];
                    let n = stream.read(&mut request).await.unwrap();
                    let request = String::from_utf8_lossy(&request[..n]);
                    assert!(!request.to_lowercase().contains("authorization:"));
                    let id = if request.contains("host.test") {
                        HOST
                    } else {
                        GATEWAY
                    };
                    let body = json!({"environmentId":id}).to_string();
                    stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n{}",body.len(),body).as_bytes()).await.unwrap();
                    let _ = stream.shutdown().await;
                });
            }
        });
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(reqwest::Certificate::from_pem(cert.cert.pem().as_bytes())?)
            .resolve("gateway.test", addr)
            .resolve("host.test", addr)
            .timeout(Duration::from_secs(2))
            .build()?;
        let publisher = Publisher { http };
        let mut policy = Policy {
            aliases: BTreeMap::from([("local".into(), GATEWAY.into())]),
            routes: vec![
                Route {
                    environment_id: GATEWAY.into(),
                    id: "gateway".into(),
                    url: format!("https://gateway.test:{}/", addr.port()),
                    priority: 0,
                },
                Route {
                    environment_id: HOST.into(),
                    id: "gateway".into(),
                    url: format!("https://host.test:{}/", addr.port()),
                    priority: 0,
                },
            ],
            clients: BTreeMap::from([(phone.id()?, vec![GATEWAY.into(), HOST.into()])]),
        };
        let mut desktop = json!({"localEnabled":true,"environments":[{"id":"local","name":"GATEWAY","enabled":true},{"id":HOST,"name":"HOST","enabled":true}]});
        assert!(publisher.publish(&owner, &desktop, &policy).await?);
        assert!(
            !publisher.publish(&owner, &desktop, &policy).await?,
            "unchanged poll keeps revision"
        );
        let node = Node::start(
            owner.clone(),
            BTreeMap::from([("t3".into(), SocketAddr::from(([127, 0, 0, 1], 9)))]),
            NetOptions::loopback(),
        )
        .await?;
        let client = Client::new(phone.clone(), NetOptions::loopback()).await?;
        let mut manager = CatalogManager::open(phone.clone(), node.addr())?;
        let first = manager.refresh(&client).await?;
        assert_eq!(
            first["catalog"]["environments"].as_array().unwrap().len(),
            2
        );
        std::fs::rename(
            owner.root().join("client-catalog.json"),
            owner.root().join("catalog-test-unavailable"),
        )?;
        assert_eq!(
            manager.refresh(&client).await?["status"],
            "offline",
            "source I/O is not a grant withdrawal"
        );
        assert_eq!(
            manager.projection(&json!([]), now * 1000)?["upserts"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        std::fs::rename(
            owner.root().join("catalog-test-unavailable"),
            owner.root().join("client-catalog.json"),
        )?;
        let plan = manager.projection(&json!([]), now * 1000)?;
        let rows = plan["upserts"].clone();
        let node_id = rows[1]["id"].clone();
        assert_eq!(
            manager.projection(
                &json!([{"id":"independent","environmentId":HOST}]),
                now * 1000
            )?["upserts"]
                .as_array()
                .unwrap()
                .len(),
            1,
            "independent row not overwritten or duplicated"
        );
        desktop["environments"][1]["name"] = json!("HOST renamed");
        assert!(publisher.publish(&owner, &desktop, &policy).await?);
        manager.refresh(&client).await?;
        assert_eq!(
            manager.projection(&rows, now * 1000)?["upserts"][1]["id"],
            node_id
        );
        policy
            .clients
            .get_mut(&phone.id()?)
            .unwrap()
            .retain(|id| id != HOST);
        assert!(publisher.publish(&owner, &desktop, &policy).await?);
        manager.refresh(&client).await?;
        let plan = manager.projection(&rows, now * 1000)?;
        assert_eq!(plan["upserts"][1]["status"], "revoked");
        assert!(plan["stop"].as_array().unwrap().contains(&node_id));
        policy
            .clients
            .get_mut(&phone.id()?)
            .unwrap()
            .push(HOST.into());
        assert!(publisher.publish(&owner, &desktop, &policy).await?);
        manager.refresh(&client).await?;
        assert_eq!(
            manager.projection(&rows, now * 1000)?["upserts"][1]["status"],
            "discovered"
        );
        task.abort();
        tokio::task::yield_now().await;
        desktop["environments"][1]["name"] = json!("should not publish on outage");
        assert!(publisher.publish(&owner, &desktop, &policy).await?);
        assert_eq!(client.catalog(&node.addr()).await?["revision"], 5);
        owner.revoke(&phone.id()?)?;
        assert_eq!(manager.refresh(&client).await?["status"], "revoked");
        let reopened = CatalogManager::open(phone, node.addr())?;
        assert_eq!(reopened.cached(now * 1000)["status"], "revoked");
        assert!(
            reopened.projection(&rows, now * 1000)?["upserts"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["baseUrl"].is_null())
        );
        client.close().await;
        node.shutdown().await;
        Ok(())
    }
}
