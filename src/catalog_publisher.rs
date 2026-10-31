//! Local desktop adapter. Only a fixed, locally selected executable is invoked;
//! no command, argument or credential comes from a remote client.
use crate::{Store, catalog};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Duration,
};

/// Which device issues each auto-published environment. Written only by the
/// local publisher; a bridge reads it to route `T3HostPair`.
const ISSUERS: &str = "all-hosts-issuers.json";
/// Routes kept per host: 128 hosts must still fit the 64 KiB control channel.
const MAX_ROUTES_PER_HOST: usize = 2;
const MAX_ENVIRONMENTS: usize = 128;
const MAX_CLIENTS: usize = 128;

pub fn write_issuers(store: &Store, issuers: &BTreeMap<String, String>) -> Result<()> {
    crate::write_document(&store.root().join(ISSUERS), issuers, true)
}
fn read_issuers(store: &Store) -> Result<BTreeMap<String, String>> {
    crate::read_document(&store.root().join(ISSUERS))
}
pub(crate) fn issuer_of(store: &Store, environment: &str) -> Result<String> {
    read_issuers(store)?
        .remove(environment)
        .context("no issuer for environment")
}

/// A host that took part in an auto-publish pass, and how it went.
#[derive(Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AutoHost {
    pub host: String,
    pub environment_id: String,
}
#[derive(Debug, Serialize, PartialEq)]
pub struct AutoSkip {
    pub host: String,
    pub reason: &'static str,
}
/// What `Publisher::publish_auto` did. Never holds a credential.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutoReport {
    pub catalog_changed: bool,
    pub published: Vec<AutoHost>,
    /// Probes failed, so the last verified publication of this host stands.
    pub retained: Vec<AutoHost>,
    pub skipped: Vec<AutoSkip>,
    /// All-hosts devices left out by the catalog's client limit.
    pub clients_left_out: Vec<String>,
}

enum Probe {
    Verified(String, Vec<String>),
    Outage,
    Mismatch,
}

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
            // A failed descriptor probe is an outage, NOT a catalog withdrawal.
            // Abort the complete update: the last verified publication survives.
            let descriptor = match self.descriptor(&route.url).await? {
                Some(descriptor) => descriptor,
                None => {
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
    /// The public descriptor behind `url`. `None` is an outage; malformed
    /// answers are errors. Sends no credential and follows no redirect.
    async fn descriptor(&self, url: &str) -> Result<Option<Value>> {
        let response = self
            .http
            .get(format!(
                "{}{}",
                url.trim_end_matches('/'),
                "/.well-known/t3/environment"
            ))
            .header("Accept", "application/json")
            .send()
            .await;
        let mut response = match response {
            Ok(response) if response.status().is_success() => response,
            _ => return Ok(None),
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
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| anyhow::anyhow!("invalid descriptor"))
    }

    /// Verifies a host's announced routes: all answering must name one UUID.
    async fn probe(&self, routes: &[String]) -> Probe {
        let mut environment: Option<String> = None;
        let mut verified = Vec::new();
        for url in routes {
            let descriptor = match self.descriptor(url).await {
                Ok(Some(descriptor)) => descriptor,
                Ok(None) => continue,
                Err(_) => return Probe::Mismatch,
            };
            let Some(id) = descriptor["environmentId"]
                .as_str()
                .filter(|id| canonical_uuid(id))
            else {
                return Probe::Mismatch;
            };
            if environment.as_deref().is_some_and(|known| known != id) {
                return Probe::Mismatch;
            }
            environment = Some(id.to_owned());
            if verified.len() < MAX_ROUTES_PER_HOST {
                verified.push(url.clone());
            }
        }
        match environment {
            Some(environment) => Probe::Verified(environment, verified),
            None => Probe::Outage,
        }
    }

    /// Publishes every host that consented to this bridge, and this device, to
    /// every device approved for all hosts. Nothing here is hand-edited: routes
    /// come from `Hello`, identities from HTTPS descriptors. A host that cannot be
    /// verified is reported and left out; it never stops the others.
    pub async fn publish_auto(&self, store: &Store) -> Result<AutoReport> {
        let now = crate::unix_time()?;
        let own = store.id()?;
        let peers = store.peers()?;
        let t3_urls = |routes: Vec<crate::routes::ServiceRoute>| -> Vec<String> {
            let mut urls: Vec<String> = routes
                .into_iter()
                .filter(|route| route.service == "t3")
                .map(|route| route.url)
                .collect();
            urls.sort();
            urls.dedup();
            urls
        };
        let mut hosts = vec![(
            own.clone(),
            store.name()?,
            t3_urls(store.service_routes(now)?),
        )];
        hosts.extend(
            peers
                .iter()
                .filter(|peer| peer.remote_bridge_consent && peer.remote_services.contains("t3"))
                .map(|peer| {
                    (
                        peer.id.clone(),
                        peer.name.clone(),
                        t3_urls(peer.remote_routes.clone()),
                    )
                }),
        );
        let previous = catalog::read_source(store).ok();
        let old_issuers = read_issuers(store).unwrap_or_default();
        let mut report = AutoReport {
            catalog_changed: false,
            published: Vec::new(),
            retained: Vec::new(),
            skipped: Vec::new(),
            clients_left_out: Vec::new(),
        };
        let skip = |report: &mut AutoReport, host: &str, reason| {
            report.skipped.push(AutoSkip {
                host: host.to_owned(),
                reason,
            })
        };
        // environment -> (host, name, route urls); `None` urls: keep the old rows.
        let mut verified = BTreeMap::<String, (String, String, Option<Vec<String>>)>::new();
        let mut contested = BTreeSet::<String>::new();
        for (index, (host, name, urls)) in hosts.iter().enumerate() {
            if index >= MAX_ENVIRONMENTS {
                skip(&mut report, host, "limit");
                continue;
            }
            if urls.is_empty() {
                skip(&mut report, host, "no_route");
                continue;
            }
            let (environment, routes) = match self.probe(urls).await {
                Probe::Verified(environment, routes) => (environment, Some(routes)),
                Probe::Mismatch => {
                    skip(&mut report, host, "descriptor_mismatch");
                    continue;
                }
                // An outage is not a withdrawal: a verified host stays published.
                Probe::Outage => {
                    match old_issuers
                        .iter()
                        .find(|(_, issuer)| *issuer == host)
                        .map(|(environment, _)| environment.clone())
                        .filter(|environment| published(previous.as_ref(), environment))
                    {
                        Some(environment) => (environment, None),
                        None => {
                            skip(&mut report, host, "descriptor_unavailable");
                            continue;
                        }
                    }
                }
            };
            // Two hosts naming one UUID: at most one tells the truth, and the
            // descriptor alone cannot say which.
            if contested.contains(&environment) {
                skip(&mut report, host, "environment_conflict");
            } else if let Some((other, _, _)) = verified.remove(&environment) {
                skip(&mut report, &other, "environment_conflict");
                skip(&mut report, host, "environment_conflict");
                contested.insert(environment);
            } else {
                verified.insert(environment, (host.clone(), name.clone(), routes));
            }
        }
        let mut environments = Vec::new();
        let mut endpoints = Vec::new();
        let mut issuers = BTreeMap::new();
        for (environment, (host, name, routes)) in &verified {
            let row = json!({"id":environment,"name":name,"enabled":true});
            let rows = match routes {
                Some(routes) => routes
                    .iter()
                    .enumerate()
                    .map(|(priority, url)| {
                        json!({"environmentId":environment,"descriptorEnvironmentId":environment,
                            "id":format!("route-{priority}"),"url":url,"priority":priority})
                    })
                    .collect::<Vec<_>>(),
                None => previous
                    .as_ref()
                    .and_then(|source| source["endpoints"].as_array())
                    .into_iter()
                    .flatten()
                    .filter(|endpoint| endpoint["environmentId"] == environment.as_str())
                    .cloned()
                    .collect(),
            };
            // The common portable-route policy decides, as for hand-written routes.
            let portable = t3_protocol::bridge_catalog::publish(
                &json!([row]),
                &json!([environment]),
                &json!(rows),
                &json!({"bridgeId":own,"clientId":"publisher-validation","revision":1,"now":0}),
            );
            if portable.is_err() {
                skip(&mut report, host, "route_not_portable");
                continue;
            }
            let entry = AutoHost {
                host: host.clone(),
                environment_id: environment.clone(),
            };
            if routes.is_some() {
                report.published.push(entry);
            } else {
                report.retained.push(entry);
            }
            environments.push(row);
            endpoints.extend(rows);
            issuers.insert(environment.clone(), host.clone());
        }
        let granted: Vec<String> = environments
            .iter()
            .filter_map(|row| row["id"].as_str().map(str::to_owned))
            .collect();
        let mut clients = BTreeMap::new();
        for peer in peers
            .iter()
            .filter(|peer| peer.all_hosts && peer.services.contains("t3"))
        {
            if clients.len() < MAX_CLIENTS {
                clients.insert(peer.id.clone(), granted.clone());
            } else {
                report.clients_left_out.push(peer.id.clone());
            }
        }
        // A withdrawn host leaves the routing table before the catalog is replaced.
        write_issuers(store, &issuers)?;
        report.catalog_changed = catalog::publish_changed(
            store,
            json!({"version":1,"revision":0,"environments":environments,"endpoints":endpoints,"clients":clients}),
        )?;
        Ok(report)
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
fn published(source: Option<&Value>, environment: &str) -> bool {
    source
        .and_then(|source| source["environments"].as_array())
        .is_some_and(|rows| rows.iter().any(|row| row["id"] == environment))
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

    const THIRD: &str = "00000000-0000-4000-8000-000000000003";

    /// HTTPS descriptors: each hostname below answers its fixed environment.
    async fn descriptors() -> Result<(Publisher, u16, tokio::task::JoinHandle<()>)> {
        let names = ["up.test", "same.test", "wrong.test", "garbled.test"];
        let cert = rcgen::generate_simple_self_signed(names.map(String::from).to_vec())?;
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
                    let n = stream.read(&mut request).await.unwrap_or(0);
                    let request = String::from_utf8_lossy(&request[..n]).to_string();
                    let body = if request.contains("garbled.test") {
                        json!({"environmentId":"not-a-uuid"})
                    } else if request.contains("wrong.test") {
                        json!({"environmentId":THIRD})
                    } else {
                        json!({"environmentId":HOST})
                    }
                    .to_string();
                    let _ = stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        let mut http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(reqwest::Certificate::from_pem(cert.cert.pem().as_bytes())?)
            .timeout(Duration::from_secs(2));
        for name in names {
            http = http.resolve(name, addr);
        }
        // Nothing listens on the port of this name: an outage.
        http = http.resolve("down.test", SocketAddr::from(([127, 0, 0, 1], 9)));
        Ok((
            Publisher {
                http: http.build()?,
            },
            addr.port(),
            task,
        ))
    }

    fn host_on(owner: &Store, dir: &Path, name: &str, url: Option<String>) -> Result<String> {
        let host = Store::open(&dir.join(name), name)?;
        let now = crate::unix_time()?;
        let invite = owner.create_invite(&["ssh".into()], Duration::from_secs(60), now)?;
        owner.claim(&invite, &host.id()?, name, now)?;
        owner.approve(&host.id()?, now)?;
        let address = iroh::EndpointAddr::new(host.id()?.parse()?);
        owner.remember_peer(&address, name, &["t3".into()], false)?;
        let routes: Vec<_> = url
            .into_iter()
            .map(|url| crate::routes::ServiceRoute {
                service: "t3".into(),
                url,
            })
            .collect();
        owner.refresh_host(&host.id()?, true, &routes)?;
        host.id()
    }

    fn reasons(report: &AutoReport) -> BTreeMap<String, &'static str> {
        report
            .skipped
            .iter()
            .map(|skip| (skip.host.clone(), skip.reason))
            .collect()
    }

    #[tokio::test]
    async fn auto_publish_skips_and_reports_hosts_it_cannot_verify() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let owner = Store::open(&dir.path().join("owner"), "bridge")?;
        let (publisher, port, task) = descriptors().await?;
        let good = host_on(
            &owner,
            dir.path(),
            "good",
            Some(format!("https://up.test:{port}/")),
        )?;
        let silent = host_on(&owner, dir.path(), "silent", None)?;
        let garbled = host_on(
            &owner,
            dir.path(),
            "garbled",
            Some(format!("https://garbled.test:{port}/")),
        )?;
        let down = host_on(
            &owner,
            dir.path(),
            "down",
            Some("https://down.test:9/".into()),
        )?;
        // Consent not reported: not even probed, nor reported.
        let refused = host_on(&owner, dir.path(), "refused", None)?;
        owner.refresh_host(&refused, false, &[])?;

        let now = crate::unix_time()?;
        let phone = Store::open(&dir.path().join("phone"), "phone")?;
        let invite = owner.create_all_hosts_invite(&["t3".into()], Duration::from_secs(60), now)?;
        owner.claim(&invite, &phone.id()?, "phone", now)?;
        owner.approve(&phone.id()?, now)?;
        let plain = Store::open(&dir.path().join("plain"), "plain")?;
        let invite = owner.create_invite(&["t3".into()], Duration::from_secs(60), now)?;
        owner.claim(&invite, &plain.id()?, "plain", now)?;
        owner.approve(&plain.id()?, now)?;

        let report = publisher.publish_auto(&owner).await?;
        assert!(report.catalog_changed);
        assert_eq!(
            report.published,
            vec![AutoHost {
                host: good.clone(),
                environment_id: HOST.into()
            }]
        );
        let reasons = reasons(&report);
        assert_eq!(reasons[&owner.id()?], "no_route", "self is reported too");
        assert_eq!(reasons[&silent], "no_route");
        assert_eq!(reasons[&garbled], "descriptor_mismatch");
        assert_eq!(reasons[&down], "descriptor_unavailable");
        assert!(!reasons.contains_key(&refused));
        assert_eq!(issuer_of(&owner, HOST)?, good);
        let source = catalog::read_source(&owner)?;
        assert_eq!(source["clients"][phone.id()?], json!([HOST]));
        assert!(
            source["clients"].get(plain.id()?).is_none(),
            "a plain t3 grant gets no hosts"
        );

        // Unchanged pass keeps the revision.
        assert!(!publisher.publish_auto(&owner).await?.catalog_changed);

        // An outage of a verified host keeps it published; it is not a withdrawal.
        owner.refresh_host(
            &good,
            true,
            &[crate::routes::ServiceRoute {
                service: "t3".into(),
                url: "https://down.test:9/".into(),
            }],
        )?;
        let report = publisher.publish_auto(&owner).await?;
        assert_eq!(
            report.retained,
            vec![AutoHost {
                host: good.clone(),
                environment_id: HOST.into()
            }]
        );
        assert!(report.published.is_empty());
        assert!(!report.catalog_changed);

        // Two hosts naming one UUID: neither is believed.
        let url = format!("https://same.test:{port}/");
        owner.refresh_host(
            &good,
            true,
            &[crate::routes::ServiceRoute {
                service: "t3".into(),
                url: url.clone(),
            }],
        )?;
        let twin = host_on(&owner, dir.path(), "twin", Some(url.clone()))?;
        let report = publisher.publish_auto(&owner).await?;
        let found = super::tests::reasons(&report);
        assert_eq!(found[&good], "environment_conflict");
        assert_eq!(found[&twin], "environment_conflict");
        assert!(report.published.is_empty());
        owner.refresh_host(&twin, false, &[])?;

        // Routes of one host naming different UUIDs: skipped, others go on.
        owner.refresh_host(
            &good,
            true,
            &[
                crate::routes::ServiceRoute {
                    service: "t3".into(),
                    url,
                },
                crate::routes::ServiceRoute {
                    service: "t3".into(),
                    url: format!("https://wrong.test:{port}/"),
                },
            ],
        )?;
        let report = publisher.publish_auto(&owner).await?;
        assert_eq!(super::tests::reasons(&report)[&good], "descriptor_mismatch");

        // Withdrawal leaves the catalog and the routing table.
        owner.refresh_host(
            &good,
            true,
            &[crate::routes::ServiceRoute {
                service: "t3".into(),
                url: format!("https://up.test:{port}/"),
            }],
        )?;
        assert!(publisher.publish_auto(&owner).await?.catalog_changed);
        assert_eq!(issuer_of(&owner, HOST)?, good);
        owner.refresh_host(&good, false, &[])?;
        let report = publisher.publish_auto(&owner).await?;
        assert!(report.catalog_changed);
        assert_eq!(
            catalog::read_source(&owner)?["clients"][phone.id()?],
            json!([])
        );
        assert!(issuer_of(&owner, HOST).is_err());
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn policy_mode_still_aborts_on_a_descriptor_mismatch() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let owner = Store::open(&dir.path().join("owner"), "bridge")?;
        let (publisher, port, task) = descriptors().await?;
        let policy = Policy {
            aliases: BTreeMap::new(),
            routes: vec![Route {
                environment_id: HOST.into(),
                id: "gateway".into(),
                url: format!("https://wrong.test:{port}/"),
                priority: 0,
            }],
            clients: BTreeMap::new(),
        };
        let desktop = json!({"environments":[{"id":HOST,"name":"HOST","enabled":true}]});
        assert!(publisher.publish(&owner, &desktop, &policy).await.is_err());
        task.abort();
        Ok(())
    }
}
