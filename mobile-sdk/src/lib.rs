//! Synchronous C ABI for Android/JNI. Owns its iroh identity and runtime.
//! This package depends on OmaBridge -> lib-t3-rust; no reverse dependency.
use anyhow::{Context, Result};
use omabridge::{Client, Invitation, NetOptions, Store, catalog_client::CatalogManager};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::CString,
    sync::{Mutex, OnceLock},
};
struct Session {
    runtime: tokio::runtime::Runtime,
    client: Client,
    store: Store,
    manager: Option<CatalogManager>,
    #[cfg(feature = "lab-tls")]
    lab_http: Option<reqwest012::blocking::Client>,
}
static SESSIONS: OnceLock<Mutex<BTreeMap<u64, Session>>> = OnceLock::new();
fn registry() -> &'static Mutex<BTreeMap<u64, Session>> {
    SESSIONS.get_or_init(|| Mutex::new(BTreeMap::new()))
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().context("invalid_input")
}
fn unix_millis() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn call(v: Value) -> Result<Value> {
    let mut sessions = registry()
        .lock()
        .map_err(|_| anyhow::anyhow!("native_error"))?;
    let op = text(&v, "op")?;
    if op == "capabilities" {
        return Ok(json!({"abi":1,"features":["mobile-admin-v1","shared-drafts-v1"]}));
    }
    if op == "open" {
        let path = std::path::Path::new(text(&v, "stateDir")?);
        anyhow::ensure!(path.is_absolute(), "invalid_state_directory");
        let store = Store::open(path, "Android")?;
        anyhow::ensure!(
            !sessions.values().any(|s| s.store.root() == store.root()),
            "identity_already_open"
        );
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let client = runtime.block_on(Client::new(
            store.clone(),
            NetOptions {
                compress_t3: false,
                bind: "0.0.0.0:0".parse()?,
                relay: if v["directOnly"] == true {
                    omabridge::Relay::Disabled
                } else {
                    omabridge::Relay::load(path)?
                },
            },
        ))?;
        let id = sessions
            .keys()
            .next_back()
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .context("handle_exhausted")?;
        let identity = store.id()?;
        let selection = store.root().join("mobile-selected-bridge.json");
        let manager = if selection.exists() {
            let peer: String = omabridge::read_document(&selection)?;
            let found = omabridge::find_peer(&store, &peer).map_err(anyhow::Error::msg)?;
            Some(CatalogManager::open(
                store.clone(),
                found.address.context("peer_address_missing")?,
            )?)
        } else {
            None
        };
        let bridge_id = manager.as_ref().map(|m| m.bridge().id.to_string());
        sessions.insert(
            id,
            Session {
                runtime,
                client,
                store,
                manager,
                #[cfg(feature = "lab-tls")]
                lab_http: v["labCaPem"]
                    .as_str()
                    .map(|pem| -> Result<_> {
                        Ok(reqwest012::blocking::Client::builder()
                            .no_proxy()
                            .redirect(reqwest012::redirect::Policy::none())
                            .timeout(std::time::Duration::from_secs(12))
                            .add_root_certificate(reqwest012::Certificate::from_pem(
                                pem.as_bytes(),
                            )?)
                            .build()?)
                    })
                    .transpose()?,
            },
        );
        return Ok(json!({"handle":id,"clientId":identity,"bridgeId":bridge_id}));
    }
    let id = v["handle"].as_u64().context("invalid_handle")?;
    if op == "close" {
        if let Some(session) = sessions.remove(&id) {
            session.runtime.block_on(session.client.close());
        }
        return Ok(json!({}));
    }
    let s = sessions.get_mut(&id).context("invalid_handle")?;
    match op {
        "peers" => Ok(json!({"clientId":s.store.id()?,"peers":s.store.peers()?})),
        "manage" | "drafts" => {
            let peer = text(&v, "peer")?;
            let found = omabridge::find_peer(&s.store, peer).map_err(anyhow::Error::msg)?;
            let address = found.address.context("peer_address_missing")?;
            let command = &v["command"];
            if op == "manage" {
                anyhow::ensure!(
                    command["action"] == "read"
                        || command["action"] == "endpoints"
                        || v["confirmed"] == true,
                    "confirmation_required"
                );
                s.runtime.block_on(s.client.manage(&address, command))
            } else {
                s.runtime.block_on(s.client.drafts(&address, command))
            }
        }
        "pair" => {
            let invite: Invitation =
                serde_json::from_value(v["invitation"].clone()).context("invalid_invitation")?;
            let decision =
                s.runtime
                    .block_on(s.client.pair(&invite, "Android", omabridge::unix_time()?))?;
            let (approved, all_hosts) = match decision {
                omabridge::PairDecision::Approved { all_hosts, .. } => (true, all_hosts),
                omabridge::PairDecision::Pending => (false, false),
            };
            Ok(json!({"approved":approved,"allHosts":all_hosts}))
        }
        "selectBridge" => {
            let peer = text(&v, "bridgeId")?;
            let found = omabridge::find_peer(&s.store, peer).map_err(anyhow::Error::msg)?;
            let addr = found.address.context("peer_address_missing")?;
            s.manager = Some(CatalogManager::open(s.store.clone(), addr)?);
            omabridge::write_document(
                &s.store.root().join("mobile-selected-bridge.json"),
                &found.id,
                true,
            )?;
            Ok(json!({}))
        }
        "refresh" => {
            let manager = s.manager.as_mut().context("bridge_not_selected")?;
            s.runtime.block_on(manager.refresh(&s.client))
        }
        "enroll" => {
            let now = unix_millis()?;
            let id = text(&v, "environmentId")?;
            let manager = s.manager.as_ref().context("bridge_not_selected")?;
            let url = manager.enrollment_route(id, now)?;
            let enrollment = s.runtime.block_on(s.client.enroll(manager.bridge(), id))?;
            let received_at = unix_millis()?;
            anyhow::ensure!(
                manager.enrollment_route(id, received_at)? == url,
                "route unavailable"
            );
            #[cfg(feature = "lab-tls")]
            let http = s.lab_http.clone();
            #[cfg(not(feature = "lab-tls"))]
            let http = None;
            let mut receipt =
                omabridge::enrollment::redeem_with_http(&enrollment, &url, received_at, http)?;
            receipt["baseUrl"] = json!(url);
            receipt["provenance"] =
                json!(format!("bridge:{}:{}", manager.bridge().id, s.store.id()?));
            Ok(receipt)
        }
        // All-hosts path: a native session with write access. Also renews one; the
        // read-only `enroll` above never touches a row this op filled.
        "hostPair" => {
            let now = unix_millis()?;
            let id = text(&v, "environmentId")?;
            let manager = s.manager.as_ref().context("bridge_not_selected")?;
            let url = manager.enrollment_route(id, now)?;
            let pairing = s
                .runtime
                .block_on(s.client.t3_host_pair(manager.bridge(), id))?;
            let received_at = unix_millis()?;
            anyhow::ensure!(
                manager.enrollment_route(id, received_at)? == url,
                "route unavailable"
            );
            let mut receipt = omabridge::enrollment::redeem_pairing(&pairing, &url, received_at)?;
            receipt["baseUrl"] = json!(url);
            receipt["provenance"] =
                json!(format!("bridge:{}:{}", manager.bridge().id, s.store.id()?));
            Ok(receipt)
        }
        #[cfg(feature = "lab-tls")]
        "labRequest" => {
            let http = s.lab_http.clone().context("lab trust not configured")?;
            let method: reqwest012::Method = text(&v, "method")?.parse()?;
            let base = reqwest012::Url::parse(text(&v, "url")?)?;
            let url = base.join(text(&v, "path")?)?;
            anyhow::ensure!(url.origin() == base.origin(), "cross origin lab request");
            let mut request = http
                .request(method, url)
                .bearer_auth(text(&v, "token")?)
                .header("x-t3-orchestration-protocol", "2");
            if let Some(body) = v.get("body") {
                request = request.json(body);
            }
            let response = request.send()?;
            let status = response.status().as_u16();
            let body: Value = response.json()?;
            Ok(json!({"httpStatus":status,"body":body}))
        }
        "cached" => Ok(s
            .manager
            .as_ref()
            .context("bridge_not_selected")?
            .cached(unix_millis()?)),
        "projection" => s
            .manager
            .as_ref()
            .context("bridge_not_selected")?
            .projection(&v["local"], unix_millis()?),
        _ => anyhow::bail!("invalid_operation"),
    }
}
/// Input/output are UTF-8 JSON. Errors are fixed codes; never serialize Rust
/// errors, invitation bodies, endpoint addresses or private state.
/// # Safety
/// `input` must point to `len` readable bytes for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omabridge_mobile_call(
    input: *const u8,
    len: usize,
) -> *mut std::ffi::c_char {
    let result = std::panic::catch_unwind(|| {
        if input.is_null() || len > 1024 * 1024 {
            return json!({"error":"invalid_input"});
        }
        let bytes = unsafe { std::slice::from_raw_parts(input, len) };
        match serde_json::from_slice(bytes)
            .map_err(|_| anyhow::anyhow!("invalid_input"))
            .and_then(call)
        {
            Ok(value) => json!({"ok":value}),
            Err(error) => {
                let codes = [
                    "invalid_input",
                    "confirmation_required",
                    "invalid_invitation",
                    "unsupported or expired invitation",
                    "pairing denied",
                    "connection setup deadline reached",
                    "no route allowed by local relay policy",
                    "bridge_not_selected",
                    "peer_address_missing",
                    "bridge_catalog_expired",
                    "bridge_catalog_invalid_window",
                    "bridge_catalog_ttl_exceeded",
                    "bridge_catalog_from_future",
                    "bridge_catalog_revision_reused",
                    "bridge_catalog_rollback",
                    "bridge_catalog_equivocation",
                    "bridge_catalog_identity_mismatch",
                    "invalid_bridge_catalog",
                    "route unavailable",
                    "catalog unavailable",
                    "authority session is not bounded read-only",
                    "authority session exceeds enrollment",
                    "authority returned unbounded session",
                    "authority returned excessive scopes",
                    "enrollment must be bounded read-only",
                    "descriptor identity mismatch",
                    "T3 session issuance failed",
                    "omabridge_host_pair_refused",
                    "omabridge_host_pair_unavailable",
                    "native_session_invalid",
                    "pairing_rejected",
                    "t3_environment_mismatch",
                ];
                let code = error
                    .chain()
                    .find_map(|cause| {
                        codes
                            .iter()
                            .find(|code| cause.to_string() == **code)
                            .copied()
                    })
                    .unwrap_or("bridge_operation_failed");
                json!({"error":code})
            }
        }
    })
    .unwrap_or_else(|_| json!({"error":"native_error"}));
    CString::new(result.to_string()).unwrap().into_raw()
}
/// # Safety
/// `ptr` must be a result from `omabridge_mobile_call`, freed exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn omabridge_mobile_free(ptr: *mut std::ffi::c_char) {
    if !ptr.is_null() {
        let mut owned = unsafe { CString::from_raw(ptr) }.into_bytes_with_nul();
        for byte in &mut owned {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omabridge::{NetOptions, Node};
    use std::{collections::BTreeMap, ffi::CStr, time::Duration};

    fn abi(input: Value) -> Value {
        let bytes = serde_json::to_vec(&input).unwrap();
        unsafe {
            let raw = omabridge_mobile_call(bytes.as_ptr(), bytes.len());
            let value = serde_json::from_slice(CStr::from_ptr(raw).to_bytes()).unwrap();
            omabridge_mobile_free(raw);
            value
        }
    }
    #[test]
    fn mobile_abi_admin_and_drafts_over_real_peer() -> Result<()> {
        assert_eq!(abi(json!({"op":"capabilities"}))["ok"]["abi"], 1);
        let dir = tempfile::tempdir()?;
        let runtime = tokio::runtime::Runtime::new()?;
        let owner = Store::open(&dir.path().join("owner"), "owner")?;
        let node = runtime.block_on(Node::start(
            owner.clone(),
            BTreeMap::from([("t3".into(), "127.0.0.1:9".parse()?)]),
            NetOptions::loopback(),
        ))?;
        owner.publish_endpoint(&node.addr(), &["t3".into()])?;
        let opened =
            abi(json!({"op":"open","stateDir":dir.path().join("mobile"),"directOnly":true}));
        let handle = opened["ok"]["handle"].clone();
        let phone = opened["ok"]["clientId"].as_str().context("open failed")?;
        let now = omabridge::unix_time()?;
        let invite = Invitation {
            version: 1,
            address: node.addr(),
            token: owner.create_invite(
                &["t3".into(), "drafts".into()],
                Duration::from_secs(300),
                now,
            )?,
            name: "owner".into(),
            expires: now + 300,
            manage: false,
        };
        let pair = json!({"op":"pair","handle":handle,"invitation":invite});
        assert_eq!(abi(pair.clone())["ok"]["approved"], false);
        owner.approve(phone, now)?;
        assert_eq!(abi(pair)["ok"]["approved"], true);
        let peer = owner.id()?;
        let read = json!({"op":"manage","handle":handle,"peer":peer,"command":{"action":"read"}});
        assert_eq!(abi(read.clone())["ok"]["error"], "omabridge_not_admin");
        owner.set_admin(phone, true)?;
        let snapshot = abi(read.clone());
        assert_eq!(snapshot["ok"]["device"]["id"], peer);
        assert_eq!(snapshot["ok"]["draftStore"]["owner"], peer);
        assert!(abi(json!({"op":"peers","handle":handle}))["ok"]["peers"].is_array());
        let rename = json!({"op":"manage","handle":handle,"peer":peer,"command":{"action":"rename","name":"renamed"}});
        assert_eq!(abi(rename.clone())["error"], "confirmation_required");
        let mut confirmed = rename;
        confirmed["confirmed"] = json!(true);
        assert_eq!(abi(confirmed)["ok"]["device"]["name"], "renamed");
        for action in [
            "bridge-consent-set",
            "admin-set",
            "grant-set",
            "gateway-domain-set",
            "identity-create",
            "pair",
        ] {
            assert_eq!(
                abi(
                    json!({"op":"manage","handle":handle,"peer":peer,"confirmed":true,"command":{"action":action}})
                )["ok"]["error"],
                "omabridge_remote_forbidden"
            );
        }
        // Issuance returns a one-time secret inline; a remote path is forbidden.
        let invitation = abi(
            json!({"op":"manage","handle":handle,"peer":peer,"confirmed":true,"command":{"action":"invite","services":["t3"],"allHosts":true}}),
        );
        let created = &invitation["ok"]["created"];
        assert_eq!(created["allHosts"], true);
        assert!(created["invitation"]["token"].is_string());
        assert!(created.get("path").is_none());
        assert_eq!(
            abi(
                json!({"op":"manage","handle":handle,"peer":peer,"confirmed":true,"command":{"action":"invite","services":["ssh"]}})
            )["ok"]["error"],
            "omabridge_service_not_granted"
        );
        assert_eq!(
            abi(
                json!({"op":"manage","handle":handle,"peer":peer,"confirmed":true,"command":{"action":"invite","services":["t3"],"directory":"/tmp"}})
            )["ok"]["error"],
            "omabridge_remote_forbidden"
        );
        let other = Store::open(&dir.path().join("other"), "other")?;
        owner.claim(
            created["invitation"]["token"].as_str().unwrap(),
            &other.id()?,
            "other",
            now,
        )?;
        assert_eq!(
            abi(
                json!({"op":"manage","handle":handle,"peer":peer,"confirmed":true,"command":{"action":"approve","peer":other.id()?}})
            )["ok"]["error"],
            "omabridge_remote_forbidden"
        );
        owner.approve(&other.id()?, now)?; // Only the owner at the device can approve it.
        let command = json!({"op":"put","scope":{"environment":"env","project":"project","kind":"thread","id":"thread"},"expected":null,"mutationId":"mobile-first","payload":{"schema":1,"text":"private mobile draft","attachments":[]}});
        let saved = abi(json!({"op":"drafts","handle":handle,"peer":peer,"command":command}));
        assert_eq!(saved["ok"]["status"], "applied");
        owner.set_services(phone, &["t3".into()], &[])?;
        assert_eq!(
            abi(json!({"op":"drafts","handle":handle,"peer":peer,"command":{"op":"list"}}))["ok"]["error"],
            "draft_forbidden"
        );
        owner.set_admin(phone, false)?;
        assert_eq!(abi(read)["ok"]["error"], "omabridge_not_admin");
        let audit = std::fs::read_to_string(owner.root().join("manage-audit.jsonl"))?;
        assert!(!audit.contains("private mobile draft"));
        assert!(!audit.contains(created["invitation"]["token"].as_str().unwrap()));
        assert!(abi(json!({"op":"close","handle":handle}))["ok"].is_object());
        runtime.block_on(node.shutdown());
        Ok(())
    }
}
