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
