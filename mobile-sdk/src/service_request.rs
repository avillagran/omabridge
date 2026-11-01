//! Single-attempt HTTP over an authenticated, grant-checked service pipe.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use http_body_util::{BodyExt, Full};
use hyper::{Request, body::Bytes};
use hyper_util::rt::TokioIo;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::sync::watch;

const BODY: usize = 512 * 1024;
const HEADERS: usize = 16 * 1024;
type Key = (u64, String);
static ACTIVE: OnceLock<Mutex<BTreeMap<Key, watch::Sender<bool>>>> = OnceLock::new();
fn active() -> &'static Mutex<BTreeMap<Key, watch::Sender<bool>>> {
    ACTIVE.get_or_init(|| Mutex::new(BTreeMap::new()))
}
fn key(v: &Value) -> Result<Key> {
    let id = text(v, "requestId")?;
    anyhow::ensure!(!id.is_empty() && id.len() <= 128, "invalid_input");
    Ok((v["handle"].as_u64().context("invalid_input")?, id.into()))
}
pub(super) fn cancel(v: &Value) -> Result<Value> {
    let key = key(v)?;
    let map = active()
        .lock()
        .map_err(|_| anyhow::anyhow!("native_error"))?;
    let found = map.get(&key);
    if let Some(tx) = found {
        let _ = tx.send(true);
    }
    Ok(json!({"cancelled":found.is_some()}))
}
struct Registration(Key);
impl Drop for Registration {
    fn drop(&mut self) {
        if let Ok(mut map) = active().lock() {
            map.remove(&self.0);
        }
    }
}
pub(super) fn call(s: &Session, v: &Value) -> Result<Value> {
    let method = text(v, "method")?;
    anyhow::ensure!(matches!(method, "GET" | "POST"), "invalid_input");
    let path = text(v, "path")?;
    anyhow::ensure!(
        path.starts_with('/')
            && !path.starts_with("//")
            && path.len() <= 4096
            && !path.contains('#'),
        "invalid_input"
    );
    let uri: hyper::Uri = path.parse().context("invalid_input")?;
    anyhow::ensure!(
        uri.scheme().is_none() && uri.authority().is_none(),
        "invalid_input"
    );
    let service = text(v, "service")?;
    anyhow::ensure!(!service.is_empty() && service.len() <= 128, "invalid_input");
    let bearer = text(v, "bearer")?;
    anyhow::ensure!(
        !bearer.is_empty() && bearer.len() <= 8192 && bearer.bytes().all(|b| b.is_ascii_graphic()),
        "invalid_input"
    );
    let body = v["bodyBase64"].as_str().unwrap_or("");
    anyhow::ensure!(body.len() <= BODY.div_ceil(3) * 4, "invalid_input");
    let body = STANDARD.decode(body).context("invalid_input")?;
    anyhow::ensure!(
        body.len() <= BODY && (method != "GET" || body.is_empty()),
        "invalid_input"
    );
    let millis = v["timeoutMs"].as_u64().context("invalid_input")?;
    anyhow::ensure!((1..=120_000).contains(&millis), "invalid_input");
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "bridge-service")
        .header("connection", "close")
        .header("authorization", format!("Bearer {bearer}"));
    let mut size = bearer.len() + 128;
    if let Some(headers) = v.get("headers") {
        let headers = headers.as_object().context("invalid_input")?;
        anyhow::ensure!(headers.len() <= 32, "invalid_input");
        for (name, value) in headers {
            // Restrict application headers: no framing, routing, cookies or credentials.
            anyhow::ensure!(
                matches!(
                    name.as_str(),
                    "accept" | "content-type" | "x-t3-orchestration-protocol"
                ),
                "invalid_input"
            );
            let value = value.as_str().context("invalid_input")?;
            size += name.len() + value.len() + 4;
            anyhow::ensure!(size <= HEADERS, "invalid_input");
            request = request.header(name, value);
        }
    }
    let request = request
        .body(Full::new(Bytes::from(body)))
        .context("invalid_input")?;
    let found = omabridge::find_peer(&s.store, text(v, "peer")?).map_err(anyhow::Error::msg)?;
    let address = found.address.context("peer_address_missing")?;
    let key = key(v)?;
    let (tx, mut cancel) = watch::channel(false);
    {
        let mut map = active()
            .lock()
            .map_err(|_| anyhow::anyhow!("native_error"))?;
        anyhow::ensure!(!map.contains_key(&key), "invalid_input");
        map.insert(key.clone(), tx);
    }
    let _registration = Registration(key);
    let sent = AtomicBool::new(false);
    let result = s.runtime.block_on(async {
        let operation = async {
            let mut pipe = s.client.open(&address, service).await.map_err(|_| "transport")?;
            let (http, tunnel) = tokio::io::duplex(32 * 1024);
            let exchange = async {
                let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
                    .max_buf_size(HEADERS).handshake(TokioIo::new(http)).await.map_err(|_| "transport")?;
                let response = async {
                    sent.store(true, Ordering::SeqCst);
                    let mut response = sender.send_request(request).await.map_err(|_| "transport")?;
                    let status = response.status().as_u16();
                    let headers = response.headers();
                    if headers.len() > 64 || headers.iter().map(|(k,v)| k.as_str().len()+v.len()+4).sum::<usize>() > HEADERS { return Err("response_too_large"); }
                    // Credentials and cookies are never returned to the caller.
                    let headers: Vec<_> = headers.iter().filter(|(k,_)| !matches!(k.as_str(), "authorization" | "proxy-authorization" | "set-cookie"))
                        .map(|(k,v)| (k.as_str().to_owned(), STANDARD.encode(v.as_bytes()))).collect();
                    let mut body = Vec::new();
                    while let Some(frame) = response.body_mut().frame().await {
                        let frame = frame.map_err(|_| "transport")?;
                        if let Ok(data) = frame.into_data() {
                            if data.len() > BODY - body.len() { return Err("response_too_large"); }
                            body.extend_from_slice(&data);
                        }
                    }
                    Ok(json!({"outcome":"http","httpStatus":status,"headersBase64":headers,"bodyBase64":STANDARD.encode(body)}))
                };
                tokio::pin!(response);
                tokio::pin!(connection);
                tokio::select! { r = &mut response => r, _ = &mut connection => response.await }
            };
            tokio::pin!(exchange);
            tokio::select! { r = &mut exchange => r, _ = pipe.transfer(tunnel) => exchange.await }
        };
        tokio::select! {
            r = operation => r,
            _ = tokio::time::sleep(Duration::from_millis(millis)) => Err("timeout"),
            _ = cancel.changed() => Err("cancelled"),
        }
    });
    Ok(result.unwrap_or_else(|reason| json!({"outcome":if sent.load(Ordering::SeqCst) {"unknown"} else {"notSent"},"reason":reason})))
}
