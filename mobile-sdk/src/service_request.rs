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
fn http_error(error: hyper::Error) -> &'static str {
    if error.is_parse_too_large() {
        "response_too_large"
    } else {
        "transport"
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
    let body = match v.get("bodyBase64") {
        Some(value) => value.as_str().context("invalid_input")?,
        None => "",
    };
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
                    .max_headers(64)
                    .max_buf_size(HEADERS)
                    .handshake(TokioIo::new(http))
                    .await
                    .map_err(|_| "transport")?;
                let response = async {
                    sent.store(true, Ordering::SeqCst);
                    let mut response = sender.send_request(request).await.map_err(http_error)?;
                    let status = response.status().as_u16();
                    let headers = response.headers();
                    let mut header_bytes = headers.iter()
                        .map(|(k, v)| k.as_str().len() + v.len() + 4)
                        .sum::<usize>();
                    if headers.len() > 64 || header_bytes > HEADERS {
                        return Err("response_too_large");
                    }
                    let mut header_count = headers.len();
                    // Credentials and cookies are never returned to the caller.
                    let headers: Vec<_> = headers.iter().filter(|(k,_)| !matches!(k.as_str(), "authorization" | "proxy-authorization" | "set-cookie"))
                        .map(|(k,v)| (k.as_str().to_owned(), STANDARD.encode(v.as_bytes()))).collect();
                    let mut body = Vec::new();
                    while let Some(frame) = response.body_mut().frame().await {
                        let frame = frame.map_err(http_error)?;
                        match frame.into_data() {
                            Ok(data) => {
                                if data.len() > BODY - body.len() {
                                    return Err("response_too_large");
                                }
                                body.extend_from_slice(&data);
                            }
                            Err(frame) => {
                                if let Ok(trailers) = frame.into_trailers() {
                                    header_count += trailers.len();
                                    header_bytes += trailers.iter()
                                        .map(|(k, v)| k.as_str().len() + v.len() + 4)
                                        .sum::<usize>();
                                    if header_count > 64 || header_bytes > HEADERS {
                                        return Err("response_too_large");
                                    }
                                }
                            }
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

#[cfg(test)]
mod tests {
    use super::super::tests::abi;
    use super::*;
    use omabridge::{NetOptions, Node};
    use std::sync::{Arc, atomic::AtomicUsize};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Clone, Default)]
    struct Logs(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Logs {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logs {
        type Writer = Self;
        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }
    #[test]
    fn real_peer_service_contract() -> Result<()> {
        let logs = Logs::default();
        tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_ansi(false)
                .with_writer(logs.clone())
                .finish(),
        )?;
        let dir = tempfile::tempdir()?;
        let rt = tokio::runtime::Runtime::new()?;
        let owner = Store::open(&dir.path().join("owner"), "owner")?;
        let calls = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicBool::new(false));
        let (node, server) = rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let target = listener.local_addr()?;
            let count = calls.clone();
            let signal = started.clone();
            let server = tokio::spawn(async move {
                while let Ok((mut socket, _)) = listener.accept().await {
                    let count = count.clone();
                    let signal = signal.clone();
                    tokio::spawn(async move {
                        let mut bytes = Vec::new();
                        loop {
                            let mut byte = [0];
                            if socket.read_exact(&mut byte).await.is_err() { return; }
                            bytes.push(byte[0]);
                            if bytes.ends_with(b"\r\n\r\n") { break; }
                            assert!(bytes.len() <= HEADERS);
                        }
                        let request = String::from_utf8(bytes).unwrap();
                        assert!(request.contains("authorization: Bearer private-service-bearer\r\n"));
                        count.fetch_add(1, Ordering::SeqCst);
                        let path = request.split_whitespace().nth(1).unwrap();
                        if path == "/post" {
                            assert!(request.starts_with("POST /post HTTP/1.1"));
                            assert!(request.contains("content-length: 2\r\n"));
                            let mut body = [0; 2];
                            socket.read_exact(&mut body).await.unwrap();
                            assert_eq!(&body, b"{}");
                        }
                        if path == "/drop" { return; }
                        if path == "/hold" {
                            signal.store(true, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            return;
                        }
                        let response = match path {
                            "/large" => format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", BODY+1, "x".repeat(BODY+1)),
                            "/headers" => format!("HTTP/1.1 200 OK\r\nx-large: {}\r\nContent-Length: 0\r\n\r\n", "x".repeat(HEADERS)),
                            "/chunked" => "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n{\r\n1\r\n}\r\n0\r\n\r\n".into(),
                            "/redirect" => "HTTP/1.1 302 Found\r\nLocation: /ok\r\nContent-Length: 0\r\n\r\n".into(),
                            _ => "HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".into(),
                        };
                        let _ = socket.write_all(response.as_bytes()).await;
                    });
                }
            });
            let node = Node::start(owner.clone(), BTreeMap::from([("desktop-snapshots".into(),target)]), NetOptions::loopback()).await?;
            Ok::<_, anyhow::Error>((node, server))
        })?;
        owner.publish_endpoint(&node.addr(), &["desktop-snapshots".into()])?;
        let opened =
            abi(json!({"op":"open","stateDir":dir.path().join("mobile"),"directOnly":true}));
        let handle = opened["ok"]["handle"].clone();
        let phone = opened["ok"]["clientId"].as_str().unwrap();
        let now = omabridge::unix_time()?;
        let invitation = Invitation {
            version: 1,
            address: node.addr(),
            token: owner.create_invite(
                &["desktop-snapshots".into()],
                Duration::from_secs(300),
                now,
            )?,
            name: "owner".into(),
            expires: now + 300,
            manage: false,
        };
        let pair = json!({"op":"pair","handle":handle,"invitation":invitation});
        assert_eq!(abi(pair.clone())["ok"]["approved"], false);
        owner.approve(phone, now)?;
        assert_eq!(abi(pair)["ok"]["approved"], true);
        let mut input = json!({"op":"serviceRequest","handle":handle,"requestId":"contract","peer":owner.id()?,"service":"desktop-snapshots","method":"GET","path":"/ok","bearer":"private-service-bearer","timeoutMs":10000});
        let response = abi(input.clone());
        assert_eq!(response["ok"]["outcome"], "http", "{response}");
        assert_eq!(response["ok"]["httpStatus"], 403);
        assert_eq!(response["ok"]["bodyBase64"], "e30=");
        input["path"] = json!("/chunked");
        assert_eq!(abi(input.clone())["ok"]["bodyBase64"], "e30=");
        input["method"] = json!("POST");
        input["path"] = json!("/post");
        input["bodyBase64"] = json!("e30=");
        input["headers"] = json!({"content-type":"application/json"});
        assert_eq!(abi(input.clone())["ok"]["httpStatus"], 403);
        input["method"] = json!("GET");
        input.as_object_mut().unwrap().remove("bodyBase64");
        input["path"] = json!("/redirect");
        let before = calls.load(Ordering::SeqCst);
        assert_eq!(abi(input.clone())["ok"]["httpStatus"], 302);
        assert_eq!(calls.load(Ordering::SeqCst), before + 1);
        for path in ["/large", "/headers"] {
            input["path"] = json!(path);
            assert_eq!(abi(input.clone())["ok"]["outcome"], "unknown");
        }
        input["method"] = json!("POST");
        input["path"] = json!("/drop");
        let before = calls.load(Ordering::SeqCst);
        assert_eq!(abi(input.clone())["ok"]["outcome"], "unknown");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            before + 1,
            "POST must never retry"
        );
        input["path"] = json!("/hold");
        input["timeoutMs"] = json!(500);
        let response = abi(input.clone());
        assert_eq!(response["ok"]["reason"], "timeout");
        assert_eq!(response["ok"]["outcome"], "unknown");
        started.store(false, Ordering::SeqCst);
        input["timeoutMs"] = json!(10000);
        let cancel_handle = handle.clone();
        let signal = started.clone();
        let canceller = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while !signal.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(5));
            }
            abi(json!({"op":"cancelServiceRequest","handle":cancel_handle,"requestId":"contract"}))
        });
        let response = abi(input.clone());
        assert_eq!(response["ok"]["outcome"], "unknown");
        assert_eq!(response["ok"]["reason"], "cancelled");
        assert_eq!(canceller.join().unwrap()["ok"]["cancelled"], true);
        assert_eq!(
            abi(json!({"op":"cancelServiceRequest","handle":handle,"requestId":"contract"}))["ok"]
                ["cancelled"],
            false
        );
        owner.set_services(phone, &[], &[])?;
        input["path"] = json!("/ok");
        let before = calls.load(Ordering::SeqCst);
        assert_eq!(abi(input.clone())["ok"]["outcome"], "notSent");
        assert_eq!(calls.load(Ordering::SeqCst), before);
        for (field, value) in [
            ("bodyBase64", json!(STANDARD.encode(vec![0; BODY + 1]))),
            ("method", json!("PUT")),
            ("path", json!("//evil")),
            ("bearer", json!("bad\r\nheader")),
            ("headers", json!({"host":"evil"})),
            ("headers", json!({"content-type":"x".repeat(HEADERS+1)})),
            ("bearer", json!("x".repeat(8193))),
            ("timeoutMs", json!(0)),
        ] {
            let mut invalid = input.clone();
            invalid[field] = value;
            assert!(abi(invalid).get("error").is_some());
        }
        assert_eq!(calls.load(Ordering::SeqCst), before);
        fn inspect(path: &std::path::Path) -> Result<()> {
            for entry in std::fs::read_dir(path)? {
                let path = entry?.path();
                if path.is_dir() {
                    inspect(&path)?;
                } else if path.is_file() {
                    assert!(
                        !std::fs::read(path)?
                            .windows(b"private-service-bearer".len())
                            .any(|w| w == b"private-service-bearer")
                    );
                }
            }
            Ok(())
        }
        inspect(dir.path())?;
        abi(json!({"op":"close","handle":handle}));
        rt.block_on(node.shutdown());
        server.abort();
        let captured = logs.0.lock().unwrap();
        assert!(
            !captured.is_empty(),
            "capture must observe real transport logs"
        );
        assert!(
            !captured
                .windows(b"private-service-bearer".len())
                .any(|w| w == b"private-service-bearer")
        );
        Ok(())
    }
}
