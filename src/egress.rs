//! Fixed-origin HTTPS egress. No client-selected destination or credential forwarding.
use anyhow::{Result, ensure};
use reqwest::Url;

/// Conservative global-unicast policy; reject translation and special-purpose ranges.
pub fn public_address(address: std::net::IpAddr) -> bool {
    match address {
        std::net::IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(matches!(a, 0 | 10 | 127)
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192
                    && (b == 168 || (b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99)))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        std::net::IpAddr::V6(ip) => {
            let [a, b, ..] = ip.segments();
            (a & 0xe000) == 0x2000
                && !(a == 0x2001 && (b <= 0x01ff || b == 0x0db8))
                && a != 0x2002
                && !(a == 0x3fff && b <= 0x0fff)
        }
    }
}

#[derive(Clone)]
pub struct Origin {
    url: Url,
    host: String,
}

impl Origin {
    pub fn parse(raw: &str) -> Result<Self> {
        let url = Url::parse(raw).map_err(|_| anyhow::anyhow!("invalid HTTPS origin"))?;
        ensure!(
            url.scheme() == "https"
                && url.username().is_empty()
                && url.password().is_none()
                && url.port_or_known_default() == Some(443)
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none(),
            "origin must be HTTPS with no credentials, path, query or nonstandard port"
        );
        let host = url.host_str().unwrap_or_default().to_owned();
        ensure!(
            host.contains('.')
                && !host.contains("..")
                && !host.starts_with('.')
                && !host.ends_with('.')
                && host.parse::<std::net::IpAddr>().is_err()
                && host
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b".-".contains(&c)),
            "origin must name a public DNS host"
        );
        Ok(Self { url, host })
    }
    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }
}

use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Request, Response,
    body::{Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use reqwest::{
    Method, StatusCode,
    header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue, TRANSFER_ENCODING},
};
use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, lookup_host},
    sync::Semaphore,
    task::{JoinHandle, JoinSet},
    time::timeout,
};

const MAX_REQUEST: usize = 1024 * 1024;
const MAX_RESPONSE: usize = 2 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(15);

struct Config {
    origin: Origin,
    authorization: Option<HeaderValue>,
    #[cfg(test)]
    client: Option<reqwest::Client>,
}

/// An owned loopback gateway; dropping it closes its listener and all active work.
pub struct Gateway {
    address: SocketAddr,
    task: JoinHandle<()>,
}

impl Gateway {
    pub async fn start(origin: Origin, key: Option<String>) -> Result<Self> {
        let authorization = key
            .map(|key| {
                ensure!(!key.is_empty(), "empty egress API credential");
                let mut value = HeaderValue::from_str(&format!("Bearer {key}"))
                    .map_err(|_| anyhow::anyhow!("invalid egress API credential"))?;
                value.set_sensitive(true);
                Ok::<_, anyhow::Error>(value)
            })
            .transpose()?;
        Self::start_config(Config {
            origin,
            authorization,
            #[cfg(test)]
            client: None,
        })
        .await
    }

    async fn start_config(config: Config) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let config = Arc::new(config);
        let task = tokio::spawn(async move {
            let capacity = Arc::new(Semaphore::new(16));
            let mut workers = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((socket, _)) = accepted else { break };
                        let Ok(permit) = capacity.clone().try_acquire_owned() else { drop(socket); continue };
                        let config = config.clone();
                        workers.spawn(async move {
                            let _permit = permit;
                            let service = service_fn(move |request| {
                                let config = config.clone();
                                async move {
                                    let response = match timeout(DEADLINE, forward(request, &config)).await {
                                        Ok(response) => response,
                                        Err(_) => reply(StatusCode::GATEWAY_TIMEOUT, b"HTTPS origin deadline reached"),
                                    };
                                    Ok::<_, Infallible>(response)
                                }
                            });
                            // Bound header parsing, idle clients and request lifetimes too.
                            let _ = timeout(Duration::from_secs(20), http1::Builder::new()
                                .keep_alive(false).max_buf_size(16384)
                                .serve_connection(TokioIo::new(socket), service)).await;
                        });
                    }
                    _ = workers.join_next(), if !workers.is_empty() => {}
                }
            }
        });
        Ok(Self { address, task })
    }
    pub fn addr(&self) -> SocketAddr {
        self.address
    }
    pub async fn shutdown(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn reply(status: StatusCode, bytes: &'static [u8]) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Connection", "close")
        .body(Full::new(Bytes::from_static(bytes)))
        .expect("static response")
}

async fn forward(request: Request<Incoming>, config: &Config) -> Response<Full<Bytes>> {
    let method = request.method();
    if method != Method::GET && method != Method::POST {
        return reply(
            StatusCode::METHOD_NOT_ALLOWED,
            b"only GET and POST are supported",
        );
    }
    let path = request
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or_default();
    if request.uri().scheme().is_some()
        || request.uri().authority().is_some()
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.len() > 8192
        || request.headers().contains_key(TRANSFER_ENCODING)
        || request.headers().get_all(CONTENT_LENGTH).iter().count() > 1
        || (method == Method::POST && !request.headers().contains_key(CONTENT_LENGTH))
    {
        return reply(
            StatusCode::BAD_REQUEST,
            b"invalid egress request framing or target",
        );
    }
    if let Some(length) = request.headers().get(CONTENT_LENGTH) {
        match length.to_str().ok().and_then(|s| s.parse::<usize>().ok()) {
            Some(size) if size <= MAX_REQUEST => {}
            _ => return reply(StatusCode::PAYLOAD_TOO_LARGE, b"request exceeds limit"),
        }
    }
    let url = match Url::parse(&format!(
        "{}{}",
        config.origin.url.as_str().trim_end_matches('/'),
        path
    )) {
        Ok(url) if url.origin() == config.origin.url.origin() => url,
        _ => return reply(StatusCode::BAD_REQUEST, b"invalid egress target"),
    };
    let (parts, body) = request.into_parts();
    let body = match Limited::new(body, MAX_REQUEST).collect().await {
        Ok(body) => body.to_bytes(),
        Err(_) => {
            return reply(
                StatusCode::PAYLOAD_TOO_LARGE,
                b"invalid or oversized request body",
            );
        }
    };
    // Do not expose reqwest errors: they may contain private request URLs.
    match upstream(config, parts.method, &parts.headers, url, body).await {
        Ok(response) => response,
        Err(_) => reply(StatusCode::BAD_GATEWAY, b"HTTPS origin unavailable"),
    }
}

async fn pinned_client(config: &Config) -> Result<reqwest::Client> {
    #[cfg(test)]
    if let Some(client) = &config.client {
        return Ok(client.clone());
    }
    let addresses: Vec<_> = lookup_host((config.origin.host(), 443)).await?.collect();
    ensure!(
        !addresses.is_empty() && addresses.iter().all(|a| public_address(a.ip())),
        "nonpublic origin DNS answer"
    );
    Ok(reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(DEADLINE)
        .resolve_to_addrs(config.origin.host(), &addresses)
        .build()?)
}

async fn upstream(
    config: &Config,
    method: Method,
    headers: &reqwest::header::HeaderMap,
    url: Url,
    body: Bytes,
) -> Result<Response<Full<Bytes>>> {
    let client = pinned_client(config).await?;
    let mut request = client
        .request(method, url)
        .header("Accept", "application/json")
        .body(body);
    if let Some(kind) = headers
        .get(CONTENT_TYPE)
        .filter(|v| v.as_bytes().len() <= 128)
    {
        request = request.header(CONTENT_TYPE, kind);
    }
    if let Some(key) = &config.authorization {
        request = request.header(AUTHORIZATION, key);
    }
    let mut response = request.send().await?;
    let mut result = Response::builder()
        .status(response.status())
        .header("Connection", "close");
    if let Some(kind) = response
        .headers()
        .get(CONTENT_TYPE)
        .filter(|v| v.as_bytes().len() <= 128)
    {
        result = result.header(CONTENT_TYPE, kind);
    }
    ensure!(
        response
            .content_length()
            .is_none_or(|size| size <= MAX_RESPONSE as u64),
        "response exceeds limit"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= MAX_RESPONSE,
            "response exceeds limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(result.body(Full::new(Bytes::from(bytes)))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full};
    use hyper::{Response, body::Bytes, server::conn::http1, service::service_fn};
    use hyper_util::rt::TokioIo;
    use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
    use std::{convert::Infallible, sync::Arc};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn real_tls_post_injects_exit_key_not_client_credentials() -> Result<()> {
        let cert = rcgen::generate_simple_self_signed(vec!["origin.test".into()])?;
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let sender = Arc::new(std::sync::Mutex::new(Some(sender)));
        let fixture = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let stream = acceptor.accept(socket).await.unwrap();
            http1::Builder::new()
                .keep_alive(false)
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let sender = sender.clone();
                        async move {
                            let (parts, body) = req.into_parts();
                            let bytes = body.collect().await.unwrap().to_bytes();
                            sender
                                .lock()
                                .unwrap()
                                .take()
                                .unwrap()
                                .send((parts, bytes))
                                .unwrap();
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(201)
                                    .header(CONTENT_TYPE, "application/json")
                                    .body(Full::new(Bytes::from_static(b"{\"ok\":true}")))
                                    .unwrap(),
                            )
                        }
                    }),
                )
                .await
                .unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(reqwest::Certificate::from_der(cert.cert.der())?)
            .resolve_to_addrs("origin.test", &[address])
            .build()?;
        let gateway = Gateway::start_config(Config {
            origin: Origin {
                url: format!("https://origin.test:{}/", address.port()).parse()?,
                host: "origin.test".into(),
            },
            authorization: Some(HeaderValue::from_static("Bearer synthetic-node-only")),
            client: Some(client),
        })
        .await?;
        let response = reqwest::Client::builder()
            .no_proxy()
            .build()?
            .post(format!("http://{}/v1/responses?test=1", gateway.addr()))
            .header(AUTHORIZATION, "Bearer wrong-client-key")
            .header("Proxy-Authorization", "attacker")
            .header("X-Target", "http://localhost")
            .header(CONTENT_TYPE, "application/json")
            .body("{\"example\":1}")
            .send()
            .await?;
        assert_eq!(response.status(), 201);
        assert_eq!(response.text().await?, "{\"ok\":true}");
        let (parts, body) = receiver.await?;
        assert_eq!(parts.uri.to_string(), "/v1/responses?test=1");
        assert_eq!(body.as_ref(), b"{\"example\":1}");
        assert_eq!(parts.headers[AUTHORIZATION], "Bearer synthetic-node-only");
        assert!(!parts.headers.contains_key("Proxy-Authorization"));
        assert!(!parts.headers.contains_key("X-Target"));
        fixture.await?;
        gateway.shutdown().await;
        Ok(())
    }
}
