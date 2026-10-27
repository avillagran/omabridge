//! Outbound MCP Events webhooks: Standard Webhooks signatures and a callback
//! client that only reaches public HTTPS addresses.
//!
//! Every request resolves the callback host, rejects private, local and other
//! non-public addresses, then connects to the validated address while keeping
//! the original hostname for TLS. Redirects are never followed.
use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::{StatusCode, Url};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

/// Largest event request body ChatGPT accepts.
pub const MAX_EVENT_BODY: usize = 256 * 1024;
const MAX_URL: usize = 2048;
const MAX_REPLY: usize = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);

/// Which callback destinations are reachable. Production allows public HTTPS only;
/// `allow_loopback` exists for local tests and also permits plain http on loopback.
#[derive(Clone, Copy, Debug, Default)]
pub struct CallbackPolicy {
    pub allow_loopback: bool,
}

/// Why a callback could not be used, reported as `data.reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    AccessRevoked,
    InvalidUrl,
    BlockedAddress,
    Unresolvable,
    Timeout,
    Unreachable,
}

impl Refusal {
    pub fn reason(self) -> &'static str {
        match self {
            Self::AccessRevoked => "access_revoked",
            Self::InvalidUrl => "invalid_url",
            Self::BlockedAddress => "blocked_address",
            Self::Unresolvable => "dns_failure",
            Self::Timeout => "timeout",
            Self::Unreachable => "connection_failed",
        }
    }
}

/// Decodes a `whsec_` secret to its 24–64 byte key.
pub fn secret_key(secret: &str) -> Option<Vec<u8>> {
    let encoded = secret.strip_prefix("whsec_")?;
    let key = STANDARD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded))
        .ok()?;
    (24..=64).contains(&key.len()).then_some(key)
}

/// Standard Webhooks `v1,<base64 HMAC-SHA256("{id}.{timestamp}.{body}")>`, one per
/// secret, space separated (several during a secret rotation).
pub fn signature(secrets: &[&str], id: &str, timestamp: u64, body: &[u8]) -> String {
    let mut message = format!("{id}.{timestamp}.").into_bytes();
    message.extend_from_slice(body);
    secrets
        .iter()
        .filter_map(|secret| secret_key(secret))
        .map(|key| {
            format!(
                "v1,{}",
                STANDARD.encode(super::server::hmac(&key, &message))
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || a == 0
        || (a == 100 && (64..128).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (b == 18 || b == 19))
        || a >= 240)
}

fn public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return public_v4(v4);
    }
    let first = ip.segments()[0];
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
        || (first & 0xffc0) == 0xfec0
        || first == 0x2001 && ip.segments()[1] == 0x0db8
        || first == 0x0064 && ip.segments()[1] == 0xff9b
        || first == 0x2002)
}

/// Whether an address is a public unicast destination.
pub fn public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => public_v6(v6),
    }
}

/// Checks the shape of a callback URL: https, a host, no credentials or fragment.
pub fn callback_url(raw: &str, policy: CallbackPolicy) -> Result<Url, Refusal> {
    if raw.len() > MAX_URL {
        return Err(Refusal::InvalidUrl);
    }
    let url = Url::parse(raw).map_err(|_| Refusal::InvalidUrl)?;
    let loopback_http = policy.allow_loopback
        && url.scheme() == "http"
        && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    if (url.scheme() != "https" && !loopback_http)
        || url.host_str().is_none_or(str::is_empty)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Refusal::InvalidUrl);
    }
    Ok(url)
}

pub(crate) async fn destination(url: &Url, policy: CallbackPolicy) -> Result<SocketAddr, Refusal> {
    let host = url.host_str().ok_or(Refusal::InvalidUrl)?;
    let port = url.port_or_known_default().ok_or(Refusal::InvalidUrl)?;
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let addresses: Vec<SocketAddr> = match bare.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => tokio::time::timeout(TIMEOUT, tokio::net::lookup_host((bare, port)))
            .await
            .map_err(|_| Refusal::Timeout)?
            .map_err(|_| Refusal::Unresolvable)?
            .collect(),
    };
    if addresses.is_empty() {
        return Err(Refusal::Unresolvable);
    }
    addresses
        .into_iter()
        .find(|a| public_address(a.ip()) || (policy.allow_loopback && a.ip().is_loopback()))
        .ok_or(Refusal::BlockedAddress)
}

/// Result of one POST to a callback.
pub struct Delivered {
    pub status: StatusCode,
    pub body: Vec<u8>,
}

/// POSTs signed JSON to a callback, pinned to an address validated just before
/// connecting. The body is sent exactly as given (it is what was signed).
pub async fn post(
    url: &Url,
    policy: CallbackPolicy,
    headers: &[(&str, String)],
    body: Vec<u8>,
) -> Result<Delivered, Refusal> {
    post_checked(url, policy, headers, body, || true).await
}

/// Recheck authorization after DNS resolution, immediately before sending bytes.
pub async fn post_checked(
    url: &Url,
    policy: CallbackPolicy,
    headers: &[(&str, String)],
    body: Vec<u8>,
    authorized: impl FnOnce() -> bool,
) -> Result<Delivered, Refusal> {
    let address = destination(url, policy).await?;
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(TIMEOUT)
        .timeout(TIMEOUT)
        .https_only(!policy.allow_loopback);
    if let Some(host) = url.host_str().filter(|h| h.parse::<IpAddr>().is_err()) {
        builder = builder.resolve(host, address);
    }
    let client = builder.build().map_err(|_| Refusal::Unreachable)?;
    let mut request = client
        .post(url.clone())
        .header("content-type", "application/json")
        .body(body);
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    if !authorized() {
        return Err(Refusal::AccessRevoked);
    }
    let mut response = request.send().await.map_err(|error| {
        if error.is_timeout() {
            Refusal::Timeout
        } else {
            Refusal::Unreachable
        }
    })?;
    let status = response.status();
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = response.chunk().await {
        if body.len() + chunk.len() > MAX_REPLY {
            break;
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Delivered { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_webhooks_reference_signature() {
        // Test vector from the Standard Webhooks specification libraries.
        let secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
        let body = br#"{"test": 2432232314}"#;
        assert_eq!(
            signature(&[secret], "msg_p5jXN8AQM9LWM0D4loKWxJek", 1614265330, body),
            "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
        );
    }

    #[test]
    fn secrets_must_decode_to_24_to_64_bytes() {
        assert!(secret_key("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").is_some());
        assert!(secret_key(&format!("whsec_{}", STANDARD.encode([1u8; 16]))).is_none());
        assert!(secret_key(&format!("whsec_{}", STANDARD.encode([1u8; 65]))).is_none());
        assert!(secret_key(&STANDARD.encode([1u8; 32])).is_none());
    }

    #[test]
    fn only_public_addresses_are_reachable() {
        for blocked in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!public_address(blocked.parse().unwrap()), "{blocked}");
        }
        for allowed in ["1.1.1.1", "104.18.0.1", "2606:4700::1111"] {
            assert!(public_address(allowed.parse().unwrap()), "{allowed}");
        }
    }

    #[test]
    fn callback_urls_must_be_https() {
        let strict = CallbackPolicy::default();
        assert!(callback_url("https://hooks.example.com/cb", strict).is_ok());
        for bad in [
            "http://hooks.example.com/cb",
            "https://user:pw@hooks.example.com/cb",
            "https://hooks.example.com/cb#x",
            "ftp://hooks.example.com",
            "http://127.0.0.1:9/cb",
        ] {
            assert_eq!(
                callback_url(bad, strict).err(),
                Some(Refusal::InvalidUrl),
                "{bad}"
            );
        }
        let test = CallbackPolicy {
            allow_loopback: true,
        };
        assert!(callback_url("http://127.0.0.1:9/cb", test).is_ok());
    }

    #[tokio::test]
    async fn literal_private_destinations_are_refused() {
        let url = Url::parse("https://10.0.0.1/cb").unwrap();
        assert_eq!(
            destination(&url, CallbackPolicy::default()).await.err(),
            Some(Refusal::BlockedAddress)
        );
        let url = Url::parse("https://[::1]/cb").unwrap();
        assert_eq!(
            destination(&url, CallbackPolicy::default()).await.err(),
            Some(Refusal::BlockedAddress)
        );
    }
}
