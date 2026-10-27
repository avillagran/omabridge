//! Enrollment is supplied by a T3 authority, never inferred from discovery.
//! Production nodes default to no authority (Denied). Embedders must implement
//! issuance/revocation at their existing T3 server, not mint bridge-only tokens.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin};

/// A short-lived, per-client/environment bootstrap credential issued by T3.
/// Not Debug: neither receipts nor errors may print credentials.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Enrollment {
    pub environment_id: String,
    pub client_id: String,
    #[serde(default)]
    pub pairing_secret: String,
    /// A session issued by T3's existing scoped CLI, not a desktop credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
    pub expires_at: u64,
    pub scopes: Vec<String>,
}
impl Enrollment {
    pub fn validate(&self, client: &str, environment: &str, now: u64) -> Result<()> {
        ensure!(
            self.client_id == client && self.environment_id == environment,
            "enrollment identity mismatch"
        );
        ensure!(
            self.scopes == ["orchestration:read"]
                && self.expires_at > now
                && self.expires_at <= now.saturating_add(300_000),
            "enrollment must be bounded read-only"
        );
        ensure!(
            self.session_token
                .as_ref()
                .map_or(!self.pairing_secret.is_empty(), |_| self
                    .pairing_secret
                    .is_empty()),
            "exactly one credential required"
        );
        let credential = self
            .session_token
            .as_deref()
            .unwrap_or(&self.pairing_secret);
        ensure!(
            !credential.is_empty()
                && credential.len() <= 4096
                && !credential.chars().any(char::is_whitespace),
            "invalid enrollment"
        );
        Ok(())
    }
}
/// The authority MUST enforce this identity, read-only scope, <=5 minute session
/// lifetime in T3 itself. Bridge withdrawal stops issuance, not existing bearers.
/// An envelope declaration is not enforcement. Nodes deny by default; operators
/// must explicitly configure an authority.
pub trait EnrollmentAuthority: Send + Sync {
    /// Delegation is a separate, explicit capability; ordinary authorities deny it.
    fn issue_delegated<'a>(
        &'a self,
        _upstream: &'a str,
        _client: &'a str,
        _environment: &'a str,
        _now: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Enrollment>> + Send + 'a>> {
        Box::pin(async { anyhow::bail!("delegation unavailable") })
    }
    fn issue<'a>(
        &'a self,
        client: &'a str,
        environment: &'a str,
        now: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Enrollment>> + Send + 'a>>;
}

/// Redeem only the native manager's selected, descriptor-verified portable route.
/// T3 enforces the resulting token; the bridge never creates an accepted bearer.
pub fn redeem(enrollment: &Enrollment, url: &str, now: u64) -> Result<serde_json::Value> {
    redeem_with_http(enrollment, url, now, None)
}

/// A caller may supply a TLS client with additional explicit trust anchors.
/// Descriptor, scope and expiration validation remain mandatory.
pub fn redeem_with_http(
    enrollment: &Enrollment,
    url: &str,
    now: u64,
    http: Option<reqwest012::blocking::Client>,
) -> Result<serde_json::Value> {
    let started = std::time::Instant::now();
    redeem_with_http_clock(enrollment, url, now, http, || {
        let elapsed = u64::try_from(started.elapsed().as_millis())?;
        Ok(now.saturating_add(elapsed))
    })
}

fn redeem_with_http_clock(
    enrollment: &Enrollment,
    url: &str,
    now: u64,
    http: Option<reqwest012::blocking::Client>,
    mut clock: impl FnMut() -> Result<u64>,
) -> Result<serde_json::Value> {
    enrollment.validate(&enrollment.client_id, &enrollment.environment_id, now)?;
    if let Some(token) = &enrollment.session_token {
        let http = match http {
            Some(http) => http,
            None => t3_protocol::ConnectionOptions::default()
                .build_http_client()
                .map_err(anyhow::Error::msg)?,
        };
        let descriptor: serde_json::Value = http
            .get(format!(
                "{}/.well-known/t3/environment",
                url.trim_end_matches('/')
            ))
            .send()?
            .error_for_status()?
            .json()?;
        ensure!(
            descriptor["environmentId"] == enrollment.environment_id,
            "descriptor identity mismatch"
        );
        enrollment.validate(&enrollment.client_id, &enrollment.environment_id, clock()?)?;
        let connection = t3_protocol::Connection::with_http_client(
            http,
            url,
            None,
            t3_protocol::Credential::bearer(token).map_err(anyhow::Error::msg)?,
        )
        .map_err(anyhow::Error::msg)?;
        let session = connection
            .request_json("GET", "/api/auth/session", None, false)
            .map_err(anyhow::Error::msg)?;
        let expiry = parse_expiry(&session["expiresAt"])?;
        let received_at = clock()?;
        enrollment.validate(
            &enrollment.client_id,
            &enrollment.environment_id,
            received_at,
        )?;
        ensure!(
            session["authenticated"] == true
                && session["scopes"] == serde_json::json!(["orchestration:read"])
                && expiry > received_at
                && expiry <= enrollment.expires_at,
            "authority session is not bounded read-only"
        );
        return Ok(
            serde_json::json!({"accessToken":token,"environmentId":enrollment.environment_id,
            "expiresAt":expiry,"scope":"orchestration:read"}),
        );
    }
    let paired = t3_protocol::pair_bearer(
        url,
        &enrollment.pairing_secret,
        Some(&enrollment.environment_id),
        &t3_protocol::PairingClient::default()
            .with_label(&format!("OmaBridge {}", enrollment.client_id))
            .with_device_type("mobile")
            .with_os("android"),
        &t3_protocol::ConnectionOptions::default(),
    )
    .map_err(anyhow::Error::msg)?;
    let received_at = clock()?;
    enrollment.validate(
        &enrollment.client_id,
        &enrollment.environment_id,
        received_at,
    )?;
    ensure!(
        paired.scope.split_whitespace().collect::<Vec<_>>() == ["orchestration:read"],
        "authority returned excessive scopes"
    );
    let ttl = paired
        .expires_in
        .filter(|n| *n > 0 && *n <= 300)
        .context("authority returned unbounded session")? as u64;
    // Anchor a relative TTL before the request: response latency must never
    // extend the session's local lifetime.
    let expiry = now
        .checked_add(ttl * 1000)
        .context("invalid session expiry")?;
    ensure!(
        expiry > received_at && expiry <= enrollment.expires_at,
        "authority session exceeds enrollment"
    );
    Ok(
        serde_json::json!({"accessToken":paired.access_token.as_str(),"environmentId":paired.environment_id,"expiresAt":expiry,"scope":paired.scope}),
    )
}

fn parse_expiry(value: &serde_json::Value) -> Result<u64> {
    let text = value.as_str().context("missing session expiry")?;
    let parsed = time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
        .context("invalid session expiry")?;
    u64::try_from(parsed.unix_timestamp_nanos() / 1_000_000).context("invalid session expiry")
}

/// Explicit local operator consent: each configured UUID names an owned T3 base
/// directory and its descriptor route. There is no default authority or token cache.
/// Remote hosts need their own issuer; no desktop bearer is imported here.
#[derive(Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LocalT3Authority {
    pub t3_binary: std::path::PathBuf,
    pub environments: std::collections::BTreeMap<String, LocalT3Environment>,
    #[serde(default = "session_ttl")]
    pub ttl_seconds: u64,
}
fn session_ttl() -> u64 {
    120
}
#[derive(Deserialize, PartialEq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LocalT3Environment {
    pub base_dir: std::path::PathBuf,
    pub descriptor_url: String,
}
impl LocalT3Authority {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.t3_binary.is_absolute() && self.t3_binary.is_file(),
            "absolute T3 binary required"
        );
        ensure!(
            (1..=240).contains(&self.ttl_seconds),
            "session TTL must be 1..240 seconds"
        );
        for environment in self.environments.values() {
            ensure!(
                environment.base_dir.is_absolute() && environment.base_dir.is_dir(),
                "existing owned T3 directory required"
            );
            let url = reqwest::Url::parse(&environment.descriptor_url)?;
            ensure!(
                url.scheme() == "http"
                    && url.host_str().is_some_and(|h| h
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback()))
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.path() == "/"
                    && url.query().is_none()
                    && url.fragment().is_none(),
                "local authority descriptor must use literal loopback"
            );
        }
        Ok(())
    }
}
impl EnrollmentAuthority for LocalT3Authority {
    fn issue<'a>(
        &'a self,
        client: &'a str,
        environment: &'a str,
        now: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Enrollment>> + Send + 'a>> {
        Box::pin(async move {
            self.validate()?;
            let selected = self
                .environments
                .get(environment)
                .context("environment has no local issuer")?;
            let url = selected.descriptor_url.clone();
            let expected = environment.to_owned();
            tokio::task::spawn_blocking(move || {
                t3_protocol::verify_environment(&url, &expected, &Default::default())
            })
            .await?
            .map_err(anyhow::Error::msg)?;
            let output = tokio::time::timeout(
                std::time::Duration::from_secs(12),
                tokio::process::Command::new(&self.t3_binary)
                    .args(["auth", "session", "issue", "--base-dir"])
                    .arg(&selected.base_dir)
                    .args([
                        "--scope",
                        "orchestration:read",
                        "--ttl",
                        &format!("{}s", self.ttl_seconds),
                        "--subject",
                        &format!("omabridge:{client}"),
                        "--label",
                        &format!("OmaBridge {client}"),
                        "--json",
                    ])
                    .stdin(std::process::Stdio::null())
                    .kill_on_drop(true)
                    .output(),
            )
            .await??;
            ensure!(output.status.success(), "T3 session issuance failed");
            // Never format Output, stderr, or JSON in an error: all can contain credentials.
            let result: serde_json::Value =
                serde_json::from_slice(&output.stdout).context("invalid T3 issuance receipt")?;
            let expires_at = parse_expiry(&result["expiresAt"])?;
            ensure!(
                result["scopes"] == serde_json::json!(["orchestration:read"])
                    && result["subject"] == format!("omabridge:{client}"),
                "T3 issuance grant mismatch"
            );
            let enrollment = Enrollment {
                environment_id: environment.into(),
                client_id: client.into(),
                pairing_secret: String::new(),
                session_token: Some(
                    result["token"]
                        .as_str()
                        .context("missing T3 session")?
                        .into(),
                ),
                expires_at,
                scopes: vec!["orchestration:read".into()],
            };
            enrollment.validate(client, environment, now)?;
            Ok(enrollment)
        })
    }
}

#[cfg(test)]
mod receipt_clock_tests {
    use super::*;
    use serde_json::json;
    use std::io::{Read, Write};

    fn session_case(
        enrollment_expiry: u64,
        session_expiry: &str,
        ticks: &[u64],
        requests: usize,
    ) -> Result<serde_json::Value> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let url = format!("http://{}", listener.local_addr()?);
        let session_expiry = session_expiry.to_owned();
        let server = std::thread::spawn(move || {
            for index in 0..requests {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                    .unwrap();
                let mut request = Vec::new();
                let mut byte = [0; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    socket.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                }
                let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
                if index == 0 {
                    assert!(request.starts_with("get /.well-known/t3/environment "));
                    assert!(!request.contains("authorization:"));
                } else {
                    assert!(request.starts_with("get /api/auth/session "));
                    assert!(request.contains("authorization: bearer fixture-session-only"));
                }
                let body = if index == 0 { json!({"environmentId":"fixture-env"}) }
                    else { json!({"authenticated":true,"scopes":["orchestration:read"],"expiresAt":session_expiry}) }.to_string();
                write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(),body).unwrap();
            }
        });
        let enrollment = Enrollment {
            environment_id: "fixture-env".into(),
            client_id: "fixture-client".into(),
            pairing_secret: String::new(),
            session_token: Some("fixture-session-only".into()),
            expires_at: enrollment_expiry,
            scopes: vec!["orchestration:read".into()],
        };
        let mut ticks = ticks.iter().copied();
        let result = redeem_with_http_clock(&enrollment, &url, 1_000, None, || {
            Ok(ticks.next().expect("unexpected clock read"))
        });
        server.join().unwrap();
        result
    }

    #[test]
    fn session_expiring_during_response_is_rejected() {
        let error =
            session_case(2_500, "1970-01-01T00:00:01.900Z", &[1_500, 2_000], 2).unwrap_err();
        assert_eq!(
            error.to_string(),
            "authority session is not bounded read-only"
        );
    }
    #[test]
    fn enrollment_expiring_during_response_is_rejected() {
        let error =
            session_case(2_000, "1970-01-01T00:00:01.900Z", &[1_500, 2_000], 2).unwrap_err();
        assert_eq!(error.to_string(), "enrollment must be bounded read-only");
    }
    #[test]
    fn expired_after_descriptor_never_sends_credential() {
        let error = session_case(2_000, "1970-01-01T00:00:01.900Z", &[2_000], 1).unwrap_err();
        assert_eq!(error.to_string(), "enrollment must be bounded read-only");
    }
    #[test]
    fn valid_response_keeps_original_absolute_expiry() {
        let receipt = session_case(2_500, "1970-01-01T00:00:02.400Z", &[1_500, 2_000], 2).unwrap();
        assert_eq!(receipt["expiresAt"], 2_400);
    }
}
