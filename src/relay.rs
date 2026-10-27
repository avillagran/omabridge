//! Embedded iroh relay with mandatory cryptographic peer allowlisting.
use anyhow::{Context, Result, ensure};
use iroh::EndpointId;
use iroh_relay::server::{
    Access, AccessControl, CertConfig, ClientRateLimit, ClientRequest, RelayConfig, Server,
    ServerConfig, TlsConfig,
};
use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io::{BufReader, Read},
    net::SocketAddr,
    num::NonZeroU32,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::Arc,
};

#[derive(Debug)]
struct AllowedPeers(BTreeSet<EndpointId>);
impl AccessControl for AllowedPeers {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        if self.0.contains(&request.endpoint_id()) {
            Access::Allow
        } else {
            Access::Deny {
                reason: Some("peer not allowed".into()),
            }
        }
    }
}

/// A relay hosted by a device's own server admits that device and the devices
/// paired with it, read from its state at every connection.
#[derive(Debug)]
struct PairedDevices {
    store: crate::Store,
    own: EndpointId,
}
impl AccessControl for PairedDevices {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let id = request.endpoint_id();
        let paired = self
            .store
            .peers()
            .is_ok_and(|peers| peers.iter().any(|peer| peer.id == id.to_string()));
        if id == self.own || paired {
            Access::Allow
        } else {
            Access::Deny {
                reason: Some("device not paired with this relay".into()),
            }
        }
    }
}

pub struct RelayServer {
    server: Server,
}

impl RelayServer {
    /// Plaintext is loopback-only for an explicitly managed TLS reverse proxy.
    /// Non-loopback listeners require a certificate chain and private key.
    pub async fn start(
        listen: SocketAddr,
        peers: Vec<EndpointId>,
        tls: Option<(&Path, &Path)>,
    ) -> Result<Self> {
        ensure!(
            !peers.is_empty() && peers.len() <= 256,
            "relay requires 1..256 explicitly allowed peers"
        );
        ensure!(
            listen.ip().is_loopback() || tls.is_some(),
            "public relay listener requires TLS"
        );
        let mut config = RelayConfig::new(if tls.is_some() {
            "127.0.0.1:0".parse()?
        } else {
            listen
        });
        config.access = Arc::new(AllowedPeers(peers.into_iter().collect()));
        config.limits.client_rx = Some(ClientRateLimit::new(NonZeroU32::new(1024 * 1024).unwrap()));
        if let Some((cert, key)) = tls {
            config.tls = Some(TlsConfig::new(
                listen,
                CertConfig::Manual {
                    server_config: tls_config(cert, key)?,
                },
            ));
        }
        let mut server_config = ServerConfig::default();
        server_config.relay = Some(config);
        Ok(Self {
            server: Server::spawn(server_config).await?,
        })
    }
    /// Hosted by a device's server for the devices paired with it. The
    /// certificate paths may be symlinks (as Let's Encrypt's `live` ones are);
    /// they are resolved first.
    pub async fn start_hosted(
        listen: SocketAddr,
        store: crate::Store,
        cert: &Path,
        key: &Path,
    ) -> Result<Self> {
        let own: EndpointId = store.id()?.parse()?;
        let mut config = RelayConfig::new("127.0.0.1:0".parse::<SocketAddr>()?);
        config.access = Arc::new(PairedDevices { store, own });
        config.limits.client_rx = Some(ClientRateLimit::new(NonZeroU32::new(1024 * 1024).unwrap()));
        config.tls = Some(TlsConfig::new(
            listen,
            CertConfig::Manual {
                server_config: tls_config(
                    &std::fs::canonicalize(cert)?,
                    &std::fs::canonicalize(key)?,
                )?,
            },
        ));
        let mut server_config = ServerConfig::default();
        server_config.relay = Some(config);
        Ok(Self {
            server: Server::spawn(server_config).await?,
        })
    }
    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.server.http_addr()
    }
    pub fn https_addr(&self) -> Option<SocketAddr> {
        self.server.https_addr()
    }
    pub async fn join(&mut self) -> Result<()> {
        self.server.join().await??;
        Ok(())
    }
    pub async fn shutdown(self) -> Result<()> {
        self.server.shutdown().await?;
        Ok(())
    }
}

fn bounded_pem(path: &Path, private: bool) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .context("cannot open relay TLS file")?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.len() <= 1024 * 1024,
        "relay TLS files must be bounded regular files"
    );
    ensure!(
        !private || meta.permissions().mode() & 0o077 == 0,
        "relay TLS private key must have private permissions (0600)"
    );
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 1024 * 1024, "relay TLS file exceeds limit");
    Ok(bytes)
}

/// A certificate chain and its key, for picking certificates by requested name.
pub(crate) fn certified_key(cert: &Path, key: &Path) -> Result<Arc<rustls::sign::CertifiedKey>> {
    let certificates =
        rustls_pemfile::certs(&mut BufReader::new(bounded_pem(cert, false)?.as_slice()))
            .collect::<std::io::Result<Vec<_>>>()
            .context("invalid certificate chain")?;
    ensure!(!certificates.is_empty(), "empty certificate chain");
    let key = rustls_pemfile::private_key(&mut BufReader::new(bounded_pem(key, true)?.as_slice()))?
        .context("private key missing")?;
    let signing =
        rustls::crypto::ring::sign::any_supported_type(&key).context("unsupported private key")?;
    Ok(Arc::new(rustls::sign::CertifiedKey::new(
        certificates,
        signing,
    )))
}

pub(crate) fn tls_config(cert: &Path, key: &Path) -> Result<rustls::ServerConfig> {
    let certificates =
        rustls_pemfile::certs(&mut BufReader::new(bounded_pem(cert, false)?.as_slice()))
            .collect::<std::io::Result<Vec<_>>>()
            .context("invalid relay certificate chain")?;
    ensure!(!certificates.is_empty(), "empty relay certificate chain");
    let key = rustls_pemfile::private_key(&mut BufReader::new(bounded_pem(key, true)?.as_slice()))?
        .context("relay private key missing")?;
    rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .context("relay certificate/key mismatch")
}
