use iroh::{Endpoint, EndpointAddr, RelayMode, endpoint::presets};
use omabridge::{NetOptions, Node, Store, hosting, relay::RelayServer};
use std::{collections::BTreeMap, os::unix::fs::PermissionsExt, path::Path, time::Duration};

fn certificate(
    dir: &Path,
    names: &[&str],
) -> anyhow::Result<(
    rcgen::CertifiedKey<rcgen::KeyPair>,
    std::path::PathBuf,
    std::path::PathBuf,
)> {
    let cert = rcgen::generate_simple_self_signed(
        names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>(),
    )?;
    let (cert_path, key_path) = (dir.join("fullchain.pem"), dir.join("privkey.pem"));
    std::fs::write(&cert_path, cert.cert.pem())?;
    std::fs::write(&key_path, cert.signing_key.serialize_pem())?;
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    Ok((cert, cert_path, key_path))
}

#[test]
fn hosted_relay_configuration_needs_a_matching_certificate() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let (_, cert, key) = certificate(
        dir.path(),
        &["relay.example.net", "*.example.net", "127.0.0.1"],
    )?;
    assert_eq!(
        hosting::certificate_names(&cert),
        ["relay.example.net"],
        "concrete DNS names only"
    );
    let config = hosting::config_for("https://relay.example.net:3341", &cert, &key)?;
    assert_eq!(config.url, "https://relay.example.net:3341/");
    assert_eq!(config.listen, "0.0.0.0:3341".parse()?);
    assert_eq!(
        hosting::config_for("https://relay.example.net", &cert, &key)?
            .listen
            .port(),
        443
    );
    assert!(
        hosting::config_for("https://other.example.net:3341", &cert, &key).is_ok(),
        "the wildcard covers it"
    );
    assert!(hosting::config_for("https://deep.other.example.net:3341", &cert, &key).is_err());
    assert!(hosting::config_for("https://relay.example.org:3341", &cert, &key).is_err());
    assert!(hosting::config_for("http://relay.example.net:3341", &cert, &key).is_err());
    Ok(())
}

/// A relay hosted by a device admits it and the devices paired with it, and
/// nobody else; pairing later admits the new device without a restart.
#[tokio::test]
async fn hosted_relay_admits_only_paired_devices() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        let dir = tempfile::tempdir()?;
        let (cert, cert_path, key_path) = certificate(dir.path(), &["127.0.0.1"])?;
        let host = Store::open(&dir.path().join("host"), "host")?;
        let guest = Store::open(&dir.path().join("guest"), "guest")?;
        let server =
            RelayServer::start_hosted("127.0.0.1:0".parse()?, host.clone(), &cert_path, &key_path)
                .await?;
        let url: iroh::RelayUrl = format!("https://{}", server.https_addr().unwrap()).parse()?;
        let endpoint = |key: iroh::SecretKey, alpn: bool| {
            let mut builder = Endpoint::builder(presets::Minimal)
                .secret_key(key)
                .clear_ip_transports()
                .clear_address_lookup()
                .ca_tls_config(iroh_relay::tls::CaTlsConfig::custom_roots([cert
                    .cert
                    .der()
                    .clone()]))
                .relay_mode(RelayMode::Custom(url.clone().into()));
            if alpn {
                builder = builder.alpns(vec![b"hosted".to_vec()]);
            }
            builder.bind()
        };
        let host_end = endpoint(host.secret_key()?, true).await?;
        let accepting = host_end.clone();
        tokio::spawn(async move {
            while let Some(incoming) = accepting.accept().await {
                if let Ok(connection) = incoming.await {
                    let _ = connection.closed().await;
                }
            }
        });
        let target = EndpointAddr::new(host_end.id()).with_relay_url(url.clone());
        let attempt = |end: Endpoint| {
            let target = target.clone();
            async move {
                let ok = matches!(
                    tokio::time::timeout(Duration::from_secs(3), end.connect(target, b"hosted"))
                        .await,
                    Ok(Ok(_))
                );
                end.close().await;
                ok
            }
        };
        assert!(
            !attempt(endpoint(guest.secret_key()?, false).await?).await,
            "unpaired devices are refused"
        );
        // Pairing is all it takes.
        let now = omabridge::unix_time()?;
        let token = host.create_invite(&["t3".into()], Duration::from_secs(60), now)?;
        host.claim(&token, &guest.id()?, "guest", now)?;
        host.approve(&guest.id()?, now)?;
        assert!(
            attempt(endpoint(guest.secret_key()?, false).await?).await,
            "paired devices are admitted"
        );
        host_end.close().await;
        server.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

/// The running server starts the relay when asked and stops it when asked.
#[tokio::test]
async fn the_server_hosts_the_configured_relay() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir = tempfile::tempdir()?;
        let (_, cert, key) = certificate(dir.path(), &["127.0.0.1"])?;
        let host = Store::open(&dir.path().join("host"), "host")?;
        let socket = std::net::TcpListener::bind("127.0.0.1:0")?;
        let node = Node::start(
            host.clone(),
            BTreeMap::from([("ssh".into(), socket.local_addr()?)]),
            NetOptions::loopback(),
        )
        .await?;
        let port = std::net::TcpListener::bind("127.0.0.1:0")?
            .local_addr()?
            .port();
        let config = hosting::HostConfig {
            url: format!("https://127.0.0.1:{port}/"),
            listen: format!("127.0.0.1:{port}").parse()?,
            cert,
            key,
        };
        hosting::save(host.root(), Some(&config))?;
        while !hosting::status(host.root()).running {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok(),
            "listening"
        );
        hosting::save(host.root(), None)?;
        while hosting::status(host.root()).running {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        node.shutdown().await;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[test]
fn wildcard_names_cover_exactly_one_label() {
    assert!(hosting::covers(
        "*.vpn.example.net",
        "laptop.vpn.example.net"
    ));
    assert!(!hosting::covers("*.vpn.example.net", "vpn.example.net"));
    assert!(!hosting::covers(
        "*.vpn.example.net",
        "a.laptop.vpn.example.net"
    ));
    assert!(!hosting::covers("*.vpn.example.net", "evilvpn.example.net"));
    assert!(hosting::covers("relay.example.net", "relay.example.net"));
    assert!(!hosting::covers("relay.example.net", "x.relay.example.net"));
    for good in ["laptop.vpn.example.net", "node-1.example.net"] {
        assert!(hosting::valid_host(good), "{good}");
    }
    for bad in [
        "localhost",
        "-a.example.net",
        "a..example.net",
        "A.example.net",
        "a b.example.net",
        "a.example.net/x",
    ] {
        assert!(!hosting::valid_host(bad), "{bad}");
    }
}
