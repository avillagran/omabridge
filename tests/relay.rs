use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, endpoint::presets};
use omabridge::relay::RelayServer;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

#[tokio::test]
async fn relay_is_never_open_or_public_plaintext_by_default() {
    let peer = SecretKey::generate().public();
    assert!(
        RelayServer::start("127.0.0.1:0".parse().unwrap(), vec![], None)
            .await
            .is_err()
    );
    assert!(
        RelayServer::start("0.0.0.0:0".parse().unwrap(), vec![peer], None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn embedded_relay_carries_real_quic_with_ip_transports_disabled() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let a_key = SecretKey::generate();
        let b_key = SecretKey::generate();
        let dir = tempfile::tempdir()?;
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()])?;
        let cert_path = dir.path().join("test-cert.pem");
        let key_path = dir.path().join("test-key.pem");
        std::fs::write(&cert_path, cert.cert.pem())?;
        std::fs::write(&key_path, cert.signing_key.serialize_pem())?;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
        let server = RelayServer::start(
            "127.0.0.1:0".parse()?,
            vec![a_key.public(), b_key.public()],
            Some((&cert_path, &key_path)),
        )
        .await?;
        let url: iroh::RelayUrl = format!("https://{}", server.https_addr().unwrap()).parse()?;
        let mut peers = Vec::new();
        for key in [a_key, b_key] {
            peers.push(
                Endpoint::builder(presets::Minimal)
                    .secret_key(key)
                    .clear_ip_transports()
                    .clear_address_lookup()
                    .ca_tls_config(iroh_relay::tls::CaTlsConfig::custom_roots([cert
                        .cert
                        .der()
                        .clone()]))
                    .relay_mode(RelayMode::Custom(url.clone().into()))
                    .alpns(vec![b"omabridge-relay-test".to_vec()])
                    .bind()
                    .await?,
            );
        }
        let b = peers[1].clone();
        let echo = tokio::spawn(async move {
            let connection = b.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let bytes = recv.read_to_end(128).await.unwrap();
            send.write_all(&bytes).await.unwrap();
            send.finish().unwrap();
            send.stopped().await.unwrap();
        });
        let connection = peers[0]
            .connect(
                EndpointAddr::new(peers[1].id()).with_relay_url(url.clone()),
                b"omabridge-relay-test",
            )
            .await?;
        let (mut send, mut recv) = connection.open_bi().await?;
        send.write_all(b"own relay, same Rust binary").await?;
        send.finish()?;
        assert_eq!(recv.read_to_end(128).await?, b"own relay, same Rust binary");
        echo.await?;
        let outsider = Endpoint::builder(presets::Minimal)
            .clear_ip_transports()
            .clear_address_lookup()
            .ca_tls_config(iroh_relay::tls::CaTlsConfig::custom_roots([cert
                .cert
                .der()
                .clone()]))
            .relay_mode(RelayMode::Custom(url.clone().into()))
            .bind()
            .await?;
        let denied = tokio::time::timeout(
            Duration::from_secs(2),
            outsider.connect(
                EndpointAddr::new(peers[1].id()).with_relay_url(url),
                b"omabridge-relay-test",
            ),
        )
        .await;
        assert!(!matches!(denied, Ok(Ok(_))), "unlisted peer admitted");
        outsider.close().await;
        for peer in peers {
            peer.close().await;
        }
        server.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}
