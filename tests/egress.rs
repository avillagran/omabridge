use omabridge::egress::Gateway;
use omabridge::egress::Origin;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn untrusted_http_targets_and_framing_are_rejected_before_dns() -> anyhow::Result<()> {
    let gateway = Gateway::start(Origin::parse("https://origin.invalid")?, None).await?;
    for (request, expected) in [
        (
            "GET http://elsewhere.example/ HTTP/1.1\r\nHost: ignored\r\n\r\n",
            "400",
        ),
        (
            "GET //elsewhere.example/ HTTP/1.1\r\nHost: ignored\r\n\r\n",
            "400",
        ),
        (
            "POST / HTTP/1.1\r\nHost: ignored\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "400",
        ),
        (
            "POST / HTTP/1.1\r\nHost: ignored\r\nContent-Length: 1048577\r\n\r\n",
            "413",
        ),
        ("POST / HTTP/1.1\r\nHost: ignored\r\n\r\n", "400"),
        (
            "CONNECT elsewhere.example:443 HTTP/1.1\r\nHost: ignored\r\n\r\n",
            "405",
        ),
    ] {
        let mut socket = tokio::net::TcpStream::connect(gateway.addr()).await?;
        socket.write_all(request.as_bytes()).await?;
        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            socket.read_to_end(&mut response),
        )
        .await??;
        assert!(String::from_utf8_lossy(&response).starts_with(&format!("HTTP/1.1 {expected}")));
    }
    let address = gateway.addr();
    gateway.shutdown().await;
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
    Ok(())
}

#[test]
fn dns_answers_must_exclude_private_special_and_translation_ranges() {
    for denied in [
        "127.0.0.1",
        "10.0.0.1",
        "100.64.0.1",
        "192.0.2.1",
        "192.168.1.1",
        "198.18.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "::1",
        "::ffff:8.8.8.8",
        "64:ff9b::a00:1",
        "fc00::1",
        "fe80::1",
        "2001:db8::1",
        "2002:a00:1::1",
    ] {
        assert!(
            !omabridge::egress::public_address(denied.parse().unwrap()),
            "accepted {denied}"
        );
    }
    for allowed in [
        "8.8.8.8",
        "1.1.1.1",
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
    ] {
        assert!(omabridge::egress::public_address(allowed.parse().unwrap()));
    }
}

#[test]
fn origin_is_one_public_https_dns_name_not_a_client_selected_destination() {
    for invalid in [
        "http://api.example.com",
        "https://127.0.0.1",
        "https://[::1]",
        "https://localhost",
        "https://user:pass@api.example.com",
        "https://api.example.com:444",
        "https://api.example.com/path",
        "https://api.example.com?redirect=elsewhere",
        "https://api.example.com#fragment",
    ] {
        assert!(Origin::parse(invalid).is_err(), "accepted {invalid}");
    }
    assert_eq!(
        Origin::parse("https://api.example.com/").unwrap().host(),
        "api.example.com"
    );
}
