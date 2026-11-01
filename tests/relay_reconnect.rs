//! Loopback dev relay only; addresses deliberately exclude all direct candidates.
use anyhow::Result;
use iroh::EndpointAddr;
use iroh_relay::server::{RelayConfig, Server, ServerConfig};
use omabridge::{Client, NetOptions, Node, Relay, Store};
use std::{collections::BTreeMap, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
async fn relay(bind: std::net::SocketAddr) -> Result<Server> {
    let mut config = ServerConfig::default();
    config.relay = Some(RelayConfig::new(bind));
    Server::spawn(config).await.map_err(Into::into)
}
async fn cycles(count: usize) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(count as u64 * 40 + 30), async {
        let dir = tempfile::tempdir()?;
        let owner = Store::open(&dir.path().join("host"), "host")?;
        let guest = Store::open(&dir.path().join("guest"), "guest")?;
        let mut server = relay("127.0.0.1:0".parse()?).await?;
        let bind = server.http_addr().unwrap();
        let url: iroh::RelayUrl = format!("http://{bind}").parse()?;
        let options = NetOptions {
            relay: Relay::Custom(url.clone()),
            ..NetOptions::loopback()
        };
        let tcp = TcpListener::bind("127.0.0.1:0").await?;
        let target = tcp.local_addr()?;
        let echo = tokio::spawn(async move {
            while let Ok((mut socket, _)) = tcp.accept().await {
                tokio::spawn(async move {
                    let mut b = [0; 4];
                    if socket.read_exact(&mut b).await.is_ok() {
                        let _ = socket.write_all(&b).await;
                    }
                });
            }
        });
        let now = omabridge::unix_time()?;
        let token = owner.create_invite(&["t3".into()], Duration::from_secs(60), now)?;
        owner.claim(&token, &guest.id()?, "guest", now)?;
        owner.approve(&guest.id()?, now)?;
        let mut node = Node::start(
            owner.clone(),
            BTreeMap::from([("t3".into(), target)]),
            options.clone(),
        )
        .await?;
        let client = Client::new(guest, options.clone()).await?;
        let addr = EndpointAddr::new(node.addr().id).with_relay_url(url);
        let mut baseline = None;
        for cycle in 0..=count {
            if cycle > 0 && cycle % 2 == 1 {
                server.shutdown().await?;
                server = relay(bind).await?;
            } else if cycle > 0 {
                node.shutdown().await;
                node = Node::start(
                    owner.clone(),
                    BTreeMap::from([("t3".into(), target)]),
                    options.clone(),
                )
                .await?;
            }
            let until = tokio::time::Instant::now() + Duration::from_secs(30);
            loop {
                if let Ok(mut pipe) = client.open(&addr, "t3").await {
                    let listener = TcpListener::bind("127.0.0.1:0").await?;
                    let mut socket = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
                    let (incoming, _) = listener.accept().await?;
                    let transfer = tokio::spawn(async move { pipe.transfer(incoming).await });
                    socket.write_all(b"ping").await?;
                    let mut b = [0; 4];
                    tokio::time::timeout(Duration::from_secs(5), socket.read_exact(&mut b))
                        .await??;
                    assert_eq!(&b, b"ping");
                    drop(socket);
                    transfer.await??;
                    break;
                }
                anyhow::ensure!(
                    tokio::time::Instant::now() < until,
                    "reconnect deadline cycle {cycle}"
                );
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            let tasks = tokio::runtime::Handle::current()
                .metrics()
                .num_alive_tasks();
            let rss = std::fs::read_to_string("/proc/self/status")?
                .lines()
                .find_map(|l| {
                    l.strip_prefix("VmRSS:")
                        .and_then(|v| v.split_whitespace().next()?.parse::<usize>().ok())
                })
                .unwrap();
            if cycle == 1 {
                baseline = Some((tasks, rss));
            }
            if cycle > 1 {
                if let Some((warm_tasks, warm_rss)) = baseline {
                    anyhow::ensure!(
                        tasks <= warm_tasks + 8,
                        "task growth: {warm_tasks} -> {tasks}"
                    );
                    anyhow::ensure!(
                        rss <= warm_rss + 16384,
                        "RSS growth KiB: {warm_rss} -> {rss}"
                    );
                }
            }
            eprintln!("cycle {cycle}: tasks {tasks}, RSS {rss} KiB");
        }
        client.close().await;
        node.shutdown().await;
        server.shutdown().await?;
        echo.abort();
        Ok(())
    })
    .await?
}
#[tokio::test]
async fn relay_and_node_restart() -> Result<()> {
    cycles(3).await
}
#[tokio::test]
#[ignore = "200 relay and node restarts"]
async fn relay_and_node_restart_stress() -> Result<()> {
    cycles(200).await
}
