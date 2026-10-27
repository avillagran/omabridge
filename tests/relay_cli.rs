use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
};

#[tokio::test]
async fn relay_command_is_a_managed_native_listener() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let state = dir.path().join("relay");
    let peer = iroh::SecretKey::generate().public().to_string();
    let mut child = Command::new(env!("CARGO_BIN_EXE_omabridge"))
        .args([
            "--state-dir",
            state.to_str().unwrap(),
            "relay",
            "--listen",
            "127.0.0.1:0",
            "--allow-peer",
            &peer,
        ])
        .env("PATH", "")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut line)?;
    if line.is_empty() {
        child.wait()?;
        anyhow::bail!("relay command missing or failed");
    }
    let ready: serde_json::Value = serde_json::from_str(&line)?;
    assert_eq!(ready["event"], "relay_listening");
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()?
        .get(format!("http://{}/ping", ready["http"].as_str().unwrap()))
        .send()
        .await?;
    assert!(response.status().is_success());
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    assert!(child.wait()?.success());
    Ok(())
}
