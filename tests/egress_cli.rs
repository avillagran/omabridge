use std::{
    io::{BufRead, BufReader, Read},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn egress_requires_requested_exit_key_without_exposing_its_value() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("device");
    let output = Command::new(env!("CARGO_BIN_EXE_omabridge"))
        .args([
            "--state-dir",
            state.to_str().unwrap(),
            "egress",
            "--origin",
            "https://api.example.com",
            "--key-env",
            "OMABRIDGE_TEST_MISSING_KEY",
        ])
        .env_remove("OMABRIDGE_TEST_MISSING_KEY")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("requested API credential is not set")
    );
}

#[test]
fn one_binary_owns_egress_and_bridge_without_python_or_shell() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("device");
    let mut child = Command::new(env!("CARGO_BIN_EXE_omabridge"))
        .args([
            "--state-dir",
            state.to_str().unwrap(),
            "--bind",
            "127.0.0.1:0",
            "egress",
            "--origin",
            "https://api.example.com",
            "--key-env",
            "OMABRIDGE_SYNTHETIC_KEY",
        ])
        .env("OMABRIDGE_SYNTHETIC_KEY", "synthetic-never-log-this")
        .env("PATH", "")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    if line.is_empty() {
        child.wait().unwrap();
        panic!("binary did not publish egress");
    }
    assert!(!line.contains("synthetic-never-log-this"));
    let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(ready["services"], serde_json::json!(["egress"]));
    let gateway: std::net::SocketAddr = ready["gateway"].as_str().unwrap().parse().unwrap();
    assert!(gateway.ip().is_loopback());
    assert!(std::net::TcpStream::connect(gateway).is_ok());
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("egress did not stop");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success());
    assert!(std::net::TcpStream::connect(gateway).is_err());
    let mut errors = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut errors)
        .unwrap();
    assert!(!errors.contains("synthetic-never-log-this"));
}
