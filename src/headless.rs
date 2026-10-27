//! Own an isolated T3 headless process, never the live installation.
use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use omabridge::{read_document, write_document};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::process::{Child, Command};

pub struct ManagedT3 {
    pub child: Child,
    pub log: PathBuf,
    _home_lock: File,
}

pub fn spawn(
    binary: &Path,
    home: &Path,
    port: u16,
    owner: &str,
    state_dir: &Path,
) -> Result<ManagedT3> {
    ensure!(
        home.is_absolute() && port != 0,
        "T3 home must be absolute and its port explicit"
    );
    let executable = binary.canonicalize().context("T3 executable not found")?;
    if !home.exists() {
        fs::create_dir_all(home)?;
        fs::set_permissions(home, fs::Permissions::from_mode(0o700))?;
    }
    let metadata = fs::symlink_metadata(home)?;
    ensure!(
        metadata.is_dir() && metadata.permissions().mode() & 0o077 == 0,
        "T3 home must be a private non-symlink directory (0700)"
    );
    let marker = home.join(".omabridge-owner.json");
    if marker.exists() {
        let value: serde_json::Value = read_document(&marker)?;
        ensure!(
            value["owner"].as_str() == Some(owner),
            "T3 home belongs to another OmaBridge identity"
        );
    } else {
        ensure!(
            fs::read_dir(home)?.next().is_none(),
            "refusing an existing, unmanaged T3 home; use serve to attach an existing server"
        );
        write_document(&marker, &serde_json::json!({"owner":owner}), false)?;
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(home.join(".omabridge-home.lock"))?;
    FileExt::try_lock_exclusive(&lock).context("another T3 process owns this managed home")?;
    // Fail before spawning when an existing listener is present; never stop it.
    let free = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        .context("T3 loopback port already in use")?;
    drop(free);
    let log_path = state_dir.join(format!("t3-{:016x}.private.log", rand::random::<u64>()));
    let log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&log_path)?;
    let runtime_home = home.join("runtime-home");
    let workspace = home.join("workspace");
    fs::create_dir_all(&runtime_home)?;
    fs::create_dir_all(&workspace)?;
    let mut command = Command::new(executable);
    command
        .env_clear()
        .env("HOME", &runtime_home)
        .env("XDG_CONFIG_HOME", runtime_home.join("config"))
        .env("XDG_CACHE_HOME", runtime_home.join("cache"))
        .env("XDG_DATA_HOME", runtime_home.join("data"))
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("LANG", "C.UTF-8");
    if let Some(tmpdir) = std::env::var_os("TMPDIR") {
        command.env("TMPDIR", tmpdir);
    }
    let child = command
        .args([
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--base-dir",
        ])
        .arg(home)
        .arg("--no-browser")
        .current_dir(workspace)
        .stdout(log.try_clone()?)
        .stderr(log)
        .kill_on_drop(true)
        .spawn()
        .context("could not start T3 headless")?;
    Ok(ManagedT3 {
        child,
        log: log_path,
        _home_lock: lock,
    })
}

async fn session_response(port: u16) -> Result<bool> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let url = format!("http://127.0.0.1:{port}/api/auth/session");
    let mut response = match http
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) if error.is_connect() || error.is_timeout() => return Ok(false),
        Err(error) => return Err(error).context("T3 readiness HTTP request failed"),
    };
    // T3 binds before its API bootstrap finishes. Keep waiting for readiness;
    // the owned PID and the unauthenticated session body are checked on success.
    if response.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE {
        return Ok(false);
    }
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "T3 session endpoint returned a non-success response: {}",
        response.status()
    );
    ensure!(
        response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            .is_some_and(|h| h.to_ascii_lowercase().starts_with("application/json")),
        "not a JSON session endpoint"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= 8192,
            "T3 readiness response too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    let body: serde_json::Value =
        serde_json::from_slice(&bytes).context("invalid T3 session response")?;
    ensure!(
        body["authenticated"].as_bool() == Some(false),
        "not an unauthenticated T3 session response"
    );
    Ok(true)
}
fn owns_listener(pid: u32, port: u16) -> Result<bool> {
    let expected = format!(":{port:04X}");
    let mut inodes = Vec::new();
    for name in ["/proc/net/tcp", "/proc/net/tcp6"] {
        for line in fs::read_to_string(name)?.lines().skip(1) {
            let columns: Vec<_> = line.split_whitespace().collect();
            if columns.len() > 9 && columns[1].ends_with(&expected) && columns[3] == "0A" {
                inodes.push(format!("socket:[{}]", columns[9]));
            }
        }
    }
    if inodes.is_empty() {
        return Ok(false);
    }
    for fd in fs::read_dir(format!("/proc/{pid}/fd"))? {
        if let Ok(target) = fs::read_link(fd?.path())
            && inodes
                .iter()
                .any(|inode| target.to_string_lossy() == *inode)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

impl ManagedT3 {
    pub async fn wait_ready(&mut self, port: u16) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if self.child.try_wait()?.is_some() {
                bail!("T3 exited before readiness; inspect its private log");
            }
            match session_response(port).await {
                Ok(true) => {
                    let pid = self.child.id().context("owned T3 PID unavailable")?;
                    ensure!(
                        self.child.try_wait()?.is_none() && owns_listener(pid, port)?,
                        "expected T3 process does not own its loopback listener"
                    );
                    return Ok(());
                }
                Ok(false) => {}
                Err(error) => return Err(error).context("T3 application readiness check failed"),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        bail!("T3 startup deadline reached; inspect its private log")
    }

    pub async fn stop(&mut self) -> Result<()> {
        if self.child.try_wait()?.is_none() {
            self.child.kill().await?;
        }
        let _ = self.child.wait().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn bootstrap_unavailable_is_retried_but_other_errors_are_not_ready() -> Result<()> {
        for (status, body, expected) in [
            (503, "", Some(false)),
            (200, r#"{"authenticated":false}"#, Some(true)),
            (401, r#"{"authenticated":false}"#, None),
            (200, r#"{"not_t3":true}"#, None),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let port = listener.local_addr()?.port();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await?;
                let mut request = [0; 2048];
                let _ = socket.read(&mut request).await?;
                socket.write_all(format!(
                    "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()
                ).as_bytes()).await
            });
            let result = session_response(port).await;
            server.await??;
            match expected {
                Some(ready) => assert_eq!(result?, ready),
                None => assert!(result.is_err()),
            }
        }
        Ok(())
    }
}
