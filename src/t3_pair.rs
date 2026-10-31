//! Native T3 pairing over the bridge, for a paired device this one shares `t3`
//! with. Granting `t3` is the consent: a device holding that grant may ask for
//! a one-use T3 pairing, as T3 Connect lists an account's environments. The
//! serving device issues it with its own T3 CLI, labelled with the asking
//! device's authenticated endpoint id so it can be revoked when the grant is
//! withdrawn. No SSH, no desktop bearer, no copied credential: T3 itself
//! exchanges the pairing for a session, over the same `t3` service.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, path::PathBuf, time::Duration};

/// Label prefix of the pairings and the sessions they become on the issuing host.
pub const LABEL_PREFIX: &str = "omabridge:";
/// Label of a pairing a host issues through a bridge for a device it never paired
/// with: `omabridge-delegated:<bridge>:<client>`. It must not start with
/// `LABEL_PREFIX`: revocation there keeps only sessions of a current peer, and a
/// client of a bridge is not one. The host revokes these when `bridge` loses
/// its consent or `t3` grant.
pub const DELEGATED_LABEL_PREFIX: &str = "omabridge-delegated:";
const TTL: &str = "2m";

pub fn delegated_label(bridge: &str, client: &str) -> String {
    format!("{DELEGATED_LABEL_PREFIX}{bridge}:{client}")
}

/// The T3 Code whose pairings this device issues.
#[derive(Clone, Debug, PartialEq)]
pub struct T3Issuer {
    pub cli: PathBuf,
    pub base_dir: PathBuf,
}

/// A one-use pairing. Not Debug: it carries a credential.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct T3Pairing {
    pub environment_id: String,
    pub credential: String,
    pub label: String,
}

impl T3Pairing {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            valid_environment(&self.environment_id),
            "invalid T3 pairing"
        );
        ensure!(
            !self.credential.is_empty()
                && self.credential.len() <= 4096
                && !self.credential.chars().any(char::is_whitespace),
            "invalid T3 pairing"
        );
        ensure!(
            (self.label.starts_with(LABEL_PREFIX)
                || self.label.starts_with(DELEGATED_LABEL_PREFIX))
                && self.label.len() <= 256,
            "invalid T3 pairing"
        );
        Ok(())
    }
}

fn valid_environment(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl T3Issuer {
    /// This user's own T3 Code (`~/.t3`), when its CLI is installed.
    pub fn detect() -> Option<Self> {
        let home = PathBuf::from(std::env::var_os("HOME")?);
        Self::detect_in(&home, std::env::var_os("PATH"))
    }

    /// The CLI of the T3 service that runs here comes first: `~/.t3/bin/t3`
    /// may be the desktop app's launcher restored from another system, whose
    /// app is gone, and every pairing would fail.
    fn detect_in(home: &std::path::Path, path: Option<std::ffi::OsString>) -> Option<Self> {
        if !home.is_absolute() {
            return None;
        }
        let base_dir = home.join(".t3");
        let cli = runtime_cli(&base_dir)
            .into_iter()
            .chain([base_dir.join("bin/t3"), home.join(".local/bin/t3")])
            .chain(
                path.into_iter()
                    .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
                    .filter(|dir| dir.is_absolute())
                    .map(|dir| dir.join("t3")),
            )
            .find(|path| is_executable(path) && !stale_desktop_launcher(path))?;
        Some(Self { cli, base_dir })
    }

    fn environment(&self) -> Result<String> {
        use std::io::Read;
        let mut text = String::new();
        std::fs::File::open(self.base_dir.join("userdata/environment-id"))?
            .take(256)
            .read_to_string(&mut text)?;
        let id = text.trim().to_owned();
        ensure!(valid_environment(&id), "invalid T3 environment");
        Ok(id)
    }

    /// Issues a one-use pairing for `peer`, after the T3 behind `target` (the
    /// published `t3` service) named this issuer's environment.
    pub async fn issue(&self, target: SocketAddr, peer: &str) -> Result<T3Pairing> {
        ensure!(valid_peer(peer), "invalid peer");
        self.issue_labelled(target, format!("{LABEL_PREFIX}{peer}"))
            .await
    }

    /// As `issue`, for `client` of the bridge `bridge`, when this host's T3 is
    /// `environment`.
    pub async fn issue_delegated(
        &self,
        target: SocketAddr,
        bridge: &str,
        client: &str,
        environment: &str,
    ) -> Result<T3Pairing> {
        ensure!(valid_peer(bridge) && valid_peer(client), "invalid peer");
        ensure!(self.environment()? == environment, "not this environment");
        self.issue_labelled(target, delegated_label(bridge, client))
            .await
    }

    async fn issue_labelled(&self, target: SocketAddr, label: String) -> Result<T3Pairing> {
        ensure!(target.ip().is_loopback(), "T3 must be on loopback");
        let environment = self.environment()?;
        let url = format!("http://{target}/");
        let expected = environment.clone();
        tokio::task::spawn_blocking(move || {
            t3_protocol::verify_environment(&url, &expected, &Default::default())
        })
        .await?
        .map_err(anyhow::Error::msg)?;
        let output = tokio::time::timeout(
            Duration::from_secs(20),
            tokio::process::Command::new(&self.cli)
                .args(["auth", "pairing", "create", "--base-dir"])
                .arg(&self.base_dir)
                .args(["--ttl", TTL, "--label", &label, "--json"])
                .stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .context("T3 pairing timed out")??;
        ensure!(output.status.success(), "T3 pairing failed");
        // Never format the output in an error: it holds the credential.
        let receipt: serde_json::Value =
            serde_json::from_slice(&output.stdout).context("invalid T3 pairing receipt")?;
        ensure!(
            receipt["label"] == label.as_str(),
            "T3 pairing label mismatch"
        );
        let pairing = T3Pairing {
            environment_id: environment,
            credential: receipt["credential"]
                .as_str()
                .context("missing T3 pairing")?
                .to_owned(),
            label,
        };
        pairing.validate()?;
        Ok(pairing)
    }
}

/// The T3 service's active version (`runtime/service-state.json`), as T3 runs it.
fn runtime_cli(base_dir: &std::path::Path) -> Option<PathBuf> {
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(base_dir.join("runtime/service-state.json")).ok()?)
            .ok()?;
    let version = state["activeVersion"].as_str()?;
    let valid = !version.is_empty()
        && version.len() <= 64
        && !version.starts_with('.')
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-+_".contains(&b));
    valid.then(|| base_dir.join("runtime/versions").join(version).join("t3"))
}

/// A launcher written by T3's desktop app whose app is no longer installed.
fn stale_desktop_launcher(path: &std::path::Path) -> bool {
    use std::io::Read;
    let mut text = String::new();
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    if file.take(4096).read_to_string(&mut text).is_err() || !text.contains("# Written by T3 Code")
    {
        return false;
    }
    text.lines()
        .find_map(|line| line.trim().strip_prefix("app='")?.strip_suffix('\''))
        .is_some_and(|app| !is_executable(std::path::Path::new(app)))
}

fn valid_peer(peer: &str) -> bool {
    peer.len() == 64 && peer.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Bounds pairing through a bridge like `CompositeAuthority`: four at once and
/// sixteen a minute per authenticated peer. Callers authorize before asking, so
/// strangers allocate nothing. Busy requests fail without waiting.
pub(crate) struct PairLimiter {
    concurrent: std::sync::Arc<tokio::sync::Semaphore>,
    attempts: std::sync::Mutex<std::collections::BTreeMap<String, (std::time::Instant, u32)>>,
}

impl PairLimiter {
    pub(crate) fn new() -> Self {
        Self {
            concurrent: std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
            attempts: Default::default(),
        }
    }

    pub(crate) fn admit(&self, peer: &str) -> Result<tokio::sync::OwnedSemaphorePermit> {
        const WINDOW: Duration = Duration::from_secs(60);
        {
            let mut attempts = self
                .attempts
                .lock()
                .map_err(|_| anyhow::anyhow!("pairing unavailable"))?;
            attempts.retain(|_, (started, _)| started.elapsed() < WINDOW);
            let entry = attempts
                .entry(peer.to_owned())
                .or_insert((std::time::Instant::now(), 0));
            ensure!(entry.1 < 16, "pairing rate exceeded");
            entry.1 += 1;
        }
        self.concurrent
            .clone()
            .try_acquire_owned()
            .context("pairing busy")
    }
}

fn is_executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn executable(path: &std::path::Path, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn launcher(app: &std::path::Path) -> String {
        format!(
            "#!/bin/sh\n# Written by T3 Code: runs the desktop app's bundled t3 CLI.\napp='{}'\nexec \"$app\" \"$@\"\n",
            app.display()
        )
    }

    #[test]
    fn prefers_the_running_service_over_a_stale_desktop_launcher() {
        let home = tempfile::tempdir().unwrap();
        let t3 = home.path().join(".t3");
        executable(
            &t3.join("bin/t3"),
            &launcher(&home.path().join("gone/t3code")),
        );
        assert_eq!(
            T3Issuer::detect_in(home.path(), None),
            None,
            "a launcher whose app is gone is skipped"
        );
        std::fs::create_dir_all(t3.join("runtime")).unwrap();
        std::fs::write(
            t3.join("runtime/service-state.json"),
            r#"{"protocol":3,"activeVersion":"0.1.4-nightly.1"}"#,
        )
        .unwrap();
        executable(
            &t3.join("runtime/versions/0.1.4-nightly.1/t3"),
            "#!/bin/sh\n",
        );
        assert_eq!(
            T3Issuer::detect_in(home.path(), None).unwrap().cli,
            t3.join("runtime/versions/0.1.4-nightly.1/t3")
        );
    }

    #[test]
    fn keeps_a_working_desktop_launcher() {
        let home = tempfile::tempdir().unwrap();
        let app = home.path().join("opt/t3code");
        executable(&app, "#!/bin/sh\n");
        let cli = home.path().join(".t3/bin/t3");
        executable(&cli, &launcher(&app));
        assert_eq!(T3Issuer::detect_in(home.path(), None).unwrap().cli, cli);
    }

    #[test]
    fn rejects_an_active_version_that_leaves_the_runtime() {
        let base = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(base.path().join("runtime")).unwrap();
        for bad in ["../../bin", "", ".hidden", "a/b"] {
            std::fs::write(
                base.path().join("runtime/service-state.json"),
                serde_json::json!({"activeVersion": bad}).to_string(),
            )
            .unwrap();
            assert_eq!(runtime_cli(base.path()), None, "{bad}");
        }
    }
}
