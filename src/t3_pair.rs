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
const TTL: &str = "2m";

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
            self.label.starts_with(LABEL_PREFIX) && self.label.len() <= 128,
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
        if !home.is_absolute() {
            return None;
        }
        let base_dir = home.join(".t3");
        let cli = [base_dir.join("bin/t3"), home.join(".local/bin/t3")]
            .into_iter()
            .chain(
                std::env::var_os("PATH")
                    .into_iter()
                    .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
                    .filter(|dir| dir.is_absolute())
                    .map(|dir| dir.join("t3")),
            )
            .find(|path| is_executable(path))?;
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
        ensure!(
            peer.len() == 64 && peer.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid peer"
        );
        ensure!(target.ip().is_loopback(), "T3 must be on loopback");
        let environment = self.environment()?;
        let url = format!("http://{target}/");
        let expected = environment.clone();
        tokio::task::spawn_blocking(move || {
            t3_protocol::verify_environment(&url, &expected, &Default::default())
        })
        .await?
        .map_err(anyhow::Error::msg)?;
        let label = format!("{LABEL_PREFIX}{peer}");
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

fn is_executable(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}
