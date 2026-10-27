//! systemd `--user` units for long-running OmaBridge processes. systemd owns their
//! lifecycle; frontends only render, install, start/stop and remove units they created.
use crate::valid_service;
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::SocketAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};

/// First line of every unit written by OmaBridge; files without it are never changed.
pub const MARKER: &str = "# Managed by OmaBridge (omabridge-gui); manual edits may be replaced.";
const MAX_UNIT: u64 = 64 * 1024;

/// Global options shared by every generated `ExecStart`.
#[derive(Clone, Debug)]
pub struct UnitContext {
    /// Absolute path of the `omabridge` CLI executable.
    pub binary: PathBuf,
    /// Absolute private state directory (same identity as the GUI).
    pub state_dir: PathBuf,
    pub name: String,
    pub bind: Option<SocketAddr>,
}

#[derive(Clone, Debug)]
pub enum UnitSpec {
    /// `omabridge … serve --service name=127.0.0.1:port …`
    Serve { services: Vec<(String, SocketAddr)> },
    /// Follow the authorized T3 runtime across port changes without restarting bridges.
    ServeTracked {
        services: Vec<(String, SocketAddr)>,
        t3_runtime: PathBuf,
    },
    /// `omabridge … forward --peer <id> --service <s> --listen 127.0.0.1:<port>`
    Forward {
        peer: String,
        service: String,
        listen: SocketAddr,
    },
}

fn unit_service(name: &str) -> bool {
    valid_service(name) && name.as_bytes()[0].is_ascii_alphanumeric()
}

fn valid_peer(peer: &str) -> bool {
    peer.len() == 64 && peer.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Characters that systemd's ExecStart parser treats literally (no quotes, `$`, `%`, `\`, `;`, spaces).
fn safe_arg(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/:=@+,[]-".contains(&b))
}

fn safe_path(path: &Path, what: &str) -> Result<String> {
    let text = path.to_str().context("unit paths must be UTF-8")?;
    ensure!(
        path.is_absolute() && safe_arg(text),
        "{what} must be an absolute path without spaces or shell/systemd metacharacters"
    );
    Ok(text.to_owned())
}

fn loopback(addr: &SocketAddr, what: &str) -> Result<()> {
    ensure!(
        addr.ip().is_loopback() && addr.port() != 0,
        "{what} must be an explicit loopback address with a fixed port"
    );
    Ok(())
}

impl UnitSpec {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Serve { services } | Self::ServeTracked { services, .. } => {
                if let Self::ServeTracked { t3_runtime, .. } = self {
                    safe_path(t3_runtime, "T3 runtime")?;
                    ensure!(
                        services.iter().any(|(name, _)| name == "t3"),
                        "T3 tracking requires a published t3 service"
                    );
                }
                ensure!((1..=32).contains(&services.len()), "publish 1..32 services");
                let mut seen = BTreeSet::new();
                for (name, target) in services {
                    ensure!(unit_service(name), "invalid service name");
                    ensure!(seen.insert(name), "duplicate service name");
                    loopback(target, "service target")?;
                }
            }
            Self::Forward {
                peer,
                service,
                listen,
            } => {
                ensure!(
                    valid_peer(peer),
                    "peer must be a 64-character lowercase hex ID"
                );
                ensure!(unit_service(service), "invalid service name");
                loopback(listen, "forward listener")?;
            }
        }
        Ok(())
    }

    pub fn unit_name(&self) -> Result<String> {
        self.validate()?;
        Ok(match self {
            Self::Serve { .. } | Self::ServeTracked { .. } => "omabridge-serve.service".to_owned(),
            Self::Forward { peer, service, .. } => {
                format!("omabridge-forward-{}-{service}.service", &peer[..8])
            }
        })
    }
}

/// Render a complete unit file. Every argument is validated; nothing is quoted or escaped.
pub fn render(context: &UnitContext, spec: &UnitSpec) -> Result<String> {
    spec.validate()?;
    let binary = safe_path(&context.binary, "omabridge binary")?;
    let state = safe_path(&context.state_dir, "state directory")?;
    ensure!(
        context.name.len() <= 80 && unit_service(&context.name),
        "device name must use only letters, digits, '.', '_' or '-' for a background unit"
    );
    let mut args = vec![
        binary,
        "--state-dir".to_owned(),
        state,
        "--name".to_owned(),
        context.name.clone(),
    ];
    if let Some(bind) = context.bind {
        args.extend(["--bind".to_owned(), bind.to_string()]);
    }
    let description = match spec {
        UnitSpec::Serve { services } | UnitSpec::ServeTracked { services, .. } => {
            args.push("serve".to_owned());
            for (name, target) in services {
                args.extend(["--service".to_owned(), format!("{name}={target}")]);
            }
            if let UnitSpec::ServeTracked { t3_runtime, .. } = spec {
                args.extend([
                    "--t3-runtime".to_owned(),
                    safe_path(t3_runtime, "T3 runtime")?,
                ]);
            }
            let names: Vec<_> = services.iter().map(|(name, _)| name.as_str()).collect();
            format!("OmaBridge publish {}", names.join(" "))
        }
        UnitSpec::Forward {
            peer,
            service,
            listen,
        } => {
            args.extend([
                "forward".to_owned(),
                "--peer".to_owned(),
                peer.clone(),
                "--service".to_owned(),
                service.clone(),
                "--listen".to_owned(),
                listen.to_string(),
            ]);
            format!("OmaBridge forward {service} from {}", &peer[..8])
        }
    };
    ensure!(args.iter().all(|arg| safe_arg(arg)), "unsafe unit argument");
    Ok(format!(
        "{MARKER}\n[Unit]\nDescription={description}\n\n[Service]\nType=simple\nExecStart={}\nRestart=on-failure\nRestartSec=5\nNoNewPrivileges=yes\n\n[Install]\nWantedBy=default.target\n",
        args.join(" ")
    ))
}

/// The `omabridge` CLI installed next to the running executable.
pub fn sibling_binary() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    Ok(exe
        .parent()
        .context("executable has no parent directory")?
        .join("omabridge"))
}

/// `$XDG_CONFIG_HOME/systemd/user`, else `$HOME/.config/systemd/user`.
pub fn user_unit_dir() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
    {
        return Ok(path.join("systemd/user"));
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .context("HOME is not set")?;
    Ok(home.join(".config/systemd/user"))
}

#[derive(Clone, Debug)]
pub struct RunOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Executes `systemctl --user <args>`; injectable so tests never reach systemd.
pub trait Runner: Send + Sync {
    fn run(&self, args: &[&str]) -> Result<RunOutput>;
}

pub struct Systemctl;
impl Runner for Systemctl {
    fn run(&self, args: &[&str]) -> Result<RunOutput> {
        let output = Command::new("systemctl")
            .arg("--user")
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .context("could not run systemctl --user")?;
        Ok(RunOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

#[derive(Clone, Debug)]
pub struct UnitFile {
    pub name: String,
    pub path: PathBuf,
    /// Created by OmaBridge (has [`MARKER`]); only these can be changed.
    pub managed: bool,
}

#[derive(Clone, Debug)]
pub struct UnitStatus {
    pub name: String,
    pub managed: bool,
    pub active: String,
    pub enabled: String,
}

fn state_word(output: &RunOutput) -> String {
    let word = output.stdout.lines().next().unwrap_or("").trim();
    if (1..=32).contains(&word.len()) && word.bytes().all(|b| b.is_ascii_lowercase() || b == b'-') {
        word.to_owned()
    } else {
        "unknown".to_owned()
    }
}

fn short_error(output: &RunOutput) -> String {
    output
        .stderr
        .chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(200)
        .collect()
}

/// `omabridge-<letters, digits, '.', '_', '-'>.service`; never a path.
fn omabridge_unit_name(name: &str) -> bool {
    name.strip_prefix("omabridge-")
        .and_then(|rest| rest.strip_suffix(".service"))
        .is_some_and(|stem| {
            !stem.is_empty()
                && stem.len() <= 120
                && stem.as_bytes()[0].is_ascii_alphanumeric()
                && stem
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}

#[derive(Clone)]
pub struct Units {
    dir: PathBuf,
    runner: Arc<dyn Runner>,
}

impl Units {
    pub fn new(dir: PathBuf, runner: Arc<dyn Runner>) -> Self {
        Self { dir, runner }
    }

    /// Real user manager and unit directory.
    pub fn user() -> Result<Self> {
        Ok(Self::new(user_unit_dir()?, Arc::new(Systemctl)))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, name: &str) -> Result<PathBuf> {
        ensure!(omabridge_unit_name(name), "not an OmaBridge unit name");
        Ok(self.dir.join(name))
    }

    /// Some(true) = ours, Some(false) = foreign or unsafe file, None = absent.
    fn ownership(path: &Path) -> Result<Option<bool>> {
        let meta = match fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !meta.is_file() || meta.len() > MAX_UNIT {
            return Ok(Some(false));
        }
        let mut text = String::new();
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?
            .take(MAX_UNIT)
            .read_to_string(&mut text)
            .ok();
        Ok(Some(text.lines().next() == Some(MARKER)))
    }

    fn require_managed(&self, name: &str) -> Result<PathBuf> {
        let path = self.path(name)?;
        ensure!(
            Self::ownership(&path)? == Some(true),
            "unit was not created by OmaBridge; refusing to change it"
        );
        Ok(path)
    }

    fn systemctl(&self, args: &[&str]) -> Result<RunOutput> {
        let output = self.runner.run(args)?;
        ensure!(
            output.success,
            "systemctl --user {} failed: {}",
            args.first().copied().unwrap_or(""),
            short_error(&output)
        );
        Ok(output)
    }

    /// Write (or replace an OmaBridge-owned) unit, mode 0644, then reload the user manager.
    pub fn install(&self, context: &UnitContext, spec: &UnitSpec) -> Result<PathBuf> {
        let text = render(context, spec)?;
        let path = self.path(&spec.unit_name()?)?;
        fs::create_dir_all(&self.dir)?;
        let existing = Self::ownership(&path)?;
        ensure!(
            existing != Some(false),
            "a unit with this name exists and was not created by OmaBridge"
        );
        let temporary = self
            .dir
            .join(format!(".omabridge-unit-{:016x}", rand::random::<u64>()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        let written = (|| -> Result<()> {
            file.write_all(text.as_bytes())?;
            file.set_permissions(fs::Permissions::from_mode(0o644))?;
            file.sync_all()?;
            if existing.is_some() {
                fs::rename(&temporary, &path)?;
            } else {
                // Never clobber a file created concurrently.
                fs::hard_link(&temporary, &path)?;
                fs::remove_file(&temporary)?;
            }
            Ok(())
        })();
        if written.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        written?;
        self.systemctl(&["daemon-reload"])?;
        Ok(path)
    }

    /// OmaBridge unit files present in the unit directory; reads files only, never systemctl.
    pub fn list(&self) -> Result<Vec<UnitFile>> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut units = Vec::new();
        for entry in entries {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !omabridge_unit_name(&name) {
                continue;
            }
            let path = entry.path();
            let managed = Self::ownership(&path)? == Some(true);
            units.push(UnitFile {
                name,
                path,
                managed,
            });
        }
        units.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(units)
    }

    /// Read-only `is-active`/`is-enabled` query; works for foreign OmaBridge-named units too.
    pub fn status(&self, name: &str) -> Result<UnitStatus> {
        let path = self.path(name)?;
        let active = state_word(&self.runner.run(&["is-active", name])?);
        let enabled = state_word(&self.runner.run(&["is-enabled", name])?);
        Ok(UnitStatus {
            name: name.to_owned(),
            managed: Self::ownership(&path)? == Some(true),
            active,
            enabled,
        })
    }

    pub fn enable_now(&self, name: &str) -> Result<()> {
        self.require_managed(name)?;
        self.systemctl(&["enable", "--now", name]).map(drop)
    }

    /// Enable and (re)start an OmaBridge-owned unit, so a rewritten unit takes effect.
    pub fn restart(&self, name: &str) -> Result<()> {
        self.require_managed(name)?;
        self.systemctl(&["enable", name])?;
        self.systemctl(&["restart", name]).map(drop)
    }

    pub fn disable_now(&self, name: &str) -> Result<()> {
        self.require_managed(name)?;
        self.systemctl(&["disable", "--now", name]).map(drop)
    }

    /// Stop, disable and delete an OmaBridge-owned unit; refuses if it is still running.
    pub fn remove(&self, name: &str) -> Result<()> {
        let path = self.require_managed(name)?;
        let _ = self.runner.run(&["disable", "--now", name]);
        let active = state_word(&self.runner.run(&["is-active", name])?);
        if matches!(
            active.as_str(),
            "active" | "activating" | "reloading" | "deactivating" | "refreshing"
        ) {
            bail!("unit is still {active}; stop it before removing");
        }
        fs::remove_file(path)?;
        self.systemctl(&["daemon-reload"]).map(drop)
    }
}
