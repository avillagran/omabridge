//! This user's T3-compatible local server: where its profile lives and, when known,
//! the CLI that issues its pairings. T3 Code keeps its profile in `~/.t3`, or in
//! `T3CODE_HOME`. O3 Code can instead run O3 Server (or T3) with its own profile and
//! records it in `~/.config/omarchy-t3-code/backends.json`; publishing `t3` and
//! issuing pairings must follow that server, not a `~/.t3` that may not exist.
use std::path::{Path, PathBuf};

/// The registry is small; anything larger is not one O3 Code wrote.
const REGISTRY_LIMIT: u64 = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalServer {
    /// The server's profile: `userdata/server-runtime.json` and
    /// `userdata/environment-id` live under it.
    pub base_dir: PathBuf,
    /// The registered CLI (`o3-server` or `t3`), when O3 Code's registry names one.
    pub cli: Option<PathBuf>,
}

impl LocalServer {
    pub fn runtime(&self) -> PathBuf {
        self.base_dir.join("userdata/server-runtime.json")
    }
}

/// The inputs `resolve` reads, so tests never depend on the process environment.
pub struct Env {
    pub home: PathBuf,
    pub t3code_home: Option<PathBuf>,
    pub config_home: Option<PathBuf>,
    pub state_home: Option<PathBuf>,
}

impl Env {
    pub fn from_process(home: &Path) -> Self {
        let absolute = |name: &str| {
            std::env::var_os(name)
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
        };
        Self {
            home: home.to_path_buf(),
            t3code_home: absolute("T3CODE_HOME"),
            config_home: absolute("XDG_CONFIG_HOME"),
            state_home: absolute("XDG_STATE_HOME"),
        }
    }
}

/// The current user's local server, or `None` without an absolute `HOME`.
pub fn detect() -> Option<LocalServer> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())?;
    Some(resolve(&Env::from_process(&home)))
}

/// An explicit `T3CODE_HOME` wins; then the server O3 Code's registry selects; then `~/.t3`.
pub fn resolve(env: &Env) -> LocalServer {
    if let Some(base_dir) = &env.t3code_home {
        return LocalServer {
            base_dir: base_dir.clone(),
            cli: None,
        };
    }
    registered(env).unwrap_or_else(|| LocalServer {
        base_dir: env.home.join(".t3"),
        cli: None,
    })
}

struct Entry {
    id: String,
    profile: PathBuf,
    cli: PathBuf,
}

/// O3 Code's choice: the saved `backend-choice.json` server, else the registry's
/// default. A registered server whose runtime file exists is preferred over a chosen
/// one that has none, as O3 Code reflects a running server rather than its rival.
/// A missing or malformed registry selects nothing.
fn registered(env: &Env) -> Option<LocalServer> {
    let config = env
        .config_home
        .clone()
        .unwrap_or_else(|| env.home.join(".config"));
    let registry = read_json(&config.join("omarchy-t3-code/backends.json"))?;
    if registry["version"] != 1 {
        return None;
    }
    let rows = registry["servers"].as_array()?;
    if rows.is_empty() || rows.len() > 2 {
        return None;
    }
    let mut entries: Vec<Entry> = Vec::new();
    for row in rows {
        let id = row["id"].as_str()?;
        let profile = PathBuf::from(row["profile"].as_str()?);
        let cli = PathBuf::from(row["cli"].as_str()?);
        if !matches!(id, "o3" | "t3")
            || !profile.is_absolute()
            || !cli.is_absolute()
            || profile == Path::new("/")
            || entries.iter().any(|e| e.id == id || e.profile == profile)
        {
            return None;
        }
        entries.push(Entry {
            id: id.to_owned(),
            profile,
            cli,
        });
    }
    let default = registry["default"].as_str()?;
    entries.iter().find(|e| e.id == default)?;
    let state = env
        .state_home
        .clone()
        .unwrap_or_else(|| env.home.join(".local/state"));
    let chosen_id = read_json(&state.join("omarchy-t3-code/backend-choice.json"))
        .and_then(|choice| choice["server"].as_str().map(str::to_owned))
        .filter(|id| entries.iter().any(|e| &e.id == id))
        .unwrap_or_else(|| default.to_owned());
    let has_runtime = |e: &Entry| e.profile.join("userdata/server-runtime.json").is_file();
    let chosen = entries.iter().find(|e| e.id == chosen_id)?;
    let entry = if has_runtime(chosen) {
        chosen
    } else {
        entries.iter().find(|e| has_runtime(e)).unwrap_or(chosen)
    };
    Some(LocalServer {
        base_dir: entry.profile.clone(),
        cli: Some(entry.cli.clone()),
    })
}

fn read_json(path: &Path) -> Option<serde_json::Value> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(REGISTRY_LIMIT + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > REGISTRY_LIMIT {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(home: &Path) -> Env {
        Env {
            home: home.to_path_buf(),
            t3code_home: None,
            config_home: None,
            state_home: None,
        }
    }

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn registry(home: &Path, body: serde_json::Value) {
        write(
            &home.join(".config/omarchy-t3-code/backends.json"),
            &body.to_string(),
        );
    }

    fn o3_registry(home: &Path) -> (PathBuf, PathBuf) {
        let profile = home.join(".local/share/o3-server/profile");
        let cli = home.join(".local/share/o3-server/bin/o3-server");
        registry(
            home,
            serde_json::json!({"version":1,"default":"o3","servers":[
                {"id":"o3","unit":"o3-server.service","profile":profile,"cli":cli}]}),
        );
        (profile, cli)
    }

    #[test]
    fn without_a_registry_uses_t3s_default_profile() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(
            resolve(&env(home.path())),
            LocalServer {
                base_dir: home.path().join(".t3"),
                cli: None
            }
        );
    }

    #[test]
    fn follows_the_server_o3_code_registered() {
        let home = tempfile::tempdir().unwrap();
        let (profile, cli) = o3_registry(home.path());
        let server = resolve(&env(home.path()));
        assert_eq!(server.base_dir, profile);
        assert_eq!(server.cli, Some(cli));
        assert_eq!(
            server.runtime(),
            profile.join("userdata/server-runtime.json")
        );
    }

    #[test]
    fn an_explicit_t3code_home_wins() {
        let home = tempfile::tempdir().unwrap();
        o3_registry(home.path());
        let mut env = env(home.path());
        env.t3code_home = Some(home.path().join("custom"));
        assert_eq!(
            resolve(&env),
            LocalServer {
                base_dir: home.path().join("custom"),
                cli: None
            }
        );
    }

    #[test]
    fn honours_the_saved_choice_and_a_running_server() {
        let home = tempfile::tempdir().unwrap();
        let o3 = home.path().join("o3");
        let t3 = home.path().join(".t3");
        registry(
            home.path(),
            serde_json::json!({"version":1,"default":"o3","servers":[
                {"id":"o3","unit":"o3-server.service","profile":o3,"cli":"/opt/o3-server"},
                {"id":"t3","unit":"t3code.service","profile":t3,"cli":"/opt/t3"}]}),
        );
        write(
            &home
                .path()
                .join(".local/state/omarchy-t3-code/backend-choice.json"),
            r#"{"server":"t3"}"#,
        );
        assert_eq!(resolve(&env(home.path())).base_dir, t3, "saved choice");
        write(&o3.join("userdata/server-runtime.json"), r#"{"port":3773}"#);
        assert_eq!(
            resolve(&env(home.path())).base_dir,
            o3,
            "the running server, while the chosen one is not"
        );
        write(&t3.join("userdata/server-runtime.json"), r#"{"port":3774}"#);
        assert_eq!(resolve(&env(home.path())).base_dir, t3);
    }

    #[test]
    fn a_malformed_registry_selects_nothing() {
        let home = tempfile::tempdir().unwrap();
        for body in [
            serde_json::json!({"version":2,"default":"o3","servers":[{"id":"o3","unit":"u.service","profile":"/p","cli":"/c"}]}),
            serde_json::json!({"version":1,"default":"t3","servers":[{"id":"o3","unit":"u.service","profile":"/p","cli":"/c"}]}),
            serde_json::json!({"version":1,"default":"o3","servers":[{"id":"o3","unit":"u.service","profile":"relative","cli":"/c"}]}),
            serde_json::json!({"version":1,"default":"x","servers":[{"id":"x","unit":"u.service","profile":"/p","cli":"/c"}]}),
            serde_json::json!({"version":1,"default":"o3","servers":[{"id":"o3","unit":"u.service","profile":"/","cli":"/c"}]}),
        ] {
            registry(home.path(), body);
            assert_eq!(resolve(&env(home.path())).base_dir, home.path().join(".t3"));
        }
        write(
            &home.path().join(".config/omarchy-t3-code/backends.json"),
            &" ".repeat(REGISTRY_LIMIT as usize + 1),
        );
        assert_eq!(resolve(&env(home.path())).base_dir, home.path().join(".t3"));
    }
}
