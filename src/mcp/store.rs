//! Private, durable gateway state: grants, hashed credentials, the run ledger and audit log.
//!
//! The gateway never stores conversations. T3 Code keeps the canonical history; this
//! ledger only remembers which `client_request_id` produced which T3 run so retries
//! and reconnections are answered without a second message.
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

/// Seconds since the epoch; a clock before 1970 is treated as 0 (everything expired).
pub fn now() -> u64 {
    crate::unix_time().unwrap_or(0)
}

const MAX_STATE: u64 = 8 * 1024 * 1024;
const MAX_RUNS: usize = 5000;
const MAX_LINK_CODES: usize = 32;
pub fn valid_environment(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
pub const DEFAULT_GRANT_TTL: u64 = 30 * 24 * 3600;

/// What an external client may do. Neither level can answer T3/Codex approvals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    /// List and read projects, sessions, messages, runs and events.
    Read,
    /// Read, plus queue messages and cancel runs in the granted sessions.
    Operate,
}

impl std::str::FromStr for Access {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        match value {
            "read" => Ok(Self::Read),
            "operate" => Ok(Self::Operate),
            _ => bail!("access must be read or operate"),
        }
    }
}

/// The scope an administrator authorizes for one external client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantScope {
    /// Explicit initial consent to an administrator-managed, mutable selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_catalog: Option<String>,
    pub label: String,
    /// Explicit environment identities. Empty preserves the original local-only grant.
    #[serde(default)]
    pub environments: Vec<String>,
    /// Explicit projects; empty when `all_projects` is set.
    pub projects: Vec<String>,
    /// Every T3 project, including ones created later.
    #[serde(default)]
    pub all_projects: bool,
    /// When present, only these T3 thread IDs in the granted projects are visible.
    pub sessions: Option<Vec<String>>,
    pub access: Access,
    pub ttl: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    pub id: String,
    #[serde(flatten)]
    pub scope: GrantScope,
    pub created: u64,
    pub expires: u64,
    pub client_name: String,
    pub redirect_host: String,
    pub revoked: Option<u64>,
    #[serde(skip)]
    pub resolution: Option<PolicyResolution>,
}

#[derive(Clone, Debug)]
pub struct PolicyResolution {
    pub original: GrantScope,
    pub revision: String,
    pub sessions: BTreeMap<String, Option<Vec<String>>>,
}

/// Administrator-only selection; this contains IDs, never credentials or history.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedPolicy {
    pub revision: String,
    pub access: Access,
    pub environments: BTreeMap<String, BTreeMap<String, Option<Vec<String>>>>,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedPolicies {
    policies: BTreeMap<String, ManagedPolicy>,
}

impl Grant {
    pub fn federated(&self) -> bool {
        self.scope.managed_catalog.is_some() || !self.scope.environments.is_empty()
    }

    pub fn active(&self, now: u64) -> bool {
        self.revoked.is_none() && now < self.expires
    }
    pub fn allows_project(&self, project: &str) -> bool {
        (self.scope.managed_catalog.is_none() || self.resolution.is_some())
            && (self.scope.all_projects
                || self.scope.projects.iter().any(|allowed| allowed == project))
    }
    pub fn allows_session(&self, project: &str, session: &str) -> bool {
        if let Some(resolved) = &self.resolution {
            return self.allows_project(project)
                && resolved.sessions.get(project).is_some_and(|sessions| {
                    sessions
                        .as_ref()
                        .is_none_or(|ids| ids.iter().any(|id| id == session))
                });
        }
        self.allows_project(project)
            && self
                .scope
                .sessions
                .as_ref()
                .is_none_or(|sessions| sessions.iter().any(|allowed| allowed == session))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LinkCode {
    scope: GrantScope,
    expires: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Token {
    grant: String,
    expires: u64,
    resource: String,
}

/// One accepted `send_message`, keyed by grant and client request ID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRecord {
    pub grant: String,
    pub session_id: String,
    pub run_id: String,
    pub message_id: String,
    pub message_sha256: String,
    /// Timeline position of the newest item before this message was sent.
    pub start_position: Option<u64>,
    pub delivery: String,
    pub created: u64,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    signing_key: String,
    #[serde(default)]
    link_codes: BTreeMap<String, LinkCode>,
    #[serde(default)]
    grants: BTreeMap<String, Grant>,
    #[serde(default)]
    tokens: BTreeMap<String, Token>,
    #[serde(default)]
    runs: BTreeMap<String, RunRecord>,
}

/// One MCP Events webhook subscription. Its ID is derived from the grant (the
/// authenticated principal), callback URL, event name and canonical arguments.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub grant: String,
    pub name: String,
    /// Canonical JSON of the subscription arguments (the filters).
    pub arguments: serde_json::Value,
    pub url: String,
    /// `whsec_` signing secret supplied by the client.
    pub secret: String,
    /// The secret a refresh replaced, still signed with until `previous_until`.
    #[serde(default)]
    pub previous_secret: Option<String>,
    #[serde(default)]
    pub previous_until: u64,
    pub created: u64,
    pub expires: u64,
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription")
            .field("id", &self.id)
            .field("grant", &self.grant)
            .field("name", &self.name)
            .field("expires", &self.expires)
            .finish_non_exhaustive()
    }
}

/// What the event watcher last saw of one T3 thread.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadMark {
    /// Status, latest run and last update as T3 lists them; unchanged means nothing to read.
    pub fingerprint: String,
    /// Terminal runs already reported, newest last (bounded).
    #[serde(default)]
    pub reported_runs: Vec<String>,
    /// Whether the thread was already waiting for an approval or an answer.
    #[serde(default)]
    pub attention: bool,
}

/// Project → thread → mark. A project absent here has no baseline yet.
pub type WatchState = BTreeMap<String, BTreeMap<String, ThreadMark>>;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventState {
    version: u32,
    #[serde(default)]
    subscriptions: BTreeMap<String, Subscription>,
    /// Hash of grant and callback URL → expiry of a successful callback verification.
    #[serde(default)]
    verified: BTreeMap<String, u64>,
    #[serde(default)]
    watch: WatchState,
}

pub const MAX_SUBSCRIPTIONS_PER_GRANT: usize = 50;

/// T3's own MCP credential for this gateway, obtained through T3's OAuth approval.
#[derive(Clone, Serialize, Deserialize)]
pub struct UpstreamCredential {
    pub url: String,
    pub token: String,
    pub access: String,
    pub expires: u64,
}

impl std::fmt::Debug for UpstreamCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamCredential")
            .field("url", &self.url)
            .field("access", &self.access)
            .field("expires", &self.expires)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct GatewayStore {
    root: PathBuf,
    ledger_environment: Option<String>,
}

/// References the existing desktop catalog publication; never copies its registry.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogBinding {
    pub device_state: PathBuf,
    pub client_id: String,
}

/// Remote source is an already paired device identity, never a caller URL.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteCatalogBinding {
    pub device_state: PathBuf,
    pub bridge_id: String,
}

/// A locally selected official T3 runtime, bound to an already consented identity.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBinding {
    pub runtime: PathBuf,
    pub environment_id: String,
}
impl RuntimeBinding {
    pub fn origin(&self) -> Result<String> {
        ensure!(
            self.runtime.is_absolute() && valid_environment(&self.environment_id),
            "absolute runtime and canonical environment UUID required"
        );
        // Official T3 metadata uses the owner's umask (0644 or 0664). It is not
        // credential storage. Refuse symlinks, foreign owners/groups, world writes,
        // and unbounded input; the separately private UUID binding remains fixed.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.runtime)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.len() <= 65536
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o002 == 0
                && (metadata.permissions().mode() & 0o020 == 0
                    || metadata.gid() == unsafe { libc::getegid() }),
            "invalid official T3 runtime metadata"
        );
        let mut bytes = Vec::new();
        file.take(65537).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 65536, "runtime metadata too large");
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        let port = value["port"]
            .as_u64()
            .filter(|p| *p > 0 && *p <= u16::MAX as u64)
            .context("invalid T3 runtime port")?;
        Ok(format!("http://127.0.0.1:{port}"))
    }
}

pub fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}

pub fn sha256_b64(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value))
}

/// Human-typable one-time link code: 100 random bits in Crockford base32 groups.
fn link_code() -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let bytes = rand::random::<[u8; 20]>();
    let symbols: String = bytes
        .iter()
        .map(|byte| ALPHABET[(byte & 31) as usize] as char)
        .collect();
    symbols
        .as_bytes()
        .chunks(5)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}

fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn private_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_dir() && meta.permissions().mode() & 0o077 == 0,
        "gateway state directory must be a private non-symlink directory (0700)"
    );
    Ok(())
}

fn read_private(path: &Path) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.permissions().mode() & 0o077 == 0 && meta.len() <= MAX_STATE,
        "gateway file must be a private bounded regular file (0600)"
    );
    let mut data = Vec::new();
    file.take(MAX_STATE + 1).read_to_end(&mut data)?;
    ensure!(data.len() as u64 <= MAX_STATE, "gateway file too large");
    Ok(data)
}

fn write_private(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    ensure!(bytes.len() as u64 <= MAX_STATE, "gateway file too large");
    let temporary = dir.join(format!(".{name}-{:016x}", rand::random::<u64>()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| -> Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, dir.join(name))?;
        File::open(dir)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.chars().any(|c| c.is_control() || c.is_whitespace())
}

impl GatewayStore {
    /// Opens `<state_dir>/mcp`, separate from device identity and T3's own state.
    pub fn open(state_dir: &Path) -> Result<Self> {
        private_dir(state_dir)?;
        let root = state_dir.join("mcp");
        private_dir(&root)?;
        let store = Self {
            root,
            ledger_environment: None,
        };
        store.update(|_| Ok(()))?;
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn lock(&self) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.root.join("gateway.lock"))?;
        FileExt::lock_exclusive(&file)?;
        Ok(file)
    }

    fn read(&self) -> Result<State> {
        let path = self.root.join("gateway.json");
        if path.symlink_metadata().is_err() {
            return Ok(State {
                version: 1,
                signing_key: random_token(),
                ..State::default()
            });
        }
        let state: State = serde_json::from_slice(&read_private(&path)?)
            .context("invalid gateway state; refusing to replace it")?;
        ensure!(state.version == 1, "unsupported gateway state version");
        Ok(state)
    }

    fn update<T>(&self, operation: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        let _lock = self.lock()?;
        let mut state = self.read()?;
        let now = now();
        state.link_codes.retain(|_, code| code.expires > now);
        state.tokens.retain(|_, token| token.expires > now);
        let value = operation(&mut state)?;
        if state.runs.len() > MAX_RUNS {
            let mut oldest: Vec<_> = state
                .runs
                .iter()
                .map(|(key, run)| (run.created, key.clone()))
                .collect();
            oldest.sort();
            for (_, key) in oldest.into_iter().take(state.runs.len() - MAX_RUNS) {
                state.runs.remove(&key);
            }
        }
        write_private(
            &self.root,
            "gateway.json",
            &serde_json::to_vec_pretty(&state)?,
        )?;
        Ok(value)
    }

    fn view<T>(&self, operation: impl FnOnce(&State) -> T) -> Result<T> {
        let _lock = self.lock()?;
        Ok(operation(&self.read()?))
    }

    fn read_policies(&self) -> Result<ManagedPolicies> {
        let path = self.root.join("managed-policies.json");
        match path.symlink_metadata() {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ManagedPolicies::default());
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        serde_json::from_slice(&read_private(&path)?).context("invalid managed catalog policy")
    }

    pub fn managed_policy(&self, id: &str) -> Result<Option<ManagedPolicy>> {
        let _lock = self.lock()?;
        Ok(self.read_policies()?.policies.remove(id))
    }

    /// Serialize read/modify/write under the existing gateway lock; no lost admin updates.
    pub fn create_managed_policy(&self, id: &str, access: Access) -> Result<()> {
        ensure!(valid_id(id), "invalid policy ID");
        let _lock = self.lock()?;
        let mut state = self.read_policies()?;
        ensure!(
            state.policies.len() < 128 && !state.policies.contains_key(id),
            "policy exists or limit reached"
        );
        state.policies.insert(
            id.into(),
            ManagedPolicy {
                revision: format!("{:032x}", rand::random::<u128>()),
                access,
                environments: BTreeMap::new(),
            },
        );
        write_private(
            &self.root,
            "managed-policies.json",
            &serde_json::to_vec_pretty(&state)?,
        )
    }

    /// Replace one exact project's selection or remove a project/whole host. No OAuth mutation.
    pub fn select_managed_project(
        &self,
        id: &str,
        environment: &str,
        project: Option<&str>,
        sessions: Option<Vec<String>>,
        remove: bool,
    ) -> Result<()> {
        ensure!(valid_environment(environment), "invalid environment UUID");
        ensure!(project.is_none_or(valid_id), "invalid project ID");
        ensure!(
            sessions.as_ref().is_none_or(|ids| !ids.is_empty()
                && ids.len() <= 256
                && ids.iter().all(|id| valid_id(id))),
            "invalid sessions"
        );
        let _lock = self.lock()?;
        let mut state = self.read_policies()?;
        let policy = state.policies.get_mut(id).context("unknown policy")?;
        if remove {
            if let Some(project) = project {
                if let Some(projects) = policy.environments.get_mut(environment) {
                    projects.remove(project);
                    if projects.is_empty() {
                        policy.environments.remove(environment);
                    }
                }
            } else {
                policy.environments.remove(environment);
            }
        } else {
            let project = project.context("project required")?;
            ensure!(
                policy.environments.contains_key(environment) || policy.environments.len() < 128,
                "environment limit"
            );
            let projects = policy.environments.entry(environment.into()).or_default();
            ensure!(
                projects.contains_key(project) || projects.len() < 64,
                "project limit"
            );
            projects.insert(project.into(), sessions);
        }
        policy.revision = format!("{:032x}", rand::random::<u128>());
        write_private(
            &self.root,
            "managed-policies.json",
            &serde_json::to_vec_pretty(&state)?,
        )
    }

    /// Materialize a single environment's current policy, retaining the immutable OAuth scope.
    pub fn resolve_grant(&self, grant: &Grant, environment: Option<&str>) -> Result<Grant> {
        let Some(id) = &grant.scope.managed_catalog else {
            return Ok(grant.clone());
        };
        let policy = self
            .managed_policy(id)?
            .context("managed policy unavailable")?;
        let original = grant
            .resolution
            .as_ref()
            .map_or(&grant.scope, |r| &r.original)
            .clone();
        let mut resolved = grant.clone();
        resolved.scope = original.clone();
        resolved.scope.environments = policy.environments.keys().cloned().collect();
        resolved.scope.projects.clear();
        resolved.scope.sessions = None;
        resolved.scope.all_projects = false;
        resolved.scope.access = if original.access == Access::Read || policy.access == Access::Read
        {
            Access::Read
        } else {
            Access::Operate
        };
        let projects = match environment {
            Some(env) => policy
                .environments
                .get(env)
                .context("environment withdrawn from managed policy")?
                .clone(),
            None => BTreeMap::new(),
        };
        resolved.scope.projects = projects.keys().cloned().collect();
        resolved.resolution = Some(PolicyResolution {
            original,
            revision: policy.revision,
            sessions: projects,
        });
        Ok(resolved)
    }

    /// Key for stateless OAuth client IDs; never leaves the private state.
    pub fn signing_key(&self) -> Result<Vec<u8>> {
        let key = self.view(|state| state.signing_key.clone())?;
        URL_SAFE_NO_PAD
            .decode(key)
            .context("invalid gateway signing key")
    }

    /// Creates a one-time code an administrator types on the authorization page.
    pub fn create_link_code(&self, scope: GrantScope, code_ttl: u64) -> Result<(String, u64)> {
        ensure!(
            scope.environments.len() <= 128
                && scope.environments.iter().all(|id| valid_environment(id)),
            "invalid environment identities"
        );
        ensure!(
            !scope.label.is_empty()
                && scope.label.len() <= 80
                && !scope.label.chars().any(char::is_control),
            "invalid grant label"
        );
        ensure!(
            if let Some(policy) = &scope.managed_catalog {
                valid_id(policy)
                    && self.managed_policy(policy)?.is_some()
                    && scope.environments.is_empty()
                    && scope.projects.is_empty()
                    && !scope.all_projects
                    && scope.sessions.is_none()
            } else if scope.all_projects {
                scope.projects.is_empty()
            } else {
                !scope.projects.is_empty()
                    && scope.projects.len() <= 64
                    && scope.projects.iter().all(|p| valid_id(p))
            },
            "grant needs 1..64 valid project IDs, or every project and no list"
        );
        if let Some(sessions) = &scope.sessions {
            ensure!(
                !sessions.is_empty()
                    && sessions.len() <= 256
                    && sessions.iter().all(|s| valid_id(s)),
                "session restriction needs 1..256 valid session IDs"
            );
        }
        ensure!(
            (60..=365 * 24 * 3600).contains(&scope.ttl),
            "grant ttl must be 60s..365d"
        );
        ensure!(
            (30..=3600).contains(&code_ttl),
            "code ttl must be 30..3600s"
        );
        let code = link_code();
        let expires = now() + code_ttl;
        self.update(|state| {
            ensure!(
                state.link_codes.len() < MAX_LINK_CODES,
                "too many live link codes"
            );
            state.link_codes.insert(
                sha256_b64(normalize_code(&code).as_bytes()),
                LinkCode { scope, expires },
            );
            Ok(())
        })?;
        Ok((code, expires))
    }

    /// Consumes a link code and creates the grant bound to this OAuth client.
    pub fn redeem_link_code(
        &self,
        code: &str,
        client_name: &str,
        redirect_host: &str,
    ) -> Result<Grant> {
        let key = sha256_b64(normalize_code(code).as_bytes());
        self.update(|state| {
            let link = state
                .link_codes
                .remove(&key)
                .context("invalid or expired link code")?;
            let now = now();
            let grant = Grant {
                id: format!("grant_{}", &random_token()[..16]),
                expires: now + link.scope.ttl,
                scope: link.scope,
                created: now,
                client_name: client_name.chars().take(100).collect(),
                redirect_host: redirect_host.chars().take(253).collect(),
                revoked: None,
                resolution: None,
            };
            state.grants.insert(grant.id.clone(), grant.clone());
            Ok(grant)
        })
    }

    pub fn issue_token(&self, grant: &str, resource: &str) -> Result<(String, u64)> {
        let token = random_token();
        self.update(|state| {
            let grant = state
                .grants
                .get(grant)
                .filter(|g| g.active(now()))
                .context("grant is not active")?;
            let expires = grant.expires;
            state.tokens.insert(
                sha256_b64(token.as_bytes()),
                Token {
                    grant: grant.id.clone(),
                    expires,
                    resource: resource.to_owned(),
                },
            );
            Ok(expires)
        })
        .map(|expires| (token, expires))
    }

    /// Resolves a bearer token for exactly this resource to its active grant.
    pub fn authenticate(&self, token: &str, resource: &str) -> Result<Option<Grant>> {
        if token.len() != 43 {
            return Ok(None);
        }
        let key = sha256_b64(token.as_bytes());
        self.view(|state| {
            let now = now();
            state
                .tokens
                .get(&key)
                .filter(|t| t.expires > now && t.resource == resource)
                .and_then(|t| state.grants.get(&t.grant))
                .filter(|g| g.active(now))
                .cloned()
        })
    }

    pub fn grants(&self) -> Result<Vec<Grant>> {
        self.view(|state| state.grants.values().cloned().collect())
    }

    /// Revokes a grant and deletes all of its tokens; effective on the next request.
    pub fn revoke(&self, grant: &str) -> Result<bool> {
        self.update(|state| {
            let Some(found) = state.grants.get_mut(grant) else {
                return Ok(false);
            };
            found.revoked.get_or_insert(now());
            state.tokens.retain(|_, token| token.grant != grant);
            Ok(true)
        })
        .and_then(|revoked| {
            self.update_events(|state| {
                state.subscriptions.retain(|_, sub| sub.grant != grant);
                Ok(())
            })?;
            Ok(revoked)
        })
    }

    fn update_events<T>(&self, operation: impl FnOnce(&mut EventState) -> Result<T>) -> Result<T> {
        let _lock = self.lock()?;
        let path = self.root.join("events.json");
        let mut state = if path.symlink_metadata().is_err() {
            EventState {
                version: 1,
                ..EventState::default()
            }
        } else {
            let state: EventState = serde_json::from_slice(&read_private(&path)?)
                .context("invalid event state; refusing to replace it")?;
            ensure!(state.version == 1, "unsupported event state version");
            state
        };
        let now = now();
        state.subscriptions.retain(|_, sub| sub.expires > now);
        state.verified.retain(|_, expires| *expires > now);
        let value = operation(&mut state)?;
        write_private(
            &self.root,
            "events.json",
            &serde_json::to_vec_pretty(&state)?,
        )?;
        Ok(value)
    }

    /// Unexpired subscriptions of every grant.
    pub fn subscriptions(&self) -> Result<Vec<Subscription>> {
        self.update_events(|state| Ok(state.subscriptions.values().cloned().collect()))
    }

    pub fn subscription(&self, id: &str) -> Result<Option<Subscription>> {
        self.update_events(|state| Ok(state.subscriptions.get(id).cloned()))
    }

    /// Creates or refreshes a subscription. A new secret on refresh keeps the old
    /// one valid for signing during `rotation` seconds.
    pub fn upsert_subscription(
        &self,
        mut sub: Subscription,
        rotation: u64,
    ) -> Result<Subscription> {
        self.update_events(|state| {
            match state.subscriptions.get(&sub.id) {
                Some(existing) => {
                    sub.created = existing.created;
                    if existing.secret != sub.secret {
                        sub.previous_secret = Some(existing.secret.clone());
                        sub.previous_until = now() + rotation;
                    } else {
                        sub.previous_secret = existing.previous_secret.clone();
                        sub.previous_until = existing.previous_until;
                    }
                }
                None => {
                    let count = state
                        .subscriptions
                        .values()
                        .filter(|s| s.grant == sub.grant)
                        .count();
                    ensure!(
                        count < MAX_SUBSCRIPTIONS_PER_GRANT,
                        "too many subscriptions for this connection"
                    );
                }
            }
            state.subscriptions.insert(sub.id.clone(), sub.clone());
            Ok(sub)
        })
    }

    pub fn remove_subscription(&self, id: &str) -> Result<bool> {
        self.update_events(|state| Ok(state.subscriptions.remove(id).is_some()))
    }

    pub fn callback_verified(&self, key: &str) -> Result<bool> {
        self.update_events(|state| Ok(state.verified.contains_key(key)))
    }

    pub fn mark_callback_verified(&self, key: &str, ttl: u64) -> Result<()> {
        self.update_events(|state| {
            if state.verified.len() >= 1000 {
                state.verified.clear();
            }
            state.verified.insert(key.to_owned(), now() + ttl);
            Ok(())
        })
    }

    /// Namespaced marks share one atomic state document; concurrent host ticks cannot overwrite one another.
    pub fn environment_watch(&self, environment: Option<&str>) -> Result<WatchState> {
        self.update_events(|state| {
            Ok(state
                .watch
                .iter()
                .filter_map(|(key, marks)| {
                    let (env, project): (Option<String>, String) =
                        serde_json::from_str(key).ok()?;
                    (env.as_deref() == environment).then(|| (project, marks.clone()))
                })
                .collect())
        })
    }
    pub fn set_environment_watch(
        &self,
        environment: Option<&str>,
        watch: WatchState,
    ) -> Result<()> {
        self.update_events(|state| {
            state.watch.retain(|key, _| {
                serde_json::from_str::<(Option<String>, String)>(key)
                    .is_ok_and(|(env, _)| env.as_deref() != environment)
            });
            for (project, marks) in watch {
                state
                    .watch
                    .insert(serde_json::to_string(&(environment, project))?, marks);
            }
            Ok(())
        })
    }

    pub fn watch_state(&self) -> Result<WatchState> {
        self.update_events(|state| Ok(state.watch.clone()))
    }

    pub fn set_watch_state(&self, watch: WatchState) -> Result<()> {
        self.update_events(|state| {
            state.watch = watch;
            Ok(())
        })
    }

    pub fn run(&self, grant: &str, client_request_id: &str) -> Result<Option<RunRecord>> {
        let key = format!("{}:{client_request_id}", self.ledger_principal(grant));
        self.view(|state| state.runs.get(&key).cloned())
    }

    pub fn run_by_id(&self, grant: &str, run_id: &str) -> Result<Option<RunRecord>> {
        self.view(|state| {
            state
                .runs
                .values()
                .find(|run| run.grant == self.ledger_principal(grant) && run.run_id == run_id)
                .cloned()
        })
    }

    /// Records an accepted run; an existing record for the same key wins.
    pub fn record_run(&self, client_request_id: &str, mut record: RunRecord) -> Result<RunRecord> {
        record.grant = self.ledger_principal(&record.grant);
        let key = format!("{}:{client_request_id}", record.grant);
        self.update(|state| Ok(state.runs.entry(key).or_insert(record).clone()))
    }

    pub fn runtime_binding(&self) -> Result<Option<RuntimeBinding>> {
        let path = self.root.join("runtime-binding.json");
        match path.symlink_metadata() {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            _ => Ok(Some(serde_json::from_slice(&read_private(&path)?)?)),
        }
    }
    /// No credential is copied or renewed: only the local route is resolved anew.
    pub fn upstream_routed(&self) -> Result<(Option<UpstreamCredential>, Option<String>)> {
        let mut credential = self.upstream()?;
        let environment = if let Some(binding) = self.runtime_binding()? {
            let origin = binding.origin()?;
            if let Some(credential) = &mut credential {
                credential.url = origin;
            }
            Some(binding.environment_id)
        } else {
            None
        };
        Ok((credential, environment))
    }
    /// Caller first verifies the descriptor and authenticates using the existing credential.
    pub fn set_runtime_binding(&self, binding: &RuntimeBinding) -> Result<()> {
        binding.origin()?;
        let _lock = self.lock()?;
        write_private(
            &self.root,
            "runtime-binding.json",
            &serde_json::to_vec(binding)?,
        )
    }

    pub fn upstream(&self) -> Result<Option<UpstreamCredential>> {
        let _lock = self.lock()?;
        let path = self.root.join("upstream.json");
        if path.symlink_metadata().is_err() {
            return Ok(None);
        }
        Ok(Some(
            serde_json::from_slice(&read_private(&path)?).context("invalid upstream credential")?,
        ))
    }

    pub fn set_upstream(&self, credential: &UpstreamCredential) -> Result<()> {
        let _lock = self.lock()?;
        write_private(
            &self.root,
            "upstream.json",
            &serde_json::to_vec_pretty(credential)?,
        )
    }

    /// Namespaces the ledger and upstream idempotency keys without copying history.
    pub fn for_environment(&self, environment: &str) -> Result<Self> {
        ensure!(
            valid_environment(environment),
            "invalid environment identity"
        );
        let mut scoped = self.clone();
        scoped.ledger_environment = Some(environment.into());
        Ok(scoped)
    }

    pub fn selected_environment(&self) -> Option<&str> {
        self.ledger_environment.as_deref()
    }

    pub fn ledger_principal(&self, grant: &str) -> String {
        match &self.ledger_environment {
            Some(environment) => format!("{grant}:env:{environment}"),
            None => grant.into(),
        }
    }

    /// Credential slots are separate from discovery. Catalog or SSH access never creates one.
    pub fn environment_store(&self, environment: &str) -> Result<Self> {
        ensure!(
            valid_environment(environment),
            "invalid environment identity"
        );
        Self::open(&self.root.join(format!("environment-{environment}")))
    }

    /// In-flight operations must not retain a scope that was narrowed after authentication.
    pub fn grant_unchanged(&self, grant: &Grant) -> Result<bool> {
        let unchanged = self.view(|state| {
            state.grants.get(&grant.id).is_some_and(|current| {
                current.active(now())
                    && current.scope
                        == grant
                            .resolution
                            .as_ref()
                            .map_or(&grant.scope, |r| &r.original)
                            .clone()
                    && current.expires == grant.expires
            })
        })?;
        let policy_unchanged = match (&grant.scope.managed_catalog, &grant.resolution) {
            (Some(id), Some(resolution)) => self
                .managed_policy(id)?
                .is_some_and(|p| p.revision == resolution.revision),
            (Some(_), None) => false,
            _ => true,
        };
        Ok(unchanged && policy_unchanged && self.grant_active(&grant.id)?)
    }

    pub fn grant_active(&self, id: &str) -> Result<bool> {
        let active = self.view(|state| state.grants.get(id).is_some_and(|g| g.active(now())))?;
        if let Some(environment) = &self.ledger_environment {
            return Ok(active && self.catalog_allows(environment)?);
        }
        Ok(active)
    }

    pub fn set_remote_catalog_binding(&self, binding: &RemoteCatalogBinding) -> Result<()> {
        ensure!(
            binding.device_state.is_absolute(),
            "absolute device state required"
        );
        let device = crate::Store {
            drafts_clock: None,
            root: binding.device_state.clone(),
        };
        ensure!(
            device
                .peers()?
                .iter()
                .any(|p| p.id == binding.bridge_id && p.address.is_some()),
            "paired catalog peer required"
        );
        ensure!(
            !self.root.join("catalog-binding.json").exists(),
            "local catalog binding already exists"
        );
        let _lock = self.lock()?;
        write_private(
            &self.root,
            "remote-catalog-binding.json",
            &serde_json::to_vec(binding)?,
        )
    }

    pub fn remote_catalog_binding(&self) -> Result<Option<RemoteCatalogBinding>> {
        let path = self.root.join("remote-catalog-binding.json");
        match path.symlink_metadata() {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            _ => Ok(Some(serde_json::from_slice(&read_private(&path)?)?)),
        }
    }

    pub fn set_catalog_binding(&self, binding: &CatalogBinding) -> Result<()> {
        ensure!(
            self.remote_catalog_binding()?.is_none(),
            "remote catalog binding already exists"
        );
        ensure!(
            binding.device_state.is_absolute() && binding.device_state.is_dir(),
            "existing absolute device state required"
        );
        ensure!(
            binding.client_id.len() == 64
                && binding
                    .client_id
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "invalid catalog client identity"
        );
        // Read the actual publisher output before accepting the reference.
        let _: serde_json::Value = serde_json::from_slice(&read_private(
            &binding.device_state.join("client-catalog.json"),
        )?)?;
        let _lock = self.lock()?;
        write_private(
            &self.root,
            "catalog-binding.json",
            &serde_json::to_vec(binding)?,
        )
    }

    /// Optional intersection with the native catalog's current per-peer allowlist.
    /// A cached manifest is not accepted; revocation is re-read on every T3 call.
    pub fn catalog_allows(&self, environment: &str) -> Result<bool> {
        if let Some(binding) = self.remote_catalog_binding()? {
            let device = crate::Store {
                drafts_clock: None,
                root: binding.device_state,
            };
            let Some(address) = device
                .peers()?
                .into_iter()
                .find(|p| p.id == binding.bridge_id)
                .and_then(|p| p.address)
            else {
                return Ok(false);
            };
            let manager = crate::catalog_client::CatalogManager::open(device, address)?;
            let projection =
                manager.projection(&serde_json::json!([]), now().saturating_mul(1000))?;
            return Ok(projection["upserts"].as_array().is_some_and(|rows| {
                rows.iter()
                    .any(|r| r["environmentId"] == environment && r["status"] == "discovered")
            }));
        }

        let path = self.root.join("catalog-binding.json");
        match path.symlink_metadata() {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            other => {
                other?;
            }
        }
        let binding: CatalogBinding = serde_json::from_slice(&read_private(&path)?)?;
        let device = crate::Store {
            drafts_clock: None,
            root: binding.device_state.clone(),
        };
        if !device.authorized(&binding.client_id, "t3")? {
            return Ok(false);
        }
        let source: serde_json::Value = serde_json::from_slice(&read_private(
            &binding.device_state.join("client-catalog.json"),
        )?)?;
        ensure!(
            source["version"] == 1 && source["revision"].is_u64(),
            "invalid native catalog source"
        );
        Ok(source["clients"][&binding.client_id]
            .as_array()
            .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(environment)))
            && source["environments"].as_array().is_some_and(|rows| {
                rows.iter()
                    .any(|row| row["id"] == environment && row["enabled"] == true)
            })
            && source["endpoints"].as_array().is_some_and(|rows| {
                rows.iter().any(|row| {
                    row["environmentId"] == environment
                        && row["descriptorEnvironmentId"] == environment
                })
            }))
    }

    /// Appends one audit record. Records carry no message text, token or link code.
    pub fn audit(&self, mut record: serde_json::Value) -> Result<()> {
        if let Some(object) = record.as_object_mut() {
            object.insert("ts".into(), now().into());
        }
        let _lock = self.lock()?;
        let path = self.root.join("audit.jsonl");
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        ensure!(
            file.metadata()?.permissions().mode() & 0o077 == 0,
            "audit log must be private (0600)"
        );
        let mut line = serde_json::to_vec(&record)?;
        line.push(b'\n');
        file.write_all(&line)?;
        Ok(())
    }

    pub fn audit_tail(&self, limit: usize) -> Result<Vec<serde_json::Value>> {
        let path = self.root.join("audit.jsonl");
        if path.symlink_metadata().is_err() {
            return Ok(Vec::new());
        }
        let _lock = self.lock()?;
        let mut data = String::new();
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?
            .read_to_string(&mut data)?;
        let lines: Vec<_> = data.lines().collect();
        Ok(lines[lines.len().saturating_sub(limit)..]
            .iter()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect())
    }
}
