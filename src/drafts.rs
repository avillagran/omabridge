//! Owner-scoped private drafts. One state lock covers grants, CAS and the
//! durable atomic commit. Content is never passed to the management audit.
use crate::Store;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
};

pub const SERVICE: &str = "drafts";
pub const MAX_DOCUMENT: usize = 8192;
const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_DOCUMENTS: usize = 128; // Includes tombstones: never silently evicted.
const MAX_MUTATIONS: usize = 2048; // Receipts and events are retained, not time-expired.
const PAGE: usize = 2;

#[derive(Default, Serialize, Deserialize)]
struct Database {
    sequence: u64,
    documents: BTreeMap<String, Value>,
    receipts: BTreeMap<String, Receipt>,
    events: Vec<Value>,
}
#[derive(Serialize, Deserialize)]
struct Receipt {
    hash: String,
    outcome: Value,
}

fn id(value: &Value) -> Result<&str> {
    let s = value.as_str().context("draft_invalid")?;
    ensure!(
        !s.is_empty()
            && s.len() <= 128
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "draft_invalid"
    );
    Ok(s)
}
fn key(scope: &Value) -> Result<String> {
    ensure!(
        scope.as_object().is_some_and(|o| o.len() == 4),
        "draft_invalid"
    );
    let kind = id(&scope["kind"])?;
    ensure!(matches!(kind, "thread" | "stash"), "draft_invalid");
    Ok(format!(
        "{}/{}/{}/{}",
        id(&scope["environment"])?,
        id(&scope["project"])?,
        kind,
        id(&scope["id"])?
    ))
}
fn payload(value: &Value, scope: &Value) -> Result<()> {
    let fields = value.as_object().context("draft_invalid")?;
    ensure!(
        fields.keys().all(|k| [
            "schema",
            "text",
            "attachments",
            "modelSelection",
            "preferences",
            "selection"
        ]
        .contains(&k.as_str())),
        "draft_invalid"
    );
    ensure!(
        value["schema"] == 1
            && value["text"].is_string()
            && serde_json::to_vec(value)?.len() <= MAX_DOCUMENT,
        "draft_invalid"
    );
    // Durable descriptors only, never OS handles, URIs or bearer URLs.
    let attachments = value["attachments"].as_array().context("draft_invalid")?;
    ensure!(attachments.len() <= 16, "draft_invalid");
    for a in attachments {
        ensure!(
            a.as_object().is_some_and(|o| o.len() == 3)
                && a["sourceEnvironment"] == scope["environment"],
            "draft_attachment_host"
        );
        id(&a["id"])?;
        let name = a["name"].as_str().context("draft_invalid")?;
        ensure!(
            name.len() <= 256 && !name.chars().any(char::is_control),
            "draft_invalid"
        );
    }
    // Options are small scalar maps: no arbitrary runtime/outbox objects.
    for field in ["modelSelection", "preferences"] {
        if let Some(options) = value.get(field) {
            let map = options.as_object().context("draft_invalid")?;
            ensure!(
                map.len() <= 16
                    && map.iter().all(|(k, v)| [
                        "provider",
                        "providerId",
                        "model",
                        "modelId",
                        "effort",
                        "interactionMode",
                        "deliveryMode",
                        "permissionMode",
                        "reasoningEffort",
                        "speedMode"
                    ]
                    .contains(&k.as_str())
                        && (v.is_boolean()
                            || v.is_number()
                            || v.as_str().is_some_and(|s| s.len() <= 256))),
                "draft_invalid"
            );
        }
    }
    if let Some(selection) = value.get("selection") {
        ensure!(
            selection.as_array().is_some_and(
                |a| a.len() == 2 && a.iter().all(|n| n.as_u64().is_some_and(|n| n <= 8192))
            ),
            "draft_invalid"
        );
    }
    Ok(())
}
fn revision(owner: &str, sequence: u64) -> String {
    format!("{owner}:{sequence}")
}
fn cursor(owner: &str, value: &Value, max: u64) -> Result<u64> {
    let raw = value.as_str().context("draft_snapshot_required")?;
    let seq = raw
        .strip_prefix(&format!("{owner}:"))
        .and_then(|s| s.parse::<u64>().ok())
        .context("draft_snapshot_required")?;
    ensure!(seq <= max, "draft_snapshot_required");
    Ok(seq)
}
fn matches(document: Option<&Value>, expected: &Value) -> bool {
    match document {
        None => expected.is_null(),
        Some(d) => expected.is_string() && d["revision"] == *expected,
    }
}
fn load(store: &Store) -> Result<Database> {
    let path = store.root().join("shared-drafts.json");
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Database::default()),
        Err(e) => return Err(e.into()),
    };
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.permissions().mode() & 0o077 == 0 && meta.len() <= MAX_BYTES as u64,
        "draft_store_invalid"
    );
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_BYTES, "draft_store_invalid");
    Ok(serde_json::from_slice(&bytes)?)
}
fn save(store: &Store, db: &Database) -> Result<()> {
    let bytes = serde_json::to_vec(db)?;
    ensure!(
        bytes.len() <= MAX_BYTES
            && db.documents.len() <= MAX_DOCUMENTS
            && db.receipts.len() <= MAX_MUTATIONS,
        "draft_quota"
    );
    let temporary = store
        .root()
        .join(format!(".drafts-{:032x}", rand::random::<u128>()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, store.root().join("shared-drafts.json"))?;
        File::open(store.root())?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

/// `peer=None` is the local owner. Remote access needs a current explicit drafts
/// service grant, independent of manage/T3/all-hosts privileges.
pub fn execute(store: &Store, peer: Option<&str>, request: &Value) -> Value {
    match run(store, peer, request) {
        Ok(v) => v,
        Err(e) => {
            let message = e.to_string();
            let code = [
                "draft_invalid",
                "draft_attachment_host",
                "draft_snapshot_required",
                "draft_forbidden",
                "draft_quota",
                "draft_mutation_reused",
            ]
            .into_iter()
            .find(|c| *c == message)
            .unwrap_or("draft_store_error");
            json!({"error":code})
        }
    }
}
fn run(store: &Store, peer: Option<&str>, r: &Value) -> Result<Value> {
    let owner = store.id()?;
    let _lock = store.lock()?;
    if let Some(peer) = peer {
        ensure!(
            store
                .read()?
                .peers
                .get(peer)
                .is_some_and(|p| p.services.contains(SERVICE)),
            "draft_forbidden"
        );
    }
    ensure!(serde_json::to_vec(r)?.len() <= 32 * 1024, "draft_invalid");
    let mut db = load(store)?;
    let op = r["op"].as_str().context("draft_invalid")?;
    let allowed: &[&str] = match op {
        "list" => &["op", "offset", "snapshot"],
        "watch" => &["op", "cursor", "offset", "snapshot"],
        "get" => &["op", "scope"],
        "receipt" => &["op", "mutationId"],
        "put" => &["op", "scope", "expected", "mutationId", "payload"],
        "delete" => &["op", "scope", "expected", "mutationId"],
        "transfer" => &[
            "op",
            "scope",
            "expected",
            "mutationId",
            "target",
            "targetExpected",
            "backup",
            "payload",
        ],
        _ => anyhow::bail!("draft_invalid"),
    };
    ensure!(
        r.as_object()
            .is_some_and(|m| m.keys().all(|k| allowed.contains(&k.as_str()))),
        "draft_invalid"
    );
    if op == "list" || op == "watch" {
        let since = if op == "watch" {
            cursor(&owner, &r["cursor"], db.sequence)?
        } else {
            0
        };
        // Snapshot pagination must restart if any commit occurred between pages.
        if op == "list" && r.get("snapshot").is_some() {
            ensure!(
                cursor(&owner, &r["snapshot"], db.sequence)? == db.sequence,
                "draft_snapshot_required"
            );
        }
        let fence = if op == "watch" && r.get("snapshot").is_some() {
            cursor(&owner, &r["snapshot"], db.sequence)?
        } else {
            db.sequence
        };
        ensure!(fence >= since, "draft_snapshot_required");
        let offset = r["offset"].as_u64().unwrap_or(0) as usize;
        ensure!(
            offset == 0 || r.get("snapshot").is_some(),
            "draft_snapshot_required"
        );
        let items: Vec<_> = if op == "list" {
            db.documents.values().cloned().collect()
        } else {
            db.events
                .iter()
                .filter(|e| {
                    e["sequence"]
                        .as_u64()
                        .is_some_and(|s| s > since && s <= fence)
                })
                .cloned()
                .collect()
        };
        ensure!(offset <= items.len(), "draft_invalid");
        let end = (offset + PAGE).min(items.len());
        return Ok(
            json!({"owner":owner,"items":items[offset..end],"cursor":revision(&owner, fence),"nextOffset":if end < items.len() {Some(end)} else {None}}),
        );
    }
    if op == "get" {
        let k = key(&r["scope"])?;
        return Ok(
            json!({"owner":owner,"document":db.documents.get(&k),"cursor":revision(&owner, db.sequence)}),
        );
    }
    let mutation = id(&r["mutationId"])?;
    let receipt_key = format!("{}:{mutation}", peer.unwrap_or(&owner));
    if op == "receipt" {
        return Ok(db
            .receipts
            .get(&receipt_key)
            .map(|r| r.outcome.clone())
            .unwrap_or(json!({"found":false})));
    }
    let hash = format!("{:x}", Sha256::digest(serde_json::to_vec(r)?));
    if let Some(receipt) = db.receipts.get(&receipt_key) {
        ensure!(receipt.hash == hash, "draft_mutation_reused");
        return Ok(receipt.outcome.clone());
    }
    ensure!(db.receipts.len() < MAX_MUTATIONS, "draft_quota");
    ensure!(["put", "delete", "transfer"].contains(&op), "draft_invalid");
    let scope = &r["scope"];
    let k = key(scope)?;
    ensure!(
        r.get("expected").is_some()
            && (r["expected"].is_null() || r["expected"].as_str().is_some_and(|s| s.len() <= 128)),
        "draft_invalid"
    );
    if op == "put" {
        payload(&r["payload"], scope)?;
    }
    let mut checks = vec![(k.clone(), &r["expected"])];
    let mut target_key = None;
    let mut backup_key = None;
    if op == "transfer" {
        let target = key(&r["target"])?;
        if let Some(content) = r.get("payload") {
            payload(content, &r["target"])?;
        }
        ensure!(
            target != k
                && r.get("targetExpected").is_some()
                && (r["targetExpected"].is_null()
                    || r["targetExpected"].as_str().is_some_and(|s| s.len() <= 128)),
            "draft_invalid"
        );
        checks.push((target.clone(), &r["targetExpected"]));
        if let Some(existing) = db.documents.get(&target).filter(|d| d["deleted"] != true) {
            let backup = key(&r["backup"])?;
            ensure!(
                r["backup"]["kind"] == "stash"
                    && r["backup"]["environment"] == r["target"]["environment"]
                    && r["backup"]["project"] == r["target"]["project"]
                    && backup != k
                    && backup != target,
                "draft_invalid"
            );
            payload(&existing["payload"], &r["backup"])?;
            // Backups are always create-if-absent; even a tombstone blocks reuse.
            checks.push((backup.clone(), &Value::Null));
            backup_key = Some(backup);
        }
        target_key = Some(target);
    }
    let conflicts: Vec<_> = checks
        .iter()
        .filter(|(k, e)| !matches(db.documents.get(k), e))
        .map(|(k, _)| json!({"key":k,"latest":db.documents.get(k)}))
        .collect();
    let outcome = if !conflicts.is_empty() {
        // The durable receipt retains the local branch and latest server content.
        json!({"status":"conflict","mutationId":mutation,"local":r,"conflicts":conflicts})
    } else {
        db.sequence = db.sequence.checked_add(1).context("draft_quota")?;
        let rev = revision(&owner, db.sequence);
        let mut changes = Vec::new();
        if op == "transfer" {
            let source = db
                .documents
                .get(&k)
                .filter(|d| d["deleted"] != true)
                .context("draft_invalid")?;
            let content = r.get("payload").unwrap_or(&source["payload"]).clone();
            payload(&content, &r["target"])?; // Cross-host attachments require explicit re-upload first.
            let target = target_key.unwrap();
            if let Some(backup) = backup_key {
                let document = json!({"scope":r["backup"],"revision":rev,"deleted":false,"payload":db.documents[&target]["payload"]});
                db.documents.insert(backup, document.clone());
                changes.push(document);
            }
            let document =
                json!({"scope":r["target"],"revision":rev,"deleted":false,"payload":content});
            db.documents.insert(target, document.clone());
            changes.push(document);
        }
        let document = json!({"scope":scope,"revision":rev,"deleted":op != "put","payload":if op == "put" {r["payload"].clone()} else {Value::Null}});
        db.documents.insert(k, document.clone());
        changes.push(document);
        let event =
            json!({"sequence":db.sequence,"revision":rev,"mutationId":mutation,"changes":changes});
        db.events.push(event.clone());
        json!({"status":"applied","mutationId":mutation,"event":event})
    };
    db.receipts.insert(
        receipt_key,
        Receipt {
            hash,
            outcome: outcome.clone(),
        },
    );
    save(store, &db)?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn scope(id: &str) -> Value {
        json!({"environment":"env","project":"project","kind":"thread","id":id})
    }
    fn put(id: &str, mutation: &str) -> Value {
        json!({"op":"put","scope":scope(id),"expected":null,"mutationId":mutation,"payload":{"schema":1,"text":"private","attachments":[]}})
    }
    #[test]
    fn quota_failure_does_not_partially_transfer_or_discard_tombstones() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let store = Store::open(&dir.path().join("state"), "owner")?;
        let mut db = Database::default();
        for i in 0..MAX_DOCUMENTS {
            let scope = scope(&format!("t{i}"));
            db.documents.insert(key(&scope)?,json!({"scope":scope,"revision":"base","deleted":i>1,"payload":{"schema":1,"text":"preserve","attachments":[]}}));
        }
        save(&store, &db)?;
        let before = fs::read(store.root().join("shared-drafts.json"))?;
        let request = json!({"op":"transfer","scope":scope("t0"),"expected":"base","target":scope("t1"),"targetExpected":"base","backup":{"environment":"env","project":"project","kind":"stash","id":"backup"},"mutationId":"full"});
        assert_eq!(execute(&store, None, &request)["error"], "draft_quota");
        assert_eq!(fs::read(store.root().join("shared-drafts.json"))?, before);
        assert_eq!(
            execute(&store, None, &put("extra", "extra"))["error"],
            "draft_quota"
        );
        Ok(())
    }
    #[test]
    fn receipt_and_byte_quotas_fail_closed_without_expiring_dedupe() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let store = Store::open(&dir.path().join("state"), "owner")?;
        let first = put("t", "first");
        let receipt = execute(&store, None, &first);
        let mut db = load(&store)?;
        for i in 1..MAX_MUTATIONS {
            db.receipts.insert(
                format!("filler-{i}"),
                Receipt {
                    hash: "hash".into(),
                    outcome: json!({"status":"applied"}),
                },
            );
        }
        save(&store, &db)?;
        assert_eq!(execute(&store, None, &first), receipt);
        assert_eq!(
            execute(&store, None, &put("new", "new"))["error"],
            "draft_quota"
        );
        let before = fs::read(store.root().join("shared-drafts.json"))?;
        db.events.push(json!({"tooBig":"x".repeat(MAX_BYTES)}));
        assert_eq!(save(&store, &db).unwrap_err().to_string(), "draft_quota");
        assert_eq!(fs::read(store.root().join("shared-drafts.json"))?, before);
        Ok(())
    }
    #[test]
    fn private_regular_state_only_and_no_runtime_payloads() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let store = Store::open(&dir.path().join("state"), "owner")?;
        let path = store.root().join("shared-drafts.json");
        let mut request = put("t", "m");
        for field in ["outbox", "contentUri", "token", "compositionRange"] {
            request["payload"][field] = json!("forbidden");
            assert_eq!(execute(&store, None, &request)["error"], "draft_invalid");
            request["payload"].as_object_mut().unwrap().remove(field);
        }
        assert!(!path.exists());
        assert_eq!(execute(&store, None, &request)["status"], "applied");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        assert_eq!(
            execute(&store, None, &json!({"op":"list"}))["error"],
            "draft_store_error"
        );
        fs::remove_file(&path)?;
        let outside = dir.path().join("outside");
        fs::write(&outside, "{}").unwrap();
        symlink(&outside, &path)?;
        assert_eq!(
            execute(&store, None, &json!({"op":"list"}))["error"],
            "draft_store_error"
        );
        assert_eq!(fs::read_to_string(outside)?, "{}");
        Ok(())
    }
}
