//! Opt-in per-peer catalog transport. It never reads a desktop credential store.
//! The desktop publisher supplies a sanitized view + descriptor-verified routes.
use crate::Store;
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
};

const FILE: &str = "client-catalog.json";
const MAX_SOURCE: u64 = 1024 * 1024;
fn only(value: &Value, keys: &[&str]) -> Result<()> {
    ensure!(
        value
            .as_object()
            .is_some_and(|o| o.keys().all(|k| keys.contains(&k.as_str()))),
        "invalid catalog source"
    );
    Ok(())
}
fn validate(source: &Value) -> Result<()> {
    only(
        source,
        &[
            "version",
            "revision",
            "environments",
            "endpoints",
            "clients",
        ],
    )?;
    ensure!(
        source["version"] == 1 && source["revision"].is_u64(),
        "invalid catalog source"
    );
    let rows = source["environments"]
        .as_array()
        .context("invalid catalog source")?;
    ensure!(rows.len() <= 128, "catalog source too large");
    for row in rows {
        only(row, &["id", "name", "enabled"])?;
    }
    let clients = source["clients"]
        .as_object()
        .context("invalid catalog clients")?;
    ensure!(
        clients.len() <= 128
            && clients.keys().all(|k| k.len() == 64
                && k.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())),
        "invalid catalog clients"
    );
    ensure!(
        source["endpoints"]
            .as_array()
            .is_some_and(|a| a.len() <= 2048),
        "invalid catalog endpoints"
    );
    for endpoint in source["endpoints"].as_array().unwrap() {
        only(
            endpoint,
            &[
                "environmentId",
                "descriptorEnvironmentId",
                "id",
                "url",
                "priority",
            ],
        )?;
    }
    Ok(())
}

/// Called by an explicitly authorized desktop publisher, not a remote client request.
/// Keeps publication and client grants in a single atomically replaced document.
pub fn publish_source(store: &Store, source: &Value) -> Result<()> {
    publish_inner(store, source.clone(), false).map(|_| ())
}
/// Serialize change detection and revision allocation with publication itself.
pub(crate) fn publish_changed(store: &Store, source: Value) -> Result<bool> {
    publish_inner(store, source, true)
}
fn publish_inner(store: &Store, mut source: Value, changed: bool) -> Result<bool> {
    validate(&source)?;
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(store.root().join(".catalog.lock"))?;
    lock.lock_exclusive()?;
    let path = store.root().join(FILE);
    let old = if path.exists() {
        Some(read_source(store)?)
    } else {
        None
    };
    if changed {
        let revision = old
            .as_ref()
            .and_then(|s| s["revision"].as_u64())
            .unwrap_or(0);
        source["revision"] = json!(revision);
        if old.as_ref() == Some(&source) {
            return Ok(false);
        }
        source["revision"] = json!(
            revision
                .checked_add(1)
                .context("catalog revision exhausted")?
        );
    }
    for (client, authorized) in source["clients"].as_object().unwrap() {
        ensure!(
            store.authorized(client, "t3")?,
            "catalog client must have a current t3 grant"
        );
        t3_protocol::bridge_catalog::publish(&source["environments"],authorized,&source["endpoints"],
            &json!({"bridgeId":store.id()?,"clientId":client,"revision":source["revision"],"now":0}))
            .map_err(|_| anyhow::anyhow!("invalid catalog publication"))?;
    }
    let bytes = serde_json::to_vec(&source)?;
    ensure!(bytes.len() as u64 <= MAX_SOURCE, "catalog source too large");
    if let Some(old) = old {
        ensure!(
            source["revision"].as_u64() > old["revision"].as_u64(),
            "catalog revision must advance"
        );
    }
    // Store's lock serializes its policy state; publication is a separate single-writer API.
    let tmp = store
        .root()
        .join(format!(".catalog-{}", rand::random::<u128>()));
    let result = (|| {
        let mut f = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, &path)?;
        Ok(true)
    })();
    let _ = fs::remove_file(tmp);
    result
}
pub(crate) fn read_source(store: &Store) -> Result<Value> {
    let path = store.root().join(FILE);
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.file_type().is_file()
            && metadata.permissions().mode() & 0o077 == 0
            && metadata.len() <= MAX_SOURCE,
        "catalog source is not private"
    );
    let mut bytes = Vec::new();
    file.take(MAX_SOURCE + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_SOURCE, "catalog source too large");
    let source = serde_json::from_slice(&bytes)?;
    validate(&source)?;
    Ok(source)
}
/// `peer` MUST be the remote authenticated iroh endpoint id, never a request field.
pub(crate) fn read_for_peer(store: &Store, peer: &str, now_ms: u64) -> Result<Value> {
    if !store.authorized(peer, "t3")? {
        return Err(crate::catalog_client::CatalogDenied.into());
    }
    let source = read_source(store)?;
    let allowed = source["clients"]
        .get(peer)
        .ok_or(crate::catalog_client::CatalogDenied)?;
    let manifest = t3_protocol::bridge_catalog::publish(
        &source["environments"],
        allowed,
        &source["endpoints"],
        &json!({"bridgeId":store.id()?,"clientId":peer,"revision":source["revision"],"now":now_ms}),
    )
    .map_err(|_| anyhow::anyhow!("invalid catalog publication"))?;
    // The existing framed control channel is bounded to 64 KiB.
    ensure!(
        serde_json::to_vec(&json!({"result":"catalog","manifest":manifest}))?.len() <= 64 * 1024,
        "catalog response too large"
    );
    Ok(manifest)
}
