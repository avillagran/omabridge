use anyhow::Result;
use serde_json::{Value, json};
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn request(state: &std::path::Path, subcommand: &str, value: Value) -> Result<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_omabridge"))
        .arg("--state-dir")
        .arg(state)
        .arg(subcommand)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&value)?.as_bytes())?;
    let output = child.wait_with_output()?;
    assert!(output.stderr.is_empty());
    Ok(serde_json::from_slice(&output.stdout)?)
}
#[test]
fn cli_and_manage_share_private_cas_store_without_logging_content() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let state = dir.path().join("state");
    let _store = omabridge::Store::open(&state, "owner")?;
    let scope = json!({"environment":"env","project":"project","kind":"thread","id":"thread"});
    let put = json!({"op":"put","scope":scope,"expected":null,"mutationId":"cli-first","payload":{"schema":1,"text":"private CLI marker","attachments":[]}});
    let applied = request(&state, "drafts", put.clone())?;
    assert_eq!(applied["status"], "applied");
    assert_eq!(request(&state, "drafts", put)?, applied);
    assert_eq!(
        request(
            &state,
            "manage",
            json!({"action":"drafts","command":{"op":"get","scope":scope}})
        )?["document"]["payload"]["text"],
        "private CLI marker"
    );
    assert_eq!(
        request(
            &state,
            "manage",
            json!({"action":"drafts","command":{"op":"delete","scope":scope,"mutationId":"clear","expected":applied["event"]["revision"]}})
        )?["error"],
        "confirmation_required"
    );
    assert!(!state.join("manage-audit.jsonl").exists());
    Ok(())
}
