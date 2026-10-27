use std::process::Command;

#[test]
fn gui_check_uses_real_library_state_without_exposing_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("device");
    let owner = omabridge::Store::open(&state, "desktop").unwrap();
    let key = owner.secret_key().unwrap().to_bytes();
    let units = dir.path().join("units");
    std::fs::create_dir_all(&units).unwrap();
    std::fs::write(
        units.join("omabridge-serve.service"),
        format!("{}\n[Service]\n", omabridge::units::MARKER),
    )
    .unwrap();
    std::fs::write(units.join("omabridge-t3-route.service"), "[Service]\n").unwrap();
    std::fs::write(units.join("other.service"), "[Service]\n").unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_omabridge-gui"))
        .args(["--state-dir", state.to_str().unwrap(), "--check"])
        .arg("--units-dir")
        .arg(&units)
        .env("PATH", "")
        .output()
        .unwrap();
    assert!(result.status.success(), "GUI readback failed");
    let public: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(public["id"], owner.id().unwrap());
    assert_eq!(public["name"], "desktop");
    assert_eq!(public["peers"], 0);
    assert_eq!(public["pending"], 0);
    assert_eq!(public["remote_routes"], 0);
    assert_eq!(public["published"], serde_json::json!([]));
    assert_eq!(
        public["units"], 1,
        "only OmaBridge-created units are counted"
    );
    assert_eq!(public["foreign_units"], 1);
    assert!(!result.stdout.windows(key.len()).any(|bytes| bytes == key));
    assert!(!String::from_utf8_lossy(&result.stderr).contains("secret"));
    std::fs::write(state.join("state.json"), b"corrupt").unwrap();
    let broken = Command::new(env!("CARGO_BIN_EXE_omabridge-gui"))
        .args(["--state-dir", state.to_str().unwrap(), "--check"])
        .output()
        .unwrap();
    assert!(
        !broken.status.success(),
        "GUI must not silently recreate a broken identity"
    );
}
