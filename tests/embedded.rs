use omabridge::{
    Store,
    manage::{EmbeddedBackend, ServeBackend},
};
use serde_json::json;
#[test]
fn embedded_publication_persists_and_restarts_without_systemd() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("host"), "host").unwrap();
    let backend = EmbeddedBackend::new(store.clone(), vec!["t3".into()]).unwrap();
    assert!(backend.allows("t3"));
    assert!(!backend.allows("ssh"));
    assert!(backend.publish(&json!({"ssh":true})).is_err());
    let mut events = backend.restart_events().unwrap();
    backend.restart().unwrap();
    assert!(events.has_changed().unwrap());
    events.borrow_and_update();
    backend.unpublish().unwrap();
    assert!(!backend.allows("t3"));
    let reopened = EmbeddedBackend::new(store.clone(), vec!["t3".into()]).unwrap();
    assert!(!reopened.allows("t3"));
    reopened.publish(&json!({"t3":true})).unwrap();
    assert!(backend.allows("t3"));
    std::fs::write(store.root().join("services.json"), "bad json").unwrap();
    assert!(!backend.allows("t3"), "corruption fails closed");
}
