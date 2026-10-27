use omabridge::units::{MARKER, RunOutput, Runner, UnitContext, UnitSpec, Units};
use std::os::unix::fs::PermissionsExt;
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct FakeRunner {
    calls: Mutex<Vec<Vec<String>>>,
    active: Mutex<String>,
}
impl Runner for FakeRunner {
    fn run(&self, args: &[&str]) -> anyhow::Result<RunOutput> {
        self.calls
            .lock()
            .unwrap()
            .push(args.iter().map(|a| a.to_string()).collect());
        let active = self.active.lock().unwrap().clone();
        let stdout = match args.first().copied() {
            Some("is-active") => format!("{active}\n"),
            Some("is-enabled") => "enabled\n".to_owned(),
            _ => String::new(),
        };
        Ok(RunOutput {
            success: args.first() != Some(&"is-active") || active == "active",
            stdout,
            stderr: String::new(),
        })
    }
}

const PEER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn context(root: &std::path::Path) -> UnitContext {
    UnitContext {
        binary: root.join("bin/omabridge"),
        state_dir: root.join("state"),
        name: "desktop".to_owned(),
        bind: Some("0.0.0.0:41234".parse().unwrap()),
    }
}

fn serve() -> UnitSpec {
    UnitSpec::Serve {
        services: vec![
            ("t3".to_owned(), "127.0.0.1:3773".parse().unwrap()),
            ("api".to_owned(), "127.0.0.1:8080".parse().unwrap()),
        ],
    }
}

fn forward() -> UnitSpec {
    UnitSpec::Forward {
        peer: PEER.to_owned(),
        service: "t3".to_owned(),
        listen: "127.0.0.1:43773".parse().unwrap(),
    }
}

#[test]
fn renders_absolute_validated_exec_lines() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(dir.path());
    let bin = ctx.binary.display().to_string();
    let state = ctx.state_dir.display().to_string();
    assert_eq!(serve().unit_name().unwrap(), "omabridge-serve.service");
    assert_eq!(
        forward().unit_name().unwrap(),
        "omabridge-forward-01234567-t3.service"
    );
    let text = omabridge::units::render(&ctx, &serve()).unwrap();
    assert!(text.starts_with(MARKER));
    assert!(text.contains(&format!(
        "ExecStart={bin} --state-dir {state} --name desktop --bind 0.0.0.0:41234 serve --service t3=127.0.0.1:3773 --service api=127.0.0.1:8080\n"
    )));
    assert!(text.contains("WantedBy=default.target"));
    let text = omabridge::units::render(&ctx, &forward()).unwrap();
    assert!(text.contains(&format!(
        "ExecStart={bin} --state-dir {state} --name desktop --bind 0.0.0.0:41234 forward --peer {PEER} --service t3 --listen 127.0.0.1:43773\n"
    )));
    let no_bind = UnitContext { bind: None, ..ctx };
    assert!(
        !omabridge::units::render(&no_bind, &forward())
            .unwrap()
            .contains("--bind")
    );
}

#[test]
fn rejects_injection_and_non_loopback_targets() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(dir.path());
    let render = |ctx: &UnitContext, spec: &UnitSpec| omabridge::units::render(ctx, spec);
    let target = |name: &str, addr: &str| UnitSpec::Serve {
        services: vec![(name.to_owned(), addr.parse().unwrap())],
    };
    for bad in [
        target("t3", "192.168.1.5:3773"),
        target("t3", "127.0.0.1:0"),
        target("t3 x", "127.0.0.1:1"),
        target("-x", "127.0.0.1:1"),
        target("a;b", "127.0.0.1:1"),
        target("$HOME", "127.0.0.1:1"),
        target("%h", "127.0.0.1:1"),
        UnitSpec::Serve { services: vec![] },
        UnitSpec::Serve {
            services: vec![
                ("t3".into(), "127.0.0.1:1".parse().unwrap()),
                ("t3".into(), "127.0.0.1:2".parse().unwrap()),
            ],
        },
        UnitSpec::Forward {
            peer: PEER.to_uppercase(),
            service: "t3".into(),
            listen: "127.0.0.1:1".parse().unwrap(),
        },
        UnitSpec::Forward {
            peer: format!("{PEER} --x"),
            service: "t3".into(),
            listen: "127.0.0.1:1".parse().unwrap(),
        },
        UnitSpec::Forward {
            peer: PEER.into(),
            service: "t3".into(),
            listen: "0.0.0.0:43773".parse().unwrap(),
        },
        UnitSpec::Forward {
            peer: PEER.into(),
            service: "t3\nExecStartPre=/bin/sh".into(),
            listen: "127.0.0.1:1".parse().unwrap(),
        },
    ] {
        assert!(render(&ctx, &bad).is_err(), "accepted {bad:?}");
    }
    for ctx in [
        UnitContext {
            binary: PathBuf::from("omabridge"),
            ..context(dir.path())
        },
        UnitContext {
            binary: dir.path().join("my bin/omabridge"),
            ..context(dir.path())
        },
        UnitContext {
            state_dir: dir.path().join("state;rm -rf ~"),
            ..context(dir.path())
        },
        UnitContext {
            state_dir: dir.path().join("$HOME"),
            ..context(dir.path())
        },
        UnitContext {
            name: "my\nExecStartPre=/bin/sh".into(),
            ..context(dir.path())
        },
        UnitContext {
            name: "a b".into(),
            ..context(dir.path())
        },
    ] {
        assert!(render(&ctx, &serve()).is_err());
    }
}

#[test]
fn installs_private_marked_units_and_never_touches_foreign_files() {
    let dir = tempfile::tempdir().unwrap();
    let units_dir = dir.path().join("systemd/user");
    let runner = Arc::new(FakeRunner::default());
    let units = Units::new(units_dir.clone(), runner.clone());
    let ctx = context(dir.path());
    let installed = units.install(&ctx, &serve()).unwrap();
    assert_eq!(installed, units_dir.join("omabridge-serve.service"));
    let mode = fs::metadata(&installed).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o644);
    // Re-installing an OmaBridge-owned unit replaces it.
    units.install(&ctx, &serve()).unwrap();
    assert_eq!(
        runner.calls.lock().unwrap().as_slice(),
        [vec!["daemon-reload"], vec!["daemon-reload"]]
    );

    let foreign = units_dir.join("omabridge-forward-01234567-t3.service");
    fs::write(&foreign, "[Service]\nExecStart=/usr/bin/true\n").unwrap();
    assert!(units.install(&ctx, &forward()).is_err());
    assert!(
        units
            .remove("omabridge-forward-01234567-t3.service")
            .is_err()
    );
    assert!(
        units
            .enable_now("omabridge-forward-01234567-t3.service")
            .is_err()
    );
    assert_eq!(
        fs::read_to_string(&foreign).unwrap(),
        "[Service]\nExecStart=/usr/bin/true\n"
    );
    fs::write(units_dir.join("unrelated.service"), "x").unwrap();
    let listed = units.list().unwrap();
    let names: Vec<_> = listed
        .iter()
        .map(|u| (u.name.as_str(), u.managed))
        .collect();
    assert_eq!(
        names,
        [
            ("omabridge-forward-01234567-t3.service", false),
            ("omabridge-serve.service", true)
        ]
    );

    for bad in [
        "../x.service",
        "omabridge-serve",
        "unrelated.service",
        "a/b",
    ] {
        assert!(units.status(bad).is_err(), "accepted {bad}");
        assert!(units.remove(bad).is_err());
    }
    runner.calls.lock().unwrap().clear();
    *runner.active.lock().unwrap() = "active".into();
    units.enable_now("omabridge-serve.service").unwrap();
    let status = units.status("omabridge-serve.service").unwrap();
    assert_eq!(
        (
            status.active.as_str(),
            status.enabled.as_str(),
            status.managed
        ),
        ("active", "enabled", true)
    );
    // A unit that is still active after disable is never deleted.
    assert!(units.remove("omabridge-serve.service").is_err());
    assert!(installed.exists());
    *runner.active.lock().unwrap() = "inactive".into();
    units.disable_now("omabridge-serve.service").unwrap();
    units.remove("omabridge-serve.service").unwrap();
    assert!(!installed.exists());
    let calls = runner.calls.lock().unwrap().clone();
    assert_eq!(calls[0], ["enable", "--now", "omabridge-serve.service"]);
    assert!(calls.contains(&vec![
        "disable".to_owned(),
        "--now".to_owned(),
        "omabridge-serve.service".to_owned()
    ]));
    assert_eq!(calls.last().unwrap(), &["daemon-reload"]);
}

#[test]
fn status_output_is_bounded_and_sanitized() {
    struct Noisy;
    impl Runner for Noisy {
        fn run(&self, _: &[&str]) -> anyhow::Result<RunOutput> {
            Ok(RunOutput {
                success: false,
                stdout: "\u{1b}[31mweird output with spaces\n".into(),
                stderr: String::new(),
            })
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let units = Units::new(dir.path().to_path_buf(), Arc::new(Noisy));
    let status = units.status("omabridge-serve.service").unwrap();
    assert_eq!(status.active, "unknown");
    assert!(!status.managed);
}

#[test]
fn tracked_t3_units_require_an_explicit_safe_runtime_and_service() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(dir.path());
    let tracked = |path: &str, name: &str| UnitSpec::ServeTracked {
        services: vec![(name.into(), "127.0.0.1:3773".parse().unwrap())],
        t3_runtime: path.into(),
    };
    let valid = tracked("/tmp/t3/userdata/server-runtime.json", "t3");
    assert!(
        omabridge::units::render(&ctx, &valid)
            .unwrap()
            .contains("--t3-runtime /tmp/t3/userdata/server-runtime.json")
    );
    for path in [
        "relative.json",
        "/tmp/t3 runtime.json",
        "/tmp/%h.json",
        "/tmp/$HOME.json",
    ] {
        assert!(omabridge::units::render(&ctx, &tracked(path, "t3")).is_err());
    }
    assert!(omabridge::units::render(&ctx, &tracked("/tmp/runtime.json", "ssh")).is_err());
}
