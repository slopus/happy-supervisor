//! On Linux a supervisor running as root refuses to start without `--workload-user`
//! (SECURITY.md; install.md).
#![cfg(target_os = "linux")]

use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_happy-supervisor");

/// Runs the supervisor as uid 0 of a user namespace bubblewrap makes, which is root as far as
/// the process can tell, with `state` writable.
fn as_root(state: &std::path::Path, args: &[&str]) -> Output {
    Command::new("bwrap")
        .args(["--unshare-user", "--uid", "0", "--gid", "0"])
        .args(["--ro-bind", "/", "/"])
        .arg("--bind")
        .args([state, state])
        .args(["--dev", "/dev", "--proc", "/proc", "--"])
        .arg(BIN)
        .args(args)
        .arg("--state-dir")
        .arg(state)
        .output()
        .unwrap()
}

#[test]
fn a_root_supervisor_without_a_workload_user_refuses_to_start() {
    let state = tempfile::tempdir().unwrap();
    for args in [&["info"][..], &["run"]] {
        let output = as_root(state.path(), args);
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert_eq!(output.stdout, b"");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            "happy-supervisor: on Linux a supervisor running as root needs --workload-user, the \
             unprivileged user its commands and file operations run as: see docs/install.md \
             (https://github.com/slopus/happy-supervisor/blob/main/docs/install.md)\n",
            "{args:?}"
        );
    }
}

#[test]
fn a_root_supervisor_with_a_workload_user_says_so() {
    let state = tempfile::tempdir().unwrap();
    let output = as_root(state.path(), &["info", "--workload-user", "nobody"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let info: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        info["identity"],
        serde_json::json!({ "supervisorUser": "root", "workloadUser": "nobody", "root": true })
    );
}
