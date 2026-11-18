use std::process::Command;

const EXE: &str = env!("CARGO_BIN_EXE_happy-supervisor");

#[cfg(unix)]
#[test]
fn sandbox_helper_runs_before_the_cli_and_rejects_a_bad_frame() {
    use std::io::Write as _;
    use std::process::Stdio;

    let mut child = Command::new(EXE)
        .arg("__sandbox")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&[0, 0, 0, 3, b'{', b'x', b'}'])
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(125));
    assert_eq!(output.stdout, b"");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.starts_with("happy-supervisor __sandbox: bad job: "),
        "{stderr}"
    );
}

#[test]
fn help_lists_the_public_commands_only() {
    let output = Command::new(EXE).arg("--help").output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    let help = String::from_utf8(output.stdout).unwrap();
    for command in ["join", "run", "info"] {
        assert!(help.contains(&format!("  {command} ")), "{help}");
    }
    assert!(!help.contains("__sandbox"), "{help}");
}
