//! An experiment, not a requirement: what a command in an AppContainer started from the test's
//! own (administrator) account can read, write and reach. Prints one line per probe.
#![cfg(windows)]

use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const NAME: &str = "hsbx-probe";

fn winbox() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_happy-supervisor"))
        .parent()
        .unwrap()
        .join(r"examples\winbox.exe")
}

fn system32(exe: &str) -> String {
    format!(r"{}\System32\{exe}", std::env::var("SystemRoot").unwrap())
}

fn show(output: std::process::Output) -> String {
    format!(
        "exit {:?}\n    stdout: {}\n    stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .replace('\n', "\n      "),
        String::from_utf8_lossy(&output.stderr)
            .trim()
            .replace('\n', "\n      ")
    )
}

fn contain(label: &str, caps: &str, argv: &[&str]) {
    let output = Command::new(winbox())
        .args(["container", NAME, caps])
        .args(argv)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    eprintln!("PROBE {label} [{caps}]: {}", show(output));
}

fn admin(label: &str, program: &str, args: &[&str]) {
    let output = Command::new(program)
        .args(args)
        .env_remove("PSModulePath")
        .output()
        .unwrap();
    eprintln!("ADMIN {label}: {}", show(output));
}

fn serve(listener: TcpListener) {
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            let _ = stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n",
            );
        }
    });
}

fn grant(path: &Path, sid: &str, rights: &str) {
    admin(
        &format!("icacls {} {rights}", path.display()),
        "icacls",
        &[
            path.to_str().unwrap(),
            "/grant",
            &format!("*{sid}:(OI)(CI){rights}"),
        ],
    );
}

#[test]
#[ignore = "an experiment; run it by name"]
fn appcontainer_probe() {
    let sid = String::from_utf8(
        Command::new(winbox())
            .args(["package-sid", NAME])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();
    eprintln!("package {sid}");
    admin(
        "firewall",
        "powershell.exe",
        &[
            "-NoProfile",
            "-Command",
            "Get-NetFirewallProfile | % { \"$($_.Name)=$($_.Enabled) in=$($_.DefaultInboundAction) out=$($_.DefaultOutboundAction)\" }",
        ],
    );

    let dir = tempfile::tempdir().unwrap();
    let root = happy_supervisor::policy::canonicalize(dir.path()).unwrap();
    for sub in ["data", "granted", "out"] {
        std::fs::create_dir(root.join(sub)).unwrap();
    }
    std::fs::write(root.join(r"data\file.txt"), "data\n").unwrap();
    std::fs::write(root.join(r"granted\file.txt"), "granted\n").unwrap();
    grant(&root.join("granted"), &sid, "RX");
    grant(&root.join("out"), &sid, "M");
    grant(winbox().parent().unwrap(), &sid, "RX");
    let p = |rel: &str| root.join(rel).to_str().unwrap().to_string();
    let cmd = system32("cmd.exe");
    let curl = system32("curl.exe");
    let powershell = system32(r"WindowsPowerShell\v1.0\powershell.exe");
    let git = r"C:\Program Files\Git\cmd\git.exe";

    contain("cmd echo", "none", &[&cmd, "/c", "echo hi"]);
    contain(
        "read without an ACE",
        "none",
        &[&cmd, "/c", &format!("type {}", p(r"data\file.txt"))],
    );
    contain(
        "read with a package ACE",
        "none",
        &[&cmd, "/c", &format!("type {}", p(r"granted\file.txt"))],
    );
    contain(
        "write with a package ACE",
        "none",
        &[&cmd, "/c", &format!("echo x>{}", p(r"out\a.txt"))],
    );
    contain(
        "write without an ACE",
        "none",
        &[&cmd, "/c", &format!("echo x>{}", p(r"data\b.txt"))],
    );
    contain(
        "read C:\\Windows\\win.ini",
        "none",
        &[&cmd, "/c", r"type C:\Windows\win.ini >NUL && echo read"],
    );
    contain(
        "list the user profile",
        "none",
        &[&cmd, "/c", "dir /b %USERPROFILE%"],
    );
    contain("list C:\\Users", "none", &[&cmd, "/c", r"dir /b C:\Users"]);
    contain(
        "read Program Files",
        "none",
        &[&cmd, "/c", r"dir /b C:\Program Files\Git"],
    );
    contain(
        "powershell",
        "none",
        &[
            &powershell,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "'hi'; $ExecutionContext.SessionState.LanguageMode",
        ],
    );
    contain("git --version", "none", &[git, "--version"]);
    contain(
        "read win.ini without NUL",
        "none",
        &[&cmd, "/c", r"type C:\Windows\win.ini"],
    );
    contain(
        "read hosts without NUL",
        "none",
        &[&cmd, "/c", r"type C:\Windows\System32\drivers\etc\hosts"],
    );
    contain(
        "list Program Files\\Git",
        "none",
        &[&cmd, "/c", r#"dir /b "C:\Program Files\Git""#],
    );
    contain(
        "open NUL from PowerShell",
        "none",
        &[
            &powershell,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            r"try { [IO.File]::OpenWrite('\\.\NUL').Close(); 'nul-ok' } catch { $_.Exception.Message }; try { [IO.File]::ReadAllText('C:\Windows\win.ini').Length } catch { $_.Exception.Message }",
        ],
    );
    admin(
        "NUL's security descriptor",
        "powershell.exe",
        &[
            "-NoProfile",
            "-Command",
            r"$h = [Microsoft.Win32.SafeHandles.SafeFileHandle]; (Get-Item \\.\GLOBALROOT\Device\Null -ErrorAction SilentlyContinue | Get-Acl -ErrorAction SilentlyContinue).Sddl; sc.exe sdshow null",
        ],
    );
    contain(
        "write NUL",
        "none",
        &[&cmd, "/c", "echo x>NUL && echo nul-ok"],
    );
    contain(
        "read hosts",
        "none",
        &[
            &cmd,
            "/c",
            r"type C:\Windows\System32\drivers\etc\hosts >NUL && echo read",
        ],
    );
    admin(
        "acls",
        "powershell.exe",
        &[
            "-NoProfile",
            "-Command",
            r"icacls C:\Windows\win.ini; icacls 'C:\Program Files\Git'; icacls 'C:\Program Files'; icacls C:\Windows\System32\drivers\etc\hosts; (Get-Acl \\.\NUL -ErrorAction SilentlyContinue).Sddl",
        ],
    );
    contain(
        "whoami /groups",
        "none",
        &[&system32("whoami.exe"), "/groups"],
    );

    contain(
        "Schannel https",
        "internetClient",
        &[
            &curl,
            "-sS",
            "--max-time",
            "15",
            "-o",
            "NUL",
            "-w",
            "%{http_code}",
            "https://example.com",
        ],
    );
    contain(
        "git ls-remote (OpenSSL)",
        "internetClient",
        &[
            git,
            "-c",
            "http.sslBackend=openssl",
            "ls-remote",
            "https://github.com/octocat/Hello-World",
            "refs/heads/master",
        ],
    );
    contain(
        "git ls-remote (Schannel)",
        "internetClient",
        &[
            git,
            "-c",
            "http.sslBackend=schannel",
            "ls-remote",
            "https://github.com/octocat/Hello-World",
            "refs/heads/master",
        ],
    );
    contain(
        "http without capabilities",
        "none",
        &[
            &curl,
            "-sS",
            "--max-time",
            "15",
            "-o",
            "NUL",
            "-w",
            "%{http_code}",
            "http://example.com",
        ],
    );
    contain(
        "nslookup without capabilities",
        "none",
        &[&system32("PING.EXE"), "-n", "1", "-w", "500", "example.com"],
    );

    let password = format!("Pr0be!{}", std::process::id());
    admin(
        "create a plain user",
        "powershell.exe",
        &[
            "-NoProfile",
            "-Command",
            &format!(
                "New-LocalUser -Name hsbxplain -Password (ConvertTo-SecureString '{password}' -AsPlainText -Force) -PasswordNeverExpires | Out-Null; 'created'"
            ),
        ],
    );
    for (label, argv) in [
        ("plain user: whoami", vec![system32("whoami.exe")]),
        (
            "plain user, container: cmd echo",
            vec![
                winbox().to_str().unwrap().to_string(),
                "container".into(),
                "hsbx-plain".into(),
                "none".into(),
                cmd.clone(),
                "/c".into(),
                "echo inside".into(),
            ],
        ),
        (
            "plain user, container: read win.ini",
            vec![
                winbox().to_str().unwrap().to_string(),
                "container".into(),
                "hsbx-plain".into(),
                "none".into(),
                cmd.clone(),
                "/c".into(),
                r"type C:\Windows\win.ini >NUL && echo read".into(),
            ],
        ),
        (
            "plain user, container: write NUL",
            vec![
                winbox().to_str().unwrap().to_string(),
                "container".into(),
                "hsbx-plain".into(),
                "none".into(),
                cmd.clone(),
                "/c".into(),
                "echo x>NUL && echo nul-ok".into(),
            ],
        ),
        (
            "plain user, container: git --version",
            vec![
                winbox().to_str().unwrap().to_string(),
                "container".into(),
                "hsbx-plain".into(),
                "none".into(),
                git.to_string(),
                "--version".into(),
            ],
        ),
        (
            "plain user, container: Schannel",
            vec![
                winbox().to_str().unwrap().to_string(),
                "container".into(),
                "hsbx-plain".into(),
                "internetClient".into(),
                curl.clone(),
                "-sS".into(),
                "--max-time".into(),
                "15".into(),
                "-w".into(),
                "%{http_code}".into(),
                "-o".into(),
                r"C:\Users\Public\x".into(),
                "https://example.com".into(),
            ],
        ),
    ] {
        let output = Command::new(winbox())
            .args(["logon", "hsbxplain", &password])
            .args(&argv)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        eprintln!("PROBE {label}: {}", show(output));
    }
    admin(
        "remove the plain user",
        "powershell.exe",
        &[
            "-NoProfile",
            "-Command",
            "Remove-LocalUser -Name hsbxplain; 'removed'",
        ],
    );

    let users_block = Command::new(winbox())
        .args(["wfp-hold", "block-user:S-1-5-32-545:80"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut users_block = users_block;
    let mut ready = [0u8; 5];
    let _ = users_block.stdout.as_mut().unwrap().read_exact(&mut ready);
    for (label, disable) in [
        ("nothing dropped", "none"),
        ("BUILTIN\\Users deny-only", "Users"),
    ] {
        let output = Command::new(winbox())
            .args([
                "escape",
                disable,
                &curl,
                "-sS",
                "--max-time",
                "10",
                "-o",
                "NUL",
                "-w",
                "%{http_code}",
                "http://example.com",
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        eprintln!(
            "PROBE admin, WFP block keyed on BUILTIN\\Users, port 80, {label}: {}",
            show(output)
        );
    }
    drop(users_block.stdin.take());
    let _ = users_block.wait();

    for (rule, cases) in [
        (
            "block-member:S-1-5-32-545:80",
            &[
                ("nothing dropped", "none"),
                ("Users deny-only", "Users"),
                ("Everyone deny-only", "Everyone"),
                ("Users and Everyone deny-only", "Users,Everyone"),
                (
                    "user, Users, Everyone, Administrators deny-only",
                    "user,Users,Everyone,Administrators",
                ),
            ][..],
        ),
        (
            "block-member:S-1-5-32-546:80",
            &[("Guests rule, nothing dropped", "none")][..],
        ),
    ] {
        let mut held = Command::new(winbox())
            .args(["wfp-hold", rule])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = [0u8; 5];
        let got = held.stdout.as_mut().unwrap().read_exact(&mut ready);
        eprintln!("wfp-hold {rule}: {got:?}");
        for (label, disable) in cases {
            let output = Command::new(winbox())
                .args([
                    "escape",
                    disable,
                    &curl,
                    "-sS",
                    "--max-time",
                    "10",
                    "-o",
                    "NUL",
                    "-w",
                    "%{http_code}",
                    "http://example.com",
                ])
                .stdin(Stdio::null())
                .output()
                .unwrap();
            eprintln!("PROBE admin, {rule}, {label}: {}", show(output));
        }
        drop(held.stdin.take());
        let output = held.wait_with_output().unwrap();
        eprintln!("wfp-hold {rule} ended: {}", show(output));
    }

    let in_range = (47800..=47999)
        .find_map(|port| TcpListener::bind((Ipv4Addr::LOCALHOST, port)).ok())
        .unwrap();
    let in_url = format!(
        "http://127.0.0.1:{}/",
        in_range.local_addr().unwrap().port()
    );
    serve(in_range);
    let out_range = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let out_url = format!(
        "http://127.0.0.1:{}/",
        out_range.local_addr().unwrap().port()
    );
    serve(out_range);
    let get = |url: &str| -> Vec<String> {
        [curl.as_str(), "-sS", "--max-time", "10", url]
            .iter()
            .map(|s| s.to_string())
            .collect()
    };
    let contain_owned = |label: &str, caps: &str, argv: Vec<String>| {
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
        contain(label, caps, &argv);
    };
    contain_owned("loopback, no exemption", "none", get(&in_url));
    contain_owned(
        "loopback, no exemption",
        "internetClient,privateNetwork",
        get(&in_url),
    );

    let mut wfp = Command::new(winbox())
        .args([
            "wfp-hold".to_string(),
            format!("block-package:{sid}"),
            format!("permit-package-loopback:{sid}:47800:47999"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = [0u8; 5];
    let held = wfp.stdout.as_mut().unwrap().read_exact(&mut ready);
    eprintln!("wfp-hold: {held:?} {:?}", String::from_utf8_lossy(&ready));
    contain_owned(
        "hard WFP permit, loopback in range, no exemption",
        "none",
        get(&in_url),
    );
    contain_owned(
        "hard WFP permit, loopback out of range, no exemption",
        "none",
        get(&out_url),
    );
    contain_owned(
        "WFP package block, internet with internetClient",
        "internetClient",
        vec![
            curl.clone(),
            "-sS".into(),
            "--max-time".into(),
            "10".into(),
            "-o".into(),
            "NUL".into(),
            "-w".into(),
            "%{http_code}".into(),
            "http://example.com".into(),
        ],
    );

    admin(
        "loopback exemption",
        &system32("CheckNetIsolation.exe"),
        &["LoopbackExempt", "-a", &format!("-p={sid}")],
    );
    contain_owned("exempt + WFP, loopback in range", "none", get(&in_url));
    contain_owned("exempt + WFP, loopback out of range", "none", get(&out_url));
    let escape = |disable: &str, url: &str| -> Vec<String> {
        let mut argv = vec![
            winbox().to_str().unwrap().to_string(),
            "escape".into(),
            disable.into(),
        ];
        argv.extend(get(url));
        argv
    };
    contain_owned(
        "exempt + WFP, out of range, user deny-only inside",
        "none",
        escape("user", &out_url),
    );
    contain_owned(
        "exempt + WFP, internet, user deny-only inside",
        "internetClient",
        escape("user", "http://example.com"),
    );
    drop(wfp.stdin.take());
    let _ = wfp.wait();
    contain_owned(
        "exempt, no WFP, loopback out of range",
        "none",
        get(&out_url),
    );
    admin(
        "remove exemption",
        &system32("CheckNetIsolation.exe"),
        &["LoopbackExempt", "-d", &format!("-p={sid}")],
    );
}
