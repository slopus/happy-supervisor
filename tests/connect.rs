//! `happy-supervisor __connect <host> <port>` through the real binary, against a stub SOCKS5
//! proxy: what ssh's `ProxyCommand` gets in an isolated command.

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;

const EXE: &str = env!("CARGO_BIN_EXE_happy-supervisor");

/// A SOCKS5 proxy for one connection: it reports the CONNECT target, answers with `reply`, and on
/// success echoes everything back in upper case.
fn stub_socks(reply: u8) -> (String, mpsc::Receiver<(String, u16)>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let (mut client, _) = listener.accept().unwrap();
        let mut greeting = [0u8; 2];
        client.read_exact(&mut greeting).unwrap();
        let mut methods = vec![0u8; greeting[1] as usize];
        client.read_exact(&mut methods).unwrap();
        client.write_all(&[5, 0]).unwrap();
        let mut head = [0u8; 5];
        client.read_exact(&mut head).unwrap();
        assert_eq!(head[..4], [5, 1, 0, 3], "CONNECT to a domain name");
        let mut name = vec![0u8; head[4] as usize];
        client.read_exact(&mut name).unwrap();
        let mut port = [0u8; 2];
        client.read_exact(&mut port).unwrap();
        tx.send((String::from_utf8(name).unwrap(), u16::from_be_bytes(port)))
            .unwrap();
        client
            .write_all(&[5, reply, 0, 1, 127, 0, 0, 1, 0, 0])
            .unwrap();
        if reply != 0 {
            return;
        }
        let mut data = Vec::new();
        client.read_to_end(&mut data).unwrap();
        client.write_all(&data.to_ascii_uppercase()).unwrap();
    });
    (format!("socks5h://{addr}"), rx)
}

fn connect(all_proxy: Option<&str>, args: &[&str], stdin: &[u8]) -> Output {
    let mut command = Command::new(EXE);
    command
        .arg("__connect")
        .args(args)
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(proxy) = all_proxy {
        command.env("ALL_PROXY", proxy);
    }
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn carries_stdio_through_the_socks_proxy() {
    let (proxy, target) = stub_socks(0);
    let output = connect(Some(&proxy), &["github.com", "22"], b"ssh-2.0 hello\n");
    assert_eq!(
        (output.status.code(), output.stdout.as_slice()),
        (Some(0), &b"SSH-2.0 HELLO\n"[..])
    );
    assert_eq!(target.recv().unwrap(), ("github.com".to_string(), 22));
}

#[test]
fn a_refusal_fails_with_the_reply_code() {
    let (proxy, target) = stub_socks(2);
    let output = connect(Some(&proxy), &["evil.test", "22"], b"");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "happy-supervisor __connect: socks5 reply 0x02\n"
    );
    assert_eq!(target.recv().unwrap(), ("evil.test".to_string(), 22));
}

#[test]
fn bad_arguments_and_a_missing_proxy_are_reported() {
    let table: [(Option<&str>, &[&str], &str); 3] = [
        (
            Some("socks5h://127.0.0.1:1"),
            &["host"],
            "usage: __connect <host> <port>",
        ),
        (
            Some("socks5h://127.0.0.1:1"),
            &["host", "port"],
            "usage: __connect <host> <port>",
        ),
        (
            None,
            &["host", "22"],
            "ALL_PROXY does not name a socks5h:// proxy",
        ),
    ];
    for (proxy, args, message) in table {
        let output = connect(proxy, args, b"");
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("happy-supervisor __connect: {message}\n")
        );
    }
}
