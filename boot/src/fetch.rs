//! Downloading a build from where releases are served (deploy/README.md, Hosting). Nothing
//! downloaded is trusted: [`Store::install`] verifies it before it is stored.

use std::path::PathBuf;
use std::time::Duration;

use ureq::tls::{RootCerts, TlsConfig};

use crate::release::{self, FILE};
use crate::store::{Build, Store};

/// Where releases are served unless the installer said otherwise.
pub const DEFAULT_BASE: &str = "https://get.happy.engineering";

const SUMS_LIMIT: u64 = 64 << 10;
const SIG_LIMIT: u64 = 4 << 10;
const BINARY_LIMIT: u64 = 512 << 20;

/// The steps of getting a build, as status reports them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Downloading,
    Verifying,
}

pub struct Fetcher {
    base: String,
    agent: ureq::Agent,
}

impl Fetcher {
    /// Releases at `base`: `https://`, or `http://` for a loopback host, for tests. TLS uses the
    /// platform's verifier and trust store, which outlive any list compiled in.
    pub fn new(base: &str) -> Result<Fetcher, String> {
        let base = base.trim_end_matches('/');
        let loopback = ["http://127.0.0.1:", "http://localhost:", "http://[::1]:"]
            .iter()
            .any(|prefix| base.starts_with(prefix));
        if !base.starts_with("https://") && !loopback {
            return Err(format!("releases must be served over https, not {base}"));
        }
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(600)))
            .timeout_connect(Some(Duration::from_secs(30)))
            .tls_config(
                TlsConfig::builder()
                    .root_certs(RootCerts::PlatformVerifier)
                    .build(),
            )
            .user_agent(concat!("happy-supervisor-boot/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Ok(Fetcher {
            base: base.to_owned(),
            agent,
        })
    }

    fn get(&self, path: &str, limit: u64) -> Result<Vec<u8>, String> {
        let url = format!("{}/{path}", self.base);
        let mut response = self
            .agent
            .get(&url)
            .call()
            .map_err(|err| format!("{url}: {err}"))?;
        response
            .body_mut()
            .with_config()
            .limit(limit)
            .read_to_vec()
            .map_err(|err| format!("{url}: {err}"))
    }

    /// The version `releases/latest` names.
    pub fn latest(&self) -> Result<String, String> {
        let latest = self.get("releases/latest", 256)?;
        let version = String::from_utf8_lossy(&latest).trim().to_owned();
        release::check_version(&version)?;
        Ok(version)
    }

    /// Downloads `version` and stores it once it verifies, reporting each step to `phase`.
    /// Returns the stored binary's path.
    pub fn fetch(
        &self,
        store: &Store,
        version: &str,
        mut phase: impl FnMut(Phase),
    ) -> Result<PathBuf, String> {
        release::check_version(version)?;
        phase(Phase::Downloading);
        let dir = format!("releases/{version}");
        let sums = self.get(&format!("{dir}/SHA256SUMS"), SUMS_LIMIT)?;
        let signature = self.get(&format!("{dir}/SHA256SUMS.minisig"), SIG_LIMIT)?;
        let signature = String::from_utf8(signature)
            .map_err(|_| format!("{version}: SHA256SUMS.minisig is not text"))?;
        // Checked before the large download, so a bad list costs no more.
        release::expected(store.keys(), version, &sums, &signature)?;
        let binary = self.get(&format!("{dir}/{FILE}"), BINARY_LIMIT)?;
        phase(Phase::Verifying);
        store.install(&Build {
            version,
            sums: &sums,
            signature: &signature,
            binary: &binary,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::io::{BufRead as _, BufReader, Write as _};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::release::{hex, sha256};
    use crate::testkit::Signer;

    /// A release server on loopback: `GET /<path>` answers the bytes put there, else `404`.
    #[derive(Clone)]
    pub(crate) struct Server {
        pub base: String,
        files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    }

    impl Server {
        pub(crate) fn start() -> Server {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let files = Arc::new(Mutex::new(HashMap::<String, Vec<u8>>::new()));
            let served = files.clone();
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request = String::new();
                    let _ = reader.read_line(&mut request);
                    loop {
                        let mut header = String::new();
                        if reader.read_line(&mut header).unwrap_or(0) <= 2 {
                            break;
                        }
                    }
                    let path = request.split(' ').nth(1).unwrap_or("/");
                    let body = served.lock().unwrap().get(&path[1..]).cloned();
                    let head = match &body {
                        Some(body) => format!(
                            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                            body.len()
                        ),
                        None => "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                            .to_owned(),
                    };
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(body.as_deref().unwrap_or_default());
                }
            });
            Server { base, files }
        }

        pub(crate) fn put(&self, path: &str, body: impl Into<Vec<u8>>) {
            self.files
                .lock()
                .unwrap()
                .insert(path.to_owned(), body.into());
        }

        /// Release `version` with `binary` as this platform's build, signed by `signer`.
        pub(crate) fn release(&self, signer: &Signer, version: &str, binary: &[u8]) {
            let sums = format!("{}  {FILE}\n", hex(&sha256(binary)));
            let sig = signer.sign(sums.as_bytes(), &format!("happy-supervisor {version}"));
            self.put(&format!("releases/{version}/SHA256SUMS"), sums);
            self.put(&format!("releases/{version}/SHA256SUMS.minisig"), sig);
            self.put(&format!("releases/{version}/{FILE}"), binary);
        }
    }

    #[test]
    fn a_release_is_downloaded_verified_and_stored() {
        let server = Server::start();
        let signer = Signer::new();
        server.release(&signer, "1.0.0", b"one");
        server.put("releases/latest", "1.0.0\n");
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().to_owned(), vec![signer.public()]).unwrap();
        let fetcher = Fetcher::new(&server.base).unwrap();

        assert_eq!(fetcher.latest().as_deref(), Ok("1.0.0"));
        let mut phases = Vec::new();
        let path = fetcher.fetch(&store, "1.0.0", |p| phases.push(p)).unwrap();
        assert_eq!(phases, [Phase::Downloading, Phase::Verifying]);
        assert_eq!(std::fs::read(path).unwrap(), b"one");

        // A binary the list does not name is downloaded, refused, and never stored.
        server.release(&signer, "2.0.0", b"two");
        server.put(&format!("releases/2.0.0/{FILE}"), "tampered");
        assert_eq!(
            fetcher.fetch(&store, "2.0.0", |_| {}),
            Err(format!(
                "2.0.0: the downloaded {FILE} is not the signed build"
            ))
        );
        assert!(store.verified("2.0.0").is_err());

        let missing = fetcher.fetch(&store, "3.0.0", |_| {}).unwrap_err();
        assert!(
            missing.starts_with(&format!("{}/releases/3.0.0/SHA256SUMS: ", server.base)),
            "{missing}"
        );
        assert_eq!(
            Fetcher::new("http://example.com").err(),
            Some("releases must be served over https, not http://example.com".to_owned())
        );
    }
}
