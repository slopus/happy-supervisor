//! The node's certificate authority (proxy.md, The node's CA) and the leaf certificates it
//! mints for intercepted hosts.

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SerialNumber,
};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration, OffsetDateTime};

use crate::error::{Error, ErrorKind, Result};

const KEY_FILE: &str = "proxy-ca.key";
const CERT_FILE: &str = "proxy-ca.crt";
const BUNDLE_FILE: &str = "ca-bundle.pem";
const CA_COMMON_NAME: &str = "happy-supervisor node CA";
/// Distinct hosts whose TLS configuration stays cached.
const LEAF_CACHE: usize = 256;
const LEAF_LIFETIME: Duration = Duration::days(30);
/// A cached leaf is replaced well before it expires, since a supervisor runs for months.
const LEAF_REFRESH: Duration = Duration::days(7);

/// The loaded CA. Cheap to clone.
#[derive(Clone)]
pub struct NodeCa {
    inner: Arc<CaInner>,
}

struct CaInner {
    issuer: Issuer<'static, KeyPair>,
    cert: CertificateDer<'static>,
    bundle: PathBuf,
    /// One key for every leaf. Leaves exist only in this process, so per-host keys buy nothing.
    leaf_key: KeyPair,
    leaves: Mutex<VecDeque<Leaf>>,
}

struct Leaf {
    host: String,
    minted: OffsetDateTime,
    config: Arc<ServerConfig>,
}

impl NodeCa {
    /// Loads the CA from `private_dir`, creating it on first start, and rewrites
    /// `public_dir/ca-bundle.pem` with the platform's roots followed by the CA. Blocking. Both
    /// directories must exist.
    pub fn load_or_create(private_dir: &Path, public_dir: &Path) -> Result<NodeCa> {
        let (key, cert) = match load(private_dir)? {
            Some(loaded) => loaded,
            None => create(private_dir)?,
        };
        let bundle = public_dir.join(BUNDLE_FILE);
        write_bundle(&bundle, &cert)?;
        Ok(NodeCa {
            inner: Arc::new(CaInner {
                issuer: Issuer::new(ca_params(), key),
                cert,
                bundle,
                leaf_key: KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(rcgen_error)?,
                leaves: Mutex::new(VecDeque::new()),
            }),
        })
    }

    /// `public/ca-bundle.pem`.
    pub fn bundle_path(&self) -> &Path {
        &self.inner.bundle
    }

    /// The CA certificate, DER.
    pub fn cert_der(&self) -> &[u8] {
        &self.inner.cert
    }

    /// A TLS server configuration presenting a leaf for `host`, which must be a lowercase DNS
    /// name. Minted on first use and cached.
    pub(crate) fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let now = OffsetDateTime::now_utc();
        let mut leaves = self.inner.leaves.lock().unwrap();
        if let Some(i) = leaves.iter().position(|leaf| leaf.host == host) {
            let leaf = leaves.remove(i).expect("position is in range");
            if now - leaf.minted < LEAF_REFRESH {
                let config = leaf.config.clone();
                leaves.push_front(leaf);
                return Ok(config);
            }
        }
        let config = Arc::new(self.mint(host, now)?);
        leaves.push_front(Leaf {
            host: host.to_owned(),
            minted: now,
            config: config.clone(),
        });
        leaves.truncate(LEAF_CACHE);
        Ok(config)
    }

    fn mint(&self, host: &str, now: OffsetDateTime) -> Result<ServerConfig> {
        let mut params = CertificateParams::new(vec![host.to_owned()]).map_err(rcgen_error)?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, host);
        params.serial_number = Some(random_serial()?);
        params.not_before = now - Duration::days(1);
        params.not_after = now + LEAF_LIFETIME;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let leaf = params
            .signed_by(&self.inner.leaf_key, &self.inner.issuer)
            .map_err(rcgen_error)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            self.inner.leaf_key.serialize_der(),
        ));
        let mut config = ServerConfig::builder_with_provider(crate::proxy::crypto_provider())
            .with_safe_default_protocol_versions()
            .map_err(tls_error)?
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone(), self.inner.cert.clone()], key)
            .map_err(tls_error)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }
}

/// The CA's identity. The issuer is rebuilt from these on every start, so they must not
/// change while a CA exists: leaves name the CA by this subject.
fn ca_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, CA_COMMON_NAME);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params
}

fn load(private_dir: &Path) -> Result<Option<(KeyPair, CertificateDer<'static>)>> {
    let key_pem = match fs::read_to_string(private_dir.join(KEY_FILE)) {
        Ok(pem) => pem,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let cert_pem = match fs::read(private_dir.join(CERT_FILE)) {
        Ok(pem) => pem,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let key = KeyPair::from_pem(&key_pem).map_err(rcgen_error)?;
    let cert = CertificateDer::from_pem_slice(&cert_pem)
        .map_err(|err| Error::new(ErrorKind::Io, format!("{CERT_FILE} is unreadable: {err}")))?;
    Ok(Some((key, cert)))
}

fn create(private_dir: &Path) -> Result<(KeyPair, CertificateDer<'static>)> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(rcgen_error)?;
    let mut params = ca_params();
    let now = OffsetDateTime::now_utc();
    params.serial_number = Some(random_serial()?);
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(3653);
    let cert = params.self_signed(&key).map_err(rcgen_error)?;
    write_atomically(
        &private_dir.join(KEY_FILE),
        key.serialize_pem().as_bytes(),
        true,
    )?;
    write_atomically(&private_dir.join(CERT_FILE), cert.pem().as_bytes(), false)?;
    Ok((key, cert.der().clone()))
}

fn write_bundle(path: &Path, ca: &CertificateDer<'_>) -> Result<()> {
    let mut pem = String::new();
    for root in rustls_native_certs::load_native_certs().certs {
        pem_encode(&mut pem, &root);
    }
    pem_encode(&mut pem, ca);
    write_atomically(path, pem.as_bytes(), false)
}

fn pem_encode(out: &mut String, der: &[u8]) {
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    out.push_str("-----BEGIN CERTIFICATE-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
}

fn write_atomically(path: &Path, contents: &[u8], owner_only: bool) -> Result<()> {
    let tmp = path.with_extension("tmp");
    // A leftover from a crash would keep its old mode.
    let _ = fs::remove_file(&tmp);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mode = if owner_only { 0o600 } else { 0o644 };
        options.mode(mode);
        let file = options.open(&tmp)?;
        // `mode` is filtered by the umask, and the bundle must be readable by every command.
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        write_and_rename(file, &tmp, path, contents)
    }
    #[cfg(not(unix))]
    {
        let _ = owner_only;
        write_and_rename(options.open(&tmp)?, &tmp, path, contents)
    }
}

fn write_and_rename(mut file: fs::File, tmp: &Path, path: &Path, contents: &[u8]) -> Result<()> {
    file.write_all(contents)?;
    file.sync_all()?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn random_serial() -> Result<SerialNumber> {
    let mut serial = [0u8; 16];
    crate::proxy::random_bytes(&mut serial)?;
    serial[0] &= 0x7f;
    Ok(SerialNumber::from_slice(&serial))
}

fn rcgen_error(err: rcgen::Error) -> Error {
    Error::new(ErrorKind::Io, format!("certificate: {err}"))
}

fn tls_error(err: rustls::Error) -> Error {
    Error::new(ErrorKind::Io, format!("tls: {err}"))
}
