//! Booting one VM (docs/vm-mode.md, Boot): the initramfs from a static build of this binary and
//! the boot's config, the VMM, and a [`Controller`] for the guest's agent over the VMM's vsock.

use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use base64::Engine as _;

use super::cpio::Archive;
use super::guest::{self, Config};
use super::{hvsock, vmm};
use crate::controller::Controller;
use crate::error::{Error, ErrorKind, Result};
use crate::ws::Dialed;

/// The vsock port the guest's agent listens on.
pub const AGENT_PORT: u32 = 1024;

/// How long a guest has to answer, from the VMM's start.
pub const BOOT_TIMEOUT: Duration = Duration::from_secs(30);

/// How much of the console a failed boot reports.
const CONSOLE_TAIL: u64 = 4096;

/// What to boot.
#[derive(Clone, Debug)]
pub struct Boot {
    pub vmm: PathBuf,
    pub kernel: PathBuf,
    /// The supervisor binary the guest runs as its init and agent: a static build of this one.
    pub guest_exe: PathBuf,
    /// The VM's files while it runs: `initrd`, `v.sock`, `console.log`, `vmm.log`. Created
    /// `0700` if missing. A socket path under it must fit in 107 bytes.
    pub run_dir: PathBuf,
    /// The root filesystem: an ext4 image the guest mounts read-write.
    pub root_disk: PathBuf,
    /// The unprivileged account `raw` work runs as in the guest.
    pub user: String,
    pub vcpus: u32,
    pub memory_mib: u64,
}

/// A running VM and the host's link to its agent. Dropping it kills the VMM.
pub struct Vm {
    controller: Controller,
    process: vmm::Process,
    run_dir: PathBuf,
}

impl Vm {
    /// Boots `boot` and returns once the guest's agent has opened a link session, or fails with
    /// the end of the console when the VMM exits or the guest does not answer within
    /// [`BOOT_TIMEOUT`].
    pub async fn boot(boot: &Boot) -> Result<Vm> {
        super::require_static(&boot.guest_exe).map_err(Error::sandbox_unavailable)?;
        std::fs::create_dir_all(&boot.run_dir)?;
        std::fs::set_permissions(&boot.run_dir, std::fs::Permissions::from_mode(0o700))?;
        let vsock = boot.run_dir.join("v.sock");
        let longest = format!("{}_{}", vsock.display(), u32::MAX);
        if longest.len() > 107 {
            return Err(Error::sandbox_unavailable(format!(
                "the VM's run directory is too deep for its vsock socket paths: {longest} is {} \
                 bytes, over 107",
                longest.len()
            )));
        }
        let _ = std::fs::remove_file(&vsock);
        let token = token()?;
        let initramfs = boot.run_dir.join("initrd");
        let config = Config {
            token: token.clone(),
            port: AGENT_PORT,
            user: boot.user.clone(),
            root: "/dev/vda".to_string(),
        };
        write_initramfs(&initramfs, &boot.guest_exe, &config)?;
        let plan = vmm::Plan {
            kernel: boot.kernel.clone(),
            initramfs,
            cmdline: format!("console=ttyS0 quiet -- {} init", guest::ARG),
            vcpus: boot.vcpus,
            memory_mib: boot.memory_mib,
            disks: vec![vmm::Disk {
                path: boot.root_disk.clone(),
                readonly: false,
            }],
            vsock: vsock.clone(),
            console: boot.run_dir.join("console.log"),
        };
        let mut process = vmm::Process::spawn(&boot.vmm, &plan, &boot.run_dir.join("vmm.log"))?;
        let deadline = Instant::now() + BOOT_TIMEOUT;
        let last = loop {
            if let Some(status) = process.exited()? {
                return Err(failed(
                    &boot.run_dir,
                    &format!("the VMM exited ({status}) before the guest answered"),
                ));
            }
            let dial = dialer(vsock.clone(), token.clone());
            match Controller::with_dialer(dial).await {
                Ok(controller) => {
                    return Ok(Vm {
                        controller,
                        process,
                        run_dir: boot.run_dir.clone(),
                    });
                }
                Err(err) if Instant::now() < deadline => {
                    tracing::debug!("the guest does not answer yet: {err}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(err) => break err,
            }
        };
        let _ = process.kill();
        Err(failed(
            &boot.run_dir,
            &format!(
                "the guest did not answer within {} s ({last})",
                BOOT_TIMEOUT.as_secs()
            ),
        ))
    }

    /// The link to the guest's agent, as its control plane.
    pub fn controller(&self) -> &Controller {
        &self.controller
    }

    /// The last 4 KiB of the guest's console.
    pub fn console(&self) -> String {
        tail(&self.run_dir.join("console.log"))
    }

    /// Closes the link and kills the VMM.
    pub fn stop(self) -> Result<ExitStatus> {
        let Vm {
            controller,
            mut process,
            ..
        } = self;
        drop(controller);
        Ok(process.kill()?)
    }
}

/// Dials the agent: `CONNECT` through the VMM's socket, then the WebSocket upgrade with the
/// token.
fn dialer(
    vsock: PathBuf,
    token: String,
) -> impl Fn() -> std::pin::Pin<Box<dyn Future<Output = Result<crate::ws::Socket>> + Send>>
+ Send
+ Sync
+ 'static {
    move || {
        let (vsock, token) = (vsock.clone(), token.clone());
        Box::pin(async move {
            let stream = hvsock::connect(&vsock, AGENT_PORT).await.map_err(|err| {
                Error::new(ErrorKind::Io, format!("connecting to the guest: {err}"))
            })?;
            match crate::ws::dial_over(stream, &token).await {
                Ok(Dialed::Open(socket)) => Ok(*socket),
                Ok(Dialed::Refused(status)) => Err(Error::new(
                    ErrorKind::PermissionDenied,
                    format!("the guest's agent refused the token ({status})"),
                )),
                Err(err) => Err(Error::new(
                    ErrorKind::Io,
                    format!("upgrading to the guest: {err}"),
                )),
            }
        })
    }
}

/// 32 random bytes, base64url: the agent's token for this boot.
fn token() -> Result<String> {
    let mut bytes = [0u8; 32];
    crate::proxy::random_bytes(&mut bytes)?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

/// The initramfs: the mount points init needs, a console, the guest binary as `/init`, then a
/// second archive with the boot's config. Owner-only, since the config holds the token.
fn write_initramfs(path: &Path, guest_exe: &Path, config: &Config) -> Result<()> {
    use std::io::Write as _;

    let mut base = Archive::new();
    for dir in ["dev", "proc", "sys", "newroot"] {
        base.directory(dir, 0o755);
    }
    base.character_device("dev/console", 0o600, 5, 1);
    base.file("init", 0o755, &std::fs::read(guest_exe)?);
    let mut boot = Archive::new();
    let json =
        serde_json::to_vec(config).map_err(|err| Error::new(ErrorKind::Io, err.to_string()))?;
    boot.file(guest::CONFIG, 0o400, &json);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&base.finish())?;
    file.write_all(&boot.finish())?;
    Ok(())
}

/// A failed boot's error: `what`, then the end of the console and of the VMM's own log.
fn failed(run_dir: &Path, what: &str) -> Error {
    Error::new(
        ErrorKind::Io,
        format!(
            "{what}\n--- console ---\n{}\n--- vmm ---\n{}",
            tail(&run_dir.join("console.log")),
            tail(&run_dir.join("vmm.log"))
        ),
    )
}

fn tail(path: &Path) -> String {
    let Ok(mut file) = std::fs::File::open(path) else {
        return String::new();
    };
    let length = file.metadata().map_or(0, |meta| meta.len());
    let _ = file.seek(SeekFrom::Start(length.saturating_sub(CONSOLE_TAIL)));
    let mut bytes = Vec::new();
    let _ = file.read_to_end(&mut bytes);
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_initramfs_is_two_archives_and_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("exe");
        std::fs::write(&exe, b"\x7fELF-not-really").unwrap();
        let path = dir.path().join("initrd");
        let config = Config {
            token: "tok".to_string(),
            port: 1024,
            user: "happy".to_string(),
            root: "/dev/vda".to_string(),
        };
        write_initramfs(&path, &exe, &config).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let trailers = bytes.windows(10).filter(|w| *w == b"TRAILER!!!").count();
        assert_eq!(trailers, 2);
        let json = br#"{"token":"tok","port":1024,"user":"happy","root":"/dev/vda"}"#;
        assert!(bytes.windows(json.len()).any(|w| w == json));
        assert!(bytes.windows(15).any(|w| w == b"\x7fELF-not-really"));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
