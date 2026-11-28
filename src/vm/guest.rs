//! The guest's side (docs/vm-mode.md, Boot): `happy-supervisor __vm init`, PID 1 in the
//! initramfs, and `__vm agent`, the `serve` node it starts once the root is in place.
//!
//! The kernel runs `/init` (this binary) with the arguments after `--` on its command line. Init
//! mounts the kernel filesystems and the root disk, binds itself read-only into a tmpfs at
//! `/.happy-supervisor` in the new root, switches to it, and starts the agent. It stays PID 1,
//! reaping orphans, and powers the VM off when the agent exits, so the VMM exits too. Anything
//! that fails before the agent runs is printed to the console and powers off.

use std::ffi::CString;
use std::io;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::ExitCode;

use serde::{Deserialize, Serialize};

/// The argument that makes this binary a VM's init or agent.
pub const ARG: &str = "__vm";

/// The boot config's path in the initramfs. It is the second archive of the initramfs, so it
/// never reaches a disk, and init removes it once read.
pub const CONFIG: &str = "vm.json";

/// The tmpfs in the guest's root holding this binary, the agent's config and its state.
pub const DIR: &str = "/.happy-supervisor";

/// The guest's view of one boot, written by the host (vm/boot.rs).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    /// What a connection to the agent must present (serve.md).
    pub token: String,
    /// The vsock port the agent listens on.
    pub port: u32,
    /// The unprivileged account `raw` work runs as, which the root's `/etc/passwd` must have.
    pub user: String,
    /// The root filesystem's block device, ext4.
    pub root: String,
}

/// `__vm init` or `__vm agent`, with the arguments after `__vm`.
pub fn main(mut args: impl Iterator<Item = String>) -> ExitCode {
    match args.next().as_deref() {
        Some("init") => init(),
        Some("agent") => agent(),
        other => {
            eprintln!("happy-supervisor: __vm takes init or agent, not {other:?}");
            ExitCode::from(2)
        }
    }
}

fn init() -> ! {
    // SAFETY: getpid has no memory effects.
    if unsafe { libc::getpid() } != 1 {
        eprintln!("happy-supervisor: __vm init runs only as a VM's PID 1");
        std::process::exit(2);
    }
    let error = match boot() {
        Ok(agent) => reap(agent),
        Err(err) => err,
    };
    eprintln!("happy-supervisor: vm init: {error}");
    power_off()
}

/// Everything before the agent runs. Returns the agent's PID.
fn boot() -> io::Result<libc::pid_t> {
    mount("devtmpfs", "/dev", "devtmpfs", libc::MS_NOSUID, "mode=0755")?;
    let kernel = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
    mount("proc", "/proc", "proc", kernel, "")?;
    mount("sysfs", "/sys", "sysfs", kernel, "")?;
    let config: Config = serde_json::from_slice(&std::fs::read(Path::new("/").join(CONFIG))?)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, format!("{CONFIG}: {err}")))?;
    std::fs::remove_file(Path::new("/").join(CONFIG))?;

    wait_for(&config.root)?;
    mount(&config.root, "/newroot", "ext4", 0, "")?;
    for dir in ["dev", "proc", "sys", "tmp", "run", &DIR[1..]] {
        match std::fs::create_dir(Path::new("/newroot").join(dir)) {
            Err(err) if err.kind() != io::ErrorKind::AlreadyExists => return Err(err),
            _ => {}
        }
    }
    let dir = format!("/newroot{DIR}");
    mount(
        "tmpfs",
        &dir,
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV,
        "mode=0755",
    )?;
    // Bound, not copied: the binary is the initramfs's largest file, and a copy would hold it
    // in the guest's memory twice.
    std::fs::set_permissions("/init", std::fs::Permissions::from_mode(0o555))?;
    let exe = format!("{dir}/happy-supervisor");
    std::fs::File::create(&exe)?;
    mount("/init", &exe, "", libc::MS_BIND, "")?;
    mount(
        "",
        &exe,
        "",
        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV,
        "",
    )?;
    write_private(&format!("{dir}/agent.json"), &serde_json::to_vec(&config)?)?;
    std::fs::create_dir(format!("{dir}/state"))?;
    std::fs::set_permissions(
        format!("{dir}/state"),
        std::fs::Permissions::from_mode(0o700),
    )?;
    let scratch = libc::MS_NOSUID | libc::MS_NODEV;
    mount("tmpfs", "/newroot/tmp", "tmpfs", scratch, "mode=1777")?;
    mount("tmpfs", "/newroot/run", "tmpfs", scratch, "mode=0755")?;
    for kernel_fs in ["dev", "proc", "sys"] {
        move_mount(&format!("/{kernel_fs}"), &format!("/newroot/{kernel_fs}"))?;
    }
    switch_root("/newroot")?;
    mount("cgroup2", "/sys/fs/cgroup", "cgroup2", kernel, "nsdelegate")?;
    loopback_up()?;

    let agent = std::process::Command::new(format!("{DIR}/happy-supervisor"))
        .args([ARG, "agent"])
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .current_dir("/")
        .spawn()?;
    Ok(agent.id() as libc::pid_t)
}

/// Reaps every child until the agent exits, then says how it ended.
fn reap(agent: libc::pid_t) -> io::Error {
    loop {
        let mut status = 0;
        // SAFETY: waitpid writes only `status`.
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if pid == agent {
            return io::Error::other(format!("the agent ended with wait status {status:#x}"));
        }
        if pid < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                return err;
            }
        }
    }
}

fn power_off() -> ! {
    // SAFETY: sync and reboot take no pointers. RB_POWER_OFF does not return when it works.
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_POWER_OFF);
    }
    eprintln!(
        "happy-supervisor: vm init: power off failed: {}",
        io::Error::last_os_error()
    );
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

/// The kernel probes virtio devices before it runs init, but may still be creating their
/// nodes. Waits up to 5 s for `device`.
fn wait_for(device: &str) -> io::Result<()> {
    for _ in 0..100 {
        if Path::new(device).exists() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("the root device {device} did not appear"),
    ))
}

/// A file only root can read, written whole.
fn write_private(path: &str, data: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)?
        .write_all(data)
}

fn cstring(text: &str) -> io::Result<CString> {
    CString::new(text).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a NUL in a path"))
}

fn mount(
    source: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
    data: &str,
) -> io::Result<()> {
    let (source_c, target_c, fstype_c, data_c) = (
        cstring(source)?,
        cstring(target)?,
        cstring(fstype)?,
        cstring(data)?,
    );
    // SAFETY: every pointer is a NUL-terminated string that lives across the call.
    let mounted = unsafe {
        libc::mount(
            source_c.as_ptr(),
            target_c.as_ptr(),
            fstype_c.as_ptr(),
            flags,
            data_c.as_ptr().cast(),
        )
    };
    if mounted != 0 {
        let err = io::Error::last_os_error();
        return Err(io::Error::new(
            err.kind(),
            format!("mounting {fstype} {source} on {target}: {err}"),
        ));
    }
    Ok(())
}

fn move_mount(from: &str, to: &str) -> io::Result<()> {
    let (from_c, to_c) = (cstring(from)?, cstring(to)?);
    // SAFETY: both pointers are NUL-terminated strings that live across the call; MS_MOVE
    // ignores the type and data.
    if unsafe {
        libc::mount(
            from_c.as_ptr(),
            to_c.as_ptr(),
            std::ptr::null(),
            libc::MS_MOVE,
            std::ptr::null(),
        )
    } != 0
    {
        let err = io::Error::last_os_error();
        return Err(io::Error::new(
            err.kind(),
            format!("moving {from} to {to}: {err}"),
        ));
    }
    Ok(())
}

/// What `switch_root` does: the new root moves over `/`, and the process chroots into it.
fn switch_root(new_root: &str) -> io::Result<()> {
    std::env::set_current_dir(new_root)?;
    move_mount(".", "/")?;
    let dot = cstring(".")?;
    // SAFETY: `dot` is a NUL-terminated string that lives across the call.
    if unsafe { libc::chroot(dot.as_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    std::env::set_current_dir("/")
}

/// Brings `lo` up, which a fresh kernel leaves down.
fn loopback_up() -> io::Result<()> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

    // SAFETY: socket takes no pointers; the descriptor it returns is owned by nothing else.
    let socket = unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        OwnedFd::from_raw_fd(fd)
    };
    // SAFETY: ifreq is plain data, so zeroed is valid; its name is filled below, NUL-terminated.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (slot, byte) in request.ifr_name.iter_mut().zip(b"lo\0") {
        *slot = *byte as libc::c_char;
    }
    // SAFETY: SIOCGIFFLAGS and SIOCSIFFLAGS read and write `request`, which lives across the
    // calls; the flags are the union's member these requests use.
    unsafe {
        if libc::ioctl(
            socket.as_raw_fd(),
            libc::SIOCGIFFLAGS as libc::Ioctl,
            &mut request,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
        request.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
        if libc::ioctl(
            socket.as_raw_fd(),
            libc::SIOCSIFFLAGS as libc::Ioctl,
            &request,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// The agent: a `serve` node on the boot's vsock port, with its state on the tmpfs, running
/// `raw` work as the boot's unprivileged user (policy.md, Workload user).
fn agent() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("happy-supervisor: vm agent: cannot start the runtime: {err}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(serve()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("happy-supervisor: vm agent: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn serve() -> crate::Result<()> {
    let config: Config = serde_json::from_slice(&std::fs::read(format!("{DIR}/agent.json"))?)
        .map_err(|err| crate::Error::invalid_params(format!("agent.json: {err}")))?;
    let state = crate::state::StateDir::open(Some(format!("{DIR}/state").into()))?
        .with_workload_user(Some(config.user.clone()));
    crate::identity::Identity::resolve(state.workload_user()?.as_deref())?;
    crate::init_limits();
    let listening = |addr: String| eprintln!("happy-supervisor: vm agent listening on {addr}");
    crate::serve::serve_until(
        state,
        crate::serve::Listen::Vsock(config.port),
        config.token,
        listening,
        std::future::pending(),
    )
    .await?;
    Ok(())
}
