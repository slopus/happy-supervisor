//! Pseudo-terminals for `exec.start` with `tty` (api.md): the node keeps the master, and the
//! command gets the slave as its controlling terminal and its stdio.

use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};

use crate::protocol::TtySize;

/// A terminal before the command is spawned.
pub(crate) struct Pty {
    pub(crate) master: File,
    slave: File,
}

impl Pty {
    pub(crate) fn open(size: TtySize) -> io::Result<Pty> {
        // SAFETY: posix_openpt returns a new descriptor or -1, and nothing else owns it.
        let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
        if master < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: as above.
        let master = File::from(unsafe { OwnedFd::from_raw_fd(master) });
        let fd = master.as_raw_fd();
        // SAFETY: fcntl, grantpt and unlockpt act on the descriptor only. macOS's
        // posix_openpt takes no O_CLOEXEC, so the flag is set here, before any spawn sees it.
        let ready = unsafe {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) == 0
                && libc::grantpt(fd) == 0
                && libc::unlockpt(fd) == 0
        };
        if !ready {
            return Err(io::Error::last_os_error());
        }
        let name = slave_name(&master)?;
        let slave = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open(name)?;
        resize(&master, size)?;
        Ok(Pty { master, slave })
    }

    /// Makes the slave `command`'s stdout and stderr, and its stdin unless `job_on_stdin`, and
    /// its controlling terminal. Call after [`super::isolate`], whose new session it needs.
    pub(crate) fn attach(&self, command: &mut Command, job_on_stdin: bool) -> io::Result<()> {
        command
            .stdout(Stdio::from(self.slave.try_clone()?))
            .stderr(Stdio::from(self.slave.try_clone()?));
        if !job_on_stdin {
            command.stdin(Stdio::from(self.slave.try_clone()?));
        }
        // SAFETY: the closure runs in the forked child after stdio is set up and only calls
        // ioctl, which is async-signal-safe.
        unsafe {
            command.pre_exec(|| {
                if libc::ioctl(1, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(())
    }
}

/// Sets the terminal's size; the command gets `SIGWINCH`.
pub(crate) fn resize(master: &File, size: TtySize) -> io::Result<()> {
    let winsize = libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCSWINSZ reads a valid winsize.
    if unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ as _, &winsize) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn slave_name(master: &File) -> io::Result<std::path::PathBuf> {
    let mut buf = [0 as libc::c_char; 128];
    // SAFETY: ptsname_r writes at most `buf.len()` bytes, NUL included.
    let rc = unsafe { libc::ptsname_r(master.as_raw_fd(), buf.as_mut_ptr(), buf.len()) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    Ok(path_of(&buf))
}

#[cfg(target_os = "macos")]
fn slave_name(master: &File) -> io::Result<std::path::PathBuf> {
    let mut buf = [0 as libc::c_char; 128];
    // SAFETY: TIOCPTYGNAME writes a NUL-terminated name of at most 128 bytes.
    if unsafe {
        libc::ioctl(
            master.as_raw_fd(),
            libc::TIOCPTYGNAME as _,
            buf.as_mut_ptr(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(path_of(&buf))
}

fn path_of(buf: &[libc::c_char]) -> std::path::PathBuf {
    use std::os::unix::ffi::OsStrExt as _;
    // SAFETY: both callers' buffers hold a NUL-terminated string.
    let name = unsafe { CStr::from_ptr(buf.as_ptr()) };
    std::ffi::OsStr::from_bytes(name.to_bytes()).into()
}
