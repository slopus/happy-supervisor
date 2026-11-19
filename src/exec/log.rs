//! Output logs (api.md, Output logs): a size-limited record of a process's combined output that
//! keeps the head and the most recent tail and drops the middle.
//!
//! [`Window`] is the offset arithmetic alone. The sinks, [`MemoryLog`] and [`FileLog`], store
//! the bytes it says to keep, and [`Log`] is either of them or a discarded memory log.

use std::ffi::OsString;
use std::fs::File;
use std::io::Write as _;
use std::ops::Range;
use std::path::Path;

use crate::error::{Error, Result};
use crate::protocol::ByteRange;

/// Which logical bytes of a log are retained. Offsets count everything the process wrote.
///
/// The head is `[0, limit / 4)`. The tail is `[tail_start, total)`. Before anything is dropped
/// `tail_start` is the head's end, so head and tail are one contiguous range. When the retained
/// bytes would pass `limit`, `tail_start` jumps so that the tail keeps about half of `limit`.
/// Between jumps the tail grows to about three quarters, so a file log is rewritten once per
/// quarter of `limit` at most.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    limit: u64,
    total: u64,
    tail_start: u64,
}

/// Where the bytes of one appended chunk go, in logical offsets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Append {
    /// The part of the chunk that lands in the head, empty at the chunk's start if none.
    pub head: Range<u64>,
    /// How many of the previously retained tail bytes are dropped from the tail's front.
    pub dropped: u64,
    /// The part of the chunk kept in the tail. Chunk bytes between `head` and `tail` are dropped.
    pub tail: Range<u64>,
}

impl Window {
    pub fn new(limit: u64) -> Window {
        Window {
            limit,
            total: 0,
            tail_start: limit / 4,
        }
    }

    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn head_end(&self) -> u64 {
        self.limit / 4
    }

    pub fn tail_start(&self) -> u64 {
        self.tail_start
    }

    /// Bytes dropped from the middle so far.
    pub fn omitted(&self) -> u64 {
        self.tail_start - self.head_end()
    }

    /// Records `len` more bytes of output.
    pub fn append(&mut self, len: u64) -> Append {
        let before = *self;
        self.total += len;
        let head_end = self.head_end();
        let retained = self.total.min(head_end) + self.total.saturating_sub(self.tail_start);
        if retained > self.limit {
            self.tail_start = self.total - (self.limit - 2 * head_end);
        }
        let old_tail = before
            .tail_start
            .max(head_end)
            .min(before.total.max(head_end));
        Append {
            head: before.total..self.total.min(head_end).max(before.total),
            dropped: self.tail_start.min(before.total).saturating_sub(old_tail),
            tail: before.total.max(self.tail_start).min(self.total)..self.total,
        }
    }

    /// The retained ranges, at most two, none empty.
    pub fn retained(&self) -> Vec<ByteRange> {
        let ranges = if self.omitted() == 0 {
            [0..self.total, 0..0]
        } else {
            [0..self.head_end(), self.tail_start..self.total]
        };
        ranges
            .into_iter()
            .filter(|r| !r.is_empty())
            .map(|r| ByteRange {
                start: r.start,
                end: r.end,
            })
            .collect()
    }

    /// The range an `exec.log` read of `length` bytes at `offset` answers: it starts at the next
    /// retained byte and stops at the end of the retained range it starts in.
    pub fn read(&self, offset: u64, length: u64) -> Range<u64> {
        let mut start = offset.min(self.total);
        let mut end = self.total;
        if self.omitted() > 0 {
            if start < self.head_end() {
                end = self.head_end();
            } else {
                start = start.max(self.tail_start);
            }
        }
        start..end.min(start.saturating_add(length))
    }
}

/// A log held in the supervisor's memory.
#[derive(Debug)]
pub struct MemoryLog {
    window: Window,
    head: Vec<u8>,
    tail: std::collections::VecDeque<u8>,
}

impl MemoryLog {
    pub fn new(limit: u64) -> MemoryLog {
        MemoryLog {
            window: Window::new(limit),
            head: Vec::new(),
            tail: std::collections::VecDeque::new(),
        }
    }

    pub fn append(&mut self, chunk: &[u8]) {
        let start = self.window.total();
        let append = self.window.append(chunk.len() as u64);
        let slice = |r: &Range<u64>| &chunk[(r.start - start) as usize..(r.end - start) as usize];
        self.head.extend_from_slice(slice(&append.head));
        self.tail.drain(..append.dropped as usize);
        self.tail.extend(slice(&append.tail));
    }

    /// The bytes it holds, which count against the node's memory log budget once it exited.
    pub fn held_bytes(&self) -> u64 {
        (self.head.len() + self.tail.len()) as u64
    }

    pub fn shrink(&mut self) {
        self.head.shrink_to_fit();
        self.tail.shrink_to_fit();
    }

    fn copy(&self, range: Range<u64>) -> Vec<u8> {
        let head_end = self.head.len() as u64;
        let mut out = Vec::with_capacity((range.end - range.start) as usize);
        if range.start < head_end {
            out.extend_from_slice(
                &self.head[range.start as usize..range.end.min(head_end) as usize],
            );
        }
        let tail_start = self.window.tail_start();
        if range.end > tail_start {
            let from = (range.start.max(tail_start) - tail_start) as usize;
            let to = (range.end - tail_start) as usize;
            out.extend(self.tail.range(from..to));
        }
        out
    }
}

/// Where a file log lives: its directory and its name there. On Unix the directory is held
/// open and the log is named only relative to it, so a rewrite never follows a path that changed
/// after the log was created, whoever controls the directory (a workload user, policy.md).
#[derive(Debug)]
pub struct Place {
    #[cfg(unix)]
    dir: std::os::fd::OwnedFd,
    #[cfg(windows)]
    dir: std::path::PathBuf,
    name: OsString,
}

impl Place {
    /// Opens `path`'s directory, which must exist, and creates or truncates the log in it, as
    /// this process's user.
    pub fn create(path: &Path) -> Result<(Place, File)> {
        let (parent, name) = match (path.parent(), path.file_name()) {
            (Some(parent), Some(name)) => (parent, name.to_os_string()),
            _ => {
                return Err(Error::invalid_params(format!(
                    "{} names no file",
                    path.display()
                )));
            }
        };
        #[cfg(unix)]
        let place = {
            use nix::fcntl::OFlag;
            // O_PATH needs only search permission on the directory.
            #[cfg(target_os = "linux")]
            let flags = OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC;
            #[cfg(not(target_os = "linux"))]
            let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC;
            let dir = nix::fcntl::open(parent, flags, nix::sys::stat::Mode::empty())
                .map_err(std::io::Error::from)?;
            Place { dir, name }
        };
        #[cfg(windows)]
        let place = Place {
            dir: parent.to_path_buf(),
            name,
        };
        let file = place.open(&place.name, false)?;
        Ok((place, file))
    }

    /// Opens `name` in the directory for reading and writing, truncated. `fresh` makes it
    /// anew, never through what is there, replacing a file or symlink of that name.
    fn open(&self, name: &OsString, fresh: bool) -> Result<File> {
        #[cfg(unix)]
        {
            use nix::fcntl::OFlag;
            use nix::sys::stat::Mode;
            let mut flags = OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_TRUNC | OFlag::O_CLOEXEC;
            if fresh {
                match nix::unistd::unlinkat(
                    &self.dir,
                    name.as_os_str(),
                    nix::unistd::UnlinkatFlags::NoRemoveDir,
                ) {
                    Ok(()) | Err(nix::errno::Errno::ENOENT) => {}
                    Err(err) => return Err(std::io::Error::from(err).into()),
                }
                flags |= OFlag::O_EXCL | OFlag::O_NOFOLLOW;
            }
            let mode = Mode::from_bits_truncate(0o666);
            let fd = nix::fcntl::openat(&self.dir, name.as_os_str(), flags, mode)
                .map_err(std::io::Error::from)?;
            Ok(File::from(fd))
        }
        #[cfg(windows)]
        {
            let _ = fresh;
            Ok(File::options()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(self.dir.join(name))?)
        }
    }

    /// Renames `temp` over the log.
    fn replace_with(&self, temp: &OsString) -> Result<()> {
        #[cfg(unix)]
        nix::fcntl::renameat(
            &self.dir,
            temp.as_os_str(),
            &self.dir,
            self.name.as_os_str(),
        )
        .map_err(std::io::Error::from)?;
        #[cfg(windows)]
        std::fs::rename(self.dir.join(temp), self.dir.join(&self.name))?;
        Ok(())
    }

    /// Hands `place` and its log, opened elsewhere, to a [`FileLog`] (a workload user's,
    /// identity.rs).
    #[cfg(unix)]
    pub fn from_parts(dir: std::os::fd::OwnedFd, name: OsString) -> Place {
        Place { dir, name }
    }

    #[cfg(unix)]
    pub fn into_parts(self) -> (std::os::fd::OwnedFd, OsString) {
        (self.dir, self.name)
    }
}

/// Gives `temp` the owner and mode of `log`, which it replaces: a supervisor running as root
/// rewrites a workload user's log.
#[cfg(unix)]
fn same_owner(temp: &File, log: &File) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let (want, have) = (log.metadata()?, temp.metadata()?);
    if (want.uid(), want.gid()) != (have.uid(), have.gid()) {
        std::os::unix::fs::fchown(temp, Some(want.uid()), Some(want.gid()))?;
    }
    if want.mode() != have.mode() {
        temp.set_permissions(std::fs::Permissions::from_mode(want.mode() & 0o7777))?;
    }
    Ok(())
}

/// A log written to a file as plain text: the head, then, once the middle was dropped, the line
/// `[happy-supervisor: N bytes omitted]`, then the tail.
#[derive(Debug)]
pub struct FileLog {
    place: Place,
    file: File,
    window: Window,
    /// The file offset of the logical byte `window.tail_start()`.
    tail_at: u64,
}

impl FileLog {
    /// Creates or truncates `path`. Its parent must exist.
    #[cfg(test)]
    pub fn create(path: &Path, limit: u64) -> Result<FileLog> {
        let (place, file) = Place::create(path)?;
        Ok(FileLog::new(place, file, limit))
    }

    /// A log in `file`, just created or truncated at `place`.
    pub fn new(place: Place, file: File, limit: u64) -> FileLog {
        let window = Window::new(limit);
        FileLog {
            place,
            file,
            tail_at: window.tail_start(),
            window,
        }
    }

    pub fn append(&mut self, chunk: &[u8]) -> Result<()> {
        let before = self.window;
        let append = self.window.append(chunk.len() as u64);
        if self.window.tail_start() == before.tail_start() {
            write_at(&self.file, self.file_offset(&before, before.total()), chunk)?;
            return Ok(());
        }
        self.compact(&before, &append, chunk)
    }

    /// Rewrites the file as head, marker line and tail, through a temp file renamed over it.
    fn compact(&mut self, before: &Window, append: &Append, chunk: &[u8]) -> Result<()> {
        let start = before.total();
        let slice = |r: &Range<u64>| &chunk[(r.start - start) as usize..(r.end - start) as usize];
        let mut temp_name = self.place.name.clone();
        temp_name.push(".happy-supervisor-tmp");
        let temp = self.place.open(&temp_name, true)?;
        #[cfg(unix)]
        same_owner(&temp, &self.file)?;
        let mut temp = std::io::BufWriter::new(temp);

        let old_head = before.total().min(before.head_end());
        self.copy_to(&mut temp, 0..old_head)?;
        temp.write_all(slice(&append.head))?;
        let marker = format!(
            "[happy-supervisor: {} bytes omitted]\n",
            self.window.omitted()
        );
        temp.write_all(marker.as_bytes())?;
        let kept = self.window.tail_start().max(before.tail_start())..before.total();
        if !kept.is_empty() {
            let from = self.file_offset(before, kept.start);
            self.copy_to(&mut temp, from..from + (kept.end - kept.start))?;
        }
        temp.write_all(slice(&append.tail))?;
        let temp = temp.into_inner().map_err(|err| err.into_error())?;

        self.place.replace_with(&temp_name)?;
        self.file = temp;
        self.tail_at = self.window.head_end() + marker.len() as u64;
        Ok(())
    }

    fn copy_to(&self, out: &mut impl std::io::Write, range: Range<u64>) -> Result<()> {
        let mut buf = vec![0; 64 << 10];
        let mut at = range.start;
        while at < range.end {
            let n = ((range.end - at) as usize).min(buf.len());
            read_exact_at(&self.file, at, &mut buf[..n])?;
            out.write_all(&buf[..n])?;
            at += n as u64;
        }
        Ok(())
    }

    /// The file offset of retained logical offset `at`, or of the end when `at` is the total.
    fn file_offset(&self, window: &Window, at: u64) -> u64 {
        if window.omitted() == 0 || at < window.head_end() {
            at
        } else {
            self.tail_at + (at - window.tail_start())
        }
    }

    fn read(&self, range: Range<u64>) -> Result<Vec<u8>> {
        let mut out = vec![0; (range.end - range.start) as usize];
        if !range.is_empty() {
            read_exact_at(
                &self.file,
                self.file_offset(&self.window, range.start),
                &mut out,
            )?;
        }
        Ok(out)
    }
}

#[cfg(unix)]
fn read_exact_at(file: &File, at: u64, buf: &mut [u8]) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(file, buf, at)
}

#[cfg(unix)]
fn write_at(file: &File, at: u64, buf: &[u8]) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(file, buf, at)
}

#[cfg(windows)]
fn read_exact_at(file: &File, mut at: u64, mut buf: &mut [u8]) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt as _;
    while !buf.is_empty() {
        match file.seek_read(buf, at)? {
            0 => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            n => {
                buf = &mut buf[n..];
                at += n as u64;
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn write_at(file: &File, mut at: u64, mut buf: &[u8]) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt as _;
    while !buf.is_empty() {
        match file.seek_write(buf, at)? {
            0 => return Err(std::io::ErrorKind::WriteZero.into()),
            n => {
                buf = &buf[n..];
                at += n as u64;
            }
        }
    }
    Ok(())
}

/// One process's output log.
#[derive(Debug)]
pub enum Log {
    Memory(MemoryLog),
    File(FileLog),
    /// A memory log of an exited process, discarded to keep the node's memory budget.
    Discarded {
        total: u64,
    },
}

/// What an `exec.log` read answers.
#[derive(Debug, PartialEq, Eq)]
pub struct Read {
    pub data: Vec<u8>,
    pub offset: u64,
    pub total: u64,
    pub retained: Vec<ByteRange>,
}

impl Log {
    pub fn append(&mut self, chunk: &[u8]) -> Result<()> {
        match self {
            Log::Memory(log) => log.append(chunk),
            Log::File(log) => log.append(chunk)?,
            Log::Discarded { total } => *total += chunk.len() as u64,
        }
        Ok(())
    }

    pub fn total(&self) -> u64 {
        match self {
            Log::Memory(log) => log.window.total(),
            Log::File(log) => log.window.total(),
            Log::Discarded { total } => *total,
        }
    }

    pub fn read(&self, offset: u64, length: u64) -> Result<Read> {
        let (window, data) = match self {
            Log::Memory(log) => {
                let range = log.window.read(offset, length);
                (&log.window, log.copy(range))
            }
            Log::File(log) => {
                let range = log.window.read(offset, length);
                (&log.window, log.read(range)?)
            }
            Log::Discarded { total } => {
                return Ok(Read {
                    data: Vec::new(),
                    offset: offset.min(*total),
                    total: *total,
                    retained: Vec::new(),
                });
            }
        };
        Ok(Read {
            offset: window.read(offset, length).start,
            data,
            total: window.total(),
            retained: window.retained(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges(window: &Window) -> Vec<(u64, u64)> {
        window.retained().iter().map(|r| (r.start, r.end)).collect()
    }

    #[test]
    fn a_log_under_its_limit_keeps_everything_in_one_range() {
        let mut window = Window::new(16);
        assert_eq!(ranges(&window), []);
        assert_eq!(
            window.append(3),
            Append {
                head: 0..3,
                dropped: 0,
                tail: 3..3
            }
        );
        assert_eq!(
            window.append(7),
            Append {
                head: 3..4,
                dropped: 0,
                tail: 4..10
            }
        );
        assert_eq!(
            window.append(6),
            Append {
                head: 10..10,
                dropped: 0,
                tail: 10..16
            }
        );
        assert_eq!(ranges(&window), [(0, 16)]);
        assert_eq!(window.read(3, 100), 3..16);
    }

    #[test]
    fn passing_the_limit_drops_the_middle_down_to_half_the_limit() {
        let mut window = Window::new(16);
        window.append(16);
        assert_eq!(
            window.append(1),
            Append {
                head: 16..16,
                dropped: 5,
                tail: 16..17
            }
        );
        assert_eq!(ranges(&window), [(0, 4), (9, 17)]);
        assert_eq!(window.omitted(), 5);
        for _ in 0..4 {
            window.append(1);
        }
        assert_eq!(ranges(&window), [(0, 4), (9, 21)]);
        assert_eq!(
            window.append(1),
            Append {
                head: 21..21,
                dropped: 5,
                tail: 21..22
            }
        );
        assert_eq!(ranges(&window), [(0, 4), (14, 22)]);
    }

    #[test]
    fn one_huge_chunk_fills_the_head_and_keeps_only_its_own_end() {
        let mut window = Window::new(16);
        window.append(2);
        assert_eq!(
            window.append(100),
            Append {
                head: 2..4,
                dropped: 0,
                tail: 94..102
            }
        );
        assert_eq!(ranges(&window), [(0, 4), (94, 102)]);
    }

    #[test]
    fn reads_skip_the_gap_and_never_cross_it() {
        let mut window = Window::new(16);
        window.append(40);
        assert_eq!(ranges(&window), [(0, 4), (32, 40)]);
        assert_eq!(window.read(0, 100), 0..4);
        assert_eq!(window.read(2, 1), 2..3);
        assert_eq!(window.read(4, 100), 32..40);
        assert_eq!(window.read(20, 3), 32..35);
        assert_eq!(window.read(38, 100), 38..40);
        assert_eq!(window.read(40, 100), 40..40);
        assert_eq!(window.read(99, 100), 40..40);
    }

    #[test]
    fn tiny_limits_have_no_head() {
        let mut window = Window::new(1);
        window.append(3);
        assert_eq!(ranges(&window), [(2, 3)]);
        assert_eq!(window.read(0, 10), 2..3);
    }

    #[test]
    fn memory_log_keeps_head_and_tail_bytes() {
        let mut log = Log::Memory(MemoryLog::new(16));
        log.append(b"0123456789").unwrap();
        log.append(b"abcdefgh").unwrap();
        log.append(b"ijklmnopqrstuv").unwrap();
        assert_eq!(
            log.read(0, 100).unwrap(),
            Read {
                data: b"0123".to_vec(),
                offset: 0,
                total: 32,
                retained: vec![
                    ByteRange { start: 0, end: 4 },
                    ByteRange { start: 24, end: 32 }
                ],
            }
        );
        assert_eq!(log.read(4, 3).unwrap().data, b"opq");
        assert_eq!(log.read(4, 3).unwrap().offset, 24);
        let Log::Memory(memory) = &log else {
            unreachable!()
        };
        assert_eq!(memory.held_bytes(), 12);
    }

    #[test]
    fn memory_log_reads_across_head_and_tail_before_any_drop() {
        let mut log = Log::Memory(MemoryLog::new(16));
        log.append(b"012").unwrap();
        log.append(b"3456").unwrap();
        assert_eq!(log.read(1, 5).unwrap().data, b"12345");
    }

    fn file_text(path: &Path) -> String {
        String::from_utf8(std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn file_log_is_rewritten_as_head_marker_and_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.log");
        std::fs::write(&path, "old contents").unwrap();
        let mut log = Log::File(FileLog::create(&path, 16).unwrap());
        assert_eq!(file_text(&path), "");
        log.append(b"0123456789").unwrap();
        log.append(b"abcdef").unwrap();
        assert_eq!(file_text(&path), "0123456789abcdef");
        log.append(b"ghij").unwrap();
        assert_eq!(
            file_text(&path),
            "0123[happy-supervisor: 8 bytes omitted]\ncdefghij"
        );
        log.append(b"klm").unwrap();
        assert_eq!(
            file_text(&path),
            "0123[happy-supervisor: 8 bytes omitted]\ncdefghijklm"
        );
        log.append(b"nop").unwrap();
        assert_eq!(
            file_text(&path),
            "0123[happy-supervisor: 14 bytes omitted]\nijklmnop"
        );
        log.append(b"qrstuvwxyz").unwrap();
        assert_eq!(
            file_text(&path),
            "0123[happy-supervisor: 24 bytes omitted]\nstuvwxyz"
        );
        assert_eq!(
            log.read(0, 100).unwrap(),
            Read {
                data: b"0123".to_vec(),
                offset: 0,
                total: 36,
                retained: vec![
                    ByteRange { start: 0, end: 4 },
                    ByteRange { start: 28, end: 36 }
                ],
            }
        );
        assert_eq!(log.read(10, 3).unwrap().data, b"stu");
        assert_eq!(log.read(33, 100).unwrap().data, b"xyz");
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["out.log"]);
    }

    #[test]
    fn file_log_needs_an_existing_parent() {
        let dir = tempfile::tempdir().unwrap();
        let err = FileLog::create(&dir.path().join("missing/out.log"), 16).unwrap_err();
        assert_eq!(err.kind, crate::error::ErrorKind::NotFound);
        assert!(!dir.path().join("missing").exists());
    }

    #[test]
    fn a_discarded_log_keeps_counting() {
        let mut log = Log::Discarded { total: 7 };
        log.append(b"abc").unwrap();
        assert_eq!(
            log.read(3, 10).unwrap(),
            Read {
                data: vec![],
                offset: 3,
                total: 10,
                retained: vec![]
            }
        );
    }
}
