//! The newc cpio archives a guest's initramfs is made of (docs/vm-mode.md, Boot). The kernel
//! unpacks concatenated archives in order, so the supervisor's binary and each boot's config
//! are two archives written once each and joined.

/// A newc archive being written. Names are relative (`init`, `dev/console`), parents first.
pub struct Archive {
    bytes: Vec<u8>,
    inode: u32,
}

const DIRECTORY: u32 = 0o040000;
const REGULAR: u32 = 0o100000;
const CHARACTER: u32 = 0o020000;

impl Archive {
    pub fn new() -> Archive {
        Archive {
            bytes: Vec::new(),
            inode: 0,
        }
    }

    pub fn directory(&mut self, name: &str, mode: u32) {
        let inode = self.next_inode();
        self.entry(inode, name, DIRECTORY | mode, 2, (0, 0), &[]);
    }

    pub fn file(&mut self, name: &str, mode: u32, data: &[u8]) {
        let inode = self.next_inode();
        self.entry(inode, name, REGULAR | mode, 1, (0, 0), data);
    }

    pub fn character_device(&mut self, name: &str, mode: u32, major: u32, minor: u32) {
        let inode = self.next_inode();
        self.entry(inode, name, CHARACTER | mode, 1, (major, minor), &[]);
    }

    /// The archive with its trailer.
    pub fn finish(mut self) -> Vec<u8> {
        self.entry(0, "TRAILER!!!", 0, 1, (0, 0), &[]);
        self.bytes
    }

    fn next_inode(&mut self) -> u32 {
        self.inode += 1;
        self.inode
    }

    /// One header, owned by root with mtime 0, then the name and the data, each padded to four
    /// bytes. The name size counts its NUL.
    fn entry(
        &mut self,
        inode: u32,
        name: &str,
        mode: u32,
        links: u32,
        rdev: (u32, u32),
        data: &[u8],
    ) {
        let fields = [
            inode,
            mode,
            0,
            0,
            links,
            0,
            data.len() as u32,
            0,
            0,
            rdev.0,
            rdev.1,
            name.len() as u32 + 1,
            0,
        ];
        self.bytes.extend_from_slice(b"070701");
        for field in fields {
            self.bytes
                .extend_from_slice(format!("{field:08X}").as_bytes());
        }
        self.bytes.extend_from_slice(name.as_bytes());
        self.bytes.push(0);
        self.pad();
        self.bytes.extend_from_slice(data);
        self.pad();
    }

    fn pad(&mut self) {
        while !self.bytes.len().is_multiple_of(4) {
            self.bytes.push(0);
        }
    }
}

impl Default for Archive {
    fn default() -> Archive {
        Archive::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_is_one_padded_header_name_and_data() {
        let mut archive = Archive::new();
        archive.file("init", 0o755, b"hi!");
        let bytes = archive.finish();
        let header = "070701\
            00000001000081ED000000000000000000000001000000000000000300000000\
            00000000000000000000000000000005\
            00000000";
        let mut expected = header.as_bytes().to_vec();
        // 110-byte header + "init\0" is 115 bytes, padded to 116; "hi!" is padded to 4.
        expected.extend_from_slice(b"init\0\0");
        expected.extend_from_slice(b"hi!\0");
        assert_eq!(&bytes[..expected.len()], &expected[..]);
        assert!(bytes.len().is_multiple_of(4));
        assert!(bytes.windows(10).any(|w| w == b"TRAILER!!!"));
    }

    /// GNU cpio, where it is installed, lists what the kernel will unpack.
    #[cfg(target_os = "linux")]
    #[test]
    fn cpio_reads_it() {
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        let Ok(mut cpio) = Command::new("cpio")
            .args(["-t", "-v", "--quiet"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
        else {
            eprintln!("cpio is not installed; skipping");
            return;
        };
        let mut archive = Archive::new();
        archive.directory("dev", 0o755);
        archive.character_device("dev/console", 0o600, 5, 1);
        archive.file("init", 0o755, &[7; 1000]);
        cpio.stdin
            .take()
            .unwrap()
            .write_all(&archive.finish())
            .unwrap();
        let output = cpio.wait_with_output().unwrap();
        assert!(output.status.success());
        let listing = String::from_utf8(output.stdout).unwrap();
        let entries: Vec<(&str, &str)> = listing
            .lines()
            .map(|line| {
                let fields: Vec<&str> = line.split_whitespace().collect();
                (fields[0], *fields.last().unwrap())
            })
            .collect();
        assert_eq!(
            entries,
            [
                ("drwxr-xr-x", "dev"),
                ("crw-------", "dev/console"),
                ("-rwxr-xr-x", "init")
            ]
        );
    }
}
