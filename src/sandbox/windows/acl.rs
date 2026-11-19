// Derived from codex-rs/windows-sandbox-rs/src/acl.rs (OpenAI Codex, Copyright 2025 OpenAI,
// Apache License 2.0). Changed: one entry point adds any mix of allow and deny ACEs for one SID,
// the masks leave SYNCHRONIZE and READ_CONTROL alone, and what to add is decided by an access
// check against the sandbox's own token instead of by scanning ACEs.

//! File ACEs for one lease. Every ACE names the slot's group; [`revoke`] removes them all.

use std::io;
use std::path::Path;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::Authorization::{
    DENY_ACCESS, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, REVOKE_ACCESS,
    SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN,
    TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACL, AccessCheck, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, GENERIC_MAPPING,
    GROUP_SECURITY_INFORMATION, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ALL_ACCESS, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_EXECUTE,
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_DATA, FILE_READ_EA,
    FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::SystemServices::MAXIMUM_ALLOWED;

use super::win::{Local, Sid, check, check_code, wide};

/// What the sandbox may do at a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Access {
    pub read: bool,
    pub write: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Ace {
    AllowRead,
    /// Read, write and delete, but not delete-child: a parent's delete-child would let the
    /// sandbox delete a child it is denied writing.
    AllowWrite,
    DenyRead,
    DenyWrite,
}

impl Ace {
    fn mask(self) -> u32 {
        match self {
            Ace::AllowRead => FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
            Ace::AllowWrite => {
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE
            }
            Ace::DenyRead => FILE_READ_DATA | FILE_READ_EA | FILE_EXECUTE,
            Ace::DenyWrite => {
                FILE_WRITE_DATA
                    | FILE_APPEND_DATA
                    | FILE_WRITE_EA
                    | FILE_WRITE_ATTRIBUTES
                    | DELETE
                    | FILE_DELETE_CHILD
                    | WRITE_DAC
                    | WRITE_OWNER
            }
        }
    }

    fn mode(self) -> i32 {
        match self {
            Ace::AllowRead | Ace::AllowWrite => GRANT_ACCESS,
            Ace::DenyRead | Ace::DenyWrite => DENY_ACCESS,
        }
    }
}

/// The ACEs that turn what the sandbox `has` at a path into what it should have.
pub(super) fn aces(want: Access, has: Access) -> Vec<Ace> {
    let mut aces = Vec::new();
    if want.write && !has.write {
        aces.push(Ace::AllowWrite);
    } else if want.read && !has.read {
        aces.push(Ace::AllowRead);
    }
    if !want.read && has.read {
        aces.push(Ace::DenyRead);
    }
    if !want.write && has.write {
        aces.push(Ace::DenyWrite);
    }
    aces
}

/// What `token` (an impersonation token) may do at `path` by its current ACL.
pub(super) fn access(path: &Path, token: HANDLE) -> io::Result<Access> {
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: a NUL-terminated path in; the descriptor out is LocalAlloc'd.
    check_code(unsafe {
        GetNamedSecurityInfoW(
            wide(path).as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    })
    .map_err(|err| at(path, err))?;
    let sd = Local(sd);
    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ,
        GenericWrite: FILE_GENERIC_WRITE,
        GenericExecute: FILE_GENERIC_EXECUTE,
        GenericAll: FILE_ALL_ACCESS,
    };
    let mut privileges = [0u8; 256];
    let mut privileges_len = privileges.len() as u32;
    let (mut granted, mut status) = (0u32, 0i32);
    // SAFETY: a valid descriptor, an impersonation token, and buffers of the lengths passed.
    check(unsafe {
        AccessCheck(
            sd.0,
            token,
            MAXIMUM_ALLOWED,
            &mapping,
            privileges.as_mut_ptr().cast(),
            &mut privileges_len,
            &mut granted,
            &mut status,
        )
    })
    .map_err(|err| at(path, err))?;
    if status == 0 {
        granted = 0;
    }
    Ok(Access {
        read: granted & FILE_READ_DATA != 0,
        write: granted & FILE_WRITE_DATA != 0,
    })
}

/// Adds `aces` for `sid` at `path`, inherited by everything below a directory.
pub(super) fn add(path: &Path, sid: &Sid, aces: &[Ace]) -> io::Result<()> {
    let inheritance = if path.is_dir() {
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
    } else {
        0
    };
    let entries: Vec<EXPLICIT_ACCESS_W> = aces
        .iter()
        .map(|ace| explicit(sid, ace.mask(), ace.mode(), inheritance))
        .collect();
    set_entries(path, &entries)
}

/// Removes every ACE for `sid` at `path`, and the copies its inheritance put below it.
pub(super) fn revoke(path: &Path, sid: &Sid) -> io::Result<()> {
    set_entries(path, &[explicit(sid, 0, REVOKE_ACCESS, 0)])
}

fn explicit(sid: &Sid, mask: u32, mode: i32, inheritance: u32) -> EXPLICIT_ACCESS_W {
    EXPLICIT_ACCESS_W {
        grfAccessPermissions: mask,
        grfAccessMode: mode,
        grfInheritance: inheritance,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.as_psid().cast(),
        },
    }
}

/// Merges `entries` into the path's DACL; SetEntriesInAclW puts denies before allows. Setting
/// the DACL by name propagates inheritable ACEs to everything below.
fn set_entries(path: &Path, entries: &[EXPLICIT_ACCESS_W]) -> io::Result<()> {
    let path_w = wide(path);
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: a NUL-terminated path in; `dacl` points into the LocalAlloc'd `sd`.
    check_code(unsafe {
        GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    })
    .map_err(|err| at(path, err))?;
    let _sd = Local(sd);
    let mut merged: *mut ACL = std::ptr::null_mut();
    // SAFETY: the entries' SIDs live in the caller's `Sid`s; the new ACL is LocalAlloc'd.
    check_code(unsafe {
        SetEntriesInAclW(entries.len() as u32, entries.as_ptr(), dacl, &mut merged)
    })
    .map_err(|err| at(path, err))?;
    let merged = Local(merged);
    // SAFETY: a NUL-terminated path and the valid ACL made above.
    check_code(unsafe {
        SetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            merged.0,
            std::ptr::null(),
        )
    })
    .map_err(|err| at(path, err))
}

fn at(path: &Path, err: io::Error) -> io::Error {
    io::Error::new(err.kind(), format!("{}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: Access = Access {
        read: false,
        write: false,
    };
    const READ: Access = Access {
        read: true,
        write: false,
    };
    const WRITE: Access = Access {
        read: true,
        write: true,
    };

    #[test]
    fn aces_close_the_gap_between_want_and_has() {
        let table = [
            (WRITE, NONE, vec![Ace::AllowWrite]),
            (WRITE, READ, vec![Ace::AllowWrite]),
            (WRITE, WRITE, vec![]),
            (READ, NONE, vec![Ace::AllowRead]),
            (READ, READ, vec![]),
            (READ, WRITE, vec![Ace::DenyWrite]),
            (NONE, NONE, vec![]),
            (NONE, READ, vec![Ace::DenyRead]),
            (NONE, WRITE, vec![Ace::DenyRead, Ace::DenyWrite]),
        ];
        for (want, has, expected) in table {
            assert_eq!(aces(want, has), expected, "want {want:?} has {has:?}");
        }
    }
}
