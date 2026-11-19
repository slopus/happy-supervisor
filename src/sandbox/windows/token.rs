// Derived from codex-rs/windows-sandbox-rs/src/token.rs (OpenAI Codex, Copyright 2025 OpenAI,
// Apache License 2.0). Changed: the restricting SIDs come from a [`TokenSpec`], and the default
// DACL names the slot's group instead of the logon SID, which CreateProcessWithLogonW shares
// with the caller.

//! The command's token: the leased account's own token, restricted.

use std::io;
use std::os::windows::io::{AsRawHandle as _, OwnedHandle};

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    ACL, CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, DuplicateTokenEx, GetSecurityDescriptorDacl,
    GetTokenInformation, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, LUA_TOKEN,
    LogonUserW, PSECURITY_DESCRIPTOR, SID_AND_ATTRIBUTES, SecurityImpersonation,
    SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_SESSIONID, TOKEN_ALL_ACCESS,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DEFAULT_DACL, TOKEN_DUPLICATE, TOKEN_GROUPS,
    TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER, TokenDefaultDacl, TokenGroups,
    TokenImpersonation, TokenUser, WRITE_RESTRICTED,
};
use windows_sys::Win32::System::SystemServices::SE_GROUP_LOGON_ID;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::win::{Local, Sid, check, owned, wide};

const EVERYONE: &str = "S-1-1-0";
/// RESTRICTED: what the NUL device and similar objects grant restricted code.
const RESTRICTED: &str = "S-1-5-12";

/// How the runner restricts its own token for the command. The broker decides it from the
/// policy; the runner, which holds the account's token, applies it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TokenSpec {
    /// `write.default` is deny: a write must also be granted to one of `restrict`.
    pub write_restricted: bool,
    /// Restricting SIDs besides the token's logon SID, which is always one.
    pub restrict: Vec<String>,
    /// The slot's group, the only one the default DACL lets open the command's own objects.
    pub owner_group: String,
}

impl TokenSpec {
    /// `slot_group` gets every file grant; `network` are the account's network groups.
    pub(super) fn new(write_restricted: bool, slot_group: &str, network: Vec<String>) -> TokenSpec {
        let mut restrict = vec![
            slot_group.to_string(),
            EVERYONE.to_string(),
            RESTRICTED.to_string(),
        ];
        // The filters' access check may count as a write, so the groups they match must pass
        // the restricted check too. Nothing grants them file access.
        restrict.extend(network);
        TokenSpec {
            write_restricted,
            restrict,
            owner_group: slot_group.to_string(),
        }
    }
}

/// Logs the account on, as the runner's own logon would.
pub(super) fn logon(account: &str, password: &str) -> io::Result<OwnedHandle> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: NUL-terminated strings in, a token handle out.
    check(unsafe {
        LogonUserW(
            wide(account).as_ptr(),
            wide(".").as_ptr(),
            wide(password).as_ptr(),
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
    })
    .map_err(|err| io::Error::new(err.kind(), format!("cannot log on {account}: {err}")))?;
    // SAFETY: LogonUserW returned a fresh handle.
    Ok(unsafe { owned(token) })
}

/// This process's token, with what restricting it needs.
pub(super) fn own() -> io::Result<OwnedHandle> {
    let mut token: HANDLE = std::ptr::null_mut();
    let access = TOKEN_DUPLICATE
        | TOKEN_QUERY
        | TOKEN_ASSIGN_PRIMARY
        | TOKEN_ADJUST_DEFAULT
        | TOKEN_ADJUST_SESSIONID;
    // SAFETY: the pseudo-handle of this process; a token handle out.
    check(unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token) })?;
    // SAFETY: a fresh handle.
    Ok(unsafe { owned(token) })
}

pub(super) fn current_user() -> io::Result<Sid> {
    let token = own()?;
    let buf = information(&token, TokenUser)?;
    // SAFETY: TokenUser fills the buffer with a TOKEN_USER whose SID points into it.
    Ok(unsafe { Sid::copy((*(buf.as_ptr() as *const TOKEN_USER)).User.Sid) })
}

/// A primary token from `base` restricted as `spec` says.
pub(super) fn restricted(base: &OwnedHandle, spec: &TokenSpec) -> io::Result<OwnedHandle> {
    let mut sids = spec
        .restrict
        .iter()
        .map(|sid| Sid::parse(sid))
        .collect::<io::Result<Vec<_>>>()?;
    sids.extend(logon_sid(base)?);
    let restrict: Vec<SID_AND_ATTRIBUTES> = sids
        .iter()
        .map(|sid| SID_AND_ATTRIBUTES {
            Sid: sid.as_psid(),
            Attributes: 0,
        })
        .collect();
    let (mut flags, restrict_count) = (DISABLE_MAX_PRIVILEGE | LUA_TOKEN, restrict.len());
    let restrict_count = if spec.write_restricted {
        flags |= WRITE_RESTRICTED;
        restrict_count
    } else {
        0
    };
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the SID arrays point into `Sid`s that outlive the call.
    check(unsafe {
        CreateRestrictedToken(
            base.as_raw_handle() as HANDLE,
            flags,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            restrict_count as u32,
            restrict.as_ptr(),
            &mut token,
        )
    })?;
    // SAFETY: a fresh handle.
    let token = unsafe { owned(token) };
    set_default_dacl(&token, &spec.owner_group)?;
    Ok(token)
}

/// An impersonation copy of `token`, for AccessCheck and for file operations.
pub(super) fn impersonation(token: &OwnedHandle) -> io::Result<OwnedHandle> {
    let mut copy: HANDLE = std::ptr::null_mut();
    // SAFETY: a valid token in, a fresh handle out.
    check(unsafe {
        DuplicateTokenEx(
            token.as_raw_handle() as HANDLE,
            TOKEN_ALL_ACCESS,
            std::ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &mut copy,
        )
    })?;
    // SAFETY: a fresh handle.
    Ok(unsafe { owned(copy) })
}

/// Objects the command creates (processes, threads, pipes) open only to the slot's group and
/// SYSTEM. The account is shared by every lease of the slot, and the logon SID by every
/// command this supervisor starts, so neither may name them. OWNER RIGHTS keeps the owner's
/// implicit WRITE_DAC from reopening them.
fn set_default_dacl(token: &OwnedHandle, owner_group: &str) -> io::Result<()> {
    let sddl = wide(format!("D:(A;;GA;;;{owner_group})(A;;GA;;;SY)(A;;RC;;;OW)"));
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: a NUL-terminated string in, a LocalAlloc'd descriptor out.
    check(unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    })?;
    let sd = Local(sd);
    let (mut present, mut dacl, mut defaulted): (i32, *mut ACL, i32) = (0, std::ptr::null_mut(), 0);
    // SAFETY: a valid descriptor; the DACL points into it.
    check(unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted) })?;
    let info = TOKEN_DEFAULT_DACL { DefaultDacl: dacl };
    // SAFETY: `info` points to a DACL that lives in `sd` across the call.
    check(unsafe {
        SetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenDefaultDacl,
            (&raw const info).cast(),
            size_of::<TOKEN_DEFAULT_DACL>() as u32,
        )
    })
}

fn logon_sid(token: &OwnedHandle) -> io::Result<Option<Sid>> {
    let buf = information(token, TokenGroups)?;
    // SAFETY: TokenGroups fills the buffer with a TOKEN_GROUPS whose array and SIDs lie in it.
    unsafe {
        let groups = buf.as_ptr() as *const TOKEN_GROUPS;
        let count = (*groups).GroupCount as usize;
        let first = (&raw const (*groups).Groups) as *const SID_AND_ATTRIBUTES;
        Ok((0..count)
            .map(|i| *first.add(i))
            .find(|group| group.Attributes & SE_GROUP_LOGON_ID as u32 == SE_GROUP_LOGON_ID as u32)
            .map(|group| Sid::copy(group.Sid)))
    }
}

/// One token information class, in a buffer aligned for the structures it holds.
fn information(token: &OwnedHandle, class: TOKEN_INFORMATION_CLASS) -> io::Result<Vec<u64>> {
    let handle = token.as_raw_handle() as HANDLE;
    let mut needed = 0u32;
    // SAFETY: a size query: no buffer.
    unsafe { GetTokenInformation(handle, class, std::ptr::null_mut(), 0, &mut needed) };
    let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: the buffer holds `needed` bytes.
    check(unsafe {
        GetTokenInformation(handle, class, buf.as_mut_ptr().cast(), needed, &mut needed)
    })?;
    Ok(buf)
}
