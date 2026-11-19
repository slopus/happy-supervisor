//! Small owned wrappers over the Win32 values the sandbox passes around: wide strings, SIDs,
//! LocalAlloc'd buffers and handles.

use std::ffi::{OsStr, c_void};
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{FromRawHandle as _, OwnedHandle};

use windows_sys::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{GetLengthSid, IsValidSid, PSID};

/// `text` as a NUL-terminated UTF-16 string.
pub(super) fn wide(text: impl AsRef<OsStr>) -> Vec<u16> {
    text.as_ref().encode_wide().chain(Some(0)).collect()
}

/// Fails with the thread's last OS error when a Win32 BOOL call returned 0.
pub(super) fn check(ok: i32) -> io::Result<()> {
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Fails when a call that returns a WIN32_ERROR or NET_API_STATUS did not return 0.
pub(super) fn check_code(code: u32) -> io::Result<()> {
    if code != 0 {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    Ok(())
}

/// Takes ownership of a handle a Win32 call returned.
///
/// # Safety
///
/// `handle` is open, and nothing else closes it.
pub(super) unsafe fn owned(handle: HANDLE) -> OwnedHandle {
    // SAFETY: as the caller promises.
    unsafe { OwnedHandle::from_raw_handle(handle) }
}

/// Memory a Win32 call allocated with LocalAlloc, freed on drop.
pub(super) struct Local<T>(pub(super) *mut T);

impl<T> Drop for Local<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from LocalAlloc and is freed once, here.
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }
}

/// A SID, owned as its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Sid(Vec<u8>);

impl Sid {
    /// Parses the string form, such as `S-1-5-32-545`.
    pub(super) fn parse(text: &str) -> io::Result<Sid> {
        let mut psid: PSID = std::ptr::null_mut();
        // SAFETY: a NUL-terminated string in, a LocalAlloc'd SID out.
        check(unsafe { ConvertStringSidToSidW(wide(text).as_ptr(), &mut psid) })?;
        let psid = Local(psid);
        // SAFETY: the SID is valid; ConvertStringSidToSidW made it.
        Ok(unsafe { Sid::copy(psid.0) })
    }

    /// Copies the SID at `psid`.
    ///
    /// # Safety
    ///
    /// `psid` points to a valid SID.
    pub(super) unsafe fn copy(psid: PSID) -> Sid {
        // SAFETY: the caller promises a valid SID, which is GetLengthSid bytes long.
        unsafe {
            debug_assert!(IsValidSid(psid) != 0);
            let len = GetLengthSid(psid) as usize;
            Sid(std::slice::from_raw_parts(psid as *const u8, len).to_vec())
        }
    }

    /// The SID for Win32 calls that read it. They take `*mut` but do not write through it.
    pub(super) fn as_psid(&self) -> PSID {
        self.0.as_ptr() as *mut c_void
    }

    pub(super) fn to_text(&self) -> io::Result<String> {
        let mut text: *mut u16 = std::ptr::null_mut();
        // SAFETY: a valid SID in, a LocalAlloc'd NUL-terminated string out.
        check(unsafe { ConvertSidToStringSidW(self.as_psid(), &mut text) })?;
        let text = Local(text);
        // SAFETY: the string is NUL-terminated.
        let len = (0..)
            .take_while(|&i| unsafe { *text.0.add(i) } != 0)
            .count();
        // SAFETY: `len` u16s precede the NUL.
        let units = unsafe { std::slice::from_raw_parts(text.0, len) };
        Ok(String::from_utf16_lossy(units))
    }
}

/// Fills `buf` from the system's preferred random number generator.
pub(super) fn random(buf: &mut [u8]) -> io::Result<()> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    // SAFETY: `buf` is valid for its length; no algorithm handle with this flag.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            buf.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(io::Error::other(format!(
            "BCryptGenRandom failed: {status:#x}"
        )));
    }
    Ok(())
}

/// Encrypts `data` with DPAPI for the current user.
pub(super) fn protect(data: &[u8]) -> io::Result<Vec<u8>> {
    dpapi(data, true)
}

/// Decrypts what [`protect`] returned, as the same user.
pub(super) fn unprotect(data: &[u8]) -> io::Result<Vec<u8>> {
    dpapi(data, false)
}

fn dpapi(data: &[u8], encrypt: bool) -> io::Result<Vec<u8>> {
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: valid blobs in; DPAPI LocalAllocs the output blob.
    let ok = unsafe {
        if encrypt {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    check(ok)?;
    let len = output.cbData as usize;
    let output = Local(output.pbData);
    // SAFETY: DPAPI wrote `len` bytes there.
    Ok(unsafe { std::slice::from_raw_parts(output.0, len) }.to_vec())
}
