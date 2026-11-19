//! An experiment harness for the Windows sandbox (not shipped): starts a command under a
//! token with chosen SIDs made deny-only, or inside an AppContainer, and holds WFP filters
//! keyed on a package or user SID while it runs.
//!
//! ```text
//! winbox escape <none|user|NAME[,NAME...]> PROGRAM [ARGS...]
//! winbox container NAME <none|CAP[,CAP...]> PROGRAM [ARGS...]
//! winbox package-sid NAME
//! winbox wfp-hold RULE...        (until stdin closes; prints "ready")
//!   block-package:SID  permit-package-loopback:SID:LO:HI  block-user:SID:PORT
//! ```
//!
//! CAP is internetClient, internetClientServer or privateNetwork. The exit code is the
//! command's, or 120 when it could not be started.

#[cfg(not(windows))]
fn main() {
    eprintln!("winbox runs only on Windows");
    std::process::exit(120);
}

#[cfg(windows)]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("escape") if args.len() >= 3 => win::escape(&args[1], &args[2..]),
        Some("container") if args.len() >= 4 => win::container(&args[1], &args[2], &args[3..]),
        Some("package-sid") if args.len() == 2 => win::package_sid(&args[1]).map(|sid| {
            println!("{sid}");
            0
        }),
        Some("wfp-hold") => win::wfp_hold(&args[1..]),
        _ => Err(std::io::Error::other(
            "bad arguments; see examples/winbox.rs",
        )),
    };
    match result {
        Ok(code) => std::process::exit(code as i32),
        Err(err) => {
            eprintln!("winbox: {err}");
            std::process::exit(120);
        }
    }
}

#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::io::{self, BufRead as _, Write as _};
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        ConvertStringSidToSidW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{
        CreateRestrictedToken, GetTokenInformation, LookupAccountNameW, PSECURITY_DESCRIPTOR, PSID,
        SECURITY_CAPABILITIES, SID, SID_AND_ATTRIBUTES, SID_NAME_USE, TOKEN_ADJUST_DEFAULT,
        TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;
    use windows_sys::Win32::System::Threading::{
        CreateProcessAsUserW, CreateProcessW, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetExitCodeProcess, INFINITE,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcessToken,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
        STARTUPINFOEXW, STARTUPINFOW, UpdateProcThreadAttribute, WaitForSingleObject,
    };
    use windows_sys::core::GUID;

    #[link(name = "userenv")]
    unsafe extern "system" {
        fn CreateAppContainerProfile(
            name: *const u16,
            display: *const u16,
            description: *const u16,
            capabilities: *const SID_AND_ATTRIBUTES,
            count: u32,
            sid: *mut PSID,
        ) -> i32;
        fn DeriveAppContainerSidFromAppContainerName(name: *const u16, sid: *mut PSID) -> i32;
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn FreeSid(sid: PSID) -> *mut c_void;
    }

    const ALREADY_EXISTS: i32 = 0x800700b7_u32 as i32;
    const SE_GROUP_ENABLED: u32 = 0x4;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain([0]).collect()
    }

    fn check(ok: i32) -> io::Result<()> {
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn hresult(code: i32) -> io::Result<()> {
        if code < 0 {
            Err(io::Error::other(format!("HRESULT {code:#010x}")))
        } else {
            Ok(())
        }
    }

    fn command_line(argv: &[String]) -> Vec<u16> {
        let quoted: Vec<String> = argv
            .iter()
            .map(|arg| {
                if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
                    return arg.clone();
                }
                let mut out = String::from('"');
                let mut slashes = 0;
                for ch in arg.chars() {
                    match ch {
                        '\\' => slashes += 1,
                        '"' => {
                            out.extend(std::iter::repeat_n('\\', slashes * 2 + 1));
                            out.push('"');
                            slashes = 0;
                        }
                        _ => {
                            out.extend(std::iter::repeat_n('\\', slashes));
                            out.push(ch);
                            slashes = 0;
                        }
                    }
                }
                out.extend(std::iter::repeat_n('\\', slashes * 2));
                out.push('"');
                out
            })
            .collect();
        wide(&quoted.join(" "))
    }

    /// A SID as bytes, so it outlives the API buffer it came from.
    struct Sid(Vec<u8>);

    impl Sid {
        fn parse(text: &str) -> io::Result<Sid> {
            let mut psid: PSID = null_mut();
            // SAFETY: a NUL-terminated string in, a LocalAlloc'd SID out.
            check(unsafe { ConvertStringSidToSidW(wide(text).as_ptr(), &mut psid) })?;
            // SAFETY: `psid` is a valid SID until LocalFree.
            let sid = unsafe { Sid::copy(psid) };
            // SAFETY: allocated by ConvertStringSidToSidW.
            unsafe { LocalFree(psid) };
            Ok(sid)
        }

        /// # Safety
        /// `psid` points to a valid SID.
        unsafe fn copy(psid: PSID) -> Sid {
            // SAFETY: the caller's promise.
            let len = unsafe { windows_sys::Win32::Security::GetLengthSid(psid) } as usize;
            // SAFETY: the SID is `len` bytes long.
            Sid(unsafe { std::slice::from_raw_parts(psid as *const u8, len) }.to_vec())
        }

        fn as_psid(&self) -> PSID {
            self.0.as_ptr() as PSID
        }

        fn text(&self) -> String {
            let mut out: *mut u16 = null_mut();
            // SAFETY: a valid SID in, a LocalAlloc'd string out.
            if unsafe { ConvertSidToStringSidW(self.as_psid(), &mut out) } == 0 {
                return "?".to_string();
            }
            // SAFETY: a NUL-terminated string from the call.
            let len = (0..).take_while(|&i| unsafe { *out.add(i) } != 0).count();
            // SAFETY: `len` u16s are valid.
            let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(out, len) });
            // SAFETY: allocated by ConvertSidToStringSidW.
            unsafe { LocalFree(out as *mut c_void) };
            text
        }
    }

    fn account_sid(name: &str) -> io::Result<Sid> {
        let mut sid = vec![0u8; 256];
        let mut sid_len = sid.len() as u32;
        let mut domain = vec![0u16; 256];
        let mut domain_len = domain.len() as u32;
        let mut kind: SID_NAME_USE = 0;
        // SAFETY: buffers and their lengths match.
        check(unsafe {
            LookupAccountNameW(
                null(),
                wide(name).as_ptr(),
                sid.as_mut_ptr() as PSID,
                &mut sid_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut kind,
            )
        })?;
        sid.truncate(sid_len as usize);
        Ok(Sid(sid))
    }

    fn own_token() -> io::Result<HANDLE> {
        let mut token: HANDLE = null_mut();
        // SAFETY: the pseudo-handle and an out pointer.
        check(unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
                &mut token,
            )
        })
        .map_err(|err| io::Error::other(format!("OpenProcessToken: {err}")))?;
        Ok(token)
    }

    fn user_sid(token: HANDLE) -> io::Result<Sid> {
        let mut buffer = vec![0u64; 64];
        let mut len = 0u32;
        // SAFETY: the buffer is 512 aligned bytes.
        check(unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr() as *mut c_void,
                512,
                &mut len,
            )
        })?;
        // SAFETY: TokenUser fills a TOKEN_USER at the start of the buffer.
        let user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
        // SAFETY: the SID lives in the buffer.
        Ok(unsafe { Sid::copy(user.User.Sid) })
    }

    fn startup() -> STARTUPINFOW {
        use std::os::windows::io::AsRawHandle as _;
        STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: std::io::stdin().as_raw_handle() as HANDLE,
            hStdOutput: std::io::stdout().as_raw_handle() as HANDLE,
            hStdError: std::io::stderr().as_raw_handle() as HANDLE,
            ..Default::default()
        }
    }

    fn wait(info: PROCESS_INFORMATION) -> io::Result<u32> {
        let mut code = 0u32;
        // SAFETY: fresh handles from CreateProcess*.
        unsafe {
            WaitForSingleObject(info.hProcess, INFINITE);
            check(GetExitCodeProcess(info.hProcess, &mut code))?;
            CloseHandle(info.hThread);
            CloseHandle(info.hProcess);
        }
        Ok(code)
    }

    /// Starts `argv` under this process's token with `disable` made deny-only.
    pub fn escape(disable: &str, argv: &[String]) -> io::Result<u32> {
        let own = own_token()?;
        let sids: Vec<Sid> = match disable {
            "none" => Vec::new(),
            list => list
                .split(',')
                .map(|name| match name {
                    "user" => user_sid(own),
                    name => account_sid(name),
                })
                .collect::<io::Result<_>>()?,
        };
        let entries: Vec<SID_AND_ATTRIBUTES> = sids
            .iter()
            .map(|sid| SID_AND_ATTRIBUTES {
                Sid: sid.as_psid(),
                Attributes: 0,
            })
            .collect();
        let mut token: HANDLE = null_mut();
        // SAFETY: the SIDs outlive the call.
        check(unsafe {
            CreateRestrictedToken(
                own,
                0,
                entries.len() as u32,
                entries.as_ptr(),
                0,
                null(),
                0,
                null(),
                &mut token,
            )
        })
        .map_err(|err| io::Error::other(format!("CreateRestrictedToken: {err}")))?;
        let disabled: Vec<String> = sids.iter().map(Sid::text).collect();
        eprintln!("winbox: deny-only {disabled:?}");
        let mut line = command_line(argv);
        let startup = startup();
        let mut info = PROCESS_INFORMATION::default();
        // SAFETY: the command line is mutable and NUL-terminated; the std handles are open.
        check(unsafe {
            CreateProcessAsUserW(
                token,
                null(),
                line.as_mut_ptr(),
                null(),
                null(),
                1,
                0,
                null(),
                null(),
                &startup,
                &mut info,
            )
        })
        .map_err(|err| io::Error::other(format!("CreateProcessAsUserW: {err}")))?;
        wait(info)
    }

    pub fn package_sid(name: &str) -> io::Result<String> {
        Ok(package(name)?.text())
    }

    fn package(name: &str) -> io::Result<Sid> {
        let wname = wide(name);
        let mut psid: PSID = null_mut();
        // SAFETY: NUL-terminated strings; no capabilities.
        let code = unsafe {
            CreateAppContainerProfile(
                wname.as_ptr(),
                wname.as_ptr(),
                wname.as_ptr(),
                null(),
                0,
                &mut psid,
            )
        };
        if code != 0 && code != ALREADY_EXISTS {
            eprintln!("winbox: CreateAppContainerProfile {code:#010x}; deriving the SID only");
        }
        if code != 0 {
            // SAFETY: as above.
            hresult(unsafe {
                DeriveAppContainerSidFromAppContainerName(wname.as_ptr(), &mut psid)
            })?;
        }
        // SAFETY: a valid SID until FreeSid.
        let sid = unsafe { Sid::copy(psid) };
        // SAFETY: allocated by the profile API.
        unsafe { FreeSid(psid) };
        Ok(sid)
    }

    fn capability(name: &str) -> io::Result<Sid> {
        match name {
            "internetClient" => Sid::parse("S-1-15-3-1"),
            "internetClientServer" => Sid::parse("S-1-15-3-2"),
            "privateNetwork" => Sid::parse("S-1-15-3-3"),
            other => Sid::parse(other),
        }
    }

    /// Starts `argv` in AppContainer `name` with `caps`.
    pub fn container(name: &str, caps: &str, argv: &[String]) -> io::Result<u32> {
        let package = package(name)?;
        let caps: Vec<Sid> = match caps {
            "none" => Vec::new(),
            list => list.split(',').map(capability).collect::<io::Result<_>>()?,
        };
        let mut entries: Vec<SID_AND_ATTRIBUTES> = caps
            .iter()
            .map(|sid| SID_AND_ATTRIBUTES {
                Sid: sid.as_psid(),
                Attributes: SE_GROUP_ENABLED,
            })
            .collect();
        let capabilities = SECURITY_CAPABILITIES {
            AppContainerSid: package.as_psid(),
            Capabilities: if entries.is_empty() {
                null_mut()
            } else {
                entries.as_mut_ptr()
            },
            CapabilityCount: entries.len() as u32,
            Reserved: 0,
        };
        eprintln!("winbox: package {}", package.text());
        let mut size = 0usize;
        // SAFETY: the sizing call.
        unsafe { InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut size) };
        let mut list = vec![0u64; size.div_ceil(8)];
        let attributes = list.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
        // SAFETY: the buffer has the size the first call asked for.
        check(unsafe { InitializeProcThreadAttributeList(attributes, 1, 0, &mut size) })?;
        // SAFETY: `capabilities` and what it points to outlive the process creation below.
        check(unsafe {
            UpdateProcThreadAttribute(
                attributes,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                &capabilities as *const _ as *const c_void,
                size_of::<SECURITY_CAPABILITIES>(),
                null_mut(),
                null(),
            )
        })?;
        let startup = STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: size_of::<STARTUPINFOEXW>() as u32,
                ..startup()
            },
            lpAttributeList: attributes,
        };
        let mut line = command_line(argv);
        let mut info = PROCESS_INFORMATION::default();
        // SAFETY: as in `escape`; the attribute list is initialised.
        let created = check(unsafe {
            CreateProcessW(
                null(),
                line.as_mut_ptr(),
                null(),
                null(),
                1,
                EXTENDED_STARTUPINFO_PRESENT,
                null(),
                null(),
                &startup.StartupInfo,
                &mut info,
            )
        });
        // SAFETY: initialised above.
        unsafe { DeleteProcThreadAttributeList(attributes) };
        created?;
        wait(info)
    }

    const SUBLAYER: GUID = GUID::from_u128(0x5e0a3c1d_2b4f_4c6a_9d8e_1f2a3b4c5d6e);

    fn fwp(code: u32) -> io::Result<()> {
        if code == 0 {
            Ok(())
        } else {
            Err(io::Error::other(format!("WFP {code:#010x}")))
        }
    }

    /// Adds the rules in a dynamic WFP session, prints `ready`, and removes them (by closing
    /// the session) when stdin closes.
    pub fn wfp_hold(rules: &[String]) -> io::Result<u32> {
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            txnWaitTimeoutInMSec: 10_000,
            ..Default::default()
        };
        let mut engine: HANDLE = null_mut();
        // SAFETY: `session` lives across the call.
        fwp(unsafe {
            FwpmEngineOpen0(
                null(),
                RPC_C_AUTHN_DEFAULT as u32,
                null(),
                &session,
                &mut engine,
            )
        })?;
        let name = wide("winbox");
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_ptr() as *mut u16,
                description: null_mut(),
            },
            weight: 0xffff,
            ..Default::default()
        };
        // SAFETY: as above.
        fwp(unsafe { FwpmSubLayerAdd0(engine, &sublayer, null_mut()) })?;
        for rule in rules {
            let parts: Vec<&str> = rule.split(':').collect();
            match parts.as_slice() {
                ["block-package", sid] => {
                    let sid = Sid::parse(sid)?;
                    for layer in [
                        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                    ] {
                        add(
                            engine,
                            layer,
                            FWP_ACTION_BLOCK,
                            1,
                            0,
                            &mut [package_cond(&sid)],
                        )?;
                    }
                }
                ["permit-package-loopback", sid, lo, hi] => {
                    let sid = Sid::parse(sid)?;
                    let mut v4 = FWP_V4_ADDR_AND_MASK {
                        addr: 0x7f00_0000,
                        mask: 0xff00_0000,
                    };
                    let mut range = FWP_RANGE0 {
                        valueLow: u16_value(lo.parse().map_err(io::Error::other)?),
                        valueHigh: u16_value(hi.parse().map_err(io::Error::other)?),
                    };
                    let mut conds = [
                        package_cond(&sid),
                        FWPM_FILTER_CONDITION0 {
                            fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                            matchType: FWP_MATCH_EQUAL,
                            conditionValue: FWP_CONDITION_VALUE0 {
                                r#type: FWP_V4_ADDR_MASK,
                                Anonymous: FWP_CONDITION_VALUE0_0 {
                                    v4AddrMask: &mut v4,
                                },
                            },
                        },
                        FWPM_FILTER_CONDITION0 {
                            fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                            matchType: FWP_MATCH_RANGE,
                            conditionValue: FWP_CONDITION_VALUE0 {
                                r#type: FWP_RANGE_TYPE,
                                Anonymous: FWP_CONDITION_VALUE0_0 {
                                    rangeValue: &mut range,
                                },
                            },
                        },
                    ];
                    add(
                        engine,
                        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                        FWP_ACTION_PERMIT,
                        10,
                        FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
                        &mut conds,
                    )?;
                }
                ["block-user", sid, port] => {
                    let sddl = wide(&format!("O:LSD:(A;;CC;;;{sid})"));
                    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
                    let mut size = 0u32;
                    // SAFETY: a NUL-terminated string in, a LocalAlloc'd descriptor out.
                    check(unsafe {
                        ConvertStringSecurityDescriptorToSecurityDescriptorW(
                            sddl.as_ptr(),
                            SDDL_REVISION_1,
                            &mut sd,
                            &mut size,
                        )
                    })?;
                    let mut blob = FWP_BYTE_BLOB {
                        size,
                        data: sd as *mut u8,
                    };
                    let port: u16 = port.parse().map_err(io::Error::other)?;
                    let mut conds = [
                        FWPM_FILTER_CONDITION0 {
                            fieldKey: FWPM_CONDITION_ALE_USER_ID,
                            matchType: FWP_MATCH_EQUAL,
                            conditionValue: FWP_CONDITION_VALUE0 {
                                r#type: FWP_SECURITY_DESCRIPTOR_TYPE,
                                Anonymous: FWP_CONDITION_VALUE0_0 { sd: &mut blob },
                            },
                        },
                        FWPM_FILTER_CONDITION0 {
                            fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                            matchType: FWP_MATCH_EQUAL,
                            conditionValue: FWP_CONDITION_VALUE0 {
                                r#type: FWP_UINT16,
                                Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port },
                            },
                        },
                    ];
                    add(
                        engine,
                        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                        FWP_ACTION_BLOCK,
                        1,
                        0,
                        &mut conds,
                    )?;
                    // SAFETY: allocated by the conversion; the engine copied it.
                    unsafe { LocalFree(sd) };
                }
                _ => return Err(io::Error::other(format!("bad rule {rule}"))),
            }
        }
        println!("ready");
        io::stdout().flush()?;
        for _ in io::stdin().lock().lines() {}
        // SAFETY: open; closing the dynamic session removes everything it added.
        unsafe { FwpmEngineClose0(engine) };
        Ok(0)
    }

    fn u16_value(port: u16) -> FWP_VALUE0 {
        FWP_VALUE0 {
            r#type: FWP_UINT16,
            Anonymous: FWP_VALUE0_0 { uint16: port },
        }
    }

    fn package_cond(sid: &Sid) -> FWPM_FILTER_CONDITION0 {
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_PACKAGE_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_SID,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    sid: sid.as_psid() as *mut SID,
                },
            },
        }
    }

    fn add(
        engine: HANDLE,
        layer: GUID,
        action: FWP_ACTION_TYPE,
        weight: u8,
        flags: u32,
        conds: &mut [FWPM_FILTER_CONDITION0],
    ) -> io::Result<()> {
        let name = wide("winbox");
        let filter = FWPM_FILTER0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_ptr() as *mut u16,
                description: null_mut(),
            },
            flags,
            layerKey: layer,
            subLayerKey: SUBLAYER,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: weight },
            },
            numFilterConditions: conds.len() as u32,
            filterCondition: conds.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: action,
                Anonymous: FWPM_ACTION0_0 {
                    filterType: GUID::from_u128(0),
                },
            },
            ..Default::default()
        };
        let mut id = 0u64;
        // SAFETY: the filter and the conditions' values live across the call.
        fwp(unsafe { FwpmFilterAdd0(engine, &filter, null_mut(), &mut id) })
    }
}
