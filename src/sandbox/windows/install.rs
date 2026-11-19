//! `happy-supervisor install-sandbox`: the one-time, administrator step that creates the
//! sandbox accounts, their groups and the WFP filters, and records them in [`Install`].

use std::ffi::c_void;
use std::io;
use std::ops::RangeInclusive;
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    LOCALGROUP_INFO_1, LOCALGROUP_MEMBERS_INFO_0, NetLocalGroupAdd, NetLocalGroupAddMembers,
    NetLocalGroupDel, NetUserAdd, NetUserDel, NetUserSetInfo, UF_DONT_EXPIRE_PASSWD,
    UF_PASSWD_CANT_CHANGE, UF_SCRIPT, USER_INFO_1, USER_INFO_1003, USER_PRIV_USER,
};
use windows_sys::Win32::Security::{LookupAccountNameW, LookupAccountSidW, SID_NAME_USE};

use super::net;
use super::win::{Sid, check, check_code, protect, random, unprotect, wide};

/// Bumped when the accounts, groups or filters change shape, so an older install reports the
/// sandbox unavailable instead of half-working.
pub(super) const VERSION: u32 = 2;

const DEFAULT_ACCOUNTS: usize = 8;

/// What `install-sandbox` created, as `install.json` in [`dir`]. Only the installing account
/// (and SYSTEM and Administrators) can read the directory, and the passwords are DPAPI-encrypted
/// for that account, so the supervisor must run as the account that installed it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Install {
    pub version: u32,
    /// The loopback ports the isolated sandbox may connect to: where command proxies listen.
    pub proxy_ports: (u16, u16),
    pub groups: NetGroups,
    pub slots: Vec<Slot>,
}

/// The network groups. WFP filters match them; an account's [`NetProfile`] fixes which ones it
/// belongs to, so a command cannot leave one.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct NetGroups {
    /// Outbound and inbound IP blocked, except TCP to `proxy_ports` on loopback.
    pub isolated: String,
    /// TCP listen blocked.
    pub no_listen: String,
    /// All loopback traffic permitted (isolated with `localBind`).
    pub loopback: String,
}

/// Which network rules an account is under, from the policy's `network`: its mode and
/// `localBind`. Each profile has its own accounts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum NetProfile {
    /// Host networking with `localBind`: no filters.
    Host,
    /// Host networking without `localBind`.
    HostNoListen,
    /// Isolated without `localBind`.
    Isolated,
    /// Isolated with `localBind`: loopback is open too.
    IsolatedLoopback,
}

impl NetProfile {
    pub(super) const ALL: [NetProfile; 4] = [
        NetProfile::Host,
        NetProfile::HostNoListen,
        NetProfile::Isolated,
        NetProfile::IsolatedLoopback,
    ];

    pub(super) fn of(network: &crate::policy::Network) -> NetProfile {
        use crate::policy::Network;
        match network {
            Network::Host {
                local_bind: true, ..
            } => NetProfile::Host,
            Network::Host {
                local_bind: false, ..
            } => NetProfile::HostNoListen,
            Network::Isolated {
                local_bind: false, ..
            } => NetProfile::Isolated,
            Network::Isolated {
                local_bind: true, ..
            } => NetProfile::IsolatedLoopback,
        }
    }

    /// The letter in its accounts' names.
    fn code(self) -> char {
        match self {
            NetProfile::Host => 'h',
            NetProfile::HostNoListen => 'n',
            NetProfile::Isolated => 'i',
            NetProfile::IsolatedLoopback => 'l',
        }
    }

    /// The network groups (of [`NET_GROUPS`], in that order) its accounts belong to.
    fn groups(self) -> &'static [usize] {
        match self {
            NetProfile::Host => &[],
            NetProfile::HostNoListen => &[1],
            NetProfile::Isolated => &[0, 1],
            NetProfile::IsolatedLoopback => &[0, 2],
        }
    }

    /// The SIDs of the network groups its accounts belong to.
    pub(super) fn group_sids(self, groups: &NetGroups) -> Vec<String> {
        let all = [&groups.isolated, &groups.no_listen, &groups.loopback];
        self.groups().iter().map(|&i| all[i].clone()).collect()
    }
}

/// One account of the pool. A command leases a slot of its network profile for its lifetime;
/// every ACE the sandbox adds names the slot's own group, never the account, so files the
/// account owns from an earlier lease give a later one no owner rights in the restricted check.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Slot {
    pub account: String,
    pub net: NetProfile,
    pub group: String,
    pub group_sid: String,
    /// DPAPI-encrypted for the installing account, base64.
    pub password: String,
}

impl Slot {
    pub(super) fn password(&self) -> io::Result<String> {
        let sealed = BASE64
            .decode(&self.password)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        String::from_utf8(unprotect(&sealed)?)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    }
}

impl Install {
    pub(super) fn load() -> io::Result<Install> {
        let text = std::fs::read(dir().join("install.json"))?;
        serde_json::from_slice(&text).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    }

    pub(super) fn proxy_ports(&self) -> RangeInclusive<u16> {
        self.proxy_ports.0..=self.proxy_ports.1
    }
}

/// `%ProgramData%\happy-supervisor\sandbox`: the install record and the slots' lease journals.
pub(super) fn dir() -> PathBuf {
    let data = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
    PathBuf::from(data).join("happy-supervisor").join("sandbox")
}

#[derive(Debug, clap::Args)]
pub struct InstallArgs {
    /// How many sandboxed operations of one network profile can run at once: one account each,
    /// for each of the four profiles.
    #[arg(long, default_value_t = DEFAULT_ACCOUNTS)]
    accounts: usize,
    /// The loopback ports isolated commands may reach, where their proxies listen.
    #[arg(long, value_parser = parse_ports, default_value = "47800-47999")]
    proxy_ports: RangeInclusive<u16>,
    /// Remove the accounts, groups, filters and records instead.
    #[arg(long)]
    uninstall: bool,
}

fn parse_ports(text: &str) -> Result<RangeInclusive<u16>, String> {
    let (low, high) = text.split_once('-').ok_or("expected LOW-HIGH")?;
    let low: u16 = low.parse().map_err(|_| format!("bad port {low:?}"))?;
    let high: u16 = high.parse().map_err(|_| format!("bad port {high:?}"))?;
    if low == 0 || low > high {
        return Err(format!("{text} is not a port range"));
    }
    Ok(low..=high)
}

/// Runs `install-sandbox`. Idempotent: running it again resets the passwords and filters.
pub fn install_main(args: InstallArgs) -> std::process::ExitCode {
    let result = if args.uninstall {
        uninstall()
    } else {
        install(args.accounts, args.proxy_ports)
    };
    match result {
        Ok(message) => {
            println!("{message}");
            std::process::ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("happy-supervisor install-sandbox: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn account_name(net: NetProfile, slot: usize) -> String {
    format!("happy-sbx-{}{slot:02}", net.code())
}

/// The accounts of version 1, one pool for every profile.
fn legacy_account_name(slot: usize) -> String {
    format!("happy-sbx-{slot:02}")
}

const NET_GROUPS: [&str; 3] = [
    "happy-sbx-isolated",
    "happy-sbx-nolisten",
    "happy-sbx-loopback",
];

fn install(accounts: usize, proxy_ports: RangeInclusive<u16>) -> io::Result<String> {
    if !(1..=99).contains(&accounts) {
        return Err(io::Error::other("--accounts must be between 1 and 99"));
    }
    let dir = dir();
    std::fs::create_dir_all(&dir)?;
    lock_down(&dir)?;

    let users = account_by_sid("S-1-5-32-545")?;
    let mut net_sids = Vec::new();
    for name in NET_GROUPS {
        ensure_group(name, "happy-supervisor sandbox network rules")?;
        net_sids.push(sid_of(name)?);
    }
    for slot in 1..=99 {
        let account = legacy_account_name(slot);
        ignore_missing(delete_user(&account))?;
        ignore_missing(delete_group(&format!("{account}-files")))?;
    }
    let mut slots = Vec::new();
    for net in NetProfile::ALL {
        for slot in 1..=accounts {
            let account = account_name(net, slot);
            let group = format!("{account}-files");
            let password = new_password()?;
            ensure_user(&account, &password)?;
            ensure_group(&group, "happy-supervisor sandbox file access, one account")?;
            let account_sid = sid_of(&account)?;
            let net_groups = net.groups().iter().map(|&i| NET_GROUPS[i]);
            for member_of in [users.as_str(), group.as_str()]
                .into_iter()
                .chain(net_groups)
            {
                add_member(member_of, &account_sid)?;
            }
            slots.push(Slot {
                group_sid: sid_of(&group)?.to_text()?,
                group,
                account,
                net,
                password: BASE64.encode(protect(password.as_bytes())?),
            });
        }
    }
    let groups = NetGroups {
        isolated: net_sids[0].to_text()?,
        no_listen: net_sids[1].to_text()?,
        loopback: net_sids[2].to_text()?,
    };
    let filters = net::install(&groups, &proxy_ports)?;
    let record = Install {
        version: VERSION,
        proxy_ports: (*proxy_ports.start(), *proxy_ports.end()),
        groups,
        slots,
    };
    let path = dir.join("install.json");
    let staged = dir.join("install.json.new");
    std::fs::write(
        &staged,
        serde_json::to_vec_pretty(&record).expect("serializes"),
    )?;
    std::fs::rename(&staged, &path)?;
    Ok(format!(
        "installed {} sandbox accounts ({accounts} per network profile) and {filters} WFP filters; proxy ports {}-{}; record {}",
        record.slots.len(),
        proxy_ports.start(),
        proxy_ports.end(),
        path.display()
    ))
}

fn uninstall() -> io::Result<String> {
    net::uninstall()?;
    let accounts: Vec<String> = match Install::load() {
        Ok(install) => install.slots.into_iter().map(|slot| slot.account).collect(),
        Err(_) => NetProfile::ALL
            .into_iter()
            .flat_map(|net| (1..=99).map(move |slot| account_name(net, slot)))
            .chain((1..=99).map(legacy_account_name))
            .collect(),
    };
    for account in accounts {
        ignore_missing(delete_user(&account))?;
        ignore_missing(delete_group(&format!("{account}-files")))?;
    }
    for name in NET_GROUPS {
        ignore_missing(delete_group(name))?;
    }
    match std::fs::remove_dir_all(dir()) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
        _ => {}
    }
    Ok("removed the sandbox accounts, groups, filters and records".to_string())
}

fn ignore_missing(result: io::Result<()>) -> io::Result<()> {
    const NERR_USER_NOT_FOUND: i32 = 2221;
    const ERROR_NO_SUCH_ALIAS: i32 = 1376;
    const NERR_GROUP_NOT_FOUND: i32 = 2220;
    match result {
        Err(err)
            if matches!(
                err.raw_os_error(),
                Some(NERR_USER_NOT_FOUND | ERROR_NO_SUCH_ALIAS | NERR_GROUP_NOT_FOUND)
            ) =>
        {
            Ok(())
        }
        other => other,
    }
}

/// Only SYSTEM, Administrators and the installing account may use the directory: the sandbox
/// accounts are ordinary users, and `ProgramData` lets users read and create.
fn lock_down(dir: &std::path::Path) -> io::Result<()> {
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
        SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
    };
    let me = super::token::current_user()?.to_text()?;
    let sddl = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{me})");
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: a NUL-terminated SDDL string in, a LocalAlloc'd descriptor out.
    check(unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(&sddl).as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    })?;
    let sd = super::win::Local(sd);
    let (mut present, mut dacl, mut defaulted) = (0, std::ptr::null_mut(), 0);
    // SAFETY: `sd` is the valid descriptor made above; the DACL points into it.
    check(unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted) })?;
    // SAFETY: a NUL-terminated path and a DACL that lives in `sd` until the call returns.
    check_code(unsafe {
        SetNamedSecurityInfoW(
            wide(dir).as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    })
}

/// 32 random bytes as base64, plus characters from each class Windows' complexity rule wants.
fn new_password() -> io::Result<String> {
    let mut bytes = [0u8; 32];
    random(&mut bytes)?;
    Ok(format!("{}aA1!", BASE64.encode(bytes)))
}

fn ensure_user(name: &str, password: &str) -> io::Result<()> {
    const NERR_USER_EXISTS: u32 = 2224;
    let name_w = wide(name);
    let password_w = wide(password);
    let comment = wide("happy-supervisor sandbox account");
    let info = USER_INFO_1 {
        usri1_name: name_w.as_ptr() as *mut u16,
        usri1_password: password_w.as_ptr() as *mut u16,
        usri1_password_age: 0,
        usri1_priv: USER_PRIV_USER,
        usri1_home_dir: std::ptr::null_mut(),
        usri1_comment: comment.as_ptr() as *mut u16,
        usri1_flags: UF_SCRIPT | UF_DONT_EXPIRE_PASSWD | UF_PASSWD_CANT_CHANGE,
        usri1_script_path: std::ptr::null_mut(),
    };
    // SAFETY: `info` and the strings it points to live across the call.
    let status = unsafe {
        NetUserAdd(
            std::ptr::null(),
            1,
            (&raw const info).cast(),
            std::ptr::null_mut(),
        )
    };
    if status != NERR_USER_EXISTS {
        return check_code(status);
    }
    let reset = USER_INFO_1003 {
        usri1003_password: password_w.as_ptr() as *mut u16,
    };
    // SAFETY: as above.
    check_code(unsafe {
        NetUserSetInfo(
            std::ptr::null(),
            name_w.as_ptr(),
            1003,
            (&raw const reset).cast(),
            std::ptr::null_mut(),
        )
    })
}

fn ensure_group(name: &str, comment: &str) -> io::Result<()> {
    const ERROR_ALIAS_EXISTS: u32 = 1379;
    const NERR_GROUP_EXISTS: u32 = 2223;
    let name_w = wide(name);
    let comment_w = wide(comment);
    let info = LOCALGROUP_INFO_1 {
        lgrpi1_name: name_w.as_ptr() as *mut u16,
        lgrpi1_comment: comment_w.as_ptr() as *mut u16,
    };
    // SAFETY: `info` and its strings live across the call.
    let status = unsafe {
        NetLocalGroupAdd(
            std::ptr::null(),
            1,
            (&raw const info).cast(),
            std::ptr::null_mut(),
        )
    };
    match status {
        ERROR_ALIAS_EXISTS | NERR_GROUP_EXISTS => Ok(()),
        status => check_code(status),
    }
}

fn add_member(group: &str, member: &Sid) -> io::Result<()> {
    const ERROR_MEMBER_IN_ALIAS: u32 = 1378;
    let info = LOCALGROUP_MEMBERS_INFO_0 {
        lgrmi0_sid: member.as_psid(),
    };
    // SAFETY: `info` and the SID it points to live across the call.
    let status = unsafe {
        NetLocalGroupAddMembers(
            std::ptr::null(),
            wide(group).as_ptr(),
            0,
            (&raw const info).cast(),
            1,
        )
    };
    match status {
        ERROR_MEMBER_IN_ALIAS => Ok(()),
        status => check_code(status),
    }
}

fn delete_user(name: &str) -> io::Result<()> {
    // SAFETY: a NUL-terminated name.
    check_code(unsafe { NetUserDel(std::ptr::null(), wide(name).as_ptr()) })
}

fn delete_group(name: &str) -> io::Result<()> {
    // SAFETY: a NUL-terminated name.
    check_code(unsafe { NetLocalGroupDel(std::ptr::null(), wide(name).as_ptr()) })
}

/// The SID of a local account or group.
pub(super) fn sid_of(name: &str) -> io::Result<Sid> {
    let name_w = wide(name);
    let mut sid = vec![0u8; 68];
    let mut sid_len = sid.len() as u32;
    let mut domain = vec![0u16; 256];
    let mut domain_len = domain.len() as u32;
    let mut kind: SID_NAME_USE = 0;
    // SAFETY: every buffer is valid for the length passed with it.
    check(unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            name_w.as_ptr(),
            sid.as_mut_ptr() as *mut c_void,
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    })?;
    // SAFETY: LookupAccountNameW wrote a valid SID.
    Ok(unsafe { Sid::copy(sid.as_mut_ptr() as *mut c_void) })
}

/// The local name of a well-known SID, such as `Users` for `S-1-5-32-545` on English Windows.
fn account_by_sid(sid: &str) -> io::Result<String> {
    let sid = Sid::parse(sid)?;
    let mut name = vec![0u16; 256];
    let mut name_len = name.len() as u32;
    let mut domain = vec![0u16; 256];
    let mut domain_len = domain.len() as u32;
    let mut kind: SID_NAME_USE = 0;
    // SAFETY: every buffer is valid for the length passed with it.
    check(unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid.as_psid(),
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    })?;
    Ok(String::from_utf16_lossy(&name[..name_len as usize]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_ranges() {
        assert_eq!(parse_ports("47800-47999"), Ok(47800..=47999));
        assert_eq!(parse_ports("5-5"), Ok(5..=5));
        assert_eq!(
            parse_ports("9-1"),
            Err("9-1 is not a port range".to_string())
        );
        assert_eq!(
            parse_ports("0-1"),
            Err("0-1 is not a port range".to_string())
        );
        assert_eq!(parse_ports("80"), Err("expected LOW-HIGH".to_string()));
    }

    #[test]
    fn account_names_fit_the_twenty_character_limit() {
        assert_eq!(account_name(NetProfile::Host, 1), "happy-sbx-h01");
        assert_eq!(
            account_name(NetProfile::IsolatedLoopback, 99),
            "happy-sbx-l99"
        );
        assert_eq!(
            format!("{}-files", account_name(NetProfile::Isolated, 99)).len(),
            19
        );
    }

    #[test]
    fn each_profile_belongs_to_its_network_groups() {
        let groups = NetGroups {
            isolated: "S-1-5-21-1-1001".to_string(),
            no_listen: "S-1-5-21-1-1002".to_string(),
            loopback: "S-1-5-21-1-1003".to_string(),
        };
        let sids = |net: NetProfile| net.group_sids(&groups);
        assert_eq!(sids(NetProfile::Host), Vec::<String>::new());
        assert_eq!(sids(NetProfile::HostNoListen), ["S-1-5-21-1-1002"]);
        assert_eq!(
            sids(NetProfile::Isolated),
            ["S-1-5-21-1-1001", "S-1-5-21-1-1002"]
        );
        assert_eq!(
            sids(NetProfile::IsolatedLoopback),
            ["S-1-5-21-1-1001", "S-1-5-21-1-1003"]
        );
    }
}
