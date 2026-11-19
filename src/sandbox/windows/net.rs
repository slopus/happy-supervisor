// Derived from codex-rs/windows-sandbox-rs/src/wfp.rs (OpenAI Codex, Copyright 2025 OpenAI,
// Apache License 2.0). Changed: the filters are a table keyed on the sandbox's network groups
// instead of one account, blocks match a group through a deny ACE so a command cannot step out
// of them, and permit filters carve the proxy ports and loopback out of the blocks.

//! The persistent WFP filters behind `network` (policy.md, Network), keyed on the network
//! groups the sandbox accounts belong to (`install::NetProfile`).
//!
//! A filter's `ALE_USER_ID` condition is an access check of the connecting token against a
//! security descriptor. An allow ACE matches only an enabled group, and any process can make
//! its own groups deny-only in a restricted token of its own, so a block keyed on an allow ACE
//! is one the command can leave. A deny ACE matches the group enabled or deny-only, and no
//! process can drop a group from its token altogether. So a block matches when the check
//! against `(D;;CC;;;group)(A;;CC;;;WD)...` fails (`FWP_MATCH_NOT_EQUAL`), and a permit when
//! the check against `(A;;CC;;;group)` passes: a command can lose a permit, never gain one, and
//! never shed a block. The allow ACEs for Everyone, RESTRICTED and WRITE RESTRICTED keep other
//! processes' restricted tokens passing the check; one restricted to none of them fails it and
//! falls under the blocks.

use std::io;
use std::ops::RangeInclusive;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_ACTION_TYPE, FWP_BYTE_BLOB, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_EMPTY, FWP_MATCH_EQUAL, FWP_MATCH_NOT_EQUAL, FWP_MATCH_RANGE,
    FWP_MATCH_TYPE, FWP_RANGE_TYPE, FWP_RANGE0, FWP_SECURITY_DESCRIPTOR_TYPE, FWP_UINT8,
    FWP_UINT16, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK,
    FWP_VALUE0, FWP_VALUE0_0, FWPM_ACTION0, FWPM_ACTION0_0, FWPM_CONDITION_ALE_USER_ID,
    FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_DISPLAY_DATA0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER0,
    FWPM_FILTER0_0, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_LISTEN_V4, FWPM_LAYER_ALE_AUTH_LISTEN_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_PROVIDER0, FWPM_SESSION0, FWPM_SUBLAYER_FLAG_PERSISTENT,
    FWPM_SUBLAYER0, FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteByKey0,
    FwpmProviderAdd0, FwpmProviderDeleteByKey0, FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0,
    FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;
use windows_sys::core::GUID;

use super::install::NetGroups;
use super::win::{Local, check, wide};

// Stable identities of our WFP objects: an install replaces filters with the same keys, and
// uninstall finds them. Never regenerate them.
const PROVIDER_KEY: GUID = GUID::from_u128(0x6f1d5c2e_8a3b_4b7e_9c41_2d7a5e0b9f13);
const SUBLAYER_KEY: GUID = GUID::from_u128(0x3c9e7a41_5b2d_4f86_a1e3_7d40c2b6e858);

const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;
const FWP_E_FILTER_NOT_FOUND: u32 = 0x8032_0003;
const FWP_E_NOT_FOUND: u32 = 0x8032_0008;
const FWP_E_PROVIDER_NOT_FOUND: u32 = 0x8032_0005;
const FWP_E_SUBLAYER_NOT_FOUND: u32 = 0x8032_0007;
const IPPROTO_TCP: u8 = 6;

/// Permits outrank blocks within our sublayer.
const PERMIT_WEIGHT: u8 = 10;
const BLOCK_WEIGHT: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Who {
    Isolated,
    NoListen,
    Loopback,
}

#[derive(Clone, Copy, Debug)]
enum Cond {
    Tcp,
    LoopbackV4,
    LoopbackV6,
    ProxyPorts,
}

struct FilterSpec {
    key: GUID,
    name: &'static str,
    layer: GUID,
    action: FWP_ACTION_TYPE,
    who: Who,
    conds: &'static [Cond],
}

const BLOCK: FWP_ACTION_TYPE = FWP_ACTION_BLOCK;
const PERMIT: FWP_ACTION_TYPE = FWP_ACTION_PERMIT;

const FILTERS: &[FilterSpec] = &[
    FilterSpec {
        key: GUID::from_u128(0x0a1f6b52_33c1_4d0e_8e2a_51f0c7d3a101),
        name: "happy-sandbox isolated: block connect v4",
        layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        action: BLOCK,
        who: Who::Isolated,
        conds: &[],
    },
    FilterSpec {
        key: GUID::from_u128(0x0a1f6b52_33c1_4d0e_8e2a_51f0c7d3a102),
        name: "happy-sandbox isolated: block connect v6",
        layer: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        action: BLOCK,
        who: Who::Isolated,
        conds: &[],
    },
    FilterSpec {
        key: GUID::from_u128(0x0a1f6b52_33c1_4d0e_8e2a_51f0c7d3a103),
        name: "happy-sandbox isolated: block accept v4",
        layer: FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        action: BLOCK,
        who: Who::Isolated,
        conds: &[],
    },
    FilterSpec {
        key: GUID::from_u128(0x0a1f6b52_33c1_4d0e_8e2a_51f0c7d3a104),
        name: "happy-sandbox isolated: block accept v6",
        layer: FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        action: BLOCK,
        who: Who::Isolated,
        conds: &[],
    },
    FilterSpec {
        key: GUID::from_u128(0x0a1f6b52_33c1_4d0e_8e2a_51f0c7d3a105),
        name: "happy-sandbox isolated: permit the proxy ports",
        layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        action: PERMIT,
        who: Who::Isolated,
        conds: &[Cond::Tcp, Cond::LoopbackV4, Cond::ProxyPorts],
    },
    FilterSpec {
        key: GUID::from_u128(0x0a1f6b52_33c1_4d0e_8e2a_51f0c7d3a106),
        name: "happy-sandbox loopback: permit connect v4",
        layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        action: PERMIT,
        who: Who::Loopback,
        conds: &[Cond::LoopbackV4],
    },
    FilterSpec {
        key: GUID::from_u128(0x0a1f6b52_33c1_4d0e_8e2a_51f0c7d3a107),
        name: "happy-sandbox loopback: permit connect v6",
        layer: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        action: PERMIT,
        who: Who::Loopback,
        conds: &[Cond::LoopbackV6],
    },
    FilterSpec {
        key: GUID::from_u128(0x0a1f6b52_33c1_4d0e_8e2a_51f0c7d3a108),
        name: "happy-sandbox loopback: permit accept v4",
        layer: FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        action: PERMIT,
        who: Who::Loopback,
        conds: &[Cond::LoopbackV4],
    },
    FilterSpec {
        key: GUID::from_u128(0x0a1f6b52_33c1_4d0e_8e2a_51f0c7d3a109),
        name: "happy-sandbox loopback: permit accept v6",
        layer: FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        action: PERMIT,
        who: Who::Loopback,
        conds: &[Cond::LoopbackV6],
    },
    FilterSpec {
        key: GUID::from_u128(0x0a1f6b52_33c1_4d0e_8e2a_51f0c7d3a10a),
        name: "happy-sandbox nolisten: block listen v4",
        layer: FWPM_LAYER_ALE_AUTH_LISTEN_V4,
        action: BLOCK,
        who: Who::NoListen,
        conds: &[],
    },
    FilterSpec {
        key: GUID::from_u128(0x0a1f6b52_33c1_4d0e_8e2a_51f0c7d3a10b),
        name: "happy-sandbox nolisten: block listen v6",
        layer: FWPM_LAYER_ALE_AUTH_LISTEN_V6,
        action: BLOCK,
        who: Who::NoListen,
        conds: &[],
    },
];

/// Replaces every filter, in one transaction. Returns how many there are.
pub(super) fn install(groups: &NetGroups, proxy_ports: &RangeInclusive<u16>) -> io::Result<usize> {
    let engine = Engine::open()?;
    let transaction = engine.begin()?;
    add_provider_and_sublayer(&engine)?;
    let sid = |who: Who| match who {
        Who::Isolated => &groups.isolated,
        Who::NoListen => &groups.no_listen,
        Who::Loopback => &groups.loopback,
    };
    for spec in FILTERS {
        delete_filter(&engine, &spec.key)?;
        let group = if spec.action == PERMIT {
            GroupMatch::enabled(sid(spec.who))?
        } else {
            GroupMatch::member(sid(spec.who))?
        };
        add_filter(&engine, spec, &group, proxy_ports)?;
    }
    transaction.commit()?;
    Ok(FILTERS.len())
}

pub(super) fn uninstall() -> io::Result<()> {
    let engine = Engine::open()?;
    let transaction = engine.begin()?;
    for spec in FILTERS {
        delete_filter(&engine, &spec.key)?;
    }
    // SAFETY: the engine handle is open; the keys are plain GUIDs.
    let sublayer = unsafe { FwpmSubLayerDeleteByKey0(engine.0, &SUBLAYER_KEY) };
    allow(sublayer, &[FWP_E_SUBLAYER_NOT_FOUND, FWP_E_NOT_FOUND])?;
    // SAFETY: as above.
    let provider = unsafe { FwpmProviderDeleteByKey0(engine.0, &PROVIDER_KEY) };
    allow(provider, &[FWP_E_PROVIDER_NOT_FOUND, FWP_E_NOT_FOUND])?;
    transaction.commit()
}

fn allow(code: u32, ok: &[u32]) -> io::Result<()> {
    if code == 0 || ok.contains(&code) {
        return Ok(());
    }
    Err(io::Error::other(format!("WFP call failed: {code:#010x}")))
}

struct Engine(HANDLE);

impl Engine {
    fn open() -> io::Result<Engine> {
        let name = wide("happy-supervisor sandbox");
        let session = FWPM_SESSION0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_ptr() as *mut u16,
                description: null_mut(),
            },
            txnWaitTimeoutInMSec: 10_000,
            ..Default::default()
        };
        let mut handle: HANDLE = null_mut();
        // SAFETY: `session` and its name live across the call.
        let code = unsafe {
            FwpmEngineOpen0(
                null(),
                RPC_C_AUTHN_DEFAULT as u32,
                null(),
                &session,
                &mut handle,
            )
        };
        allow(code, &[])?;
        Ok(Engine(handle))
    }

    fn begin(&self) -> io::Result<Transaction<'_>> {
        // SAFETY: the engine handle is open.
        allow(unsafe { FwpmTransactionBegin0(self.0, 0) }, &[])?;
        Ok(Transaction {
            engine: self,
            done: false,
        })
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: the handle is open and closed once, here.
        unsafe { FwpmEngineClose0(self.0) };
    }
}

/// Aborts unless committed.
struct Transaction<'a> {
    engine: &'a Engine,
    done: bool,
}

impl Transaction<'_> {
    fn commit(mut self) -> io::Result<()> {
        self.done = true;
        // SAFETY: the engine handle is open and in this transaction.
        allow(unsafe { FwpmTransactionCommit0(self.engine.0) }, &[])
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.done {
            // SAFETY: as in commit.
            unsafe { FwpmTransactionAbort0(self.engine.0) };
        }
    }
}

/// An `ALE_USER_ID` condition: a self-relative security descriptor and how to match it.
struct GroupMatch {
    /// Owns what `blob` points to.
    _sd: Local<core::ffi::c_void>,
    blob: FWP_BYTE_BLOB,
    match_type: FWP_MATCH_TYPE,
}

impl GroupMatch {
    /// Tokens that hold `sid` in any state, or that fail the check otherwise: for blocks.
    fn member(sid: &str) -> io::Result<GroupMatch> {
        GroupMatch::new(
            &format!("O:LSD:(D;;CC;;;{sid})(A;;CC;;;WD)(A;;CC;;;RC)(A;;CC;;;{WRITE_RESTRICTED})"),
            FWP_MATCH_NOT_EQUAL,
        )
    }

    /// Tokens in which `sid` is enabled: for permits.
    fn enabled(sid: &str) -> io::Result<GroupMatch> {
        GroupMatch::new(&format!("O:LSD:(A;;CC;;;{sid})"), FWP_MATCH_EQUAL)
    }

    fn new(sddl: &str, match_type: FWP_MATCH_TYPE) -> io::Result<GroupMatch> {
        let sddl = wide(sddl);
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let mut size = 0u32;
        // SAFETY: a NUL-terminated string in, a LocalAlloc'd self-relative descriptor out.
        check(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                &mut size,
            )
        })?;
        Ok(GroupMatch {
            blob: FWP_BYTE_BLOB {
                size,
                data: sd as *mut u8,
            },
            _sd: Local(sd),
            match_type,
        })
    }
}

/// The WRITE RESTRICTED SID, which write-restricted service tokens restrict to.
const WRITE_RESTRICTED: &str = "S-1-5-33";

fn add_provider_and_sublayer(engine: &Engine) -> io::Result<()> {
    let name = wide("happy-supervisor sandbox");
    let provider = FWPM_PROVIDER0 {
        providerKey: PROVIDER_KEY,
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_ptr() as *mut u16,
            description: null_mut(),
        },
        flags: FWPM_PROVIDER_FLAG_PERSISTENT,
        ..Default::default()
    };
    // SAFETY: `provider` and its name live across the call.
    let code = unsafe { FwpmProviderAdd0(engine.0, &provider, null_mut()) };
    allow(code, &[FWP_E_ALREADY_EXISTS])?;
    let mut provider_key = PROVIDER_KEY;
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: SUBLAYER_KEY,
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_ptr() as *mut u16,
            description: null_mut(),
        },
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        providerKey: &mut provider_key,
        weight: 0x8000,
        ..Default::default()
    };
    // SAFETY: as above.
    let code = unsafe { FwpmSubLayerAdd0(engine.0, &sublayer, null_mut()) };
    allow(code, &[FWP_E_ALREADY_EXISTS])
}

fn delete_filter(engine: &Engine, key: &GUID) -> io::Result<()> {
    // SAFETY: the engine handle is open.
    let code = unsafe { FwpmFilterDeleteByKey0(engine.0, key) };
    allow(code, &[FWP_E_FILTER_NOT_FOUND, FWP_E_NOT_FOUND])
}

fn add_filter(
    engine: &Engine,
    spec: &FilterSpec,
    group: &GroupMatch,
    proxy_ports: &RangeInclusive<u16>,
) -> io::Result<()> {
    let mut v4 = FWP_V4_ADDR_AND_MASK {
        addr: 0x7f00_0000,
        mask: 0xff00_0000,
    };
    let mut v6 = FWP_V6_ADDR_AND_MASK {
        addr: std::net::Ipv6Addr::LOCALHOST.octets(),
        prefixLength: 128,
    };
    let mut range = FWP_RANGE0 {
        valueLow: uint16(*proxy_ports.start()),
        valueHigh: uint16(*proxy_ports.end()),
    };
    let mut conditions = vec![FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_ALE_USER_ID,
        matchType: group.match_type,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_SECURITY_DESCRIPTOR_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                sd: &group.blob as *const _ as *mut _,
            },
        },
    }];
    for cond in spec.conds {
        let (field, match_type, value) = match cond {
            Cond::Tcp => (
                FWPM_CONDITION_IP_PROTOCOL,
                FWP_MATCH_EQUAL,
                FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint8: IPPROTO_TCP },
                },
            ),
            Cond::LoopbackV4 => (
                FWPM_CONDITION_IP_REMOTE_ADDRESS,
                FWP_MATCH_EQUAL,
                FWP_CONDITION_VALUE0 {
                    r#type: FWP_V4_ADDR_MASK,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        v4AddrMask: &mut v4,
                    },
                },
            ),
            Cond::LoopbackV6 => (
                FWPM_CONDITION_IP_REMOTE_ADDRESS,
                FWP_MATCH_EQUAL,
                FWP_CONDITION_VALUE0 {
                    r#type: FWP_V6_ADDR_MASK,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        v6AddrMask: &mut v6,
                    },
                },
            ),
            Cond::ProxyPorts => (
                FWPM_CONDITION_IP_REMOTE_PORT,
                FWP_MATCH_RANGE,
                FWP_CONDITION_VALUE0 {
                    r#type: FWP_RANGE_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        rangeValue: &mut range,
                    },
                },
            ),
        };
        conditions.push(FWPM_FILTER_CONDITION0 {
            fieldKey: field,
            matchType: match_type,
            conditionValue: value,
        });
    }
    let name = wide(spec.name);
    let mut provider_key = PROVIDER_KEY;
    let weight = if spec.action == PERMIT {
        PERMIT_WEIGHT
    } else {
        BLOCK_WEIGHT
    };
    let filter = FWPM_FILTER0 {
        filterKey: spec.key,
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_ptr() as *mut u16,
            description: null_mut(),
        },
        flags: FWPM_FILTER_FLAG_PERSISTENT,
        providerKey: &mut provider_key,
        layerKey: spec.layer,
        subLayerKey: SUBLAYER_KEY,
        weight: FWP_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_VALUE0_0 { uint8: weight },
        },
        numFilterConditions: conditions.len() as u32,
        filterCondition: conditions.as_mut_ptr(),
        action: FWPM_ACTION0 {
            r#type: spec.action,
            Anonymous: FWPM_ACTION0_0 {
                filterType: GUID::from_u128(0),
            },
        },
        Anonymous: FWPM_FILTER0_0 { rawContext: 0 },
        effectiveWeight: FWP_VALUE0 {
            r#type: FWP_EMPTY,
            Anonymous: FWP_VALUE0_0 { uint8: 0 },
        },
        ..Default::default()
    };
    let mut id = 0u64;
    // SAFETY: the filter, its conditions and every value they point to live across the call.
    let code = unsafe { FwpmFilterAdd0(engine.0, &filter, null_mut(), &mut id) };
    allow(code, &[]).map_err(|err| io::Error::other(format!("{}: {err}", spec.name)))
}

fn uint16(value: u16) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_UINT16,
        Anonymous: FWP_VALUE0_0 { uint16: value },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_keys_and_names_are_unique() {
        let mut keys: Vec<u128> = FILTERS
            .iter()
            .map(|f| {
                let GUID {
                    data1,
                    data2,
                    data3,
                    data4,
                } = f.key;
                (u128::from(data1) << 96)
                    | (u128::from(data2) << 80)
                    | (u128::from(data3) << 64)
                    | u128::from(u64::from_be_bytes(data4))
            })
            .collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), 11);
        let mut names: Vec<&str> = FILTERS.iter().map(|f| f.name).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), 11);
    }
}
