//! The traffic lock: while it exists, only the engine (and the verified
//! upstream client) may open connections through a physical interface.
//!
//! A socket bound to the physical interface or its address would otherwise
//! leave around the tunnel, and a dead engine would otherwise let traffic
//! fall back to the original routes. The lock is a WFP sublayer with
//! ALE connect filters. They are not added from a dynamic session and are not
//! persistent, so they outlive the service process but not a reboot. Only an
//! explicit user stop or recovery (or uninstall) removes them.
//!
//! Connection authorization is filtered, not receive: replies to inbound
//! connections and LAN traffic are untouched. DNS to port 53 on a physical
//! interface is refused for everything but the engine, so the system resolver
//! cannot answer around the tunnel.

use std::{net::Ipv6Addr, path::PathBuf};

/// Permit and block decisions in evaluation order (higher weight first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockRule {
    PermitApplication(PathBuf),
    PermitLoopback,
    BlockDns { interface_luid: u64 },
    PermitLocalV4 { address: u32, mask: u32 },
    PermitLocalV6 { address: Ipv6Addr, prefix: u8 },
    PermitDhcp,
    BlockInterface { interface_luid: u64 },
}

impl LockRule {
    pub fn weight(&self) -> u8 {
        match self {
            Self::PermitApplication(_) => 15,
            Self::PermitLoopback => 14,
            Self::BlockDns { .. } => 13,
            Self::PermitLocalV4 { .. } | Self::PermitLocalV6 { .. } => 12,
            Self::PermitDhcp => 11,
            Self::BlockInterface { .. } => 1,
        }
    }
}

const LOCAL_V4: [([u8; 4], u8); 6] = [
    ([10, 0, 0, 0], 8),
    ([172, 16, 0, 0], 12),
    ([192, 168, 0, 0], 16),
    ([169, 254, 0, 0], 16),
    ([224, 0, 0, 0], 4),
    ([255, 255, 255, 255], 32),
];
const LOCAL_V6: [(Ipv6Addr, u8); 3] = [
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
    (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
    (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
];
pub const MAX_RULES: usize = 64;

/// The full rule list: the engine and the verified upstream client, then
/// loopback, a DNS block on each physical interface, LAN and DHCP, and
/// finally a block of every new connection on each physical interface.
pub fn lock_rules(applications: &[PathBuf], physical_luids: &[u64]) -> Option<Vec<LockRule>> {
    if applications.is_empty()
        || physical_luids.is_empty()
        || physical_luids.contains(&0)
        || applications.iter().any(|path| !path.is_absolute())
    {
        return None;
    }
    let mut rules: Vec<LockRule> = applications
        .iter()
        .cloned()
        .map(LockRule::PermitApplication)
        .collect();
    rules.push(LockRule::PermitLoopback);
    rules.extend(
        physical_luids
            .iter()
            .map(|&interface_luid| LockRule::BlockDns { interface_luid }),
    );
    rules.extend(
        LOCAL_V4
            .iter()
            .map(|(address, prefix)| LockRule::PermitLocalV4 {
                address: u32::from_be_bytes(*address),
                mask: if *prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(*prefix))
                },
            }),
    );
    rules.extend(
        LOCAL_V6
            .iter()
            .map(|&(address, prefix)| LockRule::PermitLocalV6 { address, prefix }),
    );
    rules.push(LockRule::PermitDhcp);
    rules.extend(
        physical_luids
            .iter()
            .map(|&interface_luid| LockRule::BlockInterface { interface_luid }),
    );
    (rules.len() <= MAX_RULES).then_some(rules)
}

pub use native::{install, present, remove};

mod native {
    use super::{lock_rules, LockRule, MAX_RULES};
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt, path::PathBuf, ptr};
    use windows_sys::{
        core::GUID,
        Win32::{
            Foundation::{
                ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS, FWP_E_FILTER_NOT_FOUND,
                FWP_E_PROVIDER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, HANDLE,
            },
            NetworkManagement::{
                IpHelper::{
                    GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
                    IP_ADAPTER_ADDRESSES_LH,
                },
                WindowsFilteringPlatform::*,
            },
            Networking::WinSock::AF_UNSPEC,
            System::Rpc::RPC_C_AUTHN_WINNT,
        },
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TrafficLockError;

    const PROVIDER_KEY: GUID = GUID::from_u128(0x7b2b_5442_0d1e_4c3a_9b51_7d0e_5442_0001);
    const SUBLAYER_KEY: GUID = GUID::from_u128(0x7b2b_5442_0d1e_4c3a_9b51_7d0e_5442_0002);
    /// Filter keys are derived from this base, so removal never needs to
    /// enumerate (or trust) anything else in the filter store.
    const FILTER_KEY_BASE: u128 = 0x7b2b_5442_0d1e_4c3a_9b51_7d0e_5442_1000;
    const IF_TYPE_ETHERNET_CSMACD: u32 = 6;
    const IF_TYPE_IEEE80211: u32 = 71;
    const IF_OPER_STATUS_UP: i32 = 1;
    const IPPROTO_UDP: u8 = 17;

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(Some(0)).collect()
    }

    fn filter_key(index: usize, v6: bool) -> GUID {
        GUID::from_u128(FILTER_KEY_BASE + (index as u128) * 2 + u128::from(v6))
    }

    struct Engine(HANDLE);

    impl Engine {
        fn open() -> Result<Self, TrafficLockError> {
            // Not a dynamic session: the filters must outlive this process.
            let mut handle: HANDLE = ptr::null_mut();
            let status = unsafe {
                FwpmEngineOpen0(
                    ptr::null(),
                    RPC_C_AUTHN_WINNT,
                    ptr::null(),
                    ptr::null(),
                    &mut handle,
                )
            };
            if status != ERROR_SUCCESS || handle.is_null() {
                return Err(TrafficLockError);
            }
            Ok(Self(handle))
        }
    }

    impl Drop for Engine {
        fn drop(&mut self) {
            unsafe {
                FwpmEngineClose0(self.0);
            }
        }
    }

    fn ok_or_absent(status: u32, absent: i32) -> Result<(), TrafficLockError> {
        if status == ERROR_SUCCESS || status == absent as u32 {
            Ok(())
        } else {
            Err(TrafficLockError)
        }
    }

    /// Installs or atomically replaces the lock for `applications` (the
    /// engine first, then the verified upstream client).
    pub fn install(applications: &[PathBuf]) -> Result<(), TrafficLockError> {
        let rules =
            lock_rules(applications, &physical_interface_luids()?).ok_or(TrafficLockError)?;
        let engine = Engine::open()?;
        if unsafe { FwpmTransactionBegin0(engine.0, 0) } != ERROR_SUCCESS {
            return Err(TrafficLockError);
        }
        let result = replace_in_transaction(&engine, &rules);
        let status = if result.is_ok() {
            unsafe { FwpmTransactionCommit0(engine.0) }
        } else {
            unsafe { FwpmTransactionAbort0(engine.0) };
            return result;
        };
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(TrafficLockError)
        }
    }

    /// Removes the lock. Traffic goes directly again afterwards.
    pub fn remove() -> Result<(), TrafficLockError> {
        let engine = Engine::open()?;
        if unsafe { FwpmTransactionBegin0(engine.0, 0) } != ERROR_SUCCESS {
            return Err(TrafficLockError);
        }
        let result = remove_in_transaction(&engine);
        if result.is_ok() && unsafe { FwpmTransactionCommit0(engine.0) } == ERROR_SUCCESS {
            Ok(())
        } else {
            unsafe { FwpmTransactionAbort0(engine.0) };
            Err(TrafficLockError)
        }
    }

    pub fn present() -> Result<bool, TrafficLockError> {
        let engine = Engine::open()?;
        let mut sublayer: *mut FWPM_SUBLAYER0 = ptr::null_mut();
        let status = unsafe { FwpmSubLayerGetByKey0(engine.0, &SUBLAYER_KEY, &mut sublayer) };
        if !sublayer.is_null() {
            unsafe { FwpmFreeMemory0((&mut sublayer as *mut *mut FWPM_SUBLAYER0).cast()) };
        }
        match status {
            ERROR_SUCCESS => Ok(true),
            status if status == FWP_E_SUBLAYER_NOT_FOUND as u32 => Ok(false),
            _ => Err(TrafficLockError),
        }
    }

    fn remove_in_transaction(engine: &Engine) -> Result<(), TrafficLockError> {
        for index in 0..MAX_RULES {
            for v6 in [false, true] {
                let key = filter_key(index, v6);
                ok_or_absent(
                    unsafe { FwpmFilterDeleteByKey0(engine.0, &key) },
                    FWP_E_FILTER_NOT_FOUND,
                )?;
            }
        }
        ok_or_absent(
            unsafe { FwpmSubLayerDeleteByKey0(engine.0, &SUBLAYER_KEY) },
            FWP_E_SUBLAYER_NOT_FOUND,
        )?;
        ok_or_absent(
            unsafe { FwpmProviderDeleteByKey0(engine.0, &PROVIDER_KEY) },
            FWP_E_PROVIDER_NOT_FOUND,
        )
    }

    fn replace_in_transaction(engine: &Engine, rules: &[LockRule]) -> Result<(), TrafficLockError> {
        remove_in_transaction(engine)?;
        let mut name = wide("TunBridge traffic lock");
        let mut description = wide("Only the TunBridge tunnel may leave physical interfaces");
        let display = FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: description.as_mut_ptr(),
        };
        let provider = FWPM_PROVIDER0 {
            providerKey: PROVIDER_KEY,
            displayData: display,
            flags: 0,
            providerData: FWP_BYTE_BLOB {
                size: 0,
                data: ptr::null_mut(),
            },
            serviceName: ptr::null_mut(),
        };
        if unsafe { FwpmProviderAdd0(engine.0, &provider, ptr::null_mut()) } != ERROR_SUCCESS {
            return Err(TrafficLockError);
        }
        let mut provider_key = PROVIDER_KEY;
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_KEY,
            displayData: display,
            flags: 0,
            providerKey: &mut provider_key,
            providerData: FWP_BYTE_BLOB {
                size: 0,
                data: ptr::null_mut(),
            },
            weight: u16::MAX,
        };
        if unsafe { FwpmSubLayerAdd0(engine.0, &sublayer, ptr::null_mut()) } != ERROR_SUCCESS {
            return Err(TrafficLockError);
        }
        for (index, rule) in rules.iter().enumerate() {
            for v6 in [false, true] {
                add_filter(engine, display, &mut provider_key, index, v6, rule)?;
            }
        }
        Ok(())
    }

    fn add_filter(
        engine: &Engine,
        display: FWPM_DISPLAY_DATA0,
        provider_key: &mut GUID,
        index: usize,
        v6: bool,
        rule: &LockRule,
    ) -> Result<(), TrafficLockError> {
        // Values that conditions point at must live until FwpmFilterAdd0.
        let mut app_id: *mut FWP_BYTE_BLOB = ptr::null_mut();
        let mut luid: u64 = 0;
        let mut v4_mask = FWP_V4_ADDR_AND_MASK { addr: 0, mask: 0 };
        let mut v6_mask = FWP_V6_ADDR_AND_MASK {
            addr: [0; 16],
            prefixLength: 0,
        };
        let mut conditions: Vec<FWPM_FILTER_CONDITION0> = Vec::with_capacity(2);
        let condition = |field: GUID,
                         match_type: FWP_MATCH_TYPE,
                         kind: FWP_DATA_TYPE,
                         value: FWP_CONDITION_VALUE0_0| {
            FWPM_FILTER_CONDITION0 {
                fieldKey: field,
                matchType: match_type,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: kind,
                    Anonymous: value,
                },
            }
        };
        let permit = !matches!(
            rule,
            LockRule::BlockDns { .. } | LockRule::BlockInterface { .. }
        );
        match rule {
            LockRule::PermitApplication(path) => {
                let path = wide(&path.to_string_lossy());
                if unsafe { FwpmGetAppIdFromFileName0(path.as_ptr(), &mut app_id) } != ERROR_SUCCESS
                    || app_id.is_null()
                {
                    return Err(TrafficLockError);
                }
                conditions.push(condition(
                    FWPM_CONDITION_ALE_APP_ID,
                    FWP_MATCH_EQUAL,
                    FWP_BYTE_BLOB_TYPE,
                    FWP_CONDITION_VALUE0_0 { byteBlob: app_id },
                ));
            }
            LockRule::PermitLoopback => conditions.push(condition(
                FWPM_CONDITION_FLAGS,
                FWP_MATCH_FLAGS_ALL_SET,
                FWP_UINT32,
                FWP_CONDITION_VALUE0_0 {
                    uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                },
            )),
            LockRule::BlockDns { interface_luid } => {
                luid = *interface_luid;
                conditions.push(condition(
                    FWPM_CONDITION_IP_LOCAL_INTERFACE,
                    FWP_MATCH_EQUAL,
                    FWP_UINT64,
                    FWP_CONDITION_VALUE0_0 { uint64: &mut luid },
                ));
                conditions.push(condition(
                    FWPM_CONDITION_IP_REMOTE_PORT,
                    FWP_MATCH_EQUAL,
                    FWP_UINT16,
                    FWP_CONDITION_VALUE0_0 { uint16: 53 },
                ));
            }
            LockRule::PermitLocalV4 { address, mask } => {
                if v6 {
                    return Ok(());
                }
                v4_mask = FWP_V4_ADDR_AND_MASK {
                    addr: *address,
                    mask: *mask,
                };
                conditions.push(condition(
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    FWP_MATCH_EQUAL,
                    FWP_V4_ADDR_MASK,
                    FWP_CONDITION_VALUE0_0 {
                        v4AddrMask: &mut v4_mask,
                    },
                ));
            }
            LockRule::PermitLocalV6 { address, prefix } => {
                if !v6 {
                    return Ok(());
                }
                v6_mask = FWP_V6_ADDR_AND_MASK {
                    addr: address.octets(),
                    prefixLength: *prefix,
                };
                conditions.push(condition(
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    FWP_MATCH_EQUAL,
                    FWP_V6_ADDR_MASK,
                    FWP_CONDITION_VALUE0_0 {
                        v6AddrMask: &mut v6_mask,
                    },
                ));
            }
            LockRule::PermitDhcp => {
                conditions.push(condition(
                    FWPM_CONDITION_IP_PROTOCOL,
                    FWP_MATCH_EQUAL,
                    FWP_UINT8,
                    FWP_CONDITION_VALUE0_0 { uint8: IPPROTO_UDP },
                ));
                conditions.push(condition(
                    FWPM_CONDITION_IP_REMOTE_PORT,
                    FWP_MATCH_EQUAL,
                    FWP_UINT16,
                    FWP_CONDITION_VALUE0_0 {
                        uint16: if v6 { 547 } else { 67 },
                    },
                ));
            }
            LockRule::BlockInterface { interface_luid } => {
                luid = *interface_luid;
                conditions.push(condition(
                    FWPM_CONDITION_IP_LOCAL_INTERFACE,
                    FWP_MATCH_EQUAL,
                    FWP_UINT64,
                    FWP_CONDITION_VALUE0_0 { uint64: &mut luid },
                ));
            }
        }
        let filter = FWPM_FILTER0 {
            filterKey: filter_key(index, v6),
            displayData: display,
            flags: FWPM_FILTER_FLAG_NONE,
            providerKey: provider_key,
            providerData: FWP_BYTE_BLOB {
                size: 0,
                data: ptr::null_mut(),
            },
            layerKey: if v6 {
                FWPM_LAYER_ALE_AUTH_CONNECT_V6
            } else {
                FWPM_LAYER_ALE_AUTH_CONNECT_V4
            },
            subLayerKey: SUBLAYER_KEY,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 {
                    uint8: rule.weight(),
                },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: if permit {
                    FWP_ACTION_PERMIT
                } else {
                    FWP_ACTION_BLOCK
                },
                Anonymous: FWPM_ACTION0_0 {
                    calloutKey: GUID::from_u128(0),
                },
            },
            Anonymous: FWPM_FILTER0_0 { rawContext: 0 },
            reserved: ptr::null_mut(),
            filterId: 0,
            effectiveWeight: FWP_VALUE0 {
                r#type: FWP_EMPTY,
                Anonymous: FWP_VALUE0_0 { uint8: 0 },
            },
        };
        let mut id = 0_u64;
        let status = unsafe { FwpmFilterAdd0(engine.0, &filter, ptr::null_mut(), &mut id) };
        if !app_id.is_null() {
            unsafe { FwpmFreeMemory0((&mut app_id as *mut *mut FWP_BYTE_BLOB).cast()) };
        }
        let _ = (&v4_mask, &v6_mask, &luid);
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(TrafficLockError)
        }
    }

    /// Wired and wireless adapters that are up. Tunnels (Wintun, other VPNs)
    /// and loopback are not physical and are not closed.
    fn physical_interface_luids() -> Result<Vec<u64>, TrafficLockError> {
        let mut size: u32 = 16 * 1024;
        for _ in 0..4 {
            let mut buffer = vec![0_u64; (size as usize).div_ceil(8)];
            let head = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            let status = unsafe {
                GetAdaptersAddresses(
                    u32::from(AF_UNSPEC),
                    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                    ptr::null(),
                    head,
                    &mut size,
                )
            };
            if status == ERROR_BUFFER_OVERFLOW {
                continue;
            }
            if status != ERROR_SUCCESS {
                return Err(TrafficLockError);
            }
            let mut luids = Vec::new();
            let mut current = head;
            while !current.is_null() {
                let adapter = unsafe { &*current };
                if matches!(adapter.IfType, IF_TYPE_ETHERNET_CSMACD | IF_TYPE_IEEE80211)
                    && adapter.OperStatus == IF_OPER_STATUS_UP
                {
                    let luid = unsafe { adapter.Luid.Value };
                    if luid != 0 && !luids.contains(&luid) {
                        luids.push(luid);
                    }
                }
                current = adapter.Next;
            }
            return Ok(luids);
        }
        Err(TrafficLockError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_permit_the_engine_and_lan_then_block_each_physical_interface() {
        let engine = PathBuf::from(r"C:\Program Files\TunBridge\mihomo.exe");
        let client = PathBuf::from(r"C:\Program Files\Clash Verge\verge-mihomo.exe");
        let rules = lock_rules(&[engine.clone(), client.clone()], &[11, 22]).unwrap();
        assert_eq!(rules[0], LockRule::PermitApplication(engine));
        assert_eq!(rules[1], LockRule::PermitApplication(client));
        assert_eq!(rules[2], LockRule::PermitLoopback);
        assert_eq!(rules[3], LockRule::BlockDns { interface_luid: 11 });
        assert_eq!(rules[4], LockRule::BlockDns { interface_luid: 22 });
        assert!(rules.contains(&LockRule::PermitLocalV4 {
            address: u32::from_be_bytes([192, 168, 0, 0]),
            mask: 0xffff_0000,
        }));
        assert!(rules.contains(&LockRule::PermitDhcp));
        assert_eq!(
            &rules[rules.len() - 2..],
            [
                LockRule::BlockInterface { interface_luid: 11 },
                LockRule::BlockInterface { interface_luid: 22 },
            ]
        );
        // Every permit outweighs the final block; the DNS block outweighs LAN.
        let block = LockRule::BlockInterface { interface_luid: 11 }.weight();
        assert!(rules
            .iter()
            .filter(|rule| !matches!(rule, LockRule::BlockInterface { .. }))
            .all(|rule| rule.weight() > block));
        assert!(
            LockRule::BlockDns { interface_luid: 1 }.weight()
                > LockRule::PermitLocalV4 {
                    address: 0,
                    mask: 0
                }
                .weight()
        );
    }

    #[test]
    fn rules_require_an_engine_and_a_physical_interface() {
        let engine = PathBuf::from(r"C:\Program Files\TunBridge\mihomo.exe");
        assert!(lock_rules(&[], &[1]).is_none());
        assert!(lock_rules(std::slice::from_ref(&engine), &[]).is_none());
        assert!(lock_rules(&[engine], &[0]).is_none());
        assert!(lock_rules(&[PathBuf::from("mihomo.exe")], &[1]).is_none());
    }
}
