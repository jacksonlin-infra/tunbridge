use std::{io, ptr, thread::sleep, time::Duration};

use windows_sys::{
    core::GUID,
    Win32::{
        Devices::DeviceAndDriverInstallation::{
            DiUninstallDevice, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo,
            SetupDiGetClassDevsW, SetupDiGetDeviceInstanceIdW, GUID_DEVCLASS_NET, HDEVINFO,
            SP_DEVINFO_DATA,
        },
        Foundation::{ERROR_NO_MORE_ITEMS, INVALID_HANDLE_VALUE},
        NetworkManagement::IpHelper::{FreeMibTable, GetIfTable2, MIB_IF_TABLE2},
        NetworkManagement::Ndis::{MediaConnectStateConnected, NET_IF_OPER_STATUS_UP},
    },
};

pub const TUN_ALIAS: &str = "tunbridge";
const DEVICE_INSTANCE_CAPACITY: usize = 512;

/// Query the live Windows interface table for an adapter alias.
///
/// Network-class registry records are deliberately not used here: Wintun can
/// retain historical records that are not evidence of a live interface.
pub fn native_adapter_exists(expected_alias: &str) -> Result<bool, AdapterError> {
    Ok(live_adapter_guid(expected_alias)?.is_some())
}

pub fn native_adapter_instance_id(expected_alias: &str) -> Result<Option<String>, AdapterError> {
    Ok(live_adapter_guid(expected_alias)?.map(wintun_instance_id))
}

/// Snapshot every installed Wintun devnode, including stopped devices.
///
/// Pending lifecycle cleanup uses this protected pre-spawn inventory to prove
/// that a live instance was introduced by the controlled engine before it may
/// be removed. Merely observing the expected alias is not provenance because
/// Wintun may reuse an installed adapter with the same name.
pub(super) fn installed_wintun_instance_ids() -> Result<Vec<String>, AdapterError> {
    let devices = DeviceInfoSet::network_devices()?;
    let mut instances = Vec::new();
    let mut index = 0;
    loop {
        let mut device = SP_DEVINFO_DATA {
            cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
            ..Default::default()
        };
        // SAFETY: devices is valid and device has the required cbSize.
        if unsafe { SetupDiEnumDeviceInfo(devices.0, index, &mut device) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                break;
            }
            return Err(AdapterError::DeviceEnumeration(error));
        }
        let instance = device_instance_id(devices.0, &device)?;
        if instance
            .get(..11)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("SWD\\Wintun\\"))
        {
            if !valid_wintun_instance_id(&instance) {
                return Err(AdapterError::InvalidDeviceIdentity);
            }
            instances.push(instance.to_ascii_uppercase());
        }
        index += 1;
    }
    instances.sort_unstable();
    instances.dedup();
    Ok(instances)
}

/// Remove only the present Wintun devnode whose interface GUID belongs to the
/// live adapter with the exact expected alias.
///
/// Callers establish ownership by proving the alias absent before launching
/// the controlled engine and retaining protected owned-process state until
/// this cleanup succeeds. A different device type or ambiguous alias fails
/// closed without removing anything.
pub fn remove_owned_tun_adapter(expected_alias: &str) -> Result<AdapterRemoval, AdapterError> {
    remove_verified_tun_adapter(expected_alias, None)
}

/// Remove the live adapter only when its exact Wintun device instance still
/// matches the identity captured at the Running commit boundary.
pub fn remove_owned_tun_adapter_instance(
    expected_alias: &str,
    expected_instance_id: &str,
) -> Result<AdapterRemoval, AdapterError> {
    remove_verified_tun_adapter(expected_alias, Some(expected_instance_id))
}

fn remove_verified_tun_adapter(
    expected_alias: &str,
    recorded_instance_id: Option<&str>,
) -> Result<AdapterRemoval, AdapterError> {
    let Some(guid) = live_adapter_guid(expected_alias)? else {
        return Ok(AdapterRemoval::AlreadyAbsent);
    };
    let expected_instance = wintun_instance_id(guid);
    if recorded_instance_id
        .is_some_and(|recorded| !recorded.eq_ignore_ascii_case(&expected_instance))
    {
        return Err(AdapterError::RecordedIdentityMismatch);
    }
    let devices = DeviceInfoSet::network_devices()?;
    let mut matching_device = None;
    let mut index = 0;
    loop {
        let mut device = SP_DEVINFO_DATA {
            cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
            ..Default::default()
        };
        // SAFETY: devices is a valid SetupAPI set and device points to an
        // initialized structure with the required cbSize.
        if unsafe { SetupDiEnumDeviceInfo(devices.0, index, &mut device) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                break;
            }
            return Err(AdapterError::DeviceEnumeration(error));
        }
        let instance = device_instance_id(devices.0, &device)?;
        if instance.eq_ignore_ascii_case(&expected_instance)
            && matching_device.replace(device).is_some()
        {
            return Err(AdapterError::AmbiguousDeviceIdentity);
        }
        index += 1;
    }

    let Some(device) = matching_device else {
        return Err(AdapterError::UnverifiedDeviceIdentity);
    };
    #[cfg(feature = "acceptance-fault-injection")]
    {
        let fault = super::acceptance::active_fault().map_err(AdapterError::AcceptanceFault)?;
        if fault == Some(super::acceptance::AcceptanceFault::WintunCleanupFailed) {
            // Injection occurs only after GetIfTable2 supplied the live GUID
            // and SetupAPI proved one exact SWD\Wintun\{GUID} devnode. No
            // removal API has run, so protected owned state remains a truthful
            // retry anchor for Recover.
            return Err(AdapterError::AcceptanceInjectedCleanupFailure);
        }
    }
    let mut restart_required = 0;
    // SAFETY: the device came from this live SetupAPI set and the operation is
    // constrained to the exact Wintun instance derived from GetIfTable2.
    let uninstall_succeeded = unsafe {
        DiUninstallDevice(
            ptr::null_mut(),
            devices.0,
            &device,
            0,
            &mut restart_required,
        )
    } != 0;
    let uninstall_error = (!uninstall_succeeded).then(io::Error::last_os_error);

    // DiUninstallDevice returning success means the top-level devnode was
    // uninstalled. Windows may deliberately retain its disconnected kernel
    // PnP row (and Wintun may reuse that row on the next launch), so physical
    // row disappearance is not a valid lifecycle boundary. The boundary we
    // need is that the controlled interface is no longer operational.
    if uninstall_succeeded {
        return Ok(AdapterRemoval::Removed);
    }

    // A failed request can still race with asynchronous PnP teardown. Accept
    // that converged network fact before surfacing the original API error.
    for _ in 0..40 {
        if !native_adapter_exists(expected_alias)? {
            return Ok(AdapterRemoval::Removed);
        }
        sleep(Duration::from_millis(250));
    }
    if restart_required != 0 {
        Err(AdapterError::RestartRequired)
    } else {
        Err(AdapterError::DeviceRemoval(
            uninstall_error.expect("a failed uninstall captured its error"),
        ))
    }
}

fn live_adapter_guid(expected_alias: &str) -> Result<Option<GUID>, AdapterError> {
    let mut raw = ptr::null_mut();
    // SAFETY: raw points to writable storage populated by GetIfTable2.
    let result = unsafe { GetIfTable2(&mut raw) };
    if result != 0 {
        return Err(AdapterError::InterfaceTable(io::Error::from_raw_os_error(
            result as i32,
        )));
    }
    if raw.is_null() {
        return Err(AdapterError::InterfaceTable(io::Error::other(
            "GetIfTable2 returned a null table",
        )));
    }
    let table = OwnedInterfaceTable(raw);
    // SAFETY: GetIfTable2 allocated one row for each NumEntries value and the
    // guard retains the allocation for the lifetime of the slice.
    let rows = unsafe {
        std::slice::from_raw_parts((*table.0).Table.as_ptr(), (*table.0).NumEntries as usize)
    };
    let mut matching_guid = None;
    for row in rows {
        let length = row
            .Alias
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(row.Alias.len());
        if active_interface_row(row.OperStatus, row.MediaConnectState)
            && String::from_utf16_lossy(&row.Alias[..length]).eq_ignore_ascii_case(expected_alias)
            && matching_guid.replace(row.InterfaceGuid).is_some()
        {
            return Err(AdapterError::AmbiguousAlias);
        }
    }
    Ok(matching_guid)
}

fn active_interface_row(oper_status: i32, media_state: i32) -> bool {
    oper_status == NET_IF_OPER_STATUS_UP && media_state == MediaConnectStateConnected
}

fn device_instance_id(devices: HDEVINFO, device: &SP_DEVINFO_DATA) -> Result<String, AdapterError> {
    let mut buffer = [0u16; DEVICE_INSTANCE_CAPACITY];
    let mut required = 0;
    // SAFETY: buffer is writable for the advertised length and device belongs
    // to devices for the duration of this call.
    if unsafe {
        SetupDiGetDeviceInstanceIdW(
            devices,
            device,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut required,
        )
    } == 0
    {
        return Err(AdapterError::DeviceIdentity(io::Error::last_os_error()));
    }
    if required == 0 || required as usize > buffer.len() {
        return Err(AdapterError::InvalidDeviceIdentity);
    }
    Ok(String::from_utf16_lossy(&buffer[..required as usize - 1]))
}

fn wintun_instance_id(guid: GUID) -> String {
    format!(
        "SWD\\Wintun\\{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7]
    )
}

pub(super) fn valid_wintun_instance_id(instance: &str) -> bool {
    let bytes = instance.as_bytes();
    bytes.len() == 49
        && bytes[..12].eq_ignore_ascii_case(b"SWD\\Wintun\\{")
        && bytes.ends_with(b"}")
        && bytes[12..48]
            .iter()
            .copied()
            .enumerate()
            .all(|(index, byte)| match index {
                8 | 13 | 18 | 23 => byte == b'-',
                _ => byte.is_ascii_hexdigit(),
            })
}

struct OwnedInterfaceTable(*mut MIB_IF_TABLE2);

impl Drop for OwnedInterfaceTable {
    fn drop(&mut self) {
        // SAFETY: this allocation came from GetIfTable2 and is freed once.
        unsafe { FreeMibTable(self.0.cast()) };
    }
}

struct DeviceInfoSet(HDEVINFO);

impl DeviceInfoSet {
    fn network_devices() -> Result<Self, AdapterError> {
        // SAFETY: all optional pointer arguments are null and the class GUID is
        // static for the duration of the call. Flags are intentionally zero:
        // a stopped Wintun remains installed but is no longer DIGCF_PRESENT.
        let set =
            unsafe { SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, ptr::null(), ptr::null_mut(), 0) };
        if set == INVALID_HANDLE_VALUE as HDEVINFO {
            return Err(AdapterError::DeviceSet(io::Error::last_os_error()));
        }
        Ok(Self(set))
    }
}

impl Drop for DeviceInfoSet {
    fn drop(&mut self) {
        // SAFETY: this handle came from SetupDiGetClassDevsW and is closed once.
        unsafe { SetupDiDestroyDeviceInfoList(self.0) };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterRemoval {
    AlreadyAbsent,
    Removed,
}

#[derive(Debug, thiserror::Error)]
pub enum AdapterError {
    #[error("the live Windows interface table could not be queried: {0}")]
    InterfaceTable(#[source] io::Error),
    #[error("more than one live adapter has the controlled alias")]
    AmbiguousAlias,
    #[error("the installed network device set could not be opened: {0}")]
    DeviceSet(#[source] io::Error),
    #[error("the installed network device set could not be enumerated: {0}")]
    DeviceEnumeration(#[source] io::Error),
    #[error("a network device instance identity could not be queried: {0}")]
    DeviceIdentity(#[source] io::Error),
    #[error("a network device returned an invalid instance identity")]
    InvalidDeviceIdentity,
    #[error("the controlled adapter did not map to its exact Wintun device identity")]
    UnverifiedDeviceIdentity,
    #[error("the live controlled adapter does not match the recorded Wintun identity")]
    RecordedIdentityMismatch,
    #[error("more than one device matched the controlled Wintun identity")]
    AmbiguousDeviceIdentity,
    #[error("the controlled Wintun device could not be removed: {0}")]
    DeviceRemoval(#[source] io::Error),
    #[error("removing the controlled Wintun device requires a system restart")]
    RestartRequired,
    #[error("the controlled Wintun adapter remained live after removal")]
    RemovalTimeout,
    #[cfg(feature = "acceptance-fault-injection")]
    #[error("acceptance injected a controlled Wintun cleanup failure")]
    AcceptanceInjectedCleanupFailure,
    #[cfg(feature = "acceptance-fault-injection")]
    #[error("acceptance fault selector failed: {0}")]
    AcceptanceFault(#[source] super::acceptance::AcceptanceFaultError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_only_the_exact_wintun_instance_identity() {
        let guid = GUID {
            data1: 0x01f3_d263,
            data2: 0x6584,
            data3: 0x8b43,
            data4: [0xa6, 0x4c, 0xc9, 0x5f, 0xff, 0x23, 0xda, 0x26],
        };
        assert_eq!(
            wintun_instance_id(guid),
            "SWD\\Wintun\\{01F3D263-6584-8B43-A64C-C95FFF23DA26}"
        );
        assert!(valid_wintun_instance_id(&wintun_instance_id(guid)));
        assert!(!valid_wintun_instance_id(
            "SWD\\Other\\{01F3D263-6584-8B43-A64C-C95FFF23DA26}"
        ));
    }

    #[test]
    fn native_adapter_query_does_not_invent_a_missing_tun() {
        assert!(!native_adapter_exists("__tunbridge_missing_test_adapter__").unwrap());
    }

    #[test]
    fn disconnected_pnp_rows_are_not_active_tunnel_interfaces() {
        assert!(active_interface_row(
            NET_IF_OPER_STATUS_UP,
            MediaConnectStateConnected
        ));
        assert!(!active_interface_row(NET_IF_OPER_STATUS_UP, 2));
        assert!(!active_interface_row(2, MediaConnectStateConnected));
    }
}
