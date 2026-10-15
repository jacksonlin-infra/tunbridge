//! Read-only SystemConfiguration DNS configuration snapshots.
//!
//! This source reads one immutable `SCPreferences` generation. It never locks,
//! commits, applies, or writes preferences.

use crate::{
    darwin_state::{dns_snapshot_sha256, DnsSnapshot},
    lifecycle_plan::DnsConfigurationMode,
};
use std::{
    ffi::{c_char, c_void, CStr},
    net::IpAddr,
    ptr::NonNull,
};

const UTF8_ENCODING: u32 = 0x0800_0100;
const MAX_SERVICE_ID_BYTES: usize = 128;
const MAX_DNS_SERVERS: usize = 8;
const MAX_SEARCH_DOMAINS: usize = 16;
const MAX_CF_STRING_BYTES: usize = 1024;
const MAX_NETWORK_SERVICES: usize = 256;

type CfIndex = isize;
type CfTypeId = usize;
type CfRef = *const c_void;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeDnsError {
    Unavailable,
    InvalidService,
    Unsupported,
    Invalid,
}

struct OwnedCf(NonNull<c_void>);

impl OwnedCf {
    fn new(value: CfRef) -> Result<Self, NativeDnsError> {
        NonNull::new(value.cast_mut())
            .map(Self)
            .ok_or(NativeDnsError::Unavailable)
    }

    fn as_ptr(&self) -> CfRef {
        self.0.as_ptr()
    }
}

impl Drop for OwnedCf {
    fn drop(&mut self) {
        unsafe { CFRelease(self.as_ptr()) };
    }
}

pub fn configured_network_service_ids() -> Result<Vec<String>, NativeDnsError> {
    let preferences = preferences_snapshot()?;
    let services = network_services(preferences.as_ptr())?;
    let count = unsafe { CFDictionaryGetCount(services) };
    if count <= 0 || count as usize > MAX_NETWORK_SERVICES {
        return Err(NativeDnsError::Invalid);
    }
    let mut keys = vec![std::ptr::null(); count as usize];
    unsafe {
        CFDictionaryGetKeysAndValues(services, keys.as_mut_ptr(), std::ptr::null_mut());
    }
    let mut service_ids = Vec::with_capacity(keys.len());
    for key in keys {
        let service_id = parse_string(key, MAX_SERVICE_ID_BYTES)?;
        if !valid_service_id(&service_id) || service_ids.contains(&service_id) {
            return Err(NativeDnsError::Invalid);
        }
        service_ids.push(service_id);
    }
    service_ids.sort_unstable();
    Ok(service_ids)
}

pub fn configured_network_device_names() -> Result<Vec<String>, NativeDnsError> {
    let preferences = preferences_snapshot()?;
    let services = network_services(preferences.as_ptr())?;
    let count = unsafe { CFDictionaryGetCount(services) };
    if count <= 0 || count as usize > MAX_NETWORK_SERVICES {
        return Err(NativeDnsError::Invalid);
    }
    let mut values = vec![std::ptr::null(); count as usize];
    unsafe {
        CFDictionaryGetKeysAndValues(services, std::ptr::null_mut(), values.as_mut_ptr());
    }
    let mut devices = Vec::new();
    for service in values {
        require_type(service, unsafe { CFDictionaryGetTypeID() })?;
        let Some(interface) = dictionary_value(service, "Interface")? else {
            continue;
        };
        require_type(interface, unsafe { CFDictionaryGetTypeID() })?;
        let Some(device) = dictionary_value(interface, "DeviceName")? else {
            continue;
        };
        let device = parse_string(device, MAX_CF_STRING_BYTES)?;
        if !valid_device_name(&device) {
            return Err(NativeDnsError::Invalid);
        }
        if !devices.contains(&device) {
            devices.push(device);
        }
    }
    devices.sort_unstable();
    Ok(devices)
}

pub fn native_dns_snapshot(network_service_id: &str) -> Result<DnsSnapshot, NativeDnsError> {
    if !valid_service_id(network_service_id) {
        return Err(NativeDnsError::InvalidService);
    }
    let preferences = preferences_snapshot()?;
    let services = network_services(preferences.as_ptr())?;
    let service =
        dictionary_value(services, network_service_id)?.ok_or(NativeDnsError::InvalidService)?;
    snapshot_from_service(network_service_id, service)
}

#[cfg(feature = "macos-dns-effects")]
pub(crate) fn native_dns_snapshot_from_preferences(
    preferences: *const c_void,
    network_service_id: &str,
) -> Result<DnsSnapshot, NativeDnsError> {
    if preferences.is_null() || !valid_service_id(network_service_id) {
        return Err(NativeDnsError::InvalidService);
    }
    let services = network_services(preferences)?;
    let service =
        dictionary_value(services, network_service_id)?.ok_or(NativeDnsError::InvalidService)?;
    snapshot_from_service(network_service_id, service)
}

pub fn native_dns_snapshot_for_device(device_name: &str) -> Result<DnsSnapshot, NativeDnsError> {
    if !valid_device_name(device_name) {
        return Err(NativeDnsError::InvalidService);
    }
    let preferences = preferences_snapshot()?;
    let services = network_services(preferences.as_ptr())?;
    let count = unsafe { CFDictionaryGetCount(services) };
    if count <= 0 || count as usize > MAX_NETWORK_SERVICES {
        return Err(NativeDnsError::Invalid);
    }
    let mut keys = vec![std::ptr::null(); count as usize];
    let mut values = vec![std::ptr::null(); count as usize];
    unsafe {
        CFDictionaryGetKeysAndValues(services, keys.as_mut_ptr(), values.as_mut_ptr());
    }
    let mut matching = None;
    for (key, service) in keys.into_iter().zip(values) {
        require_type(service, unsafe { CFDictionaryGetTypeID() })?;
        let Some(interface) = dictionary_value(service, "Interface")? else {
            continue;
        };
        require_type(interface, unsafe { CFDictionaryGetTypeID() })?;
        let Some(device) = dictionary_value(interface, "DeviceName")? else {
            continue;
        };
        if parse_string(device, MAX_CF_STRING_BYTES)? != device_name {
            continue;
        }
        let service_id = parse_string(key, MAX_SERVICE_ID_BYTES)?;
        if !valid_service_id(&service_id) || matching.is_some() {
            return Err(NativeDnsError::Invalid);
        }
        matching = Some(snapshot_from_service(&service_id, service)?);
    }
    matching.ok_or(NativeDnsError::InvalidService)
}

fn snapshot_from_service(
    network_service_id: &str,
    service: CfRef,
) -> Result<DnsSnapshot, NativeDnsError> {
    require_type(service, unsafe { CFDictionaryGetTypeID() })?;
    let interface =
        dictionary_value(service, "Interface")?.ok_or(NativeDnsError::InvalidService)?;
    require_type(interface, unsafe { CFDictionaryGetTypeID() })?;

    let (mode, servers, search_domains) = match dictionary_value(service, "DNS")? {
        None => (DnsConfigurationMode::Automatic, Vec::new(), Vec::new()),
        Some(dns) => parse_dns_dictionary(dns)?,
    };
    let snapshot = DnsSnapshot {
        complete: true,
        network_service_id: network_service_id.into(),
        mode,
        servers,
        search_domains,
    };
    dns_snapshot_sha256(&snapshot).map_err(|_| NativeDnsError::Invalid)?;
    Ok(snapshot)
}

fn preferences_snapshot() -> Result<OwnedCf, NativeDnsError> {
    let name = cf_string("TunBridge DNS observer")?;
    OwnedCf::new(unsafe { SCPreferencesCreate(std::ptr::null(), name.as_ptr(), std::ptr::null()) })
}

fn network_services(preferences: CfRef) -> Result<CfRef, NativeDnsError> {
    let services_key = cf_string("NetworkServices")?;
    let services = unsafe { SCPreferencesGetValue(preferences, services_key.as_ptr()) };
    if services.is_null() {
        return Err(NativeDnsError::Unavailable);
    }
    require_type(services, unsafe { CFDictionaryGetTypeID() })?;
    Ok(services)
}

fn parse_dns_dictionary(
    dns: CfRef,
) -> Result<(DnsConfigurationMode, Vec<IpAddr>, Vec<String>), NativeDnsError> {
    require_type(dns, unsafe { CFDictionaryGetTypeID() })?;
    let server_value = dictionary_value(dns, "ServerAddresses")?;
    let search_value = dictionary_value(dns, "SearchDomains")?;
    let inactive_value = dictionary_value(dns, "__INACTIVE__")?;
    let recognized = server_value.is_some() as isize
        + search_value.is_some() as isize
        + inactive_value.is_some() as isize;
    if unsafe { CFDictionaryGetCount(dns) } != recognized {
        return Err(NativeDnsError::Unsupported);
    }
    let server_strings = server_value
        .map(|value| parse_string_array(value, MAX_DNS_SERVERS))
        .transpose()?
        .unwrap_or_default();
    let mut servers = Vec::with_capacity(server_strings.len());
    for value in server_strings {
        let address: IpAddr = value.parse().map_err(|_| NativeDnsError::Unsupported)?;
        if address.is_unspecified() || address.is_multicast() || servers.contains(&address) {
            return Err(NativeDnsError::Invalid);
        }
        servers.push(address);
    }
    let search_domains = search_value
        .map(|value| parse_string_array(value, MAX_SEARCH_DOMAINS))
        .transpose()?
        .unwrap_or_default();
    if has_duplicates(&search_domains) {
        return Err(NativeDnsError::Invalid);
    }
    let mode = if servers.is_empty() && search_domains.is_empty() {
        DnsConfigurationMode::Automatic
    } else {
        DnsConfigurationMode::Manual
    };
    Ok((mode, servers, search_domains))
}

fn parse_string_array(value: CfRef, maximum: usize) -> Result<Vec<String>, NativeDnsError> {
    require_type(value, unsafe { CFArrayGetTypeID() })?;
    let count = unsafe { CFArrayGetCount(value) };
    if count < 0 || count as usize > maximum {
        return Err(NativeDnsError::Invalid);
    }
    (0..count)
        .map(|index| {
            let value = unsafe { CFArrayGetValueAtIndex(value, index) };
            parse_string(value, MAX_CF_STRING_BYTES)
        })
        .collect()
}

fn parse_string(value: CfRef, maximum: usize) -> Result<String, NativeDnsError> {
    require_type(value, unsafe { CFStringGetTypeID() })?;
    let length = unsafe { CFStringGetLength(value) };
    if length < 0 {
        return Err(NativeDnsError::Invalid);
    }
    let maximum_size = unsafe { CFStringGetMaximumSizeForEncoding(length, UTF8_ENCODING) };
    if maximum_size < 0 || maximum_size as usize > maximum {
        return Err(NativeDnsError::Invalid);
    }
    let mut buffer = vec![0_u8; maximum_size as usize + 1];
    if unsafe {
        CFStringGetCString(
            value,
            buffer.as_mut_ptr().cast(),
            buffer.len() as CfIndex,
            UTF8_ENCODING,
        )
    } == 0
    {
        return Err(NativeDnsError::Invalid);
    }
    let value = CStr::from_bytes_until_nul(&buffer).map_err(|_| NativeDnsError::Invalid)?;
    value
        .to_str()
        .map(str::to_owned)
        .map_err(|_| NativeDnsError::Invalid)
}

fn dictionary_value(dictionary: CfRef, key: &str) -> Result<Option<CfRef>, NativeDnsError> {
    let key = cf_string(key)?;
    let value = unsafe { CFDictionaryGetValue(dictionary, key.as_ptr()) };
    Ok((!value.is_null()).then_some(value))
}

fn cf_string(value: &str) -> Result<OwnedCf, NativeDnsError> {
    OwnedCf::new(unsafe {
        CFStringCreateWithBytes(
            std::ptr::null(),
            value.as_ptr(),
            value.len() as CfIndex,
            UTF8_ENCODING,
            0,
        )
    })
}

fn require_type(value: CfRef, expected: CfTypeId) -> Result<(), NativeDnsError> {
    if value.is_null() || unsafe { CFGetTypeID(value) } != expected {
        Err(NativeDnsError::Unsupported)
    } else {
        Ok(())
    }
}

fn valid_service_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SERVICE_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn valid_device_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() < libc::IFNAMSIZ
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn has_duplicates(values: &[String]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: CfRef);
    fn CFGetTypeID(value: CfRef) -> CfTypeId;
    fn CFStringGetTypeID() -> CfTypeId;
    fn CFStringCreateWithBytes(
        allocator: CfRef,
        bytes: *const u8,
        byte_count: CfIndex,
        encoding: u32,
        external_representation: u8,
    ) -> CfRef;
    fn CFStringGetLength(value: CfRef) -> CfIndex;
    fn CFStringGetMaximumSizeForEncoding(length: CfIndex, encoding: u32) -> CfIndex;
    fn CFStringGetCString(
        value: CfRef,
        buffer: *mut c_char,
        buffer_size: CfIndex,
        encoding: u32,
    ) -> u8;
    fn CFDictionaryGetTypeID() -> CfTypeId;
    fn CFDictionaryGetCount(dictionary: CfRef) -> CfIndex;
    fn CFDictionaryGetValue(dictionary: CfRef, key: CfRef) -> CfRef;
    fn CFDictionaryGetKeysAndValues(dictionary: CfRef, keys: *mut CfRef, values: *mut CfRef);
    fn CFArrayGetTypeID() -> CfTypeId;
    fn CFArrayGetCount(array: CfRef) -> CfIndex;
    fn CFArrayGetValueAtIndex(array: CfRef, index: CfIndex) -> CfRef;
}

#[link(name = "SystemConfiguration", kind = "framework")]
unsafe extern "C" {
    fn SCPreferencesCreate(allocator: CfRef, name: CfRef, prefs_id: CfRef) -> CfRef;
    fn SCPreferencesGetValue(preferences: CfRef, key: CfRef) -> CfRef;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_identifier_validation_is_closed() {
        assert!(valid_service_id("C3A20E6E-38EA-4480-B563-F571E4B3518E"));
        assert!(!valid_service_id(""));
        assert!(!valid_service_id("service/../../DNS"));
        assert!(!valid_service_id(&"a".repeat(MAX_SERVICE_ID_BYTES + 1)));
        assert!(valid_device_name("en0"));
        assert!(valid_device_name("bridge0"));
        assert!(!valid_device_name("en0/../DNS"));
    }

    #[test]
    fn configured_service_dns_configuration_is_read_only_and_canonical() {
        let snapshot = configured_network_service_ids()
            .unwrap()
            .into_iter()
            .find_map(|service_id| native_dns_snapshot(&service_id).ok())
            .expect("at least one supported configured network service");
        assert!(snapshot.complete);
        dns_snapshot_sha256(&snapshot).unwrap();
    }

    #[test]
    fn configured_device_maps_to_one_exact_service() {
        let snapshot = configured_network_device_names()
            .unwrap()
            .into_iter()
            .find_map(|device| native_dns_snapshot_for_device(&device).ok())
            .expect("at least one unambiguous configured device");
        assert!(snapshot.complete);
        assert!(configured_network_service_ids()
            .unwrap()
            .contains(&snapshot.network_service_id));
    }
}
