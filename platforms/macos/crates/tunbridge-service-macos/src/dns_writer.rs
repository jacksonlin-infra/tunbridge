//! Feature-isolated exact-service SystemConfiguration DNS writer.
//!
//! No default product target links this module. The privileged helper may only
//! call the native entry point after authenticating the caller and journaling
//! the planned effect.

use crate::{
    darwin_state::{dns_snapshot_sha256, DnsSnapshot},
    dns_effect::{expected_snapshot, DnsEffectConfiguration, DnsEffectPlan, DnsEffectRequest},
    dns_store::{native_dns_snapshot, native_dns_snapshot_from_preferences, NativeDnsError},
};
use std::{ffi::c_void, ptr::NonNull};

type CfIndex = isize;
type CfRef = *const c_void;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeDnsEffectError {
    Invalid,
    Unavailable,
    Busy,
    Stale,
    Drifted,
}

trait DnsPreferencesBackend {
    fn lock(&mut self) -> Result<(), NativeDnsEffectError>;
    fn snapshot(&mut self, network_service_id: &str) -> Result<DnsSnapshot, NativeDnsEffectError>;
    fn set(&mut self, request: &DnsEffectRequest) -> Result<(), NativeDnsEffectError>;
    fn commit(&mut self) -> Result<(), NativeDnsEffectError>;
    fn apply(&mut self) -> Result<(), NativeDnsEffectError>;
    fn unlock(&mut self) -> Result<(), NativeDnsEffectError>;
    fn fresh_snapshot(
        &mut self,
        network_service_id: &str,
    ) -> Result<DnsSnapshot, NativeDnsEffectError>;
}

/// Applies one DNS plan with a locked stale-state precondition and fresh
/// post-effect verification.
///
/// This symbol is absent unless `macos-dns-effects` is explicitly enabled.
pub fn apply_dns_effect(
    plan: &DnsEffectPlan,
    expected_before_sha256: &str,
) -> Result<(), NativeDnsEffectError> {
    let mut backend = NativeDnsPreferences::new()?;
    apply_dns_transaction(&mut backend, plan, expected_before_sha256)
}

fn apply_dns_transaction<B: DnsPreferencesBackend>(
    backend: &mut B,
    plan: &DnsEffectPlan,
    expected_before_sha256: &str,
) -> Result<(), NativeDnsEffectError> {
    let expected = expected_snapshot(plan).map_err(|_| NativeDnsEffectError::Invalid)?;
    if expected_before_sha256.len() != 64
        || !expected_before_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(NativeDnsEffectError::Invalid);
    }

    backend.lock()?;
    let mutation_result = (|| {
        let before = backend.snapshot(&plan.request.network_service_id)?;
        if dns_snapshot_sha256(&before).map_err(|_| NativeDnsEffectError::Invalid)?
            != expected_before_sha256
        {
            return Err(NativeDnsEffectError::Stale);
        }
        backend.set(&plan.request)?;
        backend.commit()?;
        backend.apply()
    })();
    let unlock_result = backend.unlock();
    mutation_result?;
    unlock_result?;

    let observed = backend.fresh_snapshot(&plan.request.network_service_id)?;
    if observed != expected
        || dns_snapshot_sha256(&observed).map_err(|_| NativeDnsEffectError::Invalid)?
            != plan.expected_sha256
    {
        return Err(NativeDnsEffectError::Drifted);
    }
    Ok(())
}

struct OwnedCf(NonNull<c_void>);

impl OwnedCf {
    fn new(value: CfRef) -> Result<Self, NativeDnsEffectError> {
        NonNull::new(value.cast_mut())
            .map(Self)
            .ok_or(NativeDnsEffectError::Unavailable)
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

struct NativeDnsPreferences {
    preferences: OwnedCf,
    locked: bool,
}

impl NativeDnsPreferences {
    fn new() -> Result<Self, NativeDnsEffectError> {
        let name = cf_string("TunBridge DNS writer")?;
        let preferences = OwnedCf::new(unsafe {
            SCPreferencesCreate(std::ptr::null(), name.as_ptr(), std::ptr::null())
        })?;
        Ok(Self {
            preferences,
            locked: false,
        })
    }
}

impl DnsPreferencesBackend for NativeDnsPreferences {
    fn lock(&mut self) -> Result<(), NativeDnsEffectError> {
        if self.locked {
            return Err(NativeDnsEffectError::Invalid);
        }
        if unsafe { SCPreferencesLock(self.preferences.as_ptr(), 0) } == 0 {
            return Err(NativeDnsEffectError::Busy);
        }
        self.locked = true;
        unsafe { SCPreferencesSynchronize(self.preferences.as_ptr()) };
        Ok(())
    }

    fn snapshot(&mut self, network_service_id: &str) -> Result<DnsSnapshot, NativeDnsEffectError> {
        if !self.locked {
            return Err(NativeDnsEffectError::Invalid);
        }
        native_dns_snapshot_from_preferences(self.preferences.as_ptr(), network_service_id)
            .map_err(map_dns_error)
    }

    fn set(&mut self, request: &DnsEffectRequest) -> Result<(), NativeDnsEffectError> {
        if !self.locked {
            return Err(NativeDnsEffectError::Invalid);
        }
        let service_id = cf_string(&request.network_service_id)?;
        let service = OwnedCf::new(unsafe {
            SCNetworkServiceCopy(self.preferences.as_ptr(), service_id.as_ptr())
        })?;
        let protocol = OwnedCf::new(unsafe {
            SCNetworkServiceCopyProtocol(service.as_ptr(), kSCNetworkProtocolTypeDNS)
        })?;
        let configuration = match &request.configuration {
            DnsEffectConfiguration::Automatic => None,
            DnsEffectConfiguration::Manual {
                servers,
                search_domains,
            } => Some(dns_dictionary(servers, search_domains)?),
        };
        let configuration_pointer = configuration
            .as_ref()
            .map_or(std::ptr::null(), OwnedCf::as_ptr);
        if unsafe { SCNetworkProtocolSetConfiguration(protocol.as_ptr(), configuration_pointer) }
            == 0
        {
            return Err(NativeDnsEffectError::Unavailable);
        }
        Ok(())
    }

    fn commit(&mut self) -> Result<(), NativeDnsEffectError> {
        if !self.locked || unsafe { SCPreferencesCommitChanges(self.preferences.as_ptr()) } == 0 {
            return Err(NativeDnsEffectError::Unavailable);
        }
        Ok(())
    }

    fn apply(&mut self) -> Result<(), NativeDnsEffectError> {
        if !self.locked || unsafe { SCPreferencesApplyChanges(self.preferences.as_ptr()) } == 0 {
            return Err(NativeDnsEffectError::Unavailable);
        }
        Ok(())
    }

    fn unlock(&mut self) -> Result<(), NativeDnsEffectError> {
        if !self.locked {
            return Err(NativeDnsEffectError::Invalid);
        }
        let unlocked = unsafe { SCPreferencesUnlock(self.preferences.as_ptr()) };
        self.locked = false;
        if unlocked == 0 {
            return Err(NativeDnsEffectError::Unavailable);
        }
        Ok(())
    }

    fn fresh_snapshot(
        &mut self,
        network_service_id: &str,
    ) -> Result<DnsSnapshot, NativeDnsEffectError> {
        if self.locked {
            return Err(NativeDnsEffectError::Invalid);
        }
        native_dns_snapshot(network_service_id).map_err(map_dns_error)
    }
}

impl Drop for NativeDnsPreferences {
    fn drop(&mut self) {
        if self.locked {
            unsafe {
                SCPreferencesUnlock(self.preferences.as_ptr());
            }
            self.locked = false;
        }
    }
}

fn map_dns_error(error: NativeDnsError) -> NativeDnsEffectError {
    match error {
        NativeDnsError::InvalidService | NativeDnsError::Invalid => NativeDnsEffectError::Invalid,
        NativeDnsError::Unavailable | NativeDnsError::Unsupported => {
            NativeDnsEffectError::Unavailable
        }
    }
}

fn dns_dictionary(
    servers: &[std::net::IpAddr],
    search_domains: &[String],
) -> Result<OwnedCf, NativeDnsEffectError> {
    let server_strings: Vec<String> = servers.iter().map(ToString::to_string).collect();
    let server_array = (!server_strings.is_empty())
        .then(|| cf_string_array(&server_strings))
        .transpose()?;
    let domain_array = (!search_domains.is_empty())
        .then(|| cf_string_array(search_domains))
        .transpose()?;
    let mut keys = Vec::with_capacity(2);
    let mut values = Vec::with_capacity(2);
    if let Some(array) = &server_array {
        keys.push(unsafe { kSCPropNetDNSServerAddresses });
        values.push(array.as_ptr());
    }
    if let Some(array) = &domain_array {
        keys.push(unsafe { kSCPropNetDNSSearchDomains });
        values.push(array.as_ptr());
    }
    OwnedCf::new(unsafe {
        CFDictionaryCreate(
            std::ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            keys.len() as CfIndex,
            (&raw const kCFTypeDictionaryKeyCallBacks).cast(),
            (&raw const kCFTypeDictionaryValueCallBacks).cast(),
        )
    })
}

fn cf_string_array(values: &[String]) -> Result<OwnedCf, NativeDnsEffectError> {
    let strings: Vec<OwnedCf> = values
        .iter()
        .map(|value| cf_string(value))
        .collect::<Result<_, _>>()?;
    let pointers: Vec<CfRef> = strings.iter().map(OwnedCf::as_ptr).collect();
    OwnedCf::new(unsafe {
        CFArrayCreate(
            std::ptr::null(),
            pointers.as_ptr(),
            pointers.len() as CfIndex,
            (&raw const kCFTypeArrayCallBacks).cast(),
        )
    })
}

fn cf_string(value: &str) -> Result<OwnedCf, NativeDnsEffectError> {
    const UTF8_ENCODING: u32 = 0x0800_0100;
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

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    static kCFTypeArrayCallBacks: u8;
    static kCFTypeDictionaryKeyCallBacks: u8;
    static kCFTypeDictionaryValueCallBacks: u8;

    fn CFRelease(value: CfRef);
    fn CFStringCreateWithBytes(
        allocator: CfRef,
        bytes: *const u8,
        byte_count: CfIndex,
        encoding: u32,
        external_representation: u8,
    ) -> CfRef;
    fn CFArrayCreate(
        allocator: CfRef,
        values: *const CfRef,
        count: CfIndex,
        callbacks: *const c_void,
    ) -> CfRef;
    fn CFDictionaryCreate(
        allocator: CfRef,
        keys: *const CfRef,
        values: *const CfRef,
        count: CfIndex,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> CfRef;
}

#[link(name = "SystemConfiguration", kind = "framework")]
unsafe extern "C" {
    static kSCNetworkProtocolTypeDNS: CfRef;
    static kSCPropNetDNSSearchDomains: CfRef;
    static kSCPropNetDNSServerAddresses: CfRef;

    fn SCPreferencesCreate(allocator: CfRef, name: CfRef, prefs_id: CfRef) -> CfRef;
    fn SCPreferencesLock(preferences: CfRef, wait: u8) -> u8;
    fn SCPreferencesUnlock(preferences: CfRef) -> u8;
    fn SCPreferencesSynchronize(preferences: CfRef);
    fn SCPreferencesCommitChanges(preferences: CfRef) -> u8;
    fn SCPreferencesApplyChanges(preferences: CfRef) -> u8;
    fn SCNetworkServiceCopy(preferences: CfRef, service_id: CfRef) -> CfRef;
    fn SCNetworkServiceCopyProtocol(service: CfRef, protocol_type: CfRef) -> CfRef;
    fn SCNetworkProtocolSetConfiguration(protocol: CfRef, configuration: CfRef) -> u8;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        dns_effect::{plan_manual_dns, plan_restore_dns},
        lifecycle_plan::{DnsBaseline, DnsConfigurationMode},
    };

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Failure {
        Lock,
        Snapshot,
        Set,
        Commit,
        Apply,
        Unlock,
        FreshSnapshot,
    }

    struct MockBackend {
        before: DnsSnapshot,
        after: DnsSnapshot,
        failure: Option<Failure>,
        events: Vec<&'static str>,
    }

    impl DnsPreferencesBackend for MockBackend {
        fn lock(&mut self) -> Result<(), NativeDnsEffectError> {
            self.events.push("lock");
            fail(self.failure, Failure::Lock)
        }

        fn snapshot(
            &mut self,
            _network_service_id: &str,
        ) -> Result<DnsSnapshot, NativeDnsEffectError> {
            self.events.push("snapshot");
            fail(self.failure, Failure::Snapshot)?;
            Ok(self.before.clone())
        }

        fn set(&mut self, _request: &DnsEffectRequest) -> Result<(), NativeDnsEffectError> {
            self.events.push("set");
            fail(self.failure, Failure::Set)
        }

        fn commit(&mut self) -> Result<(), NativeDnsEffectError> {
            self.events.push("commit");
            fail(self.failure, Failure::Commit)
        }

        fn apply(&mut self) -> Result<(), NativeDnsEffectError> {
            self.events.push("apply");
            fail(self.failure, Failure::Apply)
        }

        fn unlock(&mut self) -> Result<(), NativeDnsEffectError> {
            self.events.push("unlock");
            fail(self.failure, Failure::Unlock)
        }

        fn fresh_snapshot(
            &mut self,
            _network_service_id: &str,
        ) -> Result<DnsSnapshot, NativeDnsEffectError> {
            self.events.push("fresh_snapshot");
            fail(self.failure, Failure::FreshSnapshot)?;
            Ok(self.after.clone())
        }
    }

    fn fail(actual: Option<Failure>, expected: Failure) -> Result<(), NativeDnsEffectError> {
        if actual == Some(expected) {
            Err(NativeDnsEffectError::Unavailable)
        } else {
            Ok(())
        }
    }

    fn automatic() -> DnsSnapshot {
        DnsSnapshot {
            complete: true,
            network_service_id: "service-id".into(),
            mode: DnsConfigurationMode::Automatic,
            servers: Vec::new(),
            search_domains: Vec::new(),
        }
    }

    #[test]
    fn transaction_locks_checks_sets_commits_applies_unlocks_and_verifies() {
        let before = automatic();
        let plan = plan_manual_dns(
            "service-id",
            vec!["198.18.0.1".parse().unwrap()],
            vec!["example.test".into()],
        )
        .unwrap();
        let mut backend = MockBackend {
            before: before.clone(),
            after: expected_snapshot(&plan).unwrap(),
            failure: None,
            events: Vec::new(),
        };
        apply_dns_transaction(&mut backend, &plan, &dns_snapshot_sha256(&before).unwrap()).unwrap();
        assert_eq!(
            backend.events,
            [
                "lock",
                "snapshot",
                "set",
                "commit",
                "apply",
                "unlock",
                "fresh_snapshot"
            ]
        );
    }

    #[test]
    fn stale_precondition_never_mutates_and_still_unlocks() {
        let before = automatic();
        let plan = plan_manual_dns(
            "service-id",
            vec!["198.18.0.1".parse().unwrap()],
            Vec::new(),
        )
        .unwrap();
        let mut backend = MockBackend {
            before,
            after: expected_snapshot(&plan).unwrap(),
            failure: None,
            events: Vec::new(),
        };
        assert_eq!(
            apply_dns_transaction(&mut backend, &plan, &"0".repeat(64)),
            Err(NativeDnsEffectError::Stale)
        );
        assert_eq!(backend.events, ["lock", "snapshot", "unlock"]);
    }

    #[test]
    fn every_locked_failure_attempts_unlock_and_post_drift_fails_closed() {
        let before = automatic();
        let plan = plan_restore_dns(&DnsBaseline {
            network_service_id: "service-id".into(),
            mode: DnsConfigurationMode::Automatic,
            servers: Vec::new(),
            search_domains: Vec::new(),
        })
        .unwrap();
        let before_hash = dns_snapshot_sha256(&before).unwrap();
        for failure in [
            Failure::Snapshot,
            Failure::Set,
            Failure::Commit,
            Failure::Apply,
            Failure::Unlock,
        ] {
            let mut backend = MockBackend {
                before: before.clone(),
                after: automatic(),
                failure: Some(failure),
                events: Vec::new(),
            };
            assert!(apply_dns_transaction(&mut backend, &plan, &before_hash).is_err());
            assert_eq!(backend.events.last(), Some(&"unlock"));
        }

        let mut backend = MockBackend {
            before,
            after: DnsSnapshot {
                complete: true,
                network_service_id: "service-id".into(),
                mode: DnsConfigurationMode::Manual,
                servers: vec!["192.0.2.53".parse().unwrap()],
                search_domains: Vec::new(),
            },
            failure: None,
            events: Vec::new(),
        };
        assert_eq!(
            apply_dns_transaction(&mut backend, &plan, &before_hash),
            Err(NativeDnsEffectError::Drifted)
        );
    }
}
