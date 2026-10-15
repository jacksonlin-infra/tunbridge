//! Side-effect-free preparation for the native Darwin lifecycle start path.

use crate::{
    engine_config::{
        render_darwin_engine_config, render_darwin_engine_config_v3, DarwinEngineConfig,
    },
    lifecycle_plan::NetworkBaseline,
    upstream_owner::{verify_upstream_owner, VerifiedUpstream},
};
use std::{
    collections::BTreeSet,
    ffi::{c_char, CStr},
    fmt,
    net::IpAddr,
};
use tunbridge_service::{
    protocol::{StartProfile, StartProfileV3},
    state::Caller,
};

const MAX_UTUN_SUFFIX: u16 = 9_999;
const MAX_IDENTITY_COMPONENT_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeStartError {
    InvalidCaller,
    InvalidMaterial,
    InvalidBaseline,
    UpstreamUnavailable,
    ConfigUnavailable,
}

pub struct NativeStartPreparation {
    caller_uid: u32,
    run_id: String,
    upstream: VerifiedUpstream,
    engine_config: DarwinEngineConfig,
}

impl NativeStartPreparation {
    pub fn caller_uid(&self) -> u32 {
        self.caller_uid
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn upstream(&self) -> &VerifiedUpstream {
        &self.upstream
    }

    pub fn engine_config(&self) -> &DarwinEngineConfig {
        &self.engine_config
    }

    pub fn into_engine_config(self) -> DarwinEngineConfig {
        self.engine_config
    }
}

impl fmt::Debug for NativeStartPreparation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeStartPreparation")
            .field("caller_uid", &self.caller_uid)
            .field("run_id", &self.run_id)
            .field("upstream", &self.upstream)
            .field("engine_config", &self.engine_config)
            .finish()
    }
}

pub fn prepare_native_start(
    profile: &StartProfile,
    caller: &Caller,
    baseline: &NetworkBaseline,
    run_id: &str,
    controller_secret: &str,
) -> Result<NativeStartPreparation, NativeStartError> {
    if !valid_lower_hex(run_id, 32) || !valid_lower_hex(controller_secret, 64) {
        return Err(NativeStartError::InvalidMaterial);
    }
    let (caller_uid, upstream) = verify_native_upstream(profile, caller)?;
    let configured_device = select_configured_device(baseline)?;
    let default_interface_name = default_interface_name(baseline.default_interface_index)?;
    assemble_native_start(
        profile,
        caller_uid,
        run_id,
        controller_secret,
        configured_device,
        default_interface_name,
        upstream,
    )
}

pub fn prepare_native_start_v3(
    profile: &StartProfileV3,
    caller: &Caller,
    baseline: &NetworkBaseline,
    expected_upstream: &VerifiedUpstream,
    pinned_remote: Option<IpAddr>,
    run_id: &str,
    controller_secret: &str,
) -> Result<NativeStartPreparation, NativeStartError> {
    profile
        .validate()
        .map_err(|_| NativeStartError::InvalidMaterial)?;
    if !valid_lower_hex(run_id, 32) || !valid_lower_hex(controller_secret, 64) {
        return Err(NativeStartError::InvalidMaterial);
    }
    let caller_uid = authenticated_caller_uid(caller)?;
    let configured_device = select_configured_device(baseline)?;
    let default_interface_name = default_interface_name(baseline.default_interface_index)?;
    let mut client_process_paths = Vec::new();
    let process_name = if let Some(legacy) = profile.legacy_local_profile() {
        if pinned_remote.is_some() {
            return Err(NativeStartError::UpstreamUnavailable);
        }
        let verified = verify_upstream_owner(&legacy, caller_uid)
            .map_err(|_| NativeStartError::UpstreamUnavailable)?;
        if verified.identity != expected_upstream.identity {
            return Err(NativeStartError::UpstreamUnavailable);
        }
        client_process_paths = crate::client_family::client_family_paths(verified.identity.pid);
        // The listener goes first and always: it is matched by its exact
        // path, never by name.
        let listener = crate::native::process_executable_path(verified.identity.pid)
            .ok()
            .and_then(|path| path.to_str().map(str::to_owned))
            .ok_or(NativeStartError::UpstreamUnavailable)?;
        client_process_paths.retain(|path| *path != listener);
        client_process_paths.insert(0, listener);
        client_process_paths.truncate(16);
        #[cfg(feature = "macos-development-bootstrap")]
        crate::xpc_listener::debug_log(&format!(
            "native-stage=client-family count={} paths={:?}",
            client_process_paths.len(),
            client_process_paths
        ));
        Some(verified.process_name)
    } else {
        if pinned_remote.is_none() {
            return Err(NativeStartError::UpstreamUnavailable);
        }
        None
    };
    let engine_config = render_darwin_engine_config_v3(
        profile,
        pinned_remote,
        process_name.as_deref(),
        &client_process_paths,
        controller_secret,
        &configured_device,
        &default_interface_name,
    )
    .map_err(|_| NativeStartError::ConfigUnavailable)?;
    Ok(NativeStartPreparation {
        caller_uid,
        run_id: run_id.to_owned(),
        upstream: expected_upstream.clone(),
        engine_config,
    })
}

pub fn verify_native_upstream(
    profile: &StartProfile,
    caller: &Caller,
) -> Result<(u32, VerifiedUpstream), NativeStartError> {
    let caller_uid = authenticated_caller_uid(caller)?;
    let upstream = verify_upstream_owner(profile, caller_uid)
        .map_err(|_| NativeStartError::UpstreamUnavailable)?;
    Ok((caller_uid, upstream))
}

pub(crate) fn assemble_native_start(
    profile: &StartProfile,
    caller_uid: u32,
    run_id: &str,
    controller_secret: &str,
    configured_device: String,
    default_interface_name: String,
    upstream: VerifiedUpstream,
) -> Result<NativeStartPreparation, NativeStartError> {
    if upstream.identity.pid != profile.upstream_process_id {
        return Err(NativeStartError::UpstreamUnavailable);
    }
    let engine_config = render_darwin_engine_config(
        profile,
        &upstream.process_name,
        controller_secret,
        &configured_device,
        &default_interface_name,
    )
    .map_err(|_| NativeStartError::ConfigUnavailable)?;
    Ok(NativeStartPreparation {
        caller_uid,
        run_id: run_id.to_owned(),
        upstream,
        engine_config,
    })
}

fn default_interface_name(index: u32) -> Result<String, NativeStartError> {
    let mut bytes = [0 as c_char; libc::IFNAMSIZ];
    let pointer = unsafe { libc::if_indextoname(index, bytes.as_mut_ptr()) };
    if pointer.is_null() {
        return Err(NativeStartError::InvalidBaseline);
    }
    unsafe { CStr::from_ptr(pointer) }
        .to_str()
        .ok()
        .filter(|value| !value.is_empty() && value.len() < libc::IFNAMSIZ)
        .map(ToOwned::to_owned)
        .ok_or(NativeStartError::InvalidBaseline)
}

pub(crate) fn authenticated_caller_uid(caller: &Caller) -> Result<u32, NativeStartError> {
    if caller.is_admin || caller.session_id == 0 {
        return Err(NativeStartError::InvalidCaller);
    }
    let mut components = caller.principal_id.split(':');
    let platform = components.next();
    let uid_text = components.next();
    let team_id = components.next();
    let signing_identifier = components.next();
    if platform != Some("macos")
        || components.next().is_some()
        || !team_id.is_some_and(valid_identity_component)
        || !signing_identifier.is_some_and(valid_identity_component)
    {
        return Err(NativeStartError::InvalidCaller);
    }
    let uid_text = uid_text.ok_or(NativeStartError::InvalidCaller)?;
    let uid = uid_text
        .parse::<u32>()
        .map_err(|_| NativeStartError::InvalidCaller)?;
    if uid == 0 || uid.to_string() != uid_text {
        return Err(NativeStartError::InvalidCaller);
    }
    Ok(uid)
}

fn select_configured_device(baseline: &NetworkBaseline) -> Result<String, NativeStartError> {
    let mut occupied = BTreeSet::new();
    let mut occupied_indices = BTreeSet::new();
    for interface in &baseline.preexisting_utuns {
        let suffix = interface
            .interface_name
            .strip_prefix("utun")
            .ok_or(NativeStartError::InvalidBaseline)?;
        let suffix_number = suffix
            .parse::<u16>()
            .map_err(|_| NativeStartError::InvalidBaseline)?;
        if suffix.is_empty()
            || suffix.len() > 4
            || !suffix.bytes().all(|byte| byte.is_ascii_digit())
            || interface.interface_name != format!("utun{suffix_number}")
            || interface.interface_index == 0
            || !occupied.insert(interface.interface_name.as_str())
            || !occupied_indices.insert(interface.interface_index)
        {
            return Err(NativeStartError::InvalidBaseline);
        }
    }
    (0..=MAX_UTUN_SUFFIX)
        .map(|suffix| format!("utun{suffix}"))
        .find(|candidate| !occupied.contains(candidate.as_str()))
        .ok_or(NativeStartError::InvalidBaseline)
}

fn valid_identity_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTITY_COMPONENT_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn valid_lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle_plan::{
        DnsBaseline, DnsConfigurationMode, InterfaceIdentity, ProcessIdentity,
    };
    use std::{
        net::{IpAddr, Ipv4Addr, TcpListener},
        process,
    };
    use tunbridge_service::protocol::UpstreamProtocol;

    fn caller(uid: u32) -> Caller {
        Caller {
            principal_id: format!("macos:{uid}:ABCDE12345:com.tunbridge.desktop"),
            session_id: 42,
            is_admin: false,
        }
    }

    fn profile(port: u16, pid: u32) -> StartProfile {
        StartProfile {
            upstream_host: "127.0.0.1".into(),
            upstream_port: port,
            protocol: UpstreamProtocol::Socks5,
            username: Some("fixture-user".into()),
            password: Some("fixture-password".into()),
            upstream_process_id: pid,
            bypass_domains: Vec::new(),
            bypass_cidrs: Vec::new(),
            bypass_process_names: Vec::new(),
        }
    }

    fn baseline(preexisting_utuns: Vec<InterfaceIdentity>) -> NetworkBaseline {
        NetworkBaseline {
            default_interface_index: 9,
            default_gateway: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            routes_sha256: "a".repeat(64),
            preexisting_utuns,
            dns: DnsBaseline {
                network_service_id: "fixture-service".into(),
                mode: DnsConfigurationMode::Automatic,
                servers: Vec::new(),
                search_domains: Vec::new(),
            },
        }
    }

    fn verified(pid: u32) -> VerifiedUpstream {
        VerifiedUpstream {
            identity: ProcessIdentity {
                pid,
                start_time_ns: 1,
                executable_file_id: 2,
                executable_sha256: "b".repeat(64),
            },
            process_name: "fixture-proxy".into(),
            auto_bypass_cidrs: Vec::new(),
        }
    }

    #[test]
    fn authenticated_principal_maps_to_non_root_uid_only() {
        assert_eq!(authenticated_caller_uid(&caller(502)), Ok(502));
        for invalid in [
            Caller {
                principal_id: "macos:0:ABCDE12345:com.tunbridge.desktop".into(),
                ..caller(502)
            },
            Caller {
                principal_id: "macos:0502:ABCDE12345:com.tunbridge.desktop".into(),
                ..caller(502)
            },
            Caller {
                principal_id: "macos:502:ABCDE12345:com.tunbridge.desktop:extra".into(),
                ..caller(502)
            },
            Caller {
                is_admin: true,
                ..caller(502)
            },
        ] {
            assert_eq!(
                authenticated_caller_uid(&invalid),
                Err(NativeStartError::InvalidCaller)
            );
        }
    }

    #[test]
    fn device_selection_uses_first_absent_canonical_utun() {
        let snapshot = baseline(vec![
            InterfaceIdentity {
                interface_name: "utun0".into(),
                interface_index: 10,
            },
            InterfaceIdentity {
                interface_name: "utun2".into(),
                interface_index: 12,
            },
        ]);
        assert_eq!(select_configured_device(&snapshot).unwrap(), "utun1");

        let malformed = baseline(vec![InterfaceIdentity {
            interface_name: "en0".into(),
            interface_index: 10,
        }]);
        assert_eq!(
            select_configured_device(&malformed),
            Err(NativeStartError::InvalidBaseline)
        );
        let noncanonical = baseline(vec![InterfaceIdentity {
            interface_name: "utun00".into(),
            interface_index: 10,
        }]);
        assert_eq!(
            select_configured_device(&noncanonical),
            Err(NativeStartError::InvalidBaseline)
        );
    }

    #[test]
    fn assembly_binds_run_caller_upstream_and_redacted_config() {
        let profile = profile(7890, 600);
        let secret = "c".repeat(64);
        let prepared = assemble_native_start(
            &profile,
            502,
            &"d".repeat(32),
            &secret,
            "utun7".into(),
            "en0".into(),
            verified(600),
        )
        .unwrap();
        assert_eq!(prepared.caller_uid(), 502);
        assert_eq!(prepared.run_id(), "d".repeat(32));
        assert_eq!(prepared.upstream().identity.pid, 600);
        assert_eq!(prepared.engine_config().configured_device(), "utun7");
        let debug = format!("{prepared:?}");
        assert!(!debug.contains(&secret));
        assert!(!debug.contains("fixture-password"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn native_fixture_prepares_from_exact_loopback_owner_without_system_changes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let uid = unsafe { libc::geteuid() };
        let mut network_baseline = baseline(Vec::new());
        network_baseline.default_interface_index = unsafe { libc::if_nametoindex(c"en0".as_ptr()) };
        assert_ne!(network_baseline.default_interface_index, 0);
        let prepared = prepare_native_start(
            &profile(port, process::id()),
            &caller(uid),
            &network_baseline,
            &"e".repeat(32),
            &"f".repeat(64),
        )
        .unwrap();
        assert_eq!(prepared.caller_uid(), uid);
        assert_eq!(prepared.upstream().identity.pid, process::id());
        assert_eq!(prepared.engine_config().configured_device(), "utun0");
    }
}
