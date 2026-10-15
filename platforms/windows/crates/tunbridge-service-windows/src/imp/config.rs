use std::{
    collections::HashSet,
    io,
    os::windows::process::CommandExt as _,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use tunbridge_core::{
    config, config_v2,
    profile::{Profile, Protocol, Upstream},
    remote::{preflight_pinned_tcp, resolve_endpoint_system},
};

use crate::protocol::{ActiveStartProfile, StartProfile, StartUpstreamV3, UpstreamProtocol};

use super::{
    integrity::{reject_reparse_point, validate_asset_acl, validate_engine_files, ValidatedEngine},
    random::random_hex_32,
    storage::ProtectedDataDirectory,
    upstream::{verify_upstream_listener, VerifiedUpstream},
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const CONFIG_TEST_TIMEOUT: Duration = Duration::from_secs(10);

pub struct RenderedServiceConfig {
    pub yaml: String,
    pub controller: String,
    pub tun_device: String,
    upstream: Upstream,
    controller_secret: String,
}

impl RenderedServiceConfig {
    pub fn controller_secret(&self) -> &str {
        &self.controller_secret
    }
}

pub struct PreparedServiceConfig {
    engine: ValidatedEngine,
    active_config: PathBuf,
    data_root: PathBuf,
    controller: String,
    tun_device: String,
    upstream: Upstream,
    upstream_identity: Option<VerifiedUpstream>,
    remote_upstream: bool,
    controller_secret: String,
}

impl PreparedServiceConfig {
    pub fn engine(&self) -> &ValidatedEngine {
        &self.engine
    }

    pub fn active_config(&self) -> &Path {
        &self.active_config
    }

    pub fn data_root(&self) -> &Path {
        &self.data_root
    }

    pub fn controller(&self) -> &str {
        &self.controller
    }

    pub fn tun_device(&self) -> &str {
        &self.tun_device
    }

    pub fn upstream(&self) -> &Upstream {
        &self.upstream
    }

    pub fn upstream_identity(&self) -> Option<&VerifiedUpstream> {
        self.upstream_identity.as_ref()
    }

    pub fn remote_upstream(&self) -> bool {
        self.remote_upstream
    }

    pub fn controller_secret(&self) -> &str {
        &self.controller_secret
    }

    #[cfg(test)]
    pub(super) fn for_test(
        engine: ValidatedEngine,
        active_config: PathBuf,
        data_root: PathBuf,
    ) -> Self {
        Self {
            engine,
            active_config,
            data_root,
            controller: "127.0.0.1:25412".into(),
            tun_device: "tunbridge".into(),
            upstream: Upstream {
                host: "127.0.0.1".into(),
                port: 7078,
                protocol: Protocol::Socks5,
                username: None,
                password: None,
                udp: true,
            },
            upstream_identity: Some(VerifiedUpstream::for_test()),
            remote_upstream: false,
            controller_secret: "a".repeat(64),
        }
    }
}

/// Convert the bounded IPC profile into the fixed M0/M1 product profile.
///
/// `upstream_image_path` must come from the service's own PID/listener
/// verification. It is never accepted as the authoritative anti-recursion
/// identity from the client. The listener is matched by this exact path, so
/// no other program can go direct by borrowing its file name.
pub fn render_service_config(
    request: &StartProfile,
    upstream_image_path: &Path,
) -> Result<RenderedServiceConfig, ConfigError> {
    let controller_secret = random_hex_32().map_err(ConfigError::Random)?;
    render_service_config_with_secret(request, upstream_image_path, controller_secret)
}

/// Run the already integrity-validated engine in fixed config-test mode.
/// This never starts the TUN runtime and never forwards engine diagnostics,
/// which may contain credentials from the rendered candidate.
pub fn validate_engine_config(
    engine: &ValidatedEngine,
    candidate: &Path,
    data_root: &Path,
) -> Result<(), ConfigError> {
    let canonical_root = data_root.canonicalize().map_err(ConfigError::Io)?;
    let canonical_candidate = candidate.canonicalize().map_err(ConfigError::Io)?;
    validate_candidate_path(&canonical_candidate, &canonical_root)?;
    reject_reparse_point(&canonical_root, "runtime data directory")
        .map_err(ConfigError::Integrity)?;
    validate_asset_acl(&canonical_root, "runtime data directory")
        .map_err(ConfigError::Integrity)?;
    reject_reparse_point(&canonical_candidate, "candidate config")
        .map_err(ConfigError::Integrity)?;
    validate_asset_acl(&canonical_candidate, "candidate config").map_err(ConfigError::Integrity)?;

    let mut child = Command::new(engine.path())
        .args(["-t", "-f"])
        .arg(&canonical_candidate)
        .arg("-d")
        .arg(&canonical_root)
        .current_dir(&canonical_root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(ConfigError::EngineTestSpawn)?;
    let status = wait_bounded(&mut child, CONFIG_TEST_TIMEOUT)?;
    if !status.success() {
        return Err(ConfigError::EngineRejected(status.code()));
    }
    Ok(())
}

fn validate_candidate_path(candidate: &Path, root: &Path) -> Result<(), ConfigError> {
    if candidate.parent() != Some(root)
        || !candidate.file_name().is_some_and(|name| {
            let name = name.to_string_lossy();
            name.starts_with("candidate-") && name.ends_with(".yaml")
        })
    {
        return Err(ConfigError::CandidateEscape);
    }
    Ok(())
}

fn wait_bounded(child: &mut Child, timeout: Duration) -> Result<ExitStatus, ConfigError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().map_err(ConfigError::Io)? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            // Close the race where the process exits immediately at deadline.
            if let Some(status) = child.try_wait().map_err(ConfigError::Io)? {
                return Ok(status);
            }
            let _ = child.kill();
            let _ = child.wait();
            return Err(ConfigError::EngineTestTimeout);
        }
        sleep(Duration::from_millis(25));
    }
}

fn render_service_config_with_secret(
    request: &StartProfile,
    upstream_image_path: &Path,
    controller_secret: String,
) -> Result<RenderedServiceConfig, ConfigError> {
    request.validate().map_err(ConfigError::Profile)?;
    let upstream_image_path = upstream_image_path
        .to_str()
        .filter(|path| valid_process_path(path))
        .ok_or(ConfigError::InvalidUpstreamProcessName)?;
    if controller_secret.len() != 64
        || !controller_secret
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ConfigError::InvalidControllerSecret);
    }

    let protocol = match request.protocol {
        UpstreamProtocol::Socks5 => Protocol::Socks5,
        UpstreamProtocol::Http => Protocol::Http,
    };
    let mut profile = Profile::with_upstream(Upstream {
        host: match request.upstream_host.as_str() {
            "localhost" => "127.0.0.1".into(),
            other => other.into(),
        },
        port: request.upstream_port,
        protocol,
        username: request.username.clone(),
        password: request.password.clone(),
        udp: protocol == Protocol::Socks5,
    });
    profile.secret = controller_secret;

    profile.exclude_process_paths = vec![upstream_image_path.to_string()];
    profile.exclude_processes =
        deduplicate_case_insensitive(request.bypass_process_names.iter().cloned());
    profile.bypass_domains = deduplicate_case_insensitive(
        request
            .bypass_domains
            .iter()
            .map(|domain| domain.trim_start_matches('.').to_string()),
    );
    merge_bypass_cidrs(&mut profile.bypass_cidrs, &request.bypass_cidrs);

    let yaml = config::render(&profile).map_err(ConfigError::Render)?;
    Ok(RenderedServiceConfig {
        yaml,
        controller: profile.external_controller,
        tun_device: profile.tun_device,
        upstream: profile.upstream,
        controller_secret: profile.secret,
    })
}

/// Execute the complete pre-spawn transaction. The active config changes only
/// after engine integrity, protected storage, and the real config test pass.
pub fn prepare_validated_config(
    install_root: &Path,
    request: &ActiveStartProfile,
) -> Result<PreparedServiceConfig, ConfigError> {
    request.validate().map_err(ConfigError::Profile)?;
    match &request.upstream {
        StartUpstreamV3::LocalListener { .. } => {
            let legacy = request.legacy_local_profile().ok_or_else(|| {
                ConfigError::Profile(crate::protocol::ProtocolError::InvalidProfile(
                    "the local upstream could not be represented safely".into(),
                ))
            })?;
            prepare_validated_local_config(install_root, &legacy)
        }
        StartUpstreamV3::RemoteServer {
            endpoint,
            protocol_config,
            secret_material,
        } => prepare_validated_remote_config(
            install_root,
            request,
            endpoint,
            protocol_config,
            secret_material.as_ref(),
        ),
    }
}

fn prepare_validated_local_config(
    install_root: &Path,
    request: &StartProfile,
) -> Result<PreparedServiceConfig, ConfigError> {
    let upstream = verify_upstream_listener(request).map_err(ConfigError::Upstream)?;
    let engine = validate_engine_files(install_root).map_err(ConfigError::Integrity)?;
    let rendered = render_service_config(request, upstream.image_path())?;
    prepare_rendered_config(engine, rendered, Some(upstream), false)
}

fn prepare_validated_remote_config(
    install_root: &Path,
    request: &ActiveStartProfile,
    endpoint: &tunbridge_core::upstream::Endpoint,
    protocol_config: &tunbridge_core::upstream::RemoteProtocolConfig,
    secret_material: Option<&tunbridge_core::upstream::SecretMaterialV2>,
) -> Result<PreparedServiceConfig, ConfigError> {
    let pinned = resolve_endpoint_system(endpoint)
        .map_err(ConfigError::RemoteResolution)?
        .into_iter()
        .find(std::net::IpAddr::is_ipv4)
        .ok_or(ConfigError::RemoteAddressFamily)?;
    preflight_pinned_tcp(pinned, endpoint.port, Duration::from_secs(4))
        .map_err(ConfigError::RemoteResolution)?;
    let controller_secret = random_hex_32().map_err(ConfigError::Random)?;
    let standard_protocol = protocol_config.standard_protocol();
    let (username, password) = secret_material
        .map(|material| material.material.basic_auth())
        .map_or((None, None), |(username, password)| {
            (Some(username.to_owned()), Some(password.to_owned()))
        });
    let upstream = Upstream {
        host: pinned.to_string(),
        port: endpoint.port,
        protocol: match standard_protocol {
            tunbridge_core::upstream::StandardProtocol::Socks5 => Protocol::Socks5,
            tunbridge_core::upstream::StandardProtocol::Http => Protocol::Http,
        },
        username,
        password,
        udp: protocol_config.udp_enabled(),
    };
    let mut profile = Profile::with_upstream(upstream.clone());
    profile.secret = controller_secret;
    profile.exclude_processes =
        deduplicate_case_insensitive(request.traffic_bypass_process_names.iter().cloned());
    profile.bypass_domains = deduplicate_case_insensitive(
        request
            .traffic_bypass_domains
            .iter()
            .map(|domain| domain.trim_start_matches('.').to_string()),
    );
    // Keep the default LAN, link-local and multicast bypass like the local
    // path; replacing it sent private and on-link traffic to the remote proxy.
    merge_bypass_cidrs(&mut profile.bypass_cidrs, &request.traffic_bypass_cidrs);
    let yaml = config_v2::render_remote(
        &profile,
        &config_v2::ResolvedRemoteUpstream {
            pinned_server: pinned,
            port: endpoint.port,
            protocol_config,
            secret_material,
            transport_escape: config_v2::TransportEscape::EngineRouteExclude,
        },
    )
    .map_err(ConfigError::Render)?;
    let rendered = RenderedServiceConfig {
        yaml,
        controller: profile.external_controller,
        tun_device: profile.tun_device,
        upstream,
        controller_secret: profile.secret,
    };
    let engine = validate_engine_files(install_root).map_err(ConfigError::Integrity)?;
    prepare_rendered_config(engine, rendered, None, true)
}

fn prepare_rendered_config(
    engine: ValidatedEngine,
    rendered: RenderedServiceConfig,
    upstream_identity: Option<VerifiedUpstream>,
    remote_upstream: bool,
) -> Result<PreparedServiceConfig, ConfigError> {
    let storage = ProtectedDataDirectory::prepare().map_err(ConfigError::Storage)?;
    let candidate = storage
        .write_candidate(&rendered.yaml)
        .map_err(ConfigError::Storage)?;

    if let Err(primary) = validate_candidate_transaction(&engine, &candidate, storage.root()) {
        return match storage.remove_candidate(&candidate) {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(ConfigError::CandidateCleanup {
                primary: Box::new(primary),
                cleanup,
            }),
        };
    }
    let active_config = match storage.promote_candidate(&candidate) {
        Ok(active) => active,
        Err(primary) => {
            return match storage.remove_candidate(&candidate) {
                Ok(()) => Err(ConfigError::Storage(primary)),
                Err(cleanup) => Err(ConfigError::CandidateCleanup {
                    primary: Box::new(ConfigError::Storage(primary)),
                    cleanup,
                }),
            };
        }
    };

    Ok(PreparedServiceConfig {
        engine,
        active_config,
        data_root: storage.root().to_path_buf(),
        controller: rendered.controller,
        tun_device: rendered.tun_device,
        upstream: rendered.upstream,
        upstream_identity,
        remote_upstream,
        controller_secret: rendered.controller_secret,
    })
}

fn validate_candidate_transaction(
    engine: &ValidatedEngine,
    candidate: &Path,
    data_root: &Path,
) -> Result<(), ConfigError> {
    #[cfg(feature = "acceptance-fault-injection")]
    if super::acceptance::active_fault().map_err(ConfigError::AcceptanceFault)?
        == Some(super::acceptance::AcceptanceFault::ConfigValidationRejected)
    {
        return Err(ConfigError::EngineRejected(None));
    }
    validate_engine_config(engine, candidate, data_root)
}

fn deduplicate_case_insensitive(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = HashSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.to_ascii_lowercase()))
        .collect()
}

/// An absolute Windows image path that can be embedded in one engine rule.
fn valid_process_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.len() <= 1024
        && bytes.len() > 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && bytes[2] == b'\\'
        && !path
            .chars()
            .any(|character| character.is_control() || matches!(character, ',' | '/'))
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("typed service profile is invalid: {0}")]
    Profile(#[source] crate::protocol::ProtocolError),
    #[error("verified upstream process name is invalid")]
    InvalidUpstreamProcessName,
    #[error("controller secret must be exactly 64 hexadecimal characters")]
    InvalidControllerSecret,
    #[error("Windows CSPRNG failed: {0}")]
    Random(#[source] std::io::Error),
    #[error("mihomo configuration rendering failed: {0}")]
    Render(#[source] tunbridge_core::CoreError),
    #[error("candidate config escaped the protected runtime directory")]
    CandidateEscape,
    #[error("candidate config integrity failed: {0}")]
    Integrity(#[source] super::integrity::IntegrityError),
    #[error("engine config test could not start: {0}")]
    EngineTestSpawn(#[source] io::Error),
    #[error("engine rejected the generated config with exit code {0:?}")]
    EngineRejected(Option<i32>),
    #[error("engine config test exceeded the fixed 10 second deadline")]
    EngineTestTimeout,
    #[error("engine config test I/O failed: {0}")]
    Io(#[source] io::Error),
    #[error("protected config storage failed: {0}")]
    Storage(#[source] super::storage::StorageError),
    #[error("upstream listener identity failed: {0}")]
    Upstream(#[source] super::upstream::UpstreamIdentityError),
    #[error("remote upstream resolution failed: {0}")]
    RemoteResolution(#[source] tunbridge_core::remote::RemoteResolutionError),
    #[error("remote upstream did not resolve to a supported address family")]
    RemoteAddressFamily,
    #[error("config transaction failed ({primary}); candidate cleanup also failed ({cleanup})")]
    CandidateCleanup {
        primary: Box<ConfigError>,
        cleanup: super::storage::StorageError,
    },
    #[cfg(feature = "acceptance-fault-injection")]
    #[error("acceptance fault selector failed: {0}")]
    AcceptanceFault(#[source] super::acceptance::AcceptanceFaultError),
}

/// Appends requested bypass CIDRs to the profile defaults, keeping order and
/// dropping duplicates.
fn merge_bypass_cidrs(defaults: &mut Vec<String>, requested: &[String]) {
    let mut seen: HashSet<String> = defaults.iter().cloned().collect();
    for cidr in requested {
        if seen.insert(cidr.clone()) {
            defaults.push(cidr.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> StartProfile {
        StartProfile {
            upstream_host: "localhost".into(),
            upstream_port: 7078,
            protocol: UpstreamProtocol::Socks5,
            username: Some("alice".into()),
            password: Some("secret".into()),
            upstream_process_id: 42,
            bypass_domains: vec![".Example.com".into(), "example.com".into()],
            bypass_cidrs: vec!["10.0.0.0/8".into(), "fd00::/8".into()],
            bypass_process_names: vec!["CLIENT.EXE".into(), "helper.exe".into()],
        }
    }

    const CLIENT: &str = r"C:\Program Files\Client\client.exe";

    #[test]
    fn renders_fixed_product_config_from_typed_profile() {
        let rendered =
            render_service_config_with_secret(&profile(), Path::new(CLIENT), "a".repeat(64))
                .unwrap();
        let yaml: serde_yaml::Value = serde_yaml::from_str(&rendered.yaml).unwrap();
        assert_eq!(yaml["proxies"][0]["server"], "127.0.0.1");
        assert_eq!(yaml["proxies"][0]["username"], "alice");
        assert_eq!(yaml["proxies"][0]["password"], "secret");
        assert_eq!(yaml["secret"], "a".repeat(64));
        assert_eq!(yaml["tun"]["strict-route"], false);
        assert_eq!(rendered.controller, "127.0.0.1:25412");
        assert_eq!(rendered.tun_device, "tunbridge");

        let rules: Vec<&str> = yaml["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|rule| rule.as_str().unwrap())
            .collect();
        // The listener only by its exact path; user bypasses keep their names.
        assert_eq!(
            rules[0],
            r"PROCESS-PATH,C:\Program Files\Client\client.exe,DIRECT"
        );
        assert!(!rules.contains(&"PROCESS-NAME,client.exe,DIRECT"));
        assert!(rules.contains(&"PROCESS-NAME,CLIENT.EXE,DIRECT"));
        assert!(rules.contains(&"PROCESS-NAME,helper.exe,DIRECT"));
        assert!(rules.contains(&"DOMAIN-SUFFIX,Example.com,DIRECT"));
        assert!(rules.contains(&"IP-CIDR6,fd00::/8,DIRECT,no-resolve"));
        assert_eq!(
            rules[rules.len() - 2],
            "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"
        );
        assert_eq!(rules.last(), Some(&"MATCH,upstream"));
    }

    #[test]
    fn rejects_unverified_process_identity_and_client_supplied_secret_shape() {
        for unverified in ["client.exe", r"C:\Program Files\a,b.exe", "C:/client.exe"] {
            assert!(matches!(
                render_service_config_with_secret(
                    &profile(),
                    Path::new(unverified),
                    "a".repeat(64)
                ),
                Err(ConfigError::InvalidUpstreamProcessName)
            ));
        }
        assert!(matches!(
            render_service_config_with_secret(&profile(), Path::new(CLIENT), "not-random".into()),
            Err(ConfigError::InvalidControllerSecret)
        ));
    }

    #[test]
    fn http_upstream_never_enables_udp() {
        let mut request = profile();
        request.protocol = UpstreamProtocol::Http;
        let rendered =
            render_service_config_with_secret(&request, Path::new(CLIENT), "b".repeat(64)).unwrap();
        let yaml: serde_yaml::Value = serde_yaml::from_str(&rendered.yaml).unwrap();
        assert_eq!(yaml["proxies"][0]["type"], "http");
        assert_eq!(yaml["proxies"][0]["udp"], false);
        let rules: Vec<&str> = yaml["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|rule| rule.as_str().unwrap())
            .collect();
        assert_eq!(rules[rules.len() - 2], "NETWORK,UDP,REJECT");
        assert_eq!(rules.last(), Some(&"MATCH,upstream"));
    }

    #[test]
    fn public_renderer_generates_the_controller_secret() {
        let first = render_service_config(&profile(), Path::new(CLIENT)).unwrap();
        let second = render_service_config(&profile(), Path::new(CLIENT)).unwrap();
        let first: serde_yaml::Value = serde_yaml::from_str(&first.yaml).unwrap();
        let second: serde_yaml::Value = serde_yaml::from_str(&second.yaml).unwrap();
        let first_secret = first["secret"].as_str().unwrap();
        assert_eq!(first_secret.len(), 64);
        assert_ne!(first_secret, second["secret"].as_str().unwrap());
    }

    #[test]
    fn candidate_path_must_be_a_direct_unique_child() {
        let root = Path::new(r"C:\ProgramData\TunBridge\run");
        assert!(validate_candidate_path(&root.join("candidate-a.yaml"), root).is_ok());
        assert!(validate_candidate_path(&root.join("active-config.yaml"), root).is_err());
        assert!(validate_candidate_path(&root.join(r"..\candidate-a.yaml"), root).is_err());
    }

    #[test]
    fn engine_test_wait_is_bounded() {
        let mut success = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", "exit 0"])
            .spawn()
            .unwrap();
        assert!(wait_bounded(&mut success, Duration::from_secs(2))
            .unwrap()
            .success());

        let mut stalled = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 5",
            ])
            .spawn()
            .unwrap();
        assert!(matches!(
            wait_bounded(&mut stalled, Duration::from_millis(50)),
            Err(ConfigError::EngineTestTimeout)
        ));
        assert!(stalled.try_wait().unwrap().is_some());
    }

    #[test]
    fn requested_bypass_cidrs_extend_the_default_lan_bypass() {
        let mut cidrs = vec!["192.168.0.0/16".to_string(), "10.0.0.0/8".to_string()];
        merge_bypass_cidrs(&mut cidrs, &[]);
        assert_eq!(cidrs, ["192.168.0.0/16", "10.0.0.0/8"]);
        merge_bypass_cidrs(&mut cidrs, &["10.0.0.0/8".into(), "100.64.0.0/10".into()]);
        assert_eq!(cidrs, ["192.168.0.0/16", "10.0.0.0/8", "100.64.0.0/10"]);
    }

    #[test]
    #[ignore = "requires elevated staged Program Files and ProgramData assets"]
    fn real_staged_engine_accepts_service_config_transaction() {
        use std::net::{Ipv4Addr, TcpListener};

        let install_root =
            PathBuf::from(std::env::var_os("ProgramFiles").unwrap()).join("TunBridge");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut request = profile();
        request.upstream_port = listener.local_addr().unwrap().port();
        request.upstream_process_id = std::process::id();
        let request = crate::protocol::StartProfileV3 {
            upstream: crate::protocol::StartUpstreamV3::LocalListener {
                port: request.upstream_port,
                protocol: tunbridge_core::upstream::StandardProtocol::Socks5,
                credentials: Some(tunbridge_core::upstream::SecretMaterialV2::basic_auth(
                    request.username.clone().unwrap(),
                    request.password.clone().unwrap(),
                )),
                expected_process_id: request.upstream_process_id,
            },
            traffic_bypass_domains: request.bypass_domains.clone(),
            traffic_bypass_cidrs: request.bypass_cidrs.clone(),
            traffic_bypass_process_names: request.bypass_process_names.clone(),
        };
        let prepared = prepare_validated_config(&install_root, &request).unwrap();
        assert_eq!(prepared.engine().version(), "v1.19.30");
        assert!(prepared.active_config().ends_with("active-config.yaml"));
        assert_eq!(prepared.controller(), "127.0.0.1:25412");
        assert_eq!(prepared.controller_secret().len(), 64);
    }
}
