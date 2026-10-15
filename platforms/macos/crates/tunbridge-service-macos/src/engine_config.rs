//! Deterministic Darwin Mihomo configuration with no system effects.

use serde::Serialize;
use std::{collections::BTreeSet, fmt, net::IpAddr};
use tunbridge_core::upstream::{CertificatePolicy, StandardProtocol};
use tunbridge_service::protocol::{
    StartProfile, StartProfileV3, StartUpstreamV3, UpstreamProtocol,
};
use zeroize::Zeroize;

pub const CONTROLLER_ADDRESS: &str = "127.0.0.1:25412";
const MAX_CONFIG_BYTES: usize = 256 * 1024;
const DIRECT_DEFAULT: &str = "direct-default";
const TUN_IPV4_ADDRESS: &str = "198.18.0.1/30";
const TUN_IPV6_ADDRESS: &str = "fdfe:dcba:9876::1/126";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineConfigError {
    Invalid,
    TooLarge,
}

pub struct DarwinEngineConfig {
    yaml: String,
    configured_device: String,
}

impl DarwinEngineConfig {
    pub fn as_bytes(&self) -> &[u8] {
        self.yaml.as_bytes()
    }

    pub fn configured_device(&self) -> &str {
        &self.configured_device
    }
}

impl fmt::Debug for DarwinEngineConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DarwinEngineConfig")
            .field("configured_device", &self.configured_device)
            .field("yaml", &"[REDACTED]")
            .finish()
    }
}

impl Drop for DarwinEngineConfig {
    fn drop(&mut self) {
        self.yaml.zeroize();
    }
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Config {
    allow_lan: bool,
    bind_address: &'static str,
    mode: &'static str,
    log_level: &'static str,
    ipv6: bool,
    external_controller: &'static str,
    secret: String,
    profile: ProfileState,
    dns: Dns,
    tun: Tun,
    proxies: Vec<Proxy>,
    rules: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct ProfileState {
    store_selected: bool,
    store_fake_ip: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Dns {
    enable: bool,
    ipv6: bool,
    use_system_hosts: bool,
    enhanced_mode: &'static str,
    fake_ip_range: &'static str,
    fake_ip_filter: Vec<&'static str>,
    nameserver: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Tun {
    enable: bool,
    device: String,
    inet4_address: Vec<&'static str>,
    inet6_address: Vec<&'static str>,
    stack: &'static str,
    dns_hijack: Vec<&'static str>,
    auto_route: bool,
    auto_detect_interface: bool,
    strict_route: bool,
    mtu: u16,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Proxy {
    Upstream(UpstreamProxy),
    Direct(DirectProxy),
}

#[derive(Serialize)]
struct UpstreamProxy {
    name: &'static str,
    #[serde(rename = "type")]
    kind: &'static str,
    server: String,
    port: u16,
    udp: bool,
    tls: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    sni: Option<String>,
    #[serde(rename = "skip-cert-verify")]
    skip_cert_verify: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct DirectProxy {
    name: &'static str,
    #[serde(rename = "type")]
    kind: &'static str,
    interface_name: String,
}

pub fn render_darwin_engine_config(
    profile: &StartProfile,
    upstream_process_name: &str,
    controller_secret: &str,
    configured_device: &str,
    default_interface_name: &str,
) -> Result<DarwinEngineConfig, EngineConfigError> {
    profile.validate().map_err(|_| EngineConfigError::Invalid)?;
    if !valid_process_name(upstream_process_name)
        || !valid_secret(controller_secret)
        || !valid_utun_name(configured_device)
        || !valid_default_interface_name(default_interface_name)
    {
        return Err(EngineConfigError::Invalid);
    }
    let kind = match profile.protocol {
        UpstreamProtocol::Socks5 => "socks5",
        UpstreamProtocol::Http => "http",
    };
    let mut rules = Vec::new();
    let mut process_names = BTreeSet::new();
    for name in std::iter::once(upstream_process_name)
        .chain(profile.bypass_process_names.iter().map(String::as_str))
    {
        let normalized = name.to_ascii_lowercase();
        if process_names.insert(normalized) {
            rules.push(format!("PROCESS-NAME,{name},{DIRECT_DEFAULT}"));
        }
    }
    for cidr in deduplicate(&profile.bypass_cidrs) {
        let family = if cidr.contains(':') {
            "IP-CIDR6"
        } else {
            "IP-CIDR"
        };
        rules.push(format!("{family},{cidr},{DIRECT_DEFAULT},no-resolve"));
    }
    for domain in deduplicate(&profile.bypass_domains) {
        rules.push(format!("DOMAIN-SUFFIX,{domain},{DIRECT_DEFAULT}"));
    }
    rules.push("MATCH,upstream".into());

    let config = Config {
        allow_lan: false,
        bind_address: "127.0.0.1",
        mode: "rule",
        log_level: "info",
        ipv6: true,
        external_controller: CONTROLLER_ADDRESS,
        secret: controller_secret.into(),
        profile: ProfileState {
            store_selected: false,
            store_fake_ip: false,
        },
        dns: Dns {
            enable: true,
            ipv6: true,
            use_system_hosts: true,
            enhanced_mode: "fake-ip",
            fake_ip_range: "198.18.0.1/16",
            fake_ip_filter: vec!["+.local", "+.localhost"],
            nameserver: vec![format!("dhcp://{default_interface_name}")],
        },
        tun: Tun {
            enable: true,
            device: configured_device.into(),
            inet4_address: vec![TUN_IPV4_ADDRESS],
            inet6_address: vec![TUN_IPV6_ADDRESS],
            stack: "gvisor",
            dns_hijack: vec!["any:53", "tcp://any:53"],
            auto_route: false,
            auto_detect_interface: false,
            strict_route: false,
            mtu: 1500,
        },
        proxies: vec![
            Proxy::Upstream(UpstreamProxy {
                name: "upstream",
                kind,
                server: match profile.upstream_host.as_str() {
                    "localhost" => "127.0.0.1".into(),
                    value => value.into(),
                },
                port: profile.upstream_port,
                udp: profile.protocol == UpstreamProtocol::Socks5,
                tls: false,
                sni: None,
                skip_cert_verify: false,
                username: profile.username.clone(),
                password: profile.password.clone(),
            }),
            Proxy::Direct(DirectProxy {
                name: DIRECT_DEFAULT,
                kind: "direct",
                interface_name: default_interface_name.into(),
            }),
        ],
        rules,
    };
    let yaml = serde_yaml::to_string(&config).map_err(|_| EngineConfigError::Invalid)?;
    if yaml.len() > MAX_CONFIG_BYTES {
        return Err(EngineConfigError::TooLarge);
    }
    Ok(DarwinEngineConfig {
        yaml,
        configured_device: configured_device.into(),
    })
}

pub fn render_darwin_engine_config_v3(
    profile: &StartProfileV3,
    pinned_remote: Option<IpAddr>,
    upstream_process_name: Option<&str>,
    client_process_paths: &[String],
    controller_secret: &str,
    configured_device: &str,
    default_interface_name: &str,
) -> Result<DarwinEngineConfig, EngineConfigError> {
    profile.validate().map_err(|_| EngineConfigError::Invalid)?;
    if !valid_secret(controller_secret)
        || !valid_utun_name(configured_device)
        || !valid_default_interface_name(default_interface_name)
    {
        return Err(EngineConfigError::Invalid);
    }
    if let Some(process_name) = upstream_process_name {
        if !valid_process_name(process_name) {
            return Err(EngineConfigError::Invalid);
        }
    }
    if client_process_paths.len() > 16
        || !client_process_paths
            .iter()
            .all(|path| valid_process_path(path))
    {
        return Err(EngineConfigError::Invalid);
    }

    let (kind, server, port, udp, tls, sni, skip_cert_verify, username, password) =
        match &profile.upstream {
            StartUpstreamV3::LocalListener {
                port,
                protocol,
                credentials,
                ..
            } => {
                if pinned_remote.is_some() || upstream_process_name.is_none() {
                    return Err(EngineConfigError::Invalid);
                }
                let (username, password) = credentials
                    .as_ref()
                    .map(|material| material.material.basic_auth())
                    .map_or((None, None), |(username, password)| {
                        (Some(username.to_owned()), Some(password.to_owned()))
                    });
                (
                    match protocol {
                        StandardProtocol::Socks5 => "socks5",
                        StandardProtocol::Http => "http",
                    },
                    "127.0.0.1".to_owned(),
                    *port,
                    *protocol == StandardProtocol::Socks5,
                    false,
                    None,
                    false,
                    username,
                    password,
                )
            }
            StartUpstreamV3::RemoteServer {
                endpoint,
                protocol_config,
                secret_material,
            } => {
                let pinned = pinned_remote.ok_or(EngineConfigError::Invalid)?;
                if pinned.is_ipv6() || upstream_process_name.is_some() {
                    return Err(EngineConfigError::Invalid);
                }
                let (username, password) = secret_material
                    .as_ref()
                    .map(|material| material.material.basic_auth())
                    .map_or((None, None), |(username, password)| {
                        (Some(username.to_owned()), Some(password.to_owned()))
                    });
                (
                    match protocol_config.standard_protocol() {
                        StandardProtocol::Socks5 => "socks5",
                        StandardProtocol::Http => "http",
                    },
                    pinned.to_string(),
                    endpoint.port,
                    protocol_config.udp_enabled(),
                    protocol_config.tls_enabled(),
                    protocol_config.sni().map(ToOwned::to_owned),
                    protocol_config.certificate_policy() == CertificatePolicy::Insecure,
                    username,
                    password,
                )
            }
        };

    let mut rules = Vec::new();
    let mut process_names = BTreeSet::new();
    // The upstream listener itself is matched by its full path, as part of
    // the client family below: matching it by file name would let any
    // program with the same name go direct. Only the user's own bypass
    // names stay name rules.
    for name in profile
        .traffic_bypass_process_names
        .iter()
        .map(String::as_str)
    {
        if process_names.insert(name.to_ascii_lowercase()) {
            rules.push(format!("PROCESS-NAME,{name},{DIRECT_DEFAULT}"));
        }
    }
    // The rest of the local client (for example the UI that logs in before
    // the listener exists) must never depend on the upstream it provides.
    for path in client_process_paths {
        rules.push(format!("PROCESS-PATH,{path},{DIRECT_DEFAULT}"));
    }
    for cidr in deduplicate(&profile.traffic_bypass_cidrs) {
        let family = if cidr.contains(':') {
            "IP-CIDR6"
        } else {
            "IP-CIDR"
        };
        rules.push(format!("{family},{cidr},{DIRECT_DEFAULT},no-resolve"));
    }
    for domain in deduplicate(&profile.traffic_bypass_domains) {
        rules.push(format!("DOMAIN-SUFFIX,{domain},{DIRECT_DEFAULT}"));
    }
    rules.push("MATCH,upstream".into());

    let config = Config {
        allow_lan: false,
        bind_address: "127.0.0.1",
        mode: "rule",
        log_level: "info",
        ipv6: true,
        external_controller: CONTROLLER_ADDRESS,
        secret: controller_secret.into(),
        profile: ProfileState {
            store_selected: false,
            store_fake_ip: false,
        },
        dns: Dns {
            enable: true,
            ipv6: true,
            use_system_hosts: true,
            enhanced_mode: "fake-ip",
            fake_ip_range: "198.18.0.1/16",
            fake_ip_filter: vec!["+.local", "+.localhost"],
            nameserver: vec![format!("dhcp://{default_interface_name}")],
        },
        tun: Tun {
            enable: true,
            device: configured_device.into(),
            inet4_address: vec![TUN_IPV4_ADDRESS],
            inet6_address: vec![TUN_IPV6_ADDRESS],
            stack: "gvisor",
            dns_hijack: vec!["any:53", "tcp://any:53"],
            auto_route: false,
            auto_detect_interface: false,
            strict_route: false,
            mtu: 1500,
        },
        proxies: vec![
            Proxy::Upstream(UpstreamProxy {
                name: "upstream",
                kind,
                server,
                port,
                udp,
                tls,
                sni,
                skip_cert_verify,
                username,
                password,
            }),
            Proxy::Direct(DirectProxy {
                name: DIRECT_DEFAULT,
                kind: "direct",
                interface_name: default_interface_name.into(),
            }),
        ],
        rules,
    };
    let yaml = serde_yaml::to_string(&config).map_err(|_| EngineConfigError::Invalid)?;
    if yaml.len() > MAX_CONFIG_BYTES {
        return Err(EngineConfigError::TooLarge);
    }
    Ok(DarwinEngineConfig {
        yaml,
        configured_device: configured_device.into(),
    })
}

fn deduplicate(values: &[String]) -> Vec<&str> {
    let mut seen = BTreeSet::new();
    values
        .iter()
        .filter_map(|value| {
            seen.insert(value.to_ascii_lowercase())
                .then_some(value.as_str())
        })
        .collect()
}

fn valid_process_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 1024
        && !path.contains(',')
        && !path.chars().any(char::is_control)
}

fn valid_process_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_control() && !matches!(byte, b'/' | b'\\' | b','))
}

fn valid_secret(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_utun_name(value: &str) -> bool {
    value.strip_prefix("utun").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.len() <= 4 && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn valid_default_interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value != "lo0"
        && !value.starts_with("utun")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(protocol: UpstreamProtocol) -> StartProfile {
        StartProfile {
            upstream_host: "localhost".into(),
            upstream_port: 7078,
            protocol,
            username: Some("user".into()),
            password: Some("password".into()),
            upstream_process_id: 600,
            bypass_domains: vec!["example.test".into(), "EXAMPLE.test".into()],
            bypass_cidrs: vec!["192.0.2.0/24".into(), "fd00::/8".into()],
            bypass_process_names: vec!["Other.app".into()],
        }
    }

    #[test]
    fn darwin_config_delegates_no_route_and_binds_controller_and_utun() {
        let config = render_darwin_engine_config(
            &profile(UpstreamProtocol::Socks5),
            "Proxy.app",
            &"a".repeat(64),
            "utun7",
            "en0",
        )
        .unwrap();
        let value: serde_yaml::Value = serde_yaml::from_slice(config.as_bytes()).unwrap();
        assert_eq!(value["allow-lan"], false);
        assert_eq!(value["bind-address"], "127.0.0.1");
        assert_eq!(value["external-controller"], CONTROLLER_ADDRESS);
        assert_eq!(value["tun"]["device"], "utun7");
        assert_eq!(value["tun"]["auto-route"], false);
        assert_eq!(value["tun"]["auto-detect-interface"], false);
        assert_eq!(value["tun"]["strict-route"], false);
        assert_eq!(value["tun"]["inet4-address"][0], "198.18.0.1/30");
        assert_eq!(value["tun"]["inet6-address"][0], "fdfe:dcba:9876::1/126");
        assert!(value["dns"].get("listen").is_none());
        assert_eq!(value["dns"]["nameserver"][0], "dhcp://en0");
        assert_eq!(value["proxies"][0]["type"], "socks5");
        assert_eq!(value["proxies"][0]["udp"], true);
        assert_eq!(value["proxies"][1]["type"], "direct");
        assert_eq!(value["proxies"][1]["interface-name"], "en0");
        assert_eq!(config.configured_device(), "utun7");
    }

    #[test]
    fn v3_matches_the_upstream_by_path_never_by_name() {
        use tunbridge_service::protocol::StartUpstreamV3;
        let profile = StartProfileV3 {
            upstream: StartUpstreamV3::LocalListener {
                port: 7897,
                protocol: StandardProtocol::Http,
                credentials: None,
                expected_process_id: 4242,
            },
            traffic_bypass_domains: Vec::new(),
            traffic_bypass_cidrs: Vec::new(),
            traffic_bypass_process_names: vec!["UserBypass".into()],
        };
        let listener = "/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo".to_owned();
        let config = render_darwin_engine_config_v3(
            &profile,
            None,
            Some("verge-mihomo"),
            std::slice::from_ref(&listener),
            &"b".repeat(64),
            "utun9",
            "en0",
        )
        .unwrap();
        let value: serde_yaml::Value = serde_yaml::from_slice(config.as_bytes()).unwrap();
        let rules: Vec<&str> = value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|rule| rule.as_str().unwrap())
            .collect();
        assert!(rules.contains(&"PROCESS-NAME,UserBypass,direct-default"));
        assert!(rules.contains(
            &"PROCESS-PATH,/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo,direct-default"
        ));
        assert!(!rules
            .iter()
            .any(|rule| rule.starts_with("PROCESS-NAME,verge-mihomo")));
    }

    #[test]
    fn rules_are_deduplicated_and_keep_anti_recursion_first() {
        let config = render_darwin_engine_config(
            &profile(UpstreamProtocol::Http),
            "Proxy.app",
            &"b".repeat(64),
            "utun9",
            "en0",
        )
        .unwrap();
        let value: serde_yaml::Value = serde_yaml::from_slice(config.as_bytes()).unwrap();
        let rules: Vec<&str> = value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|rule| rule.as_str().unwrap())
            .collect();
        assert_eq!(rules[0], "PROCESS-NAME,Proxy.app,direct-default");
        assert_eq!(rules.last(), Some(&"MATCH,upstream"));
        assert_eq!(
            rules
                .iter()
                .filter(|rule| **rule == "DOMAIN-SUFFIX,example.test,direct-default")
                .count(),
            1
        );
        assert_eq!(value["proxies"][0]["udp"], false);
    }

    #[test]
    fn invalid_identity_and_debug_output_fail_closed_without_secrets() {
        let secret = "c".repeat(64);
        for (process, device) in [
            ("../proxy", "utun7"),
            ("proxy,REJECT", "utun7"),
            ("Proxy.app", "en0"),
            ("Proxy.app", "utun"),
        ] {
            assert!(matches!(
                render_darwin_engine_config(
                    &profile(UpstreamProtocol::Socks5),
                    process,
                    &secret,
                    device,
                    "en0",
                ),
                Err(EngineConfigError::Invalid)
            ));
        }
        assert_eq!(
            render_darwin_engine_config(
                &profile(UpstreamProtocol::Socks5),
                "Proxy.app",
                &secret,
                "utun7",
                "lo0",
            )
            .unwrap_err(),
            EngineConfigError::Invalid
        );
        let config = render_darwin_engine_config(
            &profile(UpstreamProtocol::Socks5),
            "Proxy.app",
            &secret,
            "utun7",
            "en0",
        )
        .unwrap();
        let debug = format!("{config:?}");
        assert!(!debug.contains(&secret));
        assert!(!debug.contains("password"));
        assert!(debug.contains("[REDACTED]"));
    }
}
