use crate::profile::Profile;
use crate::upstream::{
    normalize_remote_host, CertificatePolicy, RemoteProtocolConfig, SecretMaterialV2,
    StandardProtocol,
};
use crate::{CoreError, Result};
use serde::Serialize;
use std::{fmt, net::IpAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportEscape {
    EngineRouteExclude,
    PlatformOwned,
}

pub struct ResolvedRemoteUpstream<'a> {
    pub pinned_server: IpAddr,
    pub port: u16,
    pub protocol_config: &'a RemoteProtocolConfig,
    pub secret_material: Option<&'a SecretMaterialV2>,
    pub transport_escape: TransportEscape,
}

impl ResolvedRemoteUpstream<'_> {
    pub fn validate(&self) -> Result<()> {
        if self.port == 0 {
            return Err(CoreError::Config("the upstream port is invalid".into()));
        }
        normalize_remote_host(&self.pinned_server.to_string())
            .map_err(|error| CoreError::Config(error.to_string()))?;
        self.protocol_config
            .validate()
            .map_err(|error| CoreError::Config(error.to_string()))?;
        if let Some(secret) = self.secret_material {
            secret
                .validate()
                .map_err(|error| CoreError::Config(error.to_string()))?;
        }
        Ok(())
    }
}

impl fmt::Debug for ResolvedRemoteUpstream<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedRemoteUpstream")
            .field("pinned_server", &"[REDACTED]")
            .field("port", &self.port)
            .field("protocol_config", &self.protocol_config)
            .field("has_secret_material", &self.secret_material.is_some())
            .field("transport_escape", &self.transport_escape)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum RemoteProxyEntry<'a> {
    Http {
        name: &'static str,
        server: String,
        port: u16,
        tls: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        sni: Option<&'a str>,
        #[serde(rename = "skip-cert-verify")]
        skip_cert_verify: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        username: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<&'a str>,
    },
    Socks5 {
        name: &'static str,
        server: String,
        port: u16,
        udp: bool,
        tls: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        sni: Option<&'a str>,
        #[serde(rename = "skip-cert-verify")]
        skip_cert_verify: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        username: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        password: Option<&'a str>,
    },
}

#[derive(Serialize)]
struct RemoteDns {
    enable: bool,
    listen: String,
    #[serde(rename = "enhanced-mode")]
    enhanced_mode: &'static str,
    #[serde(rename = "fake-ip-range")]
    fake_ip_range: &'static str,
    #[serde(rename = "fake-ip-filter")]
    fake_ip_filter: Vec<&'static str>,
    nameserver: Vec<&'static str>,
}

#[derive(Serialize)]
struct RemoteTun {
    enable: bool,
    device: String,
    stack: &'static str,
    #[serde(rename = "dns-hijack")]
    dns_hijack: Vec<&'static str>,
    #[serde(rename = "auto-route")]
    auto_route: bool,
    #[serde(rename = "auto-detect-interface")]
    auto_detect_interface: bool,
    #[serde(rename = "strict-route")]
    strict_route: bool,
    #[serde(
        rename = "route-exclude-address",
        skip_serializing_if = "Vec::is_empty"
    )]
    route_exclude_address: Vec<String>,
}

#[derive(Serialize)]
struct RemoteMihomoConfig<'a> {
    #[serde(rename = "mixed-port")]
    mixed_port: u16,
    #[serde(rename = "bind-address")]
    bind_address: &'static str,
    #[serde(rename = "allow-lan")]
    allow_lan: bool,
    mode: &'static str,
    #[serde(rename = "log-level")]
    log_level: &'static str,
    #[serde(rename = "external-controller")]
    external_controller: String,
    secret: String,
    dns: RemoteDns,
    tun: RemoteTun,
    proxies: Vec<RemoteProxyEntry<'a>>,
    rules: Vec<String>,
}

pub fn render_remote(profile: &Profile, upstream: &ResolvedRemoteUpstream<'_>) -> Result<String> {
    upstream.validate()?;
    let (username, password) = upstream
        .secret_material
        .map(|material| material.material.basic_auth())
        .map_or((None, None), |(username, password)| {
            (Some(username), Some(password))
        });
    let skip_cert_verify =
        upstream.protocol_config.certificate_policy() == CertificatePolicy::Insecure;
    let server = upstream.pinned_server.to_string();
    let proxy = match upstream.protocol_config.standard_protocol() {
        StandardProtocol::Http => RemoteProxyEntry::Http {
            name: "upstream",
            server,
            port: upstream.port,
            tls: upstream.protocol_config.tls_enabled(),
            sni: upstream.protocol_config.sni(),
            skip_cert_verify,
            username,
            password,
        },
        StandardProtocol::Socks5 => RemoteProxyEntry::Socks5 {
            name: "upstream",
            server,
            port: upstream.port,
            udp: upstream.protocol_config.udp_enabled(),
            tls: upstream.protocol_config.tls_enabled(),
            sni: upstream.protocol_config.sni(),
            skip_cert_verify,
            username,
            password,
        },
    };

    let route_exclude_address = match upstream.transport_escape {
        TransportEscape::EngineRouteExclude => vec![match upstream.pinned_server {
            IpAddr::V4(address) => format!("{address}/32"),
            IpAddr::V6(address) => format!("{address}/128"),
        }],
        TransportEscape::PlatformOwned => Vec::new(),
    };
    let config = RemoteMihomoConfig {
        mixed_port: profile.mixed_port,
        bind_address: "127.0.0.1",
        allow_lan: false,
        mode: "rule",
        log_level: "info",
        external_controller: profile.external_controller.clone(),
        secret: profile.secret.clone(),
        dns: RemoteDns {
            enable: true,
            listen: profile.dns_listen.clone(),
            enhanced_mode: "fake-ip",
            fake_ip_range: "198.18.0.0/15",
            fake_ip_filter: vec!["+.msftconnecttest.com", "+.msftncsi.com", "+.local"],
            nameserver: vec!["223.5.5.5", "1.1.1.1"],
        },
        tun: RemoteTun {
            enable: true,
            device: profile.tun_device.clone(),
            stack: "gvisor",
            dns_hijack: vec!["any:53"],
            auto_route: true,
            auto_detect_interface: true,
            strict_route: profile.strict_route,
            route_exclude_address,
        },
        proxies: vec![proxy],
        rules: rules(profile, upstream.protocol_config.udp_enabled()),
    };
    serde_yaml::to_string(&config).map_err(|error| CoreError::Config(error.to_string()))
}

fn rules(profile: &Profile, udp_enabled: bool) -> Vec<String> {
    let mut rules = Vec::new();
    for path in &profile.exclude_process_paths {
        rules.push(format!("PROCESS-PATH,{path},DIRECT"));
    }
    for process in &profile.exclude_processes {
        rules.push(format!("PROCESS-NAME,{process},DIRECT"));
    }
    for address in &profile.doh_reject_ips {
        rules.push(format!("IP-CIDR,{address}/32,REJECT,no-resolve"));
    }
    for cidr in &profile.bypass_cidrs {
        let kind = if cidr.contains(':') {
            "IP-CIDR6"
        } else {
            "IP-CIDR"
        };
        rules.push(format!("{kind},{cidr},DIRECT,no-resolve"));
    }
    for domain in &profile.bypass_domains {
        rules.push(format!("DOMAIN-SUFFIX,{domain},DIRECT"));
    }
    if udp_enabled {
        rules.push("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT".into());
    } else {
        rules.push("NETWORK,UDP,REJECT".into());
    }
    rules.push("MATCH,upstream".into());
    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{Protocol, Upstream};
    use crate::upstream::{CertificatePolicy, SecretMaterialV2};
    use std::net::{IpAddr, Ipv4Addr};

    fn base(port: u16) -> Profile {
        Profile::with_upstream(Upstream {
            host: "127.0.0.1".into(),
            port,
            protocol: Protocol::Http,
            username: None,
            password: None,
            udp: false,
        })
    }

    #[test]
    fn https_uses_pinned_ip_and_keeps_sni_separate() {
        let profile = base(8443);
        let protocol = RemoteProtocolConfig::Http {
            tls: true,
            sni: Some("proxy.example.com".into()),
            certificate_policy: CertificatePolicy::Strict,
        };
        let upstream = ResolvedRemoteUpstream {
            pinned_server: IpAddr::V4(Ipv4Addr::new(192, 168, 50, 4)),
            port: 8443,
            protocol_config: &protocol,
            secret_material: None,
            transport_escape: TransportEscape::EngineRouteExclude,
        };
        let yaml = render_remote(&profile, &upstream).unwrap();
        let value: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let proxy = &value["proxies"][0];
        assert_eq!(proxy["server"], "192.168.50.4");
        assert_eq!(proxy["sni"], "proxy.example.com");
        assert_eq!(proxy["tls"], true);
        assert_eq!(proxy["skip-cert-verify"], false);
        assert_eq!(value["tun"]["route-exclude-address"][0], "192.168.50.4/32");
    }

    #[test]
    fn socks5_is_typed_and_platform_owned_escape_omits_engine_route() {
        let profile = base(1080);
        let protocol = RemoteProtocolConfig::Socks5 {
            tls: false,
            sni: None,
            udp: true,
            certificate_policy: CertificatePolicy::Strict,
        };
        let secret = SecretMaterialV2::basic_auth("private-user", "private-password");
        let upstream = ResolvedRemoteUpstream {
            pinned_server: "8.8.8.8".parse().unwrap(),
            port: 1080,
            protocol_config: &protocol,
            secret_material: Some(&secret),
            transport_escape: TransportEscape::PlatformOwned,
        };
        let yaml = render_remote(&profile, &upstream).unwrap();
        let value: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let proxy = &value["proxies"][0];
        assert_eq!(proxy["type"], "socks5");
        assert_eq!(proxy["udp"], true);
        let rules: Vec<&str> = value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|rule| rule.as_str().unwrap())
            .collect();
        assert_eq!(
            rules[rules.len() - 2],
            "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"
        );
        assert_eq!(rules.last(), Some(&"MATCH,upstream"));
        assert_eq!(proxy["username"], "private-user");
        assert_eq!(proxy["password"], "private-password");
        assert!(value["tun"].get("route-exclude-address").is_none());
        assert!(value.get("proxy-providers").is_none());
        assert!(value.get("script").is_none());

        let debug = format!("{upstream:?}");
        assert!(!debug.contains("8.8.8.8"));
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("private-password"));
    }

    #[test]
    fn invalid_pinned_addresses_fail_before_yaml_rendering() {
        let profile = base(8080);
        let protocol = RemoteProtocolConfig::Http {
            tls: false,
            sni: None,
            certificate_policy: CertificatePolicy::Strict,
        };
        let upstream = ResolvedRemoteUpstream {
            pinned_server: "127.0.0.1".parse().unwrap(),
            port: 8080,
            protocol_config: &protocol,
            secret_material: None,
            transport_escape: TransportEscape::EngineRouteExclude,
        };
        assert!(render_remote(&profile, &upstream).is_err());
    }

    #[test]
    fn remote_http_rejects_udp_before_final_match() {
        let profile = base(8080);
        let protocol = RemoteProtocolConfig::Http {
            tls: false,
            sni: None,
            certificate_policy: CertificatePolicy::Strict,
        };
        let upstream = ResolvedRemoteUpstream {
            pinned_server: "192.0.2.10".parse().unwrap(),
            port: 8080,
            protocol_config: &protocol,
            secret_material: None,
            transport_escape: TransportEscape::EngineRouteExclude,
        };
        let yaml = render_remote(&profile, &upstream).unwrap();
        let value: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let rules: Vec<&str> = value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|rule| rule.as_str().unwrap())
            .collect();
        assert_eq!(rules[rules.len() - 2], "NETWORK,UDP,REJECT");
        assert_eq!(rules.last(), Some(&"MATCH,upstream"));
    }
}
