use crate::profile::{Profile, Protocol};
use crate::{CoreError, Result};
use serde::Serialize;
use std::net::IpAddr;

#[derive(Serialize)]
struct ProxyEntry {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    server: String,
    port: u16,
    udp: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
}

#[derive(Serialize)]
struct Dns {
    enable: bool,
    listen: String,
    #[serde(rename = "enhanced-mode")]
    enhanced_mode: String,
    #[serde(rename = "fake-ip-range")]
    fake_ip_range: String,
    #[serde(rename = "fake-ip-filter")]
    fake_ip_filter: Vec<String>,
    nameserver: Vec<String>,
}

#[derive(Serialize)]
struct Tun {
    enable: bool,
    device: String,
    stack: String,
    #[serde(rename = "dns-hijack")]
    dns_hijack: Vec<String>,
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
struct MihomoConfig {
    #[serde(rename = "mixed-port")]
    mixed_port: u16,
    #[serde(rename = "bind-address")]
    bind_address: String,
    #[serde(rename = "allow-lan")]
    allow_lan: bool,
    mode: String,
    #[serde(rename = "log-level")]
    log_level: String,
    #[serde(rename = "external-controller")]
    external_controller: String,
    secret: String,
    dns: Dns,
    tun: Tun,
    proxies: Vec<ProxyEntry>,
    rules: Vec<String>,
}

/// Render a mihomo yaml configuration from a Profile. Rule order is fixed:
/// excluded processes (anti-recursion) -> DoH REJECT -> bypass CIDRs -> bypass
/// domains -> UDP leak guard -> final MATCH to the upstream.
pub fn render(profile: &Profile) -> Result<String> {
    let kind = match profile.upstream.protocol {
        Protocol::Socks5 => "socks5",
        Protocol::Http => "http",
    };

    let mut rules: Vec<String> = Vec::new();
    for cidr in &profile.direct_source_cidrs {
        rules.push(format!("SRC-IP-CIDR,{cidr},DIRECT"));
    }
    for p in &profile.exclude_process_paths {
        rules.push(format!("PROCESS-PATH,{p},DIRECT"));
    }
    for p in &profile.exclude_processes {
        rules.push(format!("PROCESS-NAME,{p},DIRECT"));
    }
    for ip in &profile.doh_reject_ips {
        rules.push(format!("IP-CIDR,{ip}/32,REJECT,no-resolve"));
    }
    for cidr in &profile.bypass_cidrs {
        let kind = if cidr.contains(':') {
            "IP-CIDR6"
        } else {
            "IP-CIDR"
        };
        rules.push(format!("{kind},{cidr},DIRECT,no-resolve"));
    }
    for d in &profile.bypass_domains {
        rules.push(format!("DOMAIN-SUFFIX,{d},DIRECT"));
    }
    if profile.upstream.udp {
        // QUIC must fail closed and fall back to TCP. A local SOCKS5 endpoint
        // can accept UDP ASSOCIATE while its owning client still sends the
        // resulting UDP datagrams directly, outside TunBridge's control.
        rules.push("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT".into());
    } else {
        // Mihomo continues rule matching when the selected proxy cannot carry
        // UDP. With MATCH as the final rule that can otherwise become a direct
        // escape, so unsupported UDP is rejected explicitly.
        rules.push("NETWORK,UDP,REJECT".into());
    }
    rules.push("MATCH,upstream".into());

    let cfg = MihomoConfig {
        mixed_port: profile.mixed_port,
        bind_address: "127.0.0.1".into(),
        allow_lan: false,
        mode: "rule".into(),
        log_level: "info".into(),
        external_controller: profile.external_controller.clone(),
        secret: profile.secret.clone(),
        dns: Dns {
            enable: true,
            listen: profile.dns_listen.clone(),
            enhanced_mode: "fake-ip".into(),
            fake_ip_range: "198.18.0.0/15".into(),
            fake_ip_filter: vec![
                "+.msftconnecttest.com".into(),
                "+.msftncsi.com".into(),
                "+.local".into(),
            ],
            nameserver: vec!["223.5.5.5".into(), "1.1.1.1".into()],
        },
        tun: Tun {
            enable: true,
            device: profile.tun_device.clone(),
            stack: "gvisor".into(),
            dns_hijack: vec!["any:53".into()],
            auto_route: true,
            auto_detect_interface: true,
            strict_route: profile.strict_route,
            route_exclude_address: profile
                .route_exclude_addresses
                .iter()
                .map(|address| match address {
                    IpAddr::V4(address) => format!("{address}/32"),
                    IpAddr::V6(address) => format!("{address}/128"),
                })
                .collect(),
        },
        proxies: vec![ProxyEntry {
            name: "upstream".into(),
            kind: kind.into(),
            server: profile.upstream.host.clone(),
            port: profile.upstream.port,
            udp: profile.upstream.udp,
            username: profile.upstream.username.clone(),
            password: profile.upstream.password.clone(),
        }],
        rules,
    };

    serde_yaml::to_string(&cfg).map_err(|e| CoreError::Config(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{Profile, Protocol, Upstream};

    fn sample() -> Profile {
        Profile::with_upstream(Upstream {
            host: "127.0.0.1".into(),
            port: 7078,
            protocol: Protocol::Socks5,
            username: None,
            password: None,
            udp: true,
        })
    }

    #[test]
    fn render_encodes_m0_verdicts() {
        let mut p = sample();
        p.exclude_processes = vec!["ExampleProxy_Mix.bin".into()];
        let yaml = render(&p).unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(v["tun"]["strict-route"], serde_yaml::Value::Bool(false));
        assert_eq!(v["tun"]["auto-route"], serde_yaml::Value::Bool(true));
        assert_eq!(
            v["tun"]["auto-detect-interface"],
            serde_yaml::Value::Bool(true)
        );
        assert_eq!(
            v["dns"]["enhanced-mode"],
            serde_yaml::Value::String("fake-ip".into())
        );
        let rules = v["rules"].as_sequence().unwrap();
        let text: Vec<String> = rules
            .iter()
            .map(|r| r.as_str().unwrap().to_string())
            .collect();
        assert!(text.contains(&"PROCESS-NAME,ExampleProxy_Mix.bin,DIRECT".to_string()));
        assert!(text.iter().any(|r| r == "MATCH,upstream"));
        assert!(text
            .iter()
            .any(|r| r == "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"));
        assert!(text
            .iter()
            .any(|r| r.contains("223.5.5.5/32") && r.ends_with("REJECT,no-resolve")));
        let proxies = v["proxies"].as_sequence().unwrap();
        assert_eq!(
            proxies[0]["type"],
            serde_yaml::Value::String("socks5".into())
        );
        assert_eq!(proxies[0]["port"], serde_yaml::Value::Number(7078.into()));
    }

    #[test]
    fn rules_are_ordered_exclude_reject_bypass_match() {
        let mut p = sample();
        p.exclude_processes = vec!["client.exe".into()];
        p.bypass_cidrs.push("fd00::/8".into());
        let yaml = render(&p).unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let rules: Vec<String> = v["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap().to_string())
            .collect();
        let process_idx = rules
            .iter()
            .position(|r| r.starts_with("PROCESS-NAME"))
            .unwrap();
        let reject_idx = rules
            .iter()
            .position(|r| r.ends_with("REJECT,no-resolve"))
            .unwrap();
        let match_idx = rules.iter().position(|r| r == "MATCH,upstream").unwrap();
        let quic_reject_idx = rules
            .iter()
            .position(|r| r == "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT")
            .unwrap();
        assert!(process_idx < reject_idx, "exclude before reject");
        assert!(reject_idx < match_idx, "reject before final match");
        assert!(
            quic_reject_idx < match_idx,
            "QUIC reject before final match"
        );
        assert!(rules
            .iter()
            .any(|rule| rule == "IP-CIDR6,fd00::/8,DIRECT,no-resolve"));
        assert_eq!(match_idx, rules.len() - 1, "MATCH is last");
    }

    #[test]
    fn unsupported_udp_is_rejected_before_final_match() {
        let mut profile = sample();
        profile.upstream.protocol = Protocol::Http;
        profile.upstream.udp = false;
        let yaml = render(&profile).unwrap();
        let value: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let rules: Vec<&str> = value["rules"]
            .as_sequence()
            .unwrap()
            .iter()
            .map(|rule| rule.as_str().unwrap())
            .collect();
        assert_eq!(rules[rules.len() - 2], "NETWORK,UDP,REJECT");
        assert_eq!(rules.last(), Some(&"MATCH,upstream"));
        assert!(!rules.contains(&"AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"));
    }

    #[test]
    fn direct_source_rules_precede_every_other_rule() {
        let mut p = sample();
        assert!(!render(&p).unwrap().contains("SRC-IP-CIDR"));
        p.direct_source_cidrs = vec!["192.0.0.8/32".into()];
        let yaml = render(&p).unwrap();
        let v: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let rules = v["rules"].as_sequence().unwrap();
        assert_eq!(rules[0].as_str(), Some("SRC-IP-CIDR,192.0.0.8/32,DIRECT"));
        assert_eq!(rules.last().unwrap().as_str(), Some("MATCH,upstream"));
    }

    #[test]
    fn transport_escape_addresses_render_as_exact_tun_routes() {
        let mut profile = sample();
        profile.route_exclude_addresses = vec![
            "203.0.113.8".parse().unwrap(),
            "2001:db8::8".parse().unwrap(),
        ];
        let yaml = render(&profile).unwrap();
        let value: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(value["tun"]["route-exclude-address"][0], "203.0.113.8/32");
        assert_eq!(value["tun"]["route-exclude-address"][1], "2001:db8::8/128");
    }
}
