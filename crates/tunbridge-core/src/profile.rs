use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr};
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Socks5,
    Http,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Upstream {
    pub host: String,
    pub port: u16,
    pub protocol: Protocol,
    pub username: Option<String>,
    pub password: Option<String>,
    pub udp: bool,
}

impl fmt::Debug for Upstream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Upstream")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("protocol", &self.protocol)
            .field("username", &self.username.as_ref().map(|_| "[REDACTED]"))
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("udp", &self.udp)
            .finish()
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        if let Some(username) = self.username.as_mut() {
            username.zeroize();
        }
        if let Some(password) = self.password.as_mut() {
            password.zeroize();
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Profile {
    pub upstream: Upstream,
    /// Exact executables that go DIRECT (the verified upstream listener).
    /// A full path, unlike a name, cannot be borrowed by another program.
    pub exclude_process_paths: Vec<String>,
    pub exclude_processes: Vec<String>,
    pub route_exclude_addresses: Vec<IpAddr>,
    pub bypass_cidrs: Vec<String>,
    pub bypass_domains: Vec<String>,
    pub tun_device: String,
    pub dns_listen: String,
    pub external_controller: String,
    pub secret: String,
    pub mixed_port: u16,
    pub strict_route: bool,
    pub doh_reject_ips: Vec<String>,
    /// Source addresses whose TUN flows go DIRECT before any other rule.
    /// Linux uses one fixed address for fake-IP flows of the escaped local
    /// upstream so its own connections never depend on the upstream.
    pub direct_source_cidrs: Vec<String>,
}

impl fmt::Debug for Profile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Profile")
            .field("upstream", &self.upstream)
            .field("exclude_process_paths", &self.exclude_process_paths)
            .field("exclude_processes", &self.exclude_processes)
            .field(
                "route_exclude_addresses",
                &self
                    .route_exclude_addresses
                    .iter()
                    .map(|_| "[REDACTED]")
                    .collect::<Vec<_>>(),
            )
            .field("bypass_cidrs", &self.bypass_cidrs)
            .field("bypass_domains", &self.bypass_domains)
            .field("tun_device", &self.tun_device)
            .field("dns_listen", &self.dns_listen)
            .field("external_controller", &self.external_controller)
            .field("secret", &"[REDACTED]")
            .field("mixed_port", &self.mixed_port)
            .field("strict_route", &self.strict_route)
            .field("doh_reject_ips", &self.doh_reject_ips)
            .field("direct_source_cidrs", &self.direct_source_cidrs)
            .finish()
    }
}

impl Profile {
    /// Build a profile with the validated defaults applied.
    pub fn with_upstream(upstream: Upstream) -> Self {
        Profile {
            upstream,
            exclude_process_paths: Vec::new(),
            exclude_processes: Vec::new(),
            route_exclude_addresses: Vec::new(),
            bypass_cidrs: vec![
                "192.168.0.0/16".into(),
                "10.0.0.0/8".into(),
                "172.16.0.0/12".into(),
                "169.254.0.0/16".into(),
                "224.0.0.0/4".into(),
            ],
            bypass_domains: Vec::new(),
            tun_device: "tunbridge".into(),
            dns_listen: "127.0.0.1:25363".into(),
            external_controller: "127.0.0.1:25412".into(),
            secret: String::new(),
            mixed_port: 25411,
            // strict-route is OFF by default (DoH storm risk).
            strict_route: false,
            // Fast-fail known public DoH endpoints so the OS falls
            // back to UDP:53, which dns-hijack then captures.
            doh_reject_ips: vec![
                "223.5.5.5".into(),
                "223.6.6.6".into(),
                "120.53.53.53".into(),
                "1.1.1.1".into(),
                "8.8.8.8".into(),
            ],
            direct_source_cidrs: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_debug_redacts_credentials() {
        let upstream = Upstream {
            host: "127.0.0.1".into(),
            port: 7078,
            protocol: Protocol::Socks5,
            username: Some("private-user".into()),
            password: Some("private-password".into()),
            udp: false,
        };

        let debug = format!("{upstream:?}");
        assert!(debug.contains("127.0.0.1"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("private-password"));
    }

    #[test]
    fn profile_debug_redacts_upstream_credentials_and_controller_secret() {
        let mut profile = Profile::with_upstream(Upstream {
            host: "127.0.0.1".into(),
            port: 7078,
            protocol: Protocol::Http,
            username: Some("private-user".into()),
            password: Some("private-password".into()),
            udp: false,
        });
        profile.secret = "private-controller-secret".into();
        profile.route_exclude_addresses = vec!["203.0.113.42".parse().unwrap()];

        let debug = format!("{profile:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("private-password"));
        assert!(!debug.contains("private-controller-secret"));
        assert!(!debug.contains("203.0.113.42"));
    }
}
