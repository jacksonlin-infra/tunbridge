use serde::{Deserialize, Serialize};
use std::{fmt, net::IpAddr, str::FromStr};
use thiserror::Error;
use zeroize::Zeroize;

pub const SECRET_MATERIAL_SCHEMA_VERSION: u16 = 2;
pub const MAX_ENDPOINT_HOST_BYTES: usize = 253;
pub const MAX_USERNAME_BYTES: usize = 256;
pub const MAX_PASSWORD_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StandardProtocol {
    Socks5,
    Http,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpPreference {
    Ipv4,
    Ipv6,
    Ipv4Prefer,
    Ipv6Prefer,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    pub ip_preference: IpPreference,
}

impl Endpoint {
    pub fn new(
        host: impl Into<String>,
        port: u16,
        ip_preference: IpPreference,
    ) -> Result<Self, UpstreamModelError> {
        let endpoint = Self {
            host: normalize_remote_host(&host.into())?,
            port,
            ip_preference,
        };
        endpoint.validate()?;
        Ok(endpoint)
    }

    pub fn validate(&self) -> Result<(), UpstreamModelError> {
        if self.port == 0 {
            return Err(UpstreamModelError::InvalidPort);
        }
        if normalize_remote_host(&self.host)? != self.host {
            return Err(UpstreamModelError::InvalidHost);
        }
        Ok(())
    }

    pub fn canonicalized(self) -> Result<Self, UpstreamModelError> {
        Self::new(self.host, self.port, self.ip_preference)
    }

    pub fn literal_address(&self) -> Option<IpAddr> {
        IpAddr::from_str(&self.host).ok()
    }
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Endpoint")
            .field("host", &"[REDACTED]")
            .field("port", &self.port)
            .field("ip_preference", &self.ip_preference)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificatePolicy {
    Strict,
    Insecure,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "protocol",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum RemoteProtocolConfig {
    Http {
        tls: bool,
        sni: Option<String>,
        certificate_policy: CertificatePolicy,
    },
    Socks5 {
        tls: bool,
        sni: Option<String>,
        udp: bool,
        certificate_policy: CertificatePolicy,
    },
}

impl RemoteProtocolConfig {
    pub fn validate(&self) -> Result<(), UpstreamModelError> {
        let (tls, sni, certificate_policy) = match self {
            Self::Http {
                tls,
                sni,
                certificate_policy,
            }
            | Self::Socks5 {
                tls,
                sni,
                certificate_policy,
                ..
            } => (*tls, sni, *certificate_policy),
        };

        if !tls && (sni.is_some() || certificate_policy != CertificatePolicy::Strict) {
            return Err(UpstreamModelError::InvalidProtocolConfig);
        }
        if let Some(server_name) = sni {
            if normalize_server_name(server_name)? != *server_name {
                return Err(UpstreamModelError::InvalidProtocolConfig);
            }
        }
        Ok(())
    }

    pub fn canonicalized(mut self) -> Result<Self, UpstreamModelError> {
        match &mut self {
            Self::Http { sni, .. } | Self::Socks5 { sni, .. } => {
                if let Some(server_name) = sni.take() {
                    *sni = Some(normalize_server_name(&server_name)?);
                }
            }
        }
        self.validate()?;
        Ok(self)
    }

    pub const fn standard_protocol(&self) -> StandardProtocol {
        match self {
            Self::Http { .. } => StandardProtocol::Http,
            Self::Socks5 { .. } => StandardProtocol::Socks5,
        }
    }

    pub const fn udp_enabled(&self) -> bool {
        matches!(self, Self::Socks5 { udp: true, .. })
    }

    pub const fn tls_enabled(&self) -> bool {
        match self {
            Self::Http { tls, .. } | Self::Socks5 { tls, .. } => *tls,
        }
    }

    pub fn sni(&self) -> Option<&str> {
        match self {
            Self::Http { sni, .. } | Self::Socks5 { sni, .. } => sni.as_deref(),
        }
    }

    pub const fn certificate_policy(&self) -> CertificatePolicy {
        match self {
            Self::Http {
                certificate_policy, ..
            }
            | Self::Socks5 {
                certificate_policy, ..
            } => *certificate_policy,
        }
    }
}

impl fmt::Debug for RemoteProtocolConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http {
                tls,
                sni,
                certificate_policy,
            } => formatter
                .debug_struct("Http")
                .field("tls", tls)
                .field("sni", &sni.as_ref().map(|_| "[REDACTED]"))
                .field("certificate_policy", certificate_policy)
                .finish(),
            Self::Socks5 {
                tls,
                sni,
                udp,
                certificate_policy,
            } => formatter
                .debug_struct("Socks5")
                .field("tls", tls)
                .field("sni", &sni.as_ref().map(|_| "[REDACTED]"))
                .field("udp", udp)
                .field("certificate_policy", certificate_policy)
                .finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum UpstreamSpec {
    LocalListener {
        port: u16,
        protocol: StandardProtocol,
    },
    RemoteServer {
        endpoint: Endpoint,
        protocol_config: RemoteProtocolConfig,
    },
}

impl UpstreamSpec {
    pub fn validate(&self) -> Result<(), UpstreamModelError> {
        match self {
            Self::LocalListener { port: 0, .. } => Err(UpstreamModelError::InvalidPort),
            Self::LocalListener { .. } => Ok(()),
            Self::RemoteServer {
                endpoint,
                protocol_config,
            } => {
                endpoint.validate()?;
                protocol_config.validate()
            }
        }
    }

    pub const fn standard_protocol(&self) -> StandardProtocol {
        match self {
            Self::LocalListener { protocol, .. } => *protocol,
            Self::RemoteServer {
                protocol_config, ..
            } => protocol_config.standard_protocol(),
        }
    }

    pub const fn port(&self) -> u16 {
        match self {
            Self::LocalListener { port, .. } => *port,
            Self::RemoteServer { endpoint, .. } => endpoint.port,
        }
    }
}

impl fmt::Debug for UpstreamSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalListener { port, protocol } => formatter
                .debug_struct("LocalListener")
                .field("port", port)
                .field("protocol", protocol)
                .finish(),
            Self::RemoteServer {
                endpoint,
                protocol_config,
            } => formatter
                .debug_struct("RemoteServer")
                .field("endpoint", endpoint)
                .field("protocol_config", protocol_config)
                .finish(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretMaterialV2 {
    pub schema_version: u16,
    pub material: SecretMaterial,
}

impl SecretMaterialV2 {
    pub fn basic_auth(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            schema_version: SECRET_MATERIAL_SCHEMA_VERSION,
            material: SecretMaterial::BasicAuth {
                username: username.into(),
                password: password.into(),
            },
        }
    }

    pub fn validate(&self) -> Result<(), UpstreamModelError> {
        if self.schema_version != SECRET_MATERIAL_SCHEMA_VERSION {
            return Err(UpstreamModelError::InvalidSecret);
        }
        self.material.validate()
    }
}

impl fmt::Debug for SecretMaterialV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretMaterialV2")
            .field("schema_version", &self.schema_version)
            .field("material", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecretMaterial {
    BasicAuth { username: String, password: String },
}

impl SecretMaterial {
    pub fn validate(&self) -> Result<(), UpstreamModelError> {
        match self {
            Self::BasicAuth { username, password }
                if valid_secret_text(username, MAX_USERNAME_BYTES)
                    && valid_secret_text(password, MAX_PASSWORD_BYTES) =>
            {
                Ok(())
            }
            Self::BasicAuth { .. } => Err(UpstreamModelError::InvalidSecret),
        }
    }

    pub fn basic_auth(&self) -> (&str, &str) {
        match self {
            Self::BasicAuth { username, password } => (username, password),
        }
    }

    pub fn into_basic_auth(mut self) -> (String, String) {
        match &mut self {
            Self::BasicAuth { username, password } => {
                (std::mem::take(username), std::mem::take(password))
            }
        }
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretMaterial([REDACTED])")
    }
}

impl Drop for SecretMaterial {
    fn drop(&mut self) {
        match self {
            Self::BasicAuth { username, password } => {
                username.zeroize();
                password.zeroize();
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum UpstreamModelError {
    #[error("the upstream host is invalid")]
    InvalidHost,
    #[error("the upstream port is invalid")]
    InvalidPort,
    #[error("the upstream protocol configuration is invalid")]
    InvalidProtocolConfig,
    #[error("the upstream secret material is invalid")]
    InvalidSecret,
}

pub fn normalize_remote_host(value: &str) -> Result<String, UpstreamModelError> {
    if value.is_empty()
        || value.len() > MAX_ENDPOINT_HOST_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || value.contains(['/', '?', '#', '@', '[', ']', '%'])
    {
        return Err(UpstreamModelError::InvalidHost);
    }

    if let Ok(address) = IpAddr::from_str(value) {
        validate_remote_address(address)?;
        return Ok(address.to_string());
    }

    normalize_dns_name(value)
}

fn normalize_server_name(value: &str) -> Result<String, UpstreamModelError> {
    if let Ok(address) = IpAddr::from_str(value) {
        return Ok(address.to_string());
    }
    normalize_dns_name(value)
}

fn normalize_dns_name(value: &str) -> Result<String, UpstreamModelError> {
    let without_dot = value.strip_suffix('.').unwrap_or(value);
    if without_dot.is_empty()
        || without_dot.len() > MAX_ENDPOINT_HOST_BYTES
        || without_dot.eq_ignore_ascii_case("localhost")
        || !without_dot.is_ascii()
    {
        return Err(UpstreamModelError::InvalidHost);
    }

    for label in without_dot.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || !label.as_bytes()[0].is_ascii_alphanumeric()
            || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
        {
            return Err(UpstreamModelError::InvalidHost);
        }
    }
    Ok(without_dot.to_ascii_lowercase())
}

fn validate_remote_address(address: IpAddr) -> Result<(), UpstreamModelError> {
    let rejected = match address {
        IpAddr::V4(address) => {
            address.is_unspecified()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_multicast()
                || address.is_broadcast()
        }
        IpAddr::V6(address) => {
            address.is_unspecified()
                || address.is_loopback()
                || address.is_multicast()
                || address.is_unicast_link_local()
                || address.to_ipv4_mapped().is_some()
        }
    };
    if rejected {
        Err(UpstreamModelError::InvalidHost)
    } else {
        Ok(())
    }
}

fn valid_secret_text(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= maximum_bytes && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(host: &str) -> UpstreamSpec {
        UpstreamSpec::RemoteServer {
            endpoint: Endpoint::new(host, 1080, IpPreference::Ipv4Prefer).unwrap(),
            protocol_config: RemoteProtocolConfig::Socks5 {
                tls: false,
                sni: None,
                udp: true,
                certificate_policy: CertificatePolicy::Strict,
            },
        }
    }

    #[test]
    fn upstream_accepts_lan_public_and_canonical_dns_without_network_access() {
        for host in ["192.168.10.2", "8.8.8.8", "proxy.example.com"] {
            remote(host).validate().unwrap();
        }
        assert_eq!(
            Endpoint::new("Proxy.Example.COM.", 443, IpPreference::Ipv4Prefer)
                .unwrap()
                .host,
            "proxy.example.com"
        );
    }

    #[test]
    fn upstream_rejects_local_special_and_url_inputs() {
        for host in [
            "localhost",
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "169.254.1.2",
            "224.0.0.1",
            "http://proxy.example.com",
            "user@proxy.example.com",
            "[2001:db8::1]",
            "proxy.example.com:1080",
        ] {
            assert!(
                Endpoint::new(host, 1080, IpPreference::Ipv4Prefer).is_err(),
                "{host}"
            );
        }
    }

    #[test]
    fn tls_fields_are_strict_and_protocol_specific() {
        RemoteProtocolConfig::Http {
            tls: true,
            sni: Some("proxy.example.com".into()),
            certificate_policy: CertificatePolicy::Strict,
        }
        .validate()
        .unwrap();

        assert!(RemoteProtocolConfig::Socks5 {
            tls: false,
            sni: Some("proxy.example.com".into()),
            udp: false,
            certificate_policy: CertificatePolicy::Strict,
        }
        .validate()
        .is_err());
        assert!(RemoteProtocolConfig::Http {
            tls: false,
            sni: None,
            certificate_policy: CertificatePolicy::Insecure,
        }
        .validate()
        .is_err());
    }

    #[test]
    fn strict_schema_and_debug_output_do_not_expose_endpoint_or_secrets() {
        let upstream = remote("secret-proxy.example.com");
        let debug = format!("{upstream:?}");
        assert!(!debug.contains("secret-proxy.example.com"));
        assert!(debug.contains("[REDACTED]"));

        let secret = SecretMaterialV2::basic_auth("private-user", "private-password");
        secret.validate().unwrap();
        let debug = format!("{secret:?}");
        assert!(!debug.contains("private-user"));
        assert!(!debug.contains("private-password"));

        let mut value = serde_json::to_value(upstream).unwrap();
        value["route"] = serde_json::json!("default");
        assert!(serde_json::from_value::<UpstreamSpec>(value).is_err());
    }

    #[test]
    fn deserialized_values_require_explicit_validation() {
        let invalid: Endpoint = serde_json::from_value(serde_json::json!({
            "host": "127.0.0.1",
            "port": 1080,
            "ipPreference": "ipv4_prefer"
        }))
        .unwrap();
        assert_eq!(invalid.validate(), Err(UpstreamModelError::InvalidHost));
    }
}
