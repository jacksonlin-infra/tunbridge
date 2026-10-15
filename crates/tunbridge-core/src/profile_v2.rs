use crate::upstream::{Endpoint, RemoteProtocolConfig, StandardProtocol};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;

pub const PROFILE_SCHEMA_VERSION_V1: u16 = 1;
pub const PROFILE_SCHEMA_VERSION_V2: u16 = 2;
pub const MAX_PROFILES: usize = 64;
pub const MAX_PROFILE_STORE_BYTES: usize = 64 * 1024;
pub const MAX_DISPLAY_NAME_BYTES: usize = 64;
pub const IDENTIFIER_HEX_BYTES: usize = 32;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileStoreV2 {
    pub schema_version: u16,
    pub store_revision: u64,
    pub profiles: Vec<StoredProfileV2>,
}

impl Default for ProfileStoreV2 {
    fn default() -> Self {
        Self {
            schema_version: PROFILE_SCHEMA_VERSION_V2,
            store_revision: 0,
            profiles: Vec::new(),
        }
    }
}

impl ProfileStoreV2 {
    pub fn validate(&self) -> Result<(), ProfileV2Error> {
        if self.schema_version != PROFILE_SCHEMA_VERSION_V2 || self.profiles.len() > MAX_PROFILES {
            return Err(ProfileV2Error::InvalidStore);
        }
        let mut previous_id: Option<&str> = None;
        for profile in &self.profiles {
            profile.validate()?;
            if previous_id.is_some_and(|previous| previous >= profile.profile_id.as_str()) {
                return Err(ProfileV2Error::InvalidStore);
            }
            previous_id = Some(&profile.profile_id);
        }
        let bytes = serde_json::to_vec(self).map_err(|_| ProfileV2Error::InvalidStore)?;
        if bytes.len() > MAX_PROFILE_STORE_BYTES {
            return Err(ProfileV2Error::InvalidStore);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProfileV2Error> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| ProfileV2Error::InvalidStore)
    }

    pub fn sha256(&self) -> Result<String, ProfileV2Error> {
        let digest = Sha256::digest(self.canonical_bytes()?);
        Ok(lower_hex(&digest))
    }

    pub fn public_view(&self) -> ProfileListV2 {
        ProfileListV2 {
            schema_version: PROFILE_SCHEMA_VERSION_V2,
            store_revision: self.store_revision,
            profiles: self
                .profiles
                .iter()
                .map(|profile| PublicProfileV2 {
                    profile_id: profile.profile_id.clone(),
                    display_name: profile.display_name.clone(),
                    upstream: profile.upstream.public_view(),
                    has_credential: profile.upstream.secret_generation().is_some(),
                })
                .collect(),
        }
    }
}

impl fmt::Debug for ProfileStoreV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProfileStoreV2")
            .field("schema_version", &self.schema_version)
            .field("store_revision", &self.store_revision)
            .field("profile_count", &self.profiles.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StoredProfileV2 {
    pub profile_id: String,
    pub display_name: String,
    pub upstream: StoredUpstreamV2,
}

impl StoredProfileV2 {
    pub fn validate(&self) -> Result<(), ProfileV2Error> {
        if !valid_identifier(&self.profile_id) || !valid_display_name(&self.display_name) {
            return Err(ProfileV2Error::InvalidStore);
        }
        self.upstream.validate()
    }
}

impl fmt::Debug for StoredProfileV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredProfileV2")
            .field("profile_id", &"[REDACTED]")
            .field("display_name", &self.display_name)
            .field("upstream", &self.upstream)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum StoredUpstreamV2 {
    LocalListener {
        port: u16,
        protocol: StandardProtocol,
        credential_generation: Option<String>,
    },
    RemoteServer {
        endpoint: Endpoint,
        protocol_config: RemoteProtocolConfig,
        secret_generation: Option<String>,
    },
}

impl StoredUpstreamV2 {
    pub fn validate(&self) -> Result<(), ProfileV2Error> {
        match self {
            Self::LocalListener {
                port,
                credential_generation,
                ..
            } => {
                if *port == 0
                    || credential_generation
                        .as_deref()
                        .is_some_and(|value| !valid_identifier(value))
                {
                    return Err(ProfileV2Error::InvalidStore);
                }
                Ok(())
            }
            Self::RemoteServer {
                endpoint,
                protocol_config,
                secret_generation,
            } => {
                endpoint
                    .validate()
                    .map_err(|_| ProfileV2Error::InvalidStore)?;
                protocol_config
                    .validate()
                    .map_err(|_| ProfileV2Error::InvalidStore)?;
                if secret_generation
                    .as_deref()
                    .is_some_and(|value| !valid_identifier(value))
                {
                    return Err(ProfileV2Error::InvalidStore);
                }
                Ok(())
            }
        }
    }

    pub fn secret_generation(&self) -> Option<&str> {
        match self {
            Self::LocalListener {
                credential_generation,
                ..
            } => credential_generation.as_deref(),
            Self::RemoteServer {
                secret_generation, ..
            } => secret_generation.as_deref(),
        }
    }

    pub fn public_view(&self) -> PublicUpstreamV2 {
        match self {
            Self::LocalListener { port, protocol, .. } => PublicUpstreamV2::LocalListener {
                port: *port,
                protocol: *protocol,
            },
            Self::RemoteServer {
                endpoint,
                protocol_config,
                ..
            } => PublicUpstreamV2::RemoteServer {
                endpoint: endpoint.clone(),
                protocol_config: protocol_config.clone(),
            },
        }
    }
}

impl fmt::Debug for StoredUpstreamV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalListener { port, protocol, .. } => formatter
                .debug_struct("LocalListener")
                .field("port", port)
                .field("protocol", protocol)
                .field("has_credential", &self.secret_generation().is_some())
                .finish(),
            Self::RemoteServer {
                endpoint,
                protocol_config,
                ..
            } => formatter
                .debug_struct("RemoteServer")
                .field("endpoint", endpoint)
                .field("protocol_config", protocol_config)
                .field("has_secret", &self.secret_generation().is_some())
                .finish(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileListV2 {
    pub schema_version: u16,
    pub store_revision: u64,
    pub profiles: Vec<PublicProfileV2>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicProfileV2 {
    pub profile_id: String,
    pub display_name: String,
    pub upstream: PublicUpstreamV2,
    pub has_credential: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum PublicUpstreamV2 {
    LocalListener {
        port: u16,
        protocol: StandardProtocol,
    },
    RemoteServer {
        endpoint: Endpoint,
        protocol_config: RemoteProtocolConfig,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileMigrationV1ToV2 {
    pub store: ProfileStoreV2,
    pub credential_references: Vec<CredentialReference>,
    pub source_sha256: String,
    pub target_sha256: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct CredentialReference {
    pub profile_id: String,
    pub generation: String,
}

impl fmt::Debug for CredentialReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialReference([REDACTED])")
    }
}

pub fn parse_v2(bytes: &[u8]) -> Result<ProfileStoreV2, ProfileV2Error> {
    if bytes.len() > MAX_PROFILE_STORE_BYTES {
        return Err(ProfileV2Error::InvalidStore);
    }
    let store: ProfileStoreV2 =
        serde_json::from_slice(bytes).map_err(|_| ProfileV2Error::InvalidStore)?;
    store.validate()?;
    Ok(store)
}

pub fn migrate_v1(bytes: &[u8]) -> Result<ProfileMigrationV1ToV2, ProfileV2Error> {
    if bytes.len() > MAX_PROFILE_STORE_BYTES {
        return Err(ProfileV2Error::InvalidLegacyStore);
    }
    let legacy: ProfileStoreV1 =
        serde_json::from_slice(bytes).map_err(|_| ProfileV2Error::InvalidLegacyStore)?;
    legacy.validate()?;

    let mut credential_references = Vec::new();
    let profiles = legacy
        .profiles
        .into_iter()
        .map(|profile| {
            if let Some(generation) = profile.credential_generation.as_ref() {
                credential_references.push(CredentialReference {
                    profile_id: profile.profile_id.clone(),
                    generation: generation.clone(),
                });
            }
            StoredProfileV2 {
                profile_id: profile.profile_id,
                display_name: profile.display_name,
                upstream: StoredUpstreamV2::LocalListener {
                    port: profile.port,
                    protocol: profile.protocol,
                    credential_generation: profile.credential_generation,
                },
            }
        })
        .collect();
    let store = ProfileStoreV2 {
        schema_version: PROFILE_SCHEMA_VERSION_V2,
        store_revision: legacy.store_revision,
        profiles,
    };
    store.validate()?;
    let target_sha256 = store.sha256()?;
    Ok(ProfileMigrationV1ToV2 {
        store,
        credential_references,
        source_sha256: lower_hex(&Sha256::digest(bytes)),
        target_sha256,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProfileV2Error {
    #[error("the profile store is invalid")]
    InvalidStore,
    #[error("the legacy profile store is invalid")]
    InvalidLegacyStore,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProfileStoreV1 {
    schema_version: u16,
    store_revision: u64,
    profiles: Vec<StoredProfileV1>,
}

impl ProfileStoreV1 {
    fn validate(&self) -> Result<(), ProfileV2Error> {
        if self.schema_version != PROFILE_SCHEMA_VERSION_V1 || self.profiles.len() > MAX_PROFILES {
            return Err(ProfileV2Error::InvalidLegacyStore);
        }
        let mut previous_id: Option<&str> = None;
        for profile in &self.profiles {
            profile.validate()?;
            if previous_id.is_some_and(|previous| previous >= profile.profile_id.as_str()) {
                return Err(ProfileV2Error::InvalidLegacyStore);
            }
            previous_id = Some(&profile.profile_id);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredProfileV1 {
    profile_id: String,
    display_name: String,
    port: u16,
    protocol: StandardProtocol,
    credential_generation: Option<String>,
}

impl StoredProfileV1 {
    fn validate(&self) -> Result<(), ProfileV2Error> {
        if !valid_identifier(&self.profile_id)
            || !valid_display_name(&self.display_name)
            || self.port == 0
            || self
                .credential_generation
                .as_deref()
                .is_some_and(|value| !valid_identifier(value))
        {
            return Err(ProfileV2Error::InvalidLegacyStore);
        }
        Ok(())
    }
}

fn valid_identifier(value: &str) -> bool {
    value.len() == IDENTIFIER_HEX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_display_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DISPLAY_NAME_BYTES
        && !value.chars().any(char::is_control)
        && value.trim() == value
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upstream::{CertificatePolicy, IpPreference};

    const ID_A: &str = "00112233445566778899aabbccddeeff";
    const GEN_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn legacy_store() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "storeRevision": 7,
            "profiles": [{
                "profileId": ID_A,
                "displayName": "Local proxy",
                "port": 7078,
                "protocol": "socks5",
                "credentialGeneration": GEN_A
            }]
        }))
        .unwrap()
    }

    #[test]
    fn v1_migration_is_explicit_local_listener_and_preserves_revision_reference() {
        let migration = migrate_v1(&legacy_store()).unwrap();
        assert_eq!(migration.store.schema_version, 2);
        assert_eq!(migration.store.store_revision, 7);
        assert_eq!(migration.credential_references.len(), 1);
        assert_eq!(migration.credential_references[0].profile_id, ID_A);
        assert_eq!(migration.credential_references[0].generation, GEN_A);
        assert_ne!(migration.source_sha256, migration.target_sha256);

        let value: serde_json::Value =
            serde_json::from_slice(&migration.store.canonical_bytes().unwrap()).unwrap();
        assert_eq!(value["profiles"][0]["upstream"]["kind"], "local_listener");
        assert_eq!(value["profiles"][0]["upstream"]["port"], 7078);
        assert!(value["profiles"][0]["upstream"].get("host").is_none());
    }

    #[test]
    fn migration_and_v2_parser_reject_unknown_or_ambiguous_fields() {
        let mut legacy: serde_json::Value = serde_json::from_slice(&legacy_store()).unwrap();
        legacy["profiles"][0]["host"] = serde_json::json!("proxy.example.com");
        assert_eq!(
            migrate_v1(&serde_json::to_vec(&legacy).unwrap()).unwrap_err(),
            ProfileV2Error::InvalidLegacyStore
        );

        let migration = migrate_v1(&legacy_store()).unwrap();
        let mut v2 = serde_json::to_value(&migration.store).unwrap();
        v2["profiles"][0]["upstream"]["route"] = serde_json::json!("default");
        assert_eq!(
            parse_v2(&serde_json::to_vec(&v2).unwrap()).unwrap_err(),
            ProfileV2Error::InvalidStore
        );
    }

    #[test]
    fn remote_profile_uses_bounded_typed_config_and_rejects_loopback() {
        let valid = ProfileStoreV2 {
            schema_version: PROFILE_SCHEMA_VERSION_V2,
            store_revision: 1,
            profiles: vec![StoredProfileV2 {
                profile_id: ID_A.into(),
                display_name: "Remote gateway".into(),
                upstream: StoredUpstreamV2::RemoteServer {
                    endpoint: Endpoint::new("proxy.example.com", 443, IpPreference::Ipv4Prefer)
                        .unwrap(),
                    protocol_config: RemoteProtocolConfig::Http {
                        tls: true,
                        sni: Some("proxy.example.com".into()),
                        certificate_policy: CertificatePolicy::Strict,
                    },
                    secret_generation: Some(GEN_A.into()),
                },
            }],
        };
        valid.validate().unwrap();
        parse_v2(&valid.canonical_bytes().unwrap()).unwrap();

        let mut invalid: serde_json::Value = serde_json::to_value(valid).unwrap();
        invalid["profiles"][0]["upstream"]["endpoint"]["host"] = serde_json::json!("127.0.0.1");
        assert_eq!(
            parse_v2(&serde_json::to_vec(&invalid).unwrap()).unwrap_err(),
            ProfileV2Error::InvalidStore
        );
    }

    #[test]
    fn debug_output_redacts_identifiers_endpoint_and_generations() {
        let migration = migrate_v1(&legacy_store()).unwrap();
        let debug = format!("{:?}", migration.store.profiles[0]);
        assert!(!debug.contains(ID_A));
        assert!(!debug.contains(GEN_A));
        assert!(debug.contains("[REDACTED]"));
    }
}
