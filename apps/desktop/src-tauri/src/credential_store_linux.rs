use crate::{
    local_proxy::{MAX_PASSWORD_BYTES, MAX_USERNAME_BYTES},
    profile_store::{credential_target, CredentialInput},
    profile_store_v2::{credential_target as credential_target_v2, SecretVaultV2Error},
};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read as _, Write as _},
    os::unix::fs::MetadataExt as _,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use tunbridge_core::upstream::SecretMaterialV2;
use zeroize::Zeroizing;

const SECRET_TOOL: &str = "/usr/bin/secret-tool";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_SECRET_BYTES: usize = 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialVaultError {
    InvalidInput,
    AlreadyExists,
    NotFound,
    InvalidRecord,
    Unavailable,
}

pub trait CredentialVault {
    fn write_new(
        &self,
        profile_id: &str,
        generation: &str,
        input: &CredentialInput,
    ) -> Result<(), CredentialVaultError>;

    fn read(
        &self,
        profile_id: &str,
        generation: &str,
    ) -> Result<VaultCredential, CredentialVaultError>;

    fn delete_exact(&self, profile_id: &str, generation: &str) -> Result<(), CredentialVaultError>;
}

pub struct SecretServiceCredentialVault;

impl CredentialVault for SecretServiceCredentialVault {
    fn write_new(
        &self,
        profile_id: &str,
        generation: &str,
        input: &CredentialInput,
    ) -> Result<(), CredentialVaultError> {
        input
            .validate()
            .map_err(|_| CredentialVaultError::InvalidInput)?;
        validate_identifiers(profile_id, generation)?;
        match self.read(profile_id, generation) {
            Ok(_) => return Err(CredentialVaultError::AlreadyExists),
            Err(CredentialVaultError::NotFound) => {}
            Err(error) => return Err(error),
        }
        let payload = SecretPayload {
            schema_version: 1,
            username: input.username.expose(),
            password: input.password.expose(),
        };
        let secret = Zeroizing::new(
            serde_json::to_vec(&payload).map_err(|_| CredentialVaultError::InvalidInput)?,
        );
        if secret.len() > MAX_SECRET_BYTES {
            return Err(CredentialVaultError::InvalidInput);
        }
        let output = run_secret_tool(
            &[
                "store",
                "--label=TunBridge upstream credential",
                "application",
                "tunbridge",
                "profile",
                profile_id,
                "generation",
                generation,
            ],
            Some(secret.as_slice()),
        )?;
        if output.success {
            Ok(())
        } else {
            Err(CredentialVaultError::Unavailable)
        }
    }

    fn read(
        &self,
        profile_id: &str,
        generation: &str,
    ) -> Result<VaultCredential, CredentialVaultError> {
        validate_identifiers(profile_id, generation)?;
        let output = run_secret_tool(
            &[
                "lookup",
                "application",
                "tunbridge",
                "profile",
                profile_id,
                "generation",
                generation,
            ],
            None,
        )?;
        if !output.success {
            return if output.stderr.is_empty() && output.stdout.is_empty() {
                Err(CredentialVaultError::NotFound)
            } else {
                Err(CredentialVaultError::Unavailable)
            };
        }
        let mut secret = Zeroizing::new(output.stdout);
        if secret.last() == Some(&b'\n') {
            secret.pop();
            if secret.last() == Some(&b'\r') {
                secret.pop();
            }
        }
        if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
            return Err(CredentialVaultError::InvalidRecord);
        }
        let payload: OwnedSecretPayload =
            serde_json::from_slice(&secret).map_err(|_| CredentialVaultError::InvalidRecord)?;
        payload.validate()?;
        Ok(VaultCredential {
            username: Zeroizing::new(payload.username),
            password: Zeroizing::new(payload.password),
        })
    }

    fn delete_exact(&self, profile_id: &str, generation: &str) -> Result<(), CredentialVaultError> {
        validate_identifiers(profile_id, generation)?;
        let output = run_secret_tool(
            &[
                "clear",
                "application",
                "tunbridge",
                "profile",
                profile_id,
                "generation",
                generation,
            ],
            None,
        )?;
        if output.success || (output.stderr.is_empty() && output.stdout.is_empty()) {
            Ok(())
        } else {
            Err(CredentialVaultError::Unavailable)
        }
    }
}

impl crate::profile_store_v2::SecretVaultV2 for SecretServiceCredentialVault {
    fn write_new(
        &self,
        profile_id: &str,
        generation: &str,
        material: &SecretMaterialV2,
    ) -> Result<(), SecretVaultV2Error> {
        material
            .validate()
            .map_err(|_| SecretVaultV2Error::InvalidInput)?;
        validate_identifiers_v2(profile_id, generation)?;
        match <Self as crate::profile_store_v2::SecretVaultV2>::read(self, profile_id, generation) {
            Ok(_) => return Err(SecretVaultV2Error::AlreadyExists),
            Err(SecretVaultV2Error::NotFound) => {}
            Err(error) => return Err(error),
        }
        let secret = Zeroizing::new(
            serde_json::to_vec(material).map_err(|_| SecretVaultV2Error::InvalidInput)?,
        );
        if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
            return Err(SecretVaultV2Error::InvalidInput);
        }
        let output = run_secret_tool(
            &[
                "store",
                "--label=TunBridge upstream secret v2",
                "application",
                "tunbridge",
                "schema",
                "2",
                "profile",
                profile_id,
                "generation",
                generation,
            ],
            Some(secret.as_slice()),
        )
        .map_err(map_v2_error)?;
        if output.success {
            Ok(())
        } else {
            Err(SecretVaultV2Error::Unavailable)
        }
    }

    fn read(
        &self,
        profile_id: &str,
        generation: &str,
    ) -> Result<SecretMaterialV2, SecretVaultV2Error> {
        validate_identifiers_v2(profile_id, generation)?;
        let output = run_secret_tool(
            &[
                "lookup",
                "application",
                "tunbridge",
                "schema",
                "2",
                "profile",
                profile_id,
                "generation",
                generation,
            ],
            None,
        )
        .map_err(map_v2_error)?;
        if !output.success {
            return if output.stderr.is_empty() && output.stdout.is_empty() {
                Err(SecretVaultV2Error::NotFound)
            } else {
                Err(SecretVaultV2Error::Unavailable)
            };
        }
        let mut secret = Zeroizing::new(output.stdout);
        if secret.last() == Some(&b'\n') {
            secret.pop();
            if secret.last() == Some(&b'\r') {
                secret.pop();
            }
        }
        if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
            return Err(SecretVaultV2Error::InvalidRecord);
        }
        let material: SecretMaterialV2 =
            serde_json::from_slice(&secret).map_err(|_| SecretVaultV2Error::InvalidRecord)?;
        material
            .validate()
            .map_err(|_| SecretVaultV2Error::InvalidRecord)?;
        Ok(material)
    }

    fn delete_exact(&self, profile_id: &str, generation: &str) -> Result<(), SecretVaultV2Error> {
        validate_identifiers_v2(profile_id, generation)?;
        let output = run_secret_tool(
            &[
                "clear",
                "application",
                "tunbridge",
                "schema",
                "2",
                "profile",
                profile_id,
                "generation",
                generation,
            ],
            None,
        )
        .map_err(map_v2_error)?;
        if output.success || (output.stderr.is_empty() && output.stdout.is_empty()) {
            Ok(())
        } else {
            Err(SecretVaultV2Error::Unavailable)
        }
    }
}

pub struct VaultCredential {
    username: Zeroizing<String>,
    password: Zeroizing<String>,
}

impl VaultCredential {
    pub fn into_parts(mut self) -> (String, String) {
        (
            std::mem::take(&mut *self.username),
            std::mem::take(&mut *self.password),
        )
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(username: String, password: String) -> Self {
        Self {
            username: Zeroizing::new(username),
            password: Zeroizing::new(password),
        }
    }
}

impl std::fmt::Debug for VaultCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VaultCredential([REDACTED])")
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SecretPayload<'a> {
    schema_version: u16,
    username: &'a str,
    password: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnedSecretPayload {
    schema_version: u16,
    username: String,
    password: String,
}

impl OwnedSecretPayload {
    fn validate(&self) -> Result<(), CredentialVaultError> {
        if self.schema_version == 1
            && valid_secret(&self.username, MAX_USERNAME_BYTES)
            && valid_secret(&self.password, MAX_PASSWORD_BYTES)
        {
            Ok(())
        } else {
            Err(CredentialVaultError::InvalidRecord)
        }
    }
}

struct SecretToolOutput {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_secret_tool(
    arguments: &[&str],
    stdin: Option<&[u8]>,
) -> Result<SecretToolOutput, CredentialVaultError> {
    validate_secret_tool()?;
    let mut child = Command::new(SECRET_TOOL)
        .args(arguments)
        .env("LC_ALL", "C")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| CredentialVaultError::Unavailable)?;
    if let Some(secret) = stdin {
        child
            .stdin
            .take()
            .ok_or(CredentialVaultError::Unavailable)?
            .write_all(secret)
            .map_err(|_| CredentialVaultError::Unavailable)?;
    }
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    loop {
        if child
            .try_wait()
            .map_err(|_| CredentialVaultError::Unavailable)?
            .is_some()
        {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CredentialVaultError::Unavailable);
        }
        thread::sleep(Duration::from_millis(20));
    }
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    child
        .stdout
        .take()
        .ok_or(CredentialVaultError::Unavailable)?
        .take((MAX_SECRET_BYTES + 2) as u64)
        .read_to_end(&mut stdout)
        .map_err(|_| CredentialVaultError::Unavailable)?;
    child
        .stderr
        .take()
        .ok_or(CredentialVaultError::Unavailable)?
        .take((MAX_DIAGNOSTIC_BYTES + 1) as u64)
        .read_to_end(&mut stderr)
        .map_err(|_| CredentialVaultError::Unavailable)?;
    let status = child
        .wait()
        .map_err(|_| CredentialVaultError::Unavailable)?;
    if stdout.len() > MAX_SECRET_BYTES + 1 || stderr.len() > MAX_DIAGNOSTIC_BYTES {
        return Err(CredentialVaultError::Unavailable);
    }
    Ok(SecretToolOutput {
        success: status.success(),
        stdout,
        stderr,
    })
}

fn validate_secret_tool() -> Result<(), CredentialVaultError> {
    let metadata =
        std::fs::symlink_metadata(SECRET_TOOL).map_err(|_| CredentialVaultError::Unavailable)?;
    if metadata.file_type().is_file()
        && metadata.uid() == 0
        && metadata.mode() & 0o022 == 0
        && metadata.nlink() == 1
    {
        Ok(())
    } else {
        Err(CredentialVaultError::Unavailable)
    }
}

fn validate_identifiers(profile_id: &str, generation: &str) -> Result<(), CredentialVaultError> {
    credential_target(profile_id, generation)
        .map(|_| ())
        .map_err(|_| CredentialVaultError::InvalidInput)
}

fn validate_identifiers_v2(profile_id: &str, generation: &str) -> Result<(), SecretVaultV2Error> {
    credential_target_v2(profile_id, generation)
        .map(|_| ())
        .map_err(|_| SecretVaultV2Error::InvalidInput)
}

fn map_v2_error(error: CredentialVaultError) -> SecretVaultV2Error {
    match error {
        CredentialVaultError::InvalidInput => SecretVaultV2Error::InvalidInput,
        CredentialVaultError::AlreadyExists => SecretVaultV2Error::AlreadyExists,
        CredentialVaultError::NotFound => SecretVaultV2Error::NotFound,
        CredentialVaultError::InvalidRecord => SecretVaultV2Error::InvalidRecord,
        CredentialVaultError::Unavailable => SecretVaultV2Error::Unavailable,
    }
}

fn valid_secret(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= maximum_bytes && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_payload_is_strict_and_debug_is_redacted() {
        let valid: OwnedSecretPayload = serde_json::from_value(serde_json::json!({
            "schemaVersion": 1,
            "username": "alice",
            "password": "private"
        }))
        .unwrap();
        valid.validate().unwrap();
        assert!(
            serde_json::from_value::<OwnedSecretPayload>(serde_json::json!({
                "schemaVersion": 1,
                "username": "alice",
                "password": "private",
                "path": "/tmp/secret"
            }))
            .is_err()
        );
        let credential = VaultCredential {
            username: Zeroizing::new("alice".into()),
            password: Zeroizing::new("private".into()),
        };
        assert_eq!(format!("{credential:?}"), "VaultCredential([REDACTED])");
    }

    #[test]
    fn secret_tool_arguments_are_derived_from_strict_identifiers() {
        let valid = "ab".repeat(16);
        validate_identifiers(&valid, &valid).unwrap();
        assert_eq!(
            validate_identifiers("../profile", &valid),
            Err(CredentialVaultError::InvalidInput)
        );
    }

    #[test]
    #[ignore = "requires a running Secret Service session and /usr/bin/secret-tool"]
    fn real_secret_service_round_trip_is_exact() {
        let profile_id = format!("{:032x}", std::process::id());
        let generation = format!(
            "{:032x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let vault = SecretServiceCredentialVault;
        let _ = vault.delete_exact(&profile_id, &generation);
        let input = CredentialInput {
            username: crate::local_proxy::SecretText::from_owned("alice".into()),
            password: crate::local_proxy::SecretText::from_owned("private".into()),
        };
        vault.write_new(&profile_id, &generation, &input).unwrap();
        let (username, password) = vault.read(&profile_id, &generation).unwrap().into_parts();
        assert_eq!(username, "alice");
        assert_eq!(password, "private");
        vault.delete_exact(&profile_id, &generation).unwrap();
        assert!(matches!(
            vault.read(&profile_id, &generation),
            Err(CredentialVaultError::NotFound)
        ));
    }
}
