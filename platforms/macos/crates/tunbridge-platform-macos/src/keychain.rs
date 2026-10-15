use security_framework::{
    os::macos::keychain::SecKeychain,
    passwords::{delete_generic_password, get_generic_password},
};
use security_framework_sys::base::{errSecDuplicateItem, errSecItemNotFound};
use tunbridge_desktop_contract::adapter::{AdapterError, AdapterErrorCode, CredentialStore};

const KEYCHAIN_SERVICE: &str = "com.tunbridge.desktop.upstream";
const MAX_TARGET_BYTES: usize = 256;
const MAX_SECRET_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, Default)]
pub struct MacosKeychain;

impl CredentialStore for MacosKeychain {
    fn read(&self, target: &str) -> Result<Option<Vec<u8>>, AdapterError> {
        validate_target(target)?;
        match get_generic_password(KEYCHAIN_SERVICE, target) {
            Ok(secret) if !secret.is_empty() && secret.len() <= MAX_SECRET_BYTES => {
                Ok(Some(secret))
            }
            Ok(_) => Err(invalid_data()),
            Err(error) if error.code() == errSecItemNotFound => Ok(None),
            Err(_) => Err(unavailable()),
        }
    }

    fn write(&self, target: &str, secret: &[u8]) -> Result<(), AdapterError> {
        validate_target(target)?;
        if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
            return Err(invalid_data());
        }
        SecKeychain::default()
            .map_err(|_| unavailable())?
            .add_generic_password(KEYCHAIN_SERVICE, target, secret)
            .map_err(|error| {
                if error.code() == errSecDuplicateItem {
                    already_exists()
                } else {
                    unavailable()
                }
            })
    }

    fn delete(&self, target: &str) -> Result<(), AdapterError> {
        validate_target(target)?;
        match delete_generic_password(KEYCHAIN_SERVICE, target) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == errSecItemNotFound => Ok(()),
            Err(_) => Err(unavailable()),
        }
    }
}

fn validate_target(target: &str) -> Result<(), AdapterError> {
    if !target.is_empty()
        && target.len() <= MAX_TARGET_BYTES
        && !target.contains("..")
        && !target.contains("//")
        && target
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/'))
    {
        Ok(())
    } else {
        Err(invalid_data())
    }
}

const fn invalid_data() -> AdapterError {
    error(
        AdapterErrorCode::InvalidData,
        "The macOS Keychain request is invalid.",
        false,
    )
}
const fn already_exists() -> AdapterError {
    error(
        AdapterErrorCode::InvalidData,
        "The macOS Keychain item already exists.",
        false,
    )
}
const fn unavailable() -> AdapterError {
    error(
        AdapterErrorCode::Unavailable,
        "The macOS Keychain is unavailable.",
        true,
    )
}
const fn error(
    code: AdapterErrorCode,
    safe_message: &'static str,
    retryable: bool,
) -> AdapterError {
    AdapterError {
        code,
        safe_message,
        retryable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_validation_is_closed_and_messages_are_fixed() {
        assert!(validate_target("TunBridge.Desktop.Upstream/v1/abc/def").is_ok());
        assert_eq!(validate_target("bad//target"), Err(invalid_data()));
        assert_eq!(validate_target(""), Err(invalid_data()));
        assert!(!format!("{:?}", unavailable()).contains("/Users/"));
    }
}
