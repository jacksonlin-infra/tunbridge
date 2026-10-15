use crate::local_proxy::{MAX_PASSWORD_BYTES, MAX_USERNAME_BYTES};
use crate::profile_store::{credential_target, CredentialInput};
use crate::profile_store_v2::{credential_target as credential_target_v2, SecretVaultV2Error};
use std::{ptr, slice};
use tunbridge_core::upstream::SecretMaterialV2;
#[cfg(all(test, feature = "acceptance-m3-profile"))]
use windows_sys::Win32::Security::Credentials::CRED_PERSIST_SESSION;
#[cfg(all(test, feature = "acceptance-m3-profile"))]
use windows_sys::Win32::Security::Cryptography::{
    BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};
use windows_sys::Win32::{
    Foundation::{GetLastError, ERROR_NOT_FOUND},
    Security::Credentials::{
        CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
        CRED_TYPE_GENERIC,
    },
};
use zeroize::Zeroizing;

const MAX_USERNAME_WIDE_UNITS: usize = 513;
const MAX_SECRET_V2_BYTES: usize = 2048;
const SECRET_V2_USERNAME: &str = "TunBridge SecretMaterial v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialVaultError {
    InvalidInput,
    AlreadyExists,
    NotFound,
    InvalidRecord,
    SystemFailure,
}

pub struct CredentialVault;

impl CredentialVault {
    pub fn write_new(
        &self,
        profile_id: &str,
        generation: &str,
        input: &CredentialInput,
    ) -> Result<(), CredentialVaultError> {
        input
            .validate()
            .map_err(|_| CredentialVaultError::InvalidInput)?;
        let target = credential_target(profile_id, generation)
            .map_err(|_| CredentialVaultError::InvalidInput)?;
        match self.read(profile_id, generation) {
            Ok(_) => return Err(CredentialVaultError::AlreadyExists),
            Err(CredentialVaultError::NotFound) => {}
            Err(error) => return Err(error),
        }
        write_exact(
            &target,
            input.username.expose(),
            input.password.expose(),
            CRED_PERSIST_LOCAL_MACHINE,
        )
    }

    pub fn read(
        &self,
        profile_id: &str,
        generation: &str,
    ) -> Result<VaultCredential, CredentialVaultError> {
        let target = credential_target(profile_id, generation)
            .map_err(|_| CredentialVaultError::InvalidInput)?;
        read_exact(&target)
    }

    pub fn delete_exact(
        &self,
        profile_id: &str,
        generation: &str,
    ) -> Result<(), CredentialVaultError> {
        let target = credential_target(profile_id, generation)
            .map_err(|_| CredentialVaultError::InvalidInput)?;
        let wide_target = wide(&target);
        // SAFETY: the target is a NUL-terminated string strictly derived from
        // two validated identifiers. Type and flags are fixed.
        if unsafe { CredDeleteW(wide_target.as_ptr(), CRED_TYPE_GENERIC, 0) } != 0 {
            return Ok(());
        }
        // SAFETY: immediately follows the failing Win32 call on this thread.
        let code = unsafe { GetLastError() };
        if code == ERROR_NOT_FOUND {
            Ok(())
        } else {
            Err(CredentialVaultError::SystemFailure)
        }
    }
}

impl crate::profile_store_v2::SecretVaultV2 for CredentialVault {
    fn write_new(
        &self,
        profile_id: &str,
        generation: &str,
        material: &SecretMaterialV2,
    ) -> Result<(), SecretVaultV2Error> {
        material
            .validate()
            .map_err(|_| SecretVaultV2Error::InvalidInput)?;
        let target = credential_target_v2(profile_id, generation)
            .map_err(|_| SecretVaultV2Error::InvalidInput)?;
        match read_exact_v2(&target) {
            Ok(_) => return Err(SecretVaultV2Error::AlreadyExists),
            Err(SecretVaultV2Error::NotFound) => {}
            Err(error) => return Err(error),
        }
        let secret = Zeroizing::new(
            serde_json::to_vec(material).map_err(|_| SecretVaultV2Error::InvalidInput)?,
        );
        write_exact_v2(&target, &secret)
    }

    fn read(
        &self,
        profile_id: &str,
        generation: &str,
    ) -> Result<SecretMaterialV2, SecretVaultV2Error> {
        let target = credential_target_v2(profile_id, generation)
            .map_err(|_| SecretVaultV2Error::InvalidInput)?;
        read_exact_v2(&target)
    }

    fn delete_exact(&self, profile_id: &str, generation: &str) -> Result<(), SecretVaultV2Error> {
        let target = credential_target_v2(profile_id, generation)
            .map_err(|_| SecretVaultV2Error::InvalidInput)?;
        let wide_target = wide(&target);
        // SAFETY: the target is a NUL-terminated string derived exclusively
        // from two validated fixed-width identifiers. Type and flags are fixed.
        if unsafe { CredDeleteW(wide_target.as_ptr(), CRED_TYPE_GENERIC, 0) } != 0 {
            return Ok(());
        }
        // SAFETY: immediately follows the failing Win32 call on this thread.
        let code = unsafe { GetLastError() };
        if code == ERROR_NOT_FOUND {
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
    #[cfg(all(test, feature = "acceptance-m3-profile"))]
    pub fn username(&self) -> &str {
        self.username.as_str()
    }

    #[cfg(all(test, feature = "acceptance-m3-profile"))]
    pub fn password(&self) -> &str {
        self.password.as_str()
    }

    pub fn into_parts(mut self) -> (String, String) {
        (
            std::mem::take(&mut *self.username),
            std::mem::take(&mut *self.password),
        )
    }
}

impl std::fmt::Debug for VaultCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VaultCredential([REDACTED])")
    }
}

fn write_exact(
    target: &str,
    username: &str,
    password: &str,
    persist: u32,
) -> Result<(), CredentialVaultError> {
    if username.is_empty()
        || username.len() > MAX_USERNAME_BYTES
        || username.chars().any(char::is_control)
        || password.is_empty()
        || password.len() > MAX_PASSWORD_BYTES
        || password.chars().any(char::is_control)
    {
        return Err(CredentialVaultError::InvalidInput);
    }
    let mut wide_target = wide(target);
    let mut wide_username = Zeroizing::new(wide(username));
    let mut password = Zeroizing::new(password.as_bytes().to_vec());
    let credential = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: wide_target.as_mut_ptr(),
        CredentialBlobSize: password.len() as u32,
        CredentialBlob: password.as_mut_ptr(),
        Persist: persist,
        UserName: wide_username.as_mut_ptr(),
        ..CREDENTIALW::default()
    };
    // SAFETY: all pointers reference initialized buffers for the duration of
    // the call. No aliases are retained by CredWriteW.
    let result = unsafe { CredWriteW(&credential, 0) };
    if result == 0 {
        Err(CredentialVaultError::SystemFailure)
    } else {
        Ok(())
    }
}

fn write_exact_v2(target: &str, secret: &[u8]) -> Result<(), SecretVaultV2Error> {
    if secret.is_empty() || secret.len() > MAX_SECRET_V2_BYTES {
        return Err(SecretVaultV2Error::InvalidInput);
    }
    let mut wide_target = wide(target);
    let mut wide_username = Zeroizing::new(wide(SECRET_V2_USERNAME));
    let mut secret = Zeroizing::new(secret.to_vec());
    let credential = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: wide_target.as_mut_ptr(),
        CredentialBlobSize: secret.len() as u32,
        CredentialBlob: secret.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        UserName: wide_username.as_mut_ptr(),
        ..CREDENTIALW::default()
    };
    // SAFETY: every pointer references an initialized buffer that remains
    // alive for the call, and CredWriteW does not retain those pointers.
    if unsafe { CredWriteW(&credential, 0) } == 0 {
        Err(SecretVaultV2Error::Unavailable)
    } else {
        Ok(())
    }
}

fn read_exact(target: &str) -> Result<VaultCredential, CredentialVaultError> {
    let wide_target = wide(target);
    let mut raw = ptr::null_mut();
    // SAFETY: target is NUL-terminated and raw points to writable storage.
    if unsafe { CredReadW(wide_target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw) } == 0 {
        // SAFETY: immediately follows the failing Win32 call on this thread.
        return if unsafe { GetLastError() } == ERROR_NOT_FOUND {
            Err(CredentialVaultError::NotFound)
        } else {
            Err(CredentialVaultError::SystemFailure)
        };
    }
    if raw.is_null() {
        return Err(CredentialVaultError::InvalidRecord);
    }
    let allocation = CredentialAllocation(raw);
    // SAFETY: successful CredReadW returned one valid CREDENTIALW allocation.
    let record = unsafe { &*allocation.0 };
    validate_record(record, target)?;

    let username = Zeroizing::new(read_wide_bounded(record.UserName, MAX_USERNAME_WIDE_UNITS)?);
    let blob_len = record.CredentialBlobSize as usize;
    // SAFETY: validate_record checked a non-null blob and the fixed byte bound.
    let password_bytes = unsafe { slice::from_raw_parts(record.CredentialBlob, blob_len) };
    let password = Zeroizing::new(
        std::str::from_utf8(password_bytes)
            .map_err(|_| CredentialVaultError::InvalidRecord)?
            .to_owned(),
    );
    if !valid_secret(&username, MAX_USERNAME_BYTES) || !valid_secret(&password, MAX_PASSWORD_BYTES)
    {
        return Err(CredentialVaultError::InvalidRecord);
    }
    Ok(VaultCredential { username, password })
}

fn read_exact_v2(target: &str) -> Result<SecretMaterialV2, SecretVaultV2Error> {
    let wide_target = wide(target);
    let mut raw = ptr::null_mut();
    // SAFETY: target is NUL-terminated and raw points to writable storage for
    // the credential allocation returned by CredReadW.
    if unsafe { CredReadW(wide_target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw) } == 0 {
        // SAFETY: immediately follows the failing Win32 call on this thread.
        return if unsafe { GetLastError() } == ERROR_NOT_FOUND {
            Err(SecretVaultV2Error::NotFound)
        } else {
            Err(SecretVaultV2Error::Unavailable)
        };
    }
    if raw.is_null() {
        return Err(SecretVaultV2Error::InvalidRecord);
    }
    let allocation = CredentialAllocation(raw);
    // SAFETY: successful CredReadW returned one non-null CREDENTIALW allocation
    // owned by allocation until its Drop implementation calls CredFree.
    let record = unsafe { &*allocation.0 };
    if record.Type != CRED_TYPE_GENERIC
        || record.Persist != CRED_PERSIST_LOCAL_MACHINE
        || record.AttributeCount != 0
        || !record.Attributes.is_null()
        || !record.TargetAlias.is_null()
        || !record.Comment.is_null()
        || record.UserName.is_null()
        || record.CredentialBlob.is_null()
        || record.CredentialBlobSize == 0
        || record.CredentialBlobSize as usize > MAX_SECRET_V2_BYTES
    {
        return Err(SecretVaultV2Error::InvalidRecord);
    }
    let stored_target = read_wide_bounded(record.TargetName, target.encode_utf16().count())
        .map_err(|_| SecretVaultV2Error::InvalidRecord)?;
    let username = read_wide_bounded(record.UserName, MAX_USERNAME_WIDE_UNITS)
        .map_err(|_| SecretVaultV2Error::InvalidRecord)?;
    if stored_target != target || username != SECRET_V2_USERNAME {
        return Err(SecretVaultV2Error::InvalidRecord);
    }
    let length = record.CredentialBlobSize as usize;
    // SAFETY: the record validation above established a non-null blob and a
    // length within MAX_SECRET_V2_BYTES for the lifetime of the allocation.
    let bytes = unsafe { slice::from_raw_parts(record.CredentialBlob, length) };
    let material: SecretMaterialV2 =
        serde_json::from_slice(bytes).map_err(|_| SecretVaultV2Error::InvalidRecord)?;
    material
        .validate()
        .map_err(|_| SecretVaultV2Error::InvalidRecord)?;
    Ok(material)
}

fn validate_record(
    record: &CREDENTIALW,
    expected_target: &str,
) -> Result<(), CredentialVaultError> {
    if record.Type != CRED_TYPE_GENERIC
        || record.Persist != CRED_PERSIST_LOCAL_MACHINE
        || record.AttributeCount != 0
        || !record.Attributes.is_null()
        || !record.TargetAlias.is_null()
        || !record.Comment.is_null()
        || record.UserName.is_null()
        || record.CredentialBlob.is_null()
        || record.CredentialBlobSize == 0
        || record.CredentialBlobSize as usize > MAX_PASSWORD_BYTES
    {
        return Err(CredentialVaultError::InvalidRecord);
    }
    let stored_target =
        read_wide_bounded(record.TargetName, expected_target.encode_utf16().count())?;
    if stored_target != expected_target {
        return Err(CredentialVaultError::InvalidRecord);
    }
    Ok(())
}

fn read_wide_bounded(
    pointer: *const u16,
    max_units: usize,
) -> Result<String, CredentialVaultError> {
    if pointer.is_null() {
        return Err(CredentialVaultError::InvalidRecord);
    }
    let mut length = 0;
    // SAFETY: caller supplies a Windows credential string. The documented
    // field bound limits reads, and failure to find NUL within it is rejected.
    unsafe {
        while length <= max_units && *pointer.add(length) != 0 {
            length += 1;
        }
    }
    if length == 0 || length > max_units {
        return Err(CredentialVaultError::InvalidRecord);
    }
    // SAFETY: the bounded scan proved the slice is initialized up to NUL.
    String::from_utf16(unsafe { slice::from_raw_parts(pointer, length) })
        .map_err(|_| CredentialVaultError::InvalidRecord)
}

fn valid_secret(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}

#[cfg(all(test, feature = "acceptance-m3-profile"))]
fn random_hex_16() -> Result<String, CredentialVaultError> {
    let mut bytes = [0_u8; 16];
    // SAFETY: a null algorithm handle is required with the system-preferred
    // RNG flag and bytes is writable for its complete size.
    let status = unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(CredentialVaultError::SystemFailure);
    }
    let mut encoded = String::with_capacity(32);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").map_err(|_| CredentialVaultError::SystemFailure)?;
    }
    Ok(encoded)
}

struct CredentialAllocation(*mut CREDENTIALW);

impl Drop for CredentialAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: ownership of the allocation returned by CredReadW is
            // released exactly once with CredFree.
            unsafe { CredFree(self.0.cast()) };
        }
    }
}

#[cfg(all(test, feature = "acceptance-m3-profile"))]
mod tests {
    use super::*;

    struct ExactCleanup<'a> {
        vault: &'a CredentialVault,
        entries: Vec<(String, String)>,
    }

    impl Drop for ExactCleanup<'_> {
        fn drop(&mut self) {
            for (profile_id, generation) in &self.entries {
                let _ = self.vault.delete_exact(profile_id, generation);
            }
        }
    }

    fn input(username: &str, password: &str) -> CredentialInput {
        serde_json::from_value(serde_json::json!({
            "username": username,
            "password": password
        }))
        .unwrap()
    }

    #[test]
    #[ignore = "explicitly exercises the current user's Windows Credential Manager"]
    fn real_current_user_credential_roundtrip_is_exact_and_redacted() {
        let vault = CredentialVault;
        let profile_a = random_hex_16().unwrap();
        let generation_a = random_hex_16().unwrap();
        let profile_b = random_hex_16().unwrap();
        let generation_b = random_hex_16().unwrap();
        let invalid_profile = random_hex_16().unwrap();
        let invalid_generation = random_hex_16().unwrap();
        let cleanup = ExactCleanup {
            vault: &vault,
            entries: vec![
                (profile_a.clone(), generation_a.clone()),
                (profile_b.clone(), generation_b.clone()),
                (invalid_profile.clone(), invalid_generation.clone()),
            ],
        };

        let first = input("acceptance-user-a", "acceptance-password-a");
        let second = input("acceptance-user-b", "acceptance-password-b");
        vault.write_new(&profile_a, &generation_a, &first).unwrap();
        let restarted_vault = CredentialVault;
        let read = restarted_vault.read(&profile_a, &generation_a).unwrap();
        assert_eq!(read.username(), "acceptance-user-a");
        assert_eq!(read.password(), "acceptance-password-a");
        assert_eq!(format!("{read:?}"), "VaultCredential([REDACTED])");
        assert_eq!(
            vault.write_new(&profile_a, &generation_a, &first),
            Err(CredentialVaultError::AlreadyExists)
        );

        vault.write_new(&profile_b, &generation_b, &second).unwrap();
        vault.delete_exact(&profile_a, &generation_a).unwrap();
        assert_eq!(
            vault.read(&profile_a, &generation_a).unwrap_err(),
            CredentialVaultError::NotFound
        );
        let isolated = vault.read(&profile_b, &generation_b).unwrap();
        assert_eq!(isolated.username(), "acceptance-user-b");
        vault.delete_exact(&profile_b, &generation_b).unwrap();
        vault.delete_exact(&profile_b, &generation_b).unwrap();
        assert_eq!(
            vault.read(&profile_b, &generation_b).unwrap_err(),
            CredentialVaultError::NotFound
        );

        let invalid_target = credential_target(&invalid_profile, &invalid_generation).unwrap();
        write_exact(
            &invalid_target,
            "invalid-acceptance-user",
            "invalid-acceptance-password",
            CRED_PERSIST_SESSION,
        )
        .unwrap();
        assert_eq!(
            vault
                .read(&invalid_profile, &invalid_generation)
                .unwrap_err(),
            CredentialVaultError::InvalidRecord
        );
        vault
            .delete_exact(&invalid_profile, &invalid_generation)
            .unwrap();

        let report = serde_json::json!({
            "schemaVersion": 1,
            "ok": true,
            "checks": {
                "csprngIdentifiers": profile_a.len() == 32 && profile_b.len() == 32,
                "sameUserRestartRead": true,
                "debugRedacted": true,
                "overwriteRejected": true,
                "differentTargetPreserved": true,
                "exactDeleteIdempotent": true,
                "invalidRecordRejected": true,
                "absentAfterCleanup": true
            }
        });
        println!("M3_PROFILE_CREDENTIAL_REPORT={report}");
        drop(cleanup);
    }
}
