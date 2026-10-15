use crate::{
    identity::AppRequirementPolicy,
    native::{NativeIdentityError, XpcCodeRequirement},
};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::{Read, Take},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::Path,
};

pub const SYSTEM_APP_POLICY_PATH: &str =
    "/Library/PrivilegedHelperTools/com.tunbridge.desktop.helper.policy.json";
const POLICY_SCHEMA_VERSION: u16 = 1;
const MAX_POLICY_BYTES: u64 = 4096;
const MAX_ALLOWED_CDHASHES: usize = 4;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredAppPolicy {
    schema_version: u16,
    team_id: String,
    app_signing_identifier: String,
    allowed_cdhashes: Vec<String>,
}

pub fn load_system_app_requirement() -> Result<XpcCodeRequirement, NativeIdentityError> {
    load_app_requirement(Path::new(SYSTEM_APP_POLICY_PATH), 0, 0)
}

#[cfg(feature = "macos-development-bootstrap")]
pub fn load_development_app_requirement() -> Result<XpcCodeRequirement, NativeIdentityError> {
    XpcCodeRequirement::for_development_app()
}

fn load_app_requirement(
    path: &Path,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<XpcCodeRequirement, NativeIdentityError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| NativeIdentityError::ProcessUnavailable)?;
    validate_file(&file, expected_uid, expected_gid)?;
    let mut bytes = Vec::new();
    let mut bounded: Take<File> = file.take(MAX_POLICY_BYTES + 1);
    bounded
        .read_to_end(&mut bytes)
        .map_err(|_| NativeIdentityError::ProcessUnavailable)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_POLICY_BYTES {
        return Err(NativeIdentityError::InvalidRequirement);
    }
    parse_app_requirement(&bytes)
}

fn validate_file(
    file: &File,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), NativeIdentityError> {
    let metadata = file
        .metadata()
        .map_err(|_| NativeIdentityError::ProcessUnavailable)?;
    if !metadata.is_file()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_POLICY_BYTES
    {
        return Err(NativeIdentityError::InvalidRequirement);
    }
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 || flags & libc::O_ACCMODE != libc::O_RDONLY {
        return Err(NativeIdentityError::InvalidRequirement);
    }
    Ok(())
}

fn parse_app_requirement(bytes: &[u8]) -> Result<XpcCodeRequirement, NativeIdentityError> {
    let stored: StoredAppPolicy =
        serde_json::from_slice(bytes).map_err(|_| NativeIdentityError::InvalidRequirement)?;
    if stored.schema_version != POLICY_SCHEMA_VERSION
        || stored.allowed_cdhashes.is_empty()
        || stored.allowed_cdhashes.len() > MAX_ALLOWED_CDHASHES
    {
        return Err(NativeIdentityError::InvalidRequirement);
    }
    let allowed_cdhashes = stored
        .allowed_cdhashes
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if allowed_cdhashes.len() != stored.allowed_cdhashes.len() {
        return Err(NativeIdentityError::InvalidRequirement);
    }
    XpcCodeRequirement::for_app(&AppRequirementPolicy {
        team_id: stored.team_id,
        signing_identifier: stored.app_signing_identifier,
        allowed_cdhashes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
        sync::atomic::{AtomicUsize, Ordering},
    };

    static TEST_ID: AtomicUsize = AtomicUsize::new(0);

    fn valid() -> Vec<u8> {
        br#"{
          "schemaVersion": 1,
          "teamId": "ABCDE12345",
          "appSigningIdentifier": "com.tunbridge.desktop",
          "allowedCdhashes": [
            "1111111111111111111111111111111111111111",
            "2222222222222222222222222222222222222222"
          ]
        }"#
        .to_vec()
    }

    #[test]
    fn strict_policy_maps_to_exact_requirement() {
        let requirement = parse_app_requirement(&valid()).unwrap();
        assert_eq!(
            requirement.as_str(),
            "anchor apple generic and identifier \"com.tunbridge.desktop\" \
             and certificate leaf[subject.OU] = \"ABCDE12345\" \
             and flags runtime and (cdhash H\"1111111111111111111111111111111111111111\" \
             or cdhash H\"2222222222222222222222222222222222222222\")"
        );
    }

    #[test]
    fn unknown_duplicate_malformed_and_unbounded_policies_fail_closed() {
        let cases = [
            br#"{"schemaVersion":2,"teamId":"ABCDE12345","appSigningIdentifier":"com.tunbridge.desktop","allowedCdhashes":["1111111111111111111111111111111111111111"]}"#.as_slice(),
            br#"{"schemaVersion":1,"teamId":"ABCDE12345","appSigningIdentifier":"com.tunbridge.desktop","allowedCdhashes":["1111111111111111111111111111111111111111","1111111111111111111111111111111111111111"]}"#.as_slice(),
            br#"{"schemaVersion":1,"teamId":"ABCDE12345","appSigningIdentifier":"com.tunbridge.desktop","allowedCdhashes":[]}"#.as_slice(),
            br#"{"schemaVersion":1,"teamId":"ABCDE12345","appSigningIdentifier":"com.tunbridge.desktop","allowedCdhashes":["UPPER11111111111111111111111111111111111"]}"#.as_slice(),
            br#"{"schemaVersion":1,"teamId":"ABCDE12345","appSigningIdentifier":"com.tunbridge.desktop","allowedCdhashes":["1111111111111111111111111111111111111111"],"extra":true}"#.as_slice(),
        ];
        for bytes in cases {
            assert!(matches!(
                parse_app_requirement(bytes),
                Err(NativeIdentityError::InvalidRequirement)
            ));
        }
    }

    #[test]
    fn policy_file_requires_exact_owner_mode_regular_file_and_no_symlink() {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "tunbridge-listener-policy-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("policy.json");
        fs::write(&path, valid()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        assert!(load_app_requirement(&path, uid, gid).is_ok());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_app_requirement(&path, uid, gid).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let target = root.join("target.json");
        fs::rename(&path, &target).unwrap();
        symlink(&target, &path).unwrap();
        assert!(load_app_requirement(&path, uid, gid).is_err());

        fs::remove_file(&path).unwrap();
        fs::remove_file(&target).unwrap();
        fs::remove_dir(&root).unwrap();
    }
}
