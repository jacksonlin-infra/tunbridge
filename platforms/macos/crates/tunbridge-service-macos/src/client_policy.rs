use crate::{
    identity::HelperRequirementPolicy,
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
    path::{Path, PathBuf},
};

const POLICY_FILE_NAME: &str = "tunbridge-helper-policy.json";
const POLICY_SCHEMA_VERSION: u16 = 1;
const HELPER_SIGNING_IDENTIFIER: &str = "com.tunbridge.desktop.helper";
const MAX_POLICY_BYTES: u64 = 4096;
const MAX_ALLOWED_CDHASHES: usize = 4;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredHelperPolicy {
    schema_version: u16,
    team_id: String,
    helper_signing_identifier: String,
    allowed_cdhashes: Vec<String>,
}

pub fn load_bundle_helper_requirement() -> Result<XpcCodeRequirement, NativeIdentityError> {
    let executable =
        std::env::current_exe().map_err(|_| NativeIdentityError::ProcessUnavailable)?;
    load_bundle_helper_requirement_for_executable(&executable)
}

fn load_bundle_helper_requirement_for_executable(
    executable: &Path,
) -> Result<XpcCodeRequirement, NativeIdentityError> {
    let policy_path = policy_path(executable)?;
    let executable_metadata = executable
        .metadata()
        .map_err(|_| NativeIdentityError::ProcessUnavailable)?;
    if !executable_metadata.is_file()
        || executable_metadata.nlink() != 1
        || executable_metadata.mode() & 0o022 != 0
    {
        return Err(NativeIdentityError::InvalidRequirement);
    }
    load_helper_requirement(
        &policy_path,
        executable_metadata.uid(),
        executable_metadata.gid(),
    )
}

fn policy_path(executable: &Path) -> Result<PathBuf, NativeIdentityError> {
    if !executable.is_absolute() {
        return Err(NativeIdentityError::InvalidRequirement);
    }
    let macos = executable
        .parent()
        .ok_or(NativeIdentityError::InvalidRequirement)?;
    if macos.file_name().and_then(|value| value.to_str()) != Some("MacOS") {
        return Err(NativeIdentityError::InvalidRequirement);
    }
    let contents = macos
        .parent()
        .ok_or(NativeIdentityError::InvalidRequirement)?;
    if contents.file_name().and_then(|value| value.to_str()) != Some("Contents") {
        return Err(NativeIdentityError::InvalidRequirement);
    }
    Ok(contents.join("Resources").join(POLICY_FILE_NAME))
}

fn load_helper_requirement(
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
    parse_helper_requirement(&bytes)
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
        || metadata.mode() & 0o022 != 0
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

fn parse_helper_requirement(bytes: &[u8]) -> Result<XpcCodeRequirement, NativeIdentityError> {
    let stored: StoredHelperPolicy =
        serde_json::from_slice(bytes).map_err(|_| NativeIdentityError::InvalidRequirement)?;
    if stored.schema_version != POLICY_SCHEMA_VERSION
        || stored.helper_signing_identifier != HELPER_SIGNING_IDENTIFIER
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
    XpcCodeRequirement::for_helper(&HelperRequirementPolicy {
        team_id: stored.team_id,
        signing_identifier: stored.helper_signing_identifier,
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
          "helperSigningIdentifier": "com.tunbridge.desktop.helper",
          "allowedCdhashes": [
            "1111111111111111111111111111111111111111",
            "2222222222222222222222222222222222222222"
          ]
        }"#
        .to_vec()
    }

    fn bundle_fixture() -> (PathBuf, PathBuf) {
        let id = TEST_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "tunbridge-client-policy-{}-{id}.app",
            std::process::id()
        ));
        let macos = root.join("Contents/MacOS");
        let resources = root.join("Contents/Resources");
        fs::create_dir_all(&macos).unwrap();
        fs::create_dir_all(&resources).unwrap();
        let executable = macos.join("TunBridge");
        let policy = resources.join(POLICY_FILE_NAME);
        fs::write(&executable, b"fixture").unwrap();
        fs::write(&policy, valid()).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o644)).unwrap();
        (executable, policy)
    }

    #[test]
    fn signed_bundle_shape_maps_to_exact_helper_requirement() {
        let (executable, _) = bundle_fixture();
        let requirement = load_bundle_helper_requirement_for_executable(&executable).unwrap();
        assert_eq!(
            requirement.as_str(),
            "anchor apple generic and identifier \"com.tunbridge.desktop.helper\" \
             and certificate leaf[subject.OU] = \"ABCDE12345\" \
             and flags runtime and (cdhash H\"1111111111111111111111111111111111111111\" \
             or cdhash H\"2222222222222222222222222222222222222222\")"
        );
        fs::remove_dir_all(
            executable
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn non_bundle_paths_and_malformed_policies_fail_closed() {
        assert!(policy_path(Path::new("/tmp/TunBridge")).is_err());
        for bytes in [
            br#"{"schemaVersion":2,"teamId":"ABCDE12345","helperSigningIdentifier":"com.tunbridge.desktop.helper","allowedCdhashes":["1111111111111111111111111111111111111111"]}"#.as_slice(),
            br#"{"schemaVersion":1,"teamId":"ABCDE12345","helperSigningIdentifier":"com.attacker.helper","allowedCdhashes":["1111111111111111111111111111111111111111"]}"#.as_slice(),
            br#"{"schemaVersion":1,"teamId":"ABCDE12345","helperSigningIdentifier":"com.tunbridge.desktop.helper","allowedCdhashes":["1111111111111111111111111111111111111111","1111111111111111111111111111111111111111"]}"#.as_slice(),
            br#"{"schemaVersion":1,"teamId":"ABCDE12345","helperSigningIdentifier":"com.tunbridge.desktop.helper","allowedCdhashes":[]}"#.as_slice(),
        ] {
            assert!(parse_helper_requirement(bytes).is_err());
        }
    }

    #[test]
    fn writable_wrong_owner_shape_and_symlink_are_rejected() {
        let (executable, policy) = bundle_fixture();
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(load_bundle_helper_requirement_for_executable(&executable).is_err());
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o644)).unwrap();

        let target = policy.with_extension("target");
        fs::rename(&policy, &target).unwrap();
        symlink(&target, &policy).unwrap();
        assert!(load_bundle_helper_requirement_for_executable(&executable).is_err());

        fs::remove_dir_all(
            executable
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap(),
        )
        .unwrap();
    }
}
