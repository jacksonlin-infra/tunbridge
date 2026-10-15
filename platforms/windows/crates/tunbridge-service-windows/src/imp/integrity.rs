use std::{
    ffi::c_void,
    fmt::Write as _,
    fs::File,
    io::{self, Read},
    mem::size_of,
    os::windows::{ffi::OsStrExt as _, fs::MetadataExt as _},
    path::{Path, PathBuf},
    ptr,
};

use serde::{Deserialize, Serialize};
use windows_sys::Win32::{
    Foundation::{LocalFree, GENERIC_ALL, GENERIC_WRITE, HLOCAL},
    Security::{
        Authorization::{ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT},
        Cryptography::{
            BCryptCloseAlgorithmProvider, BCryptCreateHash, BCryptDestroyHash, BCryptFinishHash,
            BCryptGetProperty, BCryptHashData, BCryptOpenAlgorithmProvider, BCRYPT_ALG_HANDLE,
            BCRYPT_HASH_HANDLE, BCRYPT_OBJECT_LENGTH, BCRYPT_SHA256_ALGORITHM,
        },
        GetAce, IsValidAcl, IsValidSid, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
        DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID,
    },
    Storage::FileSystem::{
        DELETE, FILE_APPEND_DATA, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD,
        FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
    },
    System::SystemServices::{
        ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
        ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
        ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE_TYPE,
        ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE,
    },
};

const MANIFEST_FILENAME: &str = "engines.lock.json";
const ENGINE_FILENAME: &str = "mihomo.exe";
const MANIFEST_SCHEMA_VERSION: u16 = 1;
const SHA256_BYTES: usize = 32;
const TRUSTED_OWNERS: [&str; 3] = [
    "S-1-5-18",     // LocalSystem
    "S-1-5-32-544", // Builtin Administrators
    // NT SERVICE\TrustedInstaller
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];
const WRITE_LIKE_ACCESS: u32 = GENERIC_ALL
    | GENERIC_WRITE
    | FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineManifest {
    pub schema_version: u16,
    pub product_version: String,
    pub engine: EngineEntry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineEntry {
    pub filename: String,
    pub version: String,
    pub asset: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedEngine {
    path: PathBuf,
    version: String,
    size: u64,
    sha256: String,
}

impl ValidatedEngine {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    #[cfg(test)]
    pub(super) fn for_test(path: PathBuf) -> Self {
        Self {
            path,
            version: "v-test".into(),
            size: 1,
            sha256: "a".repeat(64),
        }
    }
}

/// Validate fixed engine/manifest files without executing the engine.
///
/// Directory ACL verification is a separate mandatory gate; callers must not
/// spawn the returned path until that gate also succeeds.
pub fn validate_engine_files(install_root: &Path) -> Result<ValidatedEngine, IntegrityError> {
    reject_reparse_point(install_root, "install root")?;
    let canonical_root = install_root.canonicalize().map_err(IntegrityError::Io)?;
    let manifest_path = install_root.join(MANIFEST_FILENAME);
    let engine_path = install_root.join(ENGINE_FILENAME);
    reject_reparse_point(&manifest_path, "engine manifest")?;
    reject_reparse_point(&engine_path, "engine binary")?;

    validate_asset_acl(&canonical_root, "install root")?;
    validate_asset_acl(&manifest_path, "engine manifest")?;
    validate_asset_acl(&engine_path, "engine binary")?;

    validate_engine_contents(&canonical_root, &manifest_path, &engine_path)
}

fn validate_engine_contents(
    canonical_root: &Path,
    manifest_path: &Path,
    engine_path: &Path,
) -> Result<ValidatedEngine, IntegrityError> {
    let canonical_manifest = manifest_path.canonicalize().map_err(IntegrityError::Io)?;
    let canonical_engine = engine_path.canonicalize().map_err(IntegrityError::Io)?;
    if canonical_manifest.parent() != Some(canonical_root)
        || canonical_engine.parent() != Some(canonical_root)
    {
        return Err(IntegrityError::PathEscape);
    }

    let manifest_file = File::open(&canonical_manifest).map_err(IntegrityError::Io)?;
    let manifest: EngineManifest =
        serde_json::from_reader(manifest_file).map_err(IntegrityError::ManifestJson)?;
    validate_manifest(&manifest)?;

    let metadata = canonical_engine.metadata().map_err(IntegrityError::Io)?;
    if !metadata.is_file() {
        return Err(IntegrityError::NotAFile);
    }
    if metadata.len() != manifest.engine.size {
        return Err(IntegrityError::SizeMismatch {
            expected: manifest.engine.size,
            actual: metadata.len(),
        });
    }
    let actual_hash = sha256_file(&canonical_engine)?;
    if actual_hash != manifest.engine.sha256 {
        return Err(IntegrityError::HashMismatch);
    }

    Ok(ValidatedEngine {
        path: canonical_engine,
        version: manifest.engine.version,
        size: metadata.len(),
        sha256: actual_hash,
    })
}

pub fn validate_asset_acl(path: &Path, label: &'static str) -> Result<(), IntegrityError> {
    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: wide_path is NUL-terminated; all requested output pointers are
    // valid. The returned self-relative descriptor owns owner and DACL memory.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(IntegrityError::AclWindows {
            label,
            source: io::Error::from_raw_os_error(status as i32),
        });
    }
    let _descriptor = LocalAllocation(descriptor.cast::<c_void>());
    if owner.is_null() || unsafe { IsValidSid(owner) } == 0 {
        return Err(IntegrityError::InvalidAcl(label));
    }
    let owner_sid = sid_string(owner)?;
    if !is_trusted_principal(&owner_sid) {
        return Err(IntegrityError::UntrustedOwner {
            label,
            sid: owner_sid,
        });
    }
    if dacl.is_null() || unsafe { IsValidAcl(dacl) } == 0 {
        return Err(IntegrityError::InvalidAcl(label));
    }

    // SAFETY: dacl belongs to a valid descriptor and IsValidAcl succeeded.
    let ace_count = unsafe { (*dacl).AceCount };
    for index in 0..u32::from(ace_count) {
        let mut raw_ace = ptr::null_mut();
        // SAFETY: index is within AceCount and raw_ace is writable.
        if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 || raw_ace.is_null() {
            return Err(IntegrityError::InvalidAcl(label));
        }
        validate_ace(raw_ace.cast_const(), label)?;
    }
    Ok(())
}

fn validate_ace(raw: *const c_void, label: &'static str) -> Result<(), IntegrityError> {
    // SAFETY: raw was returned by GetAce for a DACL that passed IsValidAcl.
    let header = unsafe { ptr::read_unaligned(raw.cast::<ACE_HEADER>()) };
    if header.AceFlags & INHERIT_ONLY_ACE as u8 != 0 {
        return Ok(());
    }
    let ace_type = u32::from(header.AceType);
    if matches!(
        ace_type,
        ACCESS_DENIED_ACE_TYPE
            | ACCESS_DENIED_OBJECT_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
    ) {
        return Ok(());
    }
    if ace_type == ACCESS_ALLOWED_COMPOUND_ACE_TYPE {
        return Err(IntegrityError::UnsupportedAce {
            label,
            ace_type: header.AceType,
        });
    }
    let is_object_ace = matches!(
        ace_type,
        ACCESS_ALLOWED_OBJECT_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
    );
    if !is_object_ace
        && !matches!(
            ace_type,
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
        )
    {
        return Err(IntegrityError::UnsupportedAce {
            label,
            ace_type: header.AceType,
        });
    }

    let ace_size = usize::from(header.AceSize);
    if ace_size < size_of::<ACCESS_ALLOWED_ACE>() {
        return Err(IntegrityError::InvalidAcl(label));
    }
    // ACCESS_ALLOWED_* ACEs place Mask immediately after the four-byte header.
    let mask = unsafe { ptr::read_unaligned(raw.cast::<u8>().add(4).cast::<u32>()) };
    if mask & WRITE_LIKE_ACCESS == 0 {
        return Ok(());
    }

    let mut sid_offset = 8_usize;
    if is_object_ace {
        if ace_size < 12 {
            return Err(IntegrityError::InvalidAcl(label));
        }
        // Object ACE flags are after Header and Mask. Each present GUID adds
        // sixteen bytes before SidStart.
        let flags = unsafe { ptr::read_unaligned(raw.cast::<u8>().add(8).cast::<u32>()) };
        sid_offset = 12;
        if flags & 0x1 != 0 {
            sid_offset += 16;
        }
        if flags & 0x2 != 0 {
            sid_offset += 16;
        }
    }
    if sid_offset >= ace_size {
        return Err(IntegrityError::InvalidAcl(label));
    }
    let sid = unsafe { raw.cast::<u8>().add(sid_offset).cast_mut().cast::<c_void>() };
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(IntegrityError::InvalidAcl(label));
    }
    let trustee = sid_string(sid)?;
    if !is_trusted_principal(&trustee) {
        return Err(IntegrityError::UserWritable {
            label,
            sid: trustee,
            mask,
        });
    }
    Ok(())
}

fn is_trusted_principal(sid: &str) -> bool {
    TRUSTED_OWNERS.contains(&sid)
}

fn sid_string(sid: PSID) -> Result<String, IntegrityError> {
    let mut wide = ptr::null_mut();
    // SAFETY: sid passed IsValidSid; Windows allocates the output with LocalAlloc.
    if unsafe { ConvertSidToStringSidW(sid, &mut wide) } == 0 {
        return Err(IntegrityError::Io(io::Error::last_os_error()));
    }
    let _allocation = LocalAllocation(wide.cast::<c_void>());
    let mut length = 0_usize;
    // SAFETY: wide is a Windows-allocated NUL-terminated UTF-16 string.
    unsafe {
        while *wide.add(length) != 0 {
            length += 1;
        }
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(wide, length) })
        .map_err(|_| IntegrityError::InvalidAcl("security descriptor"))
}

fn validate_manifest(manifest: &EngineManifest) -> Result<(), IntegrityError> {
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(IntegrityError::UnsupportedSchema(manifest.schema_version));
    }
    if manifest.product_version != env!("CARGO_PKG_VERSION") {
        return Err(IntegrityError::ProductVersionMismatch);
    }
    if !manifest
        .engine
        .filename
        .eq_ignore_ascii_case(ENGINE_FILENAME)
        || manifest.engine.filename.contains(['/', '\\'])
    {
        return Err(IntegrityError::InvalidEngineFilename);
    }
    if manifest.engine.size == 0
        || !valid_bounded_text(&manifest.engine.version, 64)
        || !valid_bounded_text(&manifest.engine.asset, 255)
        || manifest.engine.sha256.len() != 64
        || !manifest
            .engine
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(IntegrityError::InvalidManifestValue);
    }
    Ok(())
}

fn valid_bounded_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

pub fn reject_reparse_point(path: &Path, label: &'static str) -> Result<(), IntegrityError> {
    let metadata = std::fs::symlink_metadata(path).map_err(IntegrityError::Io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(IntegrityError::ReparsePoint(label));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, IntegrityError> {
    let mut algorithm = ptr::null_mut();
    // SAFETY: algorithm points to writable handle storage; SHA256 provider and
    // default implementation are fixed constants.
    check_status(unsafe {
        BCryptOpenAlgorithmProvider(&mut algorithm, BCRYPT_SHA256_ALGORITHM, ptr::null(), 0)
    })?;
    let algorithm = AlgorithmHandle(algorithm);
    let object_length = algorithm_property_u32(algorithm.0, BCRYPT_OBJECT_LENGTH)?;
    let mut object = vec![0_u8; object_length as usize];
    let mut hash = ptr::null_mut();
    // SAFETY: object is writable for object_length bytes; this is an unkeyed
    // hash, so secret is null and length is zero.
    check_status(unsafe {
        BCryptCreateHash(
            algorithm.0,
            &mut hash,
            object.as_mut_ptr(),
            object_length,
            ptr::null(),
            0,
            0,
        )
    })?;
    let hash = HashHandle(hash);

    let mut file = File::open(path).map_err(IntegrityError::Io)?;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(IntegrityError::Io)?;
        if count == 0 {
            break;
        }
        // SAFETY: count never exceeds the initialized buffer prefix.
        check_status(unsafe { BCryptHashData(hash.0, buffer.as_ptr(), count as u32, 0) })?;
    }

    let mut digest = [0_u8; SHA256_BYTES];
    // SAFETY: SHA-256 output is exactly 32 bytes.
    check_status(unsafe { BCryptFinishHash(hash.0, digest.as_mut_ptr(), digest.len() as u32, 0) })?;
    let mut result = String::with_capacity(64);
    for byte in digest {
        write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(result)
}

fn algorithm_property_u32(
    algorithm: BCRYPT_ALG_HANDLE,
    property: *const u16,
) -> Result<u32, IntegrityError> {
    let mut value = 0_u32;
    let mut written = 0_u32;
    // SAFETY: value is writable for one DWORD and the property belongs to the
    // open algorithm provider.
    check_status(unsafe {
        BCryptGetProperty(
            algorithm,
            property,
            (&mut value as *mut u32).cast::<u8>(),
            std::mem::size_of::<u32>() as u32,
            &mut written,
            0,
        )
    })?;
    if written != std::mem::size_of::<u32>() as u32 {
        return Err(IntegrityError::CryptoStatus(-1));
    }
    Ok(value)
}

fn check_status(status: i32) -> Result<(), IntegrityError> {
    if status == 0 {
        Ok(())
    } else {
        Err(IntegrityError::CryptoStatus(status))
    }
}

struct AlgorithmHandle(BCRYPT_ALG_HANDLE);

impl Drop for AlgorithmHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                BCryptCloseAlgorithmProvider(self.0, 0);
            }
        }
    }
}

struct HashHandle(BCRYPT_HASH_HANDLE);

impl Drop for HashHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                BCryptDestroyHash(self.0);
            }
        }
    }
}

struct LocalAllocation(HLOCAL);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: ownership came from GetNamedSecurityInfoW or
            // ConvertSidToStringSidW, both of which use LocalAlloc.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IntegrityError {
    #[error("engine integrity I/O failed: {0}")]
    Io(#[source] io::Error),
    #[error("engine manifest JSON is invalid: {0}")]
    ManifestJson(#[source] serde_json::Error),
    #[error("unsupported engine manifest schema {0}")]
    UnsupportedSchema(u16),
    #[error("engine manifest product version does not match the service")]
    ProductVersionMismatch,
    #[error("engine manifest contains an invalid fixed filename")]
    InvalidEngineFilename,
    #[error("engine manifest contains an invalid value")]
    InvalidManifestValue,
    #[error("engine path escaped the installation root")]
    PathEscape,
    #[error("{0} must not be a reparse point")]
    ReparsePoint(&'static str),
    #[error("{label} ACL query failed: {source}")]
    AclWindows {
        label: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("{0} has a missing or invalid owner/DACL")]
    InvalidAcl(&'static str),
    #[error("{label} owner {sid} is not SYSTEM, Administrators, or TrustedInstaller")]
    UntrustedOwner { label: &'static str, sid: String },
    #[error("{label} grants write-like access {mask:#x} to untrusted SID {sid}")]
    UserWritable {
        label: &'static str,
        sid: String,
        mask: u32,
    },
    #[error("{label} contains unsupported allow ACE type {ace_type}")]
    UnsupportedAce { label: &'static str, ace_type: u8 },
    #[error("engine path is not a regular file")]
    NotAFile,
    #[error("engine length mismatch: expected {expected}, got {actual}")]
    SizeMismatch { expected: u64, actual: u64 },
    #[error("engine SHA-256 mismatch")]
    HashMismatch,
    #[error("Windows SHA-256 provider failed with NTSTATUS {0:#x}")]
    CryptoStatus(i32),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "tunbridge-integrity-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            fs::write(root.join(ENGINE_FILENAME), b"abc").unwrap();
            let manifest = EngineManifest {
                schema_version: MANIFEST_SCHEMA_VERSION,
                product_version: env!("CARGO_PKG_VERSION").into(),
                engine: EngineEntry {
                    filename: ENGINE_FILENAME.into(),
                    version: "v-test".into(),
                    asset: "test.zip".into(),
                    size: 3,
                    sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                        .into(),
                },
            };
            fs::write(
                root.join(MANIFEST_FILENAME),
                serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
            Self { root }
        }

        fn manifest(&self) -> EngineManifest {
            serde_json::from_slice(&fs::read(self.root.join(MANIFEST_FILENAME)).unwrap()).unwrap()
        }

        fn write_manifest(&self, manifest: &EngineManifest) {
            fs::write(
                self.root.join(MANIFEST_FILENAME),
                serde_json::to_vec(manifest).unwrap(),
            )
            .unwrap();
        }

        fn validate_contents(&self) -> Result<ValidatedEngine, IntegrityError> {
            let root = self.root.canonicalize().unwrap();
            validate_engine_contents(
                &root,
                &root.join(MANIFEST_FILENAME),
                &root.join(ENGINE_FILENAME),
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn validates_fixed_file_size_and_sha256() {
        let fixture = Fixture::new();
        let validated = fixture.validate_contents().unwrap();
        assert_eq!(validated.version(), "v-test");
        assert_eq!(validated.size(), 3);
        assert_eq!(
            validated.sha256(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn rejects_hash_size_filename_and_version_mismatches() {
        let fixture = Fixture::new();
        let mut manifest = fixture.manifest();
        manifest.engine.sha256 = "0".repeat(64);
        fixture.write_manifest(&manifest);
        assert!(matches!(
            fixture.validate_contents(),
            Err(IntegrityError::HashMismatch)
        ));

        manifest.engine.sha256 =
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into();
        manifest.engine.size = 4;
        fixture.write_manifest(&manifest);
        assert!(matches!(
            fixture.validate_contents(),
            Err(IntegrityError::SizeMismatch { .. })
        ));

        manifest.engine.size = 3;
        manifest.engine.filename = "..\\evil.exe".into();
        fixture.write_manifest(&manifest);
        assert!(matches!(
            fixture.validate_contents(),
            Err(IntegrityError::InvalidEngineFilename)
        ));

        manifest.engine.filename = ENGINE_FILENAME.into();
        manifest.product_version = "99.0.0".into();
        fixture.write_manifest(&manifest);
        assert!(matches!(
            fixture.validate_contents(),
            Err(IntegrityError::ProductVersionMismatch)
        ));
    }

    #[test]
    fn strict_manifest_rejects_unknown_fields() {
        let fixture = Fixture::new();
        let raw = fs::read_to_string(fixture.root.join(MANIFEST_FILENAME)).unwrap();
        let raw = raw.replacen('{', r#"{"command":"cmd.exe","#, 1);
        fs::write(fixture.root.join(MANIFEST_FILENAME), raw).unwrap();
        assert!(matches!(
            fixture.validate_contents(),
            Err(IntegrityError::ManifestJson(_))
        ));
    }

    #[test]
    fn rejects_user_owned_or_user_writable_installation() {
        let fixture = Fixture::new();
        assert!(matches!(
            validate_engine_files(&fixture.root),
            Err(IntegrityError::UntrustedOwner { .. }) | Err(IntegrityError::UserWritable { .. })
        ));
    }

    #[test]
    fn privileged_principal_allowlist_is_exact() {
        for sid in TRUSTED_OWNERS {
            assert!(is_trusted_principal(sid));
        }
        assert!(!is_trusted_principal("S-1-1-0"));
        assert!(!is_trusted_principal("S-1-5-11"));
        assert!(!is_trusted_principal("S-1-5-32-545"));
    }

    #[test]
    fn real_program_files_root_is_not_user_writable() {
        let program_files = std::env::var_os("ProgramFiles").expect("ProgramFiles is defined");
        validate_asset_acl(&PathBuf::from(program_files), "Program Files").unwrap();
    }

    #[test]
    #[ignore = "requires scripts/fetch-windows-mihomo.ps1 to have downloaded the engine"]
    fn real_product_manifest_matches_downloaded_engine() {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let manifest: EngineManifest = serde_json::from_reader(
            File::open(repository.join(MANIFEST_FILENAME)).expect("open product engine manifest"),
        )
        .expect("parse product engine manifest");
        validate_manifest(&manifest).expect("validate product engine manifest");

        let engine = repository
            .join("target/windows-engine")
            .join(ENGINE_FILENAME);
        let metadata = engine.metadata().expect("read downloaded engine metadata");
        assert_eq!(metadata.len(), manifest.engine.size);
        assert_eq!(
            sha256_file(&engine).expect("hash downloaded engine"),
            manifest.engine.sha256
        );
    }

    #[test]
    #[ignore = "requires an elevated staged Program Files installation"]
    fn real_program_files_installation_passes_acl_and_hash() {
        let program_files = std::env::var_os("ProgramFiles").expect("ProgramFiles is defined");
        let root = PathBuf::from(program_files).join("TunBridge");
        let validated = validate_engine_files(&root).expect("validate staged product engine");
        assert_eq!(validated.version(), "v1.19.30");
        assert_eq!(validated.size(), 50_100_224);
    }
}
