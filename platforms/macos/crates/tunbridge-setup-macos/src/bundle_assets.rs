//! Fixed-path, no-follow resolution of generation assets from an authenticated
//! macOS App Bundle executable.
//!
//! The native XPC boundary is responsible for obtaining `executable_path` from
//! a public Security.framework `SecCode` guest lookup and for checking the same
//! exact code requirement both before and after this resolver runs.

use crate::{
    bootstrap_assets::ValidatedGenerationAssets,
    bootstrap_protocol::{BootstrapCaller, BootstrapError, BootstrapExecutor, GenerationMaterial},
    bundle_inspection::BOOTSTRAP_APP_POLICY_PATH,
    engine_asset::{BUNDLE_ENGINE_MANIFEST_PATH, BUNDLE_ENGINE_PATH},
    generation_store::GenerationStore,
};
use libc::{O_CLOEXEC, O_NOFOLLOW};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const MAX_POLICY_BYTES: u64 = 4096;
const MAX_MANIFEST_BYTES: u64 = 4096;
const MAX_ENGINE_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleAssetError {
    InvalidExecutablePath,
    UnsafeBundleLayout,
    UnsafeAsset,
    Oversize,
    Io,
    ValidationFailed,
    CodeIdentityChanged,
}

/// The path must have been returned for the authenticated PID by the native
/// code-signing verifier. It is never accepted from an XPC request frame.
#[derive(Debug, Clone)]
struct FixedBundleAssetResolver {
    executable_path: PathBuf,
}

pub trait BundleCodeVerifier {
    fn verified_executable(
        &mut self,
        caller: &BootstrapCaller,
    ) -> Result<PathBuf, BundleAssetError>;
}

pub struct CodeVerifiedBundleResolver<V> {
    verifier: V,
}

pub trait BundleAssetResolver {
    fn resolve(
        &mut self,
        caller: &BootstrapCaller,
        material: &GenerationMaterial,
    ) -> Result<ValidatedGenerationAssets, BundleAssetError>;
}

pub struct StoreBootstrapExecutor<R> {
    resolver: R,
    store: GenerationStore,
}

impl FixedBundleAssetResolver {
    fn new(executable_path: PathBuf) -> Self {
        Self { executable_path }
    }

    fn bundle_root(&self) -> Result<&Path, BundleAssetError> {
        let macos = self
            .executable_path
            .parent()
            .ok_or(BundleAssetError::InvalidExecutablePath)?;
        let contents = macos
            .parent()
            .ok_or(BundleAssetError::InvalidExecutablePath)?;
        let app = contents
            .parent()
            .ok_or(BundleAssetError::InvalidExecutablePath)?;
        if self.executable_path.file_name().and_then(|v| v.to_str()) != Some("tunbridge-desktop")
            || macos.file_name().and_then(|v| v.to_str()) != Some("MacOS")
            || contents.file_name().and_then(|v| v.to_str()) != Some("Contents")
            || app.extension().and_then(|v| v.to_str()) != Some("app")
        {
            return Err(BundleAssetError::InvalidExecutablePath);
        }
        Ok(app)
    }
}

impl<V> CodeVerifiedBundleResolver<V> {
    pub fn new(verifier: V) -> Self {
        Self { verifier }
    }
}

impl<F> BundleCodeVerifier for F
where
    F: FnMut(&BootstrapCaller) -> Result<PathBuf, BundleAssetError>,
{
    fn verified_executable(
        &mut self,
        caller: &BootstrapCaller,
    ) -> Result<PathBuf, BundleAssetError> {
        self(caller)
    }
}

impl<V: BundleCodeVerifier> BundleAssetResolver for CodeVerifiedBundleResolver<V> {
    fn resolve(
        &mut self,
        caller: &BootstrapCaller,
        material: &GenerationMaterial,
    ) -> Result<ValidatedGenerationAssets, BundleAssetError> {
        let before = self.verifier.verified_executable(caller)?;
        let assets = FixedBundleAssetResolver::new(before.clone()).resolve(caller, material)?;
        let after = self.verifier.verified_executable(caller)?;
        if before != after {
            return Err(BundleAssetError::CodeIdentityChanged);
        }
        Ok(assets)
    }
}

impl BundleAssetResolver for FixedBundleAssetResolver {
    fn resolve(
        &mut self,
        caller: &BootstrapCaller,
        material: &GenerationMaterial,
    ) -> Result<ValidatedGenerationAssets, BundleAssetError> {
        let root = self.bundle_root()?;
        let executable = checked_executable_metadata(&self.executable_path, caller.uid)?;
        let expected_uid = executable.uid();
        let expected_gid = executable.gid();

        for relative in [
            "",
            "Contents",
            "Contents/MacOS",
            "Contents/Resources",
            "Contents/Resources/tunbridge-engine",
        ] {
            checked_directory(&root.join(relative), expected_uid, expected_gid)?;
        }

        let policy = read_checked(
            &root.join(BOOTSTRAP_APP_POLICY_PATH),
            expected_uid,
            expected_gid,
            MAX_POLICY_BYTES,
            false,
        )?;
        let manifest = read_checked(
            &root.join(BUNDLE_ENGINE_MANIFEST_PATH),
            expected_uid,
            expected_gid,
            MAX_MANIFEST_BYTES,
            false,
        )?;
        let engine = read_checked(
            &root.join(BUNDLE_ENGINE_PATH),
            expected_uid,
            expected_gid,
            MAX_ENGINE_BYTES,
            true,
        )?;
        ValidatedGenerationAssets::validate(caller, material, policy, manifest, engine)
            .map_err(|_| BundleAssetError::ValidationFailed)
    }
}

/// Internal-only resolver used after the root helper has admitted an ad-hoc
/// caller. The policy is transported in the bounded XPC bootstrap request so
/// it can contain the final App cdhash without creating a bundle-signature
/// self-reference; engine bytes still come only from the authenticated App
/// bundle and are checked against the declared digests.
#[cfg(feature = "macos-development-installer")]
pub fn resolve_development_bundle(
    executable_path: &Path,
    caller: &BootstrapCaller,
    material: &GenerationMaterial,
    policy_json: Vec<u8>,
) -> Result<ValidatedGenerationAssets, BundleAssetError> {
    let resolver = FixedBundleAssetResolver::new(executable_path.to_owned());
    let root = resolver.bundle_root()?;
    let executable = checked_executable_metadata(executable_path, caller.uid)?;
    let expected_uid = executable.uid();
    let expected_gid = executable.gid();
    for relative in [
        "",
        "Contents",
        "Contents/MacOS",
        "Contents/Resources",
        "Contents/Resources/tunbridge-engine",
    ] {
        checked_directory(&root.join(relative), expected_uid, expected_gid)?;
    }
    let manifest = read_checked(
        &root.join(BUNDLE_ENGINE_MANIFEST_PATH),
        expected_uid,
        expected_gid,
        MAX_MANIFEST_BYTES,
        false,
    )?;
    let engine = read_checked(
        &root.join(BUNDLE_ENGINE_PATH),
        expected_uid,
        expected_gid,
        MAX_ENGINE_BYTES,
        true,
    )?;
    ValidatedGenerationAssets::validate_development(caller, material, policy_json, manifest, engine)
        .map_err(|_| BundleAssetError::ValidationFailed)
}

impl<R> StoreBootstrapExecutor<R> {
    pub fn new(resolver: R, store: GenerationStore) -> Self {
        Self { resolver, store }
    }
}

impl<R: BundleAssetResolver> BootstrapExecutor for StoreBootstrapExecutor<R> {
    fn prepare_generation(
        &mut self,
        caller: &BootstrapCaller,
        material: &GenerationMaterial,
    ) -> Result<(), BootstrapError> {
        let assets = self
            .resolver
            .resolve(caller, material)
            .map_err(|_| BootstrapError::ExecutionFailed)?;
        self.store
            .prepare_generation(&material.transaction_id, &assets)
            .map_err(|_| BootstrapError::ExecutionFailed)
    }

    fn commit_generation(&mut self, transaction_id: &str) -> Result<(), BootstrapError> {
        self.store
            .commit_generation(transaction_id)
            .map_err(|_| BootstrapError::ExecutionFailed)
    }

    fn rollback_generation(&mut self, transaction_id: &str) -> Result<(), BootstrapError> {
        self.store
            .rollback_generation(transaction_id)
            .map_err(|_| BootstrapError::ExecutionFailed)
    }
}

fn checked_directory(path: &Path, uid: u32, gid: u32) -> Result<(), BundleAssetError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| BundleAssetError::Io)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o022 != 0
    {
        return Err(BundleAssetError::UnsafeBundleLayout);
    }
    Ok(())
}

fn checked_file_metadata(
    path: &Path,
    uid: u32,
    gid: Option<u32>,
) -> Result<fs::Metadata, BundleAssetError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| BundleAssetError::Io)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != uid
        || gid.is_some_and(|value| metadata.gid() != value)
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
    {
        return Err(BundleAssetError::UnsafeAsset);
    }
    Ok(metadata)
}

fn checked_executable_metadata(
    path: &Path,
    caller_uid: u32,
) -> Result<fs::Metadata, BundleAssetError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| BundleAssetError::Io)?;
    if !metadata.file_type().is_file()
        || !allowed_bundle_owner(metadata.uid(), caller_uid)
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(BundleAssetError::UnsafeAsset);
    }
    Ok(metadata)
}

fn allowed_bundle_owner(owner_uid: u32, caller_uid: u32) -> bool {
    owner_uid == 0 || owner_uid == caller_uid
}

fn read_checked(
    path: &Path,
    uid: u32,
    gid: u32,
    maximum: u64,
    executable: bool,
) -> Result<Vec<u8>, BundleAssetError> {
    let path_metadata = checked_file_metadata(path, uid, Some(gid))?;
    if path_metadata.len() == 0 || path_metadata.len() > maximum {
        return Err(BundleAssetError::Oversize);
    }
    if executable && path_metadata.mode() & 0o111 == 0 {
        return Err(BundleAssetError::UnsafeAsset);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_CLOEXEC | O_NOFOLLOW)
        .open(path)
        .map_err(|_| BundleAssetError::Io)?;
    let before = file.metadata().map_err(|_| BundleAssetError::Io)?;
    if before.dev() != path_metadata.dev() || before.ino() != path_metadata.ino() {
        return Err(BundleAssetError::UnsafeAsset);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.by_ref()
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BundleAssetError::Io)?;
    if bytes.len() as u64 != before.len() || bytes.len() as u64 > maximum {
        return Err(BundleAssetError::Oversize);
    }
    let after = file.metadata().map_err(|_| BundleAssetError::Io)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        return Err(BundleAssetError::UnsafeAsset);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{bootstrap_protocol::GenerationMaterial, generation_store::GenerationPaths};
    use sha2::{Digest, Sha256};
    use std::{
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU64, Ordering},
    };

    const CDHASH: &str = "1111111111111111111111111111111111111111";
    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        root: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let unique = format!(
                "tunbridge-bundle-assets-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            );
            let root = std::env::temp_dir().join(unique);
            fs::create_dir(&root).unwrap();
            Self { root }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn digest(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }
    fn caller() -> BootstrapCaller {
        BootstrapCaller {
            pid: 501,
            uid: unsafe { libc::geteuid() },
            audit_session_id: 42,
            team_id: "ABCDE12345".into(),
            cdhash: CDHASH.into(),
        }
    }
    fn build_bundle(root: &Path) -> (PathBuf, GenerationMaterial) {
        let app = root.join("TunBridge.app");
        for relative in ["Contents/MacOS", "Contents/Resources/tunbridge-engine"] {
            fs::create_dir_all(app.join(relative)).unwrap();
        }
        let executable = app.join("Contents/MacOS/tunbridge-desktop");
        fs::write(&executable, b"desktop").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let policy = serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"teamId":"ABCDE12345","appSigningIdentifier":"com.tunbridge.desktop","allowedCdhashes":[CDHASH]})).unwrap();
        let engine = b"engine-fixture".to_vec();
        let manifest = serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"version":"v1.19.28","targetTriple":"aarch64-apple-darwin","binarySize":engine.len(),"binarySha256":digest(&engine)})).unwrap();
        fs::write(app.join(BOOTSTRAP_APP_POLICY_PATH), &policy).unwrap();
        fs::write(app.join(BUNDLE_ENGINE_MANIFEST_PATH), &manifest).unwrap();
        let engine_path = app.join(BUNDLE_ENGINE_PATH);
        fs::write(&engine_path, &engine).unwrap();
        fs::set_permissions(engine_path, fs::Permissions::from_mode(0o755)).unwrap();
        let material = GenerationMaterial {
            transaction_id: "0123456789abcdef0123456789abcdef".into(),
            caller_cdhash: CDHASH.into(),
            policy_sha256: digest(&policy),
            engine_manifest_sha256: digest(&manifest),
            engine_sha256: digest(&engine),
            engine_size: engine.len() as u64,
            target_triple: "aarch64-apple-darwin".into(),
        };
        (executable, material)
    }

    #[test]
    fn fixed_bundle_assets_resolve_and_drive_generation_store() {
        let bundle = Fixture::new();
        let (executable, material) = build_bundle(&bundle.root);
        let mut resolver =
            CodeVerifiedBundleResolver::new(|_: &BootstrapCaller| Ok(executable.clone()));
        assert!(resolver.resolve(&caller(), &material).is_ok());

        let system = Fixture::new();
        let paths = GenerationPaths::fixture(&system.root);
        let state_root = system.root.join("Application Support/TunBridge/Install");
        let engine_root = system.root.join("Application Support/TunBridge/Engine");
        fs::create_dir_all(&state_root).unwrap();
        fs::create_dir_all(&engine_root).unwrap();
        fs::create_dir_all(system.root.join("PrivilegedHelperTools")).unwrap();
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&engine_root, fs::Permissions::from_mode(0o755)).unwrap();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let store = GenerationStore::open(paths, uid, gid).unwrap();
        let mut executor = StoreBootstrapExecutor::new(resolver, store);
        executor.prepare_generation(&caller(), &material).unwrap();
        executor
            .commit_generation(&material.transaction_id)
            .unwrap();
    }

    #[test]
    fn injected_path_symlink_hardlink_and_digest_substitution_fail_closed() {
        let fixture = Fixture::new();
        let (executable, material) = build_bundle(&fixture.root);
        let mut wrong = FixedBundleAssetResolver::new(fixture.root.join("tunbridge-desktop"));
        assert_eq!(
            wrong.resolve(&caller(), &material),
            Err(BundleAssetError::InvalidExecutablePath)
        );

        let policy = fixture
            .root
            .join("TunBridge.app")
            .join(BOOTSTRAP_APP_POLICY_PATH);
        let hardlink = fixture.root.join("policy-copy");
        fs::hard_link(&policy, &hardlink).unwrap();
        let mut resolver = FixedBundleAssetResolver::new(executable.clone());
        assert_eq!(
            resolver.resolve(&caller(), &material),
            Err(BundleAssetError::UnsafeAsset)
        );
        fs::remove_file(hardlink).unwrap();

        fs::write(&policy, b"substituted").unwrap();
        assert_eq!(
            resolver.resolve(&caller(), &material),
            Err(BundleAssetError::ValidationFailed)
        );

        fs::remove_file(&policy).unwrap();
        std::os::unix::fs::symlink("/dev/null", &policy).unwrap();
        assert_eq!(
            resolver.resolve(&caller(), &material),
            Err(BundleAssetError::UnsafeAsset)
        );
    }

    #[test]
    fn executable_identity_change_after_asset_read_fails_closed() {
        let fixture = Fixture::new();
        let (executable, material) = build_bundle(&fixture.root);
        let changed = fixture
            .root
            .join("Replacement.app/Contents/MacOS/tunbridge-desktop");
        let mut paths = vec![executable, changed].into_iter();
        let mut resolver = CodeVerifiedBundleResolver::new(move |_: &BootstrapCaller| {
            paths.next().ok_or(BundleAssetError::CodeIdentityChanged)
        });
        assert_eq!(
            resolver.resolve(&caller(), &material),
            Err(BundleAssetError::CodeIdentityChanged)
        );
    }

    #[test]
    fn bundle_owner_must_be_root_or_authenticated_caller() {
        assert!(allowed_bundle_owner(0, 501));
        assert!(allowed_bundle_owner(501, 501));
        assert!(!allowed_bundle_owner(502, 501));
    }
}
