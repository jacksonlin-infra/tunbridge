#[cfg(target_os = "linux")]
fn main() {
    if linux::run().is_err() {
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tunbridge-maintenance-linux is only supported on Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod linux {
    use flate2::read::GzDecoder;
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        path::{Path, PathBuf},
        process::{Command, Stdio},
    };

    const ENGINE: &str = "/usr/libexec/tunbridge/mihomo";
    const MANIFEST: &str = "/usr/share/tunbridge/engine-manifest.json";
    const DATA_ROOT: &str = "/var/lib/tunbridge";
    const CURL: &str = "/usr/bin/curl";
    const SYSTEMCTL: &str = "/usr/bin/systemctl";
    #[cfg(not(feature = "pacman-package"))]
    const PACKAGE_MANAGER: &str = "/usr/bin/apt-get";
    #[cfg(feature = "pacman-package")]
    const PACKAGE_MANAGER: &str = "/usr/bin/pacman";
    #[cfg(not(feature = "pacman-package"))]
    const PACKAGE: &str = "tun-bridge";
    #[cfg(feature = "pacman-package")]
    const PACKAGE: &str = "tunbridge-desktop";
    const MAX_RELEASE: usize = 1024 * 1024;
    const MAX_ARCHIVE: u64 = 64 * 1024 * 1024;
    const MAX_ENGINE: u64 = 128 * 1024 * 1024;

    #[derive(Deserialize)]
    struct Release {
        tag_name: String,
        assets: Vec<Asset>,
    }

    #[derive(Deserialize)]
    struct Asset {
        name: String,
        digest: String,
        browser_download_url: String,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct EngineManifest<'a> {
        schema_version: u16,
        version: &'a str,
        asset_name: &'a str,
        binary_size: u64,
        binary_sha256: &'a str,
    }

    pub fn run() -> Result<(), ()> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(());
        }
        match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
            [verb] if verb == "repair" => repair(),
            [verb] if verb == "update-core" => update_core(),
            [verb] if verb == "uninstall" => uninstall(),
            _ => Err(()),
        }
    }

    fn repair() -> Result<(), ()> {
        tunbridge_setup_linux::LinuxInstallManifest::embedded().map_err(|_| ())?;
        validate_root_file(Path::new(ENGINE), 0o755)?;
        validate_root_file(Path::new(MANIFEST), 0o644)?;
        command_ok(SYSTEMCTL, &["daemon-reload"])?;
        command_ok(SYSTEMCTL, &["enable", "--now", "tunbridge.service"])
    }

    fn uninstall() -> Result<(), ()> {
        validate_root_executable(Path::new(PACKAGE_MANAGER))?;
        #[cfg(not(feature = "pacman-package"))]
        let arguments = ["purge", "--yes", PACKAGE];
        #[cfg(feature = "pacman-package")]
        let arguments = ["--remove", "--nosave", "--noconfirm", PACKAGE];
        command_ok(PACKAGE_MANAGER, &arguments)
    }

    fn update_core() -> Result<(), ()> {
        validate_root_executable(Path::new(CURL))?;
        validate_root_executable(Path::new(SYSTEMCTL))?;
        validate_data_root()?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(Path::new(DATA_ROOT).join("maintenance.lock"))
            .map_err(|_| ())?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(());
        }

        let release_body = curl_memory(
            "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest",
            MAX_RELEASE,
        )?;
        let release: Release = serde_json::from_slice(&release_body).map_err(|_| ())?;
        validate_version(&release.tag_name)?;
        let asset_name = format!("mihomo-linux-amd64-compatible-{}.gz", release.tag_name);
        let asset = release
            .assets
            .iter()
            .find(|asset| asset.name == asset_name)
            .ok_or(())?;
        let archive_sha = asset
            .digest
            .strip_prefix("sha256:")
            .filter(|value| is_lower_hex(value))
            .ok_or(())?;
        validate_download_url(&asset.browser_download_url, &release.tag_name, &asset_name)?;

        let suffix = std::process::id();
        let archive = Path::new(DATA_ROOT).join(format!(".core-update-{suffix}.gz"));
        let candidate = Path::new(DATA_ROOT).join(format!(".core-update-{suffix}.bin"));
        let next_manifest = Path::new(DATA_ROOT).join(format!(".core-update-{suffix}.json"));
        let cleanup = Cleanup([archive.clone(), candidate.clone(), next_manifest.clone()]);
        curl_file(&asset.browser_download_url, &archive)?;
        if fs::metadata(&archive).map_err(|_| ())?.len() > MAX_ARCHIVE
            || sha256_file(&archive)? != archive_sha
        {
            return Err(());
        }
        let (binary_size, binary_sha) = decompress(&archive, &candidate)?;
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o755)).map_err(|_| ())?;
        let manifest = EngineManifest {
            schema_version: 1,
            version: &release.tag_name,
            asset_name: &asset_name,
            binary_size,
            binary_sha256: &binary_sha,
        };
        let bytes = serde_json::to_vec_pretty(&manifest).map_err(|_| ())?;
        write_new(&next_manifest, &bytes, 0o644)?;

        command_ok(SYSTEMCTL, &["stop", "tunbridge.service"])?;
        let engine_backup = PathBuf::from(format!("{ENGINE}.rollback"));
        let manifest_backup = PathBuf::from(format!("{MANIFEST}.rollback"));
        remove_if_regular(&engine_backup)?;
        remove_if_regular(&manifest_backup)?;
        fs::rename(ENGINE, &engine_backup).map_err(|_| ())?;
        if fs::rename(MANIFEST, &manifest_backup).is_err()
            || fs::rename(&candidate, ENGINE).is_err()
            || fs::rename(&next_manifest, MANIFEST).is_err()
        {
            rollback(&engine_backup, &manifest_backup);
            return Err(());
        }
        sync_parent(Path::new(ENGINE))?;
        sync_parent(Path::new(MANIFEST))?;
        if command_ok(SYSTEMCTL, &["start", "tunbridge.service"]).is_err() {
            let _ = command_ok(SYSTEMCTL, &["stop", "tunbridge.service"]);
            rollback(&engine_backup, &manifest_backup);
            let _ = command_ok(SYSTEMCTL, &["start", "tunbridge.service"]);
            return Err(());
        }
        fs::remove_file(engine_backup).map_err(|_| ())?;
        fs::remove_file(manifest_backup).map_err(|_| ())?;
        drop(cleanup);
        Ok(())
    }

    fn rollback(engine_backup: &Path, manifest_backup: &Path) {
        let _ = remove_if_regular(Path::new(ENGINE));
        let _ = remove_if_regular(Path::new(MANIFEST));
        let _ = fs::rename(engine_backup, ENGINE);
        let _ = fs::rename(manifest_backup, MANIFEST);
        let _ = sync_parent(Path::new(ENGINE));
        let _ = sync_parent(Path::new(MANIFEST));
    }

    fn curl_memory(url: &str, max: usize) -> Result<Vec<u8>, ()> {
        let output = Command::new(CURL)
            .args([
                "--silent",
                "--show-error",
                "--fail",
                "--location",
                "--max-time",
                "15",
                "--connect-timeout",
                "5",
                "--max-filesize",
                &max.to_string(),
                url,
            ])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|_| ())?;
        if !output.status.success() || output.stdout.is_empty() || output.stdout.len() > max {
            return Err(());
        }
        Ok(output.stdout)
    }

    fn curl_file(url: &str, destination: &Path) -> Result<(), ()> {
        let destination = destination.to_str().ok_or(())?;
        let status = Command::new(CURL)
            .args([
                "--silent",
                "--show-error",
                "--fail",
                "--location",
                "--max-time",
                "180",
                "--connect-timeout",
                "10",
                "--max-filesize",
                &MAX_ARCHIVE.to_string(),
                "--output",
                destination,
                url,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| ())?;
        if !status.success() {
            return Err(());
        }
        let metadata = fs::symlink_metadata(destination).map_err(|_| ())?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.nlink() != 1 {
            return Err(());
        }
        Ok(())
    }

    fn decompress(archive: &Path, candidate: &Path) -> Result<(u64, String), ()> {
        let input = File::open(archive).map_err(|_| ())?;
        let mut decoder = GzDecoder::new(input).take(MAX_ENGINE + 1);
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o700)
            .open(candidate)
            .map_err(|_| ())?;
        let mut digest = Sha256::new();
        let mut size = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = decoder.read(&mut buffer).map_err(|_| ())?;
            if count == 0 {
                break;
            }
            size += count as u64;
            if size > MAX_ENGINE {
                return Err(());
            }
            digest.update(&buffer[..count]);
            output.write_all(&buffer[..count]).map_err(|_| ())?;
        }
        if size < 1024 * 1024 {
            return Err(());
        }
        output.sync_all().map_err(|_| ())?;
        Ok((size, format!("{:x}", digest.finalize())))
    }

    fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), ()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(mode)
            .open(path)
            .map_err(|_| ())?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| ())
    }

    fn validate_data_root() -> Result<(), ()> {
        let metadata = fs::symlink_metadata(DATA_ROOT).map_err(|_| ())?;
        if metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o777 == 0o700 {
            Ok(())
        } else {
            Err(())
        }
    }

    fn validate_root_file(path: &Path, mode: u32) -> Result<(), ()> {
        let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
        if metadata.is_file()
            && metadata.uid() == 0
            && metadata.mode() & 0o777 == mode
            && metadata.nlink() == 1
        {
            Ok(())
        } else {
            Err(())
        }
    }

    fn validate_root_executable(path: &Path) -> Result<(), ()> {
        let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
        if metadata.is_file()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && metadata.nlink() == 1
        {
            Ok(())
        } else {
            Err(())
        }
    }

    fn command_ok(program: &str, args: &[&str]) -> Result<(), ()> {
        validate_root_executable(Path::new(program))?;
        Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| ())
            .and_then(|status| status.success().then_some(()).ok_or(()))
    }

    fn validate_version(value: &str) -> Result<(), ()> {
        if value.starts_with('v')
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
        {
            Ok(())
        } else {
            Err(())
        }
    }

    fn validate_download_url(url: &str, version: &str, asset: &str) -> Result<(), ()> {
        let expected =
            format!("https://github.com/MetaCubeX/mihomo/releases/download/{version}/{asset}");
        if url == expected {
            Ok(())
        } else {
            Err(())
        }
    }

    fn is_lower_hex(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    fn sha256_file(path: &Path) -> Result<String, ()> {
        let mut file = File::open(path).map_err(|_| ())?;
        let mut hash = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer).map_err(|_| ())?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
        }
        Ok(format!("{:x}", hash.finalize()))
    }

    fn remove_if_regular(path: &Path) -> Result<(), ()> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() && metadata.uid() == 0 && metadata.nlink() == 1 => {
                fs::remove_file(path).map_err(|_| ())
            }
            Ok(_) => Err(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(()),
        }
    }

    fn sync_parent(path: &Path) -> Result<(), ()> {
        File::open(path.parent().ok_or(())?)
            .and_then(|file| file.sync_all())
            .map_err(|_| ())
    }

    struct Cleanup([PathBuf; 3]);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            for path in &self.0 {
                let _ = remove_if_regular(path);
            }
        }
    }

    use std::os::fd::AsRawFd;
}
