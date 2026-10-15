use plist::Value;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use tunbridge_desktop_contract::adapter::{
    AdapterError, AdapterErrorCode, Diagnostics, SystemInformation,
};

const SYSTEM_VERSION_PLIST: &str = "/System/Library/CoreServices/SystemVersion.plist";
const MAX_SYSTEM_VERSION_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, Default)]
pub struct MacosDiagnostics;

impl Diagnostics for MacosDiagnostics {
    fn system_information(&self) -> Result<SystemInformation, AdapterError> {
        let path = Path::new(SYSTEM_VERSION_PLIST);
        let mut file = File::open(path).map_err(|_| unavailable())?;
        let metadata = file.metadata().map_err(|_| unavailable())?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
            || metadata.len() > MAX_SYSTEM_VERSION_BYTES
        {
            return Err(invalid_data());
        }
        let mut bytes = Vec::new();
        file.by_ref()
            .take(MAX_SYSTEM_VERSION_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| unavailable())?;
        if bytes.len() as u64 > MAX_SYSTEM_VERSION_BYTES {
            return Err(invalid_data());
        }
        parse_system_version(&bytes)
    }
}

fn parse_system_version(bytes: &[u8]) -> Result<SystemInformation, AdapterError> {
    let value = Value::from_reader(std::io::Cursor::new(bytes)).map_err(|_| invalid_data())?;
    let dictionary = value.as_dictionary().ok_or_else(invalid_data)?;
    let field = |name: &str| {
        dictionary
            .get(name)
            .and_then(Value::as_string)
            .filter(|value| {
                !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
            })
            .map(str::to_owned)
            .ok_or_else(invalid_data)
    };
    Ok(SystemInformation {
        os_name: field("ProductName")?,
        os_release: field("ProductUserVisibleVersion")?,
        build: field("ProductBuildVersion")?,
        architecture: std::env::consts::ARCH.to_owned(),
    })
}

const fn unavailable() -> AdapterError {
    AdapterError {
        code: AdapterErrorCode::Unavailable,
        safe_message: "macOS system information is unavailable.",
        retryable: true,
    }
}

const fn invalid_data() -> AdapterError {
    AdapterError {
        code: AdapterErrorCode::InvalidData,
        safe_message: "macOS system information is invalid.",
        retryable: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bounded_system_version_fields() {
        let fixture = br#"<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
          "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
          <key>ProductName</key><string>macOS</string>
          <key>ProductUserVisibleVersion</key><string>12.7.6</string>
          <key>ProductBuildVersion</key><string>21H1320</string>
        </dict></plist>"#;
        let information = parse_system_version(fixture).unwrap();
        assert_eq!(information.os_name, "macOS");
        assert_eq!(information.os_release, "12.7.6");
        assert_eq!(information.build, "21H1320");
    }

    #[test]
    fn rejects_missing_or_control_fields() {
        let missing = br#"<?xml version="1.0"?><plist version="1.0"><dict>
          <key>ProductName</key><string>macOS</string>
        </dict></plist>"#;
        assert_eq!(
            parse_system_version(missing).unwrap_err().code,
            AdapterErrorCode::InvalidData
        );
    }

    #[test]
    fn reads_native_system_information_without_mutation() {
        let information = MacosDiagnostics.system_information().unwrap();
        assert_eq!(information.os_name, "macOS");
        assert!(!information.os_release.is_empty());
        assert!(!information.build.is_empty());
        assert!(matches!(
            information.architecture.as_str(),
            "aarch64" | "x86_64"
        ));
    }
}
