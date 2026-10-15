use plist::{Dictionary, Value};
use std::collections::BTreeMap;

pub const APP_BUNDLE_ID: &str = "com.tunbridge.desktop";
pub const HELPER_BUNDLE_ID: &str = "com.tunbridge.desktop.helper";
pub const MACH_SERVICE_NAME: &str = "com.tunbridge.desktop.helper";
pub const HELPER_EXECUTABLE: &str = "tunbridge-helper-macos";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataError {
    InvalidVersion,
    InvalidRequirement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosBundleMetadata {
    version: String,
    app_requirement: String,
    helper_requirement: String,
}

impl MacosBundleMetadata {
    pub fn new(
        version: impl Into<String>,
        team_id: impl Into<String>,
    ) -> Result<Self, MetadataError> {
        let team_id = team_id.into();
        let value = Self {
            version: version.into(),
            app_requirement: designated_requirement(APP_BUNDLE_ID, &team_id)?,
            helper_requirement: designated_requirement(HELPER_BUNDLE_ID, &team_id)?,
        };
        if !valid_version(&value.version) {
            return Err(MetadataError::InvalidVersion);
        }
        Ok(value)
    }

    pub fn monterey_helper_info(&self) -> Value {
        dictionary([
            ("CFBundleIdentifier", Value::String(HELPER_BUNDLE_ID.into())),
            ("CFBundleName", Value::String("TunBridge Helper".into())),
            (
                "CFBundleExecutable",
                Value::String(HELPER_EXECUTABLE.into()),
            ),
            ("CFBundlePackageType", Value::String("BNDL".into())),
            ("CFBundleVersion", Value::String(self.version.clone())),
            (
                "CFBundleShortVersionString",
                Value::String(self.version.clone()),
            ),
            (
                "SMAuthorizedClients",
                Value::Array(vec![Value::String(self.app_requirement.clone())]),
            ),
        ])
    }

    pub fn monterey_app_info_fragment(&self) -> Value {
        let mut privileged = Dictionary::new();
        privileged.insert(
            HELPER_BUNDLE_ID.into(),
            Value::String(self.helper_requirement.clone()),
        );
        dictionary([("SMPrivilegedExecutables", Value::Dictionary(privileged))])
    }

    pub fn modern_launch_daemon(&self) -> Value {
        let mut mach_services = Dictionary::new();
        mach_services.insert(MACH_SERVICE_NAME.into(), Value::Boolean(true));
        dictionary([
            ("Label", Value::String(HELPER_BUNDLE_ID.into())),
            (
                "BundleProgram",
                Value::String(format!("Contents/MacOS/{HELPER_EXECUTABLE}")),
            ),
            ("MachServices", Value::Dictionary(mach_services)),
            ("RunAtLoad", Value::Boolean(false)),
            ("ProcessType", Value::String("Interactive".into())),
        ])
    }

    pub fn to_xml(value: &Value) -> Result<Vec<u8>, MetadataError> {
        let mut output = Vec::new();
        value
            .to_writer_xml(&mut output)
            .map_err(|_| MetadataError::InvalidRequirement)?;
        Ok(output)
    }
}

fn dictionary<const N: usize>(entries: [(&str, Value); N]) -> Value {
    Value::Dictionary(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .collect(),
    )
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        && value.split('.').all(|component| !component.is_empty())
}

fn designated_requirement(identifier: &str, team_id: &str) -> Result<String, MetadataError> {
    if team_id.len() != 10
        || !team_id
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(MetadataError::InvalidRequirement);
    }
    Ok(format!(
        "anchor apple generic and identifier \"{identifier}\" and certificate leaf[subject.OU] = \"{team_id}\" and flags runtime"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP_REQUIREMENT: &str = "anchor apple generic and identifier \"com.tunbridge.desktop\" and certificate leaf[subject.OU] = \"ABCDE12345\" and flags runtime";
    const HELPER_REQUIREMENT: &str = "anchor apple generic and identifier \"com.tunbridge.desktop.helper\" and certificate leaf[subject.OU] = \"ABCDE12345\" and flags runtime";

    fn metadata() -> MacosBundleMetadata {
        MacosBundleMetadata::new("0.2.3", "ABCDE12345").unwrap()
    }

    #[test]
    fn monterey_metadata_has_exact_bidirectional_requirements() {
        let helper = metadata().monterey_helper_info();
        assert_eq!(
            helper
                .as_dictionary()
                .unwrap()
                .get("SMAuthorizedClients")
                .unwrap()
                .as_array()
                .unwrap(),
            &[Value::String(APP_REQUIREMENT.into())]
        );
        let app = metadata().monterey_app_info_fragment();
        assert_eq!(
            app.as_dictionary()
                .unwrap()
                .get("SMPrivilegedExecutables")
                .unwrap()
                .as_dictionary()
                .unwrap()
                .get(HELPER_BUNDLE_ID),
            Some(&Value::String(HELPER_REQUIREMENT.into()))
        );
    }

    #[test]
    fn modern_daemon_is_on_demand_and_uses_only_fixed_bundle_program() {
        let daemon = metadata().modern_launch_daemon();
        let daemon = daemon.as_dictionary().unwrap();
        assert_eq!(daemon.get("RunAtLoad"), Some(&Value::Boolean(false)));
        assert_eq!(
            daemon.get("BundleProgram"),
            Some(&Value::String(
                "Contents/MacOS/tunbridge-helper-macos".into()
            ))
        );
        assert_eq!(
            daemon
                .get("MachServices")
                .unwrap()
                .as_dictionary()
                .unwrap()
                .get(MACH_SERVICE_NAME),
            Some(&Value::Boolean(true))
        );
        let xml = MacosBundleMetadata::to_xml(&Value::Dictionary(daemon.clone())).unwrap();
        let text = String::from_utf8(xml).unwrap();
        assert!(!text.contains("sudo"));
        assert!(!text.contains("ProgramArguments"));
        assert!(!text.contains("/bin/sh"));
    }

    #[test]
    fn malformed_versions_and_team_identifiers_fail_closed() {
        assert_eq!(
            MacosBundleMetadata::new("../0.2.3", "ABCDE12345"),
            Err(MetadataError::InvalidVersion)
        );
        assert_eq!(
            MacosBundleMetadata::new("0.2.3", "team/../bad"),
            Err(MetadataError::InvalidRequirement)
        );
    }

    #[test]
    fn bootstrap_requirements_are_stable_and_never_embed_cdhashes() {
        let metadata = metadata();
        assert_eq!(metadata.app_requirement, APP_REQUIREMENT);
        assert_eq!(metadata.helper_requirement, HELPER_REQUIREMENT);
        assert!(!metadata.app_requirement.contains("cdhash"));
        assert!(!metadata.helper_requirement.contains("cdhash"));
    }
}
