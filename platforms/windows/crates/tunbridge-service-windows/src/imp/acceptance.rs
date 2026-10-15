use std::{fs::File, io::Read};

use serde::Deserialize;

use super::{
    integrity::{reject_reparse_point, validate_asset_acl, IntegrityError},
    storage::{ProtectedDataDirectory, StorageError},
};

const FAULT_FILENAME: &str = "acceptance-fault.json";
const FAULT_SCHEMA_VERSION: u16 = 1;
const MAX_FAULT_BYTES: u64 = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AcceptanceFault {
    ConfigValidationRejected,
    ControllerNotReady,
    TunNotReady,
    TransparentSelfTestFailed,
    EngineExitsEarly,
    WintunCleanupFailed,
    RuntimeUpstreamUnavailable,
    RuntimeControllerUnavailable,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptanceFaultFile {
    schema_version: u16,
    fault: AcceptanceFault,
}

/// Read a single closed fault selector from the fixed protected runtime root.
///
/// This module is not compiled into default or success-path acceptance builds.
/// No caller path, PID, argv, command, adapter, or route participates in the
/// selector. An invalid protected selector fails closed instead of silently
/// disabling injection.
pub(super) fn active_fault() -> Result<Option<AcceptanceFault>, AcceptanceFaultError> {
    let storage = ProtectedDataDirectory::prepare().map_err(AcceptanceFaultError::Storage)?;
    let root = storage.root();
    reject_reparse_point(root, "acceptance fault root").map_err(AcceptanceFaultError::Integrity)?;
    validate_asset_acl(root, "acceptance fault root").map_err(AcceptanceFaultError::Integrity)?;

    let path = root.join(FAULT_FILENAME);
    if !path.exists() {
        return Ok(None);
    }
    reject_reparse_point(&path, "acceptance fault selector")
        .map_err(AcceptanceFaultError::Integrity)?;
    validate_asset_acl(&path, "acceptance fault selector")
        .map_err(AcceptanceFaultError::Integrity)?;
    let metadata = path.metadata().map_err(AcceptanceFaultError::Io)?;
    if metadata.len() > MAX_FAULT_BYTES {
        return Err(AcceptanceFaultError::TooLarge(metadata.len()));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(AcceptanceFaultError::Io)?
        .take(MAX_FAULT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(AcceptanceFaultError::Io)?;
    if bytes.len() as u64 > MAX_FAULT_BYTES {
        return Err(AcceptanceFaultError::TooLarge(bytes.len() as u64));
    }
    parse_fault(&bytes).map(Some)
}

fn parse_fault(bytes: &[u8]) -> Result<AcceptanceFault, AcceptanceFaultError> {
    let selector: AcceptanceFaultFile =
        serde_json::from_slice(bytes).map_err(AcceptanceFaultError::Json)?;
    if selector.schema_version != FAULT_SCHEMA_VERSION {
        return Err(AcceptanceFaultError::UnsupportedSchema(
            selector.schema_version,
        ));
    }
    Ok(selector.fault)
}

#[derive(Debug, thiserror::Error)]
pub enum AcceptanceFaultError {
    #[error("protected acceptance fault storage failed: {0}")]
    Storage(#[source] StorageError),
    #[error("acceptance fault selector integrity failed: {0}")]
    Integrity(#[source] IntegrityError),
    #[error("acceptance fault selector I/O failed: {0}")]
    Io(#[source] std::io::Error),
    #[error("acceptance fault selector exceeds {MAX_FAULT_BYTES} bytes: {0}")]
    TooLarge(u64),
    #[error("acceptance fault selector JSON is invalid: {0}")]
    Json(#[source] serde_json::Error),
    #[error("unsupported acceptance fault schema {0}")]
    UnsupportedSchema(u16),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_is_a_closed_enum_without_execution_parameters() {
        assert_eq!(
            parse_fault(br#"{"schema_version":1,"fault":"tun_not_ready"}"#).unwrap(),
            AcceptanceFault::TunNotReady
        );
        assert!(parse_fault(br#"{"schema_version":1,"fault":"tun_not_ready","pid":42}"#).is_err());
        assert!(parse_fault(br#"{"schema_version":1,"fault":"run_command"}"#).is_err());
        assert_eq!(
            parse_fault(br#"{"schema_version":1,"fault":"runtime_upstream_unavailable"}"#).unwrap(),
            AcceptanceFault::RuntimeUpstreamUnavailable
        );
        assert!(matches!(
            parse_fault(br#"{"schema_version":2,"fault":"tun_not_ready"}"#),
            Err(AcceptanceFaultError::UnsupportedSchema(2))
        ));
    }
}
