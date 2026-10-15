//! Closed M2B-5 acceptance facts from one fixed protected selector.
//!
//! This module is absent from every default, lifecycle, fault and rejection
//! artifact. It accepts no caller path, PID, target, count or threshold.

use std::{fs::File, io::Read};

use serde::Deserialize;

use super::{
    integrity::{reject_reparse_point, validate_asset_acl, IntegrityError},
    storage::{ProtectedDataDirectory, StorageError},
};

const SELECTOR_FILENAME: &str = "acceptance-m2b5.json";
const SELECTOR_SCHEMA_VERSION: u16 = 1;
const MAX_SELECTOR_BYTES: u64 = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum M2b5Selector {
    TelemetryTargetA,
    TelemetryAlternatingTargets,
    TelemetryUnknown,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectorFile {
    schema_version: u16,
    selector: M2b5Selector,
}

pub(super) fn active_selector() -> Result<Option<M2b5Selector>, M2b5SelectorError> {
    let storage = ProtectedDataDirectory::prepare().map_err(M2b5SelectorError::Storage)?;
    let root = storage.root();
    reject_reparse_point(root, "M2B-5 acceptance root").map_err(M2b5SelectorError::Integrity)?;
    validate_asset_acl(root, "M2B-5 acceptance root").map_err(M2b5SelectorError::Integrity)?;

    let path = root.join(SELECTOR_FILENAME);
    if !path.exists() {
        return Ok(None);
    }
    reject_reparse_point(&path, "M2B-5 acceptance selector")
        .map_err(M2b5SelectorError::Integrity)?;
    validate_asset_acl(&path, "M2B-5 acceptance selector").map_err(M2b5SelectorError::Integrity)?;
    let metadata = path.metadata().map_err(M2b5SelectorError::Io)?;
    if metadata.len() > MAX_SELECTOR_BYTES {
        return Err(M2b5SelectorError::TooLarge(metadata.len()));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(M2b5SelectorError::Io)?
        .take(MAX_SELECTOR_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(M2b5SelectorError::Io)?;
    if bytes.len() as u64 > MAX_SELECTOR_BYTES {
        return Err(M2b5SelectorError::TooLarge(bytes.len() as u64));
    }
    parse_selector(&bytes).map(Some)
}

fn parse_selector(bytes: &[u8]) -> Result<M2b5Selector, M2b5SelectorError> {
    let selector: SelectorFile = serde_json::from_slice(bytes).map_err(M2b5SelectorError::Json)?;
    if selector.schema_version != SELECTOR_SCHEMA_VERSION {
        return Err(M2b5SelectorError::UnsupportedSchema(
            selector.schema_version,
        ));
    }
    Ok(selector.selector)
}

#[derive(Debug, thiserror::Error)]
pub(super) enum M2b5SelectorError {
    #[error("protected M2B-5 acceptance storage failed: {0}")]
    Storage(#[source] StorageError),
    #[error("M2B-5 acceptance selector integrity failed: {0}")]
    Integrity(#[source] IntegrityError),
    #[error("M2B-5 acceptance selector I/O failed: {0}")]
    Io(#[source] std::io::Error),
    #[error("M2B-5 acceptance selector exceeds {MAX_SELECTOR_BYTES} bytes: {0}")]
    TooLarge(u64),
    #[error("M2B-5 acceptance selector JSON is invalid: {0}")]
    Json(#[source] serde_json::Error),
    #[error("unsupported M2B-5 acceptance selector schema {0}")]
    UnsupportedSchema(u16),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_is_closed_and_has_no_target_count_or_execution_fields() {
        assert_eq!(
            parse_selector(br#"{"schema_version":1,"selector":"telemetry_alternating_targets"}"#)
                .unwrap(),
            M2b5Selector::TelemetryAlternatingTargets
        );
        assert!(parse_selector(
            br#"{"schema_version":1,"selector":"telemetry_target_a","count":64}"#
        )
        .is_err());
        assert!(parse_selector(
            br#"{"schema_version":1,"selector":"telemetry_target_a","target":"example.com"}"#
        )
        .is_err());
        assert!(parse_selector(
            br#"{"schema_version":1,"selector":"run_command","command":"cmd"}"#
        )
        .is_err());
    }
}
