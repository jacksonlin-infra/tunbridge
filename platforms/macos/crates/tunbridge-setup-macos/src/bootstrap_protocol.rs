//! Restricted first-install protocol for provisioning root-owned assets.
//!
//! The native XPC bridge must obtain `BootstrapAuditFacts` from the connection's
//! kernel audit token and code-signing inspection. Request JSON is never a
//! source of caller identity or filesystem paths.

use crate::engine_asset::MAX_ENGINE_BYTES;
use serde::{Deserialize, Serialize};

const BOOTSTRAP_SCHEMA_VERSION: u16 = 1;
const MAX_BOOTSTRAP_FRAME_BYTES: usize = 4096;
const APP_SIGNING_IDENTIFIER: &str = "com.tunbridge.desktop";
const CDHASH_HEX_BYTES: usize = 40;
const SHA256_HEX_BYTES: usize = 64;
const TRANSACTION_ID_HEX_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapAuditFacts {
    pub pid: u32,
    pub effective_uid: u32,
    pub real_uid: u32,
    pub audit_session_id: u32,
    pub apple_generic_anchor: bool,
    pub team_id: String,
    pub signing_identifier: String,
    pub cdhash: String,
    pub hardened_runtime: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapAdmissionPolicy {
    team_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapCaller {
    pub pid: u32,
    pub uid: u32,
    pub audit_session_id: u32,
    pub team_id: String,
    pub cdhash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationMaterial {
    pub transaction_id: String,
    pub caller_cdhash: String,
    pub policy_sha256: String,
    pub engine_manifest_sha256: String,
    pub engine_sha256: String,
    pub engine_size: u64,
    pub target_triple: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapError {
    InvalidPolicy,
    InvalidAuditToken,
    RequirementMismatch,
    InvalidFrame,
    InvalidRequest,
    InvalidState,
    TransactionMismatch,
    ExecutionFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionState {
    Ready,
    Prepared,
    Closed,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum BootstrapRequest {
    PrepareGeneration {
        schema_version: u16,
        transaction_id: String,
        caller_cdhash: String,
        policy_sha256: String,
        engine_manifest_sha256: String,
        engine_sha256: String,
        engine_size: u64,
        target_triple: String,
    },
    Commit {
        schema_version: u16,
        transaction_id: String,
    },
    Rollback {
        schema_version: u16,
        transaction_id: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapOutcome {
    Prepared,
    Committed,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BootstrapResponse {
    pub schema_version: u16,
    pub transaction_id: String,
    pub outcome: BootstrapOutcome,
}

pub trait BootstrapExecutor {
    /// Resolve assets only from the authenticated caller's signed App bundle,
    /// verify the declared digests, and stage root-owned replacements.
    fn prepare_generation(
        &mut self,
        caller: &BootstrapCaller,
        material: &GenerationMaterial,
    ) -> Result<(), BootstrapError>;

    /// Commit the already prepared transaction and discard its rollback copy.
    fn commit_generation(&mut self, transaction_id: &str) -> Result<(), BootstrapError>;

    /// Restore the captured generation without accepting caller-supplied paths.
    fn rollback_generation(&mut self, transaction_id: &str) -> Result<(), BootstrapError>;
}

pub struct BootstrapSession<E> {
    caller: BootstrapCaller,
    executor: E,
    state: SessionState,
    transaction_id: Option<String>,
}

impl BootstrapAdmissionPolicy {
    pub fn new(team_id: impl Into<String>) -> Result<Self, BootstrapError> {
        let team_id = team_id.into();
        if !valid_team_id(&team_id) {
            return Err(BootstrapError::InvalidPolicy);
        }
        Ok(Self { team_id })
    }

    pub fn authenticate(
        &self,
        facts: &BootstrapAuditFacts,
    ) -> Result<BootstrapCaller, BootstrapError> {
        if facts.pid <= 1
            || facts.effective_uid == 0
            || facts.effective_uid != facts.real_uid
            || facts.audit_session_id == 0
            || !facts.apple_generic_anchor
            || !facts.hardened_runtime
            || !valid_cdhash(&facts.cdhash)
        {
            return Err(BootstrapError::InvalidAuditToken);
        }
        if facts.team_id != self.team_id || facts.signing_identifier != APP_SIGNING_IDENTIFIER {
            return Err(BootstrapError::RequirementMismatch);
        }
        Ok(BootstrapCaller {
            pid: facts.pid,
            uid: facts.effective_uid,
            audit_session_id: facts.audit_session_id,
            team_id: facts.team_id.clone(),
            cdhash: facts.cdhash.clone(),
        })
    }
}

impl<E: BootstrapExecutor> BootstrapSession<E> {
    pub fn new(caller: BootstrapCaller, executor: E) -> Self {
        Self {
            caller,
            executor,
            state: SessionState::Ready,
            transaction_id: None,
        }
    }

    pub fn handle_frame(&mut self, frame: &[u8]) -> Result<BootstrapResponse, BootstrapError> {
        if frame.is_empty() || frame.len() > MAX_BOOTSTRAP_FRAME_BYTES {
            return Err(BootstrapError::InvalidFrame);
        }
        let request = serde_json::from_slice(frame).map_err(|_| BootstrapError::InvalidRequest)?;
        self.handle(request)
    }

    fn handle(&mut self, request: BootstrapRequest) -> Result<BootstrapResponse, BootstrapError> {
        match request {
            BootstrapRequest::PrepareGeneration {
                schema_version,
                transaction_id,
                caller_cdhash,
                policy_sha256,
                engine_manifest_sha256,
                engine_sha256,
                engine_size,
                target_triple,
            } => {
                if self.state != SessionState::Ready {
                    return Err(BootstrapError::InvalidState);
                }
                let material = GenerationMaterial {
                    transaction_id,
                    caller_cdhash,
                    policy_sha256,
                    engine_manifest_sha256,
                    engine_sha256,
                    engine_size,
                    target_triple,
                };
                validate_schema(schema_version)?;
                validate_material(&material, &self.caller)?;
                self.executor
                    .prepare_generation(&self.caller, &material)
                    .map_err(|_| BootstrapError::ExecutionFailed)?;
                self.state = SessionState::Prepared;
                self.transaction_id = Some(material.transaction_id.clone());
                Ok(response(
                    material.transaction_id,
                    BootstrapOutcome::Prepared,
                ))
            }
            BootstrapRequest::Commit {
                schema_version,
                transaction_id,
            } => {
                validate_schema(schema_version)?;
                self.require_prepared_transaction(&transaction_id)?;
                self.executor
                    .commit_generation(&transaction_id)
                    .map_err(|_| BootstrapError::ExecutionFailed)?;
                self.close();
                Ok(response(transaction_id, BootstrapOutcome::Committed))
            }
            BootstrapRequest::Rollback {
                schema_version,
                transaction_id,
            } => {
                validate_schema(schema_version)?;
                self.require_prepared_transaction(&transaction_id)?;
                self.executor
                    .rollback_generation(&transaction_id)
                    .map_err(|_| BootstrapError::ExecutionFailed)?;
                self.close();
                Ok(response(transaction_id, BootstrapOutcome::RolledBack))
            }
        }
    }

    fn require_prepared_transaction(&self, transaction_id: &str) -> Result<(), BootstrapError> {
        if self.state != SessionState::Prepared {
            return Err(BootstrapError::InvalidState);
        }
        if self.transaction_id.as_deref() != Some(transaction_id) {
            return Err(BootstrapError::TransactionMismatch);
        }
        Ok(())
    }

    fn close(&mut self) {
        self.state = SessionState::Closed;
        self.transaction_id = None;
    }
}

fn validate_schema(schema_version: u16) -> Result<(), BootstrapError> {
    if schema_version == BOOTSTRAP_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(BootstrapError::InvalidRequest)
    }
}

fn validate_material(
    material: &GenerationMaterial,
    caller: &BootstrapCaller,
) -> Result<(), BootstrapError> {
    if !valid_lower_hex(&material.transaction_id, TRANSACTION_ID_HEX_BYTES)
        || material.caller_cdhash != caller.cdhash
        || !valid_sha256(&material.policy_sha256)
        || !valid_sha256(&material.engine_manifest_sha256)
        || !valid_sha256(&material.engine_sha256)
        || material.engine_size == 0
        || material.engine_size > MAX_ENGINE_BYTES as u64
        || !matches!(
            material.target_triple.as_str(),
            "aarch64-apple-darwin" | "x86_64-apple-darwin"
        )
    {
        Err(BootstrapError::InvalidRequest)
    } else {
        Ok(())
    }
}

fn response(transaction_id: String, outcome: BootstrapOutcome) -> BootstrapResponse {
    BootstrapResponse {
        schema_version: BOOTSTRAP_SCHEMA_VERSION,
        transaction_id,
        outcome,
    }
}

fn valid_team_id(value: &str) -> bool {
    value.len() == 10
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn valid_cdhash(value: &str) -> bool {
    valid_lower_hex(value, CDHASH_HEX_BYTES)
}

fn valid_sha256(value: &str) -> bool {
    valid_lower_hex(value, SHA256_HEX_BYTES)
}

fn valid_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CDHASH: &str = "1111111111111111111111111111111111111111";
    const TX: &str = "0123456789abcdef0123456789abcdef";
    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[derive(Default)]
    struct RecordingExecutor {
        calls: Vec<String>,
    }

    impl BootstrapExecutor for RecordingExecutor {
        fn prepare_generation(
            &mut self,
            caller: &BootstrapCaller,
            material: &GenerationMaterial,
        ) -> Result<(), BootstrapError> {
            self.calls.push(format!(
                "prepare:{}:{}:{}",
                caller.uid, material.transaction_id, material.target_triple
            ));
            Ok(())
        }

        fn commit_generation(&mut self, transaction_id: &str) -> Result<(), BootstrapError> {
            self.calls.push(format!("commit:{transaction_id}"));
            Ok(())
        }

        fn rollback_generation(&mut self, transaction_id: &str) -> Result<(), BootstrapError> {
            self.calls.push(format!("rollback:{transaction_id}"));
            Ok(())
        }
    }

    fn facts() -> BootstrapAuditFacts {
        BootstrapAuditFacts {
            pid: 501,
            effective_uid: 502,
            real_uid: 502,
            audit_session_id: 42,
            apple_generic_anchor: true,
            team_id: "ABCDE12345".into(),
            signing_identifier: APP_SIGNING_IDENTIFIER.into(),
            cdhash: CDHASH.into(),
            hardened_runtime: true,
        }
    }

    fn prepare() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "operation": "prepare_generation",
            "schema_version": 1,
            "transaction_id": TX,
            "caller_cdhash": CDHASH,
            "policy_sha256": SHA_A,
            "engine_manifest_sha256": SHA_A,
            "engine_sha256": SHA_B,
            "engine_size": 4096,
            "target_triple": "aarch64-apple-darwin"
        }))
        .unwrap()
    }

    fn terminal(operation: &str, transaction_id: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "operation": operation,
            "schema_version": 1,
            "transaction_id": transaction_id
        }))
        .unwrap()
    }

    fn session() -> BootstrapSession<RecordingExecutor> {
        let caller = BootstrapAdmissionPolicy::new("ABCDE12345")
            .unwrap()
            .authenticate(&facts())
            .unwrap();
        BootstrapSession::new(caller, RecordingExecutor::default())
    }

    #[test]
    fn exact_designated_requirement_facts_are_admitted() {
        let caller = BootstrapAdmissionPolicy::new("ABCDE12345")
            .unwrap()
            .authenticate(&facts())
            .unwrap();
        assert_eq!(caller.uid, 502);
        assert_eq!(caller.audit_session_id, 42);
        assert_eq!(caller.team_id, "ABCDE12345");
        assert_eq!(caller.cdhash, CDHASH);
    }

    #[test]
    fn audit_token_and_every_designated_requirement_dimension_fail_closed() {
        let policy = BootstrapAdmissionPolicy::new("ABCDE12345").unwrap();
        let mut cases = Vec::new();
        let mut value = facts();
        value.effective_uid = 0;
        value.real_uid = 0;
        cases.push(value);
        let mut value = facts();
        value.real_uid = 503;
        cases.push(value);
        let mut value = facts();
        value.audit_session_id = 0;
        cases.push(value);
        let mut value = facts();
        value.apple_generic_anchor = false;
        cases.push(value);
        let mut value = facts();
        value.hardened_runtime = false;
        cases.push(value);
        let mut value = facts();
        value.team_id = "OTHER12345".into();
        cases.push(value);
        let mut value = facts();
        value.signing_identifier = "com.attacker.desktop".into();
        cases.push(value);
        let mut value = facts();
        value.cdhash = "UPPER11111111111111111111111111111111111".into();
        cases.push(value);
        for value in cases {
            assert!(policy.authenticate(&value).is_err());
        }
        assert_eq!(
            BootstrapAdmissionPolicy::new("TEAM/../01"),
            Err(BootstrapError::InvalidPolicy)
        );
    }

    #[test]
    fn prepare_then_commit_is_single_transaction_and_closes_session() {
        let mut session = session();
        assert_eq!(
            session.handle_frame(&prepare()).unwrap().outcome,
            BootstrapOutcome::Prepared
        );
        assert_eq!(
            session
                .handle_frame(&terminal("commit", TX))
                .unwrap()
                .outcome,
            BootstrapOutcome::Committed
        );
        assert_eq!(
            session.handle_frame(&terminal("rollback", TX)),
            Err(BootstrapError::InvalidState)
        );
        assert_eq!(
            session.executor.calls,
            [
                format!("prepare:502:{TX}:aarch64-apple-darwin"),
                format!("commit:{TX}")
            ]
        );
    }

    #[test]
    fn rollback_requires_the_prepared_transaction_and_closes_session() {
        let mut session = session();
        session.handle_frame(&prepare()).unwrap();
        assert_eq!(
            session.handle_frame(&terminal("rollback", "ffffffffffffffffffffffffffffffff")),
            Err(BootstrapError::TransactionMismatch)
        );
        assert_eq!(
            session
                .handle_frame(&terminal("rollback", TX))
                .unwrap()
                .outcome,
            BootstrapOutcome::RolledBack
        );
        assert_eq!(
            session.executor.calls,
            [
                format!("prepare:502:{TX}:aarch64-apple-darwin"),
                format!("rollback:{TX}")
            ]
        );
    }

    #[test]
    fn arbitrary_paths_payloads_network_and_lifecycle_commands_are_not_in_protocol() {
        for value in [
            serde_json::json!({"operation":"start","schema_version":1}),
            serde_json::json!({"operation":"prepare_generation","schema_version":1,"transaction_id":TX,"caller_cdhash":CDHASH,"policy_sha256":SHA_A,"engine_manifest_sha256":SHA_A,"engine_sha256":SHA_B,"engine_size":4096,"target_triple":"aarch64-apple-darwin","path":"/tmp/evil"}),
            serde_json::json!({"operation":"prepare_generation","schema_version":1,"transaction_id":TX,"caller_cdhash":CDHASH,"policy_sha256":SHA_A,"engine_manifest_sha256":SHA_A,"engine_sha256":SHA_B,"engine_size":4096,"target_triple":"aarch64-apple-darwin","url":"https://attacker.test"}),
            serde_json::json!({"operation":"prepare_generation","schema_version":1,"transaction_id":TX,"caller_cdhash":CDHASH,"policy_sha256":SHA_A,"engine_manifest_sha256":SHA_A,"engine_sha256":SHA_B,"engine_size":4096,"target_triple":"aarch64-apple-darwin","payload":"raw-bytes"}),
        ] {
            assert_eq!(
                session().handle_frame(&serde_json::to_vec(&value).unwrap()),
                Err(BootstrapError::InvalidRequest)
            );
        }
    }

    #[test]
    fn malformed_material_schema_and_oversized_frames_are_rejected_without_execution() {
        let mut wrong_hash: serde_json::Value = serde_json::from_slice(&prepare()).unwrap();
        wrong_hash["caller_cdhash"] = "2222222222222222222222222222222222222222".into();
        assert_eq!(
            session().handle_frame(&serde_json::to_vec(&wrong_hash).unwrap()),
            Err(BootstrapError::InvalidRequest)
        );

        let mut wrong_schema: serde_json::Value = serde_json::from_slice(&prepare()).unwrap();
        wrong_schema["schema_version"] = 2.into();
        assert_eq!(
            session().handle_frame(&serde_json::to_vec(&wrong_schema).unwrap()),
            Err(BootstrapError::InvalidRequest)
        );
        assert_eq!(
            session().handle_frame(&vec![b'x'; MAX_BOOTSTRAP_FRAME_BYTES + 1]),
            Err(BootstrapError::InvalidFrame)
        );
    }
}
