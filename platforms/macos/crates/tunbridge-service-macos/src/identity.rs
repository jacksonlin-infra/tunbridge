use std::collections::BTreeSet;
use tunbridge_service::state::Caller;

const MAX_IDENTIFIER_BYTES: usize = 128;
const CDHASH_HEX_BYTES: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditTokenFacts {
    pub pid: u32,
    pub effective_uid: u32,
    pub real_uid: u32,
    pub audit_session_id: u32,
    pub team_id: String,
    pub signing_identifier: String,
    pub cdhash: String,
    pub hardened_runtime: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRequirementPolicy {
    pub team_id: String,
    pub signing_identifier: String,
    pub allowed_cdhashes: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperRequirementPolicy {
    pub team_id: String,
    pub signing_identifier: String,
    pub allowed_cdhashes: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    InvalidPolicy,
    InvalidAuditToken,
    RequirementMismatch,
}

impl AppRequirementPolicy {
    pub fn authenticate(&self, facts: &AuditTokenFacts) -> Result<Caller, IdentityError> {
        validate_policy(
            &self.team_id,
            &self.signing_identifier,
            &self.allowed_cdhashes,
        )?;
        validate_facts(facts)?;
        if facts.effective_uid == 0
            || facts.effective_uid != facts.real_uid
            || facts.team_id != self.team_id
            || facts.signing_identifier != self.signing_identifier
            || !self.allowed_cdhashes.contains(&facts.cdhash)
        {
            return Err(IdentityError::RequirementMismatch);
        }
        Ok(Caller {
            principal_id: format!(
                "macos:{}:{}:{}",
                facts.effective_uid, facts.team_id, facts.signing_identifier
            ),
            session_id: facts.audit_session_id,
            is_admin: false,
        })
    }
}

impl HelperRequirementPolicy {
    pub fn verify(&self, facts: &AuditTokenFacts) -> Result<(), IdentityError> {
        validate_policy(
            &self.team_id,
            &self.signing_identifier,
            &self.allowed_cdhashes,
        )?;
        validate_facts(facts)?;
        if facts.effective_uid != 0
            || facts.real_uid != 0
            || facts.team_id != self.team_id
            || facts.signing_identifier != self.signing_identifier
            || !self.allowed_cdhashes.contains(&facts.cdhash)
        {
            Err(IdentityError::RequirementMismatch)
        } else {
            Ok(())
        }
    }
}

fn validate_policy(
    team_id: &str,
    signing_identifier: &str,
    allowed_cdhashes: &BTreeSet<String>,
) -> Result<(), IdentityError> {
    if valid_identifier(team_id)
        && valid_identifier(signing_identifier)
        && !allowed_cdhashes.is_empty()
        && allowed_cdhashes.iter().all(|value| valid_cdhash(value))
    {
        Ok(())
    } else {
        Err(IdentityError::InvalidPolicy)
    }
}

fn validate_facts(facts: &AuditTokenFacts) -> Result<(), IdentityError> {
    if facts.pid > 1
        && facts.audit_session_id != 0
        && facts.hardened_runtime
        && valid_identifier(&facts.team_id)
        && valid_identifier(&facts.signing_identifier)
        && valid_cdhash(&facts.cdhash)
    {
        Ok(())
    } else {
        Err(IdentityError::InvalidAuditToken)
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn valid_cdhash(value: &str) -> bool {
    value.len() == CDHASH_HEX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP_ID: &str = "com.tunbridge.desktop";
    const HELPER_ID: &str = "com.tunbridge.desktop.helper";
    const TEAM: &str = "ABCDE12345";
    const APP_HASH: &str = "1111111111111111111111111111111111111111";
    const HELPER_HASH: &str = "2222222222222222222222222222222222222222";

    fn hashes(value: &str) -> BTreeSet<String> {
        [value.to_owned()].into_iter().collect()
    }

    fn app_policy() -> AppRequirementPolicy {
        AppRequirementPolicy {
            team_id: TEAM.into(),
            signing_identifier: APP_ID.into(),
            allowed_cdhashes: hashes(APP_HASH),
        }
    }

    fn app_facts() -> AuditTokenFacts {
        AuditTokenFacts {
            pid: 501,
            effective_uid: 502,
            real_uid: 502,
            audit_session_id: 42,
            team_id: TEAM.into(),
            signing_identifier: APP_ID.into(),
            cdhash: APP_HASH.into(),
            hardened_runtime: true,
        }
    }

    #[test]
    fn exact_signed_app_maps_kernel_facts_to_shared_caller() {
        let caller = app_policy().authenticate(&app_facts()).unwrap();
        assert_eq!(
            caller.principal_id,
            "macos:502:ABCDE12345:com.tunbridge.desktop"
        );
        assert_eq!(caller.session_id, 42);
        assert!(!caller.is_admin);
    }

    #[test]
    fn app_authentication_rejects_each_untrusted_dimension() {
        let mut cases = Vec::new();
        let mut facts = app_facts();
        facts.effective_uid = 0;
        facts.real_uid = 0;
        cases.push(facts);
        let mut facts = app_facts();
        facts.real_uid = 503;
        cases.push(facts);
        let mut facts = app_facts();
        facts.audit_session_id = 0;
        cases.push(facts);
        let mut facts = app_facts();
        facts.team_id = "OTHER12345".into();
        cases.push(facts);
        let mut facts = app_facts();
        facts.signing_identifier = "com.example.copy".into();
        cases.push(facts);
        let mut facts = app_facts();
        facts.cdhash = "3333333333333333333333333333333333333333".into();
        cases.push(facts);
        let mut facts = app_facts();
        facts.hardened_runtime = false;
        cases.push(facts);

        for facts in cases {
            assert!(app_policy().authenticate(&facts).is_err());
        }
    }

    #[test]
    fn helper_verification_requires_root_and_exact_signed_generation() {
        let policy = HelperRequirementPolicy {
            team_id: TEAM.into(),
            signing_identifier: HELPER_ID.into(),
            allowed_cdhashes: hashes(HELPER_HASH),
        };
        let mut facts = app_facts();
        facts.effective_uid = 0;
        facts.real_uid = 0;
        facts.signing_identifier = HELPER_ID.into();
        facts.cdhash = HELPER_HASH.into();
        policy.verify(&facts).unwrap();

        facts.effective_uid = 502;
        facts.real_uid = 502;
        assert_eq!(
            policy.verify(&facts),
            Err(IdentityError::RequirementMismatch)
        );
    }

    #[test]
    fn empty_or_malformed_requirement_policy_fails_closed() {
        let mut policy = app_policy();
        policy.allowed_cdhashes.clear();
        assert_eq!(
            policy.authenticate(&app_facts()),
            Err(IdentityError::InvalidPolicy)
        );
        policy.allowed_cdhashes = hashes("UPPER11111111111111111111111111111111111");
        assert_eq!(
            policy.authenticate(&app_facts()),
            Err(IdentityError::InvalidPolicy)
        );
    }
}
