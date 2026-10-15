//! Pure App presence lease policy.
//!
//! The platform supplies authenticated caller/owner facts, monotonic ticks and
//! CSPRNG material. This module never reads a clock, opens IPC or performs a
//! lifecycle side effect.
//!
//! The lease only tells the service whether the owning App is still present.
//! It never stops the tunnel: a stopped tunnel sends traffic directly, so an
//! App that crashed, hung, was killed or quit while keeping the tunnel leaves
//! it running and re-acquires the lease when it starts again.

use std::{fmt, fmt::Write as _};

use crate::{
    state::{Caller, Phase},
    telemetry::GenerationId,
};

pub const LEASE_TTL_TICKS: u64 = 15;
pub const LEASE_RENEW_AFTER_TICKS: u64 = 5;
pub const LEASE_REATTACH_GRACE_TICKS: u64 = 30;
/// After the platform observes that the system slept, the App gets this long
/// to renew. Its renewal thread was frozen during sleep and may still be
/// throttled during a maintenance (dark) wake.
pub const LEASE_RESUME_GRACE_TICKS: u64 = 120;
pub const MAX_ACTIVE_LEASES: usize = 1;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Secret256([u8; 32]);

impl Secret256 {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_lower_hex(value: &str) -> Option<Self> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return None;
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            bytes[index] = (high << 4) | low;
        }
        Some(Self(bytes))
    }

    pub fn to_lower_hex(self) -> String {
        let mut result = String::with_capacity(64);
        for byte in self.0 {
            write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
        }
        result
    }

    fn matches(self, other: Self) -> bool {
        let mut difference = 0_u8;
        for (left, right) in self.0.into_iter().zip(other.0) {
            difference |= left ^ right;
        }
        difference == 0
    }
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

impl fmt::Debug for Secret256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret256([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct LeaseOwner {
    pub principal_id: String,
    pub session_id: u32,
    pub generation: GenerationId,
}

impl fmt::Debug for LeaseOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeaseOwner")
            .field("principal_id", &"[REDACTED]")
            .field("session_id", &"[REDACTED]")
            .field("generation", &self.generation)
            .finish()
    }
}

impl LeaseOwner {
    pub fn matches_caller(&self, caller: &Caller) -> bool {
        self.principal_id == caller.principal_id && self.session_id == caller.session_id
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseContext {
    pub phase: Phase,
    pub owner: Option<LeaseOwner>,
}

impl LeaseContext {
    pub fn running(owner: LeaseOwner) -> Self {
        Self {
            phase: Phase::Running,
            owner: Some(owner),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseSecrets {
    pub lease_id: Secret256,
    pub lease_nonce: Secret256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseGrant {
    pub lease_id: Secret256,
    pub lease_nonce: Secret256,
    pub next_seq: u64,
    pub ttl_ticks: u64,
    pub renew_after_ticks: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseProof {
    pub lease_id: Secret256,
    pub lease_nonce: Secret256,
    pub seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseDecision {
    Dormant,
    Held,
    /// The owning App stopped renewing. Reported once per lapse; the platform
    /// records it and keeps the tunnel.
    Lapsed,
    Unknown,
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum LeaseError {
    #[error("lease operation requires a running owner")]
    NotRunning,
    #[error("caller does not match the running owner")]
    NotOwner,
    #[error("the running owner already has an active lease")]
    AlreadyActive,
    #[error("lease proof is invalid")]
    Invalid,
    #[error("lease has expired")]
    Expired,
    #[error("lease sequence was replayed or skipped")]
    Replay,
    #[error("monotonic time is invalid")]
    InvalidTime,
}

#[derive(Debug, Clone)]
pub struct LeasePolicy {
    boot_epoch: Secret256,
    state: LeaseState,
    last_tick: Option<u64>,
}

#[derive(Debug, Clone)]
enum LeaseState {
    Empty,
    Reattach { owner: LeaseOwner, deadline: u64 },
    Active(LeaseRecord),
    Released { owner: LeaseOwner },
    Consumed,
}

#[derive(Debug, Clone)]
struct LeaseRecord {
    owner: LeaseOwner,
    lease_id: Secret256,
    nonce: Secret256,
    next_seq: u64,
    deadline: u64,
    lapsed: bool,
}

impl LeasePolicy {
    pub fn new(boot_epoch: Secret256) -> Self {
        debug_assert_eq!(MAX_ACTIVE_LEASES, 1);
        Self {
            boot_epoch,
            state: LeaseState::Empty,
            last_tick: None,
        }
    }

    pub fn recovered_running(
        boot_epoch: Secret256,
        owner: LeaseOwner,
        now: u64,
    ) -> Result<Self, LeaseError> {
        let deadline = now
            .checked_add(LEASE_REATTACH_GRACE_TICKS)
            .ok_or(LeaseError::InvalidTime)?;
        Ok(Self {
            boot_epoch,
            state: LeaseState::Reattach { owner, deadline },
            last_tick: Some(now),
        })
    }

    pub fn boot_epoch(&self) -> Secret256 {
        self.boot_epoch
    }

    pub fn acquire(
        &mut self,
        context: &LeaseContext,
        caller: &Caller,
        now: u64,
        secrets: LeaseSecrets,
    ) -> Result<LeaseGrant, LeaseError> {
        self.accept_tick(now)?;
        // The exact owner may always take the lease over, so an App that
        // restarted (or a service that restarted under it) reattaches. The
        // previous proof stops working.
        let owner = exact_owner(context, caller)?.clone();
        let deadline = now
            .checked_add(LEASE_TTL_TICKS)
            .ok_or(LeaseError::InvalidTime)?;
        let record = LeaseRecord {
            owner,
            lease_id: secrets.lease_id,
            nonce: secrets.lease_nonce,
            next_seq: 1,
            deadline,
            lapsed: false,
        };
        self.state = LeaseState::Active(record);
        Ok(LeaseGrant {
            lease_id: secrets.lease_id,
            lease_nonce: secrets.lease_nonce,
            next_seq: 1,
            ttl_ticks: LEASE_TTL_TICKS,
            renew_after_ticks: LEASE_RENEW_AFTER_TICKS,
        })
    }

    pub fn renew(
        &mut self,
        context: &LeaseContext,
        caller: &Caller,
        now: u64,
        proof: LeaseProof,
        next_nonce: Secret256,
    ) -> Result<LeaseGrant, LeaseError> {
        self.accept_tick(now)?;
        let owner = exact_owner(context, caller)?;
        let LeaseState::Active(record) = &mut self.state else {
            return Err(LeaseError::Invalid);
        };
        // A late renewal with a valid proof is still the same App; accepting
        // it keeps one slow round trip from orphaning the session.
        validate_record(record, owner, proof)?;
        let deadline = now
            .checked_add(LEASE_TTL_TICKS)
            .ok_or(LeaseError::InvalidTime)?;
        record.next_seq = record.next_seq.checked_add(1).ok_or(LeaseError::Replay)?;
        record.nonce = next_nonce;
        record.deadline = deadline;
        record.lapsed = false;
        Ok(LeaseGrant {
            lease_id: record.lease_id,
            lease_nonce: record.nonce,
            next_seq: record.next_seq,
            ttl_ticks: LEASE_TTL_TICKS,
            renew_after_ticks: LEASE_RENEW_AFTER_TICKS,
        })
    }

    pub fn release(
        &mut self,
        context: &LeaseContext,
        caller: &Caller,
        now: u64,
        proof: LeaseProof,
    ) -> Result<(), LeaseError> {
        self.accept_tick(now)?;
        let owner = exact_owner(context, caller)?;
        let LeaseState::Active(record) = &self.state else {
            return Err(LeaseError::Invalid);
        };
        validate_record(record, owner, proof)?;
        self.state = LeaseState::Released {
            owner: record.owner.clone(),
        };
        Ok(())
    }

    /// Extends a held lease after a system sleep, so a wake does not report
    /// the App as gone while its renewal thread is still thawing. A released,
    /// consumed or absent lease is not revived.
    pub fn grant_resume_grace(&mut self, now: u64) -> Result<(), LeaseError> {
        self.accept_tick(now)?;
        let grace = now
            .checked_add(LEASE_RESUME_GRACE_TICKS)
            .ok_or(LeaseError::InvalidTime)?;
        match &mut self.state {
            LeaseState::Active(LeaseRecord {
                deadline, lapsed, ..
            }) => {
                *deadline = (*deadline).max(grace);
                *lapsed = false;
            }
            LeaseState::Reattach { deadline, .. } => {
                *deadline = (*deadline).max(grace);
            }
            LeaseState::Released { .. } | LeaseState::Empty | LeaseState::Consumed => {}
        }
        Ok(())
    }

    pub fn evaluate(&mut self, context: &LeaseContext, now: u64) -> LeaseDecision {
        if self.accept_tick(now).is_err() {
            return LeaseDecision::Unknown;
        }
        let Some(current_owner) = context.owner.as_ref() else {
            self.state = LeaseState::Empty;
            return LeaseDecision::Dormant;
        };
        if context.phase != Phase::Running {
            self.state = LeaseState::Empty;
            return LeaseDecision::Dormant;
        }
        match &mut self.state {
            LeaseState::Active(record) if record.owner == *current_owner => {
                if now < record.deadline {
                    LeaseDecision::Held
                } else if record.lapsed {
                    LeaseDecision::Dormant
                } else {
                    // Keep the record: a late renewal with this proof revives it.
                    record.lapsed = true;
                    LeaseDecision::Lapsed
                }
            }
            LeaseState::Reattach { owner, deadline } if owner == current_owner => {
                if now < *deadline {
                    LeaseDecision::Held
                } else {
                    self.state = LeaseState::Consumed;
                    LeaseDecision::Lapsed
                }
            }
            // An App that released its lease quit on purpose and kept the
            // tunnel; there is nothing to report.
            LeaseState::Released { owner } if owner == current_owner => LeaseDecision::Dormant,
            LeaseState::Empty | LeaseState::Consumed => LeaseDecision::Dormant,
            LeaseState::Active(_) | LeaseState::Reattach { .. } | LeaseState::Released { .. } => {
                self.state = LeaseState::Empty;
                LeaseDecision::Dormant
            }
        }
    }

    fn accept_tick(&mut self, now: u64) -> Result<(), LeaseError> {
        if self.last_tick.is_some_and(|previous| now < previous) {
            return Err(LeaseError::InvalidTime);
        }
        self.last_tick = Some(now);
        Ok(())
    }
}

fn exact_owner<'a>(
    context: &'a LeaseContext,
    caller: &Caller,
) -> Result<&'a LeaseOwner, LeaseError> {
    if context.phase != Phase::Running {
        return Err(LeaseError::NotRunning);
    }
    let owner = context.owner.as_ref().ok_or(LeaseError::NotRunning)?;
    if !owner.matches_caller(caller) {
        return Err(LeaseError::NotOwner);
    }
    Ok(owner)
}

fn validate_record(
    record: &LeaseRecord,
    owner: &LeaseOwner,
    proof: LeaseProof,
) -> Result<(), LeaseError> {
    if record.owner != *owner
        || !record.lease_id.matches(proof.lease_id)
        || !record.nonce.matches(proof.lease_nonce)
    {
        return Err(LeaseError::Invalid);
    }
    if proof.seq != record.next_seq {
        return Err(LeaseError::Replay);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(value: u8) -> Secret256 {
        Secret256::from_bytes([value; 32])
    }

    fn generation(value: u8) -> GenerationId {
        GenerationId::from_bytes([value; 32])
    }

    fn owner(name: &str, session_id: u32, generation_value: u8) -> LeaseOwner {
        LeaseOwner {
            principal_id: name.into(),
            session_id,
            generation: generation(generation_value),
        }
    }

    fn caller(name: &str, session_id: u32) -> Caller {
        Caller {
            principal_id: name.into(),
            session_id,
            is_admin: false,
        }
    }

    fn secrets(value: u8) -> LeaseSecrets {
        LeaseSecrets {
            lease_id: secret(value),
            lease_nonce: secret(value + 1),
        }
    }

    fn proof(grant: LeaseGrant) -> LeaseProof {
        LeaseProof {
            lease_id: grant.lease_id,
            lease_nonce: grant.lease_nonce,
            seq: grant.next_seq,
        }
    }

    #[test]
    fn acquire_renew_and_expire_use_explicit_ticks() {
        let alice = caller("alice", 7);
        let context = LeaseContext::running(owner("alice", 7, 1));
        let mut policy = LeasePolicy::new(secret(99));
        let first = policy.acquire(&context, &alice, 10, secrets(1)).unwrap();
        assert_eq!(first.next_seq, 1);
        assert_eq!(policy.evaluate(&context, 24), LeaseDecision::Held);

        let renewed = policy
            .renew(&context, &alice, 24, proof(first), secret(3))
            .unwrap();
        assert_eq!(renewed.next_seq, 2);
        assert_eq!(policy.evaluate(&context, 38), LeaseDecision::Held);
        // A lapse is reported once and never asks for a teardown.
        assert_eq!(policy.evaluate(&context, 39), LeaseDecision::Lapsed);
        assert_eq!(policy.evaluate(&context, 40), LeaseDecision::Dormant);

        // The same App renewing late with a valid proof is held again.
        let late = policy
            .renew(&context, &alice, 41, proof(renewed), secret(4))
            .unwrap();
        assert_eq!(late.next_seq, 3);
        assert_eq!(policy.evaluate(&context, 55), LeaseDecision::Held);
        assert_eq!(policy.evaluate(&context, 56), LeaseDecision::Lapsed);
    }

    #[test]
    fn owner_takeover_replaces_an_active_lease_and_invalidates_its_proof() {
        let alice = caller("alice", 7);
        let context = LeaseContext::running(owner("alice", 7, 1));
        let mut policy = LeasePolicy::new(secret(99));
        let crashed = policy.acquire(&context, &alice, 10, secrets(1)).unwrap();
        let relaunched = policy.acquire(&context, &alice, 12, secrets(8)).unwrap();
        assert_ne!(crashed.lease_id, relaunched.lease_id);
        assert_eq!(
            policy.renew(&context, &alice, 13, proof(crashed), secret(4)),
            Err(LeaseError::Invalid)
        );
        policy
            .renew(&context, &alice, 13, proof(relaunched), secret(4))
            .unwrap();
        assert_eq!(
            policy.acquire(&context, &caller("bob", 7), 14, secrets(20)),
            Err(LeaseError::NotOwner)
        );
    }

    #[test]
    fn resume_grace_lets_the_app_renew_after_sleep() {
        let alice = caller("alice", 7);
        let context = LeaseContext::running(owner("alice", 7, 1));
        let mut policy = LeasePolicy::new(secret(99));
        let grant = policy.acquire(&context, &alice, 10, secrets(1)).unwrap();

        // The renewal thread was frozen; a maintenance wake advances the
        // uptime clock past the normal deadline before the App runs again.
        policy.grant_resume_grace(20).unwrap();
        assert_eq!(policy.evaluate(&context, 25), LeaseDecision::Held);
        assert_eq!(
            policy.evaluate(&context, 20 + LEASE_RESUME_GRACE_TICKS - 1),
            LeaseDecision::Held
        );
        let renewed = policy
            .renew(
                &context,
                &alice,
                20 + LEASE_RESUME_GRACE_TICKS - 1,
                proof(grant),
                secret(3),
            )
            .unwrap();
        assert_eq!(renewed.next_seq, 2);

        let mut abandoned = LeasePolicy::new(secret(99));
        abandoned.acquire(&context, &alice, 10, secrets(1)).unwrap();
        abandoned.grant_resume_grace(20).unwrap();
        assert_eq!(
            abandoned.evaluate(&context, 20 + LEASE_RESUME_GRACE_TICKS),
            LeaseDecision::Lapsed
        );
    }

    #[test]
    fn resume_grace_does_not_revive_a_released_lease() {
        let alice = caller("alice", 7);
        let context = LeaseContext::running(owner("alice", 7, 1));
        let mut released = LeasePolicy::new(secret(99));
        let grant = released.acquire(&context, &alice, 10, secrets(1)).unwrap();
        released
            .release(&context, &alice, 11, proof(grant))
            .unwrap();
        released.grant_resume_grace(12).unwrap();
        assert_eq!(released.evaluate(&context, 25), LeaseDecision::Dormant);

        let mut lapsed = LeasePolicy::new(secret(99));
        lapsed.acquire(&context, &alice, 10, secrets(1)).unwrap();
        assert_eq!(lapsed.evaluate(&context, 25), LeaseDecision::Lapsed);
        lapsed.grant_resume_grace(26).unwrap();
        assert_eq!(lapsed.evaluate(&context, 27), LeaseDecision::Held);
        assert_eq!(lapsed.grant_resume_grace(20), Err(LeaseError::InvalidTime));
    }

    #[test]
    fn pipe_disconnect_has_no_model_transition() {
        let alice = caller("alice", 7);
        let context = LeaseContext::running(owner("alice", 7, 1));
        let mut policy = LeasePolicy::new(secret(99));
        policy.acquire(&context, &alice, 10, secrets(1)).unwrap();

        // The policy exposes no transport/disconnect input. Advancing less than
        // the TTL is the only relevant fact and must keep the lease held.
        assert_eq!(policy.evaluate(&context, 20), LeaseDecision::Held);
    }

    #[test]
    fn principal_session_and_owner_generation_are_all_bound() {
        let alice = caller("alice", 7);
        let context = LeaseContext::running(owner("alice", 7, 1));
        let mut policy = LeasePolicy::new(secret(99));
        let grant = policy.acquire(&context, &alice, 10, secrets(1)).unwrap();

        assert_eq!(
            policy.renew(&context, &caller("bob", 7), 11, proof(grant), secret(4)),
            Err(LeaseError::NotOwner)
        );
        assert_eq!(
            policy.renew(&context, &caller("alice", 8), 11, proof(grant), secret(4)),
            Err(LeaseError::NotOwner)
        );

        let next_context = LeaseContext::running(owner("alice", 7, 2));
        assert_eq!(policy.evaluate(&next_context, 11), LeaseDecision::Dormant);
    }

    #[test]
    fn forged_replayed_and_skipped_proofs_are_rejected() {
        let alice = caller("alice", 7);
        let context = LeaseContext::running(owner("alice", 7, 1));
        let mut policy = LeasePolicy::new(secret(99));
        let grant = policy.acquire(&context, &alice, 10, secrets(1)).unwrap();

        let mut forged = proof(grant);
        forged.lease_id = secret(55);
        assert_eq!(
            policy.renew(&context, &alice, 11, forged, secret(4)),
            Err(LeaseError::Invalid)
        );

        let renewed = policy
            .renew(&context, &alice, 11, proof(grant), secret(4))
            .unwrap();
        assert_eq!(
            policy.renew(&context, &alice, 12, proof(grant), secret(5)),
            Err(LeaseError::Invalid)
        );
        let mut skipped = proof(renewed);
        skipped.seq += 1;
        assert_eq!(
            policy.renew(&context, &alice, 12, skipped, secret(5)),
            Err(LeaseError::Replay)
        );
    }

    #[test]
    fn released_lease_never_lapses_and_duplicate_release_is_rejected() {
        let alice = caller("alice", 7);
        let context = LeaseContext::running(owner("alice", 7, 1));
        let mut released = LeasePolicy::new(secret(98));
        let grant = released.acquire(&context, &alice, 10, secrets(5)).unwrap();
        released
            .release(&context, &alice, 11, proof(grant))
            .unwrap();
        assert_eq!(
            released.release(&context, &alice, 12, proof(grant)),
            Err(LeaseError::Invalid)
        );
        assert_eq!(released.evaluate(&context, 24), LeaseDecision::Dormant);
        assert_eq!(released.evaluate(&context, 25), LeaseDecision::Dormant);
    }

    #[test]
    fn released_lease_can_be_reacquired_before_deadline() {
        let alice = caller("alice", 7);
        let context = LeaseContext::running(owner("alice", 7, 1));
        let mut policy = LeasePolicy::new(secret(99));
        let old = policy.acquire(&context, &alice, 10, secrets(1)).unwrap();
        policy.release(&context, &alice, 11, proof(old)).unwrap();
        let new = policy.acquire(&context, &alice, 12, secrets(8)).unwrap();
        assert_ne!(old.lease_id, new.lease_id);
        assert_eq!(policy.evaluate(&context, 26), LeaseDecision::Held);
    }

    #[test]
    fn service_restart_invalidates_old_proof_and_uses_reattach_grace() {
        let alice = caller("alice", 7);
        let context = LeaseContext::running(owner("alice", 7, 1));
        let mut old_policy = LeasePolicy::new(secret(1));
        let old_grant = old_policy
            .acquire(&context, &alice, 10, secrets(2))
            .unwrap();

        let mut restarted =
            LeasePolicy::recovered_running(secret(9), context.owner.clone().unwrap(), 20).unwrap();
        assert_ne!(old_policy.boot_epoch(), restarted.boot_epoch());
        assert_eq!(
            restarted.renew(&context, &alice, 21, proof(old_grant), secret(8)),
            Err(LeaseError::Invalid)
        );
        assert_eq!(restarted.evaluate(&context, 49), LeaseDecision::Held);
        assert_eq!(restarted.evaluate(&context, 50), LeaseDecision::Lapsed);
        assert_eq!(restarted.evaluate(&context, 51), LeaseDecision::Dormant);

        // The relaunched App reattaches after the service restart.
        let reattached = restarted
            .acquire(&context, &alice, 52, secrets(30))
            .unwrap();
        assert_eq!(restarted.evaluate(&context, 53), LeaseDecision::Held);
        restarted
            .renew(&context, &alice, 54, proof(reattached), secret(31))
            .unwrap();
    }

    #[test]
    fn non_running_phase_and_clock_regression_are_not_lapses() {
        let alice = caller("alice", 7);
        let running = LeaseContext::running(owner("alice", 7, 1));
        let mut policy = LeasePolicy::new(secret(99));
        policy.acquire(&running, &alice, 10, secrets(1)).unwrap();
        assert_eq!(policy.evaluate(&running, 9), LeaseDecision::Unknown);

        let stopped = LeaseContext {
            phase: Phase::Stopped,
            owner: running.owner,
        };
        assert_eq!(policy.evaluate(&stopped, 11), LeaseDecision::Dormant);
    }

    #[test]
    fn deadline_overflow_is_rejected() {
        let alice = caller("alice", 7);
        let context = LeaseContext::running(owner("alice", 7, 1));
        let mut policy = LeasePolicy::new(secret(99));
        assert_eq!(
            policy.acquire(&context, &alice, u64::MAX - 1, secrets(1)),
            Err(LeaseError::InvalidTime)
        );
    }

    #[test]
    fn secret_wire_format_is_exact_lowercase_hex_and_debug_is_redacted() {
        let value = secret(0xab);
        let encoded = value.to_lower_hex();
        assert_eq!(encoded, "ab".repeat(32));
        assert_eq!(Secret256::from_lower_hex(&encoded), Some(value));
        assert!(Secret256::from_lower_hex(&"AB".repeat(32)).is_none());
        assert!(Secret256::from_lower_hex("ab").is_none());
        assert!(!format!("{value:?}").contains("ab"));
    }
}
