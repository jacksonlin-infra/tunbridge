use serde::{Deserialize, Serialize};

use crate::protocol::ErrorCode;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Caller {
    /// Stable SID-derived identity supplied by the Windows token adapter, never
    /// by an IPC request.
    pub principal_id: String,
    pub session_id: u32,
    pub is_admin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Owner {
    pub principal_id: String,
    pub session_id: u32,
}

impl Owner {
    fn matches(&self, caller: &Caller) -> bool {
        self.principal_id == caller.principal_id && self.session_id == caller.session_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Stopped,
    Starting,
    Running,
    Stopping,
    Recovering,
    Faulted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchdogReason {
    EngineExited,
    UpstreamUnavailable,
    ControllerUnavailable,
    AdapterMissing,
    RuntimeIdentityMismatch,
    LeaseExpired,
    ConnectionStorm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Status,
    Start,
    Stop,
    Recover,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceState {
    pub schema_version: u16,
    pub phase: Phase,
    pub owner: Option<Owner>,
    pub operation_id: Option<String>,
    pub last_error: Option<ErrorCode>,
    pub last_watchdog_reason: Option<WatchdogReason>,
    /// A running session whose upstream is temporarily unusable. The tunnel
    /// stays up so traffic fails closed instead of escaping directly.
    #[serde(default)]
    pub degraded_reason: Option<WatchdogReason>,
}

impl Default for ServiceState {
    fn default() -> Self {
        Self {
            schema_version: 1,
            phase: Phase::Stopped,
            owner: None,
            operation_id: None,
            last_error: None,
            last_watchdog_reason: None,
            degraded_reason: None,
        }
    }
}

impl ServiceState {
    pub fn recovered_running(owner: Owner) -> Self {
        Self {
            schema_version: 1,
            phase: Phase::Running,
            owner: Some(owner),
            operation_id: None,
            last_error: None,
            last_watchdog_reason: None,
            degraded_reason: None,
        }
    }

    pub fn recovered_fault(error: ErrorCode) -> Self {
        Self {
            schema_version: 1,
            phase: Phase::Faulted,
            owner: None,
            operation_id: None,
            last_error: Some(error),
            last_watchdog_reason: None,
            degraded_reason: None,
        }
    }

    pub fn begin(
        &mut self,
        action: Action,
        caller: &Caller,
        operation_id: impl Into<String>,
    ) -> Result<(), StateError> {
        if action == Action::Status {
            return Ok(());
        }

        let operation_id = operation_id.into();
        if operation_id.is_empty() {
            return Err(StateError::InvalidOperationId);
        }

        match action {
            Action::Status => Ok(()),
            Action::Start => self.begin_start(caller, operation_id),
            Action::Stop => self.begin_stop(caller, operation_id),
            Action::Recover => self.begin_recover(caller, operation_id),
        }
    }

    pub fn finish_success(&mut self, action: Action) -> Result<(), StateError> {
        let expected = match action {
            Action::Start => Phase::Starting,
            Action::Stop => Phase::Stopping,
            Action::Recover => Phase::Recovering,
            Action::Status => return Err(StateError::NoOperation),
        };
        if self.phase != expected || self.operation_id.is_none() {
            return Err(StateError::NoOperation);
        }

        self.phase = if action == Action::Start {
            Phase::Running
        } else {
            self.owner = None;
            Phase::Stopped
        };
        self.operation_id = None;
        self.last_error = None;
        self.degraded_reason = None;
        Ok(())
    }

    pub fn finish_failure(&mut self, error: ErrorCode) -> Result<(), StateError> {
        if !matches!(
            self.phase,
            Phase::Starting | Phase::Stopping | Phase::Recovering
        ) || self.operation_id.is_none()
        {
            return Err(StateError::NoOperation);
        }
        self.phase = Phase::Faulted;
        self.operation_id = None;
        self.last_error = Some(error);
        self.degraded_reason = None;
        Ok(())
    }

    pub fn begin_automatic_recovery(
        &mut self,
        reason: WatchdogReason,
        operation_id: impl Into<String>,
    ) -> Result<(), StateError> {
        let operation_id = operation_id.into();
        if operation_id.is_empty() {
            return Err(StateError::InvalidOperationId);
        }
        match self.phase {
            Phase::Running => {
                self.phase = Phase::Recovering;
                self.operation_id = Some(operation_id);
                self.last_watchdog_reason = Some(reason);
                self.degraded_reason = None;
                Ok(())
            }
            Phase::Stopped => Err(StateError::NotRunning),
            Phase::Faulted => Err(StateError::RecoveryRequired),
            Phase::Starting | Phase::Stopping | Phase::Recovering => {
                Err(StateError::OperationInProgress)
            }
        }
    }

    pub fn record_automatic_fault(
        &mut self,
        reason: WatchdogReason,
        error: ErrorCode,
    ) -> Result<(), StateError> {
        match self.phase {
            Phase::Running => {
                self.phase = Phase::Faulted;
                self.owner = None;
                self.operation_id = None;
                self.last_error = Some(error);
                self.last_watchdog_reason = Some(reason);
                self.degraded_reason = None;
                Ok(())
            }
            Phase::Stopped => Err(StateError::NotRunning),
            Phase::Faulted => Err(StateError::RecoveryRequired),
            Phase::Starting | Phase::Stopping | Phase::Recovering => {
                Err(StateError::OperationInProgress)
            }
        }
    }

    /// Records that the running session's upstream is unusable without
    /// tearing down the tunnel. Returns whether the visible reason changed.
    pub fn mark_degraded(&mut self, reason: WatchdogReason) -> Result<bool, StateError> {
        match self.phase {
            Phase::Running => {
                let changed = self.degraded_reason != Some(reason);
                self.degraded_reason = Some(reason);
                Ok(changed)
            }
            Phase::Stopped => Err(StateError::NotRunning),
            Phase::Faulted => Err(StateError::RecoveryRequired),
            Phase::Starting | Phase::Stopping | Phase::Recovering => {
                Err(StateError::OperationInProgress)
            }
        }
    }

    /// Clears a degradation once the upstream is usable again.
    pub fn clear_degraded(&mut self) -> bool {
        self.degraded_reason.take().is_some()
    }

    /// The automatic stop or fault reason shown while the session is not
    /// running. A user start or stop clears it.
    pub fn stop_reason(&self) -> Option<WatchdogReason> {
        match self.phase {
            Phase::Running | Phase::Starting | Phase::Stopping => None,
            Phase::Stopped | Phase::Recovering | Phase::Faulted => self.last_watchdog_reason,
        }
    }

    pub fn is_owner(&self, caller: &Caller) -> bool {
        self.owner
            .as_ref()
            .is_some_and(|owner| owner.matches(caller))
    }

    fn begin_start(&mut self, caller: &Caller, operation_id: String) -> Result<(), StateError> {
        match self.phase {
            Phase::Stopped => {
                self.owner = Some(Owner {
                    principal_id: caller.principal_id.clone(),
                    session_id: caller.session_id,
                });
                self.phase = Phase::Starting;
                self.operation_id = Some(operation_id);
                self.last_error = None;
                self.last_watchdog_reason = None;
                Ok(())
            }
            Phase::Running => Err(StateError::AlreadyRunning),
            Phase::Faulted => Err(StateError::RecoveryRequired),
            Phase::Starting | Phase::Stopping | Phase::Recovering => {
                Err(StateError::OperationInProgress)
            }
        }
    }

    fn begin_stop(&mut self, caller: &Caller, operation_id: String) -> Result<(), StateError> {
        match self.phase {
            Phase::Stopped => Err(StateError::NotRunning),
            Phase::Starting | Phase::Running => {
                self.require_owner_or_admin(caller)?;
                self.phase = Phase::Stopping;
                self.operation_id = Some(operation_id);
                self.last_watchdog_reason = None;
                self.degraded_reason = None;
                Ok(())
            }
            Phase::Faulted => {
                self.require_owner_or_admin(caller)?;
                self.phase = Phase::Stopping;
                self.operation_id = Some(operation_id);
                self.last_watchdog_reason = None;
                Ok(())
            }
            Phase::Stopping | Phase::Recovering => Err(StateError::OperationInProgress),
        }
    }

    fn begin_recover(&mut self, caller: &Caller, operation_id: String) -> Result<(), StateError> {
        self.begin_manual_recover(caller, operation_id)?;
        self.last_watchdog_reason = None;
        self.degraded_reason = None;
        Ok(())
    }

    fn begin_manual_recover(
        &mut self,
        caller: &Caller,
        operation_id: String,
    ) -> Result<(), StateError> {
        match self.phase {
            Phase::Starting | Phase::Stopping | Phase::Recovering => {
                Err(StateError::OperationInProgress)
            }
            Phase::Running => {
                self.require_owner_or_admin(caller)?;
                self.phase = Phase::Recovering;
                self.operation_id = Some(operation_id);
                Ok(())
            }
            Phase::Faulted => {
                // A startup reconciliation fault has no live session owner.
                // Any caller reaching this state has already passed the fixed
                // authenticated-interactive pipe policy, and recovery can
                // affect only identity-proven protected product resources.
                // Faults that still retain an owner remain owner/admin-only.
                if self.owner.is_some() {
                    self.require_owner_or_admin(caller)?;
                }
                self.phase = Phase::Recovering;
                self.operation_id = Some(operation_id);
                Ok(())
            }
            Phase::Stopped => {
                self.owner = Some(Owner {
                    principal_id: caller.principal_id.clone(),
                    session_id: caller.session_id,
                });
                self.phase = Phase::Recovering;
                self.operation_id = Some(operation_id);
                Ok(())
            }
        }
    }

    fn require_owner_or_admin(&self, caller: &Caller) -> Result<(), StateError> {
        if caller.is_admin || self.is_owner(caller) {
            Ok(())
        } else {
            Err(StateError::NotOwner)
        }
    }
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum StateError {
    #[error("an operation is already in progress")]
    OperationInProgress,
    #[error("tunbridge is already running")]
    AlreadyRunning,
    #[error("tunbridge is not running")]
    NotRunning,
    #[error("the caller does not own the running session")]
    NotOwner,
    #[error("recovery is required before start")]
    RecoveryRequired,
    #[error("operation id must not be empty")]
    InvalidOperationId,
    #[error("there is no matching active operation")]
    NoOperation,
}

impl StateError {
    pub fn code(self) -> ErrorCode {
        match self {
            Self::OperationInProgress => ErrorCode::OperationInProgress,
            Self::AlreadyRunning => ErrorCode::AlreadyRunning,
            Self::NotRunning => ErrorCode::NotRunning,
            Self::NotOwner => ErrorCode::NotOwner,
            Self::RecoveryRequired => ErrorCode::RecoveryRequired,
            Self::InvalidOperationId | Self::NoOperation => ErrorCode::InternalError,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(name: &str, session_id: u32, is_admin: bool) -> Caller {
        Caller {
            principal_id: name.into(),
            session_id,
            is_admin,
        }
    }

    #[test]
    fn owner_can_complete_start_and_stop() {
        let alice = caller("alice", 1, false);
        let mut state = ServiceState::default();

        state.begin(Action::Start, &alice, "start-1").unwrap();
        assert_eq!(state.phase, Phase::Starting);
        assert!(state.is_owner(&alice));
        state.finish_success(Action::Start).unwrap();
        assert_eq!(state.phase, Phase::Running);

        state.begin(Action::Stop, &alice, "stop-1").unwrap();
        state.finish_success(Action::Stop).unwrap();
        assert_eq!(state, ServiceState::default());
    }

    #[test]
    fn another_user_cannot_stop_or_recover_owner_session() {
        let alice = caller("alice", 1, false);
        let bob = caller("bob", 2, false);
        let mut state = ServiceState::default();
        state.begin(Action::Start, &alice, "start-1").unwrap();
        state.finish_success(Action::Start).unwrap();

        assert_eq!(
            state.begin(Action::Stop, &bob, "stop-1"),
            Err(StateError::NotOwner)
        );
        assert_eq!(
            state.begin(Action::Recover, &bob, "recover-1"),
            Err(StateError::NotOwner)
        );
        assert_eq!(state.phase, Phase::Running);
    }

    #[test]
    fn administrator_can_recover_another_users_session() {
        let alice = caller("alice", 1, false);
        let admin = caller("admin", 3, true);
        let mut state = ServiceState::default();
        state.begin(Action::Start, &alice, "start-1").unwrap();
        state
            .finish_failure(ErrorCode::ConfigValidationFailed)
            .unwrap();

        state.begin(Action::Recover, &admin, "recover-1").unwrap();
        state.finish_success(Action::Recover).unwrap();
        assert_eq!(state, ServiceState::default());
    }

    #[test]
    fn concurrent_and_invalid_transitions_are_rejected() {
        let alice = caller("alice", 1, false);
        let mut state = ServiceState::default();
        assert_eq!(
            state.begin(Action::Stop, &alice, "stop-1"),
            Err(StateError::NotRunning)
        );

        state.begin(Action::Start, &alice, "start-1").unwrap();
        assert_eq!(
            state.begin(Action::Start, &alice, "start-2"),
            Err(StateError::OperationInProgress)
        );
        assert_eq!(
            state.begin(Action::Recover, &alice, "recover-1"),
            Err(StateError::OperationInProgress)
        );
    }

    #[test]
    fn start_from_faulted_requires_recovery() {
        let alice = caller("alice", 1, false);
        let mut state = ServiceState::default();
        state.begin(Action::Start, &alice, "start-1").unwrap();
        state.finish_failure(ErrorCode::InternalError).unwrap();

        assert_eq!(
            state.begin(Action::Start, &alice, "start-2"),
            Err(StateError::RecoveryRequired)
        );
    }

    #[test]
    fn same_principal_in_different_session_is_not_owner() {
        let alice_session_1 = caller("alice", 1, false);
        let alice_session_2 = caller("alice", 2, false);
        let mut state = ServiceState::default();
        state
            .begin(Action::Start, &alice_session_1, "start-1")
            .unwrap();
        state.finish_success(Action::Start).unwrap();

        assert_eq!(
            state.begin(Action::Stop, &alice_session_2, "stop-1"),
            Err(StateError::NotOwner)
        );
    }

    #[test]
    fn recovered_running_preserves_owner_and_ownerless_fault_can_recover() {
        let alice = caller("alice", 1, false);
        let running = ServiceState::recovered_running(Owner {
            principal_id: alice.principal_id.clone(),
            session_id: alice.session_id,
        });
        assert_eq!(running.phase, Phase::Running);
        assert!(running.is_owner(&alice));

        let mut faulted = ServiceState::recovered_fault(ErrorCode::OwnedProcessMismatch);
        faulted.begin(Action::Recover, &alice, "recover-1").unwrap();
    }

    #[test]
    fn automatic_recovery_uses_the_existing_transaction_without_forging_a_caller() {
        let alice = caller("alice", 1, false);
        let mut state = ServiceState::default();
        state.begin(Action::Start, &alice, "start-1").unwrap();
        state.finish_success(Action::Start).unwrap();

        state
            .begin_automatic_recovery(WatchdogReason::UpstreamUnavailable, "watchdog-1")
            .unwrap();
        assert_eq!(state.phase, Phase::Recovering);
        assert!(state.is_owner(&alice));
        assert_eq!(state.operation_id.as_deref(), Some("watchdog-1"));
        assert_eq!(
            state.last_watchdog_reason,
            Some(WatchdogReason::UpstreamUnavailable)
        );
        assert_eq!(
            state.begin(Action::Stop, &alice, "stop-race"),
            Err(StateError::OperationInProgress)
        );

        state.finish_success(Action::Recover).unwrap();
        assert_eq!(state.phase, Phase::Stopped);
        assert!(state.owner.is_none());
        assert_eq!(
            state.last_watchdog_reason,
            Some(WatchdogReason::UpstreamUnavailable)
        );
    }

    #[test]
    fn automatic_identity_fault_clears_owner_and_allows_exact_recovery() {
        let alice = caller("alice", 1, false);
        let mut state = ServiceState::default();
        state.begin(Action::Start, &alice, "start-1").unwrap();
        state.finish_success(Action::Start).unwrap();

        state
            .record_automatic_fault(
                WatchdogReason::RuntimeIdentityMismatch,
                ErrorCode::OwnedProcessMismatch,
            )
            .unwrap();
        assert_eq!(state.phase, Phase::Faulted);
        assert!(state.owner.is_none());
        assert!(state.operation_id.is_none());
        assert_eq!(state.last_error, Some(ErrorCode::OwnedProcessMismatch));
        state
            .begin(Action::Recover, &alice, "recover-ownerless-fault")
            .unwrap();
    }

    #[test]
    fn upstream_degradation_keeps_the_session_running_until_cleared() {
        let alice = caller("alice", 1, false);
        let mut state = ServiceState::default();
        assert_eq!(
            state.mark_degraded(WatchdogReason::UpstreamUnavailable),
            Err(StateError::NotRunning)
        );
        state.begin(Action::Start, &alice, "start-1").unwrap();
        assert_eq!(
            state.mark_degraded(WatchdogReason::UpstreamUnavailable),
            Err(StateError::OperationInProgress)
        );
        state.finish_success(Action::Start).unwrap();

        assert_eq!(
            state.mark_degraded(WatchdogReason::UpstreamUnavailable),
            Ok(true)
        );
        assert_eq!(
            state.mark_degraded(WatchdogReason::UpstreamUnavailable),
            Ok(false)
        );
        assert_eq!(state.phase, Phase::Running);
        assert!(state.is_owner(&alice));
        assert_eq!(state.stop_reason(), None);
        assert!(state.clear_degraded());
        assert!(!state.clear_degraded());
    }

    #[test]
    fn leaving_running_clears_degradation_and_exposes_the_stop_reason() {
        let alice = caller("alice", 1, false);
        let mut state = ServiceState::default();
        state.begin(Action::Start, &alice, "start-1").unwrap();
        state.finish_success(Action::Start).unwrap();
        state
            .mark_degraded(WatchdogReason::UpstreamUnavailable)
            .unwrap();

        state
            .begin_automatic_recovery(WatchdogReason::LeaseExpired, "watchdog-1")
            .unwrap();
        assert_eq!(state.degraded_reason, None);
        state.finish_success(Action::Recover).unwrap();
        assert_eq!(state.stop_reason(), Some(WatchdogReason::LeaseExpired));

        state.begin(Action::Start, &alice, "start-2").unwrap();
        assert_eq!(state.stop_reason(), None);
        state.finish_success(Action::Start).unwrap();
        state.begin(Action::Stop, &alice, "stop-1").unwrap();
        state.finish_success(Action::Stop).unwrap();
        assert_eq!(state.stop_reason(), None);
    }

    #[test]
    fn manual_recovery_clears_the_automatic_fault_reason() {
        let alice = caller("alice", 1, false);
        let mut state = ServiceState::default();
        state.begin(Action::Start, &alice, "start-1").unwrap();
        state.finish_success(Action::Start).unwrap();
        state
            .record_automatic_fault(
                WatchdogReason::RuntimeIdentityMismatch,
                ErrorCode::OwnedProcessMismatch,
            )
            .unwrap();
        assert_eq!(
            state.stop_reason(),
            Some(WatchdogReason::RuntimeIdentityMismatch)
        );

        state.begin(Action::Recover, &alice, "recover-1").unwrap();
        assert_eq!(state.stop_reason(), None);
    }

    #[test]
    fn manual_start_clears_the_previous_watchdog_reason() {
        let alice = caller("alice", 1, false);
        let mut state = ServiceState {
            last_watchdog_reason: Some(WatchdogReason::EngineExited),
            ..ServiceState::default()
        };
        state.begin(Action::Start, &alice, "start-1").unwrap();
        assert!(state.last_watchdog_reason.is_none());
    }
}
