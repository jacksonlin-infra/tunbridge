//! Pure startup-reconcile policy.
//!
//! Platform code supplies already-classified evidence. This module contains no
//! Windows handles, paths, process identifiers, adapter names, I/O, clocks, or
//! cleanup implementation.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessFact {
    ExactRunning,
    Exited,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeFact {
    Exact,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupObservation {
    Absent,
    Invalid,
    Pending {
        process: ProcessFact,
    },
    Running {
        process: ProcessFact,
        runtime: RuntimeFact,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupDecision {
    StoppedNoAction,
    FaultNoAction,
    ConvergePendingExactProcess,
    ConvergeExitedRecord,
    RestoreRunning,
}

impl StartupDecision {
    #[must_use]
    pub const fn authorizes_process_termination(self) -> bool {
        matches!(self, Self::ConvergePendingExactProcess)
    }

    #[must_use]
    pub const fn requires_adapter_decision(self) -> bool {
        matches!(
            self,
            Self::ConvergePendingExactProcess | Self::ConvergeExitedRecord
        )
    }
}

#[must_use]
pub const fn decide_startup(observation: StartupObservation) -> StartupDecision {
    match observation {
        StartupObservation::Absent => StartupDecision::StoppedNoAction,
        StartupObservation::Invalid => StartupDecision::FaultNoAction,
        StartupObservation::Pending { process } => match process {
            ProcessFact::ExactRunning => StartupDecision::ConvergePendingExactProcess,
            ProcessFact::Exited => StartupDecision::ConvergeExitedRecord,
            ProcessFact::Unknown => StartupDecision::FaultNoAction,
        },
        StartupObservation::Running { process, runtime } => match (process, runtime) {
            (ProcessFact::ExactRunning, RuntimeFact::Exact) => StartupDecision::RestoreRunning,
            (ProcessFact::Exited, _) => StartupDecision::ConvergeExitedRecord,
            (ProcessFact::ExactRunning | ProcessFact::Unknown, _) => StartupDecision::FaultNoAction,
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterFact {
    Missing,
    ExactOwned,
    Preexisting,
    Other,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterDecision {
    ClearState,
    RemoveExactThenClear,
    FaultRetainState,
}

impl AdapterDecision {
    #[must_use]
    pub const fn authorizes_adapter_removal(self) -> bool {
        matches!(self, Self::RemoveExactThenClear)
    }

    #[must_use]
    pub const fn authorizes_state_clear(self) -> bool {
        matches!(self, Self::ClearState | Self::RemoveExactThenClear)
    }
}

#[must_use]
pub const fn decide_adapter(fact: AdapterFact) -> AdapterDecision {
    match fact {
        AdapterFact::Missing => AdapterDecision::ClearState,
        AdapterFact::ExactOwned => AdapterDecision::RemoveExactThenClear,
        AdapterFact::Preexisting | AdapterFact::Other | AdapterFact::Unknown => {
            AdapterDecision::FaultRetainState
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_and_invalid_records_never_authorize_side_effects() {
        for observation in [StartupObservation::Absent, StartupObservation::Invalid] {
            let decision = decide_startup(observation);
            assert!(!decision.authorizes_process_termination());
            assert!(!decision.requires_adapter_decision());
        }
        assert_eq!(
            decide_startup(StartupObservation::Absent),
            StartupDecision::StoppedNoAction
        );
        assert_eq!(
            decide_startup(StartupObservation::Invalid),
            StartupDecision::FaultNoAction
        );
    }

    #[test]
    fn pending_process_evidence_has_three_distinct_outcomes() {
        assert_eq!(
            decide_startup(StartupObservation::Pending {
                process: ProcessFact::ExactRunning,
            }),
            StartupDecision::ConvergePendingExactProcess
        );
        assert_eq!(
            decide_startup(StartupObservation::Pending {
                process: ProcessFact::Exited,
            }),
            StartupDecision::ConvergeExitedRecord
        );
        assert_eq!(
            decide_startup(StartupObservation::Pending {
                process: ProcessFact::Unknown,
            }),
            StartupDecision::FaultNoAction
        );
    }

    #[test]
    fn only_exact_live_running_runtime_restores_owner() {
        for process in [
            ProcessFact::ExactRunning,
            ProcessFact::Exited,
            ProcessFact::Unknown,
        ] {
            for runtime in [RuntimeFact::Exact, RuntimeFact::Unknown] {
                let decision = decide_startup(StartupObservation::Running { process, runtime });
                let expected = match (process, runtime) {
                    (ProcessFact::ExactRunning, RuntimeFact::Exact) => {
                        StartupDecision::RestoreRunning
                    }
                    (ProcessFact::Exited, _) => StartupDecision::ConvergeExitedRecord,
                    _ => StartupDecision::FaultNoAction,
                };
                assert_eq!(decision, expected);
            }
        }
    }

    #[test]
    fn only_pending_exact_process_authorizes_termination() {
        let observations = [
            StartupObservation::Absent,
            StartupObservation::Invalid,
            StartupObservation::Pending {
                process: ProcessFact::ExactRunning,
            },
            StartupObservation::Pending {
                process: ProcessFact::Exited,
            },
            StartupObservation::Pending {
                process: ProcessFact::Unknown,
            },
            StartupObservation::Running {
                process: ProcessFact::ExactRunning,
                runtime: RuntimeFact::Exact,
            },
            StartupObservation::Running {
                process: ProcessFact::ExactRunning,
                runtime: RuntimeFact::Unknown,
            },
            StartupObservation::Running {
                process: ProcessFact::Exited,
                runtime: RuntimeFact::Unknown,
            },
            StartupObservation::Running {
                process: ProcessFact::Unknown,
                runtime: RuntimeFact::Exact,
            },
        ];

        let authorized = observations
            .into_iter()
            .filter(|observation| decide_startup(*observation).authorizes_process_termination())
            .count();
        assert_eq!(authorized, 1);
    }

    #[test]
    fn adapter_policy_removes_only_exact_owned_identity() {
        for fact in [
            AdapterFact::Missing,
            AdapterFact::ExactOwned,
            AdapterFact::Preexisting,
            AdapterFact::Other,
            AdapterFact::Unknown,
        ] {
            let decision = decide_adapter(fact);
            assert_eq!(
                decision.authorizes_adapter_removal(),
                fact == AdapterFact::ExactOwned
            );
        }
    }

    #[test]
    fn ambiguous_adapter_evidence_always_retains_state() {
        for fact in [
            AdapterFact::Preexisting,
            AdapterFact::Other,
            AdapterFact::Unknown,
        ] {
            let decision = decide_adapter(fact);
            assert_eq!(decision, AdapterDecision::FaultRetainState);
            assert!(!decision.authorizes_adapter_removal());
            assert!(!decision.authorizes_state_clear());
        }
    }

    #[test]
    fn missing_adapter_clears_only_state() {
        let decision = decide_adapter(AdapterFact::Missing);
        assert_eq!(decision, AdapterDecision::ClearState);
        assert!(!decision.authorizes_adapter_removal());
        assert!(decision.authorizes_state_clear());
    }

    #[test]
    fn exact_owned_adapter_removes_before_state_clear() {
        let decision = decide_adapter(AdapterFact::ExactOwned);
        assert_eq!(decision, AdapterDecision::RemoveExactThenClear);
        assert!(decision.authorizes_adapter_removal());
        assert!(decision.authorizes_state_clear());
    }
}
