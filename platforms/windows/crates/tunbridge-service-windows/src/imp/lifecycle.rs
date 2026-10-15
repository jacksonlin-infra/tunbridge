use std::sync::Arc;

use crate::{
    protocol::{ActiveStartProfile, ErrorCode},
    state::Caller,
};

use super::{
    prepare_validated_config, reconcile_owned_engine_for_recovery, start_prepared_engine,
    stop_persisted_owned_engine, ConfigError, HealthStage, LaunchError, OwnedEngineError,
    RecoveredOwnedEngine, UpstreamIdentityError,
};

pub trait LifecycleExecutor: Send + Sync {
    fn start(&self, profile: &ActiveStartProfile, caller: &Caller) -> Result<(), LifecycleFailure>;
    fn stop(&self) -> Result<(), LifecycleFailure>;
    fn recover(&self) -> Result<(), LifecycleFailure>;
    /// Installs or refreshes the traffic lock for the current session. It
    /// belongs to the user's start and stop and outlives the engine.
    fn install_traffic_lock(&self) -> Result<(), LifecycleFailure> {
        Ok(())
    }
    fn remove_traffic_lock(&self) -> Result<(), LifecycleFailure> {
        Ok(())
    }
    /// An unreadable lock counts as present, so nothing reports traffic as
    /// free when it may not be.
    fn traffic_lock_present(&self) -> bool {
        false
    }
}

pub type SharedLifecycleExecutor = Arc<dyn LifecycleExecutor>;

pub struct SystemLifecycleExecutor;

impl LifecycleExecutor for SystemLifecycleExecutor {
    fn start(&self, profile: &ActiveStartProfile, caller: &Caller) -> Result<(), LifecycleFailure> {
        let install_root = super::scm::program_files_directory()
            .map_err(|_| LifecycleFailure::internal())?
            .join("TunBridge");
        let prepared = prepare_validated_config(&install_root, profile)
            .map_err(LifecycleFailure::from_config)?;
        start_prepared_engine(&prepared, caller).map_err(LifecycleFailure::from_launch)?;
        Ok(())
    }

    fn stop(&self) -> Result<(), LifecycleFailure> {
        stop_persisted_owned_engine()
            .map(|_| ())
            .map_err(LifecycleFailure::from_owned)
    }

    fn install_traffic_lock(&self) -> Result<(), LifecycleFailure> {
        let engine = super::scm::program_files_directory()
            .map_err(|_| LifecycleFailure::internal())?
            .join("TunBridge")
            .join("mihomo.exe");
        let mut applications = vec![engine];
        // The verified local upstream client keeps reaching its servers.
        if let Ok(Some(record)) = super::load_owned_engine() {
            if !record.remote_upstream && record.upstream_image_path.is_absolute() {
                applications.push(record.upstream_image_path);
            }
        }
        super::traffic_lock::install(&applications).map_err(|_| LifecycleFailure::internal())
    }

    fn remove_traffic_lock(&self) -> Result<(), LifecycleFailure> {
        super::traffic_lock::remove().map_err(|_| LifecycleFailure::internal())
    }

    fn traffic_lock_present(&self) -> bool {
        super::traffic_lock::present().unwrap_or(true)
    }

    fn recover(&self) -> Result<(), LifecycleFailure> {
        // Reconcile first so a stale record whose PID has been reused can be
        // cleared without ever terminating the unrelated live process. Exact
        // running ownership still converges through the strict Stop path.
        match reconcile_owned_engine_for_recovery().map_err(LifecycleFailure::from_owned)? {
            RecoveredOwnedEngine::Running(_) => self.stop(),
            RecoveredOwnedEngine::Absent
            | RecoveredOwnedEngine::ClearedPending
            | RecoveredOwnedEngine::ClearedExited => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleFailure {
    pub code: ErrorCode,
    pub safe_message: &'static str,
    pub retryable: bool,
}

impl LifecycleFailure {
    pub const fn new(code: ErrorCode, safe_message: &'static str, retryable: bool) -> Self {
        Self {
            code,
            safe_message,
            retryable,
        }
    }

    fn internal() -> Self {
        Self::new(
            ErrorCode::InternalError,
            "the privileged lifecycle operation failed safely",
            false,
        )
    }

    fn from_config(error: ConfigError) -> Self {
        match error {
            ConfigError::Profile(_)
            | ConfigError::InvalidUpstreamProcessName
            | ConfigError::InvalidControllerSecret
            | ConfigError::CandidateEscape
            | ConfigError::RemoteAddressFamily => Self::for_code(ErrorCode::InvalidProfile),
            ConfigError::RemoteResolution(_) => Self::new(
                ErrorCode::ConfigValidationFailed,
                "the remote upstream address could not be resolved safely",
                true,
            ),
            ConfigError::Upstream(error) => Self::new(
                ErrorCode::InvalidProfile,
                upstream_identity_message(&error),
                true,
            ),
            ConfigError::Integrity(_) => Self::for_code(ErrorCode::EngineIntegrityFailed),
            ConfigError::Render(_) => Self::new(
                ErrorCode::ConfigValidationFailed,
                "the controlled engine configuration could not be rendered",
                false,
            ),
            ConfigError::EngineTestSpawn(_) => Self::new(
                ErrorCode::ConfigValidationFailed,
                "the controlled engine configuration test could not start",
                true,
            ),
            ConfigError::EngineRejected(_) => Self::new(
                ErrorCode::ConfigValidationFailed,
                "the controlled engine rejected the generated configuration",
                false,
            ),
            ConfigError::EngineTestTimeout => Self::new(
                ErrorCode::ConfigValidationFailed,
                "the controlled engine configuration test timed out",
                true,
            ),
            ConfigError::Random(_)
            | ConfigError::Io(_)
            | ConfigError::Storage(_)
            | ConfigError::CandidateCleanup { .. } => Self::internal(),
            #[cfg(feature = "acceptance-fault-injection")]
            ConfigError::AcceptanceFault(_) => Self::internal(),
        }
    }

    fn from_launch(error: LaunchError) -> Self {
        match error {
            LaunchError::Integrity(_) | LaunchError::EngineChanged => {
                Self::for_code(ErrorCode::EngineIntegrityFailed)
            }
            LaunchError::ExistingOwnedState => Self::for_code(ErrorCode::RecoveryRequired),
            LaunchError::OwnedIdentity(_) => Self::for_code(ErrorCode::OwnedProcessMismatch),
            LaunchError::HealthCheckFailed(stage) => Self::from_health(stage),
            LaunchError::HealthCheckRollback { .. } => Self::new(
                ErrorCode::InternalError,
                "engine startup validation failed and exact rollback did not complete",
                false,
            ),
            LaunchError::Spawn(_) => Self::new(
                ErrorCode::ConfigValidationFailed,
                "the controlled engine process could not start",
                true,
            ),
            LaunchError::ChildStatus(_) => Self::new(
                ErrorCode::InternalError,
                "the controlled engine process status could not be verified",
                false,
            ),
            LaunchError::ActiveConfigEscape
            | LaunchError::EnginePath
            | LaunchError::BoundaryIo(_)
            | LaunchError::Storage(_)
            | LaunchError::RollbackStop(_)
            | LaunchError::RollbackAdapter(_)
            | LaunchError::RollbackStorage(_) => Self::internal(),
            #[cfg(feature = "acceptance-fault-injection")]
            LaunchError::AcceptanceFault(_) => Self::internal(),
        }
    }

    fn from_health(stage: HealthStage) -> Self {
        let message = match stage {
            HealthStage::Upstream => "the upstream proxy preflight failed",
            HealthStage::ControllerPort => "the fixed engine controller port is unavailable",
            HealthStage::ExistingTun => "a pre-existing TunBridge adapter blocks startup",
            HealthStage::Controller => "the controlled engine controller did not become ready",
            HealthStage::Tun => "the controlled TUN adapter did not become ready",
            HealthStage::Transparent => "the transparent network self-test failed",
            HealthStage::EngineProcess => "the controlled engine exited during startup",
        };
        Self::new(ErrorCode::ConfigValidationFailed, message, true)
    }

    fn from_owned(error: OwnedEngineError) -> Self {
        match error {
            OwnedEngineError::AdapterCleanup(_) => Self::new(
                ErrorCode::InternalError,
                "the controlled network adapter could not be removed",
                true,
            ),
            OwnedEngineError::Storage(_) => Self::for_code(ErrorCode::InternalError),
            _ => Self::for_code(ErrorCode::OwnedProcessMismatch),
        }
    }

    fn for_code(code: ErrorCode) -> Self {
        match code {
            ErrorCode::InvalidProfile => Self::new(
                code,
                "the requested profile failed service validation",
                false,
            ),
            ErrorCode::EngineIntegrityFailed => Self::new(
                code,
                "the installed engine failed integrity validation",
                false,
            ),
            ErrorCode::ConfigValidationFailed => {
                Self::new(code, "the controlled engine start validation failed", true)
            }
            ErrorCode::OwnedProcessMismatch => Self::new(
                code,
                "the recorded engine identity could not be verified",
                false,
            ),
            ErrorCode::RecoveryRequired => Self::new(
                code,
                "owned engine recovery is required before start",
                false,
            ),
            _ => Self::internal(),
        }
    }
}

fn upstream_identity_message(error: &UpstreamIdentityError) -> &'static str {
    match error {
        UpstreamIdentityError::Profile(_) => "the upstream profile is invalid",
        UpstreamIdentityError::ListenerMismatch => {
            "the upstream listener endpoint has no matching process owner"
        }
        UpstreamIdentityError::AmbiguousListenerOwners => {
            "the upstream listener endpoint has multiple process owners"
        }
        UpstreamIdentityError::ListenerChanged => {
            "the upstream listener process changed during validation"
        }
        UpstreamIdentityError::TcpTable(_) => "the Windows TCP listener table could not be queried",
        UpstreamIdentityError::TcpTableUnstable => {
            "the Windows TCP listener table changed during validation"
        }
        UpstreamIdentityError::MalformedTcpTable => {
            "the Windows TCP listener table returned invalid data"
        }
        UpstreamIdentityError::ProcessQuery(_) => {
            "the upstream listener process could not be inspected"
        }
        UpstreamIdentityError::ProcessIdentityChanged => {
            "the upstream listener process identity changed during validation"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ProtocolError;

    #[test]
    fn internal_errors_are_mapped_to_stable_redacted_failures() {
        let failure = LifecycleFailure::from_config(ConfigError::Profile(
            ProtocolError::InvalidProfile("contains-secret".into()),
        ));
        assert_eq!(failure.code, ErrorCode::InvalidProfile);
        assert!(!failure.safe_message.contains("secret"));

        let failure = LifecycleFailure::from_owned(OwnedEngineError::CreationTimeMismatch);
        assert_eq!(failure.code, ErrorCode::OwnedProcessMismatch);
        assert!(!failure.retryable);

        let failure = LifecycleFailure::from_owned(OwnedEngineError::AdapterCleanup(
            super::super::AdapterError::UnverifiedDeviceIdentity,
        ));
        assert_eq!(failure.code, ErrorCode::InternalError);
        assert_eq!(
            failure.safe_message,
            "the controlled network adapter could not be removed"
        );
        assert!(failure.retryable);

        #[cfg(feature = "acceptance-fault-injection")]
        {
            let injected = LifecycleFailure::from_owned(OwnedEngineError::AdapterCleanup(
                super::super::AdapterError::AcceptanceInjectedCleanupFailure,
            ));
            assert_eq!(injected.code, ErrorCode::InternalError);
            assert_eq!(injected.safe_message, failure.safe_message);
            assert!(injected.retryable);
        }
    }

    #[test]
    fn startup_stages_have_stable_safe_diagnostics() {
        let cases = [
            (HealthStage::Upstream, "upstream proxy preflight"),
            (HealthStage::ControllerPort, "controller port"),
            (HealthStage::ExistingTun, "pre-existing TunBridge adapter"),
            (HealthStage::Controller, "controller did not become ready"),
            (HealthStage::Tun, "TUN adapter did not become ready"),
            (HealthStage::Transparent, "transparent network self-test"),
            (HealthStage::EngineProcess, "engine exited during startup"),
        ];
        for (stage, expected) in cases {
            let failure = LifecycleFailure::from_launch(LaunchError::HealthCheckFailed(stage));
            assert_eq!(failure.code, ErrorCode::ConfigValidationFailed);
            assert!(failure.safe_message.contains(expected));
            assert!(failure.retryable);
        }

        let rejected = LifecycleFailure::from_config(ConfigError::EngineRejected(Some(1)));
        assert_eq!(rejected.code, ErrorCode::ConfigValidationFailed);
        assert_eq!(
            rejected.safe_message,
            "the controlled engine rejected the generated configuration"
        );
        assert!(!rejected.retryable);
    }

    #[test]
    fn upstream_identity_failures_have_fixed_stage_diagnostics() {
        let failure = LifecycleFailure::from_config(ConfigError::Upstream(
            UpstreamIdentityError::ListenerMismatch,
        ));
        assert_eq!(failure.code, ErrorCode::InvalidProfile);
        assert_eq!(
            failure.safe_message,
            "the upstream listener endpoint has no matching process owner"
        );
        assert!(failure.retryable);
    }
}
