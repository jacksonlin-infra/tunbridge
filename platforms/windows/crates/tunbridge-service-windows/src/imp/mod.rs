//! Windows-only transport and caller identity boundary.

#[cfg(feature = "acceptance-fault-injection")]
mod acceptance;
mod adapter;
mod client;
mod config;
mod integrity;
mod launch;
mod lifecycle;
#[cfg(feature = "production-local-observability")]
mod local_observability;
#[cfg(feature = "acceptance-m2b5")]
mod m2b5_acceptance;
mod owned;
mod pipe;
mod power;
mod process;
mod random;
#[cfg(feature = "acceptance-rejection")]
mod rejection;
#[cfg(feature = "acceptance-m2b5")]
mod runtime_telemetry;
mod runtime_watchdog;
mod scm;
mod security;
mod server;
mod storage;
mod traffic_lock;
mod upstream;

pub use adapter::{
    native_adapter_exists, native_adapter_instance_id, remove_owned_tun_adapter,
    remove_owned_tun_adapter_instance, AdapterError, AdapterRemoval, TUN_ALIAS,
};
pub use client::{ClientError, ServiceClient};
pub use config::{
    prepare_validated_config, render_service_config, validate_engine_config, ConfigError,
    PreparedServiceConfig, RenderedServiceConfig,
};
pub use integrity::{
    reject_reparse_point, validate_asset_acl, validate_engine_files, EngineEntry, EngineManifest,
    IntegrityError, ValidatedEngine,
};
pub use launch::{start_prepared_engine, HealthStage, LaunchError};
pub use lifecycle::{
    LifecycleExecutor, LifecycleFailure, SharedLifecycleExecutor, SystemLifecycleExecutor,
};
#[cfg(feature = "acceptance-m2b5")]
pub use owned::exact_owned_process_running_for_acceptance;
pub use owned::{
    clear_owned_engine, load_owned_engine, persist_owned_engine, reconcile_owned_engine,
    reconcile_owned_engine_for_recovery, stop_persisted_owned_engine, verify_owned_engine,
    OwnedEngineError, OwnedEngineRecord, OwnedEngineStage, RecoveredOwnedEngine, StopOwnedOutcome,
};
#[cfg(feature = "acceptance-fault-injection")]
pub use owned::{remove_owned_adapter_for_acceptance, terminate_owned_process_for_acceptance};
pub use pipe::{PipeConnection, SecurePipeListener, PIPE_NAME, PIPE_SDDL};
pub use process::{query_process_identity, ProcessIdentity, ProcessIdentityError};
#[cfg(feature = "acceptance-rejection")]
pub use scm::run_rejection_dispatcher;
pub use scm::{
    ensure_service_started, install, run_dispatcher, service_registration, uninstall, ScmError,
    ServiceRegistration, SERVICE_NAME,
};
pub use security::{CallerIdentity, IdentityError, TokenFacts};
pub use server::{
    serve_connection, ConnectionLimiter, ServerError, ServiceContext, ShutdownToken,
    MAX_AUTHENTICATED_CONNECTIONS,
};
pub use storage::{cleanup_product_data_for_uninstall, ProtectedDataDirectory, StorageError};
pub use upstream::{
    listener_owner_snapshot, resolve_unique_loopback_listener,
    resolve_unique_loopback_listener_pid, reverify_upstream_listener,
    verify_loopback_listener_owner, verify_recorded_loopback_listener, verify_upstream_listener,
    ListenerOwnerSnapshot, UpstreamIdentityError, VerifiedUpstream,
};
