//! Security-sensitive protocol and state-machine primitives for the privileged
//! TunBridge service.
//!
//! The Windows transport and Service Control Manager integration are layered on
//! top of this crate. Keeping the request validation and authorization logic
//! platform-independent makes every rejection path part of the normal test gate.

pub mod frame;
pub mod lease;
#[cfg(feature = "production-mihomo-logs-v4")]
pub mod mihomo_logs;
pub mod protocol;
pub mod startup;
pub mod state;
pub mod telemetry;
pub mod watchdog;

#[cfg(windows)]
#[path = "../../../platforms/windows/crates/tunbridge-service-windows/src/imp/mod.rs"]
pub mod windows;

pub use protocol::{ErrorCode, ProtocolError};
