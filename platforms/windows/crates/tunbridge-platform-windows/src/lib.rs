//! Windows operating-system adapters.
//!
//! P1 keeps the accepted implementation exported from `tunbridge-core` while
//! platform-specific sources move under `platforms/windows`.

#[cfg(windows)]
pub use tunbridge_core::platform::windows::*;
