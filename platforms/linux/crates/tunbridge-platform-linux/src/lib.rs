//! Linux operating-system adapters.

pub const PLATFORM_ID: &str = "linux";

#[cfg(target_os = "linux")]
mod paths;
#[cfg(target_os = "linux")]
mod process_discovery;
#[cfg(target_os = "linux")]
mod profile_files;

#[cfg(target_os = "linux")]
pub use paths::{LinuxUserPaths, PathError};
#[cfg(target_os = "linux")]
pub use process_discovery::LinuxProcessDiscovery;
#[cfg(target_os = "linux")]
pub use profile_files::{LinuxProfileStoreFiles, LinuxProfileStoreLock};
