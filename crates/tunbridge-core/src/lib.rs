// Unsafe is denied crate-wide. The single documented exception is the Windows
// handle-inheritance fix in `engine::detach_std_handles_from_children`, which
// stops a detached kernel from holding a caller's stdout pipe open forever.
#![deny(unsafe_code)]

pub mod config;
pub mod config_v2;
pub mod discovery;
pub mod engine;
pub mod error;
pub mod lifecycle;
pub mod net;
pub mod netstate;
pub mod platform;
pub mod probe;
pub mod profile;
pub mod profile_v2;
pub mod release;
pub mod remote;
pub mod state;
pub mod upstream;

pub use error::{CoreError, Result};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_is_stable() {
        assert_eq!(
            CoreError::NeedsElevation.to_string(),
            "this operation requires an elevated (administrator) process"
        );
    }
}
