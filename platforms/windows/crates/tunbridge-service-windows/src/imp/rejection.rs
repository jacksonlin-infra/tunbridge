use std::{
    io::{self, Write},
    ptr,
};

use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    Security::{ImpersonateLoggedOnUser, RevertToSelf},
    System::RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken},
};

use crate::{frame, protocol::Hello};

use super::{
    pipe::{connect_client, PipeError},
    IdentityError, SecurePipeListener,
};

const NO_ACTIVE_CONSOLE_SESSION: u32 = u32::MAX;

/// Prove the kernel-derived token/process session comparison with a real user
/// token. This function is only compiled into the fixed acceptance SCM host.
pub(super) fn prove_session_mismatch_rejected() -> Result<(), RejectionProbeError> {
    // SAFETY: this read-only API has no pointer arguments.
    let console_session = unsafe { WTSGetActiveConsoleSessionId() };
    if console_session == NO_ACTIVE_CONSOLE_SESSION {
        return Err(RejectionProbeError::NoActiveConsoleSession);
    }

    let mut raw_token = ptr::null_mut();
    // SAFETY: the service runs as LocalSystem and raw_token is writable. The
    // returned primary token belongs to the active console user.
    if unsafe { WTSQueryUserToken(console_session, &mut raw_token) } == 0 {
        return Err(RejectionProbeError::Windows(io::Error::last_os_error()));
    }
    let token = OwnedHandle(raw_token);

    let name = format!(
        r"\\.\pipe\tunbridge-service-session-mismatch-{}",
        std::process::id()
    );
    let listener = SecurePipeListener::bind_rejection_probe(&name)?;
    let server = std::thread::spawn(move || listener.accept());

    // SAFETY: token is a valid active-console user token. The guard reverts
    // this exact thread before returning from the acceptance probe.
    if unsafe { ImpersonateLoggedOnUser(token.0) } == 0 {
        return Err(RejectionProbeError::Windows(io::Error::last_os_error()));
    }
    let impersonation = LoggedOnUserGuard;
    let mut client = connect_client(&name)?;
    client.write_all(&frame::encode(&Hello::new("0.1.0"))?)?;
    client.flush()?;

    let error = match server.join() {
        Ok(Ok(_)) => return Err(RejectionProbeError::UnexpectedAuthentication),
        Ok(Err(error)) => error,
        Err(_) => return Err(RejectionProbeError::ServerPanicked),
    };
    drop(client);
    drop(impersonation);

    match error {
        PipeError::Identity(IdentityError::AccessDenied(message))
            if message == "client token and process sessions do not match" =>
        {
            Ok(())
        }
        other => Err(RejectionProbeError::UnexpectedRejection(other.to_string())),
    }
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: WTSQueryUserToken transferred one owned handle.
            unsafe { CloseHandle(self.0) };
        }
    }
}

struct LoggedOnUserGuard;

impl Drop for LoggedOnUserGuard {
    fn drop(&mut self) {
        // SAFETY: this guard exists only after successful impersonation on the
        // current thread; failure is surfaced by the explicit product probe.
        unsafe { RevertToSelf() };
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum RejectionProbeError {
    #[error("no active console session is available")]
    NoActiveConsoleSession,
    #[error("Windows rejection probe operation failed: {0}")]
    Windows(#[from] io::Error),
    #[error(transparent)]
    Pipe(#[from] PipeError),
    #[error(transparent)]
    Protocol(#[from] crate::protocol::ProtocolError),
    #[error("session-mismatched client unexpectedly authenticated")]
    UnexpectedAuthentication,
    #[error("session-mismatch pipe server panicked")]
    ServerPanicked,
    #[error("session-mismatch probe returned an unexpected rejection: {0}")]
    UnexpectedRejection(String),
}
