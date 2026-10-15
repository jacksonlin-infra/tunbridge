use std::{
    ffi::c_void,
    fs::File,
    io::{self, Read, Write},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
    ptr,
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::{GetLastError, LocalFree, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE},
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_READ_DATA, FILE_WRITE_DATA, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX,
    },
    System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
        ImpersonateNamedPipeClient, PeekNamedPipe, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE, PIPE_WAIT,
    },
};

use super::security::{
    capture_impersonated_client, CallerIdentity, IdentityError, ImpersonationGuard,
};
use super::server::ShutdownToken;
use crate::{
    frame,
    protocol::{Hello, ProtocolError, MAX_FRAME_BYTES},
};

#[cfg(not(any(feature = "production-app-lease", feature = "acceptance-m2b5")))]
pub const PIPE_NAME: &str = r"\\.\pipe\tunbridge-service-v1";
#[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
pub const PIPE_NAME: &str = r"\\.\pipe\tunbridge-service-v2";
pub const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100083;;;IU)S:(ML;;NW;;;ME)";

const PIPE_BUFFER_BYTES: u32 = 65_540;
const PIPE_INSTANCES: u32 = 17;
pub(super) const HELLO_TIMEOUT: Duration = Duration::from_secs(2);
pub(super) const REQUEST_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
pub(super) const LEASE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const REQUEST_FRAME_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const LIFECYCLE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(75);
const POLL_INTERVAL: Duration = Duration::from_millis(5);

pub struct SecurePipeListener {
    handle: OwnedHandle,
}

impl SecurePipeListener {
    /// Create the first instance with FILE_FLAG_FIRST_PIPE_INSTANCE so startup
    /// fails if another process has already squatted on the fixed pipe name.
    pub fn bind_first() -> Result<Self, PipeError> {
        Self::bind(PIPE_NAME, true)
    }

    /// Create an additional server instance after the first instance has
    /// established ownership of the pipe name.
    pub fn bind_next() -> Result<Self, PipeError> {
        Self::bind(PIPE_NAME, false)
    }

    fn bind(name: &str, first: bool) -> Result<Self, PipeError> {
        Self::bind_with_sddl(name, first, PIPE_SDDL)
    }

    fn bind_with_sddl(name: &str, first: bool, sddl: &str) -> Result<Self, PipeError> {
        let wide_name = wide(name);
        let descriptor = SecurityDescriptor::from_sddl(sddl)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of_u32::<SECURITY_ATTRIBUTES>(),
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let mut open_mode = PIPE_ACCESS_DUPLEX;
        if first {
            open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        let pipe_mode =
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;

        // SAFETY: all pointers remain valid for the call; SECURITY_ATTRIBUTES
        // contains a self-relative descriptor allocated by Windows.
        let raw = unsafe {
            CreateNamedPipeW(
                wide_name.as_ptr(),
                open_mode,
                pipe_mode,
                PIPE_INSTANCES,
                PIPE_BUFFER_BYTES,
                PIPE_BUFFER_BYTES,
                5_000,
                &attributes,
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(PipeError::Windows(io::Error::last_os_error()));
        }
        // SAFETY: CreateNamedPipeW returned a newly owned valid handle.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
        Ok(Self { handle })
    }

    /// Wait for one client, read and validate the bounded Hello frame, then
    /// authenticate its kernel-derived identity and transfer the stream.
    ///
    /// Windows requires the server to read data before pipe impersonation. The
    /// only pre-authentication parser surface is therefore one length-bounded,
    /// strict Hello frame.
    pub fn accept(self) -> Result<PipeConnection, PipeError> {
        self.wait_for_client()?;
        self.finish_accept_until(None)
    }

    /// Accept one connection while creating the next protected instance before
    /// parsing client input, so the fixed pipe name never becomes unowned.
    pub fn accept_and_rearm(self) -> Result<(PipeConnection, SecurePipeListener), PipeError> {
        self.wait_for_client()?;
        let next = Self::bind_next()?;
        let connection = self.finish_accept_until(None)?;
        Ok((connection, next))
    }

    /// Accept one client and always hand back the next protected instance.
    /// A client that disconnects, stalls or fails the handshake affects only
    /// its own connection: the inner result carries that failure while the
    /// outer result is reserved for shutdown and listener creation failures.
    pub(super) fn accept_and_rearm_until(
        self,
        shutdown: &ShutdownToken,
    ) -> Result<(Result<PipeConnection, PipeError>, SecurePipeListener), PipeError> {
        let waited = self.wait_for_client();
        if shutdown.is_cancelled() {
            return Err(PipeError::Shutdown);
        }
        let next = Self::bind_next()?;
        let connection = waited.and_then(|()| self.finish_accept_until(Some(shutdown)));
        Ok((connection, next))
    }

    fn wait_for_client(&self) -> Result<(), PipeError> {
        let raw = self.handle.as_raw_handle() as HANDLE;
        // SAFETY: raw is a listening named-pipe handle. A client that connects
        // between CreateNamedPipe and this call yields ERROR_PIPE_CONNECTED,
        // which is also a successful accept.
        if unsafe { ConnectNamedPipe(raw, ptr::null_mut()) } == 0 {
            let error = unsafe { GetLastError() };
            if error != ERROR_PIPE_CONNECTED {
                return Err(PipeError::Windows(io::Error::from_raw_os_error(
                    error as i32,
                )));
            }
        }
        Ok(())
    }

    fn finish_accept_until(
        self,
        shutdown: Option<&ShutdownToken>,
    ) -> Result<PipeConnection, PipeError> {
        let mut file = File::from(self.handle);
        let hello: Hello = frame::decode(&read_one_frame_until(
            &mut file,
            HELLO_TIMEOUT,
            HELLO_TIMEOUT,
            shutdown,
        )?)?;
        hello.validate()?;
        let identity = authenticate(file.as_raw_handle() as HANDLE)?;
        Ok(PipeConnection {
            file,
            identity,
            hello,
        })
    }

    #[cfg(test)]
    pub(super) fn bind_test(name: &str, first: bool) -> Result<Self, PipeError> {
        Self::bind(name, first)
    }

    #[cfg(feature = "acceptance-rejection")]
    pub(super) fn bind_rejection_probe(name: &str) -> Result<Self, PipeError> {
        Self::bind(name, true)
    }
}

pub struct PipeConnection {
    pub file: File,
    pub identity: CallerIdentity,
    pub hello: Hello,
}

impl PipeConnection {
    pub fn read<T: serde::de::DeserializeOwned>(&mut self) -> Result<T, PipeError> {
        Ok(frame::decode(&read_one_frame(
            &mut self.file,
            REQUEST_IDLE_TIMEOUT,
            REQUEST_FRAME_TIMEOUT,
        )?)?)
    }

    pub(super) fn read_until_shutdown<T: serde::de::DeserializeOwned>(
        &mut self,
        shutdown: &ShutdownToken,
    ) -> Result<T, PipeError> {
        Ok(frame::decode(&read_one_frame_until(
            &mut self.file,
            REQUEST_IDLE_TIMEOUT,
            REQUEST_FRAME_TIMEOUT,
            Some(shutdown),
        )?)?)
    }

    pub fn write<T: serde::Serialize>(&mut self, value: &T) -> Result<(), PipeError> {
        self.file
            .write_all(&frame::encode(value)?)
            .map_err(PipeError::Windows)?;
        self.file.flush().map_err(PipeError::Windows)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PipeError {
    #[error("Windows pipe operation failed: {0}")]
    Windows(#[source] io::Error),
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("invalid pipe security descriptor")]
    InvalidSecurityDescriptor,
    #[error("named pipe {0} timed out")]
    Timeout(&'static str),
    #[error("named pipe operation cancelled for service shutdown")]
    Shutdown,
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

impl PipeError {
    pub fn is_disconnect(&self) -> bool {
        match self {
            Self::Windows(error) => matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset
            ),
            Self::Identity(_)
            | Self::InvalidSecurityDescriptor
            | Self::Timeout(_)
            | Self::Shutdown
            | Self::Protocol(_) => false,
        }
    }
}

pub(super) fn read_one_frame(
    file: &mut File,
    idle_timeout: Duration,
    frame_timeout: Duration,
) -> Result<Vec<u8>, PipeError> {
    read_one_frame_until(file, idle_timeout, frame_timeout, None)
}

fn read_one_frame_until(
    file: &mut File,
    idle_timeout: Duration,
    frame_timeout: Duration,
    shutdown: Option<&ShutdownToken>,
) -> Result<Vec<u8>, PipeError> {
    wait_for_bytes(file, 4, Instant::now() + idle_timeout, "idle", shutdown)?;
    let mut prefix = [0_u8; 4];
    file.read_exact(&mut prefix).map_err(PipeError::Windows)?;
    let length = u32::from_le_bytes(prefix) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(PipeError::Protocol(ProtocolError::FrameTooLarge(length)));
    }
    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&prefix);
    frame.resize(4 + length, 0);
    wait_for_bytes(
        file,
        length,
        Instant::now() + frame_timeout,
        "frame",
        shutdown,
    )?;
    file.read_exact(&mut frame[4..])
        .map_err(PipeError::Windows)?;
    Ok(frame)
}

fn wait_for_bytes(
    file: &File,
    required: usize,
    deadline: Instant,
    phase: &'static str,
    shutdown: Option<&ShutdownToken>,
) -> Result<(), PipeError> {
    if required == 0 {
        return Ok(());
    }
    loop {
        if shutdown.is_some_and(ShutdownToken::is_cancelled) {
            return Err(PipeError::Shutdown);
        }
        let mut available = 0_u32;
        // SAFETY: file is a connected pipe handle and available points to one
        // writable DWORD. PeekNamedPipe does not consume bytes.
        if unsafe {
            PeekNamedPipe(
                file.as_raw_handle() as HANDLE,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut available,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(PipeError::Windows(io::Error::last_os_error()));
        }
        if available as usize >= required {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(PipeError::Timeout(phase));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn authenticate(pipe: HANDLE) -> Result<CallerIdentity, PipeError> {
    let mut client_process_id = 0_u32;
    // SAFETY: pipe is connected and output points to a writable u32.
    if unsafe { GetNamedPipeClientProcessId(pipe, &mut client_process_id) } == 0 {
        return Err(PipeError::Windows(io::Error::last_os_error()));
    }
    // SAFETY: pipe is a connected server-side named pipe.
    if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
        return Err(PipeError::Windows(io::Error::last_os_error()));
    }
    let guard = ImpersonationGuard::active();
    let identity = capture_impersonated_client(client_process_id);
    let revert = guard.revert();
    match (identity, revert) {
        (_, Err(error)) => Err(PipeError::Identity(error)),
        (Err(error), Ok(())) => Err(PipeError::Identity(error)),
        (Ok(identity), Ok(())) => Ok(identity),
    }
}

struct SecurityDescriptor(*mut c_void);

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self, PipeError> {
        let wide_sddl = wide(sddl);
        let mut descriptor = ptr::null_mut();
        // SAFETY: input is NUL-terminated and descriptor points to writable
        // storage. Windows allocates the resulting self-relative descriptor.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide_sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(PipeError::InvalidSecurityDescriptor);
        }
        Ok(Self(descriptor))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: descriptor was allocated by the conversion API.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn size_of_u32<T>() -> u32 {
    u32::try_from(std::mem::size_of::<T>()).expect("Windows structure size fits in u32")
}

pub(super) fn connect_client(name: &str) -> io::Result<File> {
    let wide_name = wide(name);
    // Use only the exact data rights required by the synchronous client. The
    // handle does not need an explicit SYNCHRONIZE request for blocking pipe
    // I/O. Requesting any broader generic right is intentionally avoided:
    // GENERIC_WRITE is intentionally denied because Windows maps it to
    // FILE_CREATE_PIPE_INSTANCE for named pipes.
    let access = FILE_READ_DATA | FILE_WRITE_DATA;
    // SAFETY: the path is NUL-terminated, OPEN_EXISTING does not consume a
    // security descriptor or template handle, and a successful call transfers
    // ownership of one client handle.
    let raw = unsafe {
        CreateFileW(
            wide_name.as_ptr(),
            access,
            0,
            ptr::null(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_handle(raw as RawHandle) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::sync::Arc;

    use windows_sys::Win32::{
        Foundation::{CloseHandle, LocalFree, ERROR_ACCESS_DENIED, HANDLE, WAIT_OBJECT_0},
        Security::{
            Authorization::ConvertStringSidToSidW, CreateRestrictedToken, CreateWellKnownSid,
            GetLengthSid, SetTokenInformation, TokenIntegrityLevel, WinAuthenticatedUserSid,
            WinInteractiveSid, DISABLE_MAX_PRIVILEGE, PSID, SID_AND_ATTRIBUTES,
            TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL,
            TOKEN_QUERY, WELL_KNOWN_SID_TYPE,
        },
        System::SystemServices::SE_GROUP_INTEGRITY,
        System::Threading::{
            CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken,
            WaitForSingleObject, PROCESS_INFORMATION, STARTUPINFOW,
        },
    };

    use crate::{
        protocol::{
            Command, HelloOk, Request, RequestKind, Response, ResponseData, PROTOCOL_VERSION,
        },
        state::ServiceState,
    };

    #[test]
    fn fixed_security_descriptor_is_accepted_by_windows() {
        SecurityDescriptor::from_sddl(PIPE_SDDL).unwrap();
    }

    #[test]
    fn first_instance_prevents_pipe_name_squatting() {
        let name = format!(r"\\.\pipe\tunbridge-service-test-{}", std::process::id());
        let first = SecurePipeListener::bind_test(&name, true).unwrap();
        assert!(SecurePipeListener::bind_test(&name, true).is_err());
        drop(first);
        let replacement = SecurePipeListener::bind_test(&name, true).unwrap();
        drop(replacement);
    }

    #[test]
    fn pipe_contract_is_fixed_and_remote_rejection_is_compiled_in() {
        #[cfg(not(any(feature = "production-app-lease", feature = "acceptance-m2b5")))]
        assert_eq!(PIPE_NAME, r"\\.\pipe\tunbridge-service-v1");
        #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
        assert_eq!(PIPE_NAME, r"\\.\pipe\tunbridge-service-v2");
        assert_ne!(PIPE_REJECT_REMOTE_CLIENTS, 0);
        assert!(PIPE_SDDL.contains("0x00100083;;;IU"));
        assert_eq!(0x00100083 & 0x4, 0);
        assert!(!PIPE_SDDL.contains("GRGW"));
        assert!(PIPE_SDDL.contains(";;;IU"));
        assert!(!PIPE_SDDL.contains(";;;WD"));
        assert!(!PIPE_SDDL.contains(";;;AN"));
        assert!(!PIPE_SDDL.contains(";;;NU"));
    }

    #[test]
    #[ignore = "requires an interactive Windows token"]
    fn real_pipe_authenticates_current_interactive_client() {
        let name = format!(
            r"\\.\pipe\tunbridge-service-auth-test-{}",
            std::process::id()
        );
        let listener = SecurePipeListener::bind_test(&name, true).unwrap();
        let server = std::thread::spawn(move || listener.accept().map(|pipe| pipe.identity));

        let mut client = connect_client(&name).unwrap();
        client
            .write_all(&frame::encode(&Hello::new("0.1.0")).unwrap())
            .unwrap();
        let identity = server.join().unwrap().unwrap();
        assert_eq!(identity.client_process_id, std::process::id());
        assert!(!identity.caller.principal_id.is_empty());
        drop(client);
    }

    #[test]
    #[ignore = "requires an interactive Windows token"]
    fn real_pipe_completes_authenticated_status_round_trip() {
        let name = format!(
            r"\\.\pipe\tunbridge-service-status-test-{}",
            std::process::id()
        );
        let listener = SecurePipeListener::bind_test(&name, true).unwrap();
        let server = std::thread::spawn(move || {
            let connection = listener.accept()?;
            super::super::server::serve_connection(
                connection,
                Arc::new(super::super::server::ServiceContext::status_only(
                    ServiceState::default(),
                )),
            )
            .map_err(|error| PipeError::Windows(io::Error::other(error.to_string())))
        });

        let mut client = connect_client(&name).unwrap();
        client
            .write_all(&frame::encode(&Hello::new("0.1.0")).unwrap())
            .unwrap();
        let hello: HelloOk =
            frame::decode(&read_one_frame(&mut client, HELLO_TIMEOUT, HELLO_TIMEOUT).unwrap())
                .unwrap();
        let request = Request {
            kind: RequestKind::Request,
            protocol: PROTOCOL_VERSION,
            session_nonce: hello.session_nonce,
            seq: 1,
            request_id: "1".repeat(32),
            command: Command::Status,
        };
        client.write_all(&frame::encode(&request).unwrap()).unwrap();
        let response: Response =
            frame::decode(&read_one_frame(&mut client, HELLO_TIMEOUT, HELLO_TIMEOUT).unwrap())
                .unwrap();
        assert!(response.result.ok);
        assert!(matches!(
            response.result.data,
            Some(ResponseData::Status {
                service_phase: crate::state::Phase::Stopped,
                engine_running: false,
                ..
            })
        ));
        drop(client);
        server.join().unwrap().unwrap();
    }

    #[test]
    #[ignore = "requires an interactive Windows token and waits for the Hello deadline"]
    fn real_pipe_rejects_silent_client_after_hello_timeout() {
        let name = format!(
            r"\\.\pipe\tunbridge-service-timeout-test-{}",
            std::process::id()
        );
        let listener = SecurePipeListener::bind_test(&name, true).unwrap();
        let started = Instant::now();
        let server = std::thread::spawn(move || listener.accept());
        let client = connect_client(&name).unwrap();

        let error = match server.join().unwrap() {
            Ok(_) => panic!("silent client unexpectedly authenticated"),
            Err(error) => error,
        };
        assert!(matches!(error, PipeError::Timeout("idle")));
        assert!(started.elapsed() >= Duration::from_millis(1_800));
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(client);
    }

    #[test]
    #[ignore = "requires an interactive Windows token"]
    fn real_pipe_rejects_malformed_hello_before_authentication() {
        let unknown_field = framed_json(
            r#"{"kind":"hello","protocol":1,"client_version":"0.1.0","path":"C:\\evil"}"#,
        );
        let duplicate_field =
            framed_json(r#"{"kind":"hello","protocol":1,"protocol":1,"client_version":"0.1.0"}"#);
        let oversized = ((MAX_FRAME_BYTES + 1) as u32).to_le_bytes().to_vec();

        for (case, frame, oversized_expected) in [
            ("unknown", unknown_field, false),
            ("duplicate", duplicate_field, false),
            ("oversized", oversized, true),
        ] {
            let name = format!(
                r"\\.\pipe\tunbridge-service-malformed-{case}-{}",
                std::process::id()
            );
            let listener = SecurePipeListener::bind_test(&name, true).unwrap();
            let server = std::thread::spawn(move || listener.accept());
            let mut client = connect_client(&name).unwrap();
            client.write_all(&frame).unwrap();

            let error = match server.join().unwrap() {
                Ok(_) => panic!("malformed {case} Hello unexpectedly authenticated"),
                Err(error) => error,
            };
            if oversized_expected {
                assert!(matches!(
                    error,
                    PipeError::Protocol(ProtocolError::FrameTooLarge(_))
                ));
            } else {
                assert!(matches!(
                    error,
                    PipeError::Protocol(ProtocolError::InvalidFrame(_))
                ));
            }
        }
    }

    #[test]
    #[ignore = "requires a medium interactive Windows token"]
    fn real_pipe_rejects_low_integrity_before_hello() {
        let name = format!(
            r"\\.\pipe\tunbridge-service-low-test-{}",
            std::process::id()
        );
        let listener = SecurePipeListener::bind_test(&name, true).unwrap();
        std::env::set_var("TUNBRIDGE_LOW_PIPE_PROBE", &name);
        let exit_code = spawn_low_integrity_probe();
        std::env::remove_var("TUNBRIDGE_LOW_PIPE_PROBE");
        assert_eq!(exit_code, 0);
        drop(listener);
    }

    #[test]
    #[ignore = "child entrypoint for the low-integrity pipe rejection test"]
    fn low_integrity_pipe_probe_child() {
        let name = std::env::var("TUNBRIDGE_LOW_PIPE_PROBE").unwrap();
        let error = connect_client(&name).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(ERROR_ACCESS_DENIED as i32));
    }

    #[test]
    #[ignore = "requires a medium interactive Windows token"]
    fn real_pipe_rejects_noninteractive_after_hello() {
        const AUTHENTICATED_USER_TEST_SDDL: &str =
            "D:P(A;;GA;;;SY)(A;;0x00100083;;;AU)S:(ML;;NW;;;ME)";

        let name = format!(
            r"\\.\pipe\tunbridge-service-noninteractive-test-{}",
            std::process::id()
        );
        let listener =
            SecurePipeListener::bind_with_sddl(&name, true, AUTHENTICATED_USER_TEST_SDDL).unwrap();
        let server = std::thread::spawn(move || listener.accept());

        std::env::set_var("TUNBRIDGE_NONINTERACTIVE_PIPE_PROBE", &name);
        let exit_code = spawn_noninteractive_probe();
        std::env::remove_var("TUNBRIDGE_NONINTERACTIVE_PIPE_PROBE");
        assert_eq!(exit_code, 0);

        let error = match server.join().unwrap() {
            Ok(_) => panic!("non-interactive client unexpectedly authenticated"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            PipeError::Identity(IdentityError::AccessDenied(_))
        ));
    }

    #[test]
    #[ignore = "child entrypoint for the non-interactive pipe rejection test"]
    fn noninteractive_pipe_probe_child() {
        let name = std::env::var("TUNBRIDGE_NONINTERACTIVE_PIPE_PROBE").unwrap();
        let mut client = connect_client(&name).unwrap();
        client
            .write_all(&frame::encode(&Hello::new("0.1.0")).unwrap())
            .unwrap();
    }

    #[test]
    #[ignore = "requires a medium interactive Windows token"]
    fn real_pipe_rejects_unauthenticated_after_hello() {
        const EVERYONE_TEST_SDDL: &str = "D:P(A;;GA;;;SY)(A;;0x00100083;;;WD)S:(ML;;NW;;;ME)";

        let name = format!(
            r"\\.\pipe\tunbridge-service-unauthenticated-test-{}",
            std::process::id()
        );
        let listener = SecurePipeListener::bind_with_sddl(&name, true, EVERYONE_TEST_SDDL).unwrap();
        let server = std::thread::spawn(move || listener.accept());

        std::env::set_var("TUNBRIDGE_UNAUTHENTICATED_PIPE_PROBE", &name);
        let exit_code = spawn_group_disabled_probe(
            WinAuthenticatedUserSid,
            "windows::pipe::tests::unauthenticated_pipe_probe_child",
        );
        std::env::remove_var("TUNBRIDGE_UNAUTHENTICATED_PIPE_PROBE");
        assert_eq!(exit_code, 0);

        let error = match server.join().unwrap() {
            Ok(_) => panic!("unauthenticated client unexpectedly authenticated"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            PipeError::Identity(IdentityError::AccessDenied(_))
        ));
    }

    #[test]
    #[ignore = "child entrypoint for the unauthenticated pipe rejection test"]
    fn unauthenticated_pipe_probe_child() {
        let name = std::env::var("TUNBRIDGE_UNAUTHENTICATED_PIPE_PROBE").unwrap();
        let mut client = connect_client(&name).unwrap();
        client
            .write_all(&frame::encode(&Hello::new("0.1.0")).unwrap())
            .unwrap();
    }

    fn framed_json(json: &str) -> Vec<u8> {
        let mut frame = (json.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(json.as_bytes());
        frame
    }

    fn spawn_low_integrity_probe() -> u32 {
        let mut current = ptr::null_mut();
        // SAFETY: current points to writable handle storage and the process
        // pseudo-handle is valid for OpenProcessToken.
        assert_ne!(
            unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
                    &mut current,
                )
            },
            0
        );
        let current = TestHandle(current);

        let mut restricted = ptr::null_mut();
        // SAFETY: all optional SID/privilege lists are empty; output is valid.
        assert_ne!(
            unsafe {
                CreateRestrictedToken(
                    current.0,
                    DISABLE_MAX_PRIVILEGE,
                    0,
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    ptr::null(),
                    &mut restricted,
                )
            },
            0
        );
        let restricted = TestHandle(restricted);

        let low_sid_text: Vec<u16> = "S-1-16-4096".encode_utf16().chain(Some(0)).collect();
        let mut low_sid = ptr::null_mut();
        // SAFETY: input is NUL-terminated and Windows allocates low_sid.
        assert_ne!(
            unsafe { ConvertStringSidToSidW(low_sid_text.as_ptr(), &mut low_sid) },
            0
        );
        let low_sid = LocalSid(low_sid);
        let label = TOKEN_MANDATORY_LABEL {
            Label: SID_AND_ATTRIBUTES {
                Sid: low_sid.0,
                Attributes: SE_GROUP_INTEGRITY as u32,
            },
        };
        // SAFETY: label and SID remain valid for the call and the token has
        // TOKEN_ADJUST_DEFAULT. Lowering integrity requires no elevation.
        assert_ne!(
            unsafe {
                SetTokenInformation(
                    restricted.0,
                    TokenIntegrityLevel,
                    (&label as *const TOKEN_MANDATORY_LABEL).cast(),
                    (size_of::<TOKEN_MANDATORY_LABEL>() + GetLengthSid(low_sid.0) as usize) as u32,
                )
            },
            0
        );

        spawn_probe_process(
            restricted.0,
            "windows::pipe::tests::low_integrity_pipe_probe_child",
        )
    }

    fn spawn_noninteractive_probe() -> u32 {
        spawn_group_disabled_probe(
            WinInteractiveSid,
            "windows::pipe::tests::noninteractive_pipe_probe_child",
        )
    }

    fn spawn_group_disabled_probe(sid_type: WELL_KNOWN_SID_TYPE, child_test_name: &str) -> u32 {
        let mut current = ptr::null_mut();
        // SAFETY: current points to writable handle storage and the process
        // pseudo-handle is valid for OpenProcessToken.
        assert_ne!(
            unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
                    &mut current,
                )
            },
            0
        );
        let current = TestHandle(current);

        let mut disabled_sid = [0_usize; 9];
        let mut disabled_sid_bytes = (disabled_sid.len() * size_of::<usize>()) as u32;
        // SAFETY: the aligned buffer is at least SECURITY_MAX_SID_SIZE bytes
        // and its reported size exactly matches the allocation.
        assert_ne!(
            unsafe {
                CreateWellKnownSid(
                    sid_type,
                    ptr::null_mut(),
                    disabled_sid.as_mut_ptr().cast(),
                    &mut disabled_sid_bytes,
                )
            },
            0
        );
        let disabled = SID_AND_ATTRIBUTES {
            Sid: disabled_sid.as_mut_ptr().cast(),
            Attributes: 0,
        };
        let mut restricted = ptr::null_mut();
        // SAFETY: the selected well-known SID buffer remains valid for the
        // call. The API converts SIDs in this list to deny-only groups in the
        // new token.
        assert_ne!(
            unsafe {
                CreateRestrictedToken(
                    current.0,
                    DISABLE_MAX_PRIVILEGE,
                    1,
                    &disabled,
                    0,
                    ptr::null(),
                    0,
                    ptr::null(),
                    &mut restricted,
                )
            },
            0
        );
        let restricted = TestHandle(restricted);

        spawn_probe_process(restricted.0, child_test_name)
    }

    fn spawn_probe_process(token: HANDLE, child_test_name: &str) -> u32 {
        let executable = std::env::current_exe().unwrap();
        let application: Vec<u16> = executable
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut command: Vec<u16> = format!(
            "\"{}\" --exact {child_test_name} --ignored",
            executable.display(),
        )
        .encode_utf16()
        .chain(Some(0))
        .collect();
        let startup = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            ..STARTUPINFOW::default()
        };
        let mut process = PROCESS_INFORMATION::default();
        // SAFETY: token is a restricted primary token derived from the caller;
        // strings and structures remain writable/valid for process creation.
        assert_ne!(
            unsafe {
                CreateProcessAsUserW(
                    token,
                    application.as_ptr(),
                    command.as_mut_ptr(),
                    ptr::null(),
                    ptr::null(),
                    0,
                    0,
                    ptr::null(),
                    ptr::null(),
                    &startup,
                    &mut process,
                )
            },
            0
        );
        let child_process = TestHandle(process.hProcess);
        let child_thread = TestHandle(process.hThread);
        assert_eq!(
            unsafe { WaitForSingleObject(child_process.0, 10_000) },
            WAIT_OBJECT_0
        );
        let mut exit_code = u32::MAX;
        assert_ne!(
            unsafe { GetExitCodeProcess(child_process.0, &mut exit_code) },
            0
        );
        drop(child_thread);
        exit_code
    }

    struct TestHandle(HANDLE);

    impl Drop for TestHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    struct LocalSid(PSID);

    impl Drop for LocalSid {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { LocalFree(self.0) };
            }
        }
    }
}
