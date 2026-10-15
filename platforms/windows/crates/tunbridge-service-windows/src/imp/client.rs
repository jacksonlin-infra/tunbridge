use std::{
    fmt::Write as _,
    io::{self, Write},
    os::windows::io::AsRawHandle,
    path::{Path, PathBuf},
    ptr,
};

use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_ACCESS_DENIED, HANDLE},
    Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG},
    System::{
        Pipes::GetNamedPipeServerProcessId,
        Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION},
    },
};

use crate::{
    frame,
    protocol::{
        ActiveStartProfile, Capability, Command, Hello, HelloOk, Request, RequestKind, Response,
        ResponseData, SessionGuard, PROTOCOL_VERSION,
    },
};

#[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
use super::pipe::LEASE_RESPONSE_TIMEOUT;
use super::{
    pipe::{
        connect_client, read_one_frame, HELLO_TIMEOUT, LIFECYCLE_RESPONSE_TIMEOUT, PIPE_NAME,
        REQUEST_FRAME_TIMEOUT, REQUEST_IDLE_TIMEOUT,
    },
    scm::program_files_directory,
};

pub struct ServiceClient {
    file: std::fs::File,
    nonce: String,
    next_seq: u64,
    capabilities: Vec<Capability>,
}

impl ServiceClient {
    pub fn connect() -> Result<Self, ClientError> {
        let mut file = connect_client(PIPE_NAME).map_err(ClientError::Windows)?;
        verify_server_image(&file)?;
        file.write_all(&frame::encode(&Hello::new(env!("CARGO_PKG_VERSION")))?)
            .map_err(ClientError::Windows)?;
        file.flush().map_err(ClientError::Windows)?;
        let hello: HelloOk =
            frame::decode(&read_one_frame(&mut file, HELLO_TIMEOUT, HELLO_TIMEOUT)?)?;
        if hello.protocol != PROTOCOL_VERSION {
            return Err(ClientError::ProtocolMismatch(hello.protocol));
        }
        if !hello.capabilities.contains(&Capability::Status) {
            return Err(ClientError::MissingStatusCapability);
        }
        SessionGuard::new(hello.session_nonce.clone())?;
        Ok(Self {
            file,
            nonce: hello.session_nonce,
            next_seq: 1,
            capabilities: hello.capabilities,
        })
    }

    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    pub fn status(&mut self) -> Result<ResponseData, ClientError> {
        self.send(Command::Status, REQUEST_IDLE_TIMEOUT)
    }

    pub fn start(&mut self, profile: ActiveStartProfile) -> Result<ResponseData, ClientError> {
        if matches!(
            &profile.upstream,
            crate::protocol::StartUpstreamV3::RemoteServer { .. }
        ) && !self.capabilities.contains(&Capability::RemoteUpstream)
        {
            return Err(ClientError::MissingCapability(Capability::RemoteUpstream));
        }
        self.send(Command::Start { profile }, LIFECYCLE_RESPONSE_TIMEOUT)
    }

    pub fn stop(&mut self) -> Result<ResponseData, ClientError> {
        self.send(Command::Stop, LIFECYCLE_RESPONSE_TIMEOUT)
    }

    pub fn recover(&mut self) -> Result<ResponseData, ClientError> {
        self.send(Command::Recover, LIFECYCLE_RESPONSE_TIMEOUT)
    }

    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    pub fn acquire_lease(&mut self) -> Result<ResponseData, ClientError> {
        self.send(Command::AcquireLease {}, LEASE_RESPONSE_TIMEOUT)
    }

    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    pub fn renew_lease(
        &mut self,
        lease_id: String,
        lease_nonce: String,
        lease_seq: u64,
    ) -> Result<ResponseData, ClientError> {
        self.send(
            Command::RenewLease {
                lease_id,
                lease_nonce,
                lease_seq,
            },
            LEASE_RESPONSE_TIMEOUT,
        )
    }

    #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
    pub fn release_lease(
        &mut self,
        lease_id: String,
        lease_nonce: String,
        lease_seq: u64,
    ) -> Result<ResponseData, ClientError> {
        self.send(
            Command::ReleaseLease {
                lease_id,
                lease_nonce,
                lease_seq,
            },
            LEASE_RESPONSE_TIMEOUT,
        )
    }

    #[cfg(feature = "production-local-observability")]
    pub fn observe_traffic(&mut self) -> Result<ResponseData, ClientError> {
        self.send(Command::ObserveTraffic {}, REQUEST_IDLE_TIMEOUT)
    }

    #[cfg(feature = "production-local-observability")]
    pub fn list_connections(
        &mut self,
        state: crate::protocol::ConnectionState,
        offset: u32,
        limit: u16,
    ) -> Result<ResponseData, ClientError> {
        self.send(
            Command::ListConnections {
                state,
                offset,
                limit,
            },
            REQUEST_IDLE_TIMEOUT,
        )
    }

    #[cfg(feature = "production-local-observability")]
    pub fn close_connection(&mut self, connection_id: String) -> Result<ResponseData, ClientError> {
        self.send(
            Command::CloseConnection { connection_id },
            REQUEST_IDLE_TIMEOUT,
        )
    }

    #[cfg(feature = "production-local-observability")]
    pub fn close_all_connections(&mut self) -> Result<ResponseData, ClientError> {
        self.send(Command::CloseAllConnections {}, REQUEST_IDLE_TIMEOUT)
    }

    #[cfg(feature = "production-mihomo-logs-v4")]
    pub fn list_mihomo_logs(
        &mut self,
        after_sequence: u64,
        limit: u16,
    ) -> Result<ResponseData, ClientError> {
        self.send(
            Command::ListMihomoLogs {
                after_sequence,
                limit,
            },
            REQUEST_IDLE_TIMEOUT,
        )
    }

    fn send(
        &mut self,
        command: Command,
        response_timeout: std::time::Duration,
    ) -> Result<ResponseData, ClientError> {
        command.validate()?;
        let capability = required_capability(&command);
        if !self.capabilities.contains(&capability) {
            return Err(ClientError::MissingCapability(capability));
        }
        let request = Request {
            kind: RequestKind::Request,
            protocol: PROTOCOL_VERSION,
            session_nonce: self.nonce.clone(),
            seq: self.next_seq,
            request_id: random_hex(16)?,
            command,
        };
        self.file
            .write_all(&frame::encode(&request)?)
            .map_err(ClientError::Windows)?;
        self.file.flush().map_err(ClientError::Windows)?;
        let response: Response = frame::decode(&read_one_frame(
            &mut self.file,
            response_timeout,
            REQUEST_FRAME_TIMEOUT,
        )?)?;
        if response.protocol != PROTOCOL_VERSION
            || response.seq != request.seq
            || response.request_id != request.request_id
        {
            return Err(ClientError::ResponseMismatch);
        }
        self.next_seq += 1;
        if response.result.ok {
            response.result.data.ok_or(ClientError::ResponseMismatch)
        } else {
            let error = response.result.error.ok_or(ClientError::ResponseMismatch)?;
            Err(ClientError::Service {
                code: error.code,
                message: error.safe_message,
                retryable: error.retryable,
            })
        }
    }
}

fn required_capability(command: &Command) -> Capability {
    match command {
        Command::Status => Capability::Status,
        Command::Start { .. } => Capability::Start,
        Command::Stop => Capability::Stop,
        Command::Recover => Capability::Recover,
        #[cfg(feature = "macos-development-bootstrap")]
        Command::ProvisionGeneration { .. } => Capability::Status,
        #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
        Command::AcquireLease {} | Command::RenewLease { .. } | Command::ReleaseLease { .. } => {
            Capability::Lease
        }
        #[cfg(feature = "production-local-observability")]
        Command::ObserveTraffic {} | Command::ListConnections { .. } => {
            Capability::ObserveLocalTraffic
        }
        #[cfg(feature = "production-local-observability")]
        Command::CloseConnection { .. } | Command::CloseAllConnections {} => {
            Capability::CloseOwnedConnections
        }
        #[cfg(feature = "production-mihomo-logs-v4")]
        Command::ListMihomoLogs { .. } => Capability::ObserveMihomoLogs,
    }
}

fn verify_server_image(file: &std::fs::File) -> Result<(), ClientError> {
    let mut process_id = 0_u32;
    // SAFETY: file is a connected client-side pipe and process_id is writable.
    if unsafe { GetNamedPipeServerProcessId(file.as_raw_handle() as HANDLE, &mut process_id) } == 0
    {
        return Err(ClientError::Windows(io::Error::last_os_error()));
    }
    // A standard user normally cannot open a LocalSystem service process even
    // for limited query access. Prove first that the kernel-reported pipe PID
    // is the fixed SCM service instance and that SCM's protected configuration
    // contains only the fixed Program Files image plus the `run` mode.
    super::scm::verify_service_process(process_id)
        .map_err(|error| ClientError::ServerIdentity(error.to_string()))?;
    // SAFETY: the requested right is read-only and process_id comes from the
    // kernel pipe object. When the process DACL permits this defense-in-depth
    // check, its live image must independently match the fixed install path.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
            return Ok(());
        }
        return Err(ClientError::Windows(error));
    }
    let process = OwnedHandle(process);
    let actual = process_image_path(process.0)?;
    let expected = program_files_directory()
        .map_err(|error| ClientError::ServerIdentity(error.to_string()))?
        .join("TunBridge")
        .join("tunbridge-service.exe");
    if !paths_equal(&actual, &expected) {
        return Err(ClientError::ServerIdentity(
            "named pipe server is not the installed TunBridge service".into(),
        ));
    }
    Ok(())
}

fn process_image_path(process: HANDLE) -> Result<PathBuf, ClientError> {
    let mut buffer = vec![0_u16; 32_768];
    let mut length = buffer.len() as u32;
    // SAFETY: buffer is writable for length UTF-16 code units and process was
    // opened with PROCESS_QUERY_LIMITED_INFORMATION.
    if unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length) } == 0 {
        return Err(ClientError::Windows(io::Error::last_os_error()));
    }
    String::from_utf16(&buffer[..length as usize])
        .map(PathBuf::from)
        .map_err(|_| ClientError::ServerIdentity("server image path is invalid UTF-16".into()))
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    normalize_path(left).eq_ignore_ascii_case(&normalize_path(right))
}

fn normalize_path(path: &Path) -> String {
    let path = path.to_string_lossy();
    path.strip_prefix(r"\\?\")
        .unwrap_or(&path)
        .replace('/', "\\")
}

fn random_hex(byte_count: usize) -> Result<String, ClientError> {
    let mut bytes = vec![0_u8; byte_count];
    // SAFETY: the null provider is valid with the system-preferred flag and the
    // vector exposes byte_count writable bytes.
    let status = unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(ClientError::Windows(io::Error::from_raw_os_error(status)));
    }
    let mut result = String::with_capacity(byte_count * 2);
    for byte in bytes {
        write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(result)
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: OpenProcess transferred ownership of this handle.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("Windows service client operation failed: {0}")]
    Windows(#[source] io::Error),
    #[error(transparent)]
    Protocol(#[from] crate::protocol::ProtocolError),
    #[error(transparent)]
    Pipe(#[from] super::pipe::PipeError),
    #[error("service protocol version {0} is not supported")]
    ProtocolMismatch(u16),
    #[error("service did not advertise the status capability")]
    MissingStatusCapability,
    #[error("service did not advertise the {0:?} capability")]
    MissingCapability(Capability),
    #[error("service response does not match the request")]
    ResponseMismatch,
    #[error("service identity check failed: {0}")]
    ServerIdentity(String),
    #[error("service returned {code:?}: {message}")]
    Service {
        code: crate::protocol::ErrorCode,
        message: String,
        retryable: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::super::{SecurePipeListener, PIPE_NAME};
    use super::*;

    #[test]
    fn windows_path_comparison_is_case_and_prefix_insensitive() {
        assert!(paths_equal(
            Path::new(r"\\?\C:\Program Files\TunBridge\tunbridge-service.exe"),
            Path::new(r"c:\program files\tunbridge\TUNBRIDGE-SERVICE.EXE")
        ));
        assert!(!paths_equal(
            Path::new(r"C:\Users\me\tunbridge-service.exe"),
            Path::new(r"C:\Program Files\TunBridge\tunbridge-service.exe")
        ));
    }

    #[test]
    #[ignore = "requires the fixed product pipe and no installed service"]
    fn real_client_rejects_non_scm_fixed_pipe_server_before_hello() {
        let listener = SecurePipeListener::bind_test(PIPE_NAME, true).unwrap();
        let server = std::thread::spawn(move || listener.accept());

        let error = match ServiceClient::connect() {
            Ok(_) => panic!("non-SCM fixed-pipe server was accepted"),
            Err(error) => error,
        };
        assert!(matches!(error, ClientError::ServerIdentity(_)));
        assert!(server.join().unwrap().is_err());
    }

    #[test]
    fn request_ids_are_32_hex_characters() {
        let request_id = random_hex(16).unwrap();
        assert_eq!(request_id.len(), 32);
        assert!(request_id.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn every_command_requires_its_exact_advertised_capability() {
        assert_eq!(required_capability(&Command::Status), Capability::Status);
        assert_eq!(required_capability(&Command::Stop), Capability::Stop);
        assert_eq!(required_capability(&Command::Recover), Capability::Recover);
        assert_eq!(
            required_capability(&Command::Start {
                profile: crate::protocol::StartProfileV3 {
                    upstream: crate::protocol::StartUpstreamV3::LocalListener {
                        port: 1080,
                        protocol: tunbridge_core::upstream::StandardProtocol::Socks5,
                        credentials: None,
                        expected_process_id: 1,
                    },
                    traffic_bypass_domains: Vec::new(),
                    traffic_bypass_cidrs: Vec::new(),
                    traffic_bypass_process_names: Vec::new(),
                }
            }),
            Capability::Start
        );
        #[cfg(any(feature = "production-app-lease", feature = "acceptance-m2b5"))]
        assert_eq!(
            required_capability(&Command::AcquireLease {}),
            Capability::Lease
        );
        #[cfg(feature = "production-local-observability")]
        assert_eq!(
            required_capability(&Command::ObserveTraffic {}),
            Capability::ObserveLocalTraffic
        );
        #[cfg(feature = "production-local-observability")]
        assert_eq!(
            required_capability(&Command::CloseAllConnections {}),
            Capability::CloseOwnedConnections
        );
        #[cfg(feature = "production-mihomo-logs-v4")]
        assert_eq!(
            required_capability(&Command::ListMihomoLogs {
                after_sequence: 0,
                limit: 25,
            }),
            Capability::ObserveMihomoLogs
        );
    }
}
