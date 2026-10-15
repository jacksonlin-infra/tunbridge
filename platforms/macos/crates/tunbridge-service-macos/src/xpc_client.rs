use std::time::Duration;
use tunbridge_desktop_contract::adapter::{AdapterError, AdapterErrorCode, ServiceTransport};
use tunbridge_service::protocol::MAX_FRAME_BYTES;

#[cfg(target_os = "macos")]
use crate::{
    native::{
        process_credentials, received_frame, verify_root_connection, XpcCodeRequirement,
        XpcFrameEnvelope,
    },
    MACH_SERVICE_NAME,
};
#[cfg(target_os = "macos")]
use block2::RcBlock;
#[cfg(target_os = "macos")]
use std::{
    ffi::{c_char, c_int, c_void, CString},
    ptr::NonNull,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, RecvTimeoutError},
        Arc,
    },
};
#[cfg(all(target_os = "macos", feature = "macos-development-bootstrap"))]
use std::{fs::OpenOptions, io::Write};

#[cfg(all(target_os = "macos", feature = "macos-development-bootstrap"))]
fn client_debug_log(message: &str) {
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/tunbridge-client-m6f.log")
    {
        let _ = writeln!(file, "{message}");
    }
}

const FRAME_PREFIX_BYTES: usize = size_of::<u32>();
pub const MAX_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(40);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XpcClientError {
    Unavailable,
    Timeout,
    IdentityRejected,
    InvalidReply,
}

pub trait XpcRequestBackend: Send {
    fn round_trip(
        &mut self,
        request_frame: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, XpcClientError>;

    fn cancel(&mut self);
}

#[cfg(target_os = "macos")]
pub struct NativeXpcClientBackend {
    connection: NonNull<c_void>,
    event_handler: RcBlock<dyn Fn(*mut c_void)>,
    failed: Arc<AtomicBool>,
    cancelled: bool,
}

#[cfg(target_os = "macos")]
impl NativeXpcClientBackend {
    pub fn connect(helper_requirement: &XpcCodeRequirement) -> Result<Self, XpcClientError> {
        let service_name =
            CString::new(MACH_SERVICE_NAME).map_err(|_| XpcClientError::Unavailable)?;
        let connection = unsafe {
            xpc_connection_create_mach_service(
                service_name.as_ptr(),
                std::ptr::null_mut(),
                XPC_CONNECTION_MACH_SERVICE_PRIVILEGED,
            )
        };
        let connection = NonNull::new(connection).ok_or(XpcClientError::Unavailable)?;
        if unsafe {
            xpc_connection_set_peer_code_signing_requirement(
                connection.as_ptr(),
                helper_requirement.as_c_str().as_ptr(),
            )
        } != 0
        {
            dispose_inactive_connection(connection);
            return Err(XpcClientError::IdentityRejected);
        }

        let failed = Arc::new(AtomicBool::new(false));
        let event_failed = Arc::clone(&failed);
        let event_handler: RcBlock<dyn Fn(*mut c_void)> =
            RcBlock::new(move |_event: *mut c_void| {
                event_failed.store(true, Ordering::Release);
            });
        let handler = (&*event_handler as *const block2::Block<dyn Fn(*mut c_void)>)
            .cast_mut()
            .cast();
        unsafe {
            xpc_connection_set_event_handler(connection.as_ptr(), handler);
            xpc_connection_activate(connection.as_ptr());
        }
        Ok(Self {
            connection,
            event_handler,
            failed,
            cancelled: false,
        })
    }
}

#[cfg(target_os = "macos")]
impl XpcRequestBackend for NativeXpcClientBackend {
    fn round_trip(
        &mut self,
        request_frame: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, XpcClientError> {
        if self.cancelled || self.failed.load(Ordering::Acquire) {
            return Err(XpcClientError::Unavailable);
        }
        let envelope = XpcFrameEnvelope::from_frame(request_frame)
            .map_err(|_| XpcClientError::InvalidReply)?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let reply_handler: RcBlock<dyn Fn(*mut c_void)> =
            RcBlock::new(move |reply: *mut c_void| {
                let result = classify_reply(reply);
                let _ = sender.send(result);
            });
        let handler = (&*reply_handler as *const block2::Block<dyn Fn(*mut c_void)>)
            .cast_mut()
            .cast();
        unsafe {
            #[cfg(feature = "macos-development-bootstrap")]
            client_debug_log("client-send");
            xpc_connection_send_message_with_reply(
                self.connection.as_ptr(),
                envelope.as_ptr(),
                std::ptr::null_mut(),
                handler,
            );
        }
        let reply = match receiver.recv_timeout(timeout) {
            Ok(reply) => match reply {
                Ok(reply) => {
                    #[cfg(feature = "macos-development-bootstrap")]
                    client_debug_log("client-reply-ok");
                    reply
                }
                Err(error) => {
                    #[cfg(feature = "macos-development-bootstrap")]
                    client_debug_log(&format!("client-reply-error={error:?}"));
                    return Err(error);
                }
            },
            Err(RecvTimeoutError::Timeout) => {
                #[cfg(feature = "macos-development-bootstrap")]
                client_debug_log("client-recv-timeout");
                self.cancel();
                return Err(XpcClientError::Timeout);
            }
            Err(RecvTimeoutError::Disconnected) => {
                #[cfg(feature = "macos-development-bootstrap")]
                client_debug_log("client-recv-disconnected");
                self.cancel();
                return Err(XpcClientError::Unavailable);
            }
        };
        #[cfg(feature = "macos-development-bootstrap")]
        client_debug_log(&format!(
            "client-peer-facts pid={} euid={} asid={}",
            unsafe { xpc_connection_get_pid(self.connection.as_ptr()) },
            unsafe { xpc_connection_get_euid(self.connection.as_ptr()) },
            unsafe { xpc_connection_get_asid(self.connection.as_ptr()) },
        ));
        #[cfg(feature = "macos-development-bootstrap")]
        client_debug_log(&format!(
            "client-process-facts={:?}",
            process_credentials(unsafe { xpc_connection_get_pid(self.connection.as_ptr()) } as u32)
        ));
        if verify_root_connection(self.connection).is_err() {
            #[cfg(feature = "macos-development-bootstrap")]
            client_debug_log("client-root-identity-rejected");
            return Err(XpcClientError::IdentityRejected);
        }
        #[cfg(feature = "macos-development-bootstrap")]
        client_debug_log("client-root-identity-ok");
        Ok(reply)
    }

    fn cancel(&mut self) {
        if !self.cancelled {
            unsafe { xpc_connection_cancel(self.connection.as_ptr()) };
            self.cancelled = true;
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for NativeXpcClientBackend {
    fn drop(&mut self) {
        self.cancel();
        let _ = &self.event_handler;
        unsafe { xpc_release(self.connection.as_ptr()) };
    }
}

#[cfg(target_os = "macos")]
unsafe impl Send for NativeXpcClientBackend {}

#[cfg(target_os = "macos")]
fn classify_reply(reply: *mut c_void) -> Result<Vec<u8>, XpcClientError> {
    let reply = NonNull::new(reply).ok_or(XpcClientError::Unavailable)?;
    let object_type = unsafe { xpc_get_type(reply.as_ptr()) };
    if object_type == std::ptr::addr_of!(_xpc_type_dictionary).cast() {
        let count = unsafe { xpc_dictionary_get_count(reply.as_ptr()) };
        let result = unsafe { received_frame(reply) };
        #[cfg(feature = "macos-development-bootstrap")]
        client_debug_log(&format!(
            "client-reply-dictionary-count={count} result={} bytes={}",
            if result.is_ok() { "ok" } else { "invalid" },
            result.as_ref().map(Vec::len).unwrap_or_default()
        ));
        result.map_err(|_| XpcClientError::InvalidReply)
    } else if reply.as_ptr()
        == std::ptr::addr_of!(_xpc_error_peer_code_signing_requirement)
            .cast_mut()
            .cast()
    {
        #[cfg(feature = "macos-development-bootstrap")]
        client_debug_log("client-reply-identity-error");
        Err(XpcClientError::IdentityRejected)
    } else {
        #[cfg(feature = "macos-development-bootstrap")]
        client_debug_log("client-reply-unavailable-error");
        Err(XpcClientError::Unavailable)
    }
}

#[cfg(target_os = "macos")]
fn dispose_inactive_connection(connection: NonNull<c_void>) {
    let handler: RcBlock<dyn Fn(*mut c_void)> = RcBlock::new(|_event: *mut c_void| {});
    let pointer = (&*handler as *const block2::Block<dyn Fn(*mut c_void)>)
        .cast_mut()
        .cast();
    unsafe {
        xpc_connection_set_event_handler(connection.as_ptr(), pointer);
        xpc_connection_activate(connection.as_ptr());
        xpc_connection_cancel(connection.as_ptr());
        xpc_release(connection.as_ptr());
    }
}

#[cfg(target_os = "macos")]
const XPC_CONNECTION_MACH_SERVICE_PRIVILEGED: u64 = 1 << 1;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    static _xpc_type_dictionary: c_void;
    static _xpc_error_peer_code_signing_requirement: c_void;
    fn xpc_connection_create_mach_service(
        name: *const c_char,
        target_queue: *mut c_void,
        flags: u64,
    ) -> *mut c_void;
    fn xpc_connection_set_peer_code_signing_requirement(
        connection: *mut c_void,
        requirement: *const c_char,
    ) -> c_int;
    fn xpc_connection_set_event_handler(connection: *mut c_void, handler: *mut c_void);
    fn xpc_connection_activate(connection: *mut c_void);
    fn xpc_connection_cancel(connection: *mut c_void);
    fn xpc_connection_send_message_with_reply(
        connection: *mut c_void,
        message: *mut c_void,
        reply_queue: *mut c_void,
        handler: *mut c_void,
    );
    fn xpc_connection_get_pid(connection: *mut c_void) -> c_int;
    fn xpc_connection_get_euid(connection: *mut c_void) -> u32;
    fn xpc_connection_get_asid(connection: *mut c_void) -> u32;
    fn xpc_dictionary_get_count(object: *mut c_void) -> usize;
    fn xpc_get_type(object: *mut c_void) -> *const c_void;
    fn xpc_release(object: *mut c_void);
}

#[derive(Debug, Default)]
pub struct UnavailableXpcBackend;

impl XpcRequestBackend for UnavailableXpcBackend {
    fn round_trip(
        &mut self,
        _request_frame: &[u8],
        _timeout: Duration,
    ) -> Result<Vec<u8>, XpcClientError> {
        Err(XpcClientError::Unavailable)
    }

    fn cancel(&mut self) {}
}

#[derive(Debug)]
pub struct MacosXpcTransport<B = UnavailableXpcBackend> {
    backend: B,
    poisoned: bool,
}

impl Default for MacosXpcTransport<UnavailableXpcBackend> {
    fn default() -> Self {
        Self::with_backend(UnavailableXpcBackend)
    }
}

impl<B> MacosXpcTransport<B> {
    pub const fn with_backend(backend: B) -> Self {
        Self {
            backend,
            poisoned: false,
        }
    }

    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }
}

#[cfg(target_os = "macos")]
impl MacosXpcTransport<NativeXpcClientBackend> {
    pub fn connect(helper_requirement: &XpcCodeRequirement) -> Result<Self, AdapterError> {
        NativeXpcClientBackend::connect(helper_requirement)
            .map(Self::with_backend)
            .map_err(map_error)
    }
}

impl<B> ServiceTransport for MacosXpcTransport<B>
where
    B: XpcRequestBackend,
{
    fn transact(
        &mut self,
        request_frame: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, AdapterError> {
        if self.poisoned {
            return Err(unavailable());
        }
        if validate_frame(request_frame).is_err() {
            #[cfg(all(target_os = "macos", feature = "macos-development-bootstrap"))]
            client_debug_log(&format!(
                "transport-request-frame-invalid bytes={}",
                request_frame.len()
            ));
            return Err(invalid_data());
        }
        if timeout.is_zero() || timeout > MAX_TRANSACTION_TIMEOUT {
            return Err(invalid_data());
        }
        match self.backend.round_trip(request_frame, timeout) {
            Ok(reply) if validate_frame(&reply).is_ok() => Ok(reply),
            Ok(_) => {
                #[cfg(all(target_os = "macos", feature = "macos-development-bootstrap"))]
                client_debug_log("transport-reply-frame-invalid");
                self.poison();
                Err(invalid_data())
            }
            Err(error) => {
                self.poison();
                Err(map_error(error))
            }
        }
    }
}

impl<B> MacosXpcTransport<B>
where
    B: XpcRequestBackend,
{
    fn poison(&mut self) {
        self.poisoned = true;
        self.backend.cancel();
    }
}

fn validate_frame(frame: &[u8]) -> Result<(), ()> {
    let prefix: [u8; FRAME_PREFIX_BYTES] = frame
        .get(..FRAME_PREFIX_BYTES)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(())?;
    let payload_bytes = u32::from_le_bytes(prefix) as usize;
    if payload_bytes > MAX_FRAME_BYTES || frame.len() != FRAME_PREFIX_BYTES + payload_bytes {
        Err(())
    } else {
        Ok(())
    }
}

fn map_error(error: XpcClientError) -> AdapterError {
    match error {
        XpcClientError::Unavailable => unavailable(),
        XpcClientError::Timeout => AdapterError {
            code: AdapterErrorCode::Unavailable,
            safe_message: "The macOS helper did not reply in time.",
            retryable: true,
        },
        XpcClientError::IdentityRejected => AdapterError {
            code: AdapterErrorCode::IdentityRejected,
            safe_message: "The macOS helper identity was rejected.",
            retryable: false,
        },
        XpcClientError::InvalidReply => invalid_data(),
    }
}

fn unavailable() -> AdapterError {
    AdapterError {
        code: AdapterErrorCode::Unavailable,
        safe_message: "The macOS helper transport is unavailable.",
        retryable: true,
    }
}

fn invalid_data() -> AdapterError {
    AdapterError {
        code: AdapterErrorCode::InvalidData,
        safe_message: "The macOS helper returned invalid data.",
        retryable: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use tunbridge_service::{frame, protocol::Hello};

    #[derive(Debug)]
    struct MockBackend {
        replies: VecDeque<Result<Vec<u8>, XpcClientError>>,
        calls: usize,
        cancels: usize,
    }

    impl MockBackend {
        fn new(replies: impl IntoIterator<Item = Result<Vec<u8>, XpcClientError>>) -> Self {
            Self {
                replies: replies.into_iter().collect(),
                calls: 0,
                cancels: 0,
            }
        }
    }

    impl XpcRequestBackend for MockBackend {
        fn round_trip(
            &mut self,
            _request_frame: &[u8],
            _timeout: Duration,
        ) -> Result<Vec<u8>, XpcClientError> {
            self.calls += 1;
            self.replies
                .pop_front()
                .unwrap_or(Err(XpcClientError::Unavailable))
        }

        fn cancel(&mut self) {
            self.cancels += 1;
        }
    }

    fn frame_fixture() -> Vec<u8> {
        frame::encode(&Hello::new("0.2.3")).unwrap()
    }

    #[test]
    fn valid_bounded_frame_round_trips_without_poisoning() {
        let fixture = frame_fixture();
        let backend = MockBackend::new([Ok(fixture.clone())]);
        let mut transport = MacosXpcTransport::with_backend(backend);

        assert_eq!(
            transport
                .transact(&fixture, Duration::from_secs(2))
                .unwrap(),
            fixture
        );
        assert!(!transport.is_poisoned());
        assert_eq!(transport.backend.calls, 1);
        assert_eq!(transport.backend.cancels, 0);
    }

    #[test]
    fn lifecycle_timeout_reaches_backend() {
        let fixture = frame_fixture();
        let backend = MockBackend::new([Ok(fixture.clone())]);
        let mut transport = MacosXpcTransport::with_backend(backend);

        assert_eq!(
            transport
                .transact(&fixture, Duration::from_secs(40))
                .unwrap(),
            fixture
        );
        assert_eq!(transport.backend.calls, 1);
        assert_eq!(transport.backend.cancels, 0);
        assert!(!transport.is_poisoned());
    }

    #[test]
    fn invalid_request_and_timeout_bounds_fail_before_backend() {
        let backend = MockBackend::new([]);
        let mut transport = MacosXpcTransport::with_backend(backend);
        for (frame, timeout) in [
            (Vec::new(), Duration::from_secs(1)),
            (frame_fixture(), Duration::ZERO),
            (
                frame_fixture(),
                MAX_TRANSACTION_TIMEOUT + Duration::from_secs(1),
            ),
        ] {
            let error = transport.transact(&frame, timeout).unwrap_err();
            assert_eq!(error.code, AdapterErrorCode::InvalidData);
        }
        assert_eq!(transport.backend.calls, 0);
        assert_eq!(transport.backend.cancels, 0);
        assert!(!transport.is_poisoned());
    }

    #[test]
    fn invalid_reply_cancels_and_permanently_poisons_connection() {
        let fixture = frame_fixture();
        let backend = MockBackend::new([Ok(vec![1, 0, 0, 0])]);
        let mut transport = MacosXpcTransport::with_backend(backend);

        assert_eq!(
            transport
                .transact(&fixture, Duration::from_secs(1))
                .unwrap_err()
                .code,
            AdapterErrorCode::InvalidData
        );
        assert!(transport.is_poisoned());
        assert_eq!(transport.backend.cancels, 1);
        assert_eq!(
            transport
                .transact(&fixture, Duration::from_secs(1))
                .unwrap_err()
                .code,
            AdapterErrorCode::Unavailable
        );
        assert_eq!(transport.backend.calls, 1);
    }

    #[test]
    fn timeout_and_identity_errors_are_safe_and_fail_closed() {
        let fixture = frame_fixture();
        for (failure, code, retryable) in [
            (XpcClientError::Timeout, AdapterErrorCode::Unavailable, true),
            (
                XpcClientError::IdentityRejected,
                AdapterErrorCode::IdentityRejected,
                false,
            ),
        ] {
            let backend = MockBackend::new([Err(failure)]);
            let mut transport = MacosXpcTransport::with_backend(backend);
            let error = transport
                .transact(&fixture, Duration::from_secs(1))
                .unwrap_err();
            assert_eq!(error.code, code);
            assert_eq!(error.retryable, retryable);
            assert!(transport.is_poisoned());
            assert_eq!(transport.backend.cancels, 1);
        }
    }

    #[test]
    fn unavailable_default_never_contacts_or_installs_a_helper() {
        let mut transport = MacosXpcTransport::default();
        let error = transport
            .transact(&frame_fixture(), Duration::from_millis(1))
            .unwrap_err();
        assert_eq!(error.code, AdapterErrorCode::Unavailable);
        assert!(transport.is_poisoned());
    }
}
