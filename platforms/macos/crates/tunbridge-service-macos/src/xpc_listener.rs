//! Pure listener admission and per-connection event state.
//!
//! The eventual libxpc listener must serialize all transitions through this
//! gate before retaining or dispatching an incoming event.

#[cfg(feature = "macos-xpc-listener")]
use crate::native::{cancel_borrowed_connection, SystemSecretSource, XpcCodeRequirement};
#[cfg(feature = "macos-xpc-listener")]
use crate::MACH_SERVICE_NAME;
use crate::{
    dispatcher::{HelperLifecycle, MacosServiceContext, SecretSource},
    lifecycle_host::HostError,
    native::{RequirementBoundConnection, XpcFrameEnvelope, XpcIncomingEvent},
    xpc_session::{NativeXpcSession, XpcAppPeer},
};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    fs::OpenOptions,
    io::Write,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};
#[cfg(feature = "macos-xpc-listener")]
use std::{
    ffi::{c_char, c_void, CString},
    ptr::NonNull,
};
use tunbridge_service::protocol::MAX_REQUESTS_PER_CONNECTION;
use zeroize::Zeroize;

pub const MAX_ACTIVE_XPC_CONNECTIONS: usize = 8;

#[cfg(feature = "macos-development-bootstrap")]
const DEBUG_LOG_MAX_BYTES: u64 = 1024 * 1024;

/// Development diagnostics from the root helper. The path is in a world
/// writable directory, so never follow a planted link, never write through a
/// file another user created or hard-linked, and keep the file bounded.
#[cfg(feature = "macos-development-bootstrap")]
pub(crate) fn debug_log(message: &str) {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/tmp/tunbridge-helper-m6f.log")
    else {
        return;
    };
    let Ok(metadata) = file.metadata() else {
        return;
    };
    if !metadata.file_type().is_file() || metadata.uid() != 0 || metadata.nlink() != 1 {
        return;
    }
    // Keep the newest diagnostics: restart the verified file at the bound.
    if metadata.len() >= DEBUG_LOG_MAX_BYTES && file.set_len(0).is_err() {
        return;
    }
    let _ = writeln!(file, "{message}");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XpcConnectionPhase {
    AwaitingHello,
    Ready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XpcListenerError {
    InvalidConnection,
    ConnectionLimit,
    DuplicateConnection,
    WrongPhase,
    RequestInFlight,
    RequestLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConnectionState {
    phase: XpcConnectionPhase,
    request_in_flight: bool,
    completed_requests: u64,
}

#[derive(Debug, Default)]
pub struct XpcListenerState {
    connections: BTreeMap<u64, ConnectionState>,
}

impl XpcListenerState {
    pub fn accept(&mut self, connection_id: u64) -> Result<(), XpcListenerError> {
        if connection_id == 0 {
            return Err(XpcListenerError::InvalidConnection);
        }
        if self.connections.contains_key(&connection_id) {
            return Err(XpcListenerError::DuplicateConnection);
        }
        if self.connections.len() >= MAX_ACTIVE_XPC_CONNECTIONS {
            return Err(XpcListenerError::ConnectionLimit);
        }
        self.connections.insert(
            connection_id,
            ConnectionState {
                phase: XpcConnectionPhase::AwaitingHello,
                request_in_flight: false,
                completed_requests: 0,
            },
        );
        Ok(())
    }

    pub fn begin_hello(&mut self, connection_id: u64) -> Result<(), XpcListenerError> {
        let state = self.connection_mut(connection_id)?;
        if state.phase != XpcConnectionPhase::AwaitingHello {
            return Err(XpcListenerError::WrongPhase);
        }
        begin_one(state)
    }

    pub fn finish_hello(
        &mut self,
        connection_id: u64,
        accepted: bool,
    ) -> Result<(), XpcListenerError> {
        let state = self.connection_mut(connection_id)?;
        if state.phase != XpcConnectionPhase::AwaitingHello || !state.request_in_flight {
            return Err(XpcListenerError::WrongPhase);
        }
        if accepted {
            state.request_in_flight = false;
            state.phase = XpcConnectionPhase::Ready;
        } else {
            self.connections.remove(&connection_id);
        }
        Ok(())
    }

    pub fn begin_request(&mut self, connection_id: u64) -> Result<(), XpcListenerError> {
        let state = self.connection_mut(connection_id)?;
        if state.phase != XpcConnectionPhase::Ready {
            return Err(XpcListenerError::WrongPhase);
        }
        if state.completed_requests >= MAX_REQUESTS_PER_CONNECTION {
            return Err(XpcListenerError::RequestLimit);
        }
        begin_one(state)
    }

    pub fn finish_request(
        &mut self,
        connection_id: u64,
        keep_open: bool,
    ) -> Result<(), XpcListenerError> {
        let state = self.connection_mut(connection_id)?;
        if state.phase != XpcConnectionPhase::Ready || !state.request_in_flight {
            return Err(XpcListenerError::WrongPhase);
        }
        if keep_open {
            state.request_in_flight = false;
            state.completed_requests = state
                .completed_requests
                .checked_add(1)
                .ok_or(XpcListenerError::RequestLimit)?;
        } else {
            self.connections.remove(&connection_id);
        }
        Ok(())
    }

    pub fn cancel(&mut self, connection_id: u64) -> bool {
        self.connections.remove(&connection_id).is_some()
    }

    pub fn active_connections(&self) -> usize {
        self.connections.len()
    }

    pub fn phase(&self, connection_id: u64) -> Option<XpcConnectionPhase> {
        self.connections
            .get(&connection_id)
            .map(|state| state.phase)
    }

    fn connection_mut(
        &mut self,
        connection_id: u64,
    ) -> Result<&mut ConnectionState, XpcListenerError> {
        self.connections
            .get_mut(&connection_id)
            .ok_or(XpcListenerError::InvalidConnection)
    }
}

fn begin_one(state: &mut ConnectionState) -> Result<(), XpcListenerError> {
    if state.request_in_flight {
        Err(XpcListenerError::RequestInFlight)
    } else {
        state.request_in_flight = true;
        Ok(())
    }
}

pub trait XpcReplyIo {
    fn send(&mut self, response: &XpcFrameEnvelope) -> Result<(), HostError>;
    fn cancel(&mut self);
}

pub fn dispatch_hello<I, F>(
    state: &mut XpcListenerState,
    connection_id: u64,
    io: &mut I,
    work: F,
) -> Result<(), HostError>
where
    I: XpcReplyIo,
    F: FnOnce() -> Result<XpcFrameEnvelope, HostError>,
{
    dispatch_hello_with_peer(state, connection_id, io, |_| work())
}

fn dispatch_hello_with_peer<I, F>(
    state: &mut XpcListenerState,
    connection_id: u64,
    io: &mut I,
    work: F,
) -> Result<(), HostError>
where
    I: XpcReplyIo,
    F: FnOnce(&I) -> Result<XpcFrameEnvelope, HostError>,
{
    if state.begin_hello(connection_id).is_err() {
        close_failed(state, connection_id, io);
        return Err(HostError::InvalidInput);
    }
    let result = work(io).and_then(|response| io.send(&response));
    if result.is_ok() && state.finish_hello(connection_id, true).is_ok() {
        Ok(())
    } else {
        close_failed(state, connection_id, io);
        Err(result.err().unwrap_or(HostError::BackendUnavailable))
    }
}

pub fn dispatch_request<I, F>(
    state: &mut XpcListenerState,
    connection_id: u64,
    io: &mut I,
    work: F,
) -> Result<(), HostError>
where
    I: XpcReplyIo,
    F: FnOnce() -> Result<XpcFrameEnvelope, HostError>,
{
    if state.begin_request(connection_id).is_err() {
        close_failed(state, connection_id, io);
        return Err(HostError::InvalidInput);
    }
    let result = work().and_then(|response| io.send(&response));
    if result.is_ok() && state.finish_request(connection_id, true).is_ok() {
        Ok(())
    } else {
        close_failed(state, connection_id, io);
        Err(result.err().unwrap_or(HostError::BackendUnavailable))
    }
}

pub struct NativeXpcEventSession {
    session_nonce: [u8; 32],
    session: Option<NativeXpcSession>,
}

impl NativeXpcEventSession {
    pub fn new(session_nonce: [u8; 32]) -> Self {
        Self {
            session_nonce,
            session: None,
        }
    }

    pub fn dispatch<L, S>(
        &mut self,
        state: &mut XpcListenerState,
        connection_id: u64,
        peer: &mut RequirementBoundConnection,
        event: XpcIncomingEvent,
        context: &MacosServiceContext<L, S>,
        now_tick: u64,
    ) -> Result<(), HostError>
    where
        L: HelperLifecycle,
        S: SecretSource,
    {
        self.dispatch_peer(state, connection_id, peer, event, context, now_tick)
    }

    fn dispatch_peer<P, L, S>(
        &mut self,
        state: &mut XpcListenerState,
        connection_id: u64,
        peer: &mut P,
        event: XpcIncomingEvent,
        context: &MacosServiceContext<L, S>,
        now_tick: u64,
    ) -> Result<(), HostError>
    where
        P: XpcReplyIo + XpcAppPeer,
        L: HelperLifecycle,
        S: SecretSource,
    {
        let XpcIncomingEvent::Message(message) = event else {
            self.session_nonce.zeroize();
            close_failed(state, connection_id, peer);
            return Err(HostError::InvalidInput);
        };
        #[cfg(feature = "macos-development-bootstrap")]
        debug_log("message-received");
        peer.set_reply_target(&message)?;
        if let Some(session) = self.session.as_mut() {
            #[cfg(feature = "macos-development-bootstrap")]
            {
                let request_frame = message.to_frame().inspect_err(|error| {
                    debug_log(&format!("request-frame-error={error:?}"));
                })?;
                let request: tunbridge_service::protocol::Request =
                    tunbridge_service::frame::decode(&request_frame).map_err(|error| {
                        debug_log(&format!("request-decode-error={error:?}"));
                        HostError::InvalidInput
                    })?;
                let command = match &request.command {
                    tunbridge_service::protocol::Command::Status => "status",
                    tunbridge_service::protocol::Command::Start { .. } => "start",
                    tunbridge_service::protocol::Command::Stop => "stop",
                    tunbridge_service::protocol::Command::Recover => "recover",
                    tunbridge_service::protocol::Command::ProvisionGeneration { .. } => {
                        "provision-generation"
                    }
                    tunbridge_service::protocol::Command::AcquireLease {} => "acquire-lease",
                    tunbridge_service::protocol::Command::RenewLease { .. } => "renew-lease",
                    tunbridge_service::protocol::Command::ReleaseLease { .. } => "release-lease",
                    tunbridge_service::protocol::Command::ObserveTraffic {} => "observe-traffic",
                    tunbridge_service::protocol::Command::ListConnections { .. } => {
                        "list-connections"
                    }
                    tunbridge_service::protocol::Command::CloseConnection { .. } => {
                        "close-connection"
                    }
                    tunbridge_service::protocol::Command::CloseAllConnections {} => {
                        "close-all-connections"
                    }
                    tunbridge_service::protocol::Command::ListMihomoLogs { .. } => {
                        "list-mihomo-logs"
                    }
                };
                debug_log(&format!("request-command={command} seq={}", request.seq));
            }
            #[cfg(feature = "macos-development-bootstrap")]
            let bootstrap = {
                let request_frame = message.to_frame().inspect_err(|error| {
                    debug_log(&format!("bootstrap-frame-error={error:?}"));
                })?;
                let request: tunbridge_service::protocol::Request =
                    tunbridge_service::frame::decode(&request_frame).map_err(|error| {
                        debug_log(&format!("bootstrap-decode-error={error:?}"));
                        HostError::InvalidInput
                    })?;
                match &request.command {
                    tunbridge_service::protocol::Command::ProvisionGeneration {
                        caller_cdhash,
                        ..
                    } => {
                        let caller = match peer.development_bootstrap_caller(caller_cdhash) {
                            Ok(caller) => caller,
                            Err(error) => {
                                debug_log(&format!("bootstrap-caller-error={error:?}"));
                                return Err(error);
                            }
                        };
                        let executable = match peer.verified_app_executable() {
                            Ok(executable) => executable,
                            Err(error) => {
                                debug_log(&format!("bootstrap-executable-error={error:?}"));
                                return Err(error);
                            }
                        };
                        Some((caller, executable))
                    }
                    _ => None,
                }
            };
            return dispatch_request(state, connection_id, peer, || {
                #[cfg(feature = "macos-development-bootstrap")]
                {
                    let bootstrap_refs = bootstrap
                        .as_ref()
                        .map(|(caller, executable)| (caller, executable.as_path()));
                    session.handle_with_bootstrap(context, &message, now_tick, bootstrap_refs)
                }
                #[cfg(not(feature = "macos-development-bootstrap"))]
                session.handle(context, &message, now_tick)
            });
        }

        // Publish the authenticated session before sending the hello reply.
        // The client is allowed to issue Start immediately after receiving
        // that reply; publishing afterwards races with the next XPC event and
        // makes the first lifecycle request look like a second hello.
        if state.begin_hello(connection_id).is_err() {
            close_failed(state, connection_id, peer);
            return Err(HostError::InvalidInput);
        }
        let accepted = NativeXpcSession::accept_peer(peer, &message, self.session_nonce);
        self.session_nonce.zeroize();
        let (session, response) = match accepted {
            Ok(value) => value,
            Err(error) => {
                close_failed(state, connection_id, peer);
                return Err(error);
            }
        };
        self.session = Some(session);
        let result = peer.send(&response).and_then(|_| {
            state
                .finish_hello(connection_id, true)
                .map_err(|_| HostError::BackendUnavailable)
        });
        if result.is_err() {
            self.session = None;
            close_failed(state, connection_id, peer);
        }
        result
    }
}

impl Drop for NativeXpcEventSession {
    fn drop(&mut self) {
        self.session_nonce.zeroize();
    }
}

struct NativeXpcConnectionRuntime {
    connection: RequirementBoundConnection,
    session: NativeXpcEventSession,
}

struct NativeXpcRegistryShared<L, S> {
    state: Mutex<XpcListenerState>,
    connections: Mutex<BTreeMap<u64, Arc<Mutex<NativeXpcConnectionRuntime>>>>,
    context: Arc<MacosServiceContext<L, S>>,
    now_tick: Arc<dyn Fn() -> Result<u64, HostError> + Send + Sync>,
}

impl<L, S> NativeXpcRegistryShared<L, S>
where
    L: HelperLifecycle + 'static,
    S: SecretSource + 'static,
{
    fn dispatch(&self, connection_id: u64, event: XpcIncomingEvent) -> Result<(), HostError> {
        #[cfg(feature = "macos-development-bootstrap")]
        debug_log(&format!("dispatch-start id={connection_id}"));
        let runtime = match self.connections.lock() {
            Ok(connections) => connections.get(&connection_id).cloned(),
            Err(_) => None,
        }
        .ok_or(HostError::InvalidInput)?;
        let result = (|| {
            let mut runtime = runtime.lock().map_err(|_| HostError::BackendUnavailable)?;
            let mut state = self
                .state
                .lock()
                .map_err(|_| HostError::BackendUnavailable)?;
            let now_tick = catch_unwind(AssertUnwindSafe(|| (self.now_tick)()))
                .map_err(|_| HostError::BackendUnavailable)??;
            let NativeXpcConnectionRuntime {
                connection,
                session,
            } = &mut *runtime;
            session.dispatch(
                &mut state,
                connection_id,
                connection,
                event,
                &self.context,
                now_tick,
            )
        })();
        if result.is_err() {
            #[cfg(feature = "macos-development-bootstrap")]
            debug_log(&format!(
                "dispatch-error id={connection_id} error={:?}",
                result
            ));
            self.remove(connection_id);
        } else {
            #[cfg(feature = "macos-development-bootstrap")]
            debug_log(&format!("dispatch-ok id={connection_id}"));
        }
        result
    }

    fn remove(&self, connection_id: u64) {
        if let Ok(mut connections) = self.connections.lock() {
            connections.remove(&connection_id);
        }
        if let Ok(mut state) = self.state.lock() {
            state.cancel(connection_id);
        }
    }
}

pub struct NativeXpcConnectionRegistry<L, S> {
    shared: Arc<NativeXpcRegistryShared<L, S>>,
    next_connection_id: AtomicU64,
    accepting: AtomicBool,
}

impl<L, S> NativeXpcConnectionRegistry<L, S>
where
    L: HelperLifecycle + 'static,
    S: SecretSource + 'static,
{
    pub fn new(
        context: Arc<MacosServiceContext<L, S>>,
        now_tick: Arc<dyn Fn() -> Result<u64, HostError> + Send + Sync>,
    ) -> Self {
        Self {
            shared: Arc::new(NativeXpcRegistryShared {
                state: Mutex::new(XpcListenerState::default()),
                connections: Mutex::new(BTreeMap::new()),
                context,
                now_tick,
            }),
            next_connection_id: AtomicU64::new(1),
            accepting: AtomicBool::new(true),
        }
    }

    pub fn admit(
        &self,
        connection: RequirementBoundConnection,
        session_nonce: [u8; 32],
    ) -> Result<u64, HostError> {
        let mut connection = connection;
        let connection_id =
            match self
                .next_connection_id
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            {
                Ok(connection_id) => connection_id,
                Err(_) => {
                    connection.cancel();
                    return Err(HostError::BackendUnavailable);
                }
            };
        match self.shared.state.lock() {
            Ok(mut state) => {
                if !self.accepting.load(Ordering::Acquire) {
                    connection.cancel();
                    return Err(HostError::BackendUnavailable);
                }
                if state.accept(connection_id).is_err() {
                    connection.cancel();
                    return Err(HostError::InvalidInput);
                }
            }
            Err(_) => {
                connection.cancel();
                return Err(HostError::BackendUnavailable);
            }
        }

        let runtime = Arc::new(Mutex::new(NativeXpcConnectionRuntime {
            connection,
            session: NativeXpcEventSession::new(session_nonce),
        }));
        match self.shared.connections.lock() {
            Ok(mut connections) => {
                let duplicate = connections
                    .insert(connection_id, Arc::clone(&runtime))
                    .is_some();
                drop(connections);
                if duplicate {
                    if let Ok(mut runtime) = runtime.lock() {
                        runtime.connection.cancel();
                    }
                    self.shared.remove(connection_id);
                    return Err(HostError::BackendUnavailable);
                }
            }
            Err(_) => {
                if let Ok(mut runtime) = runtime.lock() {
                    runtime.connection.cancel();
                }
                self.shared.remove(connection_id);
                return Err(HostError::BackendUnavailable);
            }
        }

        let weak = Arc::downgrade(&self.shared);
        let setup = runtime
            .lock()
            .map_err(|_| HostError::BackendUnavailable)
            .and_then(|mut runtime| {
                runtime
                    .connection
                    .install_event_handler(Arc::new(move |event| {
                        if let Some(shared) = weak.upgrade() {
                            let _ = shared.dispatch(connection_id, event);
                        }
                    }))?;
                runtime.connection.activate_after_event_handler()
            });
        if setup.is_err() {
            if let Ok(mut runtime) = runtime.lock() {
                runtime.connection.cancel();
            }
            self.shared.remove(connection_id);
            return Err(setup.err().unwrap_or(HostError::BackendUnavailable));
        }
        Ok(connection_id)
    }

    pub fn admit_with_secret_source<N>(
        &self,
        mut connection: RequirementBoundConnection,
        secrets: &mut N,
    ) -> Result<u64, HostError>
    where
        N: SecretSource,
    {
        let session_nonce = match secrets.next_32() {
            Ok(nonce) => nonce,
            Err(error) => {
                connection.cancel();
                return Err(error);
            }
        };
        self.admit(connection, session_nonce)
    }

    /// Bind and admit one borrowed connection delivered by the launchd Mach
    /// service listener.
    ///
    /// # Safety
    ///
    /// `connection` must remain a live borrowed libxpc object for this call.
    #[cfg(feature = "macos-xpc-listener")]
    pub unsafe fn admit_borrowed_connection(
        &self,
        connection: NonNull<c_void>,
        requirement: &XpcCodeRequirement,
    ) -> Result<u64, HostError> {
        let bound = match unsafe { RequirementBoundConnection::bind(connection, requirement) } {
            Ok(bound) => bound,
            Err(_) => {
                unsafe { cancel_borrowed_connection(connection) };
                return Err(HostError::InvalidInput);
            }
        };
        self.admit_with_secret_source(bound, &mut SystemSecretSource)
    }

    pub fn active_connections(&self) -> Result<usize, HostError> {
        self.shared
            .state
            .lock()
            .map_err(|_| HostError::BackendUnavailable)
            .map(|state| state.active_connections())
    }

    pub fn cancel_all(&self) {
        let runtimes = {
            let mut connections = self
                .shared
                .connections
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(&mut *connections)
        };
        {
            let mut state = self
                .shared
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *state = XpcListenerState::default();
        }
        drop(runtimes);
    }

    pub fn shutdown(&self) {
        self.accepting.store(false, Ordering::Release);
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let runtimes = {
            let mut connections = self
                .shared
                .connections
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::mem::take(&mut *connections)
        };
        *state = XpcListenerState::default();
        drop(state);
        drop(runtimes);
    }

    #[cfg(test)]
    pub(crate) fn is_shut_down(&self) -> bool {
        !self.accepting.load(Ordering::Acquire)
    }

    #[cfg(test)]
    fn dispatch_test_event(
        &self,
        connection_id: u64,
        event: XpcIncomingEvent,
    ) -> Result<(), HostError> {
        self.shared.dispatch(connection_id, event)
    }
}

#[cfg(feature = "macos-xpc-listener")]
pub fn run_native_xpc_main<L, S>(
    registry: Arc<NativeXpcConnectionRegistry<L, S>>,
    app_requirement: XpcCodeRequirement,
) -> Result<Infallible, HostError>
where
    L: HelperLifecycle + 'static,
    S: SecretSource + 'static,
{
    use block2::RcBlock;

    let service_name = CString::new(MACH_SERVICE_NAME).map_err(|_| HostError::InvalidInput)?;
    let listener = NonNull::new(unsafe {
        xpc_connection_create_mach_service(
            service_name.as_ptr(),
            std::ptr::null_mut(),
            XPC_CONNECTION_MACH_SERVICE_LISTENER,
        )
    })
    .ok_or(HostError::BackendUnavailable)?;
    #[cfg(feature = "macos-development-bootstrap")]
    debug_log("listener-created");
    let handler: RcBlock<dyn Fn(*mut c_void)> = RcBlock::new(move |connection: *mut c_void| {
        #[cfg(feature = "macos-development-bootstrap")]
        debug_log("listener-event");
        if let Some(connection) = NonNull::new(connection) {
            let result =
                unsafe { registry.admit_borrowed_connection(connection, &app_requirement) };
            #[cfg(feature = "macos-development-bootstrap")]
            debug_log(&format!("listener-admit result={result:?}"));
        }
    });
    let pointer = (&*handler as *const block2::Block<dyn Fn(*mut c_void)>)
        .cast_mut()
        .cast();
    unsafe {
        xpc_connection_set_event_handler(listener.as_ptr(), pointer);
        xpc_connection_activate(listener.as_ptr());
        #[cfg(feature = "macos-development-bootstrap")]
        debug_log("listener-activated");
        dispatch_main();
    }
}

#[cfg(feature = "macos-xpc-listener")]
unsafe extern "C" {
    fn xpc_connection_create_mach_service(
        name: *const c_char,
        target_queue: *mut c_void,
        flags: u64,
    ) -> *mut c_void;
    fn xpc_connection_set_event_handler(connection: *mut c_void, handler: *mut c_void);
    fn xpc_connection_activate(connection: *mut c_void);
    fn dispatch_main() -> !;
}

#[cfg(feature = "macos-xpc-listener")]
const XPC_CONNECTION_MACH_SERVICE_LISTENER: u64 = 1 << 0;

fn close_failed<I: XpcReplyIo>(state: &mut XpcListenerState, connection_id: u64, io: &mut I) {
    state.cancel(connection_id);
    io.cancel();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::AppRequirementPolicy,
        lifecycle_host::StartMaterial,
        native::{TestXpcConnectionFunctions, XpcCodeRequirement},
    };
    use std::{
        ffi::{c_char, c_int, c_void},
        ptr::NonNull,
        sync::atomic::AtomicUsize,
    };
    use tunbridge_service::{
        frame,
        protocol::{Command, Hello, HelloOk, Request, RequestKind, PROTOCOL_VERSION},
        state::Caller,
    };

    #[derive(Default)]
    struct FakeIo {
        sent: Vec<Vec<u8>>,
        cancels: usize,
        fail_send: bool,
    }

    impl XpcReplyIo for FakeIo {
        fn send(&mut self, response: &XpcFrameEnvelope) -> Result<(), HostError> {
            if self.fail_send {
                return Err(HostError::BackendUnavailable);
            }
            self.sent.push(response.to_frame()?);
            Ok(())
        }

        fn cancel(&mut self) {
            self.cancels += 1;
        }
    }

    impl XpcAppPeer for FakeIo {
        fn authenticated_caller(&self) -> Result<Caller, HostError> {
            Ok(Caller {
                principal_id: "macos:502:ABCDE12345:com.tunbridge.desktop".into(),
                session_id: 42,
                is_admin: false,
            })
        }
    }

    #[derive(Default)]
    struct MemoryLifecycle;

    impl HelperLifecycle for MemoryLifecycle {
        fn start(
            &mut self,
            _profile: &tunbridge_service::protocol::ActiveStartProfile,
            _caller: &Caller,
            _material: StartMaterial,
        ) -> Result<(), HostError> {
            Ok(())
        }

        fn recover(&mut self) -> Result<(), HostError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct DeterministicSecrets;

    impl SecretSource for DeterministicSecrets {
        fn next_32(&mut self) -> Result<[u8; 32], HostError> {
            Ok([0x5a; 32])
        }
    }

    struct FailingSecrets;

    impl SecretSource for FailingSecrets {
        fn next_32(&mut self) -> Result<[u8; 32], HostError> {
            Err(HostError::BackendUnavailable)
        }
    }

    fn response() -> XpcFrameEnvelope {
        XpcFrameEnvelope::from_frame(&frame::encode(&Hello::new("0.2.3")).unwrap()).unwrap()
    }

    fn event<T: serde::Serialize>(value: &T) -> XpcIncomingEvent {
        XpcIncomingEvent::Message(
            XpcFrameEnvelope::from_frame(&frame::encode(value).unwrap()).unwrap(),
        )
    }

    static REGISTRY_TEST_LOCK: Mutex<()> = Mutex::new(());
    static REGISTRY_RETAINS: AtomicUsize = AtomicUsize::new(0);
    static REGISTRY_RELEASES: AtomicUsize = AtomicUsize::new(0);
    static REGISTRY_ACTIVATES: AtomicUsize = AtomicUsize::new(0);
    static REGISTRY_CANCELS: AtomicUsize = AtomicUsize::new(0);
    static REGISTRY_HANDLERS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn registry_accept(
        _connection: *mut c_void,
        _requirement: *const c_char,
    ) -> c_int {
        0
    }

    unsafe extern "C" fn registry_retain(connection: *mut c_void) -> *mut c_void {
        REGISTRY_RETAINS.fetch_add(1, Ordering::SeqCst);
        connection
    }

    unsafe extern "C" fn registry_release(_connection: *mut c_void) {
        REGISTRY_RELEASES.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn registry_activate(_connection: *mut c_void) {
        REGISTRY_ACTIVATES.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn registry_cancel(_connection: *mut c_void) {
        REGISTRY_CANCELS.fetch_add(1, Ordering::SeqCst);
    }

    unsafe extern "C" fn registry_send(_connection: *mut c_void, _message: *mut c_void) {}

    unsafe extern "C" fn registry_handler(_connection: *mut c_void, _handler: *mut c_void) {
        REGISTRY_HANDLERS.fetch_add(1, Ordering::SeqCst);
    }

    fn registry_connection() -> RequirementBoundConnection {
        let policy = AppRequirementPolicy {
            team_id: "ABCDE12345".into(),
            signing_identifier: "com.tunbridge.desktop".into(),
            allowed_cdhashes: ["1111111111111111111111111111111111111111".into()]
                .into_iter()
                .collect(),
        };
        let requirement = XpcCodeRequirement::for_app(&policy).unwrap();
        unsafe {
            RequirementBoundConnection::bind_for_test(
                NonNull::dangling(),
                &requirement,
                registry_accept,
                TestXpcConnectionFunctions {
                    retain: registry_retain,
                    release: registry_release,
                    activate: registry_activate,
                    cancel: registry_cancel,
                    send: registry_send,
                    set_event_handler: registry_handler,
                },
            )
        }
        .unwrap()
    }

    fn reset_registry_counters() {
        REGISTRY_RETAINS.store(0, Ordering::SeqCst);
        REGISTRY_RELEASES.store(0, Ordering::SeqCst);
        REGISTRY_ACTIVATES.store(0, Ordering::SeqCst);
        REGISTRY_CANCELS.store(0, Ordering::SeqCst);
        REGISTRY_HANDLERS.store(0, Ordering::SeqCst);
    }

    #[test]
    fn connection_requires_one_hello_then_serial_requests() {
        let mut state = XpcListenerState::default();
        state.accept(1).unwrap();
        assert_eq!(state.phase(1), Some(XpcConnectionPhase::AwaitingHello));
        assert_eq!(state.begin_request(1), Err(XpcListenerError::WrongPhase));
        state.begin_hello(1).unwrap();
        assert_eq!(state.begin_hello(1), Err(XpcListenerError::RequestInFlight));
        state.finish_hello(1, true).unwrap();
        assert_eq!(state.phase(1), Some(XpcConnectionPhase::Ready));
        assert_eq!(state.begin_hello(1), Err(XpcListenerError::WrongPhase));

        state.begin_request(1).unwrap();
        assert_eq!(
            state.begin_request(1),
            Err(XpcListenerError::RequestInFlight)
        );
        state.finish_request(1, true).unwrap();
        state.begin_request(1).unwrap();
        state.finish_request(1, true).unwrap();
        assert_eq!(state.active_connections(), 1);
    }

    #[test]
    fn admission_is_bounded_unique_and_cancel_is_idempotent() {
        let mut state = XpcListenerState::default();
        assert_eq!(state.accept(0), Err(XpcListenerError::InvalidConnection));
        for id in 1..=MAX_ACTIVE_XPC_CONNECTIONS as u64 {
            state.accept(id).unwrap();
        }
        assert_eq!(state.accept(1), Err(XpcListenerError::DuplicateConnection));
        assert_eq!(state.accept(99), Err(XpcListenerError::ConnectionLimit));
        assert!(state.cancel(1));
        assert!(!state.cancel(1));
        state.accept(99).unwrap();
    }

    #[test]
    fn rejected_hello_and_failed_request_close_only_that_connection() {
        let mut state = XpcListenerState::default();
        state.accept(1).unwrap();
        state.accept(2).unwrap();
        state.begin_hello(1).unwrap();
        state.finish_hello(1, false).unwrap();
        assert_eq!(state.phase(1), None);

        state.begin_hello(2).unwrap();
        state.finish_hello(2, true).unwrap();
        state.begin_request(2).unwrap();
        state.finish_request(2, false).unwrap();
        assert_eq!(state.phase(2), None);
        assert_eq!(state.active_connections(), 0);
    }

    #[test]
    fn exact_request_cap_closes_admission_without_counter_wrap() {
        let mut state = XpcListenerState::default();
        state.accept(1).unwrap();
        state.begin_hello(1).unwrap();
        state.finish_hello(1, true).unwrap();
        for _ in 0..MAX_REQUESTS_PER_CONNECTION {
            state.begin_request(1).unwrap();
            state.finish_request(1, true).unwrap();
        }
        assert_eq!(state.begin_request(1), Err(XpcListenerError::RequestLimit));
        assert_eq!(state.phase(1), Some(XpcConnectionPhase::Ready));
    }

    #[test]
    fn reactor_sends_one_hello_and_request_reply_before_advancing_state() {
        let mut state = XpcListenerState::default();
        let mut io = FakeIo::default();
        state.accept(1).unwrap();
        dispatch_hello(&mut state, 1, &mut io, || Ok(response())).unwrap();
        dispatch_request(&mut state, 1, &mut io, || Ok(response())).unwrap();
        assert_eq!(io.sent.len(), 2);
        assert_eq!(io.cancels, 0);
        assert_eq!(state.phase(1), Some(XpcConnectionPhase::Ready));
    }

    #[test]
    fn reactor_cancels_on_work_send_phase_or_request_limit_failure() {
        for failure in ["work", "send", "phase", "limit"] {
            let mut state = XpcListenerState::default();
            let mut io = FakeIo::default();
            state.accept(1).unwrap();
            if failure == "phase" {
                assert!(dispatch_request(&mut state, 1, &mut io, || Ok(response())).is_err());
            } else {
                dispatch_hello(&mut state, 1, &mut io, || Ok(response())).unwrap();
                if failure == "work" {
                    assert!(dispatch_request(&mut state, 1, &mut io, || {
                        Err(HostError::InvalidInput)
                    })
                    .is_err());
                } else if failure == "send" {
                    io.fail_send = true;
                    assert!(dispatch_request(&mut state, 1, &mut io, || Ok(response())).is_err());
                } else {
                    for _ in 0..MAX_REQUESTS_PER_CONNECTION {
                        dispatch_request(&mut state, 1, &mut io, || Ok(response())).unwrap();
                    }
                    assert!(dispatch_request(&mut state, 1, &mut io, || Ok(response())).is_err());
                }
            }
            assert_eq!(io.cancels, 1);
            assert_eq!(state.phase(1), None);
        }
    }

    #[test]
    fn native_event_session_wires_hello_request_and_reply_in_order() {
        let mut state = XpcListenerState::default();
        state.accept(7).unwrap();
        let mut io = FakeIo::default();
        let mut reactor = NativeXpcEventSession::new([0xa5; 32]);
        let context = MacosServiceContext::stopped(MemoryLifecycle, DeterministicSecrets);

        reactor
            .dispatch_peer(
                &mut state,
                7,
                &mut io,
                event(&Hello::new("0.2.3")),
                &context,
                10,
            )
            .unwrap();
        let hello: HelloOk = frame::decode(&io.sent[0]).unwrap();
        reactor
            .dispatch_peer(
                &mut state,
                7,
                &mut io,
                event(&Request {
                    kind: RequestKind::Request,
                    protocol: PROTOCOL_VERSION,
                    session_nonce: hello.session_nonce,
                    seq: 1,
                    request_id: "b".repeat(32),
                    command: Command::Status,
                }),
                &context,
                11,
            )
            .unwrap();

        assert_eq!(io.sent.len(), 2);
        assert_eq!(io.cancels, 0);
        assert_eq!(state.phase(7), Some(XpcConnectionPhase::Ready));
        assert!(reactor.session.is_some());
        assert_eq!(reactor.session_nonce, [0; 32]);
    }

    #[test]
    fn native_event_session_cancels_on_invalid_error_send_and_protocol_failures() {
        for failure in ["invalid", "error", "send", "protocol"] {
            let mut state = XpcListenerState::default();
            state.accept(7).unwrap();
            let mut io = FakeIo {
                fail_send: failure == "send",
                ..FakeIo::default()
            };
            let mut reactor = NativeXpcEventSession::new([0xa5; 32]);
            let context = MacosServiceContext::stopped(MemoryLifecycle, DeterministicSecrets);
            let event = match failure {
                "invalid" => XpcIncomingEvent::Invalid,
                "error" => XpcIncomingEvent::ConnectionError,
                "send" => event(&Hello::new("0.2.3")),
                "protocol" => event(&42_u32),
                _ => unreachable!(),
            };

            assert!(reactor
                .dispatch_peer(&mut state, 7, &mut io, event, &context, 10)
                .is_err());
            assert_eq!(io.cancels, 1);
            assert_eq!(state.phase(7), None);
            assert!(reactor.session.is_none());
            assert_eq!(reactor.session_nonce, [0; 32]);
        }
    }

    #[test]
    fn native_registry_owns_activates_and_removes_failed_connections() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_registry_counters();
        let context = Arc::new(MacosServiceContext::stopped(
            MemoryLifecycle,
            DeterministicSecrets,
        ));
        let registry = NativeXpcConnectionRegistry::new(context, Arc::new(|| Ok(44)));
        let connection_id = registry.admit(registry_connection(), [0xa5; 32]).unwrap();

        assert_eq!(registry.active_connections().unwrap(), 1);
        assert_eq!(REGISTRY_RETAINS.load(Ordering::SeqCst), 1);
        assert_eq!(REGISTRY_HANDLERS.load(Ordering::SeqCst), 1);
        assert_eq!(REGISTRY_ACTIVATES.load(Ordering::SeqCst), 1);

        assert!(registry
            .dispatch_test_event(connection_id, XpcIncomingEvent::Invalid)
            .is_err());
        assert_eq!(registry.active_connections().unwrap(), 0);
        assert_eq!(REGISTRY_CANCELS.load(Ordering::SeqCst), 1);
        assert_eq!(REGISTRY_RELEASES.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn native_registry_enforces_global_connection_cap_and_drop_cleanup() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_registry_counters();
        let context = Arc::new(MacosServiceContext::stopped(
            MemoryLifecycle,
            DeterministicSecrets,
        ));
        let registry = NativeXpcConnectionRegistry::new(context, Arc::new(|| Ok(44)));
        for _ in 0..MAX_ACTIVE_XPC_CONNECTIONS {
            registry.admit(registry_connection(), [0xa5; 32]).unwrap();
        }
        assert!(registry.admit(registry_connection(), [0xa5; 32]).is_err());
        assert_eq!(
            registry.active_connections().unwrap(),
            MAX_ACTIVE_XPC_CONNECTIONS
        );
        drop(registry);
        assert_eq!(
            REGISTRY_CANCELS.load(Ordering::SeqCst),
            MAX_ACTIVE_XPC_CONNECTIONS + 1
        );
        assert_eq!(
            REGISTRY_RELEASES.load(Ordering::SeqCst),
            MAX_ACTIVE_XPC_CONNECTIONS + 1
        );
    }

    #[test]
    fn native_registry_converts_clock_panic_to_connection_cleanup() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_registry_counters();
        let context = Arc::new(MacosServiceContext::stopped(
            MemoryLifecycle,
            DeterministicSecrets,
        ));
        let registry =
            NativeXpcConnectionRegistry::new(context, Arc::new(|| panic!("clock failed")));
        let connection_id = registry.admit(registry_connection(), [0xa5; 32]).unwrap();

        assert!(registry
            .dispatch_test_event(connection_id, event(&Hello::new("0.2.3")))
            .is_err());
        assert_eq!(registry.active_connections().unwrap(), 0);
        assert_eq!(REGISTRY_CANCELS.load(Ordering::SeqCst), 1);
        assert_eq!(REGISTRY_RELEASES.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn native_registry_rejects_connection_when_nonce_generation_fails() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_registry_counters();
        let context = Arc::new(MacosServiceContext::stopped(
            MemoryLifecycle,
            DeterministicSecrets,
        ));
        let registry = NativeXpcConnectionRegistry::new(context, Arc::new(|| Ok(44)));

        assert!(registry
            .admit_with_secret_source(registry_connection(), &mut FailingSecrets)
            .is_err());
        assert_eq!(registry.active_connections().unwrap(), 0);
        assert_eq!(REGISTRY_CANCELS.load(Ordering::SeqCst), 1);
        assert_eq!(REGISTRY_RELEASES.load(Ordering::SeqCst), 1);
        assert_eq!(REGISTRY_HANDLERS.load(Ordering::SeqCst), 0);
        assert_eq!(REGISTRY_ACTIVATES.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn native_registry_rejects_connection_id_overflow_before_admission() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_registry_counters();
        let context = Arc::new(MacosServiceContext::stopped(
            MemoryLifecycle,
            DeterministicSecrets,
        ));
        let registry = NativeXpcConnectionRegistry::new(context, Arc::new(|| Ok(44)));
        registry
            .next_connection_id
            .store(u64::MAX, Ordering::SeqCst);

        assert!(registry.admit(registry_connection(), [0xa5; 32]).is_err());
        assert_eq!(registry.active_connections().unwrap(), 0);
        assert_eq!(REGISTRY_CANCELS.load(Ordering::SeqCst), 1);
        assert_eq!(REGISTRY_RELEASES.load(Ordering::SeqCst), 1);
        assert_eq!(REGISTRY_HANDLERS.load(Ordering::SeqCst), 0);
        assert_eq!(REGISTRY_ACTIVATES.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn native_registry_cancel_all_closes_every_connection_and_resets_admission() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_registry_counters();
        let context = Arc::new(MacosServiceContext::stopped(
            MemoryLifecycle,
            DeterministicSecrets,
        ));
        let registry = NativeXpcConnectionRegistry::new(context, Arc::new(|| Ok(44)));
        for _ in 0..3 {
            registry.admit(registry_connection(), [0xa5; 32]).unwrap();
        }

        registry.cancel_all();
        assert_eq!(registry.active_connections().unwrap(), 0);
        assert_eq!(REGISTRY_CANCELS.load(Ordering::SeqCst), 3);
        assert_eq!(REGISTRY_RELEASES.load(Ordering::SeqCst), 3);

        registry.admit(registry_connection(), [0xa5; 32]).unwrap();
        assert_eq!(registry.active_connections().unwrap(), 1);
    }

    #[test]
    fn native_registry_shutdown_closes_connections_and_rejects_new_admission() {
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_registry_counters();
        let context = Arc::new(MacosServiceContext::stopped(
            MemoryLifecycle,
            DeterministicSecrets,
        ));
        let registry = NativeXpcConnectionRegistry::new(context, Arc::new(|| Ok(44)));
        registry.admit(registry_connection(), [0xa5; 32]).unwrap();

        registry.shutdown();
        assert_eq!(registry.active_connections().unwrap(), 0);
        assert_eq!(REGISTRY_CANCELS.load(Ordering::SeqCst), 1);
        assert_eq!(REGISTRY_RELEASES.load(Ordering::SeqCst), 1);

        assert!(registry.admit(registry_connection(), [0xa5; 32]).is_err());
        assert_eq!(REGISTRY_CANCELS.load(Ordering::SeqCst), 2);
        assert_eq!(REGISTRY_RELEASES.load(Ordering::SeqCst), 2);
    }
}
