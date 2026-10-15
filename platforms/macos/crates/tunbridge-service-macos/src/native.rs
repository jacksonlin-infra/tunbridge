use crate::{
    darwin_state::{DarwinInterface, InterfaceSnapshot, RouteSnapshot},
    dispatcher::SecretSource,
    identity::{AppRequirementPolicy, HelperRequirementPolicy},
    lifecycle_host::HostError,
    lifecycle_plan::ProcessIdentity,
    route_message::{decode_route_messages, RouteMessageError},
};
use block2::RcBlock;
#[cfg(target_os = "macos")]
use security_framework::os::macos::code_signing::SecRequirement;
#[cfg(all(target_os = "macos", not(feature = "macos-development-bootstrap")))]
use security_framework::os::macos::code_signing::{Flags, GuestAttributes, SecCode};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{c_char, c_int, c_void, CStr, CString},
    fs::File,
    io::Read,
    mem::{size_of, MaybeUninit},
    os::{
        fd::FromRawFd,
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    panic::{catch_unwind, AssertUnwindSafe},
    path::PathBuf,
    ptr::NonNull,
    sync::Arc,
};
use tunbridge_service::protocol::MAX_FRAME_BYTES;
use tunbridge_service::state::Caller;
#[cfg(feature = "macos-development-bootstrap")]
use tunbridge_setup_macos::bootstrap_protocol::BootstrapCaller;

const PROC_PIDTBSDINFO: c_int = 3;
const MAXCOMLEN: usize = 16;
const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;
const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_INTERFACES: usize = 256;
const MAX_ROUTE_DUMP_BYTES: usize = 4 * 1024 * 1024;
const ROUTE_DUMP_RETRIES: usize = 3;
const FRAME_KEY: &[u8] = b"frame\0";
#[cfg(test)]
const EXTRA_TEST_KEY: &[u8] = b"extra\0";
const PREFIX_BYTES: usize = size_of::<u32>();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeIdentityError {
    InvalidRequirement,
    RequirementRejected,
    InvalidConnectionFacts,
    ProcessUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeRouteError {
    Unavailable,
    Oversize,
    Decode(RouteMessageError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XpcCodeRequirement {
    encoded: CString,
    team_id: String,
    signing_identifier: String,
    allowed_cdhashes: BTreeSet<String>,
    role: PeerRole,
}

impl XpcCodeRequirement {
    pub fn for_app(policy: &AppRequirementPolicy) -> Result<Self, NativeIdentityError> {
        Self::new(
            &policy.team_id,
            &policy.signing_identifier,
            &policy.allowed_cdhashes,
            PeerRole::UserApp,
        )
    }

    pub fn for_helper(policy: &HelperRequirementPolicy) -> Result<Self, NativeIdentityError> {
        Self::new(
            &policy.team_id,
            &policy.signing_identifier,
            &policy.allowed_cdhashes,
            PeerRole::RootHelper,
        )
    }

    #[cfg(feature = "macos-development-bootstrap")]
    pub fn for_development_app() -> Result<Self, NativeIdentityError> {
        let encoded = CString::new("identifier \"com.tunbridge.desktop\"")
            .map_err(|_| NativeIdentityError::InvalidRequirement)?;
        Ok(Self {
            encoded,
            team_id: "adhoc".into(),
            signing_identifier: "com.tunbridge.desktop".into(),
            allowed_cdhashes: BTreeSet::new(),
            role: PeerRole::UserApp,
        })
    }

    pub fn as_str(&self) -> &str {
        self.encoded
            .to_str()
            .expect("validated requirement is ASCII")
    }

    pub(crate) fn as_c_str(&self) -> &CStr {
        &self.encoded
    }

    pub fn allows_cdhash(&self, cdhash: &str) -> bool {
        self.allowed_cdhashes.contains(cdhash)
    }

    fn new(
        team_id: &str,
        signing_identifier: &str,
        allowed_cdhashes: &BTreeSet<String>,
        role: PeerRole,
    ) -> Result<Self, NativeIdentityError> {
        if !valid_identifier(team_id)
            || !valid_identifier(signing_identifier)
            || allowed_cdhashes.is_empty()
            || !allowed_cdhashes.iter().all(|hash| valid_cdhash(hash))
        {
            return Err(NativeIdentityError::InvalidRequirement);
        }
        let hashes = allowed_cdhashes
            .iter()
            .map(|hash| format!("cdhash H\"{hash}\""))
            .collect::<Vec<_>>()
            .join(" or ");
        let requirement = if team_id == "adhoc" {
            format!("identifier \"{signing_identifier}\" and ({hashes})")
        } else {
            format!(
                "anchor apple generic and identifier \"{signing_identifier}\" \
                 and certificate leaf[subject.OU] = \"{team_id}\" \
                 and flags runtime and ({hashes})"
            )
        };
        let encoded =
            CString::new(requirement).map_err(|_| NativeIdentityError::InvalidRequirement)?;
        Ok(Self {
            encoded,
            team_id: team_id.into(),
            signing_identifier: signing_identifier.into(),
            allowed_cdhashes: allowed_cdhashes.clone(),
            role,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerRole {
    UserApp,
    RootHelper,
}

#[derive(Debug)]
pub struct RequirementBoundConnection {
    connection: NonNull<c_void>,
    team_id: String,
    signing_identifier: String,
    code_requirement: String,
    allowed_cdhashes: BTreeSet<String>,
    role: PeerRole,
    functions: XpcConnectionFunctions,
    event_handler: Option<RcBlock<dyn Fn(*mut c_void)>>,
    reply_target: Option<NonNull<c_void>>,
    active: bool,
    cancelled: bool,
}

#[derive(Debug, Clone, Copy)]
struct XpcConnectionFunctions {
    retain: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
    release: unsafe extern "C" fn(*mut c_void),
    activate: unsafe extern "C" fn(*mut c_void),
    cancel: unsafe extern "C" fn(*mut c_void),
    send: unsafe extern "C" fn(*mut c_void, *mut c_void),
    set_event_handler: unsafe extern "C" fn(*mut c_void, *mut c_void),
}

#[cfg(test)]
pub(crate) struct TestXpcConnectionFunctions {
    pub(crate) retain: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
    pub(crate) release: unsafe extern "C" fn(*mut c_void),
    pub(crate) activate: unsafe extern "C" fn(*mut c_void),
    pub(crate) cancel: unsafe extern "C" fn(*mut c_void),
    pub(crate) send: unsafe extern "C" fn(*mut c_void, *mut c_void),
    pub(crate) set_event_handler: unsafe extern "C" fn(*mut c_void, *mut c_void),
}

#[derive(Debug)]
pub enum XpcIncomingEvent {
    Message(XpcFrameEnvelope),
    ConnectionError,
    Invalid,
}

impl RequirementBoundConnection {
    /// The connection must be a live XPC connection that has not yet been
    /// resumed and has no previously installed peer requirement. On success,
    /// the wrapper owns one retain and remains valid after the callback that
    /// supplied the borrowed connection returns.
    ///
    /// # Safety
    ///
    /// `connection` must remain valid for the duration of this call and must
    /// identify a suspended XPC connection object.
    pub unsafe fn bind(
        connection: NonNull<c_void>,
        requirement: &XpcCodeRequirement,
    ) -> Result<Self, NativeIdentityError> {
        let object_type = unsafe { xpc_get_type(connection.as_ptr()) };
        let connection_type = std::ptr::addr_of!(_xpc_type_connection).cast();
        if object_type != connection_type {
            return Err(NativeIdentityError::InvalidConnectionFacts);
        }
        unsafe {
            Self::bind_with_functions(
                connection,
                requirement,
                xpc_connection_set_peer_code_signing_requirement,
                XpcConnectionFunctions {
                    retain: xpc_retain,
                    release: xpc_release,
                    activate: xpc_connection_activate,
                    cancel: xpc_connection_cancel,
                    send: xpc_connection_send_message,
                    set_event_handler: xpc_connection_set_event_handler,
                },
            )
        }
    }

    unsafe fn bind_with_functions(
        connection: NonNull<c_void>,
        requirement: &XpcCodeRequirement,
        set_requirement: unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int,
        functions: XpcConnectionFunctions,
    ) -> Result<Self, NativeIdentityError> {
        let requirement_status =
            unsafe { set_requirement(connection.as_ptr(), requirement.encoded.as_ptr()) };
        #[cfg(feature = "macos-development-bootstrap")]
        crate::xpc_listener::debug_log(&format!("bind-requirement status={requirement_status}"));
        if requirement_status != 0 {
            return Err(NativeIdentityError::RequirementRejected);
        }
        let retained = NonNull::new(unsafe { (functions.retain)(connection.as_ptr()) })
            .ok_or(NativeIdentityError::RequirementRejected)?;
        #[cfg(feature = "macos-development-bootstrap")]
        crate::xpc_listener::debug_log("bind-retained");
        Ok(Self {
            connection: retained,
            team_id: requirement.team_id.clone(),
            signing_identifier: requirement.signing_identifier.clone(),
            code_requirement: requirement.as_str().into(),
            allowed_cdhashes: requirement.allowed_cdhashes.clone(),
            role: requirement.role,
            functions,
            event_handler: None,
            reply_target: None,
            active: false,
            cancelled: false,
        })
    }

    #[cfg(test)]
    pub(crate) unsafe fn bind_for_test(
        connection: NonNull<c_void>,
        requirement: &XpcCodeRequirement,
        set_requirement: unsafe extern "C" fn(*mut c_void, *const c_char) -> c_int,
        functions: TestXpcConnectionFunctions,
    ) -> Result<Self, NativeIdentityError> {
        unsafe {
            Self::bind_with_functions(
                connection,
                requirement,
                set_requirement,
                XpcConnectionFunctions {
                    retain: functions.retain,
                    release: functions.release,
                    activate: functions.activate,
                    cancel: functions.cancel,
                    send: functions.send,
                    set_event_handler: functions.set_event_handler,
                },
            )
        }
    }

    pub fn install_event_handler(
        &mut self,
        callback: Arc<dyn Fn(XpcIncomingEvent) + Send + Sync>,
    ) -> Result<(), HostError> {
        if self.active || self.cancelled || self.event_handler.is_some() {
            return Err(HostError::InvalidInput);
        }
        let handler: RcBlock<dyn Fn(*mut c_void)> = RcBlock::new(move |event: *mut c_void| {
            if let Some(event) = NonNull::new(event) {
                let result = catch_unwind(AssertUnwindSafe(|| {
                    callback(classify_incoming_event(event));
                }));
                #[cfg(feature = "macos-development-bootstrap")]
                if result.is_err() {
                    crate::xpc_listener::debug_log("connection-event-panic");
                }
                #[cfg(not(feature = "macos-development-bootstrap"))]
                let _ = result;
            }
        });
        let pointer = (&*handler as *const block2::Block<dyn Fn(*mut c_void)>)
            .cast_mut()
            .cast();
        unsafe {
            (self.functions.set_event_handler)(self.connection.as_ptr(), pointer);
        }
        #[cfg(feature = "macos-development-bootstrap")]
        crate::xpc_listener::debug_log("connection-handler-installed");
        self.event_handler = Some(handler);
        Ok(())
    }

    pub fn activate_after_event_handler(&mut self) -> Result<(), HostError> {
        if self.active || self.cancelled || self.event_handler.is_none() {
            return Err(HostError::InvalidInput);
        }
        unsafe { (self.functions.activate)(self.connection.as_ptr()) };
        #[cfg(feature = "macos-development-bootstrap")]
        crate::xpc_listener::debug_log("connection-activated");
        self.active = true;
        Ok(())
    }

    pub fn send(&mut self, envelope: &XpcFrameEnvelope) -> Result<(), HostError> {
        if !self.active || self.cancelled {
            return Err(HostError::InvalidInput);
        }
        let frame = envelope.to_frame()?;
        if let Some(request) = self.reply_target.take() {
            let reply = NonNull::new(unsafe { xpc_dictionary_create_reply(request.as_ptr()) })
                .ok_or_else(|| {
                    #[cfg(feature = "macos-development-bootstrap")]
                    crate::xpc_listener::debug_log("reply-create-failed");
                    HostError::BackendUnavailable
                })?;
            #[cfg(feature = "macos-development-bootstrap")]
            crate::xpc_listener::debug_log("reply-created");
            unsafe {
                xpc_dictionary_set_data(
                    reply.as_ptr(),
                    FRAME_KEY.as_ptr().cast(),
                    frame.as_ptr().cast(),
                    frame.len(),
                );
                (self.functions.send)(self.connection.as_ptr(), reply.as_ptr());
                xpc_release(reply.as_ptr());
            }
            #[cfg(feature = "macos-development-bootstrap")]
            crate::xpc_listener::debug_log("reply-sent");
            return Ok(());
        }
        envelope.to_frame()?;
        unsafe {
            (self.functions.send)(self.connection.as_ptr(), envelope.object.as_ptr());
        }
        Ok(())
    }

    pub(crate) fn set_reply_target(&mut self, request: &XpcFrameEnvelope) {
        self.reply_target = Some(request.object);
        #[cfg(feature = "macos-development-bootstrap")]
        crate::xpc_listener::debug_log("reply-target-set");
    }

    pub fn cancel(&mut self) {
        if !self.cancelled {
            unsafe { (self.functions.cancel)(self.connection.as_ptr()) };
            self.cancelled = true;
        }
    }

    pub fn facts(&self) -> Result<NativeConnectionFacts, NativeIdentityError> {
        let pid = unsafe { xpc_connection_get_pid(self.connection.as_ptr()) };
        let effective_uid = unsafe { xpc_connection_get_euid(self.connection.as_ptr()) };
        let audit_session_id = unsafe { xpc_connection_get_asid(self.connection.as_ptr()) };
        if pid <= 1 || audit_session_id == 0 {
            return Err(NativeIdentityError::InvalidConnectionFacts);
        }
        let process = process_credentials(pid as u32)?;
        if process.effective_uid != effective_uid || process.pid != pid as u32 {
            return Err(NativeIdentityError::InvalidConnectionFacts);
        }
        Ok(NativeConnectionFacts {
            pid: pid as u32,
            effective_uid,
            real_uid: process.real_uid,
            audit_session_id,
            start_time_ns: process.start_time_ns,
        })
    }

    pub fn authenticated_app_caller(&self) -> Result<Caller, NativeIdentityError> {
        let facts = self.facts()?;
        authenticate_app_facts(self.role, &self.team_id, &self.signing_identifier, facts)
    }

    /// Re-resolve the authenticated connection PID through public
    /// Security.framework APIs and return the exact executable path only when
    /// the process start time and code requirement remain stable.
    pub fn verified_app_executable(&self) -> Result<PathBuf, NativeIdentityError> {
        if self.role != PeerRole::UserApp {
            return Err(NativeIdentityError::InvalidConnectionFacts);
        }
        let facts = self.facts()?;
        verified_guest_executable(facts.pid, facts.start_time_ns, &self.code_requirement)
    }

    #[cfg(feature = "macos-development-bootstrap")]
    pub fn bootstrap_caller_for_cdhash(
        &self,
        requested_cdhash: &str,
    ) -> Result<BootstrapCaller, NativeIdentityError> {
        if self.role != PeerRole::UserApp
            || !valid_cdhash(requested_cdhash)
            || (!self.allowed_cdhashes.is_empty()
                && !self.allowed_cdhashes.contains(requested_cdhash))
        {
            return Err(NativeIdentityError::RequirementRejected);
        }
        let facts = self.facts()?;
        Ok(BootstrapCaller {
            pid: facts.pid,
            uid: facts.effective_uid,
            audit_session_id: facts.audit_session_id,
            team_id: self.team_id.clone(),
            cdhash: requested_cdhash.into(),
        })
    }

    pub fn verify_root_helper(&self) -> Result<(), NativeIdentityError> {
        let facts = self.facts()?;
        verify_helper_facts(self.role, facts)
    }
}

/// Cancel a borrowed listener event only when it is an XPC connection.
///
/// # Safety
///
/// `object` must be a live libxpc object for the duration of this call.
pub unsafe fn cancel_borrowed_connection(object: NonNull<c_void>) -> bool {
    let object_type = unsafe { xpc_get_type(object.as_ptr()) };
    let connection_type = std::ptr::addr_of!(_xpc_type_connection).cast();
    if object_type == connection_type {
        unsafe { xpc_connection_cancel(object.as_ptr()) };
        true
    } else {
        false
    }
}

fn classify_incoming_event(event: NonNull<c_void>) -> XpcIncomingEvent {
    let event_type = unsafe { xpc_get_type(event.as_ptr()) };
    let dictionary_type = std::ptr::addr_of!(_xpc_type_dictionary).cast();
    let error_type = std::ptr::addr_of!(_xpc_type_error).cast();
    if event_type == dictionary_type {
        match unsafe { XpcFrameEnvelope::retain_received(event) } {
            Ok(envelope) => XpcIncomingEvent::Message(envelope),
            Err(_) => XpcIncomingEvent::Invalid,
        }
    } else if event_type == error_type {
        XpcIncomingEvent::ConnectionError
    } else {
        XpcIncomingEvent::Invalid
    }
}

impl Drop for RequirementBoundConnection {
    fn drop(&mut self) {
        if self.active && !self.cancelled {
            self.cancel();
        }
        unsafe { (self.functions.release)(self.connection.as_ptr()) };
    }
}

impl crate::xpc_listener::XpcReplyIo for RequirementBoundConnection {
    fn send(&mut self, response: &XpcFrameEnvelope) -> Result<(), HostError> {
        RequirementBoundConnection::send(self, response)
    }

    fn cancel(&mut self) {
        RequirementBoundConnection::cancel(self);
    }
}

// The pointer is an opaque libxpc object. This wrapper owns one retain, libxpc
// connection objects are concurrency-safe, and the copied block captures only
// an Arc callback whose contract is Send + Sync.
unsafe impl Send for RequirementBoundConnection {}
unsafe impl Sync for RequirementBoundConnection {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeConnectionFacts {
    pub pid: u32,
    pub effective_uid: u32,
    pub real_uid: u32,
    pub audit_session_id: u32,
    pub start_time_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessCredentials {
    pub pid: u32,
    pub effective_uid: u32,
    pub real_uid: u32,
    pub effective_gid: u32,
    pub real_gid: u32,
    pub start_time_ns: u64,
}

fn authenticate_app_facts(
    role: PeerRole,
    team_id: &str,
    signing_identifier: &str,
    facts: NativeConnectionFacts,
) -> Result<Caller, NativeIdentityError> {
    if role != PeerRole::UserApp
        || facts.effective_uid == 0
        || facts.effective_uid != facts.real_uid
        || facts.audit_session_id == 0
    {
        return Err(NativeIdentityError::InvalidConnectionFacts);
    }
    Ok(Caller {
        principal_id: format!(
            "macos:{}:{team_id}:{signing_identifier}",
            facts.effective_uid
        ),
        session_id: facts.audit_session_id,
        is_admin: false,
    })
}

fn verify_helper_facts(
    role: PeerRole,
    facts: NativeConnectionFacts,
) -> Result<(), NativeIdentityError> {
    if role == PeerRole::RootHelper
        && facts.effective_uid == 0
        && facts.real_uid == 0
        && facts.audit_session_id != 0
    {
        Ok(())
    } else {
        Err(NativeIdentityError::InvalidConnectionFacts)
    }
}

pub fn process_credentials(pid: u32) -> Result<ProcessCredentials, NativeIdentityError> {
    if pid <= 1 || pid > i32::MAX as u32 {
        return Err(NativeIdentityError::ProcessUnavailable);
    }
    let mut info = MaybeUninit::<ProcBsdInfo>::zeroed();
    let expected = size_of::<ProcBsdInfo>();
    let received = unsafe {
        proc_pidinfo(
            pid as c_int,
            PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            expected as c_int,
        )
    };
    if received != expected as c_int {
        return Err(NativeIdentityError::ProcessUnavailable);
    }
    let info = unsafe { info.assume_init() };
    let start_time_ns = info
        .pbi_start_tvsec
        .checked_mul(1_000_000_000)
        .and_then(|seconds| {
            info.pbi_start_tvusec
                .checked_mul(1_000)
                .and_then(|micros| seconds.checked_add(micros))
        })
        .ok_or(NativeIdentityError::InvalidConnectionFacts)?;
    if info.pbi_pid != pid || start_time_ns == 0 {
        return Err(NativeIdentityError::InvalidConnectionFacts);
    }
    Ok(ProcessCredentials {
        pid,
        effective_uid: info.pbi_uid,
        real_uid: info.pbi_ruid,
        effective_gid: info.pbi_gid,
        real_gid: info.pbi_rgid,
        start_time_ns,
    })
}

pub fn process_identity(pid: u32) -> Result<ProcessIdentity, NativeIdentityError> {
    let before = process_credentials(pid)?;
    let mut path = [0_i8; PROC_PIDPATHINFO_MAXSIZE];
    let length = unsafe { proc_pidpath(pid as c_int, path.as_mut_ptr().cast(), path.len() as u32) };
    if length <= 0 || length as usize >= path.len() {
        return Err(NativeIdentityError::ProcessUnavailable);
    }
    let path = unsafe { CStr::from_ptr(path.as_ptr()) };
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(NativeIdentityError::ProcessUnavailable);
    }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let metadata_before = file
        .metadata()
        .map_err(|_| NativeIdentityError::ProcessUnavailable)?;
    if !metadata_before.file_type().is_file()
        || metadata_before.len() == 0
        || metadata_before.len() > MAX_EXECUTABLE_BYTES
        || metadata_before.ino() == 0
    {
        return Err(NativeIdentityError::ProcessUnavailable);
    }

    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| NativeIdentityError::ProcessUnavailable)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(NativeIdentityError::ProcessUnavailable)?;
        if total > MAX_EXECUTABLE_BYTES {
            return Err(NativeIdentityError::ProcessUnavailable);
        }
        hasher.update(&buffer[..read]);
    }
    let metadata_after = file
        .metadata()
        .map_err(|_| NativeIdentityError::ProcessUnavailable)?;
    let after = process_credentials(pid)?;
    if before != after
        || total != metadata_before.len()
        || metadata_before.dev() != metadata_after.dev()
        || metadata_before.ino() != metadata_after.ino()
        || metadata_before.len() != metadata_after.len()
    {
        return Err(NativeIdentityError::ProcessUnavailable);
    }

    Ok(ProcessIdentity {
        pid,
        start_time_ns: before.start_time_ns,
        executable_file_id: metadata_before.ino(),
        executable_sha256: format!("{:x}", hasher.finalize()),
    })
}

pub fn verified_guest_executable(
    pid: u32,
    expected_start_time_ns: u64,
    requirement: &str,
) -> Result<PathBuf, NativeIdentityError> {
    let before = process_credentials(pid)?;
    if before.start_time_ns != expected_start_time_ns {
        return Err(NativeIdentityError::InvalidConnectionFacts);
    }
    #[cfg(feature = "macos-development-bootstrap")]
    {
        // Keep requirement syntax validation in the internal path so malformed
        // policy material still fails closed; only the Monterey ad-hoc
        // SecCode validity check is relaxed below.
        validate_requirement_text(requirement)?;
        #[cfg(target_os = "macos")]
        let _requirement: SecRequirement = requirement
            .parse()
            .map_err(|_| NativeIdentityError::InvalidRequirement)?;
        // Monterey's root launchd context can reject a Security.framework
        // guest requirement check for an ad-hoc WebView host even though the
        // XPC connection has already enforced the same identifier-only peer
        // requirement. Keep the PID/start-time and executable-path checks,
        // while leaving the strict SecCode validation to the production path.
        let process_path = process_executable_path(pid)?;
        let after = process_credentials(pid)?;
        if before != after {
            return Err(NativeIdentityError::InvalidConnectionFacts);
        }
        Ok(process_path)
    }
    #[cfg(not(feature = "macos-development-bootstrap"))]
    {
        let requirement: SecRequirement = requirement
            .parse()
            .map_err(|_| NativeIdentityError::InvalidRequirement)?;
        let mut attributes = GuestAttributes::new();
        attributes.set_pid(pid as libc::pid_t);
        let code =
            SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE).map_err(|_| {
                #[cfg(feature = "macos-development-bootstrap")]
                crate::xpc_listener::debug_log("verified-guest-copy-failed");
                NativeIdentityError::RequirementRejected
            })?;
        #[cfg(feature = "macos-development-bootstrap")]
        let flags = Flags::CHECK_ALL_ARCHITECTURES | Flags::NO_NETWORK_ACCESS;
        #[cfg(not(feature = "macos-development-bootstrap"))]
        let flags = Flags::CHECK_ALL_ARCHITECTURES
            | Flags::CHECK_NESTED_CODE
            | Flags::STRICT_VALIDATE
            | Flags::NO_NETWORK_ACCESS;
        code.check_validity(flags, &requirement).map_err(|_| {
            #[cfg(feature = "macos-development-bootstrap")]
            crate::xpc_listener::debug_log("verified-guest-requirement-failed");
            NativeIdentityError::RequirementRejected
        })?;
        let signed_path = code
            .path(Flags::NONE)
            .map_err(|_| NativeIdentityError::ProcessUnavailable)?
            .to_path()
            .ok_or(NativeIdentityError::ProcessUnavailable)?;
        let process_path = process_executable_path(pid)?;
        let after = process_credentials(pid)?;
        if before != after || signed_path != process_path {
            return Err(NativeIdentityError::InvalidConnectionFacts);
        }
        Ok(signed_path)
    }
}

#[cfg(feature = "macos-development-bootstrap")]
fn validate_requirement_text(requirement: &str) -> Result<(), NativeIdentityError> {
    if requirement.is_empty()
        || requirement.len() > 4096
        || requirement.bytes().any(|byte| byte.is_ascii_control())
        || !requirement.matches('"').count().is_multiple_of(2)
        || requirement.matches('(').count() != requirement.matches(')').count()
    {
        return Err(NativeIdentityError::InvalidRequirement);
    }
    Ok(())
}

pub(crate) fn process_executable_path(pid: u32) -> Result<PathBuf, NativeIdentityError> {
    if pid <= 1 || pid > i32::MAX as u32 {
        return Err(NativeIdentityError::ProcessUnavailable);
    }
    let mut buffer = [0_i8; PROC_PIDPATHINFO_MAXSIZE];
    let length = unsafe {
        proc_pidpath(
            pid as c_int,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
        )
    };
    if length <= 0 || length as usize >= buffer.len() {
        return Err(NativeIdentityError::ProcessUnavailable);
    }
    let path = unsafe { CStr::from_ptr(buffer.as_ptr()) };
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(path.to_bytes())))
}

pub fn process_executable_leaf(pid: u32) -> Result<String, NativeIdentityError> {
    let path = process_executable_path(pid)?;
    let leaf = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(NativeIdentityError::ProcessUnavailable)?;
    if leaf.is_empty()
        || leaf.len() > 128
        || matches!(leaf, "." | "..")
        || leaf
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'/' | b'\\' | b','))
    {
        return Err(NativeIdentityError::ProcessUnavailable);
    }
    Ok(leaf.into())
}

pub fn interface_snapshot() -> Result<InterfaceSnapshot, NativeIdentityError> {
    let mut head = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 || head.is_null() {
        return Err(NativeIdentityError::ProcessUnavailable);
    }
    struct Guard(*mut libc::ifaddrs);
    impl Drop for Guard {
        fn drop(&mut self) {
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let _guard = Guard(head);
    let mut interfaces = BTreeMap::<(u32, String), DarwinInterface>::new();
    let mut cursor = head;
    while !cursor.is_null() {
        let address = unsafe { &*cursor };
        if address.ifa_name.is_null() {
            return Err(NativeIdentityError::ProcessUnavailable);
        }
        let name = unsafe { CStr::from_ptr(address.ifa_name) }
            .to_str()
            .map_err(|_| NativeIdentityError::ProcessUnavailable)?;
        if name.is_empty()
            || name.len() >= libc::IFNAMSIZ
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(NativeIdentityError::ProcessUnavailable);
        }
        let index = unsafe { libc::if_nametoindex(address.ifa_name) };
        if index == 0 {
            return Err(NativeIdentityError::ProcessUnavailable);
        }
        interfaces
            .entry((index, name.into()))
            .or_insert_with(|| DarwinInterface {
                name: name.into(),
                index,
                // getifaddrs proves inventory only; it provides no process
                // ownership evidence for a utun interface.
                owner_pid: None,
            });
        if interfaces.len() > MAX_INTERFACES {
            return Err(NativeIdentityError::ProcessUnavailable);
        }
        cursor = address.ifa_next;
    }
    Ok(InterfaceSnapshot {
        complete: true,
        interfaces: interfaces.into_values().collect(),
    })
}

pub fn read_route_dump2() -> Result<Vec<u8>, NativeRouteError> {
    const CTL_NET: c_int = 4;
    const PF_ROUTE: c_int = 17;
    const NET_RT_DUMP2: c_int = 7;
    let mut mib = [CTL_NET, PF_ROUTE, 0, 0, NET_RT_DUMP2, 0];
    for _ in 0..ROUTE_DUMP_RETRIES {
        let mut required = 0_usize;
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                std::ptr::null_mut(),
                &mut required,
                std::ptr::null_mut(),
                0,
            )
        } != 0
        {
            return Err(NativeRouteError::Unavailable);
        }
        if required == 0 {
            return Err(NativeRouteError::Unavailable);
        }
        if required > MAX_ROUTE_DUMP_BYTES {
            return Err(NativeRouteError::Oversize);
        }
        let mut bytes = vec![0_u8; required];
        let mut actual = bytes.len();
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                bytes.as_mut_ptr().cast(),
                &mut actual,
                std::ptr::null_mut(),
                0,
            )
        } == 0
        {
            if actual == 0 || actual > bytes.len() {
                return Err(NativeRouteError::Unavailable);
            }
            bytes.truncate(actual);
            return Ok(bytes);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOMEM) {
            return Err(NativeRouteError::Unavailable);
        }
    }
    Err(NativeRouteError::Unavailable)
}

pub fn native_route_snapshot() -> Result<RouteSnapshot, NativeRouteError> {
    let bytes = read_route_dump2()?;
    decode_route_messages(&bytes).map_err(NativeRouteError::Decode)
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemSecretSource;

impl SecretSource for SystemSecretSource {
    fn next_32(&mut self) -> Result<[u8; 32], HostError> {
        let mut bytes = [0_u8; 32];
        if unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) } == 0 {
            Ok(bytes)
        } else {
            Err(HostError::BackendUnavailable)
        }
    }
}

#[derive(Debug)]
pub struct XpcFrameEnvelope {
    object: NonNull<c_void>,
}

impl XpcFrameEnvelope {
    pub fn from_frame(frame: &[u8]) -> Result<Self, HostError> {
        validate_frame_shape(frame)?;
        let object = unsafe { xpc_dictionary_create(std::ptr::null(), std::ptr::null(), 0) };
        let object = NonNull::new(object).ok_or(HostError::BackendUnavailable)?;
        unsafe {
            xpc_dictionary_set_data(
                object.as_ptr(),
                FRAME_KEY.as_ptr().cast(),
                frame.as_ptr().cast(),
                frame.len(),
            );
        }
        Ok(Self { object })
    }

    /// Retain and validate one dictionary received from a live XPC event
    /// handler. The resulting envelope owns exactly one retain.
    ///
    /// # Safety
    ///
    /// `object` must be a live libxpc object for the duration of this call.
    pub unsafe fn retain_received(object: NonNull<c_void>) -> Result<Self, HostError> {
        let object_type = unsafe { xpc_get_type(object.as_ptr()) };
        let dictionary_type = std::ptr::addr_of!(_xpc_type_dictionary).cast();
        if object_type != dictionary_type
            || unsafe { xpc_dictionary_get_count(object.as_ptr()) } != 1
        {
            return Err(HostError::InvalidInput);
        }
        let retained = unsafe { xpc_retain(object.as_ptr()) };
        let retained = NonNull::new(retained).ok_or(HostError::BackendUnavailable)?;
        let envelope = Self { object: retained };
        if envelope.to_frame().is_err() {
            return Err(HostError::InvalidInput);
        }
        Ok(envelope)
    }

    pub fn to_frame(&self) -> Result<Vec<u8>, HostError> {
        if unsafe { xpc_dictionary_get_count(self.object.as_ptr()) } != 1 {
            return Err(HostError::InvalidInput);
        }
        let mut length = 0_usize;
        let bytes = unsafe {
            xpc_dictionary_get_data(self.object.as_ptr(), FRAME_KEY.as_ptr().cast(), &mut length)
        };
        if bytes.is_null() || length == 0 || length > MAX_FRAME_BYTES + PREFIX_BYTES {
            return Err(HostError::InvalidInput);
        }
        let frame = unsafe { std::slice::from_raw_parts(bytes.cast::<u8>(), length) }.to_vec();
        validate_frame_shape(&frame)?;
        Ok(frame)
    }

    pub(crate) fn as_ptr(&self) -> *mut c_void {
        self.object.as_ptr()
    }
}

pub(crate) unsafe fn received_frame(object: NonNull<c_void>) -> Result<Vec<u8>, HostError> {
    unsafe { XpcFrameEnvelope::retain_received(object) }?.to_frame()
}

pub(crate) fn verify_root_connection(
    connection: NonNull<c_void>,
) -> Result<(), NativeIdentityError> {
    let pid = unsafe { xpc_connection_get_pid(connection.as_ptr()) };
    let effective_uid = unsafe { xpc_connection_get_euid(connection.as_ptr()) };
    let audit_session_id = unsafe { xpc_connection_get_asid(connection.as_ptr()) };
    if pid <= 1 || effective_uid != 0 || audit_session_id == 0 {
        return Err(NativeIdentityError::InvalidConnectionFacts);
    }
    match process_credentials(pid as u32) {
        Ok(process) if process.effective_uid == 0 && process.real_uid == 0 => Ok(()),
        // Monterey denies a user process' proc_pidinfo lookup for a root
        // launchd helper even though libxpc already supplied the peer's
        // kernel-verified uid and audit session. The client connection also
        // installs the helper's exact code-signing requirement before
        // activation, so those XPC facts are the authoritative fallback.
        Err(NativeIdentityError::ProcessUnavailable) => Ok(()),
        _ => Err(NativeIdentityError::InvalidConnectionFacts),
    }
}

impl Drop for XpcFrameEnvelope {
    fn drop(&mut self) {
        unsafe { xpc_release(self.object.as_ptr()) };
    }
}

// XPC objects are documented as concurrency-safe. This wrapper owns one retain
// and exposes only copying reads.
unsafe impl Send for XpcFrameEnvelope {}
unsafe impl Sync for XpcFrameEnvelope {}

fn validate_frame_shape(frame: &[u8]) -> Result<(), HostError> {
    let prefix: [u8; PREFIX_BYTES] = frame
        .get(..PREFIX_BYTES)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(HostError::InvalidInput)?;
    let payload_length = u32::from_le_bytes(prefix) as usize;
    if payload_length > MAX_FRAME_BYTES || frame.len() != PREFIX_BYTES + payload_length {
        Err(HostError::InvalidInput)
    } else {
        Ok(())
    }
}

pub fn helper_scaffold_main() -> Result<(), HostError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(HostError::InvalidInput);
    }
    // M3E intentionally has no production LifecycleBackend and does not open
    // the Mach service. The binary becomes runnable only after the M3 effect
    // backend and installer gates are satisfied.
    Err(HostError::BackendUnavailable)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn valid_cdhash(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[repr(C)]
struct ProcBsdInfo {
    pbi_flags: u32,
    pbi_status: u32,
    pbi_xstatus: u32,
    pbi_pid: u32,
    pbi_ppid: u32,
    pbi_uid: u32,
    pbi_gid: u32,
    pbi_ruid: u32,
    pbi_rgid: u32,
    pbi_svuid: u32,
    pbi_svgid: u32,
    rfu_1: u32,
    pbi_comm: [c_char; MAXCOMLEN],
    pbi_name: [c_char; MAXCOMLEN * 2],
    pbi_nfiles: u32,
    pbi_pgid: u32,
    pbi_pjobc: u32,
    e_tdev: u32,
    e_tpgid: u32,
    pbi_nice: i32,
    pbi_start_tvsec: u64,
    pbi_start_tvusec: u64,
}

unsafe extern "C" {
    static _xpc_type_dictionary: c_void;
    static _xpc_type_connection: c_void;
    static _xpc_type_error: c_void;
    fn xpc_connection_set_peer_code_signing_requirement(
        connection: *mut c_void,
        requirement: *const c_char,
    ) -> c_int;
    fn xpc_connection_get_pid(connection: *mut c_void) -> c_int;
    fn xpc_connection_get_euid(connection: *mut c_void) -> u32;
    fn xpc_connection_get_asid(connection: *mut c_void) -> u32;
    fn xpc_connection_activate(connection: *mut c_void);
    fn xpc_connection_cancel(connection: *mut c_void);
    fn xpc_connection_send_message(connection: *mut c_void, message: *mut c_void);
    fn xpc_connection_set_event_handler(connection: *mut c_void, handler: *mut c_void);
    fn xpc_dictionary_create(
        keys: *const *const c_char,
        values: *const *mut c_void,
        count: usize,
    ) -> *mut c_void;
    fn xpc_dictionary_create_reply(original: *mut c_void) -> *mut c_void;
    fn xpc_dictionary_set_data(
        dictionary: *mut c_void,
        key: *const c_char,
        bytes: *const c_void,
        length: usize,
    );
    fn xpc_dictionary_get_data(
        dictionary: *mut c_void,
        key: *const c_char,
        length: *mut usize,
    ) -> *const c_void;
    fn xpc_dictionary_get_count(dictionary: *mut c_void) -> usize;
    fn xpc_get_type(object: *mut c_void) -> *const c_void;
    fn xpc_retain(object: *mut c_void) -> *mut c_void;
    fn xpc_release(object: *mut c_void);
    #[cfg(test)]
    fn xpc_string_create(value: *const c_char) -> *mut c_void;
}

unsafe extern "C" {
    fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        arg: u64,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
    fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffer_size: u32) -> c_int;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::BTreeSet,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Mutex,
        },
    };
    use tunbridge_service::{frame, protocol::Hello};

    fn hashes(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    static TEST_RETAINS: AtomicUsize = AtomicUsize::new(0);
    static TEST_RELEASES: AtomicUsize = AtomicUsize::new(0);
    static TEST_ACTIVATES: AtomicUsize = AtomicUsize::new(0);
    static TEST_CANCELS: AtomicUsize = AtomicUsize::new(0);
    static TEST_SENDS: AtomicUsize = AtomicUsize::new(0);
    static TEST_HANDLERS: AtomicUsize = AtomicUsize::new(0);
    static TEST_BIND_LOCK: Mutex<()> = Mutex::new(());
    static TEST_CONNECTION_EVENTS: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());

    unsafe extern "C" fn accept_requirement(
        _connection: *mut c_void,
        _requirement: *const c_char,
    ) -> c_int {
        0
    }

    unsafe extern "C" fn reject_requirement(
        _connection: *mut c_void,
        _requirement: *const c_char,
    ) -> c_int {
        1
    }

    unsafe extern "C" fn test_retain(connection: *mut c_void) -> *mut c_void {
        TEST_RETAINS.fetch_add(1, Ordering::SeqCst);
        TEST_CONNECTION_EVENTS.lock().unwrap().push("retain");
        connection
    }

    unsafe extern "C" fn test_release(_connection: *mut c_void) {
        TEST_RELEASES.fetch_add(1, Ordering::SeqCst);
        TEST_CONNECTION_EVENTS.lock().unwrap().push("release");
    }

    unsafe extern "C" fn test_activate(_connection: *mut c_void) {
        TEST_ACTIVATES.fetch_add(1, Ordering::SeqCst);
        TEST_CONNECTION_EVENTS.lock().unwrap().push("activate");
    }

    unsafe extern "C" fn test_cancel(_connection: *mut c_void) {
        TEST_CANCELS.fetch_add(1, Ordering::SeqCst);
        TEST_CONNECTION_EVENTS.lock().unwrap().push("cancel");
    }

    unsafe extern "C" fn test_send(_connection: *mut c_void, _message: *mut c_void) {
        TEST_SENDS.fetch_add(1, Ordering::SeqCst);
        TEST_CONNECTION_EVENTS.lock().unwrap().push("send");
    }

    unsafe extern "C" fn test_set_event_handler(_connection: *mut c_void, _handler: *mut c_void) {
        TEST_HANDLERS.fetch_add(1, Ordering::SeqCst);
        TEST_CONNECTION_EVENTS.lock().unwrap().push("handler");
    }

    fn test_connection_functions() -> XpcConnectionFunctions {
        XpcConnectionFunctions {
            retain: test_retain,
            release: test_release,
            activate: test_activate,
            cancel: test_cancel,
            send: test_send,
            set_event_handler: test_set_event_handler,
        }
    }

    fn reset_connection_counters() {
        TEST_RETAINS.store(0, Ordering::SeqCst);
        TEST_RELEASES.store(0, Ordering::SeqCst);
        TEST_ACTIVATES.store(0, Ordering::SeqCst);
        TEST_CANCELS.store(0, Ordering::SeqCst);
        TEST_SENDS.store(0, Ordering::SeqCst);
        TEST_HANDLERS.store(0, Ordering::SeqCst);
        TEST_CONNECTION_EVENTS.lock().unwrap().clear();
    }

    #[test]
    fn requirement_is_exact_deterministic_and_monterey_compatible() {
        let policy = AppRequirementPolicy {
            team_id: "ABCDE12345".into(),
            signing_identifier: "com.tunbridge.desktop".into(),
            allowed_cdhashes: hashes(&[
                "1111111111111111111111111111111111111111",
                "2222222222222222222222222222222222222222",
            ]),
        };
        assert_eq!(
            XpcCodeRequirement::for_app(&policy).unwrap().as_str(),
            "anchor apple generic and identifier \"com.tunbridge.desktop\" \
             and certificate leaf[subject.OU] = \"ABCDE12345\" \
             and flags runtime and (cdhash H\"1111111111111111111111111111111111111111\" \
             or cdhash H\"2222222222222222222222222222222222222222\")"
        );
    }

    #[test]
    fn requirement_bound_connection_owns_exactly_one_successful_retain() {
        let _guard = TEST_BIND_LOCK.lock().unwrap();
        reset_connection_counters();
        let policy = AppRequirementPolicy {
            team_id: "ABCDE12345".into(),
            signing_identifier: "com.tunbridge.desktop".into(),
            allowed_cdhashes: hashes(&["1111111111111111111111111111111111111111"]),
        };
        let requirement = XpcCodeRequirement::for_app(&policy).unwrap();
        let pointer = NonNull::<c_void>::dangling();
        let bound = unsafe {
            RequirementBoundConnection::bind_with_functions(
                pointer,
                &requirement,
                accept_requirement,
                test_connection_functions(),
            )
        }
        .unwrap();
        assert_eq!(TEST_RETAINS.load(Ordering::SeqCst), 1);
        assert_eq!(TEST_RELEASES.load(Ordering::SeqCst), 0);
        drop(bound);
        assert_eq!(TEST_RELEASES.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn rejected_requirement_never_retains_or_releases_connection() {
        let _guard = TEST_BIND_LOCK.lock().unwrap();
        reset_connection_counters();
        let policy = AppRequirementPolicy {
            team_id: "ABCDE12345".into(),
            signing_identifier: "com.tunbridge.desktop".into(),
            allowed_cdhashes: hashes(&["1111111111111111111111111111111111111111"]),
        };
        let requirement = XpcCodeRequirement::for_app(&policy).unwrap();
        assert!(matches!(
            unsafe {
                RequirementBoundConnection::bind_with_functions(
                    NonNull::<c_void>::dangling(),
                    &requirement,
                    reject_requirement,
                    test_connection_functions(),
                )
            },
            Err(NativeIdentityError::RequirementRejected)
        ));
        assert_eq!(TEST_RETAINS.load(Ordering::SeqCst), 0);
        assert_eq!(TEST_RELEASES.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn connection_control_is_activate_once_send_active_only_and_cancel_idempotent() {
        let _guard = TEST_BIND_LOCK.lock().unwrap();
        reset_connection_counters();
        let policy = AppRequirementPolicy {
            team_id: "ABCDE12345".into(),
            signing_identifier: "com.tunbridge.desktop".into(),
            allowed_cdhashes: hashes(&["1111111111111111111111111111111111111111"]),
        };
        let requirement = XpcCodeRequirement::for_app(&policy).unwrap();
        let mut bound = unsafe {
            RequirementBoundConnection::bind_with_functions(
                NonNull::<c_void>::dangling(),
                &requirement,
                accept_requirement,
                test_connection_functions(),
            )
        }
        .unwrap();
        let envelope =
            XpcFrameEnvelope::from_frame(&frame::encode(&Hello::new("0.2.3")).unwrap()).unwrap();

        assert_eq!(bound.send(&envelope), Err(HostError::InvalidInput));
        assert_eq!(
            bound.activate_after_event_handler(),
            Err(HostError::InvalidInput)
        );
        bound.install_event_handler(Arc::new(|_event| {})).unwrap();
        bound.activate_after_event_handler().unwrap();
        assert_eq!(
            bound.activate_after_event_handler(),
            Err(HostError::InvalidInput)
        );
        bound.send(&envelope).unwrap();
        bound.cancel();
        bound.cancel();
        assert_eq!(bound.send(&envelope), Err(HostError::InvalidInput));
        drop(bound);

        assert_eq!(TEST_ACTIVATES.load(Ordering::SeqCst), 1);
        assert_eq!(TEST_SENDS.load(Ordering::SeqCst), 1);
        assert_eq!(TEST_CANCELS.load(Ordering::SeqCst), 1);
        assert_eq!(TEST_RELEASES.load(Ordering::SeqCst), 1);
        assert_eq!(
            *TEST_CONNECTION_EVENTS.lock().unwrap(),
            ["retain", "handler", "activate", "send", "cancel", "release"]
        );
    }

    #[test]
    fn active_connection_drop_cancels_before_releasing() {
        let _guard = TEST_BIND_LOCK.lock().unwrap();
        reset_connection_counters();
        let policy = AppRequirementPolicy {
            team_id: "ABCDE12345".into(),
            signing_identifier: "com.tunbridge.desktop".into(),
            allowed_cdhashes: hashes(&["1111111111111111111111111111111111111111"]),
        };
        let requirement = XpcCodeRequirement::for_app(&policy).unwrap();
        let mut bound = unsafe {
            RequirementBoundConnection::bind_with_functions(
                NonNull::<c_void>::dangling(),
                &requirement,
                accept_requirement,
                test_connection_functions(),
            )
        }
        .unwrap();
        bound.install_event_handler(Arc::new(|_event| {})).unwrap();
        bound.activate_after_event_handler().unwrap();
        drop(bound);
        assert_eq!(TEST_CANCELS.load(Ordering::SeqCst), 1);
        assert_eq!(TEST_RELEASES.load(Ordering::SeqCst), 1);
        assert_eq!(
            *TEST_CONNECTION_EVENTS.lock().unwrap(),
            ["retain", "handler", "activate", "cancel", "release"]
        );
    }

    #[test]
    fn event_handler_is_installed_once_and_ignores_null_events() {
        let _guard = TEST_BIND_LOCK.lock().unwrap();
        reset_connection_counters();
        let policy = AppRequirementPolicy {
            team_id: "ABCDE12345".into(),
            signing_identifier: "com.tunbridge.desktop".into(),
            allowed_cdhashes: hashes(&["1111111111111111111111111111111111111111"]),
        };
        let requirement = XpcCodeRequirement::for_app(&policy).unwrap();
        let mut bound = unsafe {
            RequirementBoundConnection::bind_with_functions(
                NonNull::<c_void>::dangling(),
                &requirement,
                accept_requirement,
                test_connection_functions(),
            )
        }
        .unwrap();
        let messages = Arc::new(AtomicUsize::new(0));
        let invalid = Arc::new(AtomicUsize::new(0));
        let captured_messages = Arc::clone(&messages);
        let captured_invalid = Arc::clone(&invalid);
        let frame = frame::encode(&Hello::new("0.2.3")).unwrap();
        let expected_frame = frame.clone();
        bound
            .install_event_handler(Arc::new(move |event| match event {
                XpcIncomingEvent::Message(envelope) => {
                    assert_eq!(envelope.to_frame().unwrap(), expected_frame);
                    captured_messages.fetch_add(1, Ordering::SeqCst);
                }
                XpcIncomingEvent::Invalid => {
                    captured_invalid.fetch_add(1, Ordering::SeqCst);
                }
                XpcIncomingEvent::ConnectionError => {
                    panic!("test did not supply an XPC error event");
                }
            }))
            .unwrap();
        assert_eq!(
            bound.install_event_handler(Arc::new(|_event| {})),
            Err(HostError::InvalidInput)
        );
        let handler = bound.event_handler.as_ref().unwrap();
        handler.call((std::ptr::null_mut(),));
        let source = XpcFrameEnvelope::from_frame(&frame).unwrap();
        handler.call((source.object.as_ptr(),));
        let value = CString::new("not-a-message").unwrap();
        let string = NonNull::new(unsafe { xpc_string_create(value.as_ptr()) }).unwrap();
        handler.call((string.as_ptr(),));
        unsafe { xpc_release(string.as_ptr()) };
        assert_eq!(messages.load(Ordering::SeqCst), 1);
        assert_eq!(invalid.load(Ordering::SeqCst), 1);
        assert_eq!(TEST_HANDLERS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn requirement_binding_rejects_non_connection_before_native_bind() {
        let policy = AppRequirementPolicy {
            team_id: "ABCDE12345".into(),
            signing_identifier: "com.tunbridge.desktop".into(),
            allowed_cdhashes: hashes(&["1111111111111111111111111111111111111111"]),
        };
        let requirement = XpcCodeRequirement::for_app(&policy).unwrap();
        let dictionary =
            XpcFrameEnvelope::from_frame(&frame::encode(&Hello::new("0.2.3")).unwrap()).unwrap();
        assert!(matches!(
            unsafe { RequirementBoundConnection::bind(dictionary.object, &requirement) },
            Err(NativeIdentityError::InvalidConnectionFacts)
        ));
        assert!(!unsafe { cancel_borrowed_connection(dictionary.object) });
    }

    #[test]
    fn malformed_requirement_components_fail_before_xpc() {
        let policy = HelperRequirementPolicy {
            team_id: "ABCDE12345".into(),
            signing_identifier: "com.tunbridge.desktop.helper\" or true".into(),
            allowed_cdhashes: hashes(&["1111111111111111111111111111111111111111"]),
        };
        assert_eq!(
            XpcCodeRequirement::for_helper(&policy),
            Err(NativeIdentityError::InvalidRequirement)
        );
    }

    #[test]
    fn current_process_credentials_are_read_only_and_self_consistent() {
        let credentials = process_credentials(std::process::id()).unwrap();
        assert_eq!(credentials.pid, std::process::id());
        assert_eq!(credentials.effective_uid, unsafe { libc::geteuid() });
        assert_eq!(credentials.real_uid, unsafe { libc::getuid() });
        assert!(credentials.start_time_ns > 0);
    }

    #[test]
    fn public_guest_lookup_rejects_stale_process_generation_before_code_query() {
        let credentials = process_credentials(std::process::id()).unwrap();
        assert_eq!(
            verified_guest_executable(
                credentials.pid,
                credentials.start_time_ns.saturating_add(1),
                "anchor apple generic"
            ),
            Err(NativeIdentityError::InvalidConnectionFacts)
        );
    }

    #[test]
    fn public_guest_lookup_rejects_invalid_requirement_text() {
        let credentials = process_credentials(std::process::id()).unwrap();
        assert_eq!(
            verified_guest_executable(
                credentials.pid,
                credentials.start_time_ns,
                "not a valid code requirement ("
            ),
            Err(NativeIdentityError::InvalidRequirement)
        );
    }

    #[test]
    fn current_process_file_identity_is_stable_and_bounded() {
        let first = process_identity(std::process::id()).unwrap();
        let second = process_identity(std::process::id()).unwrap();
        let leaf = process_executable_leaf(std::process::id()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.pid, std::process::id());
        assert!(first.start_time_ns > 0);
        assert!(first.executable_file_id > 0);
        assert_eq!(first.executable_sha256.len(), 64);
        assert!(first
            .executable_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')));
        assert!(!leaf.is_empty());
        assert!(leaf.len() <= 128);
        assert!(!leaf
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'/' | b'\\' | b',')));
    }

    #[test]
    fn native_interface_inventory_is_read_only_and_never_invents_owner_pid() {
        let snapshot = interface_snapshot().unwrap();
        assert!(snapshot.complete);
        assert!(!snapshot.interfaces.is_empty());
        assert!(snapshot
            .interfaces
            .iter()
            .all(|interface| interface.index > 0 && interface.owner_pid.is_none()));
        assert!(snapshot
            .interfaces
            .iter()
            .any(|interface| interface.name == "lo0"));
    }

    #[test]
    fn native_route_dump_read_is_bounded_and_read_only() {
        let bytes = read_route_dump2().unwrap();
        assert!(!bytes.is_empty());
        assert!(bytes.len() <= MAX_ROUTE_DUMP_BYTES);
        assert!(u16::from_ne_bytes(bytes[0..2].try_into().unwrap()) as usize <= bytes.len());
    }

    #[test]
    fn native_route_dump_decodes_to_complete_snapshot() {
        let snapshot = native_route_snapshot().unwrap();
        assert!(snapshot.complete);
        assert!(!snapshot.routes.is_empty());
    }

    #[test]
    fn system_secret_source_returns_fresh_nonzero_material() {
        let mut source = SystemSecretSource;
        let first = source.next_32().unwrap();
        let second = source.next_32().unwrap();
        assert_ne!(first, [0; 32]);
        assert_ne!(second, [0; 32]);
        assert_ne!(first, second);
    }

    #[test]
    fn requirement_bound_facts_map_only_to_the_expected_peer_role() {
        let app = NativeConnectionFacts {
            pid: 500,
            effective_uid: 502,
            real_uid: 502,
            audit_session_id: 42,
            start_time_ns: 1,
        };
        let caller = authenticate_app_facts(
            PeerRole::UserApp,
            "ABCDE12345",
            "com.tunbridge.desktop",
            app,
        )
        .unwrap();
        assert_eq!(
            caller.principal_id,
            "macos:502:ABCDE12345:com.tunbridge.desktop"
        );
        assert_eq!(
            authenticate_app_facts(
                PeerRole::RootHelper,
                "ABCDE12345",
                "com.tunbridge.desktop.helper",
                app,
            ),
            Err(NativeIdentityError::InvalidConnectionFacts)
        );

        let root = NativeConnectionFacts {
            effective_uid: 0,
            real_uid: 0,
            ..app
        };
        verify_helper_facts(PeerRole::RootHelper, root).unwrap();
        assert_eq!(
            verify_helper_facts(PeerRole::UserApp, root),
            Err(NativeIdentityError::InvalidConnectionFacts)
        );
    }

    #[test]
    fn native_xpc_dictionary_round_trips_one_bounded_shared_frame() {
        let frame = frame::encode(&Hello::new("0.2.3")).unwrap();
        let envelope = XpcFrameEnvelope::from_frame(&frame).unwrap();
        assert_eq!(envelope.to_frame().unwrap(), frame);
    }

    #[test]
    fn native_xpc_dictionary_rejects_truncated_and_oversized_frames() {
        assert!(matches!(
            XpcFrameEnvelope::from_frame(&[1, 0, 0, 0]),
            Err(HostError::InvalidInput)
        ));
        let mut oversized = ((MAX_FRAME_BYTES + 1) as u32).to_le_bytes().to_vec();
        oversized.resize(MAX_FRAME_BYTES + PREFIX_BYTES + 1, 0);
        assert!(matches!(
            XpcFrameEnvelope::from_frame(&oversized),
            Err(HostError::InvalidInput)
        ));
    }

    #[test]
    fn received_dictionary_is_exactly_retained_and_survives_source_drop() {
        let frame = frame::encode(&Hello::new("0.2.3")).unwrap();
        let source = XpcFrameEnvelope::from_frame(&frame).unwrap();
        let retained = unsafe { XpcFrameEnvelope::retain_received(source.object) }.unwrap();
        drop(source);
        assert_eq!(retained.to_frame().unwrap(), frame);
    }

    #[test]
    fn received_non_dictionary_or_dictionary_with_extra_field_is_rejected() {
        let value = CString::new("not-a-dictionary").unwrap();
        let string = NonNull::new(unsafe { xpc_string_create(value.as_ptr()) }).unwrap();
        assert!(matches!(
            unsafe { XpcFrameEnvelope::retain_received(string) },
            Err(HostError::InvalidInput)
        ));
        unsafe { xpc_release(string.as_ptr()) };

        let frame = frame::encode(&Hello::new("0.2.3")).unwrap();
        let source = XpcFrameEnvelope::from_frame(&frame).unwrap();
        unsafe {
            xpc_dictionary_set_data(
                source.object.as_ptr(),
                EXTRA_TEST_KEY.as_ptr().cast(),
                frame.as_ptr().cast(),
                frame.len(),
            );
        }
        assert!(matches!(
            unsafe { XpcFrameEnvelope::retain_received(source.object) },
            Err(HostError::InvalidInput)
        ));
    }
}
