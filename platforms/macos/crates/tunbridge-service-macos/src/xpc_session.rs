//! Requirement-bound XPC frame/session adapter.
//!
//! This module does not create, resume, or register an XPC listener. It only
//! connects an already requirement-bound peer and bounded dictionary envelope
//! to the shared helper dispatcher.

use crate::{
    dispatcher::{HelperLifecycle, MacosHelperConnection, MacosServiceContext, SecretSource},
    lifecycle_host::HostError,
    native::{RequirementBoundConnection, XpcFrameEnvelope},
};
use std::path::{Path, PathBuf};
use tunbridge_service::state::Caller;
#[cfg(feature = "macos-development-bootstrap")]
use tunbridge_setup_macos::bootstrap_protocol::BootstrapCaller;

pub(crate) trait XpcAppPeer {
    fn authenticated_caller(&self) -> Result<Caller, HostError>;

    fn set_reply_target(&mut self, _request: &XpcFrameEnvelope) -> Result<(), HostError> {
        Ok(())
    }

    #[cfg(feature = "macos-development-bootstrap")]
    fn development_bootstrap_caller(
        &self,
        _requested_cdhash: &str,
    ) -> Result<BootstrapCaller, HostError> {
        Err(HostError::InvalidInput)
    }

    #[cfg(feature = "macos-development-bootstrap")]
    fn verified_app_executable(&self) -> Result<PathBuf, HostError> {
        Err(HostError::InvalidInput)
    }
}

impl XpcAppPeer for RequirementBoundConnection {
    fn authenticated_caller(&self) -> Result<Caller, HostError> {
        self.authenticated_app_caller()
            .map_err(|_| HostError::InvalidInput)
    }

    fn set_reply_target(&mut self, request: &XpcFrameEnvelope) -> Result<(), HostError> {
        RequirementBoundConnection::set_reply_target(self, request);
        Ok(())
    }

    #[cfg(feature = "macos-development-bootstrap")]
    fn development_bootstrap_caller(
        &self,
        requested_cdhash: &str,
    ) -> Result<BootstrapCaller, HostError> {
        self.bootstrap_caller_for_cdhash(requested_cdhash)
            .map_err(|_| HostError::InvalidInput)
    }

    #[cfg(feature = "macos-development-bootstrap")]
    fn verified_app_executable(&self) -> Result<PathBuf, HostError> {
        match self.verified_app_executable() {
            Ok(path) => Ok(path),
            Err(error) => {
                #[cfg(feature = "macos-development-bootstrap")]
                crate::xpc_listener::debug_log(&format!(
                    "verified-app-executable-native-error={error:?}"
                ));
                Err(HostError::InvalidInput)
            }
        }
    }
}

pub struct NativeXpcSession {
    connection: MacosHelperConnection,
}

impl NativeXpcSession {
    pub fn accept(
        peer: &RequirementBoundConnection,
        hello: &XpcFrameEnvelope,
        session_nonce: [u8; 32],
    ) -> Result<(Self, XpcFrameEnvelope), HostError> {
        Self::accept_peer(peer, hello, session_nonce)
    }

    pub(crate) fn accept_peer<P: XpcAppPeer>(
        peer: &P,
        hello: &XpcFrameEnvelope,
        session_nonce: [u8; 32],
    ) -> Result<(Self, XpcFrameEnvelope), HostError> {
        let caller = peer.authenticated_caller()?;
        let hello_frame = hello.to_frame()?;
        let (connection, response) =
            MacosHelperConnection::accept(caller, &hello_frame, lower_hex(&session_nonce))?;
        Ok((
            Self { connection },
            XpcFrameEnvelope::from_frame(&response)?,
        ))
    }

    pub fn handle<L, S>(
        &mut self,
        context: &MacosServiceContext<L, S>,
        request: &XpcFrameEnvelope,
        now_tick: u64,
    ) -> Result<XpcFrameEnvelope, HostError>
    where
        L: HelperLifecycle,
        S: SecretSource,
    {
        let request_frame = request.to_frame()?;
        let response = self.connection.handle(context, &request_frame, now_tick)?;
        XpcFrameEnvelope::from_frame(&response)
    }

    #[cfg(feature = "macos-development-bootstrap")]
    pub(crate) fn handle_with_bootstrap<L, S>(
        &mut self,
        context: &MacosServiceContext<L, S>,
        request: &XpcFrameEnvelope,
        now_tick: u64,
        bootstrap: Option<(&BootstrapCaller, &Path)>,
    ) -> Result<XpcFrameEnvelope, HostError>
    where
        L: HelperLifecycle,
        S: SecretSource,
    {
        let request_frame = request.to_frame()?;
        let response =
            self.connection
                .handle_with_bootstrap(context, &request_frame, now_tick, bootstrap)?;
        XpcFrameEnvelope::from_frame(&response)
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dispatcher::SecretSource, lifecycle_host::StartMaterial};
    use std::cell::Cell;
    use tunbridge_service::{
        frame,
        protocol::{
            Command, Hello, HelloOk, Request, RequestKind, Response, ResponseData, PROTOCOL_VERSION,
        },
        state::Phase,
    };

    struct FakePeer {
        caller: Option<Caller>,
        calls: Cell<usize>,
    }

    impl XpcAppPeer for FakePeer {
        fn authenticated_caller(&self) -> Result<Caller, HostError> {
            self.calls.set(self.calls.get() + 1);
            self.caller.clone().ok_or(HostError::InvalidInput)
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
    struct DeterministicSecrets(u8);

    impl SecretSource for DeterministicSecrets {
        fn next_32(&mut self) -> Result<[u8; 32], HostError> {
            self.0 = self.0.checked_add(1).ok_or(HostError::BackendUnavailable)?;
            Ok([self.0; 32])
        }
    }

    fn caller() -> Caller {
        Caller {
            principal_id: "macos:502:ABCDE12345:com.tunbridge.desktop".into(),
            session_id: 42,
            is_admin: false,
        }
    }

    fn envelope<T: serde::Serialize>(value: &T) -> XpcFrameEnvelope {
        XpcFrameEnvelope::from_frame(&frame::encode(value).unwrap()).unwrap()
    }

    #[test]
    fn authenticated_envelope_handshake_and_status_share_one_session_guard() {
        let peer = FakePeer {
            caller: Some(caller()),
            calls: Cell::new(0),
        };
        let (mut session, hello_response) =
            NativeXpcSession::accept_peer(&peer, &envelope(&Hello::new("0.2.3")), [0xa5; 32])
                .unwrap();
        assert_eq!(peer.calls.get(), 1);
        let hello: HelloOk = frame::decode(&hello_response.to_frame().unwrap()).unwrap();
        assert_eq!(hello.session_nonce, "a5".repeat(32));

        let context =
            MacosServiceContext::stopped(MemoryLifecycle, DeterministicSecrets::default());
        let request = Request {
            kind: RequestKind::Request,
            protocol: PROTOCOL_VERSION,
            session_nonce: hello.session_nonce,
            seq: 1,
            request_id: "b".repeat(32),
            command: Command::Status,
        };
        let response = session.handle(&context, &envelope(&request), 0).unwrap();
        let response: Response = frame::decode(&response.to_frame().unwrap()).unwrap();
        assert_eq!(
            response.result.data,
            Some(ResponseData::Status {
                service_phase: Phase::Stopped,
                caller_is_owner: false,
                engine_running: false,
                service_version: env!("CARGO_PKG_VERSION").into(),
                stop_reason: None,
                degraded_reason: None,
            })
        );
    }

    #[test]
    fn rejected_peer_is_checked_before_hello_frame_is_decoded() {
        let peer = FakePeer {
            caller: None,
            calls: Cell::new(0),
        };
        let malformed = envelope(&42_u32);
        assert!(matches!(
            NativeXpcSession::accept_peer(&peer, &malformed, [1; 32]),
            Err(HostError::InvalidInput)
        ));
        assert_eq!(peer.calls.get(), 1);
    }

    #[test]
    fn replayed_xpc_request_is_rejected_before_second_dispatch() {
        let peer = FakePeer {
            caller: Some(caller()),
            calls: Cell::new(0),
        };
        let (mut session, _) =
            NativeXpcSession::accept_peer(&peer, &envelope(&Hello::new("0.2.3")), [0xa5; 32])
                .unwrap();
        let context =
            MacosServiceContext::stopped(MemoryLifecycle, DeterministicSecrets::default());
        let request = envelope(&Request {
            kind: RequestKind::Request,
            protocol: PROTOCOL_VERSION,
            session_nonce: "a5".repeat(32),
            seq: 1,
            request_id: "b".repeat(32),
            command: Command::Status,
        });
        session.handle(&context, &request, 0).unwrap();
        assert!(matches!(
            session.handle(&context, &request, 0),
            Err(HostError::InvalidInput)
        ));
    }
}
