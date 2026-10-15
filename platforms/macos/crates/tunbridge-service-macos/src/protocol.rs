use tunbridge_service::{
    frame,
    protocol::{
        Capability, Command, Hello, HelloOk, Request, RequestKind, Response, SessionGuard,
        MAX_FRAME_BYTES, MAX_REQUESTS_PER_CONNECTION, PROTOCOL_VERSION,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolContractError {
    InvalidFrame,
    IdentityRejected,
    CapabilityUnavailable,
    RequestLimitReached,
    ResponseRejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRequest {
    request: Request,
    frame: Vec<u8>,
}

impl PendingRequest {
    pub fn frame(&self) -> &[u8] {
        &self.frame
    }

    pub fn request(&self) -> &Request {
        &self.request
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosProtocolSession {
    session_nonce: String,
    next_sequence: u64,
    capabilities: Vec<Capability>,
}

impl MacosProtocolSession {
    pub fn hello_frame(client_version: &str) -> Result<Vec<u8>, ProtocolContractError> {
        let hello = Hello::new(client_version);
        hello
            .validate()
            .map_err(|_| ProtocolContractError::InvalidFrame)?;
        frame::encode(&hello).map_err(|_| ProtocolContractError::InvalidFrame)
    }

    pub fn accept_hello_frame(frame_bytes: &[u8]) -> Result<Self, ProtocolContractError> {
        let hello: HelloOk =
            frame::decode(frame_bytes).map_err(|_| ProtocolContractError::InvalidFrame)?;
        if hello.protocol != PROTOCOL_VERSION
            || hello.max_frame_bytes != MAX_FRAME_BYTES
            || hello.service_version.is_empty()
            || hello.service_version.len() > 64
            || hello.service_version.chars().any(char::is_control)
            || !hello.capabilities.contains(&Capability::Status)
            || has_duplicate_capabilities(&hello.capabilities)
            || SessionGuard::new(hello.session_nonce.clone()).is_err()
        {
            return Err(ProtocolContractError::IdentityRejected);
        }
        Ok(Self {
            session_nonce: hello.session_nonce,
            next_sequence: 1,
            capabilities: hello.capabilities,
        })
    }

    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    pub fn prepare(
        &self,
        command: Command,
        request_id: String,
    ) -> Result<PendingRequest, ProtocolContractError> {
        if self.next_sequence > MAX_REQUESTS_PER_CONNECTION {
            return Err(ProtocolContractError::RequestLimitReached);
        }
        let required = required_capability(&command);
        if !self.capabilities.contains(&required) {
            return Err(ProtocolContractError::CapabilityUnavailable);
        }
        let request = Request {
            kind: RequestKind::Request,
            protocol: PROTOCOL_VERSION,
            session_nonce: self.session_nonce.clone(),
            seq: self.next_sequence,
            request_id,
            command,
        };
        request
            .validate_envelope()
            .map_err(|_| ProtocolContractError::InvalidFrame)?;
        let frame = frame::encode(&request).map_err(|_| ProtocolContractError::InvalidFrame)?;
        Ok(PendingRequest { request, frame })
    }

    pub fn accept_response(
        &mut self,
        pending: &PendingRequest,
        frame_bytes: &[u8],
    ) -> Result<Response, ProtocolContractError> {
        if pending.request.seq != self.next_sequence
            || pending.request.session_nonce != self.session_nonce
        {
            return Err(ProtocolContractError::ResponseRejected);
        }
        let response: Response =
            frame::decode(frame_bytes).map_err(|_| ProtocolContractError::InvalidFrame)?;
        let result_shape_valid = if response.result.ok {
            response.result.data.is_some() && response.result.error.is_none()
        } else {
            response.result.data.is_none() && response.result.error.is_some()
        };
        if response.protocol != PROTOCOL_VERSION
            || response.seq != pending.request.seq
            || response.request_id != pending.request.request_id
            || !result_shape_valid
        {
            return Err(ProtocolContractError::ResponseRejected);
        }
        self.next_sequence += 1;
        Ok(response)
    }
}

fn has_duplicate_capabilities(capabilities: &[Capability]) -> bool {
    capabilities
        .iter()
        .enumerate()
        .any(|(index, capability)| capabilities[..index].contains(capability))
}

fn required_capability(command: &Command) -> Capability {
    match command {
        Command::Status => Capability::Status,
        Command::Start { .. } => Capability::Start,
        Command::Stop => Capability::Stop,
        Command::Recover => Capability::Recover,
        #[cfg(feature = "macos-development-bootstrap")]
        Command::ProvisionGeneration { .. } => Capability::Provision,
        Command::AcquireLease {} | Command::RenewLease { .. } | Command::ReleaseLease { .. } => {
            Capability::Lease
        }
        Command::ObserveTraffic {} | Command::ListConnections { .. } => {
            Capability::ObserveLocalTraffic
        }
        Command::CloseConnection { .. } | Command::CloseAllConnections {} => {
            Capability::CloseOwnedConnections
        }
        Command::ListMihomoLogs { .. } => Capability::ObserveMihomoLogs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunbridge_service::protocol::{ErrorCode, HelloOk, ResponseData};
    use tunbridge_service::state::Phase;

    fn hello(capabilities: Vec<Capability>) -> Vec<u8> {
        frame::encode(&HelloOk::with_capabilities(
            "0.2.3",
            "a".repeat(64),
            capabilities,
        ))
        .unwrap()
    }

    fn session() -> MacosProtocolSession {
        MacosProtocolSession::accept_hello_frame(&hello(vec![
            Capability::Status,
            Capability::Start,
            Capability::Stop,
            Capability::Recover,
            Capability::Lease,
        ]))
        .unwrap()
    }

    #[test]
    fn hello_and_request_use_shared_bounded_frame_contract() {
        let hello_frame = MacosProtocolSession::hello_frame("0.2.3").unwrap();
        let decoded: Hello = frame::decode(&hello_frame).unwrap();
        assert_eq!(decoded.protocol, PROTOCOL_VERSION);

        let pending = session().prepare(Command::Status, "b".repeat(32)).unwrap();
        assert!(pending.frame().len() <= MAX_FRAME_BYTES + size_of::<u32>());
        let decoded: Request = frame::decode(pending.frame()).unwrap();
        assert_eq!(decoded.seq, 1);
        assert_eq!(decoded.request_id, "b".repeat(32));
    }

    #[test]
    fn handshake_rejects_wrong_protocol_nonce_bounds_and_duplicate_capabilities() {
        let mut wrong_protocol =
            HelloOk::with_capabilities("0.2.3", "a".repeat(64), vec![Capability::Status]);
        wrong_protocol.protocol += 1;
        let wrong_protocol = frame::encode(&wrong_protocol).unwrap();

        let bad_nonce =
            HelloOk::with_capabilities("0.2.3", "not-hex".into(), vec![Capability::Status]);
        let bad_nonce = frame::encode(&bad_nonce).unwrap();

        for frame_bytes in [
            wrong_protocol,
            bad_nonce,
            hello(Vec::new()),
            hello(vec![Capability::Status, Capability::Status]),
        ] {
            assert_eq!(
                MacosProtocolSession::accept_hello_frame(&frame_bytes),
                Err(ProtocolContractError::IdentityRejected)
            );
        }
    }

    #[test]
    fn capability_and_request_identifier_checks_fail_before_transport() {
        let status_only =
            MacosProtocolSession::accept_hello_frame(&hello(vec![Capability::Status])).unwrap();
        assert_eq!(
            status_only.prepare(Command::Stop, "b".repeat(32)),
            Err(ProtocolContractError::CapabilityUnavailable)
        );
        assert_eq!(
            status_only.prepare(Command::Status, "not-hex".into()),
            Err(ProtocolContractError::InvalidFrame)
        );
    }

    #[test]
    fn response_must_match_protocol_sequence_request_and_result_shape() {
        let mut session = session();
        let pending = session.prepare(Command::Status, "b".repeat(32)).unwrap();
        let response = Response::success(
            pending.request(),
            ResponseData::Status {
                service_phase: Phase::Stopped,
                caller_is_owner: false,
                engine_running: false,
                service_version: "0.2.3".into(),
                stop_reason: None,
                degraded_reason: None,
            },
        );
        let response_frame = frame::encode(&response).unwrap();
        session.accept_response(&pending, &response_frame).unwrap();

        let pending = session.prepare(Command::Status, "c".repeat(32)).unwrap();
        let mut wrong = Response::error(
            pending.request(),
            ErrorCode::InternalError,
            "safe fixture",
            false,
        );
        wrong.request_id = "d".repeat(32);
        assert_eq!(
            session.accept_response(&pending, &frame::encode(&wrong).unwrap()),
            Err(ProtocolContractError::ResponseRejected)
        );
    }

    #[test]
    fn rejected_response_does_not_advance_sequence() {
        let mut session = session();
        let pending = session.prepare(Command::Status, "b".repeat(32)).unwrap();
        assert_eq!(
            session.accept_response(&pending, &frame::encode(&Hello::new("0.2.3")).unwrap()),
            Err(ProtocolContractError::InvalidFrame)
        );
        assert_eq!(
            session
                .prepare(Command::Status, "c".repeat(32))
                .unwrap()
                .request()
                .seq,
            1
        );
    }
}
