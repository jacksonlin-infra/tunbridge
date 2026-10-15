//! Exact-owner Mihomo controller source for helper observability commands.

use crate::{
    controller::{
        ControllerError, ControllerOwnerVerifier, ObservabilityControllerTransport,
        ObservabilityMethod,
    },
    engine_config::CONTROLLER_ADDRESS,
    lifecycle_plan::{OwnedRunRecord, OwnedStage, ProcessIdentity},
    observability::{ObservabilityFailure, OwnedControllerSource},
};
use tunbridge_service::protocol::ErrorCode;
use zeroize::Zeroize;

pub struct NativeOwnedControllerSource<T, V> {
    generation: String,
    engine: ProcessIdentity,
    controller_secret: String,
    transport: T,
    verifier: V,
}

impl<T, V> NativeOwnedControllerSource<T, V> {
    pub fn new(
        record: OwnedRunRecord,
        transport: T,
        verifier: V,
    ) -> Result<Self, ObservabilityFailure> {
        record.validate().map_err(|_| unavailable())?;
        if record.stage != OwnedStage::Running {
            return Err(unavailable());
        }
        let engine = record.engine.clone().ok_or_else(unavailable)?;
        Ok(Self {
            generation: record.run_id.clone(),
            engine,
            controller_secret: record.controller_secret.clone(),
            transport,
            verifier,
        })
    }

    fn request(
        &mut self,
        method: ObservabilityMethod,
        connection_id: Option<&str>,
    ) -> Result<Vec<u8>, ObservabilityFailure>
    where
        T: ObservabilityControllerTransport,
        V: ControllerOwnerVerifier,
    {
        self.verify_owner()?;
        let response = self
            .transport
            .request(method, connection_id, &self.controller_secret)
            .map_err(map_controller_error)?;
        self.verify_owner()?;
        Ok(response)
    }

    fn verify_owner(&mut self) -> Result<(), ObservabilityFailure>
    where
        V: ControllerOwnerVerifier,
    {
        match self
            .verifier
            .is_exact_owner(CONTROLLER_ADDRESS, &self.engine)
        {
            Ok(true) => Ok(()),
            Ok(false) => Err(unavailable()),
            Err(error) => Err(map_controller_error(error)),
        }
    }
}

impl<T, V> OwnedControllerSource for NativeOwnedControllerSource<T, V>
where
    T: ObservabilityControllerTransport,
    V: ControllerOwnerVerifier,
{
    fn engine_generation(&self) -> Result<String, ObservabilityFailure> {
        Ok(self.generation.clone())
    }

    fn connections(&mut self) -> Result<Vec<u8>, ObservabilityFailure> {
        self.request(ObservabilityMethod::Get, None)
    }

    fn close(&mut self, connection_id: Option<&str>) -> Result<(), ObservabilityFailure> {
        self.request(ObservabilityMethod::Delete, connection_id)
            .map(|_| ())
    }
}

impl<T, V> Drop for NativeOwnedControllerSource<T, V> {
    fn drop(&mut self) {
        self.controller_secret.zeroize();
    }
}

fn map_controller_error(_error: ControllerError) -> ObservabilityFailure {
    unavailable()
}

fn unavailable() -> ObservabilityFailure {
    ObservabilityFailure {
        code: ErrorCode::ObservabilityUnavailable,
        safe_message: "The owned macOS controller is unavailable.",
        retryable: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        lifecycle_plan::{DnsBaseline, DnsConfigurationMode, NetworkBaseline, TunIdentity},
        observability::OwnedControllerSource,
    };
    use std::{
        collections::VecDeque,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
    };

    const SECRET: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn record() -> OwnedRunRecord {
        let engine = ProcessIdentity {
            pid: 700,
            start_time_ns: 100,
            executable_file_id: 200,
            executable_sha256: "b".repeat(64),
        };
        OwnedRunRecord {
            schema_version: 2,
            run_id: "c".repeat(32),
            stage: OwnedStage::Running,
            owner_principal_id: "macos:502:ABCDE12345:com.tunbridge.desktop".into(),
            owner_session_id: 42,
            upstream: ProcessIdentity {
                pid: 600,
                start_time_ns: 90,
                executable_file_id: 190,
                executable_sha256: "d".repeat(64),
            },
            engine: Some(engine),
            tun: Some(TunIdentity {
                interface_name: "utun7".into(),
                interface_index: 7,
                engine_pid: 700,
            }),
            baseline: NetworkBaseline {
                default_interface_index: 4,
                default_gateway: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                routes_sha256: "f".repeat(64),
                preexisting_utuns: Vec::new(),
                dns: DnsBaseline {
                    network_service_id: "service".into(),
                    mode: DnsConfigurationMode::Automatic,
                    servers: Vec::new(),
                    search_domains: Vec::new(),
                },
            },
            route_deltas: vec![
                crate::lifecycle_plan::RouteDelta {
                    destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    prefix_length: 1,
                    gateway: None,
                    interface_index: 7,
                    interface_scoped: false,
                },
                crate::lifecycle_plan::RouteDelta {
                    destination: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    prefix_length: 1,
                    gateway: None,
                    interface_index: 7,
                    interface_scoped: false,
                },
            ],
            planned_dns_sha256: Some("e".repeat(64)),
            controller_secret: SECRET.into(),
        }
    }

    #[derive(Default)]
    struct MockTransport {
        calls: Vec<(ObservabilityMethod, Option<String>)>,
    }

    impl ObservabilityControllerTransport for MockTransport {
        fn request(
            &mut self,
            method: ObservabilityMethod,
            connection_id: Option<&str>,
            secret: &str,
        ) -> Result<Vec<u8>, ControllerError> {
            assert_eq!(secret, SECRET);
            self.calls
                .push((method, connection_id.map(ToOwned::to_owned)));
            Ok(br#"{"connections":[]}"#.to_vec())
        }
    }

    struct MockVerifier(VecDeque<bool>);

    impl ControllerOwnerVerifier for MockVerifier {
        fn is_exact_owner(
            &mut self,
            address: &str,
            expected: &ProcessIdentity,
        ) -> Result<bool, ControllerError> {
            assert_eq!(address, CONTROLLER_ADDRESS);
            assert_eq!(expected.pid, 700);
            self.0.pop_front().ok_or(ControllerError::Unavailable)
        }
    }

    #[test]
    fn every_read_and_delete_is_surrounded_by_exact_owner_checks() {
        let mut source = NativeOwnedControllerSource::new(
            record(),
            MockTransport::default(),
            MockVerifier(VecDeque::from([true, true, true, true])),
        )
        .unwrap();
        source.connections().unwrap();
        source.close(Some("id_7")).unwrap();
        assert_eq!(
            source.transport.calls,
            vec![
                (ObservabilityMethod::Get, None),
                (ObservabilityMethod::Delete, Some("id_7".into()))
            ]
        );
        assert!(source.verifier.0.is_empty());
    }

    #[test]
    fn listener_replacement_blocks_operation_or_result() {
        for checks in [VecDeque::from([false]), VecDeque::from([true, false])] {
            let mut source = NativeOwnedControllerSource::new(
                record(),
                MockTransport::default(),
                MockVerifier(checks),
            )
            .unwrap();
            assert_eq!(
                source.connections().unwrap_err().code,
                ErrorCode::ObservabilityUnavailable
            );
        }
    }
}
