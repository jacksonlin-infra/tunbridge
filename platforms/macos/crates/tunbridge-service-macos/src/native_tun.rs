//! Read-only authenticated controller and causal utun verification.

use crate::{
    controller::{
        read_tun_evidence, ControllerOwnerVerifier, ControllerTransport, TcpControllerTransport,
    },
    controller_owner::NativeControllerOwnerVerifier,
    darwin_state::InterfaceSnapshot,
    lifecycle_plan::{NetworkBaseline, ProcessIdentity, TunIdentity},
    native::interface_snapshot,
    tun_attribution::attribute_new_utun,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeTunError {
    ControllerUnavailable,
    InterfaceUnavailable,
    AttributionUnavailable,
}

pub trait InterfaceInventorySource {
    fn snapshot(&mut self) -> Result<InterfaceSnapshot, NativeTunError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemInterfaceInventorySource;

impl InterfaceInventorySource for SystemInterfaceInventorySource {
    fn snapshot(&mut self) -> Result<InterfaceSnapshot, NativeTunError> {
        interface_snapshot().map_err(|_| NativeTunError::InterfaceUnavailable)
    }
}

pub struct NativeTunVerifier<T, V, I> {
    transport: T,
    owner_verifier: V,
    interfaces: I,
}

impl Default
    for NativeTunVerifier<
        TcpControllerTransport,
        NativeControllerOwnerVerifier,
        SystemInterfaceInventorySource,
    >
{
    fn default() -> Self {
        Self::new(
            TcpControllerTransport,
            NativeControllerOwnerVerifier,
            SystemInterfaceInventorySource,
        )
    }
}

impl<T, V, I> NativeTunVerifier<T, V, I>
where
    T: ControllerTransport,
    V: ControllerOwnerVerifier,
    I: InterfaceInventorySource,
{
    pub fn new(transport: T, owner_verifier: V, interfaces: I) -> Self {
        Self {
            transport,
            owner_verifier,
            interfaces,
        }
    }

    pub fn verify(
        &mut self,
        baseline: &NetworkBaseline,
        engine: &ProcessIdentity,
        controller_secret: &str,
        configured_device: &str,
    ) -> Result<TunIdentity, NativeTunError> {
        let controller = read_tun_evidence(
            &mut self.transport,
            &mut self.owner_verifier,
            engine,
            controller_secret,
            configured_device,
        )
        .map_err(|_| NativeTunError::ControllerUnavailable)?;
        let interfaces = self.interfaces.snapshot()?;
        attribute_new_utun(baseline, engine, &controller, &interfaces)
            .map_err(|_| NativeTunError::AttributionUnavailable)
    }

    pub fn into_parts(self) -> (T, V, I) {
        (self.transport, self.owner_verifier, self.interfaces)
    }

    /// Reauthenticate an already journaled TUN without requiring unrelated
    /// baseline VPN interfaces to remain alive throughout our run.
    pub fn verify_recorded(
        &mut self,
        baseline: &NetworkBaseline,
        engine: &ProcessIdentity,
        controller_secret: &str,
        expected: &TunIdentity,
    ) -> Result<TunIdentity, NativeTunError> {
        let controller = read_tun_evidence(
            &mut self.transport,
            &mut self.owner_verifier,
            engine,
            controller_secret,
            &expected.interface_name,
        )
        .map_err(|_| NativeTunError::ControllerUnavailable)?;
        let interfaces = self.interfaces.snapshot()?;
        let mut remaining_baseline = baseline.clone();
        remaining_baseline.preexisting_utuns.retain(|previous| {
            interfaces.interfaces.iter().any(|current| {
                current.name == previous.interface_name && current.index == previous.interface_index
            })
        });
        let verified = attribute_new_utun(&remaining_baseline, engine, &controller, &interfaces)
            .map_err(|_| NativeTunError::AttributionUnavailable)?;
        if verified != *expected {
            return Err(NativeTunError::AttributionUnavailable);
        }
        Ok(verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        controller::ControllerError,
        darwin_state::DarwinInterface,
        engine_config::CONTROLLER_ADDRESS,
        lifecycle_plan::{DnsBaseline, DnsConfigurationMode, InterfaceIdentity, ProcessIdentity},
    };
    use std::{
        cell::Cell,
        net::{IpAddr, Ipv4Addr},
    };

    struct MockTransport {
        configured_device: String,
        calls: Cell<usize>,
    }

    impl ControllerTransport for MockTransport {
        fn get(&mut self, path: &'static str, secret: &str) -> Result<Vec<u8>, ControllerError> {
            assert_eq!(secret, "a".repeat(64));
            self.calls.set(self.calls.get() + 1);
            match path {
                "/version" => Ok(br#"{"version":"v1.19.0","meta":true}"#.to_vec()),
                "/configs" => Ok(format!(
                    r#"{{"tun":{{"enable":true,"device":"{}"}}}}"#,
                    self.configured_device
                )
                .into_bytes()),
                _ => Err(ControllerError::Invalid),
            }
        }
    }

    struct MockOwner {
        exact: bool,
        calls: Cell<usize>,
    }

    impl ControllerOwnerVerifier for MockOwner {
        fn is_exact_owner(
            &mut self,
            address: &str,
            expected: &ProcessIdentity,
        ) -> Result<bool, ControllerError> {
            assert_eq!(address, CONTROLLER_ADDRESS);
            assert_eq!(expected.pid, 700);
            self.calls.set(self.calls.get() + 1);
            Ok(self.exact)
        }
    }

    struct MockInterfaces {
        snapshot: Option<InterfaceSnapshot>,
        calls: Cell<usize>,
    }

    impl InterfaceInventorySource for MockInterfaces {
        fn snapshot(&mut self) -> Result<InterfaceSnapshot, NativeTunError> {
            self.calls.set(self.calls.get() + 1);
            self.snapshot
                .clone()
                .ok_or(NativeTunError::InterfaceUnavailable)
        }
    }

    fn engine() -> ProcessIdentity {
        ProcessIdentity {
            pid: 700,
            start_time_ns: 70_000,
            executable_file_id: 7_000,
            executable_sha256: "b".repeat(64),
        }
    }

    fn baseline() -> NetworkBaseline {
        NetworkBaseline {
            default_interface_index: 9,
            default_gateway: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            routes_sha256: "c".repeat(64),
            preexisting_utuns: vec![InterfaceIdentity {
                interface_name: "utun3".into(),
                interface_index: 13,
            }],
            dns: DnsBaseline {
                network_service_id: "fixture-service".into(),
                mode: DnsConfigurationMode::Automatic,
                servers: Vec::new(),
                search_domains: Vec::new(),
            },
        }
    }

    fn interfaces(additions: &[(&str, u32)]) -> InterfaceSnapshot {
        let mut values = vec![DarwinInterface {
            name: "utun3".into(),
            index: 13,
            owner_pid: None,
        }];
        values.extend(additions.iter().map(|(name, index)| DarwinInterface {
            name: (*name).into(),
            index: *index,
            owner_pid: None,
        }));
        InterfaceSnapshot {
            complete: true,
            interfaces: values,
        }
    }

    fn verifier(
        device: &str,
        exact_owner: bool,
        snapshot: Option<InterfaceSnapshot>,
    ) -> NativeTunVerifier<MockTransport, MockOwner, MockInterfaces> {
        NativeTunVerifier::new(
            MockTransport {
                configured_device: device.into(),
                calls: Cell::new(0),
            },
            MockOwner {
                exact: exact_owner,
                calls: Cell::new(0),
            },
            MockInterfaces {
                snapshot,
                calls: Cell::new(0),
            },
        )
    }

    #[test]
    fn authenticated_controller_and_one_new_device_yield_exact_tun() {
        let mut verifier = verifier("utun7", true, Some(interfaces(&[("utun7", 17)])));
        assert_eq!(
            verifier.verify(&baseline(), &engine(), &"a".repeat(64), "utun7"),
            Ok(TunIdentity {
                interface_name: "utun7".into(),
                interface_index: 17,
                engine_pid: 700,
            })
        );
        let (transport, owner, interfaces) = verifier.into_parts();
        assert_eq!(transport.calls.get(), 2);
        assert_eq!(owner.calls.get(), 2);
        assert_eq!(interfaces.calls.get(), 1);
    }

    #[test]
    fn controller_owner_or_device_mismatch_never_reads_interface_inventory() {
        for (device, exact_owner) in [("utun8", true), ("utun7", false)] {
            let mut verifier = verifier(device, exact_owner, Some(interfaces(&[("utun7", 17)])));
            assert_eq!(
                verifier.verify(&baseline(), &engine(), &"a".repeat(64), "utun7"),
                Err(NativeTunError::ControllerUnavailable)
            );
            assert_eq!(verifier.into_parts().2.calls.get(), 0);
        }
    }

    #[test]
    fn incomplete_missing_or_ambiguous_inventory_fails_closed() {
        let mut incomplete = interfaces(&[("utun7", 17)]);
        incomplete.complete = false;
        for snapshot in [
            None,
            Some(incomplete),
            Some(interfaces(&[])),
            Some(interfaces(&[("utun7", 17), ("utun8", 18)])),
        ] {
            let mut verifier = verifier("utun7", true, snapshot);
            assert!(verifier
                .verify(&baseline(), &engine(), &"a".repeat(64), "utun7")
                .is_err());
        }
    }

    #[test]
    fn recorded_tun_recovery_allows_foreign_baseline_interface_to_disappear() {
        let expected = TunIdentity {
            interface_name: "utun7".into(),
            interface_index: 17,
            engine_pid: 700,
        };
        let mut inventory = interfaces(&[("utun7", 17)]);
        inventory.interfaces.retain(|entry| entry.name != "utun3");
        let mut verifier = verifier("utun7", true, Some(inventory));
        assert!(verifier
            .verify(&baseline(), &engine(), &"a".repeat(64), "utun7")
            .is_err());
        assert_eq!(
            verifier.verify_recorded(&baseline(), &engine(), &"a".repeat(64), &expected),
            Ok(expected)
        );
    }

    #[test]
    fn recorded_tun_recovery_rejects_reuse_ambiguity_and_unauthenticated_owner() {
        let expected = TunIdentity {
            interface_name: "utun7".into(),
            interface_index: 17,
            engine_pid: 700,
        };
        for (exact_owner, inventory) in [
            (false, interfaces(&[("utun7", 17)])),
            (true, interfaces(&[("utun7", 18)])),
            (true, interfaces(&[("utun7", 17), ("utun8", 18)])),
            (true, interfaces(&[])),
        ] {
            let mut verifier = verifier("utun7", exact_owner, Some(inventory));
            assert!(verifier
                .verify_recorded(&baseline(), &engine(), &"a".repeat(64), &expected)
                .is_err());
        }
    }
}
