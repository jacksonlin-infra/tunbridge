//! Journal-bound orchestration for exact Darwin route and DNS effects.

use crate::{
    darwin_state::{dns_baseline_sha256, plan_tunnel_routes_with_bypass, RouteSnapshot},
    dns_effect::{plan_manual_dns, plan_restore_dns, DnsEffectPlan},
    dns_writer::apply_dns_effect,
    lifecycle_plan::{DnsBaseline, NetworkBaseline, RouteDelta, TunIdentity},
    native::native_route_snapshot,
    route_effect::{RouteEffectOperation, RouteEffectRequest},
    route_socket::apply_route_effect,
};
use std::net::{IpAddr, Ipv4Addr};

const TUN_DNS_SERVER: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeNetworkEffectError {
    InvalidState,
    InvalidPlan,
    Stale,
    EffectUnavailable,
}

pub trait NetworkEffectRuntime {
    fn route_snapshot(&mut self) -> Result<RouteSnapshot, NativeNetworkEffectError>;
    fn apply_route(&mut self, request: &RouteEffectRequest)
        -> Result<(), NativeNetworkEffectError>;
    fn apply_dns(
        &mut self,
        plan: &DnsEffectPlan,
        expected_before_sha256: &str,
    ) -> Result<(), NativeNetworkEffectError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemNetworkEffectRuntime;

impl NetworkEffectRuntime for SystemNetworkEffectRuntime {
    fn route_snapshot(&mut self) -> Result<RouteSnapshot, NativeNetworkEffectError> {
        native_route_snapshot().map_err(|_| NativeNetworkEffectError::EffectUnavailable)
    }

    fn apply_route(
        &mut self,
        request: &RouteEffectRequest,
    ) -> Result<(), NativeNetworkEffectError> {
        apply_route_effect(request).map_err(|error| {
            #[cfg(feature = "macos-development-harness")]
            eprintln!("macos_route_effect_failed request={request:?} error={error:?}");
            #[cfg(not(feature = "macos-development-harness"))]
            let _ = error;
            NativeNetworkEffectError::EffectUnavailable
        })
    }

    fn apply_dns(
        &mut self,
        plan: &DnsEffectPlan,
        expected_before_sha256: &str,
    ) -> Result<(), NativeNetworkEffectError> {
        apply_dns_effect(plan, expected_before_sha256).map_err(|error| {
            #[cfg(feature = "macos-development-harness")]
            eprintln!("macos_dns_effect_failed plan={plan:?} error={error:?}");
            #[cfg(not(feature = "macos-development-harness"))]
            let _ = error;
            NativeNetworkEffectError::EffectUnavailable
        })
    }
}

#[derive(Debug, Clone)]
struct PlannedRoutes {
    default_interface_index: u32,
    default_gateway: IpAddr,
    routes: Vec<RouteDelta>,
}

#[derive(Debug, Clone)]
struct PlannedDns {
    baseline_sha256: String,
    apply: DnsEffectPlan,
}

pub struct NativeNetworkEffects<R: NetworkEffectRuntime = SystemNetworkEffectRuntime> {
    runtime: R,
    routes: Option<PlannedRoutes>,
    dns: Option<PlannedDns>,
    next_sequence: u32,
}

impl Default for NativeNetworkEffects<SystemNetworkEffectRuntime> {
    fn default() -> Self {
        Self::new(SystemNetworkEffectRuntime)
    }
}

impl<R: NetworkEffectRuntime> NativeNetworkEffects<R> {
    pub fn new(runtime: R) -> Self {
        Self {
            runtime,
            routes: None,
            dns: None,
            next_sequence: 1,
        }
    }

    /// Check split-default collisions before the host starts an engine or
    /// creates an owned journal. No existing route is adopted or replaced.
    pub fn preflight_split_routes(&mut self) -> Result<(), NativeNetworkEffectError> {
        let observed = self.runtime.route_snapshot()?;
        let split_destinations: [IpAddr; 4] = [
            Ipv4Addr::UNSPECIFIED.into(),
            Ipv4Addr::new(128, 0, 0, 0).into(),
            std::net::Ipv6Addr::UNSPECIFIED.into(),
            std::net::Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0).into(),
        ];
        if !observed.complete
            || observed.routes.iter().any(|route| {
                route.prefix_length == 1 && split_destinations.contains(&route.destination)
            })
        {
            return Err(NativeNetworkEffectError::Stale);
        }
        Ok(())
    }

    pub fn plan_routes(
        &mut self,
        baseline: &NetworkBaseline,
        tun: &TunIdentity,
    ) -> Result<Vec<RouteDelta>, NativeNetworkEffectError> {
        self.plan_routes_with_bypass(baseline, tun, &[])
    }

    pub fn plan_routes_with_bypass(
        &mut self,
        baseline: &NetworkBaseline,
        tun: &TunIdentity,
        bypass_cidrs: &[String],
    ) -> Result<Vec<RouteDelta>, NativeNetworkEffectError> {
        if self.routes.is_some() {
            return Err(NativeNetworkEffectError::InvalidState);
        }
        let mut routes = plan_tunnel_routes_with_bypass(
            baseline,
            tun,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            true,
            bypass_cidrs,
        )
        .map_err(|_| NativeNetworkEffectError::InvalidPlan)?;
        // Reject existing routes before the host journals these keys as an
        // owned plan. A foreign route must never be recorded as ours.
        let observed = self.runtime.route_snapshot()?;
        if !observed.complete {
            return Err(NativeNetworkEffectError::Stale);
        }
        // A scoped default that already exists (for example one configd
        // installs for a secondary service) serves the same purpose; leave it
        // unowned rather than refusing the start.
        routes.retain(|owned| {
            !owned.interface_scoped
                || !observed
                    .routes
                    .iter()
                    .any(|existing| existing.same_key(owned))
        });
        ensure_route_keys_available(&routes, &observed)?;
        self.routes = Some(PlannedRoutes {
            default_interface_index: baseline.default_interface_index,
            default_gateway: baseline.default_gateway,
            routes: routes.clone(),
        });
        Ok(routes)
    }

    pub fn apply_routes(&mut self, routes: &[RouteDelta]) -> Result<(), NativeNetworkEffectError> {
        let planned = self
            .routes
            .as_ref()
            .ok_or(NativeNetworkEffectError::InvalidState)?;
        if planned.routes != routes {
            return Err(NativeNetworkEffectError::InvalidPlan);
        }
        let observed = self.runtime.route_snapshot()?;
        if !observed.complete
            || !observed.routes.iter().any(|route| {
                !route.interface_scoped
                    && route.destination.is_unspecified()
                    && route.destination.is_ipv4() == planned.default_gateway.is_ipv4()
                    && route.prefix_length == 0
                    && route.gateway == Some(planned.default_gateway)
                    && route.interface_index == planned.default_interface_index
            })
        {
            return Err(NativeNetworkEffectError::Stale);
        }
        // Recheck after journaling: another owner can change routes between
        // planning and application.
        ensure_route_keys_available(routes, &observed)?;
        for route in routes {
            let request = self.route_request(RouteEffectOperation::Add, route.clone())?;
            self.runtime.apply_route(&request)?;
        }
        Ok(())
    }

    pub fn plan_dns(
        &mut self,
        baseline: &DnsBaseline,
        tun: &TunIdentity,
    ) -> Result<String, NativeNetworkEffectError> {
        if self.dns.is_some() || !valid_tun(tun) {
            return Err(NativeNetworkEffectError::InvalidState);
        }
        let baseline_sha256 =
            dns_baseline_sha256(baseline).map_err(|_| NativeNetworkEffectError::InvalidPlan)?;
        let apply = plan_manual_dns(
            &baseline.network_service_id,
            vec![IpAddr::V4(TUN_DNS_SERVER)],
            Vec::new(),
        )
        .map_err(|_| NativeNetworkEffectError::InvalidPlan)?;
        let expected_sha256 = apply.expected_sha256.clone();
        self.dns = Some(PlannedDns {
            baseline_sha256,
            apply,
        });
        Ok(expected_sha256)
    }

    pub fn apply_dns(&mut self, planned_dns_sha256: &str) -> Result<(), NativeNetworkEffectError> {
        let planned = self
            .dns
            .as_ref()
            .ok_or(NativeNetworkEffectError::InvalidState)?;
        if planned.apply.expected_sha256 != planned_dns_sha256 {
            return Err(NativeNetworkEffectError::InvalidPlan);
        }
        self.runtime
            .apply_dns(&planned.apply, &planned.baseline_sha256)
    }

    pub fn remove_routes(&mut self, routes: &[RouteDelta]) -> Result<(), NativeNetworkEffectError> {
        if routes.is_empty() {
            return Err(NativeNetworkEffectError::InvalidPlan);
        }
        for route in routes.iter().rev() {
            let request = self.route_request(RouteEffectOperation::Delete, route.clone())?;
            self.runtime.apply_route(&request)?;
        }
        self.routes = None;
        Ok(())
    }

    pub fn restore_dns(
        &mut self,
        baseline: &DnsBaseline,
        planned_dns_sha256: &str,
    ) -> Result<(), NativeNetworkEffectError> {
        let restore =
            plan_restore_dns(baseline).map_err(|_| NativeNetworkEffectError::InvalidPlan)?;
        self.runtime.apply_dns(&restore, planned_dns_sha256)?;
        self.dns = None;
        Ok(())
    }

    pub fn runtime(&self) -> &R {
        &self.runtime
    }

    fn route_request(
        &mut self,
        operation: RouteEffectOperation,
        route: RouteDelta,
    ) -> Result<RouteEffectRequest, NativeNetworkEffectError> {
        let sequence = self.next_sequence;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .filter(|value| *value <= i32::MAX as u32)
            .ok_or(NativeNetworkEffectError::InvalidState)?;
        Ok(RouteEffectRequest {
            operation,
            route,
            sequence,
            sender_pid: std::process::id(),
        })
    }
}

fn ensure_route_keys_available(
    routes: &[RouteDelta],
    observed: &RouteSnapshot,
) -> Result<(), NativeNetworkEffectError> {
    if !observed.complete
        || observed
            .routes
            .iter()
            .any(|existing| routes.iter().any(|owned| existing.same_key(owned)))
    {
        return Err(NativeNetworkEffectError::Stale);
    }
    Ok(())
}

fn valid_tun(tun: &TunIdentity) -> bool {
    tun.interface_index > 0
        && tun.engine_pid > 1
        && tun
            .interface_name
            .strip_prefix("utun")
            .is_some_and(|suffix| {
                !suffix.is_empty()
                    && suffix.len() <= 4
                    && suffix.bytes().all(|byte| byte.is_ascii_digit())
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        darwin_state::{dns_baseline_sha256, plan_tunnel_routes, route_snapshot_sha256},
        lifecycle_plan::DnsConfigurationMode,
    };
    use std::cell::{Cell, RefCell};

    struct MockRuntime {
        routes: RefCell<RouteSnapshot>,
        route_requests: RefCell<Vec<RouteEffectRequest>>,
        dns_requests: RefCell<Vec<(DnsEffectPlan, String)>>,
        fail_route_call: Cell<Option<usize>>,
    }

    impl NetworkEffectRuntime for MockRuntime {
        fn route_snapshot(&mut self) -> Result<RouteSnapshot, NativeNetworkEffectError> {
            Ok(self.routes.borrow().clone())
        }

        fn apply_route(
            &mut self,
            request: &RouteEffectRequest,
        ) -> Result<(), NativeNetworkEffectError> {
            let call = self.route_requests.borrow().len() + 1;
            if self.fail_route_call.get() == Some(call) {
                return Err(NativeNetworkEffectError::EffectUnavailable);
            }
            self.route_requests.borrow_mut().push(request.clone());
            let mut snapshot = self.routes.borrow_mut();
            match request.operation {
                RouteEffectOperation::Add => snapshot.routes.push(request.route.clone()),
                RouteEffectOperation::Delete => {
                    snapshot.routes.retain(|route| route != &request.route);
                }
            }
            Ok(())
        }

        fn apply_dns(
            &mut self,
            plan: &DnsEffectPlan,
            expected_before_sha256: &str,
        ) -> Result<(), NativeNetworkEffectError> {
            self.dns_requests
                .borrow_mut()
                .push((plan.clone(), expected_before_sha256.into()));
            Ok(())
        }
    }

    fn base_routes() -> RouteSnapshot {
        RouteSnapshot {
            complete: true,
            routes: vec![RouteDelta {
                destination: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                prefix_length: 0,
                gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
                interface_index: 9,
                interface_scoped: false,
            }],
        }
    }

    fn dns() -> DnsBaseline {
        DnsBaseline {
            network_service_id: "fixture-service".into(),
            mode: DnsConfigurationMode::Manual,
            servers: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))],
            search_domains: vec!["example.test".into()],
        }
    }

    fn baseline() -> NetworkBaseline {
        let routes = base_routes();
        NetworkBaseline {
            default_interface_index: 9,
            default_gateway: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            routes_sha256: route_snapshot_sha256(&routes).unwrap(),
            preexisting_utuns: Vec::new(),
            dns: dns(),
        }
    }

    fn tun() -> TunIdentity {
        TunIdentity {
            interface_name: "utun7".into(),
            interface_index: 17,
            engine_pid: 700,
        }
    }

    fn runtime() -> MockRuntime {
        MockRuntime {
            routes: RefCell::new(base_routes()),
            route_requests: RefCell::new(Vec::new()),
            dns_requests: RefCell::new(Vec::new()),
            fail_route_call: Cell::new(None),
        }
    }

    #[test]
    fn exact_plans_apply_routes_then_dns_with_baseline_preconditions() {
        let mut effects = NativeNetworkEffects::new(runtime());
        let routes = effects.plan_routes(&baseline(), &tun()).unwrap();
        assert_eq!(routes.len(), 5);
        assert!(routes[0].interface_scoped && routes[0].prefix_length == 0);
        effects.apply_routes(&routes).unwrap();
        let dns_sha256 = effects.plan_dns(&dns(), &tun()).unwrap();
        effects.apply_dns(&dns_sha256).unwrap();

        let runtime = effects.runtime();
        let route_requests = runtime.route_requests.borrow();
        assert_eq!(route_requests.len(), 5);
        assert!(route_requests
            .iter()
            .all(|request| request.operation == RouteEffectOperation::Add));
        assert_eq!(
            route_requests
                .iter()
                .map(|request| request.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
        let dns_requests = runtime.dns_requests.borrow();
        assert_eq!(dns_requests.len(), 1);
        assert_eq!(dns_requests[0].0.expected_sha256, dns_sha256);
        assert_eq!(dns_requests[0].1, dns_baseline_sha256(&dns()).unwrap());
    }

    #[test]
    fn unrelated_routes_do_not_block_owned_effects() {
        let mut runtime = runtime();
        runtime.routes.get_mut().routes.push(RouteDelta {
            destination: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)),
            prefix_length: 24,
            gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            interface_index: 9,
            interface_scoped: false,
        });
        let mut effects = NativeNetworkEffects::new(runtime);
        let routes = effects.plan_routes(&baseline(), &tun()).unwrap();
        effects.apply_routes(&routes).unwrap();
        assert_eq!(effects.runtime().route_requests.borrow().len(), 5);
    }

    #[test]
    fn existing_scoped_physical_default_is_left_unowned() {
        let mut runtime = runtime();
        let mut scoped = base_routes().routes[0].clone();
        scoped.interface_scoped = true;
        runtime.routes.get_mut().routes.push(scoped);
        let mut effects = NativeNetworkEffects::new(runtime);
        let routes = effects.plan_routes(&baseline(), &tun()).unwrap();
        assert_eq!(routes.len(), 4);
        assert!(routes.iter().all(|route| !route.interface_scoped));
        effects.apply_routes(&routes).unwrap();
        assert_eq!(effects.runtime().route_requests.borrow().len(), 4);
    }

    #[test]
    fn changed_default_route_and_substituted_plans_produce_no_effects() {
        let mut runtime = runtime();
        runtime.routes.get_mut().routes[0].gateway =
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254)));
        let mut effects = NativeNetworkEffects::new(runtime);
        let routes = effects.plan_routes(&baseline(), &tun()).unwrap();
        assert_eq!(
            effects.apply_routes(&routes),
            Err(NativeNetworkEffectError::Stale)
        );
        let mut substituted = routes;
        substituted.pop();
        assert_eq!(
            effects.apply_routes(&substituted),
            Err(NativeNetworkEffectError::InvalidPlan)
        );
        assert!(effects.runtime().route_requests.borrow().is_empty());
    }

    #[test]
    fn partial_route_failure_can_remove_recorded_set_in_reverse() {
        let runtime = runtime();
        runtime.fail_route_call.set(Some(3));
        let mut effects = NativeNetworkEffects::new(runtime);
        let routes = effects.plan_routes(&baseline(), &tun()).unwrap();
        assert_eq!(
            effects.apply_routes(&routes),
            Err(NativeNetworkEffectError::EffectUnavailable)
        );
        effects.runtime.fail_route_call.set(None);
        effects.remove_routes(&routes).unwrap();
        let requests = effects.runtime().route_requests.borrow();
        assert_eq!(requests[0].operation, RouteEffectOperation::Add);
        assert_eq!(requests[1].operation, RouteEffectOperation::Add);
        assert!(requests[2..]
            .iter()
            .all(|request| request.operation == RouteEffectOperation::Delete));
        assert_eq!(
            requests[2..]
                .iter()
                .map(|request| request.route.clone())
                .collect::<Vec<_>>(),
            routes.iter().rev().cloned().collect::<Vec<_>>()
        );
    }

    #[test]
    fn preexisting_exact_or_conflicting_destination_is_never_claimed_as_owned() {
        let mut snapshot = base_routes();
        let preview =
            plan_tunnel_routes(&baseline(), &tun(), IpAddr::V4(Ipv4Addr::LOCALHOST), true).unwrap();
        snapshot.routes.push(preview[1].clone());
        let mut conflicting_baseline = baseline();
        conflicting_baseline.routes_sha256 = route_snapshot_sha256(&snapshot).unwrap();
        let runtime = MockRuntime {
            routes: RefCell::new(snapshot),
            ..runtime()
        };
        let mut effects = NativeNetworkEffects::new(runtime);
        assert_eq!(
            effects.plan_routes(&conflicting_baseline, &tun()),
            Err(NativeNetworkEffectError::Stale)
        );
        assert!(effects.routes.is_none());
        assert!(effects.runtime().route_requests.borrow().is_empty());
    }

    #[test]
    fn route_conflict_appearing_after_planning_still_blocks_application() {
        let mut effects = NativeNetworkEffects::new(runtime());
        let routes = effects.plan_routes(&baseline(), &tun()).unwrap();
        let mut foreign_route = routes[1].clone();
        foreign_route.interface_index = 23;
        effects
            .runtime
            .routes
            .borrow_mut()
            .routes
            .push(foreign_route);
        assert_eq!(
            effects.apply_routes(&routes),
            Err(NativeNetworkEffectError::Stale)
        );
        assert!(effects.runtime().route_requests.borrow().is_empty());
    }

    #[test]
    fn split_route_preflight_rejects_foreign_tun_without_recording_a_plan() {
        let mut effects = NativeNetworkEffects::new(runtime());
        effects.preflight_split_routes().unwrap();
        effects.runtime.routes.borrow_mut().routes.push(RouteDelta {
            destination: Ipv4Addr::new(128, 0, 0, 0).into(),
            prefix_length: 1,
            gateway: Some(Ipv4Addr::new(198, 18, 0, 1).into()),
            interface_index: 23,
            interface_scoped: false,
        });
        assert_eq!(
            effects.preflight_split_routes(),
            Err(NativeNetworkEffectError::Stale)
        );
        assert!(effects.routes.is_none());
        assert!(effects.runtime().route_requests.borrow().is_empty());
    }

    #[test]
    fn dns_restore_requires_the_owned_applied_hash_as_precondition() {
        let mut effects = NativeNetworkEffects::new(runtime());
        let planned = effects.plan_dns(&dns(), &tun()).unwrap();
        effects.apply_dns(&planned).unwrap();
        effects.restore_dns(&dns(), &planned).unwrap();
        let requests = effects.runtime().dns_requests.borrow();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].1, planned);
        assert_eq!(
            requests[1].0.expected_sha256,
            dns_baseline_sha256(&dns()).unwrap()
        );
    }
}
