use crate::platform::model::NetSnapshot;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RecoveryCheck {
    pub adapter_gone: bool,
    pub routes_clean: bool,
    pub added_routes: Vec<String>,
}

fn is_tun_related(route: &str, tun_name: &str) -> bool {
    route.contains(tun_name) || route.starts_with("198.18.") || route.starts_with("198.19.")
}

/// Recovery assertion: after teardown the tun adapter must be
/// gone, no tun-name/fake-ip routes may remain, and no route may exist that was
/// absent from the baseline.
pub fn check_recovery(
    baseline: &NetSnapshot,
    current: &NetSnapshot,
    tun_name: &str,
    adapter_present: bool,
) -> RecoveryCheck {
    let tun_rows: Vec<String> = current
        .routes
        .iter()
        .filter(|r| is_tun_related(r, tun_name))
        .cloned()
        .collect();

    let added: Vec<String> = current
        .routes
        .iter()
        .filter(|r| !baseline.routes.contains(*r))
        .cloned()
        .collect();

    RecoveryCheck {
        adapter_gone: !adapter_present,
        routes_clean: tun_rows.is_empty() && added.is_empty(),
        added_routes: added,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::model::NetSnapshot;

    fn snap(routes: &[&str], adapters: &[&str]) -> NetSnapshot {
        NetSnapshot {
            routes: routes.iter().map(|s| s.to_string()).collect(),
            adapters: adapters.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn clean_when_back_to_baseline_and_adapter_gone() {
        let base = snap(&["0.0.0.0/0|Ethernet|192.168.1.1"], &["Ethernet"]);
        let now = base.clone();
        let r = check_recovery(&base, &now, "tunbridge", false);
        assert!(r.adapter_gone);
        assert!(r.routes_clean);
        assert!(r.added_routes.is_empty());
    }

    #[test]
    fn dirty_when_tun_route_remains() {
        let base = snap(&["0.0.0.0/0|Ethernet|192.168.1.1"], &["Ethernet"]);
        let now = snap(
            &[
                "0.0.0.0/0|Ethernet|192.168.1.1",
                "1.0.0.0/8|tunbridge|0.0.0.0",
            ],
            &["Ethernet", "tunbridge"],
        );
        let r = check_recovery(&base, &now, "tunbridge", true);
        assert!(!r.adapter_gone);
        assert!(!r.routes_clean);
        assert!(r.added_routes.iter().any(|x| x.contains("tunbridge")));
    }

    #[test]
    fn dirty_when_fakeip_route_remains() {
        let base = snap(&["0.0.0.0/0|Ethernet|192.168.1.1"], &["Ethernet"]);
        let now = snap(
            &[
                "0.0.0.0/0|Ethernet|192.168.1.1",
                "198.18.0.0/15|SomeIface|0.0.0.0",
            ],
            &["Ethernet"],
        );
        let r = check_recovery(&base, &now, "tunbridge", false);
        assert!(!r.routes_clean);
    }
}
