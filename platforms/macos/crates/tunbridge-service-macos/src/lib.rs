//! Monterey-compatible macOS privileged service/XPC boundary.
//!
//! M3A defines the endpoint, typed transport, protocol/identity policy, and
//! dry-run recovery plan without connecting to or registering a privileged
//! helper on the development machine.

#[cfg(target_os = "macos")]
pub mod baseline;
#[cfg(all(target_os = "macos", feature = "macos-engine-process"))]
pub mod client_family;
#[cfg(target_os = "macos")]
pub mod client_policy;
pub mod client_session;
#[cfg(all(target_os = "macos", feature = "macos-controller-client"))]
pub mod controller;
#[cfg(all(target_os = "macos", feature = "macos-controller-client"))]
pub mod controller_owner;
pub mod darwin_state;
pub mod dispatcher;
pub mod dns_effect;
#[cfg(target_os = "macos")]
pub mod dns_store;
#[cfg(all(target_os = "macos", feature = "macos-dns-effects"))]
pub mod dns_writer;
pub mod engine_config;
#[cfg(all(target_os = "macos", feature = "macos-engine-process"))]
pub mod engine_process;
pub mod identity;
#[cfg(target_os = "macos")]
pub mod journal;
pub mod lifecycle_host;
pub mod lifecycle_plan;
#[cfg(all(target_os = "macos", feature = "macos-xpc-listener"))]
pub mod listener_policy;
#[cfg(target_os = "macos")]
pub mod native;
#[cfg(all(target_os = "macos", feature = "macos-native-lifecycle"))]
pub mod native_backend;
#[cfg(all(target_os = "macos", feature = "macos-engine-process"))]
pub mod native_engine;
#[cfg(all(target_os = "macos", feature = "macos-native-network-effects"))]
pub mod native_network_effects;
#[cfg(all(target_os = "macos", feature = "macos-controller-client"))]
pub mod native_observability;
#[cfg(all(target_os = "macos", feature = "macos-engine-process"))]
pub mod native_start;
#[cfg(all(target_os = "macos", feature = "macos-controller-client"))]
pub mod native_tun;
pub mod observability;
pub mod observer;
pub mod protocol;
pub mod route_effect;
pub mod route_message;
#[cfg(all(target_os = "macos", feature = "macos-route-effects"))]
pub mod route_socket;
#[cfg(all(target_os = "macos", feature = "macos-xpc-listener"))]
pub mod service_bootstrap;
pub mod traffic_lock;
pub mod tun_attribution;
#[cfg(all(target_os = "macos", feature = "macos-engine-process"))]
pub mod upstream_owner;
#[cfg(all(target_os = "macos", feature = "macos-engine-process"))]
pub mod upstream_route_probe;
pub mod xpc_client;
#[cfg(target_os = "macos")]
pub mod xpc_listener;
#[cfg(target_os = "macos")]
pub mod xpc_session;

pub use xpc_client::MacosXpcTransport;

pub const SERVICE_HOST_ID: &str = "launchd-xpc";
pub const MACH_SERVICE_NAME: &str = "com.tunbridge.desktop.helper";
pub const PROTOCOL_VERSION: u16 = tunbridge_service::protocol::PROTOCOL_VERSION;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_identity_and_protocol_are_fixed() {
        assert_eq!(SERVICE_HOST_ID, "launchd-xpc");
        assert_eq!(MACH_SERVICE_NAME, "com.tunbridge.desktop.helper");
        assert_eq!(PROTOCOL_VERSION, 4);
    }
}
