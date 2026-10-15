//! Linux privileged service host.

pub const SERVICE_HOST_ID: &str = "systemd";

#[cfg(target_os = "linux")]
mod lifecycle;
#[cfg(target_os = "linux")]
mod observability;
#[cfg(target_os = "linux")]
mod status_host;
#[cfg(target_os = "linux")]
mod transport;

#[cfg(target_os = "linux")]
pub use lifecycle::{
    LifecycleFailure, LinuxLifecycle, OwnedEngineRecord, DATA_ROOT, ENGINE_PATH, TUN_DEVICE,
};
#[cfg(target_os = "linux")]
pub use status_host::{
    serve_connection, LinuxClientError, LinuxServiceClient, LinuxServiceContext, LinuxStatusClient,
};
#[cfg(target_os = "linux")]
pub use transport::{
    PeerCredentials, UnixServiceConnection, UnixServiceListener, UnixServiceTransport,
    SERVICE_SOCKET_PATH,
};
