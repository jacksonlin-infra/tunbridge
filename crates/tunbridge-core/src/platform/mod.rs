pub mod model;

#[cfg(not(windows))]
pub mod stub;
#[cfg(windows)]
#[path = "../../../../platforms/windows/crates/tunbridge-platform-windows/src/imp/core.rs"]
pub mod windows;

use crate::Result;
use model::{Listener, NetSnapshot};
use std::time::Duration;

pub trait Privilege {
    fn is_elevated(&self) -> bool;
}

pub trait PortProber {
    fn is_open(&self, host: &str, port: u16, timeout: Duration) -> bool;
}

pub trait ProcessLister {
    fn listeners(&self) -> Result<Vec<Listener>>;
}

pub trait NetworkInspector {
    fn snapshot(&self) -> Result<NetSnapshot>;
    fn adapter_exists(&self, name: &str) -> bool;
    fn flush_dns(&self) -> Result<()>;
    fn remove_routes_for(&self, tun_name: &str) -> Result<()>;
}

#[cfg(windows)]
pub fn default_privilege() -> Box<dyn Privilege> {
    Box::new(windows::WinPrivilege)
}
#[cfg(windows)]
pub fn default_port_prober() -> Box<dyn PortProber> {
    Box::new(windows::TcpPortProber)
}
#[cfg(windows)]
pub fn default_process_lister() -> Box<dyn ProcessLister> {
    Box::new(windows::WinProcessLister)
}
#[cfg(windows)]
pub fn default_network_inspector() -> Box<dyn NetworkInspector> {
    Box::new(windows::WinNetworkInspector)
}

#[cfg(not(windows))]
pub fn default_privilege() -> Box<dyn Privilege> {
    Box::new(stub::StubPrivilege)
}
#[cfg(not(windows))]
pub fn default_port_prober() -> Box<dyn PortProber> {
    Box::new(stub::TcpPortProber)
}
#[cfg(not(windows))]
pub fn default_process_lister() -> Box<dyn ProcessLister> {
    Box::new(stub::StubProcessLister)
}
#[cfg(not(windows))]
pub fn default_network_inspector() -> Box<dyn NetworkInspector> {
    Box::new(stub::StubNetworkInspector)
}
