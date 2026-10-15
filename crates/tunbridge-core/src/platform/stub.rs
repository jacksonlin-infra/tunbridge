use crate::platform::model::{Listener, NetSnapshot};
use crate::platform::{NetworkInspector, PortProber, Privilege, ProcessLister};
use crate::{CoreError, Result};
use std::net::TcpStream;
use std::time::Duration;

pub struct StubPrivilege;
impl Privilege for StubPrivilege {
    fn is_elevated(&self) -> bool {
        false
    }
}

pub struct TcpPortProber;
impl PortProber for TcpPortProber {
    fn is_open(&self, host: &str, port: u16, timeout: Duration) -> bool {
        match format!("{host}:{port}").parse() {
            Ok(addr) => TcpStream::connect_timeout(&addr, timeout).is_ok(),
            Err(_) => false,
        }
    }
}

pub struct StubProcessLister;
impl ProcessLister for StubProcessLister {
    fn listeners(&self) -> Result<Vec<Listener>> {
        Err(CoreError::Unsupported(
            "process listing only implemented on windows".into(),
        ))
    }
}

pub struct StubNetworkInspector;
impl NetworkInspector for StubNetworkInspector {
    fn snapshot(&self) -> Result<NetSnapshot> {
        Err(CoreError::Unsupported(
            "network inspection only implemented on windows".into(),
        ))
    }
    fn adapter_exists(&self, _name: &str) -> bool {
        false
    }
    fn flush_dns(&self) -> Result<()> {
        Err(CoreError::Unsupported("windows only".into()))
    }
    fn remove_routes_for(&self, _tun_name: &str) -> Result<()> {
        Err(CoreError::Unsupported("windows only".into()))
    }
}
