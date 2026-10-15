use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Listener {
    pub local_port: u16,
    pub pid: u32,
    pub process_name: String,
    pub process_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetSnapshot {
    pub routes: Vec<String>,
    pub adapters: Vec<String>,
}
