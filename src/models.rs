use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy)]
pub struct TimingProfile {
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub retries: u32,
}

#[derive(Debug, Clone)]
pub struct OpenPort {
    pub ip: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScriptResult {
    pub script: String,
    pub status: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortReport {
    pub ip: IpAddr,
    pub port: u16,
    pub state: &'static str,
    pub service_name: &'static str,
    pub scripts: Vec<ScriptResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WasmScanInput {
    pub ip: String,
    pub port: u16,
}
