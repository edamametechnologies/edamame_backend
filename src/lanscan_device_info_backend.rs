use crate::lanscan_port_info_backend::PortInfoBackend;
use crate::lanscan_vulnerability_info_backend::VulnerabilityInfoBackend;
use blake3::Hasher;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeviceInfoBackend {
    pub mdns_services: Vec<String>,
    pub device_vendor: String,
    pub vulnerabilities: Vec<VulnerabilityInfoBackend>,
    pub open_ports: Vec<PortInfoBackend>,
}

impl DeviceInfoBackend {
    pub fn uid(&self, language: &str) -> String {
        let mut hasher = Hasher::new();
        hasher.update(language.as_bytes());
        hasher.update(self.device_vendor.as_bytes());
        // Use a pipe delimiter to avoid collisions
        hasher.update(self.mdns_services.join("|").as_bytes());
        // Vulnerabilities have a possibility of change, so we include it
        let mut sorted_vulnerabilities = self.vulnerabilities.clone();
        sorted_vulnerabilities.sort_by(|a, b| a.name.cmp(&b.name));
        hasher.update(format!("{sorted_vulnerabilities:?}").as_bytes());
        let mut sorted_open_ports = self.open_ports.clone();
        sorted_open_ports.sort_by(|a, b| a.port.cmp(&b.port));
        hasher.update(format!("{sorted_open_ports:?}").as_bytes());
        hasher.finalize().to_hex().to_string()
    }
}
