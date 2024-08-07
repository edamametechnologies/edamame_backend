use crate::lanscan_port_info_backend::PortInfoBackend;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DislikeDeviceInfoBackend {
    pub device_type: String,
    pub open_ports: Vec<PortInfoBackend>,
    pub mdns_services: Vec<String>,
    pub device_vendor: String,
    pub hostname: String,
    /// User comment
    pub note: String,
}
