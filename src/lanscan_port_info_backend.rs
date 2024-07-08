use crate::lanscan_vulnerability_info_backend::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Ord, Eq, PartialEq, PartialOrd)]
pub struct PortInfoBackend {
    pub port: u16,
    pub protocol: String,
    pub service: String,
    pub banner: String,
    pub vulnerabilities: Vec<VulnerabilityInfoBackend>,
}
