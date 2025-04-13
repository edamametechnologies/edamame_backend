use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfoBackend {
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub dst_domain: Option<String>,
    pub dst_asn_number: Option<u32>,
    pub dst_asn_country: Option<String>,
    pub dst_asn_owner: Option<String>,
    pub criticality: String,
    pub dst_service: Option<String>,
    pub l7_process_name: Option<String>,
    pub l7_process_path: Option<String>,
    pub l7_process_user: Option<String>,
}
