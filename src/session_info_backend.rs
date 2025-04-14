use blake3::Hasher;
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

impl SessionInfoBackend {
    pub fn uid(&self, language: &str) -> String {
        let mut hasher = Hasher::new();
        hasher.update(language.as_bytes());
        hasher.update(self.dst_ip.as_bytes());
        hasher.update(self.dst_port.to_string().as_bytes());
        hasher.update(self.protocol.as_bytes());
        if let Some(dst_domain) = &self.dst_domain {
            hasher.update(dst_domain.as_bytes());
        }
        if let Some(dst_asn_number) = self.dst_asn_number {
            hasher.update(dst_asn_number.to_string().as_bytes());
        }
        if let Some(dst_asn_country) = &self.dst_asn_country {
            hasher.update(dst_asn_country.as_bytes());
        }
        if let Some(dst_asn_owner) = &self.dst_asn_owner {
            hasher.update(dst_asn_owner.as_bytes());
        }
        hasher.update(self.criticality.as_bytes());
        if let Some(dst_service) = &self.dst_service {
            hasher.update(dst_service.as_bytes());
        }
        if let Some(l7_process_name) = &self.l7_process_name {
            hasher.update(l7_process_name.as_bytes());
        }
        if let Some(l7_process_path) = &self.l7_process_path {
            hasher.update(l7_process_path.as_bytes());
        }
        if let Some(l7_process_user) = &self.l7_process_user {
            hasher.update(l7_process_user.as_bytes());
        }
        hasher.finalize().to_hex().to_string()
    }
}
