use blake3::Hasher;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfoBackend {
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub domain: Option<String>,
    pub asn_number: Option<u32>,
    pub asn_country: Option<String>,
    pub asn_owner: Option<String>,
    pub criticality: String,
    pub service: Option<String>,
    pub l7_process_name: Option<String>,
    pub l7_process_path: Option<String>,
    pub l7_process_user: Option<String>,
}

impl SessionInfoBackend {
    pub fn uid(&self, language: &str) -> String {
        let mut hasher = Hasher::new();
        hasher.update(language.as_bytes());
        hasher.update(self.ip.as_bytes());
        hasher.update(self.port.to_string().as_bytes());
        hasher.update(self.protocol.as_bytes());
        if let Some(domain) = &self.domain {
            hasher.update(domain.as_bytes());
        }
        if let Some(asn_number) = self.asn_number {
            hasher.update(asn_number.to_string().as_bytes());
        }
        if let Some(asn_country) = &self.asn_country {
            hasher.update(asn_country.as_bytes());
        }
        if let Some(asn_owner) = &self.asn_owner {
            hasher.update(asn_owner.as_bytes());
        }
        hasher.update(self.criticality.as_bytes());
        if let Some(service) = &self.service {
            hasher.update(service.as_bytes());
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
