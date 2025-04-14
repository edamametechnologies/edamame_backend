use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub enum PwnedCriticalityBackend {
    Unknown,
    Low,
    Medium,
    High,
}

impl Display for PwnedCriticalityBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PwnedCriticalityBackend::Unknown => write!(f, "Unknown"),
            PwnedCriticalityBackend::Low => write!(f, "Low"),
            PwnedCriticalityBackend::Medium => write!(f, "Medium"),
            PwnedCriticalityBackend::High => write!(f, "High"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq)]
pub struct BreachDetailBackend {
    pub name: String,
    pub title: String,
    pub domain: String,
    pub breachdate: String,
    pub count: u64,
    pub description: String,
    // Invariant
    pub short_data_classes: Vec<String>,
    pub data_classes: Vec<String>,
    pub is_verified: bool,
    pub is_sensitive: bool,
    pub criticality: PwnedCriticalityBackend,
}

impl BreachDetailBackend {
    pub fn uid(&self, language: &str, user_skills: &str) -> String {
        let mut hasher = Hasher::new();
        hasher.update(language.as_bytes());
        hasher.update(user_skills.as_bytes());
        hasher.update(self.name.as_bytes());
        // Description has a possibility of change, so we include it
        hasher.update(self.description.as_bytes());
        hasher.finalize().to_hex().to_string()
    }
}
