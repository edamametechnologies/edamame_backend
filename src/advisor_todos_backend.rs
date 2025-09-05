use blake3::Hasher;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdviceTypeBackend {
    Policy,
    Threat,
    NetworkPort,
    NetworkSession,
    PwnedBreach,
    Configure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisorAdviceBackend {
    pub advice_type: AdviceTypeBackend,
    pub advice_details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdvicePriorityBackend {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisorTodoBackend {
    pub advice: AdvisorAdviceBackend,
    pub priority: AdvicePriorityBackend,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisorTodosBackend {
    pub system_overview: String,
    pub todos: Vec<AdvisorTodoBackend>,
    pub email: Option<String>,
}

impl AdvisorTodosBackend {
    pub fn uid(&self, language: &str) -> String {
        let mut hasher = Hasher::new();
        hasher.update(language.as_bytes());
        hasher.update(self.system_overview.as_bytes());
        hasher.update(format!("{:?}", self.todos).as_bytes());
        hasher.finalize().to_hex().to_string()
    }
}
