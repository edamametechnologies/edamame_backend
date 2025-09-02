use blake3::Hasher;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisorAdviceBackend {
    pub advice_type: String,
    pub advice_details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdvisorPriorityBackend {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisorTodoBackend {
    pub advice: Vec<AdvisorAdviceBackend>,
    pub priority: AdvisorPriorityBackend,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisorTodosBackend {
    pub todos: Vec<AdvisorTodoBackend>,
}

impl AdvisorTodosBackend {
    pub fn uid(&self, language: &str) -> String {
        let mut hasher = Hasher::new();
        hasher.update(language.as_bytes());
        hasher.update(format!("{:?}", self.todos).as_bytes());
        hasher.finalize().to_hex().to_string()
    }
}
