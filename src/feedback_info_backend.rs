use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackInfoBackend {
    pub core_info: String,
    pub threat_model_name: String,
    pub threat_model_date: String,
    pub threat_model_signature: String,
    pub stars: f64,
    pub helper_state: String,
    pub os_name: String,
    pub os_version: String,
    pub context: String,
    pub note: String,
    pub email: String,
    pub app_log: String,
    pub helper_log: String,
}
