use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub enum MetricOrderTypeBackend {
    Capture,
    Remediate,
    Rollback,
}