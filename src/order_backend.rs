use crate::order_type_backend::MetricOrderTypeBackend;
use serde::{Deserialize, Serialize};

// Compact version of MetricOrderResult to transmit to the backend
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct MetricOrderResultBackend {
    pub metricname: String,
    pub ordertype: MetricOrderTypeBackend,
    pub timestamp: String,
    pub success: bool,
    pub validated: bool,
    pub output: String,
}
