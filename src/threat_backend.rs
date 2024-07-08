use serde::{Deserialize, Serialize};

// Only Strings in order to easily read the JSON array
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ThreatMetricEducationJSONBackend {
    pub locale: String,
    pub class: String,
    pub target: String,
}

// Only Strings in order to easily read the JSON array
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ThreatMetricImplementationJSONBackend {
    pub system: String,
    pub minversion: i32,
    pub maxversion: i32,
    pub class: String,
    pub elevation: String,
    pub target: String,
    pub education: Vec<ThreatMetricEducationJSONBackend>,
}

// Only Strings in order to easily read the JSON array
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ThreatMetricDescriptionJSONBackend {
    pub locale: String,
    pub title: String,
    pub summary: String,
}

// Only Strings in order to easily read the JSON array
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ThreatMetricJSONBackend {
    pub name: String,
    pub metrictype: String,
    pub dimension: String,
    pub severity: i32,
    pub scope: String,
    pub tags: Vec<String>,
    pub description: Vec<ThreatMetricDescriptionJSONBackend>,
    pub implementation: ThreatMetricImplementationJSONBackend,
    pub remediation: ThreatMetricImplementationJSONBackend,
    pub rollback: ThreatMetricImplementationJSONBackend,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ThreatMetricsJSONBackend {
    pub name: String,
    pub extends: String,
    pub date: String,
    pub signature: String,
    pub metrics: Vec<ThreatMetricJSONBackend>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, PartialOrd)]
pub enum ThreatStatusBackend {
    Active,
    Inactive,
    Unknown,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ThreatMetricBackend {
    pub metric: ThreatMetricJSONBackend,
    // Can be empty
    pub timestamp: String,
    pub status: ThreatStatusBackend,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ThreatMetricsBackend {
    pub metrics: Vec<ThreatMetricBackend>,
    // Copied field from the JSON threat model
    pub name: String,
    pub extends: String,
    pub date: String,
    pub signature: String,
}
