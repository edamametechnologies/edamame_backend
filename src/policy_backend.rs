use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct PoliciesStatusBackend {
    pub name: String,
    pub passed: bool,
    pub reason: Vec<ReasonBackend>,
    pub providers: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub enum ReasonBackend {
    /// Minimum score has not been respected
    MinScoreNotRespected {
        /// Required overall score
        required: u8,

        // Device's reported overall score
        got: u8,
    },

    /// At least one required security check does not pass
    SecurityChecksNotPassed {
        /// Required security checks
        required: Vec<String>,

        // Device's passed security checks (subset of required only, not all the passed)
        passed: Vec<String>,

        // Device's failed security checks (subset of required only, not all the failed)
        failed: Vec<String>,
    },

    //
    TagsNotRespected {
        /// failed tag
        required: String,

        // Device's ratio tag
        got: f64,
    },
}
