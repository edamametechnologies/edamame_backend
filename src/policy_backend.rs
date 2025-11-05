use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct PoliciesStatusResponseBackend {
    pub policies: Vec<PoliciesStatusBackend>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct PoliciesStatusBackend {
    pub name: String,
    pub passed: bool,
    pub reason: Vec<ReasonBackend>,
    pub providers: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub enum ReasonBackend {
    // Minimum score has not been respected
    MinScoreNotRespectedBackend {
        // Required overall score
        required: u8,

        // Device's reported overall score
        got: u8,
    },

    // At least one required security check does not pass
    SecurityChecksNotPassedBackend {
        // Required security checks
        required: Vec<String>,

        // Device's passed security checks (subset of required only, not all the passed)
        passed: Vec<String>,

        // Device's failed security checks (subset of required only, not all the failed)
        failed: Vec<String>,
    },

    // Failed tag
    TagsNotRespectedBackend {
        // Required tag
        required: String,

        // Device's compliance ratio for tag
        got: f64,

        // Security checks that were not respected
        // For backward compatibility, this field is optional and defaults to an empty vector
        #[serde(default)]
        failed_security_checks: Vec<String>,
    },
}
