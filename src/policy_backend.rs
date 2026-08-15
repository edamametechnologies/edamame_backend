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

    // What the device satisfied, mirroring `reason`.
    //
    // Without this, a compliant device is told it complies with no way to see
    // against what: `reason` describes violations only, so a passing policy
    // returns an empty list and `MinScore(60)` passing at 78 cannot say so.
    //
    // A rule that could not be evaluated belongs in neither list -- a Groups
    // rule short-circuits before the others run, and a Tags rule finds no
    // compliance figure for a tag the device does not carry. Folding those
    // into "passed" would credit the device for a rule that never ran.
    //
    // The Hub owns its own deploy schedule, so responses predating the field
    // must still deserialize; an absent list means "not reported".
    #[serde(default)]
    pub passed_rules: Vec<PassedRuleBackend>,
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
        failed_security_checks: Vec<String>,

        // Security checks carrying the tag that did pass.
        //
        // Together with `failed_security_checks` this is the full set of
        // checks carrying `required`, so `passed / (passed + failed)` restates
        // `got`. A check whose status is unknown counts as failed and belongs
        // in `failed_security_checks`: that is how the ratio itself is
        // computed, and putting unknowns in neither list would leave the two
        // lists unable to reconcile with `got`, so a client rendering
        // "12 of 15 passed" beside a 60% ratio would contradict itself.
        //
        // The Hub owns its own deploy schedule, so responses predating the
        // field must still deserialize instead of failing the whole policy
        // payload; an absent list means "not reported", rendered as empty.
        #[serde(default)]
        passed_security_checks: Vec<String>,
    },
}

// What a device satisfied, mirroring `ReasonBackend` variant for variant so a
// client renders a pass and a failure through one code path.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub enum PassedRuleBackend {
    // Minimum score was respected
    MinScoreRespectedBackend {
        // Required overall score
        required: u8,

        // Device's reported overall score
        got: u8,
    },

    // Every required security check passed
    SecurityChecksPassedBackend {
        // The rule's required checks. All of them passed -- that is what makes
        // this a pass -- so this is deliberately the required set and not the
        // device's full passed set, which also carries every unrelated check
        // the device reports and would make the pass look far broader than the
        // rule.
        passed: Vec<String>,
    },

    // Tag compliance was respected
    TagsRespectedBackend {
        // Required tag
        required: String,

        // Device's compliance ratio for tag
        got: f64,

        // Security checks carrying the tag that passed. Same unknown-counts-as
        // -failed convention as `ReasonBackend::TagsNotRespectedBackend`, so a
        // rule can clear its threshold with this list shorter than the tag's
        // full check set.
        passed_security_checks: Vec<String>,
    },
}
