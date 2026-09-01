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

    // An AI governance whitelist is not satisfied.
    AiWhitelistNotSatisfiedBackend {
        // The list the rule names.
        whitelist_id: String,

        // Things the device reports that the list does not permit.
        not_permitted: Vec<AiWhitelistItemBackend>,

        // Failing AI checks the list does not accept.
        not_accepted: Vec<String>,

        // False when the device shared no AI detail, which is itself the
        // denial. Sent so the client can say "enable AI detail sharing"
        // rather than listing nothing and leaving the user with no action.
        evidence_shared: bool,
    },
}

// One thing an AI whitelist permits, accepts, or does not permit.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct AiWhitelistItemBackend {
    pub kind: String,
    pub key: String,
    pub scope: String,
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

    // An AI governance whitelist was satisfied.
    AiWhitelistSatisfiedBackend {
        // The list that was satisfied. Kept alongside the details: it is the
        // stable reference, and the name can be edited at any time.
        whitelist_id: String,

        // Human label, as it reads right now.
        name: String,

        // Kinds this list restricts. Anything of these kinds not in `allowed`
        // would be a violation; a kind absent here is not policed at all.
        enforced_kinds: Vec<String>,

        // What the list permits to exist.
        allowed: Vec<AiWhitelistItemBackend>,

        // Findings the list forgives. A different statement from `allowed`:
        // permitting a thing to exist and accepting a finding about it are
        // not the same, and one never implies the other.
        accepted: Vec<AiWhitelistItemBackend>,

        // RFC3339, absent when the list never expires. Sent so a client can
        // warn before a permission lapses rather than after.
        expires_at: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    // The Hub emits externally tagged variants; lock the wire shape of the
    // AI whitelist reasons so a Hub deploy cannot break policy parsing.
    #[test]
    fn ai_whitelist_reasons_deserialize_from_hub_shape() {
        let json = r#"{
          "policies": [{
            "name": "AI governance",
            "passed": false,
            "providers": ["hub"],
            "reason": [{"AiWhitelistNotSatisfiedBackend": {
              "whitelist_id": "wl-1",
              "not_permitted": [{"kind": "mcp_server", "key": "filesystem", "scope": "cursor"}],
              "not_accepted": ["unsecured_claude_code"],
              "evidence_shared": true
            }}],
            "passed_rules": [{"AiWhitelistSatisfiedBackend": {
              "whitelist_id": "wl-2",
              "name": "Engineering AI baseline",
              "enforced_kinds": ["mcp_server", "agent"],
              "allowed": [{"kind": "agent", "key": "claude_code", "scope": "host"}],
              "accepted": [],
              "expires_at": null
            }}]
          }]
        }"#;
        let parsed: PoliciesStatusResponseBackend = serde_json::from_str(json).expect("parse");
        let policy = &parsed.policies[0];
        match &policy.reason[0] {
            ReasonBackend::AiWhitelistNotSatisfiedBackend {
                whitelist_id,
                not_permitted,
                not_accepted,
                evidence_shared,
            } => {
                assert_eq!(whitelist_id, "wl-1");
                assert_eq!(not_permitted[0].key, "filesystem");
                assert_eq!(not_accepted, &vec!["unsecured_claude_code".to_string()]);
                assert!(evidence_shared);
            }
            other => panic!("unexpected reason {other:?}"),
        }
        match &policy.passed_rules[0] {
            PassedRuleBackend::AiWhitelistSatisfiedBackend {
                name,
                enforced_kinds,
                expires_at,
                ..
            } => {
                assert_eq!(name, "Engineering AI baseline");
                assert_eq!(enforced_kinds.len(), 2);
                assert!(expires_at.is_none());
            }
            other => panic!("unexpected passed rule {other:?}"),
        }
    }
}
