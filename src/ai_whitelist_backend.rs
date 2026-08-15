use serde::{Deserialize, Serialize};

/// Client-side mirror of the Hub's `GET /api/ai-whitelists` response.
///
/// An admin defines in the Hub what AI posture is acceptable on their fleet; a
/// device asks whether it complies. The Hub answers by matching the device's
/// most recent detail bundle (see [`crate::detail_backend`]) against the
/// domain's whitelists, so this endpoint is the read side of the same
/// `FailureCauseBackend` model the client already emits on the score report.
///
/// Two properties of the Hub contract shape everything below:
///
/// - **`kind` is open.** A selector kind the Hub does not recognise is
///   displayed, never dropped, so a new [`crate::detail_backend::FailureSelectorKindBackend`]
///   ships without a Hub release. Kinds are therefore `String` here too --
///   never parse one back into the closed Rust enum for display purposes.
/// - **Signature resolution is live-table only.** `details` exists on the live
///   device-report table but not on the history table, so a signature the Hub
///   can only resolve from history 404s rather than answering from no evidence.
///   An absent answer must never render as "compliant" -- that is why the core
///   caches `Option<AiWhitelistStatus>` and the UI distinguishes "not
///   evaluated" from `fits: false`.
///
/// Wire casing is camelCase: this endpoint was written Hub-side without an
/// `edamame_backend` type, so we match what it already serves rather than
/// asking for a rename.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AiWhitelistStatusBackend {
    /// The device satisfies every whitelist that covers it. False when any
    /// covering whitelist reports a violation, and also false when the device
    /// is covered by nothing (nothing has vouched for it).
    pub fits: bool,
    /// How many of the domain's whitelists cover this device.
    pub covered_by: u32,
    /// The device shared its AI detail bundle. When false the Hub is matching
    /// against no evidence and cannot derive a pass -- consent was withheld,
    /// or the client predates the detail domain.
    pub evidence_shared: bool,
    /// Emit-time capping dropped causes from the evidence. A truncated bundle
    /// can never derive a pass: the dropped causes are unknown, so "everything
    /// is covered" is unprovable.
    pub truncated: bool,
    /// Flattened union of everything blocking a pass, across all covering
    /// whitelists. Convenience for a summary row; per-whitelist detail lives
    /// in [`AiWhitelistBackend::not_permitted`] / `not_accepted`.
    pub violations: Vec<AiWhitelistSelectorBackend>,
    /// Every whitelist the Hub evaluated for this device.
    pub whitelists: Vec<AiWhitelistBackend>,
}

impl AiWhitelistStatusBackend {
    /// No whitelist covers this device, so the domain has expressed no opinion
    /// about it. Distinct from a failing evaluation: there is nothing to fix.
    pub fn is_uncovered(&self) -> bool {
        self.covered_by == 0
    }

    /// The Hub answered from incomplete evidence, so `fits` carries no weight
    /// either way and must not be rendered as a verdict.
    pub fn evidence_is_inconclusive(&self) -> bool {
        !self.evidence_shared || self.truncated
    }
}

/// One admin-defined whitelist and how this device measures against it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AiWhitelistBackend {
    pub whitelist_id: String,
    /// Operator-chosen display name.
    pub name: String,
    /// Selector kinds this whitelist governs. A kind absent from this list is
    /// not enforced, so an observation of that kind can never be a violation
    /// -- which is why `allowed` alone is not enough to read the verdict.
    ///
    /// `#[serde(default)]`: the Hub deploys on its own schedule and this field
    /// post-dates the first `/api/ai-whitelists` rollout. Absent means "not
    /// reported"; render the enforced set as unknown rather than as empty.
    #[serde(default)]
    pub enforced_kinds: Vec<String>,
    /// Observations the admin permits outright, for the enforced kinds.
    ///
    /// `#[serde(default)]` for the same rollout reason as `enforced_kinds`.
    #[serde(default)]
    pub allowed: Vec<AiWhitelistSelectorBackend>,
    /// Failure causes the admin accepts even though the underlying check fails.
    ///
    /// `#[serde(default)]` for the same rollout reason as `enforced_kinds`.
    #[serde(default)]
    pub accepted: Vec<AiWhitelistSelectorBackend>,
    /// This whitelist applies to this device.
    pub covered: bool,
    /// This device satisfies this whitelist. Only meaningful when `covered`.
    pub fits: bool,
    /// Observations of an enforced kind that `allowed` does not permit.
    pub not_permitted: Vec<AiWhitelistSelectorBackend>,
    /// Failing checks whose causes `accepted` does not cover.
    pub not_accepted: Vec<AiWhitelistUncoveredCheckBackend>,
}

impl AiWhitelistBackend {
    /// Total blocking observations, for a count badge.
    pub fn violation_count(&self) -> usize {
        self.not_permitted.len()
            + self
                .not_accepted
                .iter()
                .map(|c| c.causes.len())
                .sum::<usize>()
    }
}

/// One named observation: a [`crate::detail_backend::FailureSelectorBackend`]
/// with its subject folded in.
///
/// The detail bundle keeps `scope` on the cause because a cause groups
/// alternative names for one condition; here each selector is already resolved
/// against a subject, so the two travel together.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AiWhitelistSelectorBackend {
    /// Open vocabulary -- see [`crate::detail_backend::FailureSelectorKindBackend`]
    /// for the kinds this client emits. Display an unrecognised kind verbatim.
    pub kind: String,
    /// Normalized stable key (process basename, MCP server name, secret label).
    pub key: String,
    /// Subject this observation belongs to (agent slug). Empty when host-global.
    pub scope: String,
}

impl AiWhitelistSelectorBackend {
    /// Display token: `kind:key`, matching
    /// [`crate::detail_backend::FailureSelectorBackend::token`].
    pub fn token(&self) -> String {
        format!("{}:{}", self.kind, self.key)
    }
}

/// A failing check whose causes the whitelist does not accept.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AiWhitelistUncoveredCheckBackend {
    /// Metric name of the failing check (`agents_with_blast_radius`, ...).
    pub check: String,
    /// The uncovered causes, already resolved to selector + subject.
    pub causes: Vec<AiWhitelistSelectorBackend>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape the Hub serves today, verbatim from the contract notes.
    const DEPLOYED_RESPONSE: &str = r#"{
        "fits": false,
        "coveredBy": 1,
        "evidenceShared": true,
        "truncated": false,
        "violations": [{ "kind": "mcp_server", "key": "gojiberry", "scope": "cursor" }],
        "whitelists": [{
            "whitelistId": "076093c3-0000-0000-0000-000000000000",
            "name": "quentin test",
            "enforcedKinds": ["mcp_server"],
            "allowed":  [{ "kind": "mcp_server", "key": "postman", "scope": "" }],
            "accepted": [{ "kind": "critical_process", "key": "ssh", "scope": "cursor" }],
            "covered": true,
            "fits": false,
            "notPermitted": [{ "kind": "mcp_server", "key": "gojiberry", "scope": "cursor" }],
            "notAccepted": [{
                "check": "agents_with_blast_radius",
                "causes": [{ "kind": "critical_process", "key": "ssh", "scope": "cursor" }]
            }]
        }]
    }"#;

    #[test]
    fn deserializes_deployed_response() {
        let status: AiWhitelistStatusBackend =
            serde_json::from_str(DEPLOYED_RESPONSE).expect("deserialize");
        assert!(!status.fits);
        assert_eq!(status.covered_by, 1);
        assert!(status.evidence_shared);
        assert!(!status.is_uncovered());
        assert!(!status.evidence_is_inconclusive());

        let wl = &status.whitelists[0];
        assert_eq!(wl.name, "quentin test");
        assert_eq!(wl.enforced_kinds, vec!["mcp_server"]);
        assert!(wl.covered);
        assert!(!wl.fits);
        assert_eq!(wl.violation_count(), 2);
        assert_eq!(status.violations[0].token(), "mcp_server:gojiberry");
    }

    /// `enforcedKinds` / `allowed` / `accepted` post-date the first rollout, so
    /// a response predating the Hub redeploy must still parse.
    #[test]
    fn deserializes_response_predating_enforced_kinds_redeploy() {
        let status: AiWhitelistStatusBackend = serde_json::from_str(
            r#"{"fits":true,"coveredBy":1,"evidenceShared":true,"truncated":false,
                "violations":[],
                "whitelists":[{"whitelistId":"a","name":"n","covered":true,"fits":true,
                               "notPermitted":[],"notAccepted":[]}]}"#,
        )
        .expect("deserialize");
        let wl = &status.whitelists[0];
        assert!(wl.enforced_kinds.is_empty());
        assert!(wl.allowed.is_empty());
        assert!(wl.accepted.is_empty());
        assert_eq!(wl.violation_count(), 0);
    }

    /// A kind this build does not know must survive to the UI rather than
    /// failing the payload -- the Hub validates but does not close the set.
    #[test]
    fn unknown_selector_kind_still_deserializes() {
        let status: AiWhitelistStatusBackend = serde_json::from_str(
            r#"{"fits":false,"coveredBy":1,"evidenceShared":true,"truncated":false,
                "violations":[{"kind":"future_kind","key":"x","scope":"cursor"}],
                "whitelists":[]}"#,
        )
        .expect("deserialize");
        assert_eq!(status.violations[0].kind, "future_kind");
        assert_eq!(status.violations[0].token(), "future_kind:x");
    }

    /// Nothing covers the device: distinct from a failing evaluation.
    #[test]
    fn uncovered_device_is_not_a_violation() {
        let status: AiWhitelistStatusBackend = serde_json::from_str(
            r#"{"fits":false,"coveredBy":0,"evidenceShared":true,"truncated":false,
                "violations":[],"whitelists":[]}"#,
        )
        .expect("deserialize");
        assert!(status.is_uncovered());
        assert!(status.violations.is_empty());
    }

    /// Truncated or unshared evidence makes `fits` unusable as a verdict.
    #[test]
    fn inconclusive_evidence_is_flagged() {
        let truncated: AiWhitelistStatusBackend = serde_json::from_str(
            r#"{"fits":false,"coveredBy":1,"evidenceShared":true,"truncated":true,
                "violations":[],"whitelists":[]}"#,
        )
        .expect("deserialize");
        assert!(truncated.evidence_is_inconclusive());

        let denied: AiWhitelistStatusBackend = serde_json::from_str(
            r#"{"fits":false,"coveredBy":1,"evidenceShared":false,"truncated":false,
                "violations":[],"whitelists":[]}"#,
        )
        .expect("deserialize");
        assert!(denied.evidence_is_inconclusive());
    }
}
