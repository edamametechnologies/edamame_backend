//! Structured per-domain detail shipped alongside a score report.
//!
//! One [`DetailBackend`] bundle per data class. A bundle carries its own consent
//! mode, the inventory of what EDAMAME can see (`coverage`), and the evidence
//! naming why individual checks failed (`checks`). Bundling them means consent
//! and payload cannot drift apart on the wire: a denied bundle is structurally
//! incapable of carrying detail (see [`DetailBackend::with_payload`]).
//!
//! Today the only domain is `ai`. A future domain (FIM, capture, …) is an extra
//! element in `DetailedScoreBackend.details`, not a new top-level field.
//!
//! See `edamame_core/AIGOVERNANCE.md`.

use serde::{Deserialize, Serialize};

/// Hard cap on failure facts per check in a single score report.
pub const MAX_FAILURE_FACTS: usize = 32;

/// Data class one [`DetailBackend`] bundle covers.
///
/// Typed at emit time, carried as a plain string on the wire: an unknown enum
/// variant fails deserialization of the *entire* score report, not just the
/// bundle, so a client that learns a new domain would stop reporting to a Hub
/// that predates it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DetailDomainBackend {
    /// AI posture: agent slugs, process basenames, MCP server names, harness
    /// slugs, secret labels, plus per-agent observation coverage.
    Ai,
}

impl DetailDomainBackend {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ai => "ai",
        }
    }
}

/// Effective consent for one detail domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DetailModeBackend {
    /// Operator has not opted in. The bundle carries no payload.
    Denied,
    /// Operator opted in on this device.
    Enabled,
    /// Managed fleet forced export via posture; the device-local toggle is
    /// bypassed.
    Forced,
}

impl DetailModeBackend {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::Enabled => "enabled",
            Self::Forced => "forced",
        }
    }

    pub fn allows_detail(&self) -> bool {
        matches!(self, Self::Enabled | Self::Forced)
    }
}

/// Closed vocabulary of failure fact kinds used by Hub governance whitelisting.
/// Keys are normalized at emit time (process basename, MCP server_name, MCP rule
/// id, harness slug, secret label).
///
/// Every kind here is an AI-posture kind today, but the carrier is
/// domain-generic: another domain that can name what made a check fail adds a
/// kind rather than a parallel structure. Stringly-typed on the wire for the
/// same forward-compatibility reason as [`DetailDomainBackend`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FailureFactKindBackend {
    Agent,
    Amplifier,
    CriticalProcess,
    McpServer,
    McpRule,
    Harness,
    ExpectedHarness,
    SecretLabel,
    Observer,
}

impl FailureFactKindBackend {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Amplifier => "amplifier",
            Self::CriticalProcess => "critical_process",
            Self::McpServer => "mcp_server",
            Self::McpRule => "mcp_rule",
            Self::Harness => "harness",
            Self::ExpectedHarness => "expected_harness",
            Self::SecretLabel => "secret_label",
            Self::Observer => "observer",
        }
    }
}

/// One structured failure detail naming what made a check fail.
/// Whitelist matching uses `(kind, key)` with an optional `scope`.
///
/// Wire token form (for display / docs): `{kind}:{key}` e.g.
/// `critical_process:ssh`, `mcp_server:gojiberry`, `amplifier:passwordless_root`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FailureFactBackend {
    /// Fact kind -- see [`FailureFactKindBackend`].
    pub kind: String,
    /// Normalized stable key (process basename, MCP server_name, harness slug, …).
    pub key: String,
    /// Optional subject narrowing the fact. AI posture checks put the agent slug
    /// here (`cursor`, `claude_code`, …). Empty when host-global.
    pub scope: String,
}

impl FailureFactBackend {
    pub fn new(kind: FailureFactKindBackend, key: impl Into<String>) -> Self {
        Self {
            kind: kind.as_str().to_string(),
            key: key.into(),
            scope: String::new(),
        }
    }

    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = scope.into();
        self
    }

    /// Display / whitelist token: `kind:key` (scope is matched separately).
    pub fn token(&self) -> String {
        format!("{}:{}", self.kind, self.key)
    }
}

/// Facts for one failing check, keyed by the check's metric name.
///
/// Keyed here rather than carried on `ThreatMetricBackend` so that consent
/// governs one place: dropping the bundle drops every fact with it, instead of
/// requiring a sweep over the metric list before send.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CheckDetailBackend {
    /// Metric name of the failing check (`agents_with_blast_radius`, …).
    pub check: String,
    /// What made it fail. Never empty -- a check with no facts is omitted.
    pub facts: Vec<FailureFactBackend>,
    /// True when emit-time capping dropped additional facts.
    pub truncated: bool,
}

impl CheckDetailBackend {
    pub fn new(check: impl Into<String>, facts: Vec<FailureFactBackend>, truncated: bool) -> Self {
        Self {
            check: check.into(),
            facts,
            truncated,
        }
    }
}

/// Subject class a [`CoverageRowBackend`] inventories.
///
/// Not the same taxonomy as [`DetailDomainBackend`]. This one names *what is
/// being inventoried* within a domain (one row per agent, per watch path, per
/// interface); that one names the data class a consent grant covers. Stringly
/// typed on the wire for the same reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CoverageKindBackend {
    /// AI agent transcript observation. `key` is the registry agent slug.
    Agent,
}

impl CoverageKindBackend {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Agent => "agent",
        }
    }
}

/// One observation-coverage row: does this subject exist on the host, and is
/// EDAMAME watching it?
///
/// Coverage is inventory, not evidence. Rows are emitted for every known
/// subject regardless of check status, carry no failing detail, and are never
/// whitelist-matched -- that is [`FailureFactBackend`]'s job. They exist
/// because a boolean check cannot separate "absent" from "present and
/// healthy": both are Inactive. See `edamame_core/AIGOVERNANCE.md` §6.
///
/// For `agent` rows, `present` means the transcript root is reachable and
/// `monitored` means the host-side observer is active.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CoverageRowBackend {
    /// Subject class -- see [`CoverageKindBackend`].
    pub kind: String,
    /// Stable key within the kind (agent slug, watch path, interface name).
    pub key: String,
    /// The subject exists on this host.
    pub present: bool,
    /// EDAMAME is actively observing it.
    pub monitored: bool,
}

impl CoverageRowBackend {
    pub fn new(
        kind: CoverageKindBackend,
        key: impl Into<String>,
        present: bool,
        monitored: bool,
    ) -> Self {
        Self {
            kind: kind.as_str().to_string(),
            key: key.into(),
            present,
            monitored,
        }
    }

    /// Display state: `"unmonitored"`, `"monitored"`, or `"absent"`.
    /// For `agent` rows these read as unsecured / secured / not on this host.
    pub fn state(&self) -> &'static str {
        match (self.present, self.monitored) {
            (true, false) => "unmonitored",
            (true, true) => "monitored",
            (false, _) => "absent",
        }
    }
}

/// Everything one detail domain contributed to this report: the consent it was
/// collected under, what EDAMAME can see, and why checks failed.
///
/// A bundle is emitted for every domain the client knows about *including
/// denied ones* -- an explicit `mode: "denied"` bundle is what lets the Hub tell
/// a refusal from a client that predates the domain (no bundle at all).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DetailBackend {
    /// Data class -- see [`DetailDomainBackend`].
    pub domain: String,
    /// Consent state -- see [`DetailModeBackend`].
    pub mode: String,
    /// Inventory of observable subjects. Empty when denied, or when the domain
    /// has nothing to inventory.
    /// `#[serde(default)]`: tolerate a producer that omits the field.
    #[serde(default)]
    pub coverage: Vec<CoverageRowBackend>,
    /// Per-check failure evidence. Empty when denied, or when no check in this
    /// domain is failing.
    /// `#[serde(default)]`: tolerate a producer that omits the field.
    #[serde(default)]
    pub checks: Vec<CheckDetailBackend>,
}

impl DetailBackend {
    /// Payload-free bundle for `domain` under `mode`. Attach payload with
    /// [`Self::with_payload`], which enforces the consent invariant.
    pub fn new(domain: DetailDomainBackend, mode: DetailModeBackend) -> Self {
        Self {
            domain: domain.as_str().to_string(),
            mode: mode.as_str().to_string(),
            coverage: Vec::new(),
            checks: Vec::new(),
        }
    }

    /// Whether this bundle's mode permits carrying detail.
    pub fn allows_detail(&self) -> bool {
        self.mode != DetailModeBackend::Denied.as_str()
    }

    /// Attach inventory and evidence. **No-op when the mode denies export**, so
    /// "denied" and "carries detail" cannot both be true on the wire regardless
    /// of what the caller computed.
    pub fn with_payload(
        mut self,
        coverage: Vec<CoverageRowBackend>,
        checks: Vec<CheckDetailBackend>,
    ) -> Self {
        if self.allows_detail() {
            self.coverage = coverage;
            self.checks = checks;
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_coverage() -> Vec<CoverageRowBackend> {
        vec![CoverageRowBackend::new(
            CoverageKindBackend::Agent,
            "cursor",
            true,
            false,
        )]
    }

    fn sample_checks() -> Vec<CheckDetailBackend> {
        vec![CheckDetailBackend::new(
            "unsecured_cursor",
            vec![
                FailureFactBackend::new(FailureFactKindBackend::Agent, "cursor")
                    .with_scope("cursor"),
                FailureFactBackend::new(FailureFactKindBackend::Observer, "paused")
                    .with_scope("cursor"),
            ],
            false,
        )]
    }

    #[test]
    fn denied_bundle_cannot_carry_payload() {
        let bundle = DetailBackend::new(DetailDomainBackend::Ai, DetailModeBackend::Denied)
            .with_payload(sample_coverage(), sample_checks());
        assert!(!bundle.allows_detail());
        assert!(bundle.coverage.is_empty());
        assert!(bundle.checks.is_empty());
    }

    #[test]
    fn forced_bundle_carries_payload() {
        let bundle = DetailBackend::new(DetailDomainBackend::Ai, DetailModeBackend::Forced)
            .with_payload(sample_coverage(), sample_checks());
        assert!(bundle.allows_detail());
        assert_eq!(bundle.coverage.len(), 1);
        assert_eq!(bundle.checks.len(), 1);
    }

    #[test]
    fn wire_shape_is_flat_strings() {
        let bundle = DetailBackend::new(DetailDomainBackend::Ai, DetailModeBackend::Enabled)
            .with_payload(sample_coverage(), sample_checks());
        let json = serde_json::to_value(&bundle).expect("serialize");
        assert_eq!(json["domain"], "ai");
        assert_eq!(json["mode"], "enabled");
        assert_eq!(json["coverage"][0]["kind"], "agent");
        assert_eq!(json["coverage"][0]["key"], "cursor");
        assert_eq!(json["coverage"][0]["present"], true);
        assert_eq!(json["coverage"][0]["monitored"], false);
        assert_eq!(json["checks"][0]["check"], "unsecured_cursor");
        assert_eq!(json["checks"][0]["truncated"], false);
        assert_eq!(json["checks"][0]["facts"][0]["kind"], "agent");
        assert_eq!(json["checks"][0]["facts"][0]["key"], "cursor");
        assert_eq!(json["checks"][0]["facts"][0]["scope"], "cursor");
        assert_eq!(json["checks"][0]["facts"][1]["kind"], "observer");
    }

    #[test]
    fn missing_payload_fields_deserialize_as_empty() {
        let bundle: DetailBackend =
            serde_json::from_str(r#"{"domain":"ai","mode":"denied"}"#).expect("deserialize");
        assert!(bundle.coverage.is_empty());
        assert!(bundle.checks.is_empty());
    }

    #[test]
    fn unknown_domain_and_kind_still_deserialize() {
        // Strings, not enums: a Hub-side producer naming a domain this build
        // does not know must not fail the whole report.
        let bundle: DetailBackend = serde_json::from_str(
            r#"{"domain":"fim","mode":"enabled",
                "coverage":[{"kind":"watch_path","key":"/etc","present":true,"monitored":true}],
                "checks":[]}"#,
        )
        .expect("deserialize");
        assert_eq!(bundle.domain, "fim");
        assert_eq!(bundle.coverage[0].kind, "watch_path");
        assert_eq!(bundle.coverage[0].state(), "monitored");
    }

    #[test]
    fn fact_token_is_kind_colon_key() {
        let fact = FailureFactBackend::new(FailureFactKindBackend::CriticalProcess, "ssh");
        assert_eq!(fact.token(), "critical_process:ssh");
        assert!(fact.scope.is_empty());
    }
}
