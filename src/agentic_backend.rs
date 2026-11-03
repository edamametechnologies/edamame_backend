use crate::advisor_todos_backend::AdviceTypeBackend;
use blake3::Hasher;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgenticAnalysisRequestBackend {
    /// The pre-constructed prompt to send to the LLM
    /// This must include the make_decision tool call.
    pub prompt: String,
    /// The system prompt to send to the LLM
    pub system_prompt: String,
    /// Maximum tokens for the response
    pub max_tokens: u32,
    /// Type of analysis to perform
    pub analysis_type: AdviceTypeBackend,
    /// The same prompt with worked examples in it (attack-pattern
    /// adjudication, 2.3.1). The Portal sends it to its model in place of
    /// `prompt` only when that model is one the examples were measured
    /// helping; any other model gets `prompt`.
    /// `#[serde(default)]`: older agents omit this field on the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_with_examples: Option<String>,
    /// What the request adjudicates (2.3.2), so the Portal appends only the
    /// operator-accepted false-positive shapes that concern it: an entry may
    /// only ever quiet a finding of its own check, and the entries of other
    /// checks made the model more cautious about everything else.
    /// `#[serde(default)]`: older agents omit this field on the wire, and the
    /// Portal then appends every accepted shape, as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adjudication_scope: Option<AgenticAdjudicationScopeBackend>,
}

/// The findings an agentic analysis request adjudicates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgenticAdjudicationScopeBackend {
    /// `vulnerability` (attack-pattern findings), `divergence`, or `none`
    /// for a request that adjudicates no finding (a behavioral model, an
    /// advisor todo).
    pub domain: String,
    /// The detector checks (attack pattern) or evidence categories
    /// (divergence) of the findings in the prompt, as a dismissal report
    /// names them (`check_or_category`), sorted and without duplicates.
    /// Empty for `none`.
    pub checks: Vec<String>,
}

impl AgenticAdjudicationScopeBackend {
    pub const VULNERABILITY: &'static str = "vulnerability";
    pub const DIVERGENCE: &'static str = "divergence";
    pub const NONE: &'static str = "none";

    /// The scope of a request adjudicating findings of `domain` with these
    /// checks: trimmed, empty ones dropped, sorted, without duplicates.
    pub fn findings<I, S>(domain: &str, checks: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut checks: Vec<String> = checks
            .into_iter()
            .map(|check| check.as_ref().trim().to_string())
            .filter(|check| !check.is_empty())
            .collect();
        checks.sort();
        checks.dedup();
        Self {
            domain: domain.to_string(),
            checks,
        }
    }

    /// The scope of a request that adjudicates no finding.
    pub fn no_findings() -> Self {
        Self {
            domain: Self::NONE.to_string(),
            checks: Vec::new(),
        }
    }
}

impl AgenticAnalysisRequestBackend {
    /// The request's cache identity. A request carrying the examples variant
    /// or a scope is a different request (a model given the examples, or
    /// other accepted shapes, may answer otherwise); one without keeps the
    /// identity it always had.
    pub fn uid(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(self.prompt.as_bytes());
        hasher.update(self.max_tokens.to_le_bytes().as_slice());
        if let Some(with_examples) = &self.prompt_with_examples {
            hasher.update(b"\0prompt_with_examples\0");
            hasher.update(with_examples.as_bytes());
        }
        if let Some(scope) = &self.adjudication_scope {
            hasher.update(b"\0adjudication_scope\0");
            hasher.update(scope.domain.as_bytes());
            for check in &scope.checks {
                hasher.update(b"\0");
                hasher.update(check.as_bytes());
            }
        }
        hasher.finalize().to_hex().to_string()
    }
}

/// LLM's decision about a todo (same structure as TodoDecision)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgenticDecisionBackend {
    /// Action to take: "auto_resolve" or "escalate"
    pub action: String,
    /// Detailed reasoning for this decision
    pub reasoning: String,
    /// Risk score from 0.0 (very safe) to 1.0 (critical risk)
    pub risk_score: f64,
    /// Priority for escalated items: "low", "medium", "high", "critical"
    pub priority: String,
    /// Recommended follow-up actions
    pub recommended_actions: Vec<String>,
}

impl AgenticDecisionBackend {
    pub fn uid(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(self.action.as_bytes());
        hasher.update(self.reasoning.as_bytes());
        hasher.update(self.risk_score.to_bits().to_le_bytes().as_slice());
        hasher.update(self.priority.as_bytes());
        hasher.update(self.recommended_actions.join("|").as_bytes());
        hasher.finalize().to_hex().to_string()
    }
}

/// Response from agentic analysis via Backend LLM proxy
///
/// The backend has forwarded the prompt to its internal LLM, parsed the
/// tool call response, and returns the extracted decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgenticAnalysisResponseBackend {
    /// The LLM's decision (extracted from make_decision tool call)
    pub decision: AgenticDecisionBackend,
    /// Input tokens consumed
    pub input_tokens: u32,
    /// Output tokens generated
    pub output_tokens: u32,
}

impl AgenticAnalysisResponseBackend {
    pub fn uid(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(self.decision.uid().as_bytes());
        hasher.update(self.input_tokens.to_le_bytes().as_slice());
        hasher.update(self.output_tokens.to_le_bytes().as_slice());
        hasher.finalize().to_hex().to_string()
    }
}

/// Response from agentic subscription status endpoint
/// Returns the user's plan and current usage information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgenticSubscriptionStatusBackend {
    /// The name of the user's subscription plan (e.g., "free", "pro", "enterprise")
    pub plan_name: String,
    /// Current usage as a percentage (0.0 to 1.0, where 1.0 = 100% of quota used)
    pub usage: f64,
}

// ---------------------------------------------------------------------------
// Agentic Notification -- Portal backend collation
// ---------------------------------------------------------------------------

/// Source of the agentic notification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AgenticNotificationSourceBackend {
    /// Vulnerability detector findings (CVE-style runtime checks).
    Vulnerability,
    /// Two-plane divergence detection between intent model and system telemetry.
    Divergence,
    /// Periodic actions report (auto-resolved, pending confirmation counts).
    ActionReport,
    /// Escalation alert (escalated actions needing human review, or failed actions).
    Escalation,
}

impl std::fmt::Display for AgenticNotificationSourceBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vulnerability => write!(f, "vulnerability"),
            Self::Divergence => write!(f, "divergence"),
            Self::ActionReport => write!(f, "action_report"),
            Self::Escalation => write!(f, "escalation"),
        }
    }
}

/// Criticality level for an agentic notification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AgenticNotificationCriticalityBackend {
    Info,
    Warning,
    Critical,
}

impl std::fmt::Display for AgenticNotificationCriticalityBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARNING"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// An individual finding attached to a vulnerability or divergence notification.
///
/// Carries the per-finding detail that the portal needs for drill-down
/// without requiring it to understand the full internal report schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgenticNotificationFindingBackend {
    /// Unique key for this finding (dedup/correlation).
    pub finding_key: String,
    /// Severity label (e.g. "CRITICAL", "HIGH", "WARNING").
    pub severity: String,
    /// Human-readable description of the finding.
    pub description: String,
    /// Reference identifier (CVE, check name, category, ...).
    pub reference: String,
    /// Process name that triggered the finding, if known.
    pub process_name: Option<String>,
    /// Destination domain, if applicable.
    pub destination_domain: Option<String>,
    /// Destination IP address, if applicable.
    pub destination_ip: Option<String>,
    /// Destination port, if applicable.
    pub destination_port: Option<u16>,
    /// Whether the finding has been dismissed locally.
    pub dismissed: bool,
    /// Adjudication verdict actually applied to this finding by the LLM
    /// adjudicator, after guardrail enforcement: "KEEP" or "DEMOTE".
    /// `None` when the report was published without per-finding
    /// adjudication (deterministic mode, LLM unavailable, or an older
    /// coarse `suppressed_checks` decision). A "DEMOTE" is the only way to
    /// tell a finding the model quieted from one the detector graded LOW on
    /// its own.
    pub verdict: Option<String>,
    /// Per-finding reasoning, identical to the text the device shows on the
    /// finding's detail card: the detector diagnosis, what the finding was
    /// detected from, how it was adjudicated, and the model's own words.
    /// `None` when no reasoning was produced for this finding.
    pub reasoning: Option<String>,
    /// Detector check id on the attack-pattern plane (`file_system_tampering`,
    /// `credential_harvest`, ...) or evidence category on the divergence plane
    /// (`policy:allowlist_growth`, `correlation:unexpected_egress`, ...).
    /// `reference` stays the human-facing taxonomy line; this is the stable
    /// identifier the device's own card groups and labels by.
    ///
    /// `#[serde(default)]` on this and the other non-`Option` additions for
    /// the same reason as `AgenticDismissalReportBackend::adjudication`: the
    /// Portal deserializes device notifications with this very crate, and
    /// devices older than the field send none. `Option` fields already read
    /// as `None` when absent.
    #[serde(default)]
    pub check: String,
    /// What the finding was detected from: the attack detector's detection
    /// basis tokens (`file_monitor`, `temp_staging`, ...) or, on the divergence
    /// plane, the trigger reason. Empty when the source recorded none.
    #[serde(default)]
    pub detection_basis: Vec<String>,
    /// Canonical subject path of the finding (the file written, the anchor for
    /// folder-context dismissals), when the check has one.
    pub subject_path: Option<String>,
    /// Path of the process behind `process_name`, when known.
    pub process_path: Option<String>,
    pub parent_process_name: Option<String>,
    pub parent_process_path: Option<String>,
    /// Script the parent process was running, when the lineage knew it.
    pub parent_script_path: Option<String>,
    /// Files the finding is about: the open files that corroborated an
    /// attack-pattern finding, or the unexpected sensitive paths behind a
    /// divergence evidence entry. Bounded by the device.
    #[serde(default)]
    pub open_files: Vec<String>,
    /// Session the finding was attributed to, when it came from network
    /// telemetry.
    pub session_uid: Option<String>,
    /// Agent attribution when the device could pin the finding to an agent
    /// slice (divergence evidence today): the agent type slug and the
    /// instance id. From EDAMAME 2.0.3 the instance id is a per-process
    /// pseudonym (`instance-<8 hex>` plus the `-observer` / `-pushed`
    /// suffix) that changes when the device's core restarts; earlier
    /// devices send the id itself, which carries the host name. Display
    /// only: never a key.
    pub agent_type: Option<String>,
    pub agent_instance_id: Option<String>,
    /// When the device first recorded this finding in its action history.
    /// Carried-forward findings keep their original detection time here while
    /// the notification `timestamp` moves with every tick. `None` when the
    /// finding is not yet in history.
    pub first_detected: Option<DateTime<Utc>>,
}

impl AgenticNotificationFindingBackend {
    pub fn uid(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(self.finding_key.as_bytes());
        hasher.update(self.severity.as_bytes());
        hasher.update(self.description.as_bytes());
        hasher.update(self.reference.as_bytes());
        hasher.finalize().to_hex().to_string()
    }
}

/// An individual action item attached to an ActionReport or Escalation notification.
///
/// Mirrors the per-action detail from the LLM-driven advisor processing loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgenticNotificationActionBackend {
    /// Unique action ID.
    pub action_id: String,
    /// Action type label (e.g. "RemediateThreat", "DismissSession", "RollbackThreat").
    pub action_type: String,
    /// Advice type from the original todo (e.g. "Policy", "Threat", "NetworkSession", "PwnedBreach").
    pub advice_type: String,
    /// Result status: "auto_resolved", "requires_confirmation", "escalated", "failed".
    pub result_status: String,
    /// LLM risk score from 0.0 (very safe) to 1.0 (critical risk).
    pub risk_score: f64,
    /// Priority label: "low", "medium", "high", "critical".
    pub priority: String,
    /// LLM reasoning for the decision.
    pub reasoning: String,
    /// Human-readable description of the action target.
    pub description: String,
    /// Error message if the action failed.
    pub error: Option<String>,
    /// Whether undo is available for this action.
    pub undo_available: bool,
    /// Session display string (e.g. "process_name -> domain:port"), if applicable.
    pub session_display: Option<String>,
}

impl AgenticNotificationActionBackend {
    pub fn uid(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(self.action_id.as_bytes());
        hasher.update(self.action_type.as_bytes());
        hasher.update(self.result_status.as_bytes());
        hasher.update(self.risk_score.to_bits().to_le_bytes().as_slice());
        hasher.finalize().to_hex().to_string()
    }
}

/// Structured agentic notification sent to the Portal backend for
/// collation and reporting across a fleet of devices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgenticNotificationBackend {
    /// Source loop that produced this notification.
    pub source: AgenticNotificationSourceBackend,
    /// Criticality level.
    pub criticality: AgenticNotificationCriticalityBackend,
    /// UTC timestamp when the notification was generated.
    pub timestamp: DateTime<Utc>,

    // -- Device identity ------------------------------------------------
    /// Hostname of the reporting device. Empty from EDAMAME 2.0.3, which
    /// sends no host name (the Portal knows the device by the id every
    /// request carries), and whose titles and bodies no longer name the
    /// device; its paths write a person's home as `~` and its texts mask the
    /// secrets the device recognizes. `finding_key` values are unchanged.
    pub hostname: String,
    /// Primary IPv4 address.
    pub ip4: String,
    /// Primary IPv6 address.
    pub ip6: String,
    /// Device model string (e.g. "MacBookPro18,1").
    pub model: String,
    /// OS version string (e.g. "macOS 15.4.1").
    pub os_version: String,

    // -- Notification content -------------------------------------------
    /// Short title (suitable for alert subjects / push titles).
    pub title: String,
    /// Full notification body (may contain markdown or plain text).
    pub body: String,

    // -- Contextual fields (populated when available) -------------------
    /// Process name associated with the primary finding, if any.
    pub process_name: Option<String>,
    /// Destination domain associated with the primary finding, if any.
    pub destination_domain: Option<String>,
    /// Destination IP associated with the primary finding, if any.
    pub destination_ip: Option<String>,
    /// Destination port associated with the primary finding, if any.
    pub destination_port: Option<u16>,

    // -- Summary metrics -----------------------------------------------
    /// Total number of active (non-dismissed) findings (vulnerability/divergence).
    pub active_findings_count: usize,
    /// Current security score at the time of notification.
    pub security_score: Option<f64>,
    /// LLM verdict string (e.g. "FINDINGS", "CLEAR", "Divergence").
    pub verdict: Option<String>,
    /// LLM decision source (e.g. "LLM_CONFIRMED", "GUARDRAIL_FORCED_DETERMINISTIC").
    pub decision_source: Option<String>,

    // -- Findings (vulnerability / divergence) -------------------------
    /// Up to N individual findings for drill-down.
    pub findings: Vec<AgenticNotificationFindingBackend>,

    // -- Action items (action_report / escalation) ---------------------
    /// Individual action items from the advisor processing loop.
    pub actions: Vec<AgenticNotificationActionBackend>,
    /// Count of actions that were automatically resolved in this cycle.
    pub auto_resolved_count: usize,
    /// Count of actions pending user confirmation.
    pub requires_confirmation_count: usize,
    /// Count of actions escalated for human review.
    pub escalated_count: usize,
    /// Count of actions that failed during processing.
    pub failed_count: usize,
}

/// One entry of the per-device attack-pattern / divergence history kept by
/// the Portal (`POST /api/agentic_history`).
///
/// Where `AgenticNotificationBackend` is sent only when the alert gate passes
/// (alertable findings, content dedup, cooldown), a history event is sent on
/// every change of the published state: the active finding set changed, the
/// verdict changed, a finding was dismissed or restored, or the state cleared.
/// The `notification` carries the same device identity, verdict, decision
/// source and finding list the alert would, so the Portal can render both
/// with one shape; `event` says why the entry exists and the key lists say
/// what changed since the previous entry from this device and domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgenticHistoryEventBackend {
    /// `findings_changed`, `verdict_changed`, `dismissed`, `undismissed`,
    /// `cleared`.
    pub event: String,
    /// Finding keys that became active since the previous entry.
    pub added_keys: Vec<String>,
    /// Finding keys that stopped being active since the previous entry.
    pub removed_keys: Vec<String>,
    /// The published state at the time of the event. `source` is the domain
    /// (`Vulnerability` / `Divergence`); `findings` is the full active set
    /// (capped by the sender), not only the alertable subset.
    pub notification: AgenticNotificationBackend,
}

impl AgenticHistoryEventBackend {
    pub fn uid(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(self.event.as_bytes());
        for key in &self.added_keys {
            hasher.update(b"+");
            hasher.update(key.as_bytes());
        }
        for key in &self.removed_keys {
            hasher.update(b"-");
            hasher.update(key.as_bytes());
        }
        hasher.update(self.notification.uid().as_bytes());
        hasher.finalize().to_hex().to_string()
    }
}

impl AgenticNotificationBackend {
    pub fn uid(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(self.source.to_string().as_bytes());
        hasher.update(self.criticality.to_string().as_bytes());
        hasher.update(self.timestamp.to_rfc3339().as_bytes());
        hasher.update(self.hostname.as_bytes());
        hasher.update(self.title.as_bytes());
        hasher.update(self.active_findings_count.to_le_bytes().as_slice());
        for finding in &self.findings {
            hasher.update(finding.uid().as_bytes());
        }
        for action in &self.actions {
            hasher.update(action.uid().as_bytes());
        }
        hasher.finalize().to_hex().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request from an agent older than `prompt_with_examples` (2.3.0 and
    /// before) still parses, and a request without examples keeps the old
    /// wire shape, so a Portal on the previous crate reads it unchanged.
    #[test]
    fn analysis_request_prompt_with_examples_is_optional_on_the_wire() {
        let old_agent =
            r#"{"prompt":"p","system_prompt":"","max_tokens":800,"analysis_type":"Threat"}"#;
        let request: AgenticAnalysisRequestBackend = serde_json::from_str(old_agent).unwrap();
        assert!(request.prompt_with_examples.is_none());

        let encoded = serde_json::to_value(&request).unwrap();
        assert!(encoded.get("prompt_with_examples").is_none());

        let with_examples = AgenticAnalysisRequestBackend {
            prompt_with_examples: Some("p and examples".to_string()),
            ..request
        };
        let encoded = serde_json::to_string(&with_examples).unwrap();
        let decoded: AgenticAnalysisRequestBackend = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            decoded.prompt_with_examples.as_deref(),
            Some("p and examples")
        );
    }

    /// A request without examples keeps the cache identity it had before the
    /// field existed; one with them is another request.
    #[test]
    fn analysis_request_uid_tells_the_examples_variant_apart() {
        let plain = AgenticAnalysisRequestBackend {
            prompt: "p".to_string(),
            system_prompt: String::new(),
            max_tokens: 800,
            analysis_type: AdviceTypeBackend::Threat,
            prompt_with_examples: None,
            adjudication_scope: None,
        };
        let with_examples = AgenticAnalysisRequestBackend {
            prompt_with_examples: Some("p and examples".to_string()),
            ..plain.clone()
        };
        let mut hasher = Hasher::new();
        hasher.update(b"p");
        hasher.update(800u32.to_le_bytes().as_slice());
        assert_eq!(plain.uid(), hasher.finalize().to_hex().to_string());
        assert_ne!(plain.uid(), with_examples.uid());
    }

    /// A request from an agent older than `adjudication_scope` (2.3.1 and
    /// before) still parses, and one without a scope keeps the wire shape and
    /// the cache identity it had; a scope makes it another request.
    #[test]
    fn analysis_request_adjudication_scope_is_optional_on_the_wire() {
        let old_agent =
            r#"{"prompt":"p","system_prompt":"","max_tokens":800,"analysis_type":"Threat"}"#;
        let plain: AgenticAnalysisRequestBackend = serde_json::from_str(old_agent).unwrap();
        assert!(plain.adjudication_scope.is_none());
        let encoded = serde_json::to_value(&plain).unwrap();
        assert!(encoded.get("adjudication_scope").is_none());

        let scoped = AgenticAnalysisRequestBackend {
            adjudication_scope: Some(AgenticAdjudicationScopeBackend::findings(
                AgenticAdjudicationScopeBackend::VULNERABILITY,
                [
                    "token_exfiltration",
                    " credential_harvest ",
                    "",
                    "token_exfiltration",
                ],
            )),
            ..plain.clone()
        };
        let encoded = serde_json::to_string(&scoped).unwrap();
        let decoded: AgenticAnalysisRequestBackend = serde_json::from_str(&encoded).unwrap();
        let scope = decoded.adjudication_scope.expect("scope on the wire");
        assert_eq!(scope.domain, "vulnerability");
        assert_eq!(
            scope.checks,
            vec!["credential_harvest", "token_exfiltration"]
        );

        let mut hasher = Hasher::new();
        hasher.update(b"p");
        hasher.update(800u32.to_le_bytes().as_slice());
        assert_eq!(plain.uid(), hasher.finalize().to_hex().to_string());
        assert_ne!(plain.uid(), scoped.uid());
        let none = AgenticAnalysisRequestBackend {
            adjudication_scope: Some(AgenticAdjudicationScopeBackend::no_findings()),
            ..plain.clone()
        };
        assert_ne!(none.uid(), scoped.uid());
        assert_ne!(none.uid(), plain.uid());
    }

    fn sample_notification() -> AgenticNotificationBackend {
        AgenticNotificationBackend {
            source: AgenticNotificationSourceBackend::Vulnerability,
            criticality: AgenticNotificationCriticalityBackend::Critical,
            timestamp: Utc::now(),
            hostname: "test-host".to_string(),
            ip4: "192.168.1.1".to_string(),
            ip6: "::1".to_string(),
            model: "TestModel".to_string(),
            os_version: "Linux 6.5".to_string(),
            title: "Test finding".to_string(),
            body: "Suspicious process detected".to_string(),
            process_name: Some("curl".to_string()),
            destination_domain: Some("evil.example.com".to_string()),
            destination_ip: Some("10.0.0.1".to_string()),
            destination_port: Some(443),
            active_findings_count: 1,
            security_score: Some(3.5),
            verdict: Some("FINDINGS".to_string()),
            decision_source: Some("LLM_CONFIRMED".to_string()),
            findings: vec![AgenticNotificationFindingBackend {
                finding_key: "token_exfiltration|curl|evil.example.com:443".to_string(),
                severity: "HIGH".to_string(),
                description: "Anomalous outbound to evil.example.com".to_string(),
                reference: "CVE-2025-30066".to_string(),
                process_name: Some("curl".to_string()),
                destination_domain: Some("evil.example.com".to_string()),
                destination_ip: Some("10.0.0.1".to_string()),
                destination_port: Some(443),
                dismissed: false,
                verdict: Some("KEEP".to_string()),
                reasoning: Some(
                    "The model kept this finding: curl read a token and reached a blacklisted host."
                        .to_string(),
                ),
                check: "token_exfiltration".to_string(),
                detection_basis: vec!["anomalous_session".to_string(), "sensitive_file".to_string()],
                subject_path: None,
                process_path: Some("/usr/bin/curl".to_string()),
                parent_process_name: Some("bash".to_string()),
                parent_process_path: Some("/bin/bash".to_string()),
                parent_script_path: Some("/tmp/run.sh".to_string()),
                open_files: vec!["/Users/test/.aws/credentials".to_string()],
                session_uid: Some("session-1".to_string()),
                agent_type: None,
                agent_instance_id: None,
                first_detected: Some(Utc::now()),
            }],
            actions: Vec::new(),
            auto_resolved_count: 0,
            requires_confirmation_count: 0,
            escalated_count: 0,
            failed_count: 0,
        }
    }

    /// The Portal deserializes device notifications with this crate. A device
    /// older than the per-finding card fields (1.9.1 and before) sends none of
    /// them, and its notification MUST still parse: `Option` fields read as
    /// `None` on their own, the three non-`Option` additions carry an explicit
    /// default. Dropping a fleet's notifications on a Portal deploy is the
    /// failure this guards against.
    #[test]
    fn test_finding_from_a_device_older_than_the_card_fields_still_parses() {
        let old_shape = serde_json::json!({
            "finding_key": "k",
            "severity": "HIGH",
            "description": "d",
            "reference": "r",
            "process_name": null,
            "destination_domain": null,
            "destination_ip": null,
            "destination_port": null,
            "dismissed": false
        });
        let parsed: AgenticNotificationFindingBackend =
            serde_json::from_value(old_shape).expect("pre-card finding must parse");
        assert!(parsed.check.is_empty());
        assert!(parsed.detection_basis.is_empty());
        assert!(parsed.open_files.is_empty());
        assert!(parsed.verdict.is_none() && parsed.reasoning.is_none());
        assert!(parsed.first_detected.is_none());
    }

    #[test]
    fn test_notification_roundtrip_serialization() {
        let notification = sample_notification();
        let json = serde_json::to_string(&notification).expect("serialization should succeed");
        let parsed: AgenticNotificationBackend =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(parsed.source, notification.source);
        assert_eq!(parsed.criticality, notification.criticality);
        assert_eq!(parsed.title, notification.title);
        assert_eq!(parsed.active_findings_count, 1);
        assert_eq!(parsed.findings.len(), 1);
        assert_eq!(
            parsed.findings[0].finding_key,
            "token_exfiltration|curl|evil.example.com:443"
        );
    }

    #[test]
    fn test_notification_uid_deterministic() {
        let notification = sample_notification();
        let uid1 = notification.uid();
        let uid2 = notification.uid();
        assert_eq!(uid1, uid2, "uid should be deterministic");
        assert!(!uid1.is_empty());
    }

    #[test]
    fn test_notification_uid_varies_with_content() {
        let mut n1 = sample_notification();
        let mut n2 = sample_notification();
        n2.title = "Different finding".to_string();
        let uid1 = n1.uid();
        let uid2 = n2.uid();
        assert_ne!(uid1, uid2, "different content should produce different uid");

        n1.active_findings_count = 5;
        assert_ne!(n1.uid(), uid1, "changing findings count should change uid");
    }

    #[test]
    fn test_history_event_uid_covers_event_and_keys() {
        let notification = sample_notification();
        let event = AgenticHistoryEventBackend {
            event: "findings_changed".to_string(),
            added_keys: vec!["k1".to_string()],
            removed_keys: vec![],
            notification: notification.clone(),
        };
        let same = event.clone();
        assert_eq!(event.uid(), same.uid());
        let mut other_event = event.clone();
        other_event.event = "dismissed".to_string();
        assert_ne!(event.uid(), other_event.uid());
        let mut other_keys = event.clone();
        other_keys.removed_keys.push("k2".to_string());
        assert_ne!(event.uid(), other_keys.uid());
        let json = serde_json::to_string(&event).unwrap();
        let back: AgenticHistoryEventBackend = serde_json::from_str(&json).unwrap();
        assert_eq!(back.uid(), event.uid());
    }

    #[test]
    fn test_notification_source_display() {
        assert_eq!(
            AgenticNotificationSourceBackend::Vulnerability.to_string(),
            "vulnerability"
        );
        assert_eq!(
            AgenticNotificationSourceBackend::Divergence.to_string(),
            "divergence"
        );
    }
}
