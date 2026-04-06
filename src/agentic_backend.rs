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
}

impl AgenticAnalysisRequestBackend {
    pub fn uid(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(self.prompt.as_bytes());
        hasher.update(self.max_tokens.to_le_bytes().as_slice());
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
    /// Hostname of the reporting device.
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
