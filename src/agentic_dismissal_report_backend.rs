use serde::{Deserialize, Serialize};

/// Operator-initiated report sent to the EDAMAME backend when a user
/// dismisses a vulnerability or divergence finding and explicitly opts in
/// to share that decision (analogous to `DislikeDeviceInfoBackend` for
/// device profiling feedback).
///
/// The receiving Lambda treats this as feedback intended to harden the
/// detector / classifier. It is NOT a remediation order, and it does NOT
/// influence policy on this device -- the local dismissal is already
/// applied by `agentic_dismiss_with_scope` before this report is sent.
///
/// All free-form fields (`note`, `email`) are entered by the operator
/// in the consent dialog and may be empty.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgenticDismissalReportBackend {
    // -- Identity / context --
    /// `vulnerability` or `divergence`.
    pub domain: String,
    /// Stable finding key the operator dismissed (the same key the engine
    /// uses to dedup findings into action history).
    pub finding_key: String,
    /// Optional human-readable title for the finding (e.g. the deterministic
    /// check name and severity, or the divergence summary).
    pub finding_title: String,
    /// Severity at the time the operator dismissed (`LOW`, `HIGH`, etc.).
    pub finding_severity: String,
    /// For vulnerability findings: the deterministic check that fired
    /// (`token_exfiltration`, `sandbox_exploitation`, ...). For divergence,
    /// the alignment category (`outside`, `forbidden`, ...). May be empty.
    pub check_or_category: String,

    // -- Dismissal rule shape --
    /// One of: `finding`, `process_for_check`, `process_lineage`,
    /// `process_and_material_class`, `agent_workspace_pattern`.
    pub scope: String,
    /// `high_and_below` (default) or `critical_capable` (operator
    /// explicitly accepted that this rule may also suppress CRITICAL).
    pub severity_ceiling: String,
    /// TTL for the dismissal in seconds, or `None` for permanent.
    pub ttl_secs: Option<i64>,

    // -- Matcher snapshot for the rule --
    /// Process basename or executable name. Empty when not in the matcher.
    pub process_name: String,
    /// Process executable path. Empty when not in the matcher.
    pub process_path: String,
    /// Parent process basename. Empty when not in the matcher.
    pub parent_process_name: String,
    /// Parent process executable path. Empty when not in the matcher.
    pub parent_process_path: String,
    /// Parent script (sh / py / ps1) absolute path. Empty when not present.
    pub parent_script_path: String,
    /// Material classes the rule matches (e.g. `ssh`, `aws_credentials`).
    pub material_classes: Vec<String>,
    /// Sensitive-path classes the rule matches (e.g. `dot_ssh`).
    pub sensitive_path_classes: Vec<String>,
    /// Bucketed destination class (`web`, `web_ip`, `domain`, `unknown`,
    /// `portNNN`). Empty when not in the matcher.
    pub destination_class: String,
    /// Bucketed destination port. `None` when not in the matcher.
    pub destination_port: Option<u16>,
    /// Agent type associated with the finding (`cursor`, `claude_code`,
    /// `claude_desktop`, `openclaw`). Empty when not present.
    pub agent_type: String,
    /// Agent instance ID (12-hex SHA256 prefix). Empty when not present.
    pub agent_instance_id: String,
    /// Workspace root (when the finding is workspace-scoped).
    pub workspace_root: String,

    // -- Operator-supplied --
    /// Free-form operator reason (the same string captured at dismissal time
    /// in the local audit log).
    pub reason: String,
    /// Optional operator note from the consent dialog (mirrors `note` in
    /// `DislikeDeviceInfoBackend`). May be empty.
    pub note: String,
    /// Optional operator email from the consent dialog. May be empty.
    pub email: String,

    // -- Local provenance --
    /// `os_name` and `os_version` so the EDAMAME backend can correlate
    /// suppression patterns across platforms.
    pub os_name: String,
    pub os_version: String,
    /// `core_version` (matches the `BACKEND_VERSION` header pattern) so the
    /// receiving Lambda can fingerprint which detector version produced the
    /// dismissed finding.
    pub core_version: String,
}
