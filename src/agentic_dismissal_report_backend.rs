use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// What the adjudicator saw and said about a finding at the time it was last
/// published -- the device's half of the row a dismissal becomes on the Portal:
/// (features, model verdict, human verdict). Without it a dismissal is an
/// audit entry; with it, it is a labelled training example for the
/// adjudicator, joinable through `report_id` to the notification and history
/// the Portal already holds for the same detector tick.
///
/// Snapshot semantics: the device fills this from the most recent report in
/// its own vulnerability history (or the most recent divergence verdict)
/// that still carries the finding. `None` when that history is gone --
/// pruned, cleared, or produced by an earlier daemon instance -- so the
/// Portal can tell "no evidence was available" from "the evidence was empty".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgenticDismissalAdjudicationBackend {
    /// Detector report id (vulnerability) or verdict entry id (divergence)
    /// that last carried the finding.
    pub report_id: String,
    /// When that report / verdict was produced.
    pub report_timestamp: DateTime<Utc>,
    /// How the publication was decided, lowercased: `llm_confirmed`,
    /// `history_reused`, `deterministic_only`, `llm_unavailable`,
    /// `llm_overruled_soft_signals`, `guardrail_forced_deterministic`, or
    /// empty when the report recorded none.
    pub decision_source: String,
    /// Report-level verdict: `CLEAR` / `PARTIAL` / `FINDINGS` for a
    /// vulnerability report, the cycle verdict (`CLEAN`, `DIVERGENCE`, ...)
    /// for divergence. Empty when no model decision was recorded.
    pub report_verdict: String,
    /// The per-finding verdict the model asked for -- `KEEP`, `SUPPRESS` or
    /// `DEMOTE` -- before the guardrail tier had its say. `None` when the
    /// decision carried no per-finding verdicts (coarse decisions, the
    /// deterministic path, divergence).
    pub model_verdict: Option<String>,
    /// The model's own words about this finding when it produced any (the
    /// per-finding reasoning for vulnerability, the cycle reasoning for
    /// divergence), character-capped by the device. `None` when there were
    /// none.
    pub model_reasoning: Option<String>,
    /// Severity the deterministic detector graded before adjudication. A
    /// `DEMOTE` rewrites the published severity to LOW, so the published one
    /// is not the label a trainer wants.
    pub detector_severity: String,
    /// Guardrail tier the finding landed in, lowercased: `evidence_floor`,
    /// `critical_no_corroboration`, `open`; empty for divergence.
    pub adjudication_tier: String,
    /// Deterministic detection basis tags the finding carried.
    pub detection_basis: Vec<String>,
    /// The structured evidence packet the adjudicator was shown, as JSON:
    /// the `FindingEvidence` packet for a vulnerability finding, the evidence
    /// entry for divergence. `None` when the finding predates the packet.
    pub evidence: Option<serde_json::Value>,
    /// The CRS evidence score attached to the finding, as JSON, when the
    /// detector computed one.
    pub evidence_score: Option<serde_json::Value>,
}

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
///
/// Shape note (2026-09-18): since `finding` carries the whole device card,
/// the flat finding fields below (`finding_title`, `finding_severity`,
/// `check_or_category`, the process lineage and the agent pair) duplicate
/// it; the rule-matcher fields (`scope`, `severity_ceiling`, `ttl_secs`, the
/// class lists, `destination_*`, `workspace_root`) are the part that is not
/// a finding and would become a nested `AgenticDismissalRuleBackend`. Not
/// done on its own because the Portal lambda and FP review read the flat
/// fields and fielded devices keep sending them; the two-step plan is in
/// `edamame_core/VULNERABILITYDETECTION.md` ("Factorization of the FP
/// report"). Fold step one into the next change that touches this struct.
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

    // -- What the adjudicator saw and said --
    /// The finding's evidence packet and the model's verdict on it at the
    /// time it was last published, so the Portal stores every dismissal as a
    /// (features, model verdict, human verdict) row. `None` when the device
    /// no longer holds the report that carried the finding.
    /// `#[serde(default)]` for the same reason as
    /// `ContextDetailBackend::adjudication`: deserialized server-side from
    /// device reports, and clients older than the field send none.
    #[serde(default)]
    pub adjudication: Option<AgenticDismissalAdjudicationBackend>,
    /// The finding as the device last published it, in exactly the shape the
    /// notification and history payloads carry (same builder on the device),
    /// so the Portal's false-positive review shows the operator the card they
    /// dismissed and a trainer joins the report to the history row by
    /// `finding_key` without a second schema. `None` when local history no
    /// longer carries the finding. `#[serde(default)]` as for `adjudication`.
    #[serde(default)]
    pub finding: Option<crate::agentic_backend::AgenticNotificationFindingBackend>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AgenticDismissalReportBackend {
        AgenticDismissalReportBackend {
            domain: "vulnerability".to_string(),
            finding_key: "token_exfiltration|curl|evil.example.com:443".to_string(),
            finding_title: "Token exfiltration".to_string(),
            finding_severity: "HIGH".to_string(),
            check_or_category: "token_exfiltration".to_string(),
            scope: "process_for_check".to_string(),
            severity_ceiling: "high_and_below".to_string(),
            ttl_secs: Some(3600),
            process_name: "curl".to_string(),
            process_path: "/usr/bin/curl".to_string(),
            parent_process_name: "bash".to_string(),
            parent_process_path: "/bin/bash".to_string(),
            parent_script_path: "/tmp/payload.sh".to_string(),
            material_classes: vec!["ssh".to_string(), "aws_credentials".to_string()],
            sensitive_path_classes: vec!["dot_ssh".to_string()],
            destination_class: "web".to_string(),
            destination_port: Some(443),
            agent_type: "cursor".to_string(),
            agent_instance_id: "abcdef012345".to_string(),
            workspace_root: "/Users/me/repo".to_string(),
            reason: "false positive: rustup-init bootstrap".to_string(),
            note: "trusted CI bootstrap".to_string(),
            email: "ops@example.com".to_string(),
            os_name: "macOS".to_string(),
            os_version: "26.4.0".to_string(),
            core_version: "1.2.3".to_string(),
            adjudication: Some(sample_adjudication()),
            finding: Some(crate::agentic_backend::AgenticNotificationFindingBackend {
                finding_key: "token_exfiltration|curl|evil.example.com:443".to_string(),
                severity: "HIGH".to_string(),
                description: "Anomalous outbound to evil.example.com".to_string(),
                reference: "CVE-2025-30066".to_string(),
                process_name: Some("curl".to_string()),
                destination_domain: Some("evil.example.com".to_string()),
                destination_ip: Some("10.0.0.1".to_string()),
                destination_port: Some(443),
                dismissed: true,
                verdict: Some("KEEP".to_string()),
                reasoning: Some(
                    "kept: curl read a token and reached a blacklisted host".to_string(),
                ),
                check: "token_exfiltration".to_string(),
                detection_basis: vec!["anomalous_session".to_string()],
                subject_path: None,
                process_path: Some("/usr/bin/curl".to_string()),
                parent_process_name: Some("bash".to_string()),
                parent_process_path: Some("/bin/bash".to_string()),
                parent_script_path: None,
                open_files: vec!["/Users/test/.aws/credentials".to_string()],
                session_uid: Some("session-1".to_string()),
                agent_type: None,
                agent_instance_id: None,
                first_detected: Some(Utc::now()),
            }),
        }
    }

    fn sample_adjudication() -> AgenticDismissalAdjudicationBackend {
        AgenticDismissalAdjudicationBackend {
            report_id: "vuln-report-42".to_string(),
            report_timestamp: chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 9, 17, 10, 0, 0)
                .unwrap(),
            decision_source: "llm_confirmed".to_string(),
            report_verdict: "FINDINGS".to_string(),
            model_verdict: Some("KEEP".to_string()),
            model_reasoning: Some(
                "curl read ~/.ssh/id_ed25519 then posted to an unknown host".to_string(),
            ),
            detector_severity: "HIGH".to_string(),
            adjudication_tier: "open".to_string(),
            detection_basis: vec!["sensitive_file:ssh".to_string()],
            evidence: Some(serde_json::json!({
                "session_is_anomalous": true,
                "credential_store_kind": "ssh",
            })),
            evidence_score: Some(serde_json::json!({ "total": 0.72 })),
        }
    }

    #[test]
    fn test_report_serialization_roundtrip_preserves_all_fields() {
        let report = sample();
        let json = serde_json::to_string(&report).expect("serialize must succeed");
        let parsed: AgenticDismissalReportBackend =
            serde_json::from_str(&json).expect("deserialize must succeed");
        assert_eq!(parsed.domain, report.domain);
        assert_eq!(parsed.finding_key, report.finding_key);
        assert_eq!(parsed.finding_title, report.finding_title);
        assert_eq!(parsed.finding_severity, report.finding_severity);
        assert_eq!(parsed.check_or_category, report.check_or_category);
        assert_eq!(parsed.scope, report.scope);
        assert_eq!(parsed.severity_ceiling, report.severity_ceiling);
        assert_eq!(parsed.ttl_secs, report.ttl_secs);
        assert_eq!(parsed.process_name, report.process_name);
        assert_eq!(parsed.process_path, report.process_path);
        assert_eq!(parsed.parent_process_name, report.parent_process_name);
        assert_eq!(parsed.parent_process_path, report.parent_process_path);
        assert_eq!(parsed.parent_script_path, report.parent_script_path);
        assert_eq!(parsed.material_classes, report.material_classes);
        assert_eq!(parsed.sensitive_path_classes, report.sensitive_path_classes);
        assert_eq!(parsed.destination_class, report.destination_class);
        assert_eq!(parsed.destination_port, report.destination_port);
        assert_eq!(parsed.agent_type, report.agent_type);
        assert_eq!(parsed.agent_instance_id, report.agent_instance_id);
        assert_eq!(parsed.workspace_root, report.workspace_root);
        assert_eq!(parsed.reason, report.reason);
        assert_eq!(parsed.note, report.note);
        assert_eq!(parsed.email, report.email);
        assert_eq!(parsed.os_name, report.os_name);
        assert_eq!(parsed.os_version, report.os_version);
        assert_eq!(parsed.core_version, report.core_version);
        assert_eq!(parsed.adjudication, report.adjudication);
    }

    #[test]
    fn test_report_serialized_field_names_match_lambda_contract() {
        // The Lambda contract is the snake_case JSON wire format. If any
        // field gets renamed (e.g. someone adds #[serde(rename = ...)]),
        // this test catches it before the change reaches the backend.
        let report = sample();
        let value: serde_json::Value =
            serde_json::to_value(&report).expect("to_value must succeed");
        let obj = value.as_object().expect("payload must be a JSON object");
        let expected_keys = [
            "domain",
            "finding_key",
            "finding_title",
            "finding_severity",
            "check_or_category",
            "scope",
            "severity_ceiling",
            "ttl_secs",
            "process_name",
            "process_path",
            "parent_process_name",
            "parent_process_path",
            "parent_script_path",
            "material_classes",
            "sensitive_path_classes",
            "destination_class",
            "destination_port",
            "agent_type",
            "agent_instance_id",
            "workspace_root",
            "reason",
            "note",
            "email",
            "os_name",
            "os_version",
            "core_version",
            "adjudication",
            "finding",
        ];
        for key in expected_keys {
            assert!(
                obj.contains_key(key),
                "JSON payload missing required Lambda contract field '{}'",
                key
            );
        }
        assert_eq!(
            obj.len(),
            expected_keys.len(),
            "JSON payload has unexpected fields: {:?}",
            obj.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_report_roundtrip_handles_minimum_payload() {
        // Operator chose Finding scope with no matcher overrides and no TTL;
        // every optional / matcher field must roundtrip as empty.
        let report = AgenticDismissalReportBackend {
            domain: "divergence".to_string(),
            finding_key: "divergence|alignment|key".to_string(),
            finding_title: String::new(),
            finding_severity: String::new(),
            check_or_category: String::new(),
            scope: "finding".to_string(),
            severity_ceiling: "high_and_below".to_string(),
            ttl_secs: None,
            process_name: String::new(),
            process_path: String::new(),
            parent_process_name: String::new(),
            parent_process_path: String::new(),
            parent_script_path: String::new(),
            material_classes: Vec::new(),
            sensitive_path_classes: Vec::new(),
            destination_class: String::new(),
            destination_port: None,
            agent_type: String::new(),
            agent_instance_id: String::new(),
            workspace_root: String::new(),
            reason: String::new(),
            note: String::new(),
            email: String::new(),
            os_name: String::new(),
            os_version: String::new(),
            core_version: String::new(),
            adjudication: None,
            finding: None,
        };
        let json = serde_json::to_string(&report).expect("serialize must succeed");
        let parsed: AgenticDismissalReportBackend =
            serde_json::from_str(&json).expect("deserialize must succeed");
        assert_eq!(parsed.scope, "finding");
        assert!(parsed.adjudication.is_none());
        assert!(parsed.ttl_secs.is_none());
        assert!(parsed.destination_port.is_none());
        assert!(parsed.material_classes.is_empty());
        assert!(parsed.sensitive_path_classes.is_empty());
    }

    #[test]
    fn test_report_no_serde_default_silently_inserts_missing_fields() {
        // Per workspace serde policy (no #[serde(default)] on backend wire
        // structs), removing any field from the JSON MUST cause deserialization
        // to fail loudly rather than silently coerce to defaults. This test
        // catches a future regression where someone accidentally adds
        // #[serde(default)] to one of these fields.
        let json = serde_json::to_value(sample()).expect("to_value");
        let mut obj = json.as_object().unwrap().clone();
        obj.remove("finding_key");
        let bad = serde_json::to_string(&obj).unwrap();
        let result: Result<AgenticDismissalReportBackend, _> = serde_json::from_str(&bad);
        assert!(
            result.is_err(),
            "missing finding_key must fail deserialization (no #[serde(default)] allowed)"
        );
    }

    /// Clients older than the field send no `adjudication` key at all. The
    /// Portal must keep accepting those reports (the mixed-fleet reason for
    /// the one `#[serde(default)]` on this struct), reading the field as
    /// `None` -- "no evidence was available" -- rather than rejecting the
    /// report.
    #[test]
    fn test_report_without_adjudication_key_deserializes_as_none() {
        let json = serde_json::to_value(sample()).expect("to_value");
        let mut obj = json.as_object().unwrap().clone();
        obj.remove("adjudication");
        let old_client = serde_json::to_string(&obj).unwrap();
        let parsed: AgenticDismissalReportBackend =
            serde_json::from_str(&old_client).expect("older-client payload must still parse");
        assert!(parsed.adjudication.is_none());
    }

    /// The nested adjudication snapshot is born complete: a device that sends
    /// it sends every field, and a missing one is a bug, not a default.
    #[test]
    fn test_adjudication_snapshot_has_no_silent_defaults() {
        let json = serde_json::to_value(sample_adjudication()).expect("to_value");
        let mut obj = json.as_object().unwrap().clone();
        obj.remove("detector_severity");
        let bad = serde_json::to_string(&obj).unwrap();
        let result: Result<AgenticDismissalAdjudicationBackend, _> = serde_json::from_str(&bad);
        assert!(
            result.is_err(),
            "missing detector_severity must fail deserialization (no #[serde(default)] allowed)"
        );
    }

    /// The evidence packet travels as opaque JSON and comes back byte-for-byte:
    /// the Portal stores it for training, it never interprets it.
    #[test]
    fn test_adjudication_evidence_roundtrips_as_json_value() {
        let snapshot = sample_adjudication();
        let json = serde_json::to_string(&snapshot).expect("serialize");
        let parsed: AgenticDismissalAdjudicationBackend =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.evidence, snapshot.evidence);
        assert_eq!(parsed.evidence_score, snapshot.evidence_score);
        assert_eq!(parsed.report_timestamp, snapshot.report_timestamp);
    }
}
