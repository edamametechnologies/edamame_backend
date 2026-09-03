//! Structured per-domain detail shipped alongside a score report.
//!
//! One [`DetailBackend`] bundle per data class. A bundle carries its own consent
//! mode, the observation tri-state (`coverage`), the always-on posture snapshot
//! (`inventory`), and the evidence naming why individual checks failed
//! (`checks`). Bundling them means consent and payload cannot drift apart on
//! the wire: a denied bundle is structurally incapable of carrying detail (see
//! [`DetailBackend::with_payload`]).
//!
//! Today the only domain is `ai`. A future domain (FIM, capture, …) is an extra
//! element in `DetailedScoreBackend.details`, not a new top-level field.
//!
//! See `edamame_core/AIGOVERNANCE.md`.

use serde::{Deserialize, Serialize};

/// Hard cap on failure causes per check in a single score report.
pub const MAX_FAILURE_CAUSES: usize = 32;

/// Hard caps on the always-on posture inventory. Unlike [`MAX_FAILURE_CAUSES`],
/// hitting these is display-only: inventory is never whitelist-matched, so a
/// dropped row cannot make an uncovered cause look covered. See
/// [`AiInventoryBackend::truncated`].
pub const MAX_INVENTORY_AGENTS: usize = 32;
pub const MAX_INVENTORY_HARNESSES: usize = 32;
pub const MAX_INVENTORY_MCP_SERVERS_PER_AGENT: usize = 64;
pub const MAX_INVENTORY_CRITICAL_PROCESSES_PER_AGENT: usize = 32;
pub const MAX_INVENTORY_SECRET_LABELS_PER_AGENT: usize = 32;
pub const MAX_INVENTORY_RULE_IDS_PER_SERVER: usize = 16;

/// Hard caps on the rich display-only context attached to a check.
///
/// Unlike [`MAX_FAILURE_CAUSES`], hitting these is cosmetic in exactly the way
/// [`AiInventoryBackend::truncated`] is: context is never whitelist-matched, so
/// a dropped row can never make an uncovered cause look covered, and must never
/// change a derived governance verdict.
pub const MAX_CHECK_CONTEXT_ROWS: usize = 24;
pub const MAX_CONTEXT_FACTS: usize = 16;
/// Ceiling on any single free-text context string (title, summary, fact value).
/// Bounds report size and caps the blast radius of an unexpectedly long
/// deterministic description.
pub const MAX_CONTEXT_TEXT_LEN: usize = 512;

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

/// Closed vocabulary of failure selector kinds used by Hub governance
/// whitelisting. Keys are normalized at emit time (process basename, MCP
/// server_name, MCP rule id, secret label).
///
/// Every kind here is an AI-posture kind today, but the carrier is
/// domain-generic: another domain that can name what made a check fail adds a
/// kind rather than a parallel structure. Stringly-typed on the wire for the
/// same forward-compatibility reason as [`DetailDomainBackend`].
///
/// Note there is deliberately no `agent` selector kind. The agent is the
/// *subject* of a cause ([`FailureCauseBackend::scope`]), never an acceptable
/// reason to pass a check -- otherwise "accept cursor" would silently accept
/// every future failure cursor develops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FailureSelectorKindBackend {
    /// Broad blast-radius condition (`passwordless_root`, `critical_subprocess`,
    /// `secret_exposure`).
    Amplifier,
    /// Normalized basename of a critical subprocess the agent spawned.
    CriticalProcess,
    /// MCP server name declared by an agent.
    McpServer,
    /// MCP exposure rule id.
    McpRule,
    /// Governance-harness state for the scoped agent (`missing`, `diverging`).
    HarnessState,
    /// Class of secret material reachable by the agent.
    SecretLabel,
    /// Host-side transcript observer state for the scoped agent (`paused`).
    Observer,
    /// Detector family behind an attack finding (`credential_harvest`,
    /// `token_exfiltration`, ...).
    AttackFamily,
    /// Stable `finding_key` of one attack finding -- the narrowest possible
    /// acceptance.
    AttackFinding,
    /// Normalized basename of the process an attack finding is attributed to.
    AttackProcess,
    /// Destination an attack finding egressed to (domain, else IP).
    AttackDestination,
    /// Category of one divergence evidence row (`correlation:unexplained`, ...).
    DivergenceCategory,
    /// Stable `finding_key` of one divergence evidence row.
    DivergenceFinding,
    /// Normalized basename of the process a divergence row is attributed to.
    DivergenceProcess,
    /// Class of an escalated advisor action awaiting review.
    EscalatedAction,
    /// The runtime engine behind a check is not running (`stopped`).
    ///
    /// Its own kind because "the detector found something" and "the detector is
    /// switched off" are different operational states that the raw boolean
    /// collapses together. Without it a stopped engine would emit a cause-less
    /// Active check, which the Hub could derive `Passed` for vacuously.
    EngineState,
}

impl FailureSelectorKindBackend {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Amplifier => "amplifier",
            Self::CriticalProcess => "critical_process",
            Self::McpServer => "mcp_server",
            Self::McpRule => "mcp_rule",
            Self::HarnessState => "harness_state",
            Self::SecretLabel => "secret_label",
            Self::Observer => "observer",
            Self::AttackFamily => "attack_family",
            Self::AttackFinding => "attack_finding",
            Self::AttackProcess => "attack_process",
            Self::AttackDestination => "attack_destination",
            Self::DivergenceCategory => "divergence_category",
            Self::DivergenceFinding => "divergence_finding",
            Self::DivergenceProcess => "divergence_process",
            Self::EscalatedAction => "escalated_action",
            Self::EngineState => "engine_state",
        }
    }
}

/// One way to name a failure cause. A whitelist rule matches a selector.
///
/// Wire token form (for display / docs): `{kind}:{key}` e.g.
/// `critical_process:ssh`, `mcp_server:gojiberry`, `amplifier:passwordless_root`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FailureSelectorBackend {
    /// Selector kind -- see [`FailureSelectorKindBackend`].
    pub kind: String,
    /// Normalized stable key (process basename, MCP server_name, secret label, …).
    pub key: String,
}

impl FailureSelectorBackend {
    pub fn new(kind: FailureSelectorKindBackend, key: impl Into<String>) -> Self {
        Self {
            kind: kind.as_str().to_string(),
            key: key.into(),
        }
    }

    /// Display / whitelist token: `kind:key`.
    pub fn token(&self) -> String {
        format!("{}:{}", self.kind, self.key)
    }
}

/// One independent reason a check failed, plus every alternative way to name it.
///
/// The cause is the unit of acceptance. A cause is covered when a whitelist rule
/// matches **any** of its `selectors` (they describe the same condition at
/// different granularities -- `mcp_rule` accepts the exposure class everywhere,
/// `mcp_server` accepts one server). A check can be marked passing only when
/// **every** cause is covered, so accepting one condition never silently accepts
/// a different one on the same agent.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FailureCauseBackend {
    /// Subject this cause belongs to. AI posture checks put the agent slug here
    /// (`cursor`, `claude_code`, …). Empty when host-global.
    pub scope: String,
    /// Alternative names for this one condition. Never empty.
    pub selectors: Vec<FailureSelectorBackend>,
}

impl FailureCauseBackend {
    pub fn new(scope: impl Into<String>, selectors: Vec<FailureSelectorBackend>) -> Self {
        Self {
            scope: scope.into(),
            selectors,
        }
    }

    /// A cause with no selector can never be accepted, so it must never ship.
    pub fn is_valid(&self) -> bool {
        !self.selectors.is_empty()
            && self
                .selectors
                .iter()
                .all(|s| !s.kind.is_empty() && !s.key.is_empty())
    }

    /// Stable identity across reports: scope plus the selector token set.
    /// Selectors are emitted sorted, so this is order-independent in practice.
    pub fn fingerprint(&self) -> String {
        let mut tokens: Vec<String> = self.selectors.iter().map(|s| s.token()).collect();
        tokens.sort();
        tokens.dedup();
        format!("{}|{}", self.scope, tokens.join(","))
    }
}

/// Closed vocabulary of diagnostic-context kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CheckContextKindBackend {
    /// Governance harness detected on the host (`nono`, `srt`, …).
    Harness,
    /// One attack finding, carrying the card an operator already sees on the
    /// device. `key` is the finding_key.
    AttackFinding,
    /// One divergence evidence row. `key` is the finding_key.
    DivergenceFinding,
    /// One escalated advisor action awaiting review. `key` is the action id.
    EscalatedAction,
}

impl CheckContextKindBackend {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Harness => "harness",
            Self::AttackFinding => "attack_finding",
            Self::DivergenceFinding => "divergence_finding",
            Self::EscalatedAction => "escalated_action",
        }
    }
}

/// One `label: value` row of a [`ContextDetailBackend`], mirroring a row of the
/// on-device finding card.
///
/// Values are metadata only -- process basenames, destinations, detection-basis
/// tokens, severities, counts. Never file content, environment values, secret
/// material, or transcript bodies. See the consent ceiling in
/// `edamame_core/AIGOVERNANCE.md` §4.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContextFactBackend {
    pub label: String,
    pub value: String,
}

impl ContextFactBackend {
    pub fn new(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            label: truncate_context_text(label.into()),
            value: truncate_context_text(value.into()),
        }
    }
}

/// The third level of check detail: what the operator already sees on the
/// device when an attack or divergence finding is raised.
///
/// The first two levels answer governance questions -- `causes` is what an
/// administrator may accept, `context` (kind/key) is what explains the failure
/// without being acceptable. Neither carries enough for a reviewer to actually
/// *judge* a runtime finding: "attack_family:credential_harvest on cursor" says
/// what fired, not what happened. This level carries that, so a Hub reviewer
/// reaches the same decision the device user would from the same evidence.
///
/// Display-only, exactly like the row that owns it: never whitelist-matched,
/// and truncating it must never change a derived verdict.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct ContextDetailBackend {
    /// Card headline. Uses the "attack" vocabulary, not the internal
    /// "vulnerability" type names.
    pub title: String,
    /// `critical` / `high` / `medium` / `low`, lowercased at emit time.
    pub severity: String,
    /// The deterministic description shown in the card body. Never an LLM
    /// rationale: that is generated prose over telemetry and is the highest
    /// disclosure risk in the finding.
    pub summary: String,
    /// What the finding is about -- process basename, or agent slug for
    /// divergence. May be empty when host-global.
    pub subject: String,
    /// Card rows, capped at [`MAX_CONTEXT_FACTS`].
    pub facts: Vec<ContextFactBackend>,
    /// Framework tokens already carried by the finding (OWASP / ATLAS / rule
    /// reference). Display-only.
    pub references: Vec<String>,
    /// The finding is currently dismissed on the device. Dismissed findings
    /// still ship so the Hub can show that a condition was reviewed locally
    /// rather than silently absent.
    pub dismissed: bool,
}

impl ContextDetailBackend {
    pub fn new(
        title: impl Into<String>,
        severity: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            title: truncate_context_text(title.into()),
            severity: severity.into().trim().to_ascii_lowercase(),
            summary: truncate_context_text(summary.into()),
            subject: String::new(),
            facts: Vec::new(),
            references: Vec::new(),
            dismissed: false,
        }
    }

    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = truncate_context_text(subject.into());
        self
    }

    /// Attach card rows. Empty labels or values are dropped, and the list is
    /// capped at [`MAX_CONTEXT_FACTS`].
    pub fn with_facts(mut self, facts: Vec<ContextFactBackend>) -> Self {
        self.facts = facts
            .into_iter()
            .filter(|f| !f.label.is_empty() && !f.value.is_empty())
            .take(MAX_CONTEXT_FACTS)
            .collect();
        self
    }

    pub fn with_references(mut self, references: Vec<String>) -> Self {
        self.references = references
            .into_iter()
            .map(truncate_context_text)
            .filter(|r| !r.is_empty())
            .take(MAX_CONTEXT_FACTS)
            .collect();
        self
    }

    pub fn with_dismissed(mut self, dismissed: bool) -> Self {
        self.dismissed = dismissed;
        self
    }
}

/// Clamp one context string to [`MAX_CONTEXT_TEXT_LEN`], on a char boundary so
/// the result is always valid UTF-8.
pub fn truncate_context_text(raw: String) -> String {
    let trimmed = raw.trim();
    if trimmed.len() <= MAX_CONTEXT_TEXT_LEN {
        return trimmed.to_string();
    }
    let mut end = MAX_CONTEXT_TEXT_LEN;
    while end > 0 && !trimmed.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &trimmed[..end])
}

/// Display-only fact that helps an operator read a finding but is **never**
/// whitelist-matched.
///
/// A detected harness is the canonical example: knowing that `nono` is installed
/// explains why `harness_divergence` fired rather than `agents_without_harness`,
/// but "a harness is installed" is not a reason to accept an agent escaping it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CheckContextBackend {
    /// Context kind -- see [`CheckContextKindBackend`].
    pub kind: String,
    /// Normalized stable key.
    pub key: String,
    /// Optional subject. Empty when host-global.
    pub scope: String,
    /// The rich card behind this row, when the kind has one. `None` for a bare
    /// diagnostic like `harness:nono`.
    ///
    /// `#[serde(default)]` -- the one place in this module where it is correct.
    /// This surface HAS shipped (Hub `report_score` already ingests `details`
    /// and parses it as [`DetailBackend`]), and clients roll out over weeks. A
    /// required field here would make every pre-upgrade client's whole bundle
    /// fail deserialization on the Hub and silently blank its AI governance
    /// view. Same rollout-skew reason as `AiWhitelistBackend::enforced_kinds`.
    #[serde(default)]
    pub detail: Option<ContextDetailBackend>,
}

impl CheckContextBackend {
    pub fn new(kind: CheckContextKindBackend, key: impl Into<String>) -> Self {
        Self {
            kind: kind.as_str().to_string(),
            key: key.into(),
            scope: String::new(),
            detail: None,
        }
    }

    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = scope.into();
        self
    }

    pub fn with_detail(mut self, detail: ContextDetailBackend) -> Self {
        self.detail = Some(detail);
        self
    }

    pub fn token(&self) -> String {
        format!("{}:{}", self.kind, self.key)
    }
}

/// Evidence for one failing check, keyed by the check's metric name.
///
/// Keyed here rather than carried on `ThreatMetricBackend` so that consent
/// governs one place: dropping the bundle drops every cause with it, instead of
/// requiring a sweep over the metric list before send.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CheckDetailBackend {
    /// Metric name of the failing check (`agents_with_blast_radius`, …).
    pub check: String,
    /// Framework reference tokens for the CHECK as a whole -- the static
    /// crosswalk of what this check evidences (`OWASP-ASI05`, `OWASP-LLM06`,
    /// `AML.T0053`, `TC-AID-01`, `ISO42001-A.4.5`, ...). Derived by the client
    /// from the same catalogs its OWASP / ATLAS / Trust Controls scorecards use,
    /// so the Hub can group live failing checks by framework without a mapping
    /// table of its own. Metadata only: never consulted for severity, alerting,
    /// or acceptance. Per-finding references stay on the context rows.
    pub references: Vec<String>,
    /// Independent reasons the check failed. Every one must be covered before
    /// the Hub may derive a passing governance status.
    pub causes: Vec<FailureCauseBackend>,
    /// Display-only diagnostics. Never whitelist-matched.
    pub context: Vec<CheckContextBackend>,
    /// True when emit-time capping dropped additional causes. A truncated check
    /// can never derive a passing governance status: the dropped causes are
    /// unknown, so "everything is covered" is unprovable.
    pub truncated: bool,
}

impl CheckDetailBackend {
    pub fn new(
        check: impl Into<String>,
        causes: Vec<FailureCauseBackend>,
        context: Vec<CheckContextBackend>,
        truncated: bool,
    ) -> Self {
        Self {
            check: check.into(),
            references: Vec::new(),
            causes,
            context,
            truncated,
        }
    }

    /// Nothing to report for this check.
    /// Attach the check-level framework reference tokens (sorted, deduped).
    pub fn with_references(mut self, references: Vec<String>) -> Self {
        let mut references: Vec<String> = references
            .into_iter()
            .map(|r| r.trim().to_string())
            .filter(|r| !r.is_empty())
            .collect();
        references.sort();
        references.dedup();
        self.references = references;
        self
    }

    pub fn is_empty(&self) -> bool {
        self.causes.is_empty() && self.context.is_empty()
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
/// whitelist-matched -- that is [`FailureCauseBackend`]'s job. They exist
/// because a boolean check cannot separate "absent" from "present and
/// healthy": both are Inactive. See `edamame_core/AIGOVERNANCE.md`.
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
/// collected under, what EDAMAME can see (coverage + posture inventory), and
/// why checks failed.
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
    /// Minimal observation tri-state (present/monitored). Empty when denied.
    pub coverage: Vec<CoverageRowBackend>,
    /// Always-on AI posture snapshot (sandbox / harness / amplifiers / MCP).
    /// Informational only -- never whitelist-matched. `None` when denied.
    pub inventory: Option<AiInventoryBackend>,
    /// Per-check failure evidence. Empty when denied, or when no check in this
    /// domain is failing.
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
            inventory: None,
            checks: Vec::new(),
        }
    }

    /// Whether this bundle's mode permits carrying detail.
    pub fn allows_detail(&self) -> bool {
        self.mode != DetailModeBackend::Denied.as_str()
    }

    /// Attach coverage, posture inventory, and evidence. **No-op when the mode
    /// denies export**, so "denied" and "carries detail" cannot both be true on
    /// the wire regardless of what the caller computed.
    pub fn with_payload(
        mut self,
        coverage: Vec<CoverageRowBackend>,
        checks: Vec<CheckDetailBackend>,
        inventory: Option<AiInventoryBackend>,
    ) -> Self {
        if self.allows_detail() {
            self.coverage = coverage;
            self.checks = checks;
            self.inventory = inventory;
        } else {
            self.coverage.clear();
            self.checks.clear();
            self.inventory = None;
        }
        self
    }
}

/// Always-on AI posture snapshot for Hub / local drill-down.
///
/// Independent of Active checks: emit whenever export is allowed so admins can
/// inspect sandbox, harness, privilege amplifiers, and MCP even when green.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct AiInventoryBackend {
    pub host: AiHostInventoryBackend,
    /// Full known harness roster with a `detected` flag per slug.
    pub harnesses: Vec<AiHarnessInventoryBackend>,
    pub agents: Vec<AiAgentInventoryBackend>,
    /// True when an inventory cap dropped rows. Display-only: unlike
    /// [`CheckDetailBackend::truncated`], this must never change a derived
    /// governance verdict, because inventory is not the matched surface.
    pub truncated: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct AiHostInventoryBackend {
    pub assessed: bool,
    pub passwordless_root: bool,
    pub admin_user: bool,
    pub elevated_session: bool,
    pub user: String,
    pub platform: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct AiHarnessInventoryBackend {
    pub slug: String,
    pub display_name: String,
    pub detected: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct AiAgentInventoryBackend {
    /// Normalized agent key. Uses the same normalization as a
    /// [`FailureCauseBackend::scope`] so the Hub can join an inventory row to
    /// the cause an Accept would resolve against.
    pub key: String,
    pub present: bool,
    pub monitored: bool,
    pub sandbox: AiSandboxInventoryBackend,
    pub amplifiers: AiAmplifiersInventoryBackend,
    /// Critical process basenames attributed to this agent (empty when none).
    /// Normalized as [`FailureSelectorKindBackend::CriticalProcess`] keys.
    pub critical_processes: Vec<String>,
    /// Secret-exposure labels attributed to this agent (empty when none).
    /// Normalized as [`FailureSelectorKindBackend::SecretLabel`] keys.
    pub secret_exposure_labels: Vec<String>,
    /// All declared MCP endpoints for this agent (not only HIGH/CRITICAL).
    pub mcp_servers: Vec<AiMcpServerInventoryBackend>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct AiSandboxInventoryBackend {
    /// `None` when sandbox state was not assessed for this agent.
    pub sandboxed: Option<bool>,
    pub mechanism: String,
    pub file_access_scope: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct AiAmplifiersInventoryBackend {
    pub unsandboxed: bool,
    pub passwordless_root: bool,
    pub critical_subprocess: bool,
    pub secret_exposure: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct AiMcpServerInventoryBackend {
    /// Normalized as a [`FailureSelectorKindBackend::McpServer`] key.
    pub server_name: String,
    pub transport: String,
    pub exposure_scope: String,
    pub auth_strength: String,
    pub is_edamame_server: bool,
    /// Highest severity among visibility findings for this endpoint; empty
    /// when none.
    pub max_severity: String,
    /// True when any finding is HIGH/CRITICAL (alertable gate).
    pub alertable: bool,
    /// Rule identifiers behind this endpoint's findings, normalized as
    /// [`FailureSelectorKindBackend::McpRule`] keys so the Hub can offer a
    /// per-rule Accept instead of only a whole-server one.
    pub rule_ids: Vec<String>,
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
            vec![FailureCauseBackend::new(
                "cursor",
                vec![FailureSelectorBackend::new(
                    FailureSelectorKindBackend::Observer,
                    "paused",
                )],
            )],
            Vec::new(),
            false,
        )]
    }

    fn sample_inventory() -> AiInventoryBackend {
        AiInventoryBackend {
            host: AiHostInventoryBackend {
                assessed: true,
                passwordless_root: true,
                admin_user: false,
                elevated_session: false,
                user: "alice".to_string(),
                platform: "macos".to_string(),
            },
            harnesses: vec![AiHarnessInventoryBackend {
                slug: "nono".to_string(),
                display_name: "nono".to_string(),
                detected: true,
            }],
            agents: vec![AiAgentInventoryBackend {
                key: "cursor".to_string(),
                present: true,
                monitored: false,
                sandbox: AiSandboxInventoryBackend {
                    sandboxed: Some(false),
                    mechanism: String::new(),
                    file_access_scope: String::new(),
                },
                amplifiers: AiAmplifiersInventoryBackend {
                    unsandboxed: true,
                    passwordless_root: true,
                    critical_subprocess: false,
                    secret_exposure: false,
                },
                critical_processes: vec!["ssh".to_string()],
                secret_exposure_labels: vec!["aws_credentials".to_string()],
                mcp_servers: vec![AiMcpServerInventoryBackend {
                    server_name: "filesystem".to_string(),
                    transport: "stdio".to_string(),
                    exposure_scope: "stdio".to_string(),
                    auth_strength: "none".to_string(),
                    is_edamame_server: false,
                    max_severity: "low".to_string(),
                    alertable: false,
                    rule_ids: vec!["shell_exec".to_string()],
                }],
            }],
            truncated: false,
        }
    }

    #[test]
    fn denied_bundle_cannot_carry_payload() {
        let bundle = DetailBackend::new(DetailDomainBackend::Ai, DetailModeBackend::Denied)
            .with_payload(sample_coverage(), sample_checks(), Some(sample_inventory()));
        assert!(!bundle.allows_detail());
        assert!(bundle.coverage.is_empty());
        assert!(bundle.checks.is_empty());
        assert!(bundle.inventory.is_none());
    }

    #[test]
    fn forced_bundle_carries_payload() {
        let bundle = DetailBackend::new(DetailDomainBackend::Ai, DetailModeBackend::Forced)
            .with_payload(sample_coverage(), sample_checks(), Some(sample_inventory()));
        assert!(bundle.allows_detail());
        assert_eq!(bundle.coverage.len(), 1);
        assert_eq!(bundle.checks.len(), 1);
        assert!(bundle.inventory.is_some());
        assert_eq!(bundle.inventory.as_ref().unwrap().agents.len(), 1);
    }

    #[test]
    fn wire_shape_is_flat_strings() {
        let bundle = DetailBackend::new(DetailDomainBackend::Ai, DetailModeBackend::Enabled)
            .with_payload(sample_coverage(), sample_checks(), Some(sample_inventory()));
        let json = serde_json::to_value(&bundle).expect("serialize");
        assert_eq!(json["domain"], "ai");
        assert_eq!(json["mode"], "enabled");
        assert_eq!(json["coverage"][0]["kind"], "agent");
        assert_eq!(json["coverage"][0]["key"], "cursor");
        assert_eq!(json["coverage"][0]["present"], true);
        assert_eq!(json["coverage"][0]["monitored"], false);
        assert_eq!(json["inventory"]["host"]["passwordless_root"], true);
        assert_eq!(json["inventory"]["harnesses"][0]["slug"], "nono");
        assert_eq!(json["inventory"]["agents"][0]["key"], "cursor");
        assert_eq!(
            json["inventory"]["agents"][0]["mcp_servers"][0]["server_name"],
            "filesystem"
        );
        assert_eq!(json["inventory"]["truncated"], false);
        assert_eq!(
            json["inventory"]["agents"][0]["critical_processes"][0],
            "ssh"
        );
        assert_eq!(
            json["inventory"]["agents"][0]["secret_exposure_labels"][0],
            "aws_credentials"
        );
        assert_eq!(
            json["inventory"]["agents"][0]["mcp_servers"][0]["rule_ids"][0],
            "shell_exec"
        );
        assert_eq!(json["checks"][0]["check"], "unsecured_cursor");
        assert_eq!(json["checks"][0]["truncated"], false);
        assert_eq!(json["checks"][0]["causes"][0]["scope"], "cursor");
        assert_eq!(
            json["checks"][0]["causes"][0]["selectors"][0]["kind"],
            "observer"
        );
        assert_eq!(
            json["checks"][0]["causes"][0]["selectors"][0]["key"],
            "paused"
        );
        assert!(json["checks"][0]["context"].as_array().unwrap().is_empty());
    }

    #[test]
    fn missing_payload_fields_fail_to_deserialize() {
        // No shipped producer omits these, so a missing field is a bug, not an
        // old client. Defaulting `checks` to empty would read as "nothing is
        // failing" and silently derive a passing governance verdict.
        let err = serde_json::from_str::<DetailBackend>(r#"{"domain":"ai","mode":"denied"}"#)
            .expect_err("missing payload fields must not deserialize");
        assert!(err.to_string().contains("coverage"), "{err}");
    }

    #[test]
    fn denied_bundle_round_trips_with_explicit_empty_payload() {
        let bundle = DetailBackend::new(DetailDomainBackend::Ai, DetailModeBackend::Denied);
        let json = serde_json::to_string(&bundle).expect("serialize");
        let parsed: DetailBackend = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, bundle);
        assert!(parsed.inventory.is_none());
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
    fn selector_token_is_kind_colon_key() {
        let selector =
            FailureSelectorBackend::new(FailureSelectorKindBackend::CriticalProcess, "ssh");
        assert_eq!(selector.token(), "critical_process:ssh");
    }

    #[test]
    fn cause_without_selectors_is_invalid() {
        let cause = FailureCauseBackend::new("cursor", Vec::new());
        assert!(!cause.is_valid());
    }

    #[test]
    fn cause_with_blank_selector_key_is_invalid() {
        let cause = FailureCauseBackend::new(
            "cursor",
            vec![FailureSelectorBackend::new(
                FailureSelectorKindBackend::McpServer,
                "",
            )],
        );
        assert!(!cause.is_valid());
    }

    #[test]
    fn cause_fingerprint_is_selector_order_independent() {
        let a = FailureCauseBackend::new(
            "cursor",
            vec![
                FailureSelectorBackend::new(FailureSelectorKindBackend::McpRule, "shell_exec"),
                FailureSelectorBackend::new(FailureSelectorKindBackend::McpServer, "gojiberry"),
            ],
        );
        let b = FailureCauseBackend::new(
            "cursor",
            vec![
                FailureSelectorBackend::new(FailureSelectorKindBackend::McpServer, "gojiberry"),
                FailureSelectorBackend::new(FailureSelectorKindBackend::McpRule, "shell_exec"),
            ],
        );
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn cause_fingerprint_separates_scopes() {
        let selectors = vec![FailureSelectorBackend::new(
            FailureSelectorKindBackend::Observer,
            "paused",
        )];
        let cursor = FailureCauseBackend::new("cursor", selectors.clone());
        let claude = FailureCauseBackend::new("claude_code", selectors);
        assert_ne!(cursor.fingerprint(), claude.fingerprint());
    }

    #[test]
    fn context_is_separate_from_causes_on_the_wire() {
        let detail = CheckDetailBackend::new(
            "harness_divergence",
            vec![FailureCauseBackend::new(
                "cursor",
                vec![FailureSelectorBackend::new(
                    FailureSelectorKindBackend::CriticalProcess,
                    "ssh",
                )],
            )],
            vec![
                CheckContextBackend::new(CheckContextKindBackend::Harness, "nono")
                    .with_scope("cursor"),
            ],
            false,
        );
        let json = serde_json::to_value(&detail).expect("serialize");
        assert_eq!(
            json["causes"][0]["selectors"][0]["kind"],
            "critical_process"
        );
        assert_eq!(json["context"][0]["kind"], "harness");
        assert_eq!(json["context"][0]["key"], "nono");
        assert_eq!(json["context"][0]["scope"], "cursor");
        // Context carries no selectors: it can never be matched by a rule.
        assert!(json["context"][0].get("selectors").is_none());
    }
}
