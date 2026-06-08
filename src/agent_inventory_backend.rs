use blake3::Hasher;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// First-seen classification of an agent footprint, mirrored from the core's
/// `AgentClassification`. Standing-state export only -- never an alert by
/// itself (the alarm lives in-app / in the agentic notification channel).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AgentInventoryClassificationBackend {
    /// Operator tapped "yes, this is me" -- the agent type is acknowledged.
    Acknowledged,
    /// Present on the host but its host-side observer is off (blind spot).
    Shadow,
    /// First-seen, unacknowledged footprint (the first-seen tripwire).
    New,
}

impl std::fmt::Display for AgentInventoryClassificationBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Acknowledged => write!(f, "acknowledged"),
            Self::Shadow => write!(f, "shadow"),
            Self::New => write!(f, "new"),
        }
    }
}

/// One row of the operator agent inventory exported to the fleet backend.
///
/// Pure metadata (counts + flags). It carries no transcript content, no file
/// bodies, and no secrets (privacy invariant I5): only the per-agent footprint
/// shape the fleet needs to spot shadow / first-seen agents across devices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInventoryRowBackend {
    /// Stable agent type slug (e.g. "cursor", "claude_code", "openclaw").
    pub agent_type: String,
    /// Human-readable agent name.
    pub display_name: String,
    /// First-seen classification.
    pub classification: AgentInventoryClassificationBackend,
    /// EDAMAME plugin installed in the agent's MCP config.
    pub installed: bool,
    /// Transcript root present on disk.
    pub discovered: bool,
    /// Host-side transcript observer enabled for this agent.
    pub observer_enabled: bool,
    /// Operator acknowledged this agent type ("yes, this is me").
    pub acknowledged: bool,
    /// Count of MCP endpoints declared by this agent.
    pub mcp_endpoint_count: u32,
    /// Count of SBOM components attributed to this agent.
    pub sbom_component_count: u32,
    /// Count of high-or-critical visibility findings touching this agent.
    pub alertable_finding_count: u32,
}

impl AgentInventoryRowBackend {
    pub fn uid(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(self.agent_type.as_bytes());
        hasher.update(self.classification.to_string().as_bytes());
        hasher.update(&[
            self.installed as u8,
            self.discovered as u8,
            self.observer_enabled as u8,
            self.acknowledged as u8,
        ]);
        hasher.update(self.mcp_endpoint_count.to_le_bytes().as_slice());
        hasher.update(self.sbom_component_count.to_le_bytes().as_slice());
        hasher.update(self.alertable_finding_count.to_le_bytes().as_slice());
        hasher.finalize().to_hex().to_string()
    }
}

/// Device-scoped standing snapshot of every agent footprint on the host.
///
/// This is the standing-state counterpart to the event-shaped
/// `AgenticNotificationBackend`: rather than reporting a single moment-in-time
/// alert, it reports the current inventory so the fleet can answer "which
/// agents exist on which devices, and which are unacknowledged / unobserved".
/// It mirrors the device-identity header of `AgenticNotificationBackend` so the
/// backend can key it to the same device, and is pushed on each structural
/// visibility refresh and on operator acknowledge / unacknowledge (deduped by
/// `uid()` so a steady-state refresh does not re-send unchanged inventory).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInventoryBackend {
    /// UTC timestamp when the snapshot was taken.
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

    // -- Rollup counts --------------------------------------------------
    /// Total inventory rows (agents with any footprint or acknowledged).
    pub agent_count: u32,
    /// Rows classified `acknowledged`.
    pub acknowledged_count: u32,
    /// Rows classified `shadow` (present but unobserved).
    pub shadow_count: u32,
    /// Rows classified `new` (first-seen, unacknowledged).
    pub new_count: u32,
    /// Total high-or-critical visibility findings across all agents.
    pub alertable_finding_count: u32,

    // -- Rows -----------------------------------------------------------
    /// Per-agent inventory rows.
    pub agents: Vec<AgentInventoryRowBackend>,
}

impl AgentInventoryBackend {
    /// Content fingerprint over device identity + every row, used to dedup
    /// pushes. The timestamp is intentionally excluded so an unchanged
    /// inventory taken at a later tick hashes identically.
    pub fn uid(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(self.hostname.as_bytes());
        hasher.update(self.ip4.as_bytes());
        hasher.update(self.ip6.as_bytes());
        hasher.update(self.model.as_bytes());
        hasher.update(self.os_version.as_bytes());
        for row in &self.agents {
            hasher.update(row.uid().as_bytes());
        }
        hasher.finalize().to_hex().to_string()
    }
}
