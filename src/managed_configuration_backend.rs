use serde::{Deserialize, Serialize};

/// The device's answer to its domain's Hub-managed configuration (2.0.5),
/// carried by every score report so the domain's admins see adoption. Never
/// a secret: the Portal enrollment token stays on the device.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ManagedConfigurationStatusBackend {
    /// The configuration of the list this device took: `app`, `cicd` or
    /// `posture`.
    pub target: String,
    /// The configuration answered (`sha256:...`).
    pub fingerprint: String,
    /// `pending`, `accepted` or `declined`.
    pub state: String,
    /// The device exchanged its Portal enrollment token for a key.
    pub portal_enrolled: bool,
    /// Problems verifying or applying it (never a secret).
    pub errors: Vec<String>,
    /// The fingerprint of the configuration in force, the one `elements`
    /// describes: the accepted one, also while a newer one is `pending`.
    /// Empty when none is in force (2.2.4).
    /// `#[serde(default)]`: agents before 2.2.4 omit it on the wire.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub applied_fingerprint: String,
    /// Element by element, what the configuration in force wants and what
    /// the device runs, so the domain's admins see whether it is really set
    /// (2.2.4). Empty when nothing is in force or not measured yet.
    /// `#[serde(default)]`: agents before 2.2.4 omit it on the wire.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub elements: Vec<ManagedConfigurationElementStatusBackend>,
}

/// One element of the configuration in force, as the device runs it.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd)]
pub struct ManagedConfigurationElementStatusBackend {
    /// The element: `protection_enabled`, `assistant_level`,
    /// `share_ai_failure_details`, `lan_auto_scan`, `capture_enabled`,
    /// `file_monitor_enabled`, `portal`.
    pub key: String,
    /// What the configuration sets: `true` / `false`, `review` / `auto`, or
    /// `portal`.
    pub wanted: String,
    /// What the device runs, in the same vocabulary; for `portal` the model
    /// in use: `portal` (the domain's Portal account), `portal_signed_in`
    /// (the user's own Portal sign-in), `claude`, `openai`, `ollama`,
    /// `none`. Empty when it could not be measured.
    pub effective: String,
    /// `applied`: runs as wanted. `changed_by_user`: the user's own setting
    /// differs (an element the configuration does not lock). `not_running`:
    /// set as wanted but not running (a service that failed to start, a
    /// Portal account not enrolled yet). `set_by_device`: the device's own
    /// policy locks it and keeps its value (not the user's doing).
    /// `unmeasured`: the device could not read it.
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_answer_from_an_agent_before_2_2_4_still_parses_and_new_fields_stay_off_the_wire_when_empty(
    ) {
        let old: ManagedConfigurationStatusBackend = serde_json::from_value(serde_json::json!({
            "target": "app",
            "fingerprint": "sha256:00",
            "state": "accepted",
            "portal_enrolled": false,
            "errors": []
        }))
        .unwrap();
        assert!(old.applied_fingerprint.is_empty());
        assert!(old.elements.is_empty());
        let json = serde_json::to_value(&old).unwrap();
        assert!(json.get("applied_fingerprint").is_none());
        assert!(json.get("elements").is_none());

        let mut new = old.clone();
        new.applied_fingerprint = "sha256:00".to_string();
        new.elements.push(ManagedConfigurationElementStatusBackend {
            key: "capture_enabled".to_string(),
            wanted: "true".to_string(),
            effective: "false".to_string(),
            status: "changed_by_user".to_string(),
        });
        let json = serde_json::to_value(&new).unwrap();
        assert_eq!(json["applied_fingerprint"], "sha256:00");
        assert_eq!(json["elements"][0]["status"], "changed_by_user");
        let back: ManagedConfigurationStatusBackend = serde_json::from_value(json).unwrap();
        assert_eq!(back, new);
    }
}
