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
}
