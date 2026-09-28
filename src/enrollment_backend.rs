//! Hub enrollment tokens (MDM deployment without per-user PINs).
//!
//! A device presents an admin-created domain enrollment token once, to
//! `POST {score gateway}enroll`, and receives a per-device credential. It then
//! reports its score with that credential in the
//! [`DEVICE_CREDENTIAL_HEADER`] header instead of the `code` (PIN) query
//! parameter. Both secrets travel in the body / a header, never in a URL.
use serde::{Deserialize, Serialize};

/// Prefix of an enrollment token (`edm_enr_<32 hex id>_<43 base64url>`).
pub const ENROLLMENT_TOKEN_PREFIX: &str = "edm_enr_";

/// Prefix of a device credential (`edm_dev_<43 base64url>`).
pub const DEVICE_CREDENTIAL_PREFIX: &str = "edm_dev_";

/// Header carrying a token-enrolled device's credential on score reports.
pub const DEVICE_CREDENTIAL_HEADER: &str = "x-edamame-device-credential";

/// Body of `POST enroll`. Wire contract: the Hub reads exactly these fields.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollDeviceRequestBackend {
    pub device_id: String,
    pub connected_user: String,
    pub connected_domain: String,
    pub enrollment_token: String,
}

/// Answer of a successful `POST enroll`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrollDeviceResponseBackend {
    pub device_credential: String,
}

// Secrets never reach a log through Debug.
impl std::fmt::Debug for EnrollDeviceRequestBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollDeviceRequestBackend")
            .field("device_id", &self.device_id)
            .field("connected_user", &self.connected_user)
            .field("connected_domain", &self.connected_domain)
            .field("enrollment_token", &"<redacted>")
            .finish()
    }
}

impl std::fmt::Debug for EnrollDeviceResponseBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollDeviceResponseBackend")
            .field("device_credential", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_wire_shape_and_redacted_debug() {
        let req = EnrollDeviceRequestBackend {
            device_id: "dev-1".into(),
            connected_user: "alice".into(),
            connected_domain: "acme.com".into(),
            enrollment_token: "edm_enr_secret".into(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["connected_user"], "alice");
        assert_eq!(json["enrollment_token"], "edm_enr_secret");
        assert!(!format!("{req:?}").contains("edm_enr_secret"));

        let resp: EnrollDeviceResponseBackend =
            serde_json::from_str(r#"{"device_credential":"edm_dev_x"}"#).unwrap();
        assert!(!format!("{resp:?}").contains("edm_dev_x"));
    }
}
