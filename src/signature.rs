use anyhow::{anyhow, Result};
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::env;

type HmacSha256 = Hmac<Sha256>;

// Minimum version supported for the 0 major version
const EDAMAME_MINIMUM_MINOR: u64 = 3;
const EDAMAME_MINIMUM_PATCH: u64 = 3;

fn verify_version(version: &str) -> bool {
    let parse_parts = |v: &str| -> Option<(u64, u64, u64)> {
        let parts: Vec<&str> = v.split('.').collect();
        if parts.len() == 3 {
            if let (Ok(major), Ok(minor), Ok(patch)) = (
                parts[0].parse::<u64>(),
                parts[1].parse::<u64>(),
                parts[2].parse::<u64>(),
            ) {
                return Some((major, minor, patch));
            }
        }
        None
    };

    let (version_major, version_minor, version_patch) = match parse_parts(version) {
        Some(v) => v,
        None => return false,
    };
    let (backend_major, backend_minor, backend_patch) = match parse_parts(env!("CARGO_PKG_VERSION"))
    {
        Some(v) => v,
        None => return false,
    };

    // Same major
    version_major == backend_major
        // Compatible minor 
        && version_minor >= EDAMAME_MINIMUM_MINOR
        && version_minor <= backend_minor
        // Compatible patch
        && version_patch >= EDAMAME_MINIMUM_PATCH
        && version_patch <= backend_patch
}

pub fn verify_header(secret: &str, headers: HashMap<String, String>) -> Result<()> {
    // Get the version
    let version = match headers.get("x-edamame-version") {
        Some(version) => version,
        None => {
            let error = "missing x-edamame-version".to_string();
            return Err(anyhow!(error));
        }
    };

    // Get the timestamp
    let timestamp = match headers.get("x-edamame-timestamp") {
        Some(timestamp) => timestamp,
        None => {
            let error = "missing x-edamame-timestamp".to_string();
            return Err(anyhow!(error));
        }
    };

    // Get the request id
    let request_id = match headers.get("x-edamame-request-id") {
        Some(request_id) => request_id,
        None => {
            let error = "missing x-edamame-request-id".to_string();
            return Err(anyhow!(error));
        }
    };

    // Get the signature
    let received_signature = match headers.get("x-edamame-signature") {
        Some(received_signature) => received_signature,
        None => {
            let error = "missing x-edamame-signature".to_string();
            return Err(anyhow!(error));
        }
    };

    // Check compatibility of the version
    if !verify_version(version) {
        let error = format!(
            "bad version: received version {} is not compatible with backend version {}",
            version,
            env!("CARGO_PKG_VERSION")
        );
        return Err(anyhow!(error));
    };

    // Verify the signature
    if received_signature.is_empty() {
        let error = "missing signature".to_string();
        return Err(anyhow!(error));
    }
    verify_signature(
        secret,
        timestamp.parse().unwrap_or(0),
        request_id,
        received_signature,
    )
}

pub fn generate_signature(secret: &str, request_id: &str) -> (String, String) {
    // Get the current timestamp as seconds since the UNIX epoch
    let timestamp = Utc::now().timestamp() as u64;

    // Prepare data to sign: concatenate timestamp and request_id
    let data = format!("{timestamp}{request_id}");

    // Create HMAC-SHA256 instance with the secret key
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(data.as_bytes());

    // Finalize the HMAC and get the resulting code
    let result = mac.finalize();
    let code_bytes = result.into_bytes();

    // Convert the HMAC result to a hex string
    let signature_hex = hex::encode(code_bytes);

    (timestamp.to_string(), signature_hex)
}

pub fn verify_signature(
    secret: &str,
    timestamp: u64,
    request_id: &str,
    received_signature: &str,
) -> Result<()> {
    verify_signature_cmd(secret, timestamp, request_id, received_signature, false)
}

pub fn verify_signature_no_timestamp_check(
    secret: &str,
    timestamp: u64,
    request_id: &str,
    received_signature: &str,
) -> Result<()> {
    verify_signature_cmd(secret, timestamp, request_id, received_signature, true)
}

fn verify_signature_cmd(
    secret: &str,
    timestamp: u64,
    request_id: &str,
    received_signature: &str,
    no_timestamp_check: bool,
) -> Result<()> {
    // Ensure the timestamp is within an acceptable range (e.g., +/- 5 minutes)
    if !no_timestamp_check {
        let current_time = Utc::now().timestamp() as u64;
        if (current_time as i64 - timestamp as i64).abs() > 300 {
            let error = format!("bad timestamp: {timestamp} != {current_time}");
            return Err(anyhow!(error));
        }
    }

    // Recreate the data to sign
    let data_to_sign = format!("{timestamp}{request_id}");

    // Create HMAC instance with the secret
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(data_to_sign.as_bytes());

    // Perform HMAC verification
    match hex::decode(received_signature) {
        Ok(decoded_signature) => {
            let ok = mac.verify_slice(&decoded_signature).is_ok();
            if !ok {
                let error = format!("slice verification failed for {received_signature:?}");
                return Err(anyhow!(error));
            };
            Ok(())
        }
        Err(_) => {
            let error = format!("failed to decode signature: {received_signature:?}");
            Err(anyhow!(error))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_verification() {
        let secret = "test_secret";
        let request_id = "test_request";

        let (gen_timestamp, gen_signature) = generate_signature(secret, request_id);
        assert!(verify_signature(
            secret,
            gen_timestamp.parse().unwrap_or(0),
            request_id,
            &gen_signature
        )
        .is_ok());
    }

    // With a bad timestamp
    #[test]
    fn test_signature_verification_bad_timestamp() {
        let secret = "test_secret";
        let request_id = "test_request";
        let (gen_timestamp, gen_signature) = generate_signature(secret, request_id);
        assert!(verify_signature(
            secret,
            gen_timestamp.parse().unwrap_or(0) + 301,
            request_id,
            &gen_signature
        )
        .is_err());
    }

    // With a bad signature
    #[test]
    fn test_signature_verification_bad_signature() {
        let secret = "test_secret";
        let request_id = "test_request";
        let (gen_timestamp, _gen_signature) = generate_signature(secret, request_id);
        assert!(verify_signature(
            secret,
            gen_timestamp.parse().unwrap_or(0),
            request_id,
            "bad_signature"
        )
        .is_err());
    }

    // With a bad request id
    #[test]
    fn test_signature_verification_bad_request_id() {
        let secret = "test_secret";
        let request_id = "test_request";
        let (gen_timestamp, gen_signature) = generate_signature(secret, request_id);
        assert!(verify_signature(
            secret,
            gen_timestamp.parse().unwrap_or(0),
            "bad_request_id",
            &gen_signature
        )
        .is_err());
    }

    // With a bad version
    #[test]
    fn test_signature_verification_bad_version() {
        let secret = "test_secret";
        let request_id = "test_request";
        let (gen_timestamp, _gen_signature) = generate_signature(secret, request_id);
        assert!(verify_signature(
            secret,
            gen_timestamp.parse().unwrap_or(0),
            request_id,
            "bad_version"
        )
        .is_err());
    }

    #[test]
    fn test_version_verification() {
        let version = "0.3.3";
        assert!(verify_version(version));

        let version = "0.3.4";
        assert!(verify_version(version));

        let version = "0.3.5";
        assert!(!verify_version(version));

        let version = "0.3.10";
        assert!(!verify_version(version));

        let version = "0.3.2";
        assert!(!verify_version(version));

        let version = "0.2.3";
        assert!(!verify_version(version));

        let version = "0.10.3";
        assert!(!verify_version(version));

        let version = "10.10.3";
        assert!(!verify_version(version));
    }

    #[test]
    fn test_header_verification() {
        let secret = "test_secret";
        let request_id = "test_request";
        let (timestamp, signature) = generate_signature(secret, request_id);
        let mut headers = HashMap::new();
        headers.insert("x-edamame-version".to_string(), "0.3.3".to_string());
        headers.insert("x-edamame-timestamp".to_string(), timestamp);
        headers.insert("x-edamame-request-id".to_string(), request_id.to_string());
        headers.insert("x-edamame-signature".to_string(), signature);
        assert!(verify_header(secret, headers).is_ok());
    }

    #[test]
    fn test_header_verification_bad_version() {
        let secret = "test_secret";
        let request_id = "test_request";
        let (timestamp, signature) = generate_signature(secret, request_id);
        let mut headers = HashMap::new();
        headers.insert("x-edamame-version".to_string(), "0.3.2".to_string());
        headers.insert("x-edamame-timestamp".to_string(), timestamp);
        headers.insert("x-edamame-request-id".to_string(), request_id.to_string());
        headers.insert("x-edamame-signature".to_string(), signature);
        assert!(verify_header(secret, headers).is_err());
    }
}
