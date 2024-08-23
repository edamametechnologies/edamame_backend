use anyhow::{anyhow, Result};
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;

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

    // Verify the version
    if version != env!("CARGO_PKG_VERSION") {
        let error = format!(
            "bad version: received version {} != lambda version {}",
            version,
            env!("CARGO_PKG_VERSION")
        );
        return Err(anyhow!(error));
    }

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
    let data = format!("{}{}", timestamp, request_id);

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
            let error = format!("bad timestamp: {} != {}", timestamp, current_time);
            return Err(anyhow!(error));
        }
    }

    // Recreate the data to sign
    let data_to_sign = format!("{}{}", timestamp, request_id);

    // Create HMAC instance with the secret
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(data_to_sign.as_bytes());

    // Perform HMAC verification
    match hex::decode(received_signature) {
        Ok(decoded_signature) => {
            let ok = mac.verify_slice(&decoded_signature).is_ok();
            if !ok {
                let error = format!("slice verification failed for {:?}", received_signature);
                return Err(anyhow!(error));
            };
            Ok(())
        }
        Err(_) => {
            let error = format!("failed to decode signature: {:?}", received_signature);
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
}
