use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use lambda_http::Request;
use edamame_foundation::foundation::FOUNDATION_VERSION;

type HmacSha256 = Hmac<Sha256>;

// Verify version and signature of the request and return an error message if the request is invalid
pub fn verify_header(request: Request) -> String {
    // Get the headers
    let headers = request.headers();

    // Get the version
    let version = match headers.get("x-edamame-version") {
        Some(version) => version.to_str().unwrap_or(""),
        None => "",
    };

    // Get the timestamp
    let timestamp = match headers.get("x-edamame-timestamp") {
        Some(timestamp) => timestamp.to_str().unwrap_or(""),
        None => "",
    };

    // Get the request id
    let request_id = match headers.get("x-edamame-request-id") {
        Some(request_id) => request_id.to_str().unwrap_or(""),
        None => "",
    };

    // Get the signature
    let received_signature = match headers.get("x-edamame-signature") {
        Some(received_signature) => received_signature.to_str().unwrap_or(""),
        None => "",
    };

    // Verify the version
    if version != FOUNDATION_VERSION {
        println!("bad version: {} != {}", version, FOUNDATION_VERSION);
        return "bad version".to_string();
    }

    // Verify the signature
    if !verify_signature(timestamp.parse().unwrap_or(0), request_id, received_signature) {
        println!("bad signature");
        return "bad signature".to_string();
    }

    // Return an empty string if the request is valid
    "".to_string()
}

fn verify_signature(timestamp: u64, request_id: &str, received_signature: &str) -> bool {

    let secret = env!("LAMBDA_SIGNATURE");

    // Ensure the timestamp is within an acceptable range (e.g., 5 minutes)
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    if current_time > timestamp + 300 || current_time < timestamp {
        return false;
    }

    // Recreate the data to sign
    let data_to_sign = format!("{}{}", timestamp, request_id);

    // Create HMAC instance with the secret
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(data_to_sign.as_bytes());

    // Perform HMAC verification
    match hex::decode(received_signature) {
        Ok(decoded_signature) => mac.verify_slice(&decoded_signature).is_ok(),
        Err(_) => false,
    }
}
