/// HTTP Message Signatures helpers — RFC 9421, used by RFC 9635 Section 7.3.1
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::types::ComplianceError;

/// Components covered by GNAP HTTP signatures.
pub const GNAP_SIGNATURE_COMPONENTS: &[&str] = &[
    "@method",
    "@target-uri",
    "content-type",
    "content-digest",
    "content-length",
    "authorization",
];

/// Build the signature base string per RFC 9421 Section 2.5.
///
/// Each component is formatted as `"component": value`, followed by the
/// signature parameters line.
pub fn build_signature_base(components: &[(&str, &str)], sig_params: &str) -> String {
    let mut parts: Vec<String> = components
        .iter()
        .map(|(name, value)| format!("\"{name}\": {value}"))
        .collect();
    parts.push(format!("\"@signature-params\": {sig_params}"));
    parts.join("\n")
}

/// Build the signature parameters string per RFC 9421 Section 2.3.
///
/// Format: `(component1 component2 ...);created=TIMESTAMP;keyid="KEY_ID";tag="gnap"`
/// RFC 9635 Section 7.3.1: tag="gnap" is REQUIRED.
pub fn build_signature_params(component_names: &[&str], created: i64, key_id: &str) -> String {
    let names = component_names
        .iter()
        .map(|n| format!("\"{n}\""))
        .collect::<Vec<_>>()
        .join(" ");
    format!("({names});created={created};keyid=\"{key_id}\";tag=\"gnap\"")
}

/// Sign a signature base string with an Ed25519 key.
///
/// Returns the base64-encoded signature.
pub fn sign_ed25519(signing_key: &SigningKey, signature_base: &str) -> String {
    let signature = signing_key.sign(signature_base.as_bytes());
    STANDARD.encode(signature.to_bytes())
}

/// Verify an Ed25519 signature against a signature base string.
pub fn verify_ed25519(
    verifying_key: &VerifyingKey,
    signature_base: &str,
    signature_b64: &str,
) -> Result<(), ComplianceError> {
    let sig_bytes = STANDARD
        .decode(signature_b64)
        .map_err(|e| ComplianceError::Crypto(format!("Base64 decode failed: {e}")))?;

    let sig_bytes: [u8; 64] = sig_bytes.try_into().map_err(|_| {
        ComplianceError::Crypto("Invalid signature length (expected 64 bytes)".to_string())
    })?;

    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify(signature_base.as_bytes(), &signature)
        .map_err(|_| ComplianceError::Crypto("Signature verification failed".to_string()))
}

/// Full sign-and-produce-headers workflow for GNAP HTTP requests.
///
/// Returns `(signature_value, signature_input_value)` ready for HTTP headers.
pub fn create_gnap_signature_headers(
    signing_key: &SigningKey,
    key_id: &str,
    components: &[(&str, &str)],
    created: i64,
) -> (String, String) {
    let component_names: Vec<&str> = components.iter().map(|(name, _)| *name).collect();
    let sig_params = build_signature_params(&component_names, created, key_id);
    let sig_base = build_signature_base(components, &sig_params);
    let signature = sign_ed25519(signing_key, &sig_base);
    let sig_input = format!("sig1={sig_params}");
    (format!("sig1=:{signature}:"), sig_input)
}

/// Parse a `Signature-Input` header value to extract components, created, and keyid.
///
/// Expects format: `sig1=("c1" "c2");created=TIMESTAMP;keyid="KEY_ID";tag="gnap"`
/// RFC 9635 Section 7.3.1: verifier MUST verify tag="gnap" is present.
pub fn parse_signature_input(input: &str) -> Result<(Vec<String>, i64, String), ComplianceError> {
    let input = input.strip_prefix("sig1=").unwrap_or(input);

    let mut components = Vec::new();
    let mut created: Option<i64> = None;
    let mut keyid: Option<String> = None;
    let mut tag: Option<String> = None;

    for part in input.split(';') {
        let part = part.trim();
        if part.starts_with('(') {
            let inner = part
                .strip_prefix('(')
                .and_then(|p| p.strip_suffix(')'))
                .ok_or_else(|| {
                    ComplianceError::Validation("Malformed component list".to_string())
                })?;
            components = inner
                .split_whitespace()
                .map(|s| s.trim_matches('"').to_string())
                .collect();
        } else if let Some(val) = part.strip_prefix("created=") {
            created = Some(val.parse().map_err(|_| {
                ComplianceError::Validation("Invalid created timestamp".to_string())
            })?);
        } else if let Some(val) = part.strip_prefix("keyid=") {
            keyid = Some(val.trim_matches('"').to_string());
        } else if let Some(val) = part.strip_prefix("tag=") {
            tag = Some(val.trim_matches('"').to_string());
        } else if part.starts_with("alg=") {
            return Err(ComplianceError::Validation(
                "alg parameter MUST NOT be included in GNAP signatures (Section 7.3.1)".to_string(),
            ));
        }
    }

    let created = created.ok_or_else(|| {
        ComplianceError::Validation("Missing created in Signature-Input".to_string())
    })?;
    let keyid = keyid.ok_or_else(|| {
        ComplianceError::Validation("Missing keyid in Signature-Input".to_string())
    })?;

    match tag.as_deref() {
        Some("gnap") => {}
        Some(other) => {
            return Err(ComplianceError::Validation(format!(
                "tag must be \"gnap\", got \"{other}\" (Section 7.3.1)"
            )));
        }
        None => {
            return Err(ComplianceError::Validation(
                "Missing tag=\"gnap\" in Signature-Input (Section 7.3.1)".to_string(),
            ));
        }
    }

    Ok((components, created, keyid))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_test_key() -> SigningKey {
        SigningKey::generate(&mut rand::rngs::OsRng)
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = generate_test_key();
        let components = [
            ("@method", "POST"),
            ("@target-uri", "https://as.example.com/gnap"),
            ("content-type", "application/json"),
        ];
        let created = 1234567890;

        let (sig_header, sig_input) =
            create_gnap_signature_headers(&key, "test-key", &components, created);

        // Parse back
        let (parsed_components, parsed_created, parsed_keyid) =
            parse_signature_input(&sig_input).unwrap();
        assert_eq!(
            parsed_components,
            vec!["@method", "@target-uri", "content-type"]
        );
        assert_eq!(parsed_created, created);
        assert_eq!(parsed_keyid, "test-key");

        // Verify signature
        let sig_params = build_signature_params(
            &parsed_components
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            parsed_created,
            &parsed_keyid,
        );
        let component_pairs: Vec<(&str, &str)> = parsed_components
            .iter()
            .zip(["POST", "https://as.example.com/gnap", "application/json"])
            .map(|(name, val)| (name.as_str(), val))
            .collect();
        let sig_base = build_signature_base(&component_pairs, &sig_params);

        // Extract signature value from "sig1=:BASE64:" format
        let sig_value = sig_header
            .strip_prefix("sig1=:")
            .and_then(|s| s.strip_suffix(':'))
            .unwrap();

        verify_ed25519(&key.verifying_key(), &sig_base, sig_value).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_base() {
        let key = generate_test_key();
        let sig_base = "\"@method\": POST\n\"@target-uri\": https://as.example.com/gnap";
        let signature = sign_ed25519(&key, sig_base);

        let tampered = "\"@method\": GET\n\"@target-uri\": https://as.example.com/gnap";
        let result = verify_ed25519(&key.verifying_key(), tampered, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let key1 = generate_test_key();
        let key2 = generate_test_key();
        let sig_base = "\"@method\": POST";
        let signature = sign_ed25519(&key1, sig_base);

        let result = verify_ed25519(&key2.verifying_key(), sig_base, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn parse_signature_input_valid() {
        let input = "sig1=(\"@method\" \"@target-uri\" \"content-type\");created=1618884473;keyid=\"gnap-key\";tag=\"gnap\"";
        let (components, created, keyid) = parse_signature_input(input).unwrap();
        assert_eq!(components, vec!["@method", "@target-uri", "content-type"]);
        assert_eq!(created, 1618884473);
        assert_eq!(keyid, "gnap-key");
    }

    #[test]
    fn parse_signature_input_missing_created() {
        let input = "sig1=(\"@method\");keyid=\"k\";tag=\"gnap\"";
        assert!(parse_signature_input(input).is_err());
    }

    #[test]
    fn parse_signature_input_missing_keyid() {
        let input = "sig1=(\"@method\");created=123;tag=\"gnap\"";
        assert!(parse_signature_input(input).is_err());
    }

    #[test]
    fn parse_signature_input_rejects_missing_tag() {
        let input = "sig1=(\"@method\");created=123;keyid=\"k\"";
        let result = parse_signature_input(input);
        assert!(result.is_err());
    }

    #[test]
    fn parse_signature_input_rejects_wrong_tag() {
        let input = "sig1=(\"@method\");created=123;keyid=\"k\";tag=\"other\"";
        let result = parse_signature_input(input);
        assert!(result.is_err());
    }
}
