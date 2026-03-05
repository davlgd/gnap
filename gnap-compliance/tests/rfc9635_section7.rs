use ed25519_dalek::SigningKey;
/// Compliance tests for RFC 9635 Section 7 — Presenting Access Tokens & Key Proofing
use gnap_compliance::crypto::{
    Ed25519Jwk, build_signature_base, build_signature_params, compute_content_digest_sha256,
    compute_content_digest_sha512, create_gnap_signature_headers, parse_signature_input,
    sign_ed25519, verify_ed25519,
};

fn generate_key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

// ─── Section 7.2: Presenting Access Tokens ───────────────────────────────────

#[test]
fn gnap_authorization_header_format() {
    // RFC 9635 Section 7.2: access token presented as "GNAP <token>"
    let token = "OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0";
    let header = format!("GNAP {token}");
    assert!(header.starts_with("GNAP "));
    assert!(!header.contains("Bearer"));
}

// ─── Section 7.3.1: HTTP Message Signatures (httpsig) ────────────────────────

#[test]
fn signature_creation_and_verification() {
    let key = generate_key();
    let components = [
        ("@method", "POST"),
        ("@target-uri", "https://as.example.com/gnap"),
        ("content-type", "application/json"),
    ];

    let (sig_header, sig_input) =
        create_gnap_signature_headers(&key, "my-key-id", &components, 1618884475);

    // Signature header format: sig1=:BASE64:
    assert!(sig_header.starts_with("sig1=:"));
    assert!(sig_header.ends_with(':'));

    // Signature-Input header format: sig1=("c1" "c2" ...);created=...;keyid="...";tag="gnap"
    assert!(sig_input.starts_with("sig1="));
    assert!(sig_input.contains("created=1618884475"));
    assert!(sig_input.contains("keyid=\"my-key-id\""));
    assert!(
        sig_input.contains("tag=\"gnap\""),
        "tag=\"gnap\" is REQUIRED per Section 7.3.1"
    );

    // Parse and verify
    let (parsed_components, created, keyid) = parse_signature_input(&sig_input).unwrap();
    assert_eq!(created, 1618884475);
    assert_eq!(keyid, "my-key-id");

    let sig_params = build_signature_params(
        &parsed_components
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        created,
        &keyid,
    );
    let component_pairs: Vec<(&str, &str)> = parsed_components
        .iter()
        .zip(["POST", "https://as.example.com/gnap", "application/json"])
        .map(|(n, v)| (n.as_str(), v))
        .collect();
    let sig_base = build_signature_base(&component_pairs, &sig_params);

    let sig_value = sig_header
        .strip_prefix("sig1=:")
        .and_then(|s| s.strip_suffix(':'))
        .unwrap();
    verify_ed25519(&key.verifying_key(), &sig_base, sig_value).unwrap();
}

#[test]
fn signature_with_authorization_header() {
    let key = generate_key();
    let components = [
        ("@method", "POST"),
        ("@target-uri", "https://rs.example.com/resource"),
        ("authorization", "GNAP some-token-value"),
        ("content-type", "application/json"),
    ];

    let (sig_header, sig_input) =
        create_gnap_signature_headers(&key, "k1", &components, 1618884475);

    assert!(sig_input.contains("\"authorization\""));
    assert!(!sig_header.is_empty());
}

#[test]
fn signature_components_order_matters() {
    let params1 = build_signature_params(&["@method", "@target-uri"], 100, "k");
    let params2 = build_signature_params(&["@target-uri", "@method"], 100, "k");
    assert_ne!(params1, params2);
}

// ─── Content-Digest (RFC 9530, used by GNAP) ────────────────────────────────

#[test]
fn content_digest_sha512_deterministic() {
    let body = r#"{"access_token":{"access":["read"]},"client":"client-id"}"#;
    let d1 = compute_content_digest_sha512(body.as_bytes());
    let d2 = compute_content_digest_sha512(body.as_bytes());
    assert_eq!(d1, d2);
}

#[test]
fn content_digest_sha256_deterministic() {
    let body = b"test body";
    let d1 = compute_content_digest_sha256(body);
    let d2 = compute_content_digest_sha256(body);
    assert_eq!(d1, d2);
}

#[test]
fn content_digest_changes_with_body() {
    let d1 = compute_content_digest_sha512(b"body1");
    let d2 = compute_content_digest_sha512(b"body2");
    assert_ne!(d1, d2);
}

// ─── Section 7.1: Key Formats (JWK) ─────────────────────────────────────────

#[test]
fn jwk_ed25519_roundtrip() {
    let key = generate_key();
    let jwk = Ed25519Jwk::from_signing_key(&key, Some("test-kid".to_string()));

    assert_eq!(jwk.kty, "OKP");
    assert_eq!(jwk.crv, "Ed25519");
    assert_eq!(jwk.alg, "EdDSA");

    let recovered = jwk.to_verifying_key().unwrap();
    assert_eq!(recovered, key.verifying_key());
}

#[test]
fn jwk_validation_requires_okp_kty() {
    let jwk = Ed25519Jwk {
        kty: "RSA".to_string(),
        crv: "Ed25519".to_string(),
        alg: "EdDSA".to_string(),
        x: "dGVzdA".to_string(),
        kid: Some("k1".to_string()),
        use_: None,
    };
    assert!(jwk.validate().is_err());
}

#[test]
fn jwk_from_json() {
    let json = r#"{
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": "dGVzdC1rZXktdmFsdWUtMTIzNDU2Nzg5MGFi",
        "kid": "example-key",
        "use": "sig"
    }"#;
    let jwk: Ed25519Jwk = serde_json::from_str(json).expect("parse JWK");
    assert_eq!(jwk.kid.as_deref(), Some("example-key"));
    assert_eq!(jwk.use_.as_deref(), Some("sig"));
}

// ─── Ed25519 sign/verify edge cases ─────────────────────────────────────────

#[test]
fn verify_rejects_invalid_base64() {
    let key = generate_key();
    let result = verify_ed25519(&key.verifying_key(), "data", "not-valid-base64!!!");
    assert!(result.is_err());
}

#[test]
fn verify_rejects_wrong_length_signature() {
    let key = generate_key();
    // Valid base64 but wrong length (not 64 bytes)
    let result = verify_ed25519(&key.verifying_key(), "data", "aGVsbG8=");
    assert!(result.is_err());
}

#[test]
fn sign_verify_empty_message() {
    let key = generate_key();
    let sig = sign_ed25519(&key, "");
    verify_ed25519(&key.verifying_key(), "", &sig).unwrap();
}

#[test]
fn sign_verify_unicode_message() {
    let key = generate_key();
    let msg = "\"@method\": POST\n\"content-type\": application/json; charset=utf-8";
    let sig = sign_ed25519(&key, msg);
    verify_ed25519(&key.verifying_key(), msg, &sig).unwrap();
}

#[test]
fn parse_signature_input_rejects_alg_parameter() {
    // RFC 9635 Section 7.3.1: alg MUST NOT be included in GNAP signatures.
    let input =
        "sig1=(\"@method\");created=123;keyid=\"k\";alg=\"ed25519\";tag=\"gnap\"";
    let result = parse_signature_input(input);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("alg parameter MUST NOT"));
}
