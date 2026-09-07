//! Issuance and hostile-wire verification with public RFC test key material.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use gnap_crypto::{Ps256Signer, Signer};
use gnap_registry::AssertionFormat;
use gnap_subject::{issue, verify, AssertionError, Expectations, Issuance, MAX_ASSERTION_BYTES};
use gnap_types::user::Assertion;
use serde_json::{json, Value};

const PUBLIC_TEST_KEY: &str = include_str!("fixtures/rfc9421-b12.pkcs1.pem");

fn signer() -> Ps256Signer {
    Ps256Signer::from_pkcs1_pem(PUBLIC_TEST_KEY, "assertion-key").unwrap()
}

const fn expected() -> Expectations<'static> {
    Expectations {
        issuer: "https://issuer.example",
        audience: "client-a",
        nonce: "session-a",
        now: 1000,
        max_age: 300,
        clock_skew: 0,
    }
}

const fn input() -> Issuance<'static> {
    Issuance {
        issuer: "https://issuer.example",
        subject: "pairwise-subject",
        audience: "client-a",
        nonce: "session-a",
        authenticated_at: 990,
        issued_at: 1000,
        expires_at: 1300,
    }
}

fn header() -> Value {
    json!({"alg":"PS256", "typ":"JWT", "kid":"assertion-key"})
}
fn payload() -> Value {
    json!({"iss":"https://issuer.example", "sub":"pairwise-subject", "aud":"client-a",
        "nonce":"session-a", "auth_time":990, "iat":1000, "exp":1300})
}

// Construct wire data independently of the issuer's claim serializer. The key
// primitive is shared; this is not independent-vendor cryptographic evidence.
fn wire(header: &str, payload: &str) -> Assertion {
    let signed = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let signature = signer().sign(signed.as_bytes()).unwrap();
    Assertion {
        format: AssertionFormat::IdToken,
        value: format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature)),
    }
}

fn token(header: &Value, payload: &Value) -> Assertion {
    wire(&header.to_string(), &payload.to_string())
}

#[test]
fn issuance_verification_and_redacted_identity_agree() {
    let signer = signer();
    let assertion = issue(&signer, &input()).unwrap();
    let identity = verify(&assertion, &signer.verifier(), &expected()).unwrap();
    assert_eq!(identity.issuer(), "https://issuer.example");
    assert_eq!(identity.subject(), "pairwise-subject");
    assert_eq!(identity.authenticated_at(), 990);
    assert_eq!(identity.issued_at(), 1000);
    assert_eq!(identity.expires_at(), 1300);
    assert!(!format!("{identity:?}").contains("pairwise-subject"));
    assert!(!format!("{identity:?}").contains("session-a"));
}

#[test]
fn pem_keys_require_an_explicit_identifier_when_the_token_has_one() {
    let pem = include_str!("fixtures/rfc9421-b12.spki.pem");
    let key = gnap_crypto::Ps256Verifier::from_public_key_pem(pem).unwrap();
    let assertion = issue(&signer(), &input()).unwrap();
    assert_eq!(
        verify(&assertion, &key, &expected()),
        Err(AssertionError::Header)
    );
    let key = key.with_key_id("assertion-key");
    assert!(verify(&assertion, &key, &expected()).is_ok());
    let other = Ps256Signer::generate(2048, "assertion-key").unwrap();
    assert_eq!(
        verify(&assertion, &other.verifier(), &expected()),
        Err(AssertionError::Signature)
    );
}

#[test]
fn exact_subject_and_authentication_boundaries_are_accepted() {
    let subject = "s".repeat(255);
    let input = Issuance {
        subject: &subject,
        authenticated_at: 1000,
        ..input()
    };
    let key = signer();
    assert!(verify(&issue(&key, &input).unwrap(), &key.verifier(), &expected()).is_ok());
    assert_eq!(key.thumbprint(), key.verifier().thumbprint());
    let renamed = gnap_crypto::Ps256Verifier::from_public_jwk(&key.public_jwk().unwrap())
        .unwrap()
        .with_key_id("another-routing-name");
    assert_eq!(key.thumbprint(), renamed.thumbprint());
}

#[test]
fn trust_rejects_attribution_conflicts_and_ambiguous_responses() {
    use gnap_subject::Trust;
    use gnap_types::user::SubjectResponse;
    let key = signer().verifier();
    let trust = Trust {
        as_endpoint: "https://as.example/gnap",
        issuer: expected().issuer,
        key: &key,
        max_age: 300,
        clock_skew: 0,
    };
    let assertion = issue(&signer(), &input()).unwrap();
    let response = json!({"assertions":[assertion], "sub_ids":[
        {"format":"iss_sub", "iss":input().issuer, "sub":input().subject},
        {"format":"opaque", "id":"not-interpreted-as-a-verified-claim"}
    ]});
    let check = |value: Value, endpoint| {
        trust.verify_subject(
            &serde_json::from_value::<SubjectResponse>(value).unwrap(),
            endpoint,
            expected().audience,
            expected().nonce,
            expected().now,
        )
    };
    assert!(check(response.clone(), trust.as_endpoint).is_ok());
    let mut opaque_only = response.clone();
    opaque_only["sub_ids"] = json!([{"format":"opaque", "id":"opaque-only"}]);
    assert_eq!(
        check(opaque_only, trust.as_endpoint).unwrap().subject(),
        input().subject
    );
    assert_eq!(
        check(response.clone(), "https://other.example/gnap"),
        Err(AssertionError::Context)
    );
    for ids in [
        json!([{"format":"iss_sub","iss":input().issuer,"sub":"someone-else"}]),
        json!([{"format":"iss_sub","iss":"https://other.example","sub":input().subject}]),
        json!([{"format":"iss_sub","iss":input().issuer}]),
    ] {
        let mut changed = response.clone();
        changed["sub_ids"] = ids;
        assert_eq!(
            check(changed, trust.as_endpoint),
            Err(AssertionError::Context)
        );
    }
    for assertions in [json!([]), json!([assertion, assertion]), Value::Null] {
        let mut changed = response.clone();
        changed["assertions"] = assertions;
        assert_eq!(
            check(changed, trust.as_endpoint),
            Err(AssertionError::Context)
        );
    }
}

#[test]
fn optional_headers_and_unknown_claims_do_not_become_trusted_key_input() {
    let key = signer().verifier();
    let mut claims = payload();
    claims["aud"] = json!(["client-a"]);
    claims["azp"] = json!("client-a");
    claims["unrecognized"] = json!({"nested": ["ignored"]});
    for header in [json!({"alg":"PS256"}), json!({"alg":"PS256", "typ":"jwt"})] {
        assert!(verify(&token(&header, &claims), &key, &expected()).is_ok());
    }
}

#[test]
fn malformed_algorithm_members_are_header_errors_not_claim_errors() {
    let key = signer().verifier();
    for value in [Value::Null, json!(false), json!(256), json!([]), json!({})] {
        let mut header = header();
        header["alg"] = value;
        assert_eq!(
            verify(&token(&header, &payload()), &key, &expected()),
            Err(AssertionError::Header)
        );
    }
    let mut header = header();
    header.as_object_mut().unwrap().remove("alg");
    assert_eq!(
        verify(&token(&header, &payload()), &key, &expected()),
        Err(AssertionError::Header)
    );
}

#[test]
fn issuer_audience_nonce_and_authorized_party_are_bound_independently() {
    let key = signer().verifier();
    for (field, value) in [
        ("iss", json!("https://other.example")),
        ("iss", json!("https://issuer.example/")),
        ("aud", json!("client-b")),
        ("aud", json!(["client-a", "client-b"])),
        ("aud", json!([])),
        ("aud", json!(["client-a", null])),
        ("nonce", json!("session-b")),
        ("nonce", Value::Null),
        ("azp", json!("client-b")),
        ("azp", Value::Null),
    ] {
        let mut claims = payload();
        claims[field] = value;
        assert!(
            verify(&token(&header(), &claims), &key, &expected()).is_err(),
            "{field}"
        );
    }
}

#[test]
fn required_claims_types_and_subject_bounds_are_checked() {
    let key = signer().verifier();
    for field in ["iss", "sub", "aud", "nonce", "auth_time", "iat", "exp"] {
        let mut claims = payload();
        claims.as_object_mut().unwrap().remove(field);
        assert!(
            verify(&token(&header(), &claims), &key, &expected()).is_err(),
            "{field}"
        );
        claims[field] = json!({"wrong":"type"});
        assert!(
            verify(&token(&header(), &claims), &key, &expected()).is_err(),
            "{field}"
        );
    }
    for subject in [String::new(), "a".repeat(256), "non-ascii-é".into()] {
        let mut claims = payload();
        claims["sub"] = json!(subject);
        assert!(verify(&token(&header(), &claims), &key, &expected()).is_err());
    }
    for value in [json!(-1), json!(1000.5), json!(true)] {
        let mut claims = payload();
        claims["iat"] = value;
        assert!(verify(&token(&header(), &claims), &key, &expected()).is_err());
    }
}

#[test]
fn time_edges_and_skew_are_checked_without_integer_overflow() {
    let key = signer().verifier();
    let assertion = token(&header(), &payload());
    let mut policy = expected();
    policy.now = 1299;
    assert!(verify(&assertion, &key, &policy).is_ok());
    policy.now = 1300;
    assert_eq!(
        verify(&assertion, &key, &policy).unwrap_err(),
        AssertionError::Time
    );
    policy.clock_skew = 10;
    policy.now = 1309;
    assert!(verify(&assertion, &key, &policy).is_ok());
    policy.now = 1310;
    assert!(verify(&assertion, &key, &policy).is_err());
    policy.now = 990;
    assert!(verify(&assertion, &key, &policy).is_ok());
    policy.now = 989;
    assert!(verify(&assertion, &key, &policy).is_err());
    for (field, value) in [
        ("exp", 1301),
        ("exp", 1000),
        ("auth_time", 1001),
        ("iat", u64::MAX),
        ("exp", u64::MAX),
        ("nbf", u64::MAX),
    ] {
        let mut claims = payload();
        claims[field] = json!(value);
        assert!(
            verify(&token(&header(), &claims), &key, &expected()).is_err(),
            "{field}"
        );
    }
    policy = expected();
    policy.now = u64::MAX;
    policy.clock_skew = 300;
    assert!(verify(&assertion, &key, &policy).is_err());
}

#[test]
fn algorithms_key_hints_and_critical_extensions_cannot_change_trust() {
    let key = signer().verifier();
    for (field, value) in [
        ("alg", json!("none")),
        ("alg", json!("HS256")),
        ("alg", json!("RS256")),
        ("alg", Value::Null),
        ("typ", json!("at+jwt")),
        ("typ", Value::Null),
        ("kid", json!("another-key")),
        ("kid", Value::Null),
        ("jku", json!("https://untrusted.invalid/keys")),
        ("jwk", json!({})),
        ("x5u", json!("https://untrusted.invalid/cert")),
        ("x5c", json!([])),
        ("crit", json!([])),
        ("crit", Value::Null),
        ("b64", json!(false)),
    ] {
        let mut fields = header();
        fields[field] = value;
        assert!(
            verify(&token(&fields, &payload()), &key, &expected()).is_err(),
            "{field}"
        );
    }
}

#[test]
fn wire_bounds_duplicate_members_and_exact_signature_bytes_are_checked() {
    let key = signer().verifier();
    let assertion = token(&header(), &payload());
    for value in [
        String::new(),
        "a.b".into(),
        "a.b.c.d".into(),
        "..".into(),
        format!("{}=", assertion.value),
        "a".repeat(MAX_ASSERTION_BYTES + 1),
    ] {
        assert!(verify(
            &Assertion {
                format: AssertionFormat::IdToken,
                value
            },
            &key,
            &expected()
        )
        .is_err());
    }
    for (head, body) in [
        (
            "{\"alg\":\"PS256\",\"alg\":\"PS256\"}".into(),
            payload().to_string(),
        ),
        (
            header().to_string(),
            payload()
                .to_string()
                .replacen('{', "{\"sub\":\"different\",", 1),
        ),
        ("[]".into(), payload().to_string()),
        (header().to_string(), "null".into()),
    ] {
        assert!(verify(&wire(&head, &body), &key, &expected()).is_err());
    }
    let (signed, signature) = assertion.value.rsplit_once('.').unwrap();
    let mut bytes = URL_SAFE_NO_PAD.decode(signature).unwrap();
    bytes[0] ^= 1;
    let tampered = Assertion {
        format: AssertionFormat::IdToken,
        value: format!("{signed}.{}", URL_SAFE_NO_PAD.encode(bytes)),
    };
    assert_eq!(
        verify(&tampered, &key, &expected()).unwrap_err(),
        AssertionError::Signature
    );
    let changed_payload = URL_SAFE_NO_PAD.encode(
        payload()
            .to_string()
            .replace("pairwise-subject", "another-subject"),
    );
    let changed = Assertion {
        format: AssertionFormat::IdToken,
        value: format!(
            "{}.{}.{}",
            signed.split('.').next().unwrap(),
            changed_payload,
            signature
        ),
    };
    assert_eq!(
        verify(&changed, &key, &expected()).unwrap_err(),
        AssertionError::Signature
    );
}

#[test]
fn unsafe_configuration_and_weak_keys_are_refused_without_echoing_input() {
    let signer = signer();
    let key = signer.verifier();
    let assertion = issue(&signer, &input()).unwrap();
    for issuer in [
        "http://issuer.example",
        "https:///path",
        "https://issuer.example?query",
        "https://user@issuer.example",
        "https://issuer.example#fragment",
    ] {
        let mut config = expected();
        config.issuer = issuer;
        assert_eq!(
            verify(&assertion, &key, &config).unwrap_err(),
            AssertionError::Configuration
        );
    }
    let mut config = expected();
    config.clock_skew = 301;
    assert!(verify(&assertion, &key, &config).is_err());
    config = expected();
    config.max_age = 0;
    assert!(verify(&assertion, &key, &config).is_err());
    let weak = Ps256Signer::generate(1024, "assertion-key").unwrap();
    assert_eq!(weak.modulus_bits(), 1024);
    assert_eq!(
        issue(&weak, &input()).unwrap_err(),
        AssertionError::Configuration
    );
    assert_eq!(
        verify(&assertion, &weak.verifier(), &expected()).unwrap_err(),
        AssertionError::Configuration
    );
    let mut invalid = input();
    invalid.subject = "";
    assert!(issue(&signer, &invalid).is_err());
    for error in [
        AssertionError::Format,
        AssertionError::Header,
        AssertionError::Signature,
        AssertionError::Claims,
        AssertionError::Recipient,
        AssertionError::Nonce,
        AssertionError::Time,
    ] {
        assert!(!error.to_string().contains("session-a"));
        assert!(!error.to_string().contains("pairwise-subject"));
    }
}
