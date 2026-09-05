//! Public JWK import/export, including hostile metadata and bounded RSA inputs.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use gnap_crypto::httpsig::{sign, Component, Message, SignatureInput, Tag};
use gnap_crypto::{
    verify_request, Expectations, Ps256Signer, Ps256Verifier, SignedRequest, Signer, Verifier,
};
use serde_json::{json, Map, Value};

// Public test material from RFC 9421 Appendix B.1.2; never a deployment key.
const PRIVATE: &str = include_str!("rfc9421-b12.pkcs1.pem");

fn signer() -> Ps256Signer {
    Ps256Signer::from_pkcs1_pem(PRIVATE, "jwk-client").unwrap()
}

fn jwk() -> Map<String, Value> {
    signer().public_jwk().unwrap()
}

fn rejects(jwk: &Map<String, Value>) {
    assert!(Ps256Verifier::from_public_jwk(jwk).is_err());
}

#[test]
fn exported_jwk_contains_only_public_material_and_verifies_ps256() {
    let signer = signer();
    let jwk = signer.public_jwk().unwrap();
    assert_eq!(jwk.len(), 6);
    assert_eq!(jwk["kty"], "RSA");
    assert_eq!(jwk["alg"], "PS256");
    assert_eq!(jwk["kid"], "jwk-client");
    assert_eq!(jwk["e"], "AQAB");
    assert_eq!(jwk["key_ops"], json!(["verify"]));
    assert!(jwk.contains_key("n"));

    let decoded: Map<String, Value> =
        serde_json::from_slice(&serde_json::to_vec(&jwk).unwrap()).unwrap();
    assert_eq!(decoded, jwk);
    let verifier = Ps256Verifier::from_public_jwk(&decoded).unwrap();
    assert_eq!(verifier.expected_key_id(), Some("jwk-client"));
    assert_eq!(verifier.algorithm(), "PS256");
    let signature = signer.sign(b"the same exact bytes").unwrap();
    verifier
        .verify(b"the same exact bytes", &signature)
        .unwrap();
    assert!(verifier.verify(b"different bytes", &signature).is_err());
    for truncated in [&signature[..0], &signature[..signature.len() - 1]] {
        assert!(verifier.verify(b"the same exact bytes", truncated).is_err());
    }
    let mut tampered = signature;
    tampered[0] ^= 1;
    assert!(verifier.verify(b"the same exact bytes", &tampered).is_err());
}

#[test]
fn imported_kid_is_enforced_by_the_http_request_verifier() {
    let signer = signer();
    let mut public = jwk();
    let message = Message {
        method: "GET",
        target_uri: "https://resource.example/folder",
        content_digest: None,
        authorization: Some("GNAP access-token"),
        other: vec![],
    };
    let input = SignatureInput {
        components: vec![
            Component::Method,
            Component::TargetUri,
            Component::Authorization,
        ],
        created: 1000,
        keyid: "jwk-client".into(),
        nonce: Some("test-nonce".into()),
        tag: Tag::Gnap,
    };
    let (signature_input, signature) = sign(&message, &input, &signer, "proof").unwrap();
    let headers = vec![
        ("Authorization".into(), "GNAP access-token".into()),
        ("Signature-Input".into(), signature_input),
        ("Signature".into(), signature),
    ];
    let request = SignedRequest {
        method: message.method,
        target_uri: message.target_uri,
        headers: &headers,
        body: None,
    };
    let expectations = Expectations {
        now: 1000,
        max_clock_skew: 10,
        key_id: None,
    };
    let unused_nonce = |_: &str, _: u64| true;
    verify_request(
        &request,
        &Ps256Verifier::from_public_jwk(&public).unwrap(),
        &expectations,
        &unused_nonce,
    )
    .unwrap();
    public.insert("kid".into(), json!("another-client"));
    assert!(verify_request(
        &request,
        &Ps256Verifier::from_public_jwk(&public).unwrap(),
        &expectations,
        &unused_nonce
    )
    .is_err());
}

#[test]
fn ps256_rejects_a_pss_signature_with_a_non_sha256_length_salt() {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::signature::{RandomizedSigner, SignatureEncoding};

    let private = rsa::RsaPrivateKey::from_pkcs1_pem(PRIVATE).unwrap();
    let wrong_salt = rsa::pss::BlindedSigningKey::<sha2::Sha256>::new_with_salt_len(private, 20);
    let signature = wrong_salt.sign_with_rng(&mut rsa::rand_core::OsRng, b"salt length matters");
    assert!(Ps256Verifier::from_public_jwk(&jwk())
        .unwrap()
        .verify(b"salt length matters", &signature.to_vec())
        .is_err());
}

#[test]
fn supported_rsa_size_and_exponent_boundaries_are_accepted_structurally() {
    // These are structural boundary probes, not asserted to be secure RSA
    // keys. Public metadata alone cannot establish correct key generation.
    for bits in [2048_usize, 2049, 3072, 4096] {
        for exponent in [3_u64, (1 << 33) - 1] {
            let mut n = vec![0; bits.div_ceil(8)];
            n[0] = 1 << ((bits - 1) % 8);
            *n.last_mut().unwrap() |= 1;
            let bytes = exponent.to_be_bytes();
            let e = &bytes[bytes.iter().position(|b| *b != 0).unwrap()..];
            let mut public = jwk();
            public.insert("n".into(), json!(URL_SAFE_NO_PAD.encode(n)));
            public.insert("e".into(), json!(URL_SAFE_NO_PAD.encode(e)));
            assert!(Ps256Verifier::from_public_jwk(&public).is_ok());
        }
    }
}

#[test]
fn required_metadata_is_not_guessed_or_coerced() {
    let original = jwk();
    for field in ["kty", "alg", "kid", "n", "e"] {
        let mut missing = original.clone();
        missing.remove(field);
        rejects(&missing);
        for value in [
            Value::Null,
            json!(42),
            json!([]),
            json!({}),
            json!(true),
            json!(""),
        ] {
            let mut invalid = original.clone();
            invalid.insert(field.into(), value);
            rejects(&invalid);
        }
    }
    for (field, value) in [
        ("kty", "oct"),
        ("kty", "EC"),
        ("kty", "rsa"),
        ("alg", "RS256"),
        ("alg", "none"),
        ("alg", "ps256"),
    ] {
        let mut invalid = original.clone();
        invalid.insert(field.into(), json!(value));
        rejects(&invalid);
    }
}

#[test]
fn private_and_certificate_parameters_are_never_silently_discarded() {
    for field in [
        "d", "p", "q", "dp", "dq", "qi", "oth", "k", "x5c", "x5u", "x5t", "x5t#S256",
    ] {
        for value in [Value::Null, json!("not-a-secret"), json!([])] {
            let mut invalid = jwk();
            invalid.insert(field.into(), value);
            rejects(&invalid);
        }
    }
}

#[test]
fn usage_constraints_are_honored_without_closing_extension_points() {
    let mut public = jwk();
    public.remove("key_ops");
    public.insert(
        "https://example.net/key-description".into(),
        json!({"future": [1, 2]}),
    );
    assert!(Ps256Verifier::from_public_jwk(&public).is_ok());
    public.insert("use".into(), json!("sig"));
    for operations in [
        json!(["verify"]),
        json!(["sign", "verify"]),
        json!(["verify", "https://example.net/custom-operation"]),
    ] {
        public.insert("key_ops".into(), operations);
        assert!(Ps256Verifier::from_public_jwk(&public).is_ok());
    }
    for operations in [
        json!([]),
        json!(["sign"]),
        json!(["VERIFY"]),
        json!(["verify", "verify"]),
        json!(["verify", 0]),
        json!(["verify", null]),
        json!("verify"),
        Value::Null,
    ] {
        public.insert("key_ops".into(), operations);
        rejects(&public);
    }
    for operation in [
        "encrypt",
        "decrypt",
        "wrapKey",
        "unwrapKey",
        "deriveKey",
        "deriveBits",
    ] {
        public.insert("key_ops".into(), json!(["verify", operation]));
        rejects(&public);
    }
    public.insert("key_ops".into(), json!(["verify"]));
    for usage in [
        json!("enc"),
        json!("SIG"),
        json!("unknown-use"),
        json!(0),
        Value::Null,
    ] {
        public.insert("use".into(), usage);
        rejects(&public);
    }
}

#[test]
fn rsa_integers_must_be_positive_minimal_canonical_and_bounded() {
    let original = jwk();
    for field in ["n", "e"] {
        for value in [
            "", "AA", "AAE", "AQ==", "AQ+", "AQ/", "A Q", "AQ\n", "AR", "☃",
        ] {
            let mut invalid = original.clone();
            invalid.insert(field.into(), json!(value));
            rejects(&invalid);
        }
        let mut invalid = original.clone();
        invalid.insert(field.into(), json!("A".repeat(100_000)));
        rejects(&invalid);
        let bytes = URL_SAFE_NO_PAD
            .decode(original[field].as_str().unwrap())
            .unwrap();
        invalid.insert(
            field.into(),
            json!(URL_SAFE_NO_PAD.encode([&[0][..], &bytes].concat())),
        );
        rejects(&invalid);
    }
    for exponent in [0_u64, 1, 2, 4, (1 << 33) + 1, u64::MAX] {
        let mut invalid = original.clone();
        let bytes = exponent.to_be_bytes();
        let bytes = &bytes[bytes.iter().position(|b| *b != 0).unwrap_or(7)..];
        invalid.insert("e".into(), json!(URL_SAFE_NO_PAD.encode(bytes)));
        rejects(&invalid);
    }
    for bits in [8_usize, 1024, 2047, 4097] {
        let mut bytes = vec![0; bits.div_ceil(8)];
        bytes[0] = 1 << ((bits - 1) % 8);
        *bytes.last_mut().unwrap() |= 1;
        let mut invalid = original.clone();
        invalid.insert("n".into(), json!(URL_SAFE_NO_PAD.encode(bytes)));
        rejects(&invalid);
    }
    let mut even = original;
    let mut n = URL_SAFE_NO_PAD.decode(even["n"].as_str().unwrap()).unwrap();
    *n.last_mut().unwrap() &= !1;
    even.insert("n".into(), json!(URL_SAFE_NO_PAD.encode(n)));
    rejects(&even);
}

#[test]
fn metadata_limits_apply_before_cloning_or_unbounded_work() {
    let mut public = jwk();
    public.insert("kid".into(), json!("k".repeat(1024)));
    assert!(Ps256Verifier::from_public_jwk(&public).is_ok());
    public.insert("kid".into(), json!("k".repeat(1025)));
    rejects(&public);
    assert!(Ps256Signer::from_pkcs1_pem(PRIVATE, "")
        .unwrap()
        .public_jwk()
        .is_err());
    assert!(Ps256Signer::from_pkcs1_pem(PRIVATE, "k".repeat(1025))
        .unwrap()
        .public_jwk()
        .is_err());
    public.insert("kid".into(), json!("bounded"));
    public.insert("key_ops".into(), json!(vec!["verify"; 33]));
    rejects(&public);
    public.insert("key_ops".into(), json!(["verify", "x".repeat(1025)]));
    rejects(&public);
}
