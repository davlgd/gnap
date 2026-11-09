//! Ed25519 and ES256 keys: published vectors, JWK import, and refusals.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use gnap_crypto::{
    Ed25519Signer, Ed25519Verifier, Es256Signer, Es256Verifier, JwkSigner, PublicKey, Signer,
    Verifier,
};
use serde_json::{json, Map, Value};

// Public test material from RFC 9421 Appendices B.1.3 and B.1.4; never a deployment key.
const P256_SEC1: &str = include_str!("rfc9421-b13.sec1.pem");
const P256_SPKI: &str = include_str!("rfc9421-b13.spki.pem");
const ED25519_PKCS8: &str = include_str!("rfc9421-b14.pkcs8.pem");
const ED25519_SPKI: &str = include_str!("rfc9421-b14.spki.pem");

fn object(value: Value) -> Map<String, Value> {
    let Value::Object(map) = value else {
        panic!("a JWK is a JSON object");
    };
    map
}

/// The RFC 9421 Appendix B.1.4 key as a JWK, with the `alg` GNAP requires.
fn ed25519_jwk() -> Map<String, Value> {
    object(json!({
        "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "kid": "test-key-ed25519",
        "x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
    }))
}

/// The RFC 9421 Appendix B.1.3 key as a public JWK, with the `alg` GNAP requires.
fn p256_jwk() -> Map<String, Value> {
    object(json!({
        "kty": "EC", "crv": "P-256", "alg": "ES256", "kid": "test-key-ecc-p256",
        "x": "qIVYZVLCrPZHGHjP17CTW0_-D9Lfw0EkjqF7xB4FivA",
        "y": "Mc4nN9LTDOBhfoUeg8Ye9WedFRhnZXZJA12Qp0zZ6F0"
    }))
}

/// RFC 9421 Appendix B.2.6: Ed25519 is deterministic, so the signature over
/// the published signature base must be the published one.
#[test]
fn ed25519_reproduces_rfc9421_b26() {
    let base = concat!(
        "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n",
        "\"@method\": POST\n",
        "\"@path\": /foo\n",
        "\"@authority\": example.com\n",
        "\"content-type\": application/json\n",
        "\"content-length\": 18\n",
        "\"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" ",
        "\"content-type\" \"content-length\");created=1618884473",
        ";keyid=\"test-key-ed25519\""
    );
    let expected = STANDARD
        .decode(concat!(
            "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1",
            "u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw=="
        ))
        .unwrap();
    let signer = Ed25519Signer::from_pkcs8_pem(ED25519_PKCS8, "test-key-ed25519").unwrap();
    assert_eq!(signer.sign(base.as_bytes()).unwrap(), expected);
    assert_eq!(signer.algorithm(), "EdDSA");

    let jwk = Ed25519Verifier::from_public_jwk(&ed25519_jwk()).unwrap();
    jwk.verify(base.as_bytes(), &expected).unwrap();
    assert_eq!(jwk.expected_key_id(), Some("test-key-ed25519"));
    let pem = Ed25519Verifier::from_public_key_pem(ED25519_SPKI).unwrap();
    pem.verify(base.as_bytes(), &expected).unwrap();
    assert!(pem.verify(b"another base", &expected).is_err());
}

/// RFC 9421 Appendix B.2.4: ECDSA is randomized, so the published signature
/// is verified, and a fresh one verifies under the same key.
#[test]
fn es256_verifies_rfc9421_b24() {
    let base = concat!(
        "\"@status\": 200\n",
        "\"content-type\": application/json\n",
        "\"content-digest\": sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ4",
        "1QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:\n",
        "\"content-length\": 23\n",
        "\"@signature-params\": (\"@status\" \"content-type\" \"content-digest\" ",
        "\"content-length\");created=1618884473;keyid=\"test-key-ecc-p256\""
    );
    let published = STANDARD
        .decode(concat!(
            "wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NK",
            "ocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw=="
        ))
        .unwrap();
    let jwk = Es256Verifier::from_public_jwk(&p256_jwk()).unwrap();
    jwk.verify(base.as_bytes(), &published).unwrap();
    Es256Verifier::from_public_key_pem(P256_SPKI)
        .unwrap()
        .verify(base.as_bytes(), &published)
        .unwrap();

    let signer = Es256Signer::from_sec1_pem(P256_SEC1, "test-key-ecc-p256").unwrap();
    let fresh = signer.sign(base.as_bytes()).unwrap();
    assert_eq!(fresh.len(), 64, "r then s, never DER");
    jwk.verify(base.as_bytes(), &fresh).unwrap();
    assert!(jwk.verify(b"another base", &fresh).is_err());
}

/// RFC 7515 Appendix A.3: the ES256 example JWS verifies.
#[test]
fn es256_verifies_rfc7515_a3() {
    let key = Es256Verifier::from_public_jwk(&object(json!({
        "kty": "EC", "crv": "P-256", "alg": "ES256", "kid": "rfc7515-a3",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    })))
    .unwrap();
    let input = concat!(
        "eyJhbGciOiJFUzI1NiJ9",
        ".",
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt",
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    );
    let signature = URL_SAFE_NO_PAD
        .decode(concat!(
            "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8IS",
            "lSApmWQxfKTUJqPP3-Kg6NU1Q"
        ))
        .unwrap();
    key.verify(input.as_bytes(), &signature).unwrap();
}

/// RFC 8037 Appendices A.3 and A.4: the Ed25519 thumbprint and the JWS
/// signature, checked with the strict verifier.
#[test]
fn ed25519_matches_rfc8037() {
    let key = Ed25519Verifier::from_public_jwk(&object(json!({
        "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "kid": "rfc8037",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    })))
    .unwrap();
    assert_eq!(
        key.thumbprint(),
        "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
    );
    let signature = URL_SAFE_NO_PAD
        .decode(concat!(
            "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5B",
            "hVsPt9g7sVvpAr_MuM0KAg"
        ))
        .unwrap();
    key.verify(
        b"eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc",
        &signature,
    )
    .unwrap();
}

#[test]
fn generated_keys_export_a_jwk_that_imports_and_verifies() {
    let ed25519 = Ed25519Signer::generate("generated-ed25519").unwrap();
    let es256 = Es256Signer::generate("generated-es256").unwrap();
    for (signer, alg) in [
        (&ed25519 as &dyn JwkSigner, "EdDSA"),
        (&es256 as &dyn JwkSigner, "ES256"),
    ] {
        let jwk = signer.public_jwk().unwrap();
        assert_eq!(jwk["alg"], alg);
        assert!(
            !jwk.contains_key("d"),
            "a public JWK holds no private member"
        );
        let key = PublicKey::from_jwk(&jwk).unwrap();
        assert_eq!(key.algorithm(), alg);
        assert_eq!(key.thumbprint(), signer.thumbprint());
        let signature = signer.sign(b"payload").unwrap();
        key.verify(b"payload", &signature).unwrap();
        assert!(key.verify(b"another payload", &signature).is_err());
    }
}

/// The verifier is chosen from `kty`, `crv`, and `alg` together.
#[test]
fn public_key_import_refuses_every_other_combination() {
    let mut rs256 = ed25519_jwk();
    rs256.insert("kty".into(), json!("RSA"));
    rs256.insert("alg".into(), json!("RS256"));
    let mut mixed = p256_jwk();
    mixed.insert("alg".into(), json!("EdDSA"));
    let mut x25519 = ed25519_jwk();
    x25519.insert("crv".into(), json!("X25519"));
    let mut no_alg = p256_jwk();
    no_alg.remove("alg");
    let mut p384 = p256_jwk();
    p384.insert("crv".into(), json!("P-384"));
    for refused in [rs256, mixed, x25519, no_alg, p384] {
        assert!(PublicKey::from_jwk(&refused).is_err(), "{refused:?}");
    }
    assert!(matches!(
        PublicKey::from_jwk(&ed25519_jwk()),
        Ok(PublicKey::Ed25519(_))
    ));
    assert!(matches!(
        PublicKey::from_jwk(&p256_jwk()),
        Ok(PublicKey::Es256(_))
    ));
}

#[test]
fn jwk_import_refuses_private_and_malformed_members() {
    let mut okp_with_d = ed25519_jwk();
    okp_with_d.insert(
        "d".into(),
        json!("n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU"),
    );
    let mut ec_with_d = p256_jwk();
    ec_with_d.insert(
        "d".into(),
        json!("UpuF81l-kOxbjf7T4mNSv0r5tN67Gim7rnf6EFpcYDs"),
    );
    let mut short_x = ed25519_jwk();
    short_x.insert("x".into(), json!(URL_SAFE_NO_PAD.encode([7u8; 31])));
    let mut padded_x = ed25519_jwk();
    padded_x.insert(
        "x".into(),
        json!("JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs="),
    );
    // The identity point is a weak key that strict verification refuses.
    let mut weak = ed25519_jwk();
    let mut identity = [0u8; 32];
    identity[0] = 1;
    weak.insert("x".into(), json!(URL_SAFE_NO_PAD.encode(identity)));
    let mut off_curve = p256_jwk();
    off_curve.insert("y".into(), json!(URL_SAFE_NO_PAD.encode([1u8; 32])));
    let mut no_kid = p256_jwk();
    no_kid.remove("kid");
    let mut encryption = p256_jwk();
    encryption.insert("use".into(), json!("enc"));
    for refused in [&okp_with_d, &short_x, &padded_x, &weak] {
        assert!(
            Ed25519Verifier::from_public_jwk(refused).is_err(),
            "{refused:?}"
        );
    }
    for refused in [&ec_with_d, &off_curve, &no_kid, &encryption] {
        assert!(
            Es256Verifier::from_public_jwk(refused).is_err(),
            "{refused:?}"
        );
    }
}

#[test]
fn signatures_in_another_encoding_or_length_are_refused() {
    let signer = Es256Signer::from_sec1_pem(P256_SEC1, "test-key-ecc-p256").unwrap();
    let verifier = signer.verifier();
    let signature = signer.sign(b"payload").unwrap();
    // A DER signature starts with a SEQUENCE tag and isn't 64 bytes long.
    let mut der = vec![0x30, 0x44, 0x02, 0x20];
    der.extend_from_slice(&signature[..32]);
    der.extend_from_slice(&[0x02, 0x20]);
    der.extend_from_slice(&signature[32..]);
    assert!(verifier.verify(b"payload", &der).is_err());
    assert!(verifier.verify(b"payload", &signature[..63]).is_err());

    let ed25519 = Ed25519Signer::from_pkcs8_pem(ED25519_PKCS8, "test-key-ed25519").unwrap();
    let mut tampered = ed25519.sign(b"payload").unwrap();
    ed25519.verifier().verify(b"payload", &tampered).unwrap();
    tampered[63] ^= 0x80;
    assert!(ed25519.verifier().verify(b"payload", &tampered).is_err());
    assert!(ed25519
        .verifier()
        .verify(b"payload", &tampered[..63])
        .is_err());
}

/// A GNAP request signed with each supported key verifies through the shared
/// request verifier, and only under its own key.
#[test]
fn every_key_type_signs_and_verifies_a_gnap_request() {
    use gnap_crypto::digest::{content_digest, DigestAlgorithm};
    use gnap_crypto::httpsig::{sign, Component, Message, SignatureInput, Tag};
    use gnap_crypto::verify::{verify_request, Expectations, SignedRequest};

    const URL: &str = "https://as.example/gnap";
    const NOW: u64 = 1_700_000_000;
    let ps256 = gnap_crypto::Ps256Signer::from_pkcs1_pem(
        include_str!("rfc9421-b12.pkcs1.pem"),
        "test-key-rsa-pss",
    )
    .unwrap();
    let es256 = Es256Signer::from_sec1_pem(P256_SEC1, "test-key-ecc-p256").unwrap();
    let ed25519 = Ed25519Signer::from_pkcs8_pem(ED25519_PKCS8, "test-key-ed25519").unwrap();
    let keys: [&dyn JwkSigner; 3] = [&ps256, &es256, &ed25519];
    let body = br#"{"client":"c"}"#.to_vec();
    let digest = content_digest(&body, DigestAlgorithm::Sha256);
    for (index, signer) in keys.iter().enumerate() {
        let message = Message {
            method: "POST",
            target_uri: URL,
            content_digest: Some(&digest),
            authorization: None,
            other: Vec::new(),
        };
        let input = SignatureInput {
            components: vec![
                Component::Method,
                Component::TargetUri,
                Component::ContentDigest,
            ],
            created: NOW,
            keyid: signer.key_id().into(),
            nonce: Some(format!("nonce-{index}")),
            tag: Tag::Gnap,
        };
        let (signature_input, signature) = sign(&message, &input, signer, "sig1").unwrap();
        assert!(
            !signature_input.contains("alg="),
            "GNAP never sends alg (§7.3.1)"
        );
        let headers = vec![
            ("Content-Digest".to_owned(), digest.clone()),
            ("Signature-Input".to_owned(), signature_input),
            ("Signature".to_owned(), signature),
        ];
        let request = SignedRequest {
            method: "POST",
            target_uri: URL,
            headers: &headers,
            body: Some(&body),
        };
        let expectations = Expectations {
            now: NOW,
            max_clock_skew: 300,
            key_id: Some(signer.key_id()),
        };
        let key = PublicKey::from_jwk(&signer.public_jwk().unwrap()).unwrap();
        verify_request(&request, &key, &expectations, &|_: &str, _: u64| true).unwrap();
        for other in keys
            .iter()
            .filter(|other| other.key_id() != signer.key_id())
        {
            let wrong = PublicKey::from_jwk(&other.public_jwk().unwrap()).unwrap();
            let expectations = Expectations {
                key_id: None,
                ..expectations
            };
            assert!(
                verify_request(&request, &wrong, &expectations, &|_: &str, _: u64| true).is_err(),
                "{} accepted a {} signature",
                other.algorithm(),
                signer.algorithm()
            );
        }
    }
}

/// The identity point is a weak Ed25519 key: with it, a signature of zeros
/// passes the permissive check. Neither import builds a verifier from it, so
/// no such key reaches the strict verifier.
#[test]
fn neither_ed25519_import_accepts_the_identity_key() {
    let mut identity = [0u8; 32];
    identity[0] = 1;
    // SubjectPublicKeyInfo for Ed25519: the algorithm identifier, then the key.
    let mut spki = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki.extend_from_slice(&identity);
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        STANDARD.encode(&spki)
    );
    let Err(refusal) = Ed25519Verifier::from_public_key_pem(&pem) else {
        panic!("the identity key must be refused");
    };
    assert!(refusal.to_string().contains("weak"), "{refusal}");
    let mut jwk = ed25519_jwk();
    jwk.insert("x".into(), json!(URL_SAFE_NO_PAD.encode(identity)));
    assert!(Ed25519Verifier::from_public_jwk(&jwk).is_err());
}
