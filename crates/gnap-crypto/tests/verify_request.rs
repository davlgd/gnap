//! The shared verifier: every check of RFC 9635 §7.3.1, obtained directly.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use gnap_crypto::digest::{content_digest, DigestAlgorithm};
use gnap_crypto::httpsig::{sign, signature_base, Component, Message, SignatureInput, Tag};
use gnap_crypto::proof::{ProofError, Signer, Verifier};
use gnap_crypto::ps256::{Ps256Signer, Ps256Verifier};
use gnap_crypto::verify::{verify_request, Accepted, Expectations, SignedRequest, VerifyError};
use std::cell::RefCell;
use std::collections::HashSet;

const RSA_PKCS1: &str = include_str!("rfc9421-b12.pkcs1.pem");
const URL: &str = "https://as.example/gnap";
const NOW: u64 = 1_700_000_000;

fn signer() -> Ps256Signer {
    Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap()
}

fn input(components: Vec<Component>, nonce: Option<&str>) -> SignatureInput {
    SignatureInput {
        components,
        created: NOW,
        keyid: "gnap-demo".into(),
        nonce: nonce.map(str::to_owned),
        tag: Tag::Gnap,
    }
}

/// Signs exactly what `input` says, bypassing `sign`'s own coverage checks so
/// that a non-conformant signature can be built on purpose.
fn forge(input: &SignatureInput, message: &Message<'_>, label: &str) -> Vec<(String, String)> {
    let raw = input.serialize().unwrap();
    let base = signature_base(message, &input.components, &raw).unwrap();
    let sig = signer().sign(base.as_bytes()).unwrap();
    vec![
        ("Signature-Input".into(), format!("{label}={raw}")),
        (
            "Signature".into(),
            format!("{label}=:{}:", STANDARD.encode(sig)),
        ),
    ]
}

const fn expectations() -> Expectations<'static> {
    Expectations {
        now: NOW,
        max_clock_skew: 300,
        key_id: Some("gnap-demo"),
    }
}

/// A nonce memory that is a set, and can be inspected.
fn memory() -> RefCell<HashSet<String>> {
    RefCell::new(HashSet::new())
}

fn verify(
    headers: &[(String, String)],
    body: Option<&[u8]>,
    expectations: &Expectations<'_>,
    seen: &RefCell<HashSet<String>>,
) -> Result<Accepted, VerifyError> {
    let remember = |nonce: &str, _: u64| seen.borrow_mut().insert(nonce.to_owned());
    verify_request(
        &SignedRequest {
            method: "POST",
            target_uri: URL,
            headers,
            body,
        },
        &signer().verifier(),
        expectations,
        &remember,
    )
}

/// The full shape: content, a token, an extra covered field, a nonce.
fn conformant() -> (Vec<(String, String)>, Vec<u8>) {
    let body = br#"{"client":"c"}"#.to_vec();
    let digest = content_digest(&body, DigestAlgorithm::Sha256);
    let message = Message {
        method: "POST",
        target_uri: URL,
        content_digest: Some(&digest),
        authorization: Some("GNAP tok"),
        other: vec![("\"x-extra\"".into(), "a, b".into())],
    };
    let input = input(
        vec![
            Component::Method,
            Component::TargetUri,
            Component::ContentDigest,
            Component::Authorization,
            Component::Field("x-extra".into()),
        ],
        Some("n-1"),
    );
    let (sig_input, sig) = sign(&message, &input, &signer(), "sig1").unwrap();
    let headers = vec![
        ("Content-Digest".into(), digest),
        ("Authorization".into(), "GNAP tok".into()),
        ("X-Extra".into(), " a ".into()),
        ("x-extra".into(), "b".into()),
        ("Signature-Input".into(), sig_input),
        ("Signature".into(), sig),
    ];
    (headers, body)
}

/// GNAP-9635-§7.3.1-M19 — the signature validates against the expected key,
/// and what was accepted is reported rather than re-parsed by the caller.
#[test]
fn a_conformant_request_is_accepted_and_described() {
    let (headers, body) = conformant();
    let seen = memory();
    let accepted = verify(&headers, Some(&body), &expectations(), &seen).unwrap();
    assert_eq!(accepted.label, "sig1");
    assert_eq!(accepted.params.created, Some(NOW));
    assert_eq!(accepted.params.nonce.as_deref(), Some("n-1"));
    assert_eq!(accepted.components.len(), 5);
    assert!(seen.borrow().contains("n-1"), "the nonce was spent");
}

/// A request with no signature at all is told apart from one whose signature
/// is refused: the two are answered differently by a role.
#[test]
fn an_unsigned_request_is_refused_as_such() {
    let e = verify(&[], None, &expectations(), &memory()).unwrap_err();
    assert_eq!(e, VerifyError::Unsigned);
}

/// GNAP-9635-§7.3.1-M04, GNAP-9635-§7.3.1-M09, GNAP-9635-§7.3.1-M11,
/// GNAP-9635-§7.3.1-M12, GNAP-9635-§7.3.1-M15, GNAP-9635-§7.3.1-MN16,
/// GNAP-9635-§7.3.1-M17, GNAP-9635-§7.3.1-M18 — each requirement of the
/// section refused on its own, with a reason that names it.
#[test]
fn each_requirement_of_7_3_1_is_enforced() {
    let plain = Message {
        method: "POST",
        target_uri: URL,
        content_digest: None,
        authorization: None,
        other: Vec::new(),
    };
    let both = vec![Component::Method, Component::TargetUri];

    // The tag has to be `gnap`.
    let mut rotate = input(both.clone(), None);
    rotate.tag = Tag::GnapRotate;
    let e = verify(
        &forge(&rotate, &plain, "sig1"),
        None,
        &expectations(),
        &memory(),
    )
    .unwrap_err();
    assert!(e.to_string().contains("tag="), "{e}");

    // `alg` is forbidden. Its presence is decided before any signature check,
    // so the signature bytes do not matter here.
    let with_alg = vec![
        (
            "Signature-Input".into(),
            format!(
                r#"sig1=("@method" "@target-uri");created={NOW};keyid="gnap-demo";tag="gnap";alg="rsa-pss-sha512""#
            ),
        ),
        ("Signature".into(), "sig1=:AAAA:".into()),
    ];
    let e = verify(&with_alg, None, &expectations(), &memory()).unwrap_err();
    assert!(e.to_string().contains("`alg`"), "{e}");

    // `keyid` names the presented key.
    let other_key = Expectations {
        key_id: Some("someone-else"),
        ..expectations()
    };
    let e = verify(
        &forge(&input(both.clone(), None), &plain, "sig1"),
        None,
        &other_key,
        &memory(),
    )
    .unwrap_err();
    assert!(e.to_string().contains("keyid"), "{e}");

    // `created` sits within the window.
    let late = Expectations {
        now: NOW + 301,
        ..expectations()
    };
    let e = verify(
        &forge(&input(both.clone(), None), &plain, "sig1"),
        None,
        &late,
        &memory(),
    )
    .unwrap_err();
    assert!(e.to_string().contains("created"), "{e}");
    let just_in_time = Expectations {
        now: NOW + 300,
        ..expectations()
    };
    verify(
        &forge(&input(both.clone(), None), &plain, "sig1"),
        None,
        &just_in_time,
        &memory(),
    )
    .expect("the edge of the window is inside it");

    // @method and @target-uri are always covered.
    for (missing, kept) in [
        ("@method", Component::TargetUri),
        ("@target-uri", Component::Method),
    ] {
        let e = verify(
            &forge(&input(vec![kept], None), &plain, "sig1"),
            None,
            &expectations(),
            &memory(),
        )
        .unwrap_err();
        assert!(e.to_string().contains(missing), "{e}");
    }

    // A token present but not covered.
    let mut with_token = forge(&input(both.clone(), None), &plain, "sig1");
    with_token.push(("Authorization".into(), "GNAP tok".into()));
    let e = verify(&with_token, None, &expectations(), &memory()).unwrap_err();
    assert!(e.to_string().contains("`authorization`"), "{e}");

    // Content present but its digest not covered.
    let body = b"{}";
    let e = verify(
        &forge(&input(both, None), &plain, "sig1"),
        Some(body),
        &expectations(),
        &memory(),
    )
    .unwrap_err();
    assert!(e.to_string().contains("`content-digest`"), "{e}");

    // Content covered, then tampered with.
    let (headers, mut body) = conformant();
    body[2] ^= 0x20;
    let e = verify(&headers, Some(&body), &expectations(), &memory()).unwrap_err();
    assert!(e.to_string().contains("digest does not match"), "{e}");
}

/// GNAP-9635-§7.3.1-M14 — a nonce is unique, and GNAP-9635-§7.3.1-M21 — an
/// unproven signature must not spend one.
#[test]
fn a_nonce_is_spent_once_and_only_by_a_proven_signature() {
    let (headers, body) = conformant();
    let seen = memory();
    verify(&headers, Some(&body), &expectations(), &seen).unwrap();
    let e = verify(&headers, Some(&body), &expectations(), &seen).unwrap_err();
    assert!(e.to_string().contains("already been seen"), "{e}");

    // A forged signature carrying a fresh nonce is refused before the nonce is
    // remembered, so the legitimate signer can still use it.
    let plain = Message {
        method: "POST",
        target_uri: URL,
        content_digest: None,
        authorization: None,
        other: Vec::new(),
    };
    let genuine = forge(
        &input(vec![Component::Method, Component::TargetUri], Some("n-2")),
        &plain,
        "sig1",
    );
    let mut forged = genuine.clone();
    forged[1].1 = "sig1=:AAAA:".into();
    let e = verify(&forged, None, &expectations(), &seen).unwrap_err();
    assert!(e.to_string().contains("verification"), "{e}");
    assert!(
        !seen.borrow().contains("n-2"),
        "an unproven signature spent a nonce"
    );
    verify(&genuine, None, &expectations(), &seen).expect("the nonce was still fresh");
}

/// GNAP-9635-§7.3.1-M21 — "The verifier MUST examine all included signatures
/// until it finds (at least) one that is acceptable".
#[test]
fn every_signature_is_examined_until_one_is_acceptable() {
    let plain = Message {
        method: "POST",
        target_uri: URL,
        content_digest: None,
        authorization: None,
        other: Vec::new(),
    };
    let good = forge(
        &input(vec![Component::Method, Component::TargetUri], None),
        &plain,
        "sig1",
    );
    let bad = forge(&input(vec![Component::Method], None), &plain, "bad");
    let headers = vec![
        (
            "Signature-Input".into(),
            format!("{}, {}", bad[0].1, good[0].1),
        ),
        ("Signature".into(), format!("{}, {}", bad[1].1, good[1].1)),
    ];
    let accepted = verify(&headers, None, &expectations(), &memory()).unwrap();
    assert_eq!(accepted.label, "sig1");

    // With the good one gone, the reason reported is the last candidate's.
    let headers = vec![
        ("Signature-Input".into(), bad[0].1.clone()),
        ("Signature".into(), bad[1].1.clone()),
    ];
    let e = verify(&headers, None, &expectations(), &memory()).unwrap_err();
    assert!(
        matches!(e, VerifyError::Rejected(_)) && e.to_string().contains("@target-uri"),
        "{e}"
    );
}

/// GNAP-9635-§7.3.1-M15 — a key resolved by reference names itself through
/// the verifier, and that name is checked too.
#[test]
fn the_verifiers_own_key_identity_is_checked() {
    struct Named(Ps256Verifier);
    impl Verifier for Named {
        fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), ProofError> {
            self.0.verify(data, signature)
        }
        fn algorithm(&self) -> &'static str {
            self.0.algorithm()
        }
        fn expected_key_id(&self) -> Option<&str> {
            Some("registered-key")
        }
    }

    let plain = Message {
        method: "POST",
        target_uri: URL,
        content_digest: None,
        authorization: None,
        other: Vec::new(),
    };
    let headers = forge(
        &input(vec![Component::Method, Component::TargetUri], None),
        &plain,
        "sig1",
    );
    let no_presented_key = Expectations {
        key_id: None,
        ..expectations()
    };
    let remember = |_: &str, _: u64| true;
    let e = verify_request(
        &SignedRequest {
            method: "POST",
            target_uri: URL,
            headers: &headers,
            body: None,
        },
        &Named(signer().verifier()),
        &no_presented_key,
        &remember,
    )
    .unwrap_err();
    assert!(e.to_string().contains("registered-key"), "{e}");
}
