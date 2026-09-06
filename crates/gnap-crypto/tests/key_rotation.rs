//! Real PS256 proofs for RFC 9635 §7.3.1.1, including adversarial pairings.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use gnap_crypto::httpsig::{signature_base, Component, Message, SignatureInput, Tag};
use gnap_crypto::rotation::{MAX_ROTATION_SIGNATURES, MAX_ROTATION_SIGNATURE_BYTES};
use gnap_crypto::{
    content_digest, verify_key_rotation, verify_request, AcceptedRotation, DigestAlgorithm,
    Expectations, ProofError, Ps256Signer, RotationNonceMemory, RotationProof, SignedRequest,
    Signer, Verifier, VerifyError,
};
use std::cell::Cell;
use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

const URL: &str = "https://as.example/token/manage";
const NOW: u64 = 1_700_000_000;

fn old_key() -> &'static Ps256Signer {
    static KEY: OnceLock<Ps256Signer> = OnceLock::new();
    KEY.get_or_init(|| {
        Ps256Signer::from_pkcs1_pem(include_str!("rfc9421-b12.pkcs1.pem"), "old").unwrap()
    })
}

fn new_key() -> &'static Ps256Signer {
    static KEY: OnceLock<Ps256Signer> = OnceLock::new();
    KEY.get_or_init(|| Ps256Signer::generate(2048, "new").unwrap())
}

fn impostor() -> &'static Ps256Signer {
    static KEY: OnceLock<Ps256Signer> = OnceLock::new();
    KEY.get_or_init(|| Ps256Signer::generate(2048, "new").unwrap())
}

#[derive(Default)]
struct Memory(Mutex<HashSet<String>>);

impl Memory {
    fn snapshot(&self) -> HashSet<String> {
        self.0.lock().unwrap().clone()
    }
}

impl RotationNonceMemory for Memory {
    fn remember_pair(&self, previous: Option<&str>, replacement: Option<&str>, now: u64) -> bool {
        assert_eq!(now, NOW);
        let mut seen = self.0.lock().unwrap();
        if [previous, replacement]
            .into_iter()
            .flatten()
            .any(|nonce| seen.contains(nonce))
        {
            return false;
        }
        seen.extend(
            [previous, replacement]
                .into_iter()
                .flatten()
                .map(str::to_owned),
        );
        true
    }
}

fn components() -> Vec<Component> {
    vec![
        Component::Method,
        Component::TargetUri,
        Component::ContentDigest,
        Component::Authorization,
    ]
}

fn member(field: &str, key: &str) -> Component {
    Component::DictionaryMember {
        field: field.into(),
        key: key.into(),
    }
}

fn input(tag: Tag, nonce: &str, previous: &str) -> SignatureInput {
    let mut components = components();
    if tag == Tag::GnapRotate {
        components.extend([
            member("signature", previous),
            member("signature-input", previous),
        ]);
    }
    SignatureInput {
        components,
        created: NOW,
        keyid: if tag == Tag::Gnap { "old" } else { "new" }.into(),
        nonce: Some(nonce.into()),
        tag,
    }
}

struct Request {
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn new() -> Self {
        let body = br#"{"key":"new-key-reference"}"#.to_vec();
        Self {
            headers: vec![
                (
                    "Content-Digest".into(),
                    content_digest(&body, DigestAlgorithm::Sha256),
                ),
                ("Authorization".into(), "GNAP management-credential".into()),
            ],
            body,
        }
    }

    fn signed() -> Self {
        let mut request = Self::new();
        request.add(
            old_key(),
            &input(Tag::Gnap, "old-nonce", ""),
            "old-good",
            false,
        );
        request.add(
            new_key(),
            &input(Tag::GnapRotate, "new-nonce", "old-good"),
            "new-good",
            false,
        );
        request
    }

    fn view(&self) -> SignedRequest<'_> {
        SignedRequest {
            method: "POST",
            target_uri: URL,
            headers: &self.headers,
            body: Some(&self.body),
        }
    }

    /// Signs the requested shape even when GNAP coverage is intentionally wrong.
    fn add(
        &mut self,
        signer: &Ps256Signer,
        input: &SignatureInput,
        label: &str,
        extra_space: bool,
    ) {
        let mut raw = input.serialize().unwrap();
        if extra_space {
            raw = raw.replace(
                "\"@method\" \"@target-uri\"",
                "\"@method\"   \"@target-uri\"",
            );
        }
        self.add_raw(signer, &input.components, &raw, label);
    }

    fn add_raw(&mut self, signer: &Ps256Signer, components: &[Component], raw: &str, label: &str) {
        // The new Signature-Input is known before signing. This also permits
        // covering that entire field, unlike covering the entire Signature field.
        self.headers
            .push(("Signature-Input".into(), format!("{label}={raw}")));
        let digest = self
            .headers
            .iter()
            .find(|(name, _)| name == "Content-Digest")
            .unwrap()
            .1
            .as_str();
        let message = Message {
            method: "POST",
            target_uri: URL,
            content_digest: Some(digest),
            authorization: Some("GNAP management-credential"),
            other: Vec::new(),
        }
        .with_fields(components, |name| {
            self.headers
                .iter()
                .filter(|(field, _)| field.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>()
        })
        .with_dictionary_fields(components, |name| {
            self.headers
                .iter()
                .filter(|(field, _)| field.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>()
        })
        .unwrap();
        let base = signature_base(&message, components, raw).unwrap();
        let signature = signer.sign(base.as_bytes()).unwrap();
        self.headers.push((
            "Signature".into(),
            format!("{label}=:{}:", STANDARD.encode(signature)),
        ));
    }

    fn verify(&self, memory: &Memory) -> Result<AcceptedRotation, VerifyError> {
        verify(&self.view(), memory, &new_key().verifier())
    }
}

const fn expectations() -> Expectations<'static> {
    Expectations {
        now: NOW,
        max_clock_skew: 30,
        key_id: None,
    }
}

fn verify(
    request: &SignedRequest<'_>,
    memory: &Memory,
    new: &dyn Verifier,
) -> Result<AcceptedRotation, VerifyError> {
    verify_key_rotation(
        request,
        &RotationProof {
            verifier: &old_key().verifier(),
            expectations: expectations(),
            policy: &|p| p.nonce.is_some(),
        },
        &RotationProof {
            verifier: new,
            expectations: expectations(),
            policy: &|p| p.nonce.is_some(),
        },
        memory,
    )
}

#[test]
fn a_linked_pair_uses_both_actual_keys_and_reserves_both_nonces() {
    assert_ne!(
        old_key().public_jwk().unwrap()["n"],
        new_key().public_jwk().unwrap()["n"]
    );
    let request = Request::signed();
    let memory = Memory::default();
    let accepted = request.verify(&memory).unwrap();
    assert_eq!(accepted.previous.label, "old-good");
    assert_eq!(accepted.replacement.label, "new-good");
    assert_eq!(
        memory.snapshot(),
        HashSet::from(["old-nonce".into(), "new-nonce".into()])
    );
    assert!(request.verify(&memory).is_err());
}

#[test]
fn canonical_dictionary_members_do_not_replace_old_raw_signature_parameters() {
    let mut request = Request::new();
    request.add(
        old_key(),
        &input(Tag::Gnap, "old-nonce", ""),
        "old-good",
        true,
    );
    let mut new = input(Tag::GnapRotate, "new-nonce", "old-good");
    new.created -= 5;
    request.add(new_key(), &new, "new-good", false);
    let accepted = request.verify(&Memory::default()).unwrap();
    assert_eq!(accepted.previous.params.created, Some(NOW));
    assert_eq!(accepted.replacement.params.created, Some(NOW - 5));
}

#[test]
fn dictionary_member_resolution_matches_rfc9421_canonical_values() {
    let components = [member("example-dict", "c"), member("example-dict", "d")];
    let message = Message {
        method: "POST",
        target_uri: URL,
        content_digest: None,
        authorization: None,
        other: Vec::new(),
    }
    .with_dictionary_fields(&components, |_| ["a=1, c=(a   b    c)", "d"])
    .unwrap();
    assert_eq!(
        message.other,
        vec![
            ("\"example-dict\";key=\"c\"".into(), "(a b c)".into()),
            ("\"example-dict\";key=\"d\"".into(), "?1".into()),
        ]
    );
    assert!(Message {
        method: "POST",
        target_uri: URL,
        content_digest: None,
        authorization: None,
        other: Vec::new(),
    }
    .with_dictionary_fields(&[member("example-dict", "missing")], |_| ["a=1"])
    .is_err());
}

#[test]
fn the_entire_signature_input_field_can_cover_the_old_input() {
    let mut request = Request::new();
    request.add(
        old_key(),
        &input(Tag::Gnap, "old-nonce", ""),
        "old-good",
        false,
    );
    let mut new = input(Tag::GnapRotate, "new-nonce", "old-good");
    new.components.pop();
    new.components
        .push(Component::Field("signature-input".into()));
    request.add(new_key(), &new, "new-good", false);
    request.verify(&Memory::default()).unwrap();
}

#[test]
fn missing_or_unlinked_proofs_spend_no_nonce() {
    for coverage in [None, Some("signature"), Some("signature-input")] {
        let mut request = Request::new();
        request.add(
            old_key(),
            &input(Tag::Gnap, "old-nonce", ""),
            "old-good",
            false,
        );
        let mut new = input(Tag::GnapRotate, "new-nonce", "old-good");
        new.components.retain(|component| match component {
            Component::DictionaryMember { field, .. } => coverage == Some(field.as_str()),
            _ => true,
        });
        request.add(new_key(), &new, "new-good", false);
        let memory = Memory::default();
        assert!(request.verify(&memory).is_err(), "{coverage:?}");
        assert!(memory.snapshot().is_empty());
    }
    for missing_tag in [Tag::Gnap, Tag::GnapRotate] {
        let mut request = Request::signed();
        let label = if missing_tag == Tag::Gnap {
            "old-good="
        } else {
            "new-good="
        };
        request
            .headers
            .retain(|(_, value)| !value.starts_with(label));
        let memory = Memory::default();
        assert!(request.verify(&memory).is_err());
        assert!(memory.snapshot().is_empty());
    }
}

#[test]
fn a_different_key_with_the_same_kid_is_not_the_replacement_key() {
    assert_eq!(new_key().key_id(), impostor().key_id());
    assert_ne!(
        new_key().public_jwk().unwrap()["n"],
        impostor().public_jwk().unwrap()["n"]
    );
    let memory = Memory::default();
    assert!(verify(&Request::signed().view(), &memory, &impostor().verifier()).is_err());
    assert!(memory.snapshot().is_empty());
}

#[test]
fn each_new_proof_requirement_is_enforced_before_nonce_reservation() {
    for case in 0..9 {
        let mut request = Request::new();
        request.add(
            old_key(),
            &input(Tag::Gnap, "old-nonce", ""),
            "old-good",
            false,
        );
        let mut new = input(Tag::GnapRotate, "new-nonce", "old-good");
        match case {
            0..=3 => {
                new.components.remove(case);
            }
            4 => new.tag = Tag::Gnap,
            5 => new.created = NOW - 31,
            6 => new.keyid = "old".into(),
            7 => new.nonce = None,
            8 => new.nonce = Some("old-nonce".into()),
            _ => unreachable!(),
        }
        request.add(new_key(), &new, "new-good", false);
        let memory = Memory::default();
        assert!(request.verify(&memory).is_err(), "case {case}");
        assert!(memory.snapshot().is_empty(), "case {case}");
    }
}

#[test]
fn tampering_with_the_signed_request_never_spends_a_nonce() {
    for case in 0..4 {
        let mut request = Request::signed();
        match case {
            0 => request.body.push(b' '),
            1 => request.headers[1].1 = "GNAP another-management-credential".into(),
            2 => request
                .headers
                .push(("Authorization".into(), "GNAP duplicate".into())),
            3 => request.body.clear(),
            _ => unreachable!(),
        }
        let memory = Memory::default();
        assert!(request.verify(&memory).is_err(), "case {case}");
        assert!(memory.snapshot().is_empty());
    }
    let request = Request::signed();
    for changed in [
        SignedRequest {
            method: "PATCH",
            ..request.view()
        },
        SignedRequest {
            target_uri: "https://elsewhere.example/token",
            ..request.view()
        },
    ] {
        assert!(verify(&changed, &Memory::default(), &new_key().verifier()).is_err());
    }
}

#[test]
fn a_replayed_pair_does_not_mask_a_later_fresh_pair() {
    let mut request = Request::new();
    request.add(
        old_key(),
        &input(Tag::Gnap, "old-nonce", ""),
        "old-good",
        false,
    );
    request.add(
        new_key(),
        &input(Tag::GnapRotate, "spent-new", "old-good"),
        "new-spent",
        false,
    );
    request.add(
        new_key(),
        &input(Tag::GnapRotate, "fresh-new", "old-good"),
        "new-fresh",
        false,
    );
    let memory = Memory::default();
    memory.0.lock().unwrap().insert("spent-new".into());
    let accepted = request.verify(&memory).unwrap();
    assert_eq!(accepted.replacement.label, "new-fresh");
    assert_eq!(memory.snapshot().len(), 3);
}

#[test]
fn the_link_names_the_old_signature_that_actually_verified() {
    let mut request = Request::new();
    request.add(
        old_key(),
        &input(Tag::Gnap, "old-nonce", ""),
        "old-good",
        false,
    );
    request.add(
        new_key(),
        &input(Tag::Gnap, "decoy-nonce", ""),
        "old-decoy",
        false,
    );
    request.add(
        new_key(),
        &input(Tag::GnapRotate, "new-nonce", "old-decoy"),
        "new-decoy",
        false,
    );
    let memory = Memory::default();
    assert!(request.verify(&memory).is_err());
    assert!(memory.snapshot().is_empty());
    request.add(
        new_key(),
        &input(Tag::GnapRotate, "fresh-new", "old-good"),
        "new-good",
        false,
    );
    assert_eq!(
        request.verify(&memory).unwrap().replacement.label,
        "new-good"
    );
    assert!(!memory.snapshot().contains("decoy-nonce"));
    assert!(!memory.snapshot().contains("new-nonce"));
}

#[test]
fn ordinary_verification_still_requires_gnap_and_shares_nonce_state() {
    let request = Request::signed();
    let memory = Memory::default();
    request.verify(&memory).unwrap();
    let remember = |nonce: &str, _: u64| memory.0.lock().unwrap().insert(nonce.into());
    assert!(verify_request(
        &request.view(),
        &old_key().verifier(),
        &expectations(),
        &remember
    )
    .is_err());
    let mut only_new = Request::signed();
    // Keep the covered old fields, but there is no old proof under the new key.
    assert!(verify_request(
        &only_new.view(),
        &new_key().verifier(),
        &expectations(),
        &remember
    )
    .is_err());
    only_new
        .headers
        .retain(|(_, value)| !value.starts_with("new-good="));
    assert!(only_new.verify(&Memory::default()).is_err());
}

#[test]
fn resource_limits_and_clock_mismatch_fail_before_crypto() {
    struct Unused;
    impl Verifier for Unused {
        fn verify(&self, _: &[u8], _: &[u8]) -> Result<(), ProofError> {
            panic!("must not verify")
        }
        fn algorithm(&self) -> &'static str {
            "unused"
        }
    }
    let old = RotationProof {
        verifier: &Unused,
        expectations: expectations(),
        policy: &|_| true,
    };
    let mut new = RotationProof {
        verifier: &Unused,
        expectations: expectations(),
        policy: &|_| true,
    };
    let mut request = Request::new();
    for index in 0..=MAX_ROTATION_SIGNATURES {
        request
            .headers
            .push(("Signature-Input".into(), format!("s{index}=?1")));
        request
            .headers
            .push(("Signature".into(), format!("s{index}=:AA==:")));
    }
    assert!(verify_key_rotation(&request.view(), &old, &new, &Memory::default()).is_err());
    request
        .headers
        .push(("Signature".into(), "a".repeat(MAX_ROTATION_SIGNATURE_BYTES)));
    assert!(verify_key_rotation(&request.view(), &old, &new, &Memory::default()).is_err());
    new.expectations.now += 1;
    assert!(
        verify_key_rotation(&Request::signed().view(), &old, &new, &Memory::default()).is_err()
    );
}

#[test]
fn both_keys_enforce_parameters_and_body_coverage() {
    for old_side in [true, false] {
        for case in 0..5 {
            let mut request = Request::new();
            let old = input(Tag::Gnap, "old-nonce", "");
            if !old_side {
                request.add(old_key(), &old, "old-good", false);
            }
            let mut bad = if old_side {
                old
            } else {
                input(Tag::GnapRotate, "new-nonce", "old-good")
            };
            match case {
                0 => {
                    bad.components.remove(2);
                }
                1 => bad.created = NOW + 31,
                2 => bad.keyid = "not-the-key".into(),
                3 => bad.nonce = None,
                4 => {}
                _ => unreachable!(),
            }
            let mut raw = bad.serialize().unwrap();
            if case == 4 {
                raw.push_str(";alg=\"rsa-pss-sha256\"");
            }
            request.add_raw(
                if old_side { old_key() } else { new_key() },
                &bad.components,
                &raw,
                if old_side { "old-good" } else { "new-good" },
            );
            if old_side {
                request.add(
                    new_key(),
                    &input(Tag::GnapRotate, "new-nonce", "old-good"),
                    "new-good",
                    false,
                );
            }
            let memory = Memory::default();
            assert!(
                request.verify(&memory).is_err(),
                "old={old_side}, case={case}"
            );
            assert!(memory.snapshot().is_empty());
        }
    }
}

#[test]
fn each_candidate_is_verified_once_even_with_multiple_possible_pairs() {
    struct Count<'a> {
        inner: &'a dyn Verifier,
        calls: Cell<usize>,
    }
    impl Verifier for Count<'_> {
        fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), ProofError> {
            self.calls.set(self.calls.get() + 1);
            self.inner.verify(data, signature)
        }
        fn algorithm(&self) -> &'static str {
            self.inner.algorithm()
        }
        fn expected_key_id(&self) -> Option<&str> {
            self.inner.expected_key_id()
        }
    }
    let mut request = Request::new();
    // A valid Structured Field member, but not a usable signature, must not
    // hide the old and new candidates that follow it.
    request
        .headers
        .push(("Signature-Input".into(), "unusable=?1".into()));
    request
        .headers
        .push(("Signature".into(), "unusable=:AA==:".into()));
    request.add(
        old_key(),
        &input(Tag::Gnap, "old-spent", ""),
        "first",
        false,
    );
    request.add(
        old_key(),
        &input(Tag::Gnap, "old-fresh", ""),
        "second",
        false,
    );
    request.add(
        new_key(),
        &input(Tag::GnapRotate, "new-first", "first"),
        "new-first",
        false,
    );
    request.add(
        new_key(),
        &input(Tag::GnapRotate, "new-second", "second"),
        "new-second",
        false,
    );
    let old = Count {
        inner: &old_key().verifier(),
        calls: Cell::new(0),
    };
    let new = Count {
        inner: &new_key().verifier(),
        calls: Cell::new(0),
    };
    let memory = Memory::default();
    memory.0.lock().unwrap().insert("old-spent".into());
    let accepted = verify_key_rotation(
        &request.view(),
        &RotationProof {
            verifier: &old,
            expectations: expectations(),
            policy: &|_| true,
        },
        &RotationProof {
            verifier: &new,
            expectations: expectations(),
            policy: &|_| true,
        },
        &memory,
    )
    .unwrap();
    assert_eq!(accepted.previous.label, "second");
    assert_eq!(accepted.replacement.label, "new-second");
    assert_eq!(old.calls.get(), 2);
    assert_eq!(new.calls.get(), 2);
    assert!(!memory.snapshot().contains("new-first"));
}

#[test]
fn nonce_pair_atomicity_prevents_two_acceptances_with_a_shared_old_nonce() {
    let first = Request::signed();
    let mut second = Request::new();
    second.add(
        old_key(),
        &input(Tag::Gnap, "old-nonce", ""),
        "old-good",
        false,
    );
    second.add(
        new_key(),
        &input(Tag::GnapRotate, "other-new", "old-good"),
        "new-good",
        false,
    );
    let memory = Memory::default();
    let barrier = std::sync::Barrier::new(2);
    let outcomes = std::thread::scope(|scope| {
        let one = scope.spawn(|| {
            barrier.wait();
            first.verify(&memory).is_ok()
        });
        let two = scope.spawn(|| {
            barrier.wait();
            second.verify(&memory).is_ok()
        });
        [one.join().unwrap(), two.join().unwrap()]
    });
    assert_eq!(outcomes.into_iter().filter(|accepted| *accepted).count(), 1);
    assert_eq!(memory.snapshot().len(), 2);
    assert!(memory.snapshot().contains("old-nonce"));
}
