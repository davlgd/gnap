//! JOSE proofs, `jws` and `jwsd`: RFC vectors, round trips, key rotation,
//! replay protection, and every refusal of the profile.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use gnap_crypto::jws::{DETACHED_JWS_HEADER, JOSE_MEDIA_TYPE, MAX_DETACHED_JWS_BYTES};
use gnap_crypto::{
    sign_jws, sign_jws_rotation, unverified_attached_payload, unverified_rotation_content,
    verify_jws_request, verify_jws_rotation, Ed25519Signer, Es256Signer, Expectations, JwkSigner,
    JwsKey, JwsMethod, JwsParams, JwsProof, JwsReplayMemory, Ps256Signer, PublicKey, ReplayCache,
    ReplayId, Rs256Signer, Rs256Verifier, SignedRequest, Signer, Verifier, VerifyError,
};
use serde_json::{json, Map, Value};
use sha2::{Digest as _, Sha256};
use std::sync::{Barrier, Mutex};

// Public test material from RFC 9421 Appendices B.1.2 to B.1.4 and RFC 9635
// §7.3.3 and §7.3.4; never a deployment key.
const RSA_PKCS1: &str = include_str!("rfc9421-b12.pkcs1.pem");
const P256_SEC1: &str = include_str!("rfc9421-b13.sec1.pem");
const ED25519_PKCS8: &str = include_str!("rfc9421-b14.pkcs8.pem");
const GNAP_RSA_JWK: &str = include_str!("rfc9635-gnap-rsa.jwk.json");
const RFC_DETACHED: &str = include_str!("rfc9635-7.3.3.detached-jws.txt");
const RFC_ATTACHED: &str = include_str!("rfc9635-7.3.4.attached-jws.txt");

const URI: &str = "https://server.example.com/gnap";
const NOW: u64 = 1_618_884_475;
const SKEW: u64 = 60;
const CONTENT: &[u8] = br#"{"access_token":{"access":["dolphin-metadata"]}}"#;

fn rs256() -> Rs256Signer {
    Rs256Signer::from_pkcs1_pem(RSA_PKCS1, "rsa-key").unwrap()
}
fn es256() -> Es256Signer {
    Es256Signer::from_sec1_pem(P256_SEC1, "p256-key").unwrap()
}
fn ed25519() -> Ed25519Signer {
    Ed25519Signer::from_pkcs8_pem(ED25519_PKCS8, "ed25519-key").unwrap()
}

/// The three signers, with the public key a server would import for each.
fn signers() -> Vec<(Box<dyn Signer>, PublicKey)> {
    fn entry<S: JwkSigner + 'static>(signer: S) -> (Box<dyn Signer>, PublicKey) {
        let key = PublicKey::for_jws(&signer.public_jwk().unwrap()).unwrap();
        (Box::new(signer), key)
    }
    vec![entry(rs256()), entry(es256()), entry(ed25519())]
}

fn key<'a>(verifier: &'a dyn Verifier, identity: &'a str) -> JwsKey<'a> {
    JwsKey {
        verifier,
        identity: identity.into(),
        expectations: Expectations {
            now: NOW,
            max_clock_skew: SKEW,
            key_id: None,
        },
    }
}

const fn params(token: Option<&str>) -> JwsParams<'_> {
    JwsParams {
        method: "POST",
        target_uri: URI,
        created: NOW,
        access_token: token,
    }
}

/// A request as it travels: its headers, and the content it carries.
struct Wire {
    method: String,
    uri: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Wire {
    fn new(proof: JwsProof, content: &[u8], token: Option<&str>) -> Self {
        let mut wire = Self {
            method: "POST".into(),
            uri: URI.into(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        match proof {
            JwsProof::Detached(value) => {
                wire.header(DETACHED_JWS_HEADER, &value);
                wire.body = content.to_vec();
            }
            JwsProof::Attached(value) => {
                wire.header("Content-Type", JOSE_MEDIA_TYPE);
                wire.body = value.into_bytes();
            }
        }
        if let Some(token) = token {
            wire.header("Authorization", &format!("GNAP {token}"));
        }
        wire
    }

    fn header(&mut self, name: &str, value: &str) -> &mut Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    fn without(&mut self, name: &str) -> &mut Self {
        self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        self
    }

    fn request(&self) -> SignedRequest<'_> {
        SignedRequest {
            method: &self.method,
            target_uri: &self.uri,
            headers: &self.headers,
            body: Some(&self.body),
        }
    }
}

/// A memory that accepts every reservation: the checks under test come first.
fn forgetful() -> impl JwsReplayMemory {
    |_: &[ReplayId], _: u64| true
}

fn rejection(result: Result<gnap_crypto::AcceptedJws, VerifyError>) -> String {
    match result {
        Err(VerifyError::Rejected(reason)) => reason,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

/// Signs `header` and `payload` as given, to build proofs a signer refuses.
fn forge(header: &Value, payload: &[u8], signer: &dyn Signer) -> String {
    forge_raw(&header.to_string(), payload, signer)
}

fn forge_raw(header: &str, payload: &[u8], signer: &dyn Signer) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let signature = signer.sign(input.as_bytes()).unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn jwsd_header(signer: &dyn Signer) -> Value {
    json!({
        "alg": signer.algorithm(), "kid": signer.key_id(), "typ": "gnap-binding-jwsd",
        "htm": "POST", "uri": URI, "created": NOW
    })
}

fn digest(content: &[u8]) -> Vec<u8> {
    Sha256::digest(content).to_vec()
}

/// RFC 9635 §7.3.3 and §7.3.4: both examples are valid `RS256` signatures
/// under the published key, and both carry `"typ":"gnap-binding+jwsd"`,
/// which the normative text and the registered media types spell with a
/// hyphen, and which names the wrong method for the attached example.
#[test]
fn rfc9635_examples_are_rs256_signatures_with_a_typ_the_profile_refuses() {
    let jwk: Map<String, Value> = serde_json::from_str(GNAP_RSA_JWK).unwrap();
    let verifier = Rs256Verifier::from_public_jwk(&jwk).unwrap();
    for compact in [RFC_DETACHED.trim(), RFC_ATTACHED.trim()] {
        let (input, signature) = compact.rsplit_once('.').unwrap();
        verifier
            .verify(
                input.as_bytes(),
                &URL_SAFE_NO_PAD.decode(signature).unwrap(),
            )
            .expect("the published signature verifies");
        let (header, _) = input.split_once('.').unwrap();
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap();
        assert_eq!(header["typ"], "gnap-binding+jwsd");
    }

    let detached = Wire::new(
        JwsProof::Detached(RFC_DETACHED.trim().into()),
        CONTENT,
        None,
    );
    let attached = Wire::new(JwsProof::Attached(RFC_ATTACHED.trim().into()), b"", None);
    for (method, wire) in [(JwsMethod::Jwsd, detached), (JwsMethod::Jws, attached)] {
        let reason = rejection(verify_jws_request(
            method,
            &wire.request(),
            &key(&verifier, "gnap-rsa"),
            &forgetful(),
        ));
        assert!(reason.contains("typ"), "{reason}");
    }
}

/// Every algorithm, both methods, with and without content and access token.
#[test]
fn every_algorithm_round_trips_with_both_methods() {
    for (signer, public) in signers() {
        for method in [JwsMethod::Jws, JwsMethod::Jwsd] {
            for content in [CONTENT, b""] {
                for token in [None, Some("80UPRY5NM33OMUKMKSKU")] {
                    let proof = sign_jws(method, &params(token), content, signer.as_ref()).unwrap();
                    let detached = matches!(proof, JwsProof::Detached(_));
                    assert_eq!(
                        detached,
                        method == JwsMethod::Jwsd || content.is_empty(),
                        "{method:?} {content:?}"
                    );
                    let wire = Wire::new(proof, content, token);
                    let cache = ReplayCache::new(16, SKEW);
                    let accepted = verify_jws_request(
                        method,
                        &wire.request(),
                        &key(&public, "client"),
                        &cache,
                    )
                    .unwrap_or_else(|e| panic!("{} {method:?}: {e}", signer.algorithm()));
                    assert_eq!(accepted.content, content);
                    assert_eq!(accepted.created, NOW);
                    let replay = rejection(verify_jws_request(
                        method,
                        &wire.request(),
                        &key(&public, "client"),
                        &cache,
                    ));
                    assert!(replay.contains("already used"), "{replay}");
                }
            }
        }
    }
}

/// The `jwsd` payload is the raw digest, encoded once, as in the §7.3.3
/// example, and an empty payload without content.
#[test]
fn a_detached_proof_signs_the_digest_of_the_content() {
    let signer = ed25519();
    for (content, payload) in [
        (CONTENT, URL_SAFE_NO_PAD.encode(digest(CONTENT))),
        (&b""[..], String::new()),
    ] {
        let JwsProof::Detached(compact) =
            sign_jws(JwsMethod::Jwsd, &params(None), content, &signer).unwrap()
        else {
            panic!("jwsd is detached");
        };
        assert_eq!(compact.split('.').nth(1), Some(payload.as_str()));
    }
}

/// The content a verifier returns for `jws` is the authenticated payload,
/// and a `jwsd` proof binds the exact bytes of the content.
#[test]
fn the_content_is_the_one_the_key_signed() {
    let signer = es256();
    let public = PublicKey::for_jws(&signer.public_jwk().unwrap()).unwrap();
    let mut wire = Wire::new(
        sign_jws(JwsMethod::Jwsd, &params(None), CONTENT, &signer).unwrap(),
        CONTENT,
        None,
    );
    wire.body.push(b' ');
    let reason = rejection(verify_jws_request(
        JwsMethod::Jwsd,
        &wire.request(),
        &key(&public, "client"),
        &forgetful(),
    ));
    assert!(reason.contains("payload"), "{reason}");

    let JwsProof::Attached(compact) =
        sign_jws(JwsMethod::Jws, &params(None), CONTENT, &signer).unwrap()
    else {
        panic!("jws with content is attached");
    };
    let mut segments: Vec<String> = compact.split('.').map(Into::into).collect();
    segments[1] = URL_SAFE_NO_PAD.encode(br#"{"access_token":{"access":["everything"]}}"#);
    let tampered = Wire::new(JwsProof::Attached(segments.join(".")), b"", None);
    let reason = rejection(verify_jws_request(
        JwsMethod::Jws,
        &tampered.request(),
        &key(&public, "client"),
        &forgetful(),
    ));
    assert!(reason.contains("signature"), "{reason}");
}

/// Key rotation, for both methods and across algorithms: the previous key
/// signs the request, the replacement key signs that proof.
#[test]
fn a_key_rotation_needs_both_keys_and_reserves_both_proofs() {
    let keys = signers();
    for method in [JwsMethod::Jws, JwsMethod::Jwsd] {
        for (i, (previous, previous_key)) in keys.iter().enumerate() {
            let (replacement, replacement_key) = &keys[(i + 1) % keys.len()];
            let proof = sign_jws_rotation(
                method,
                &params(Some("token")),
                CONTENT,
                previous.as_ref(),
                replacement.as_ref(),
            )
            .unwrap();
            let wire = Wire::new(proof, CONTENT, Some("token"));
            let cache = ReplayCache::new(16, SKEW);
            let old = key(previous_key, "old");
            let new = key(replacement_key, "new");

            for (a, b) in [(&new, &old), (&old, &old), (&new, &new)] {
                assert!(verify_jws_rotation(method, &wire.request(), a, b, &cache).is_err());
            }
            assert!(cache.is_empty(), "a refused rotation reserves nothing");
            // The outer proof alone is no ordinary proof: its payload is the
            // inner JWS, neither the digest of the content nor JSON.
            let ordinary = rejection(verify_jws_request(method, &wire.request(), &new, &cache));
            assert!(ordinary.contains("payload"), "{ordinary}");
            assert!(cache.is_empty());

            let accepted =
                verify_jws_rotation(method, &wire.request(), &old, &new, &cache).unwrap();
            assert_eq!(accepted.content, CONTENT);
            assert_eq!(cache.len(), 2);
            let replay = rejection(verify_jws_rotation(
                method,
                &wire.request(),
                &old,
                &new,
                &cache,
            ));
            assert!(replay.contains("already used"), "{replay}");
        }
    }
}

/// The inner proof of a rotation can't be used again under a fresh outer
/// one, and a refused pair reserves neither half.
#[test]
fn an_inner_rotation_proof_is_single_use() {
    let (previous, replacement) = (rs256(), ed25519());
    let previous_key = PublicKey::for_jws(&previous.public_jwk().unwrap()).unwrap();
    let replacement_key = PublicKey::for_jws(&replacement.public_jwk().unwrap()).unwrap();
    let JwsProof::Detached(first) = sign_jws_rotation(
        JwsMethod::Jwsd,
        &params(None),
        CONTENT,
        &previous,
        &replacement,
    )
    .unwrap() else {
        panic!("jwsd is detached");
    };
    let cache = ReplayCache::new(16, SKEW);
    let (old, new) = (key(&previous_key, "old"), key(&replacement_key, "new"));
    let wire = Wire::new(JwsProof::Detached(first.clone()), CONTENT, None);
    verify_jws_rotation(JwsMethod::Jwsd, &wire.request(), &old, &new, &cache).unwrap();

    let inner = URL_SAFE_NO_PAD
        .decode(first.split('.').nth(1).unwrap())
        .unwrap();
    let mut header = jwsd_header(&replacement);
    header["created"] = json!(NOW + 1);
    let fresh = forge(&header, &inner, &replacement);
    let wire = Wire::new(JwsProof::Detached(fresh), CONTENT, None);
    let reason = rejection(verify_jws_rotation(
        JwsMethod::Jwsd,
        &wire.request(),
        &old,
        &new,
        &cache,
    ));
    assert!(reason.contains("already used"), "{reason}");
    assert_eq!(cache.len(), 2, "the fresh outer proof isn't reserved");
}

/// `ES256` signatures are malleable: `(r, n − s)` verifies too. The replay
/// identifier leaves the signature out, so the second encoding is a replay.
#[test]
fn a_second_encoding_of_an_es256_proof_is_a_replay() {
    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let signer = es256();
    let public = PublicKey::for_jws(&signer.public_jwk().unwrap()).unwrap();
    let JwsProof::Detached(compact) =
        sign_jws(JwsMethod::Jwsd, &params(None), CONTENT, &signer).unwrap()
    else {
        panic!("jwsd is detached");
    };
    let (input, signature) = compact.rsplit_once('.').unwrap();
    let mut bytes = URL_SAFE_NO_PAD.decode(signature).unwrap();
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let difference = i16::from(ORDER[i]) - i16::from(bytes[32 + i]) - borrow;
        borrow = i16::from(difference < 0);
        bytes[32 + i] = u8::try_from(difference.rem_euclid(256)).unwrap();
    }
    assert!(
        public.verify(input.as_bytes(), &bytes).is_ok(),
        "the second encoding must verify, or it proves nothing"
    );
    let malleated = format!("{input}.{}", URL_SAFE_NO_PAD.encode(&bytes));
    assert_ne!(malleated, compact);

    let cache = ReplayCache::new(16, SKEW);
    let original = Wire::new(JwsProof::Detached(compact), CONTENT, None);
    verify_jws_request(
        JwsMethod::Jwsd,
        &original.request(),
        &key(&public, "client"),
        &cache,
    )
    .unwrap();
    let second = Wire::new(JwsProof::Detached(malleated), CONTENT, None);
    let reason = rejection(verify_jws_request(
        JwsMethod::Jwsd,
        &second.request(),
        &key(&public, "client"),
        &cache,
    ));
    assert!(reason.contains("already used"), "{reason}");
}

/// Two concurrent verifications of one proof: exactly one is accepted.
#[test]
fn concurrent_reservations_of_one_proof_accept_one() {
    let signer = ed25519();
    let public = PublicKey::for_jws(&signer.public_jwk().unwrap()).unwrap();
    let wire = Wire::new(
        sign_jws(JwsMethod::Jwsd, &params(None), CONTENT, &signer).unwrap(),
        CONTENT,
        None,
    );
    let cache = ReplayCache::new(16, SKEW);
    let barrier = Barrier::new(8);
    let accepted = Mutex::new(0);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                barrier.wait();
                let key = key(&public, "client");
                if verify_jws_request(JwsMethod::Jwsd, &wire.request(), &key, &cache).is_ok() {
                    *accepted.lock().unwrap() += 1;
                }
            });
        }
    });
    assert_eq!(*accepted.lock().unwrap(), 1);
}

/// The cache holds an identifier through its `created` plus its own skew,
/// that second included, refuses beyond its capacity, and forgets afterwards.
#[test]
fn the_replay_cache_retains_inclusively_and_refuses_when_full() {
    let signer = ed25519();
    let public = PublicKey::for_jws(&signer.public_jwk().unwrap()).unwrap();
    let ids = Mutex::new(Vec::new());
    let capture = |batch: &[ReplayId], _: u64| {
        ids.lock().unwrap().extend_from_slice(batch);
        true
    };
    for created in [NOW, NOW + 1] {
        let proof = sign_jws(
            JwsMethod::Jwsd,
            &JwsParams {
                created,
                ..params(None)
            },
            CONTENT,
            &signer,
        )
        .unwrap();
        let wire = Wire::new(proof, CONTENT, None);
        verify_jws_request(
            JwsMethod::Jwsd,
            &wire.request(),
            &key(&public, "client"),
            &capture,
        )
        .unwrap();
    }
    let ids = ids.into_inner().unwrap();
    let (first, second) = (ids[0], ids[1]);
    assert_eq!((first.created(), second.created()), (NOW, NOW + 1));
    assert_ne!(first.digest(), second.digest());

    let cache = ReplayCache::new(1, SKEW);
    assert!(cache.reserve(&[first], NOW));
    assert!(!cache.reserve(&[second], NOW), "the cache is full");
    assert!(
        !cache.reserve(&[first], NOW + SKEW),
        "held through its last second"
    );
    assert!(
        cache.reserve(&[second], NOW + SKEW + 1),
        "forgotten after it"
    );
    let fresh = ReplayCache::new(4, SKEW);
    assert!(!fresh.reserve(&[first, first], NOW), "a batch is distinct");
    assert!(fresh.is_empty(), "and a refused batch reserves nothing");
}

/// The clock window is inclusive at both ends, and a skew of zero accepts
/// only the current second.
#[test]
fn created_is_checked_against_the_clock_inclusively() {
    let signer = ed25519();
    let public = PublicKey::for_jws(&signer.public_jwk().unwrap()).unwrap();
    for (created, skew, accepted) in [
        (NOW - SKEW, SKEW, true),
        (NOW + SKEW, SKEW, true),
        (NOW - SKEW - 1, SKEW, false),
        (NOW + SKEW + 1, SKEW, false),
        (NOW, 0, true),
        (NOW + 1, 0, false),
    ] {
        let proof = sign_jws(
            JwsMethod::Jwsd,
            &JwsParams {
                created,
                ..params(None)
            },
            CONTENT,
            &signer,
        )
        .unwrap();
        let wire = Wire::new(proof, CONTENT, None);
        let mut key = key(&public, "client");
        key.expectations.max_clock_skew = skew;
        let result = verify_jws_request(
            JwsMethod::Jwsd,
            &wire.request(),
            &key,
            &ReplayCache::new(4, skew),
        );
        assert_eq!(result.is_ok(), accepted, "created {created}, skew {skew}");
    }
}

/// Each member of the protected header has to be what the profile says.
#[test]
fn the_protected_header_is_a_closed_profile() {
    let signer = ed25519();
    let public = PublicKey::for_jws(&signer.public_jwk().unwrap()).unwrap();
    let payload = digest(CONTENT);
    let base = jwsd_header(&signer);
    let mut cases: Vec<(Value, &str)> = Vec::new();
    for (member, value, reason) in [
        ("typ", json!("gnap-binding+jwsd"), "typ"),
        ("typ", json!("gnap-binding-jws"), "typ"),
        ("typ", json!("gnap-binding-rotation-jwsd"), "typ"),
        ("alg", json!("none"), "alg"),
        ("alg", json!("ES256"), "alg"),
        ("kid", json!(""), "kid"),
        ("htm", json!("post"), "htm"),
        ("uri", json!("https://server.example.com/gnap/"), "uri"),
        ("created", json!(1.0), "created"),
        ("created", json!(-1), "created"),
        ("created", json!("1618884475"), "created"),
        ("created", json!(true), "created"),
        ("created", json!(1e9), "created"),
        ("ath", json!("unexpected"), "ath"),
        ("crit", json!(["htm"]), "crit"),
        ("b64", json!(false), "b64"),
        ("jwk", Value::Null, "jwk"),
        ("jku", json!("https://attacker.example/jwks"), "jku"),
        ("x5c", json!([]), "x5c"),
        ("cty", json!("json"), "cty"),
    ] {
        let mut header = base.clone();
        header[member] = value;
        cases.push((header, reason));
    }
    for member in ["alg", "typ", "htm", "uri", "created"] {
        let mut header = base.clone();
        header.as_object_mut().unwrap().remove(member);
        cases.push((header, member));
    }
    for (header, reason) in cases {
        let wire = Wire::new(
            JwsProof::Detached(forge(&header, &payload, &signer)),
            CONTENT,
            None,
        );
        let found = rejection(verify_jws_request(
            JwsMethod::Jwsd,
            &wire.request(),
            &key(&public, "client"),
            &forgetful(),
        ));
        assert!(found.contains(reason), "{header}: {found}");
    }

    let duplicate = base.to_string().replacen('{', r#"{"htm":"GET","#, 1);
    let wire = Wire::new(
        JwsProof::Detached(forge_raw(&duplicate, &payload, &signer)),
        CONTENT,
        None,
    );
    let found = rejection(verify_jws_request(
        JwsMethod::Jwsd,
        &wire.request(),
        &key(&public, "client"),
        &forgetful(),
    ));
    assert!(found.contains("JSON object"), "{found}");
    let wire = Wire::new(
        JwsProof::Detached(forge_raw("[]", &payload, &signer)),
        CONTENT,
        None,
    );
    assert!(verify_jws_request(
        JwsMethod::Jwsd,
        &wire.request(),
        &key(&public, "client"),
        &forgetful()
    )
    .is_err());
}

/// The `kid` must name the key whenever the key or the caller names one.
#[test]
fn the_kid_must_be_the_expected_one() {
    let signer = es256();
    let public = PublicKey::for_jws(&signer.public_jwk().unwrap()).unwrap();
    let payload = digest(CONTENT);
    let mut other = jwsd_header(&signer);
    other["kid"] = json!("another-key");
    let mut absent = jwsd_header(&signer);
    absent.as_object_mut().unwrap().remove("kid");
    for header in [other, absent] {
        let wire = Wire::new(
            JwsProof::Detached(forge(&header, &payload, &signer)),
            CONTENT,
            None,
        );
        let reason = rejection(verify_jws_request(
            JwsMethod::Jwsd,
            &wire.request(),
            &key(&public, "client"),
            &forgetful(),
        ));
        assert!(reason.contains("kid"), "{reason}");
    }
    let wire = Wire::new(
        sign_jws(JwsMethod::Jwsd, &params(None), CONTENT, &signer).unwrap(),
        CONTENT,
        None,
    );
    let mut expecting = key(&public, "client");
    expecting.expectations.key_id = Some("another-key");
    let reason = rejection(verify_jws_request(
        JwsMethod::Jwsd,
        &wire.request(),
        &expecting,
        &forgetful(),
    ));
    assert!(reason.contains("kid"), "{reason}");
}

/// `ath` is required exactly when the request presents a GNAP access token,
/// and has to hash that token.
#[test]
fn ath_binds_the_presented_access_token() {
    let signer = rs256();
    let public = PublicKey::for_jws(&signer.public_jwk().unwrap()).unwrap();
    let check = |wire: &Wire| {
        verify_jws_request(
            JwsMethod::Jwsd,
            &wire.request(),
            &key(&public, "client"),
            &forgetful(),
        )
    };
    let proof = |token| sign_jws(JwsMethod::Jwsd, &params(token), CONTENT, &signer).unwrap();

    let mut stripped = Wire::new(proof(Some("token")), CONTENT, None);
    assert!(rejection(check(&stripped)).contains("ath"));
    stripped.header("Authorization", "GNAP another-token");
    assert!(rejection(check(&stripped)).contains("ath"));
    let unbound = Wire::new(proof(None), CONTENT, Some("token"));
    assert!(rejection(check(&unbound)).contains("ath"));

    let mut twice = Wire::new(proof(Some("token")), CONTENT, Some("token"));
    twice.header("Authorization", "GNAP token");
    assert!(rejection(check(&twice)).contains("more than once"));
    for field in ["Bearer token", "GNAP", "GNAP ", "GNAP to ken"] {
        let mut wire = Wire::new(proof(Some("token")), CONTENT, None);
        wire.header("Authorization", field);
        assert!(rejection(check(&wire)).contains("Authorization"), "{field}");
    }
    let mut scheme = Wire::new(proof(Some("token")), CONTENT, None);
    scheme.header("Authorization", "gnap token");
    check(&scheme).expect("the scheme is case-insensitive");
    let mut spaces = Wire::new(proof(Some("token")), CONTENT, None);
    spaces.header("Authorization", "GNAP   token");
    check(&spaces).expect("one or more spaces separate the scheme and the token");
    let mut tab = Wire::new(proof(Some("token")), CONTENT, None);
    tab.header("Authorization", "GNAP\ttoken");
    assert!(
        rejection(check(&tab)).contains("Authorization"),
        "a tab isn't a separator"
    );
}

/// Where a proof may travel, and what may travel with it.
#[test]
fn the_envelope_is_unambiguous() {
    let signer = ed25519();
    let public = PublicKey::for_jws(&signer.public_jwk().unwrap()).unwrap();
    let check = |method, wire: &Wire| {
        verify_jws_request(
            method,
            &wire.request(),
            &key(&public, "client"),
            &forgetful(),
        )
    };
    let detached = || {
        Wire::new(
            sign_jws(JwsMethod::Jwsd, &params(None), CONTENT, &signer).unwrap(),
            CONTENT,
            None,
        )
    };
    let attached = || {
        Wire::new(
            sign_jws(JwsMethod::Jws, &params(None), CONTENT, &signer).unwrap(),
            CONTENT,
            None,
        )
    };

    let unsigned = Wire::new(JwsProof::Attached(String::new()), b"", None);
    let result = check(JwsMethod::Jwsd, &unsigned);
    assert_eq!(result, Err(VerifyError::Unsigned));
    let message = result.unwrap_err().to_string();
    assert!(!message.contains("Signature-Input"), "{message}");

    let mut twice = detached();
    let value = twice.headers[0].1.clone();
    twice.header(DETACHED_JWS_HEADER, &value);
    assert!(rejection(check(JwsMethod::Jwsd, &twice)).contains("more than once"));

    for (name, value) in [("Signature-Input", "sig=()"), ("Signature", "sig=:AA==:")] {
        let mut mixed = detached();
        mixed.header(name, value);
        assert!(rejection(check(JwsMethod::Jwsd, &mixed)).contains("HTTP message signature"));
    }

    let mut both = attached();
    both.header(DETACHED_JWS_HEADER, &value);
    assert!(rejection(check(JwsMethod::Jws, &both)).contains("Detached-JWS"));
    for (types, unsigned) in [
        (&[][..], true),
        (&["application/json"][..], true),
        (&[JOSE_MEDIA_TYPE, JOSE_MEDIA_TYPE][..], false),
        (&["application/json", JOSE_MEDIA_TYPE][..], false),
    ] {
        let mut wire = attached();
        wire.without("Content-Type");
        for value in types {
            wire.header("Content-Type", value);
        }
        let result = check(JwsMethod::Jws, &wire);
        if unsigned {
            assert_eq!(result, Err(VerifyError::Unsigned), "{types:?}");
        } else {
            assert!(rejection(result).contains("Content-Type"), "{types:?}");
        }
    }
    let mut parameters = attached();
    parameters
        .without("Content-Type")
        .header("content-type", "Application/JOSE; charset=utf-8");
    check(JwsMethod::Jws, &parameters).expect("the media type ignores case and parameters");

    let mut payload = detached();
    payload.headers[0].1 = sign_jws(JwsMethod::Jws, &params(None), b"", &signer)
        .map(|proof| match proof {
            JwsProof::Detached(value) | JwsProof::Attached(value) => value,
        })
        .unwrap();
    assert!(
        rejection(check(JwsMethod::Jws, &payload)).contains("Detached-JWS"),
        "content with a detached jws"
    );
    payload.body.clear();
    check(JwsMethod::Jws, &payload).expect("a jws without content is detached");
    let mut empty = jwsd_header(&signer);
    empty["typ"] = json!("gnap-binding-jws");
    let nonempty = Wire::new(JwsProof::Detached(forge(&empty, b"x", &signer)), b"", None);
    assert!(rejection(check(JwsMethod::Jws, &nonempty)).contains("payload"));
    let hollow = Wire::new(JwsProof::Attached(forge(&empty, b"", &signer)), b"", None);
    assert!(
        check(JwsMethod::Jws, &hollow).is_err(),
        "an attached jws needs content"
    );
}

/// Malformed compact serializations are refused before any decoding work.
#[test]
fn malformed_compact_serializations_are_refused() {
    let signer = ed25519();
    let public = PublicKey::for_jws(&signer.public_jwk().unwrap()).unwrap();
    let JwsProof::Detached(good) =
        sign_jws(JwsMethod::Jwsd, &params(None), CONTENT, &signer).unwrap()
    else {
        panic!("jwsd is detached");
    };
    let segments: Vec<&str> = good.split('.').collect();
    let long_header = "e".repeat(16 * 1024);
    for compact in [
        format!("{good}.extra"),
        format!("{}.{}", segments[0], segments[1]),
        format!(".{}.{}", segments[1], segments[2]),
        format!("{}.{}.", segments[0], segments[1]),
        format!("{}=.{}.{}", segments[0], segments[1], segments[2]),
        format!(
            "{}.{}.{}",
            segments[0],
            segments[1],
            segments[2].replace('A', "+")
        ),
        format!("{long_header}.{}.{}", segments[1], segments[2]),
        format!("{}.{}.{}", segments[0], segments[1], "A".repeat(1024)),
        "x".repeat(MAX_DETACHED_JWS_BYTES + 1),
    ] {
        let wire = Wire::new(JwsProof::Detached(compact), CONTENT, None);
        assert!(verify_jws_request(
            JwsMethod::Jwsd,
            &wire.request(),
            &key(&public, "client"),
            &forgetful()
        )
        .is_err());
    }
}

/// The method of the request and its URI are compared exactly, and a URI
/// with a fragment is refused even when both sides carry it.
#[test]
fn the_method_and_uri_match_the_request() {
    let signer = es256();
    let public = PublicKey::for_jws(&signer.public_jwk().unwrap()).unwrap();
    let check = |wire: &Wire| {
        verify_jws_request(
            JwsMethod::Jwsd,
            &wire.request(),
            &key(&public, "client"),
            &forgetful(),
        )
    };
    let mut put = Wire::new(
        sign_jws(JwsMethod::Jwsd, &params(None), CONTENT, &signer).unwrap(),
        CONTENT,
        None,
    );
    put.method = "PUT".into();
    assert!(rejection(check(&put)).contains("htm"));
    let mut elsewhere = Wire::new(
        sign_jws(JwsMethod::Jwsd, &params(None), CONTENT, &signer).unwrap(),
        CONTENT,
        None,
    );
    elsewhere.uri = "https://server.example.com/gnap?x=1".into();
    assert!(rejection(check(&elsewhere)).contains("uri"));

    let fragment = format!("{URI}#part");
    let mut header = jwsd_header(&signer);
    header["uri"] = json!(fragment);
    let mut wire = Wire::new(
        JwsProof::Detached(forge(&header, &digest(CONTENT), &signer)),
        CONTENT,
        None,
    );
    wire.uri = fragment;
    assert!(rejection(check(&wire)).contains("uri"));

    let mut delete = Wire::new(
        sign_jws(
            JwsMethod::Jwsd,
            &JwsParams {
                method: "DELETE",
                ..params(None)
            },
            CONTENT,
            &signer,
        )
        .unwrap(),
        CONTENT,
        None,
    );
    delete.method = "DELETE".into();
    check(&delete).expect("a method usually without content may still have some");
}

/// A signer or verifier of an algorithm outside the JOSE profile is refused,
/// and so are a method or URI a proof can't carry.
#[test]
fn signing_refuses_what_the_profile_excludes() {
    let ps256 = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "ps256-key").unwrap();
    assert!(sign_jws(JwsMethod::Jwsd, &params(None), CONTENT, &ps256).is_err());
    let verifier = ps256.verifier();
    let rs256 = rs256();
    let wire = Wire::new(
        sign_jws(JwsMethod::Jwsd, &params(None), CONTENT, &rs256).unwrap(),
        CONTENT,
        None,
    );
    let reason = rejection(verify_jws_request(
        JwsMethod::Jwsd,
        &wire.request(),
        &key(&verifier, "client"),
        &forgetful(),
    ));
    assert!(reason.contains("alg"), "{reason}");

    let signer = ed25519();
    for bad in [
        JwsParams {
            method: "PO ST",
            ..params(None)
        },
        JwsParams {
            method: "",
            ..params(None)
        },
        JwsParams {
            target_uri: "/gnap",
            ..params(None)
        },
        JwsParams {
            target_uri: "https://server.example.com/gnap#x",
            ..params(None)
        },
    ] {
        assert!(
            sign_jws(JwsMethod::Jws, &bad, CONTENT, &signer).is_err(),
            "{bad:?}"
        );
    }
    assert!(sign_jws_rotation(JwsMethod::Jws, &params(None), b"", &signer, &es256()).is_err());
    assert!(sign_jws(JwsMethod::Jws, &params(None), b"not json", &signer).is_err());
    assert!(sign_jws_rotation(
        JwsMethod::Jws,
        &params(None),
        b"not json",
        &signer,
        &es256()
    )
    .is_err());
    sign_jws(JwsMethod::Jwsd, &params(None), b"not json", &signer).expect("jwsd signs any bytes");
}

/// A PS256 key signs a well-formed JOSE header naming PS256: the profile still
/// refuses it, since `PS256` belongs to `httpsig`.
#[test]
fn a_ps256_jws_is_refused_even_when_its_alg_names_the_key() {
    let ps256 = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "ps256-key").unwrap();
    let verifier = ps256.verifier();
    let wire = Wire::new(
        JwsProof::Detached(forge(&jwsd_header(&ps256), &digest(CONTENT), &ps256)),
        CONTENT,
        None,
    );
    let reason = rejection(verify_jws_request(
        JwsMethod::Jwsd,
        &wire.request(),
        &key(&verifier, "client"),
        &forgetful(),
    ));
    assert!(reason.contains("alg"), "{reason}");
}

/// The replay identifier includes the key's identity: the same signing input
/// accepted under another key's identity isn't a replay of the first.
#[test]
fn the_replay_identifier_is_scoped_to_the_key() {
    let signer = ed25519();
    let public = PublicKey::for_jws(&signer.public_jwk().unwrap()).unwrap();
    let wire = Wire::new(
        sign_jws(JwsMethod::Jwsd, &params(None), CONTENT, &signer).unwrap(),
        CONTENT,
        None,
    );
    let cache = ReplayCache::new(4, SKEW);
    for identity in ["one-key", "another-key"] {
        verify_jws_request(
            JwsMethod::Jwsd,
            &wire.request(),
            &key(&public, identity),
            &cache,
        )
        .unwrap_or_else(|e| panic!("{identity}: {e}"));
    }
    assert_eq!(cache.len(), 2);
}

/// In a detached rotation only the inner proof covers the content, through
/// its digest: the outer one signs the inner JWS. A changed content fails.
#[test]
fn a_detached_rotation_binds_the_content_through_the_inner_proof() {
    let (previous, replacement) = (es256(), rs256());
    let previous_key = PublicKey::for_jws(&previous.public_jwk().unwrap()).unwrap();
    let replacement_key = PublicKey::for_jws(&replacement.public_jwk().unwrap()).unwrap();
    let proof = sign_jws_rotation(
        JwsMethod::Jwsd,
        &params(None),
        CONTENT,
        &previous,
        &replacement,
    )
    .unwrap();
    let mut wire = Wire::new(proof, CONTENT, None);
    wire.body = br#"{"key":"an attacker's key"}"#.to_vec();
    let cache = ReplayCache::new(4, SKEW);
    let reason = rejection(verify_jws_rotation(
        JwsMethod::Jwsd,
        &wire.request(),
        &key(&previous_key, "old"),
        &key(&replacement_key, "new"),
        &cache,
    ));
    assert!(reason.contains("inner JWS payload"), "{reason}");
    assert!(cache.is_empty());
}

/// The access token grammar is the `token68` of `gnap_types::token::TokenValue`,
/// for the verifier as for the signer.
#[test]
fn the_access_token_grammar_is_the_one_of_token_values() {
    let signer = ed25519();
    let public = PublicKey::for_jws(&signer.public_jwk().unwrap()).unwrap();
    for token in [
        "80UPRY5NM33OMUKMKSKU",
        "a-b.c_d~e+f/g",
        "abc==",
        "=",
        "a=b",
        "a\"b",
        "a,b",
        "a:b",
        "a;b",
        "é",
        "a%20b",
    ] {
        let valid = gnap_types::token::TokenValue::new(token).is_ok();
        assert_eq!(
            sign_jws(JwsMethod::Jwsd, &params(Some(token)), CONTENT, &signer).is_ok(),
            valid,
            "signing with {token:?}"
        );
        let reference =
            sign_jws(JwsMethod::Jwsd, &params(Some("token")), CONTENT, &signer).unwrap();
        let JwsProof::Detached(compact) = reference else {
            panic!("jwsd is detached");
        };
        let mut header = jwsd_header(&signer);
        header["ath"] = json!(URL_SAFE_NO_PAD.encode(digest(token.as_bytes())));
        let forged = forge(
            &header,
            &URL_SAFE_NO_PAD
                .decode(compact.split('.').nth(1).unwrap())
                .unwrap(),
            &signer,
        );
        let wire = Wire::new(JwsProof::Detached(forged), CONTENT, Some(token));
        let accepted = verify_jws_request(
            JwsMethod::Jwsd,
            &wire.request(),
            &key(&public, "client"),
            &forgetful(),
        )
        .is_ok();
        assert_eq!(accepted, valid, "verifying with {token:?}");
    }
}

/// [`JwsKey::for_public_key`] takes the identity from the key itself, so two
/// imports of one key share their replay protection, and leaves the `kid` to
/// the key, so the JWS has to name it.
#[test]
fn a_key_built_from_a_jwk_is_identified_by_its_thumbprint() {
    let signer = es256();
    let jwk = signer.public_jwk().unwrap();
    let (first, second) = (
        PublicKey::for_jws(&jwk).unwrap(),
        PublicKey::for_jws(&jwk).unwrap(),
    );
    let wire = Wire::new(
        sign_jws(JwsMethod::Jwsd, &params(None), CONTENT, &signer).unwrap(),
        CONTENT,
        None,
    );
    let cache = ReplayCache::new(4, SKEW);
    let key = JwsKey::for_public_key(&first, NOW, SKEW);
    assert_eq!(key.identity, signer.thumbprint());
    verify_jws_request(JwsMethod::Jwsd, &wire.request(), &key, &cache).unwrap();
    let again = rejection(verify_jws_request(
        JwsMethod::Jwsd,
        &wire.request(),
        &JwsKey::for_public_key(&second, NOW, SKEW),
        &cache,
    ));
    assert!(again.contains("already used"), "{again}");

    let mut header = jwsd_header(&signer);
    header.as_object_mut().unwrap().remove("kid");
    let unnamed = Wire::new(
        JwsProof::Detached(forge(&header, &digest(CONTENT), &signer)),
        CONTENT,
        None,
    );
    let reason = rejection(verify_jws_request(
        JwsMethod::Jwsd,
        &unnamed.request(),
        &JwsKey::for_public_key(&first, NOW, SKEW),
        &forgetful(),
    ));
    assert!(reason.contains("kid"), "{reason}");
}

/// A key without identity can't scope its replay protection; one proof
/// verified under two clock tolerances is one proof; the cache doesn't
/// forget when the clock goes back; and retention saturates at the end of
/// time instead of wrapping.
#[test]
fn replay_protection_holds_at_its_edges() {
    let signer = ed25519();
    let public = PublicKey::for_jws(&signer.public_jwk().unwrap()).unwrap();
    let wire = Wire::new(
        sign_jws(JwsMethod::Jwsd, &params(None), CONTENT, &signer).unwrap(),
        CONTENT,
        None,
    );
    let reason = rejection(verify_jws_request(
        JwsMethod::Jwsd,
        &wire.request(),
        &key(&public, ""),
        &forgetful(),
    ));
    assert!(reason.contains("identity"), "{reason}");

    let cache = ReplayCache::new(4, SKEW);
    verify_jws_request(
        JwsMethod::Jwsd,
        &wire.request(),
        &key(&public, "client"),
        &cache,
    )
    .unwrap();
    let mut wider = key(&public, "client");
    wider.expectations.max_clock_skew = 2 * SKEW;
    assert!(verify_jws_request(JwsMethod::Jwsd, &wire.request(), &wider, &cache).is_err());
    let mut earlier = key(&public, "client");
    earlier.expectations.now = NOW - 1;
    assert!(verify_jws_request(JwsMethod::Jwsd, &wire.request(), &earlier, &cache).is_err());

    let end = JwsParams {
        created: u64::MAX,
        ..params(None)
    };
    let wire = Wire::new(
        sign_jws(JwsMethod::Jwsd, &end, CONTENT, &signer).unwrap(),
        CONTENT,
        None,
    );
    let ids = Mutex::new(Vec::new());
    let capture = |batch: &[ReplayId], _: u64| {
        ids.lock().unwrap().extend_from_slice(batch);
        true
    };
    let mut late = key(&public, "client");
    late.expectations.now = u64::MAX;
    verify_jws_request(JwsMethod::Jwsd, &wire.request(), &late, &capture).unwrap();
    let id = ids.into_inner().unwrap()[0];
    assert_eq!(id.created(), u64::MAX);
    let cache = ReplayCache::new(4, SKEW);
    assert!(cache.reserve(&[id], u64::MAX));
    assert!(!cache.reserve(&[id], u64::MAX), "its retention saturates");
}

/// The memory owns its window and its clock: a proof it forgot can't come
/// back under a verifier with a wider skew, nor after its clock went back.
#[test]
fn a_forgotten_proof_stays_refused() {
    const CREATED: u64 = 1_000;
    let signer = ed25519();
    let public = PublicKey::for_jws(&signer.public_jwk().unwrap()).unwrap();
    let sign = |created| {
        let params = JwsParams {
            created,
            ..params(None)
        };
        Wire::new(
            sign_jws(JwsMethod::Jwsd, &params, CONTENT, &signer).unwrap(),
            CONTENT,
            None,
        )
    };
    let at = |now, skew| JwsKey {
        verifier: &public,
        identity: "client".into(),
        expectations: Expectations {
            now,
            max_clock_skew: skew,
            key_id: None,
        },
    };
    let (proof, other) = (sign(CREATED), sign(CREATED + 2));
    let verify = |wire: &Wire, now, skew, cache: &ReplayCache| {
        verify_jws_request(JwsMethod::Jwsd, &wire.request(), &at(now, skew), cache)
    };

    let cache = ReplayCache::new(8, 1);
    verify(&proof, CREATED, 1, &cache).unwrap();
    verify(&other, CREATED + 2, 1, &cache).expect("this reservation forgets the first proof");
    let wider = rejection(verify(&proof, CREATED + 2, 300, &cache));
    assert!(wider.contains("already used"), "{wider}");

    let cache = ReplayCache::new(8, 1);
    verify(&proof, CREATED, 1, &cache).unwrap();
    verify(&other, CREATED + 2, 1, &cache).unwrap();
    let earlier = rejection(verify(&proof, CREATED, 1, &cache));
    assert!(earlier.contains("already used"), "{earlier}");
}

/// The signer applies the verifier's bounds, so it never produces a proof
/// this crate would refuse.
#[test]
fn signing_applies_the_verifier_bounds() {
    let signer = ed25519();
    let long = format!(
        "{URI}?{}",
        "q".repeat(gnap_crypto::jws::MAX_JWS_HEADER_BYTES)
    );
    let params = JwsParams {
        target_uri: &long,
        ..params(None)
    };
    for method in [JwsMethod::Jws, JwsMethod::Jwsd] {
        let error = sign_jws(method, &params, CONTENT, &signer).unwrap_err();
        assert!(error.to_string().contains("too long"), "{error}");
    }
    let large = format!(
        "[{}\"\"]",
        "\"0123456789abcdef\",".repeat(gnap_crypto::jws::MAX_ATTACHED_JWS_BYTES / 16)
    );
    let error = sign_jws(
        JwsMethod::Jws,
        &self::params(None),
        large.as_bytes(),
        &signer,
    )
    .unwrap_err();
    assert!(error.to_string().contains("too long"), "{error}");
    sign_jws(
        JwsMethod::Jwsd,
        &self::params(None),
        large.as_bytes(),
        &signer,
    )
    .expect("a detached proof signs only the digest");
}

/// The verifier holds `htm` and `uri` to the grammar the signer applies,
/// even when the request carries the same malformed value.
#[test]
fn the_verifier_applies_the_signer_grammars() {
    let signer = ed25519();
    let public = PublicKey::for_jws(&signer.public_jwk().unwrap()).unwrap();
    for method in ["PO ST", "", "MÉTHOD"] {
        let mut header = jwsd_header(&signer);
        header["htm"] = json!(method);
        let mut wire = Wire::new(
            JwsProof::Detached(forge(&header, &digest(CONTENT), &signer)),
            CONTENT,
            None,
        );
        wire.method = method.into();
        let reason = rejection(verify_jws_request(
            JwsMethod::Jwsd,
            &wire.request(),
            &key(&public, "client"),
            &forgetful(),
        ));
        assert!(reason.contains("htm"), "{method:?}: {reason}");
        let params = JwsParams {
            method,
            ..params(None)
        };
        assert!(
            sign_jws(JwsMethod::Jwsd, &params, CONTENT, &signer).is_err(),
            "{method:?}"
        );
    }
    for uri in [
        "https://server.example.com/%ZZ",
        "https://[broken/gnap",
        "https://server.example.com/{bad}",
        "https://server.example.com/gnap#part",
    ] {
        let mut header = jwsd_header(&signer);
        header["uri"] = json!(uri);
        let mut wire = Wire::new(
            JwsProof::Detached(forge(&header, &digest(CONTENT), &signer)),
            CONTENT,
            None,
        );
        wire.uri = uri.into();
        let reason = rejection(verify_jws_request(
            JwsMethod::Jwsd,
            &wire.request(),
            &key(&public, "client"),
            &forgetful(),
        ));
        assert!(reason.contains("uri"), "{uri}: {reason}");
        let params = JwsParams {
            target_uri: uri,
            ..params(None)
        };
        assert!(
            sign_jws(JwsMethod::Jwsd, &params, CONTENT, &signer).is_err(),
            "{uri}"
        );
    }
}

/// The signer refuses a key identifier its verifier would refuse, and the
/// `Debug` output of the parameters hides the access token.
#[test]
fn the_signer_refuses_what_its_verifier_refuses() {
    let long = Ed25519Signer::from_pkcs8_pem(ED25519_PKCS8, "k".repeat(1025)).unwrap();
    assert!(sign_jws(JwsMethod::Jwsd, &params(None), CONTENT, &long).is_err());
    let debug = format!("{:?}", params(Some("synthetic-secret-token")));
    assert!(!debug.contains("synthetic-secret-token"), "{debug}");
    assert!(debug.contains("<redacted>"), "{debug}");
}

/// A signer without identifier signs without `kid`, for a key that isn't
/// presented as a JWK: a verifier that expects no `kid` accepts the proof.
#[test]
fn a_signer_without_identifier_signs_without_kid() {
    let signer = Ed25519Signer::from_pkcs8_pem(ED25519_PKCS8, "").unwrap();
    let JwsProof::Detached(compact) =
        sign_jws(JwsMethod::Jwsd, &params(None), CONTENT, &signer).unwrap()
    else {
        panic!("jwsd is detached");
    };
    let header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(compact.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert!(header.get("kid").is_none(), "{header}");
    let verifier =
        gnap_crypto::Ed25519Verifier::from_public_key_pem(include_str!("rfc9421-b14.spki.pem"))
            .unwrap();
    let wire = Wire::new(JwsProof::Detached(compact), CONTENT, None);
    verify_jws_request(
        JwsMethod::Jwsd,
        &wire.request(),
        &key(&verifier, "pem-key"),
        &forgetful(),
    )
    .expect("a verifier without kid expectation accepts it");
}

/// The unverified payload is the attached JWS's payload as it travels, and
/// nothing else: no detached proof, no envelope the verifier refuses, and no
/// second layer.
#[test]
fn the_unverified_payload_reads_one_attached_jws() {
    let signer = ed25519();
    let attached = Wire::new(
        sign_jws(JwsMethod::Jws, &params(None), CONTENT, &signer).unwrap(),
        CONTENT,
        None,
    );
    assert_eq!(
        unverified_attached_payload(&attached.request()).unwrap(),
        CONTENT
    );
    let bodyless = Wire::new(
        sign_jws(JwsMethod::Jws, &params(None), b"", &signer).unwrap(),
        b"",
        None,
    );
    assert_eq!(
        unverified_attached_payload(&bodyless.request()),
        Err(VerifyError::Unsigned),
        "a jws without content is detached"
    );
    let detached = Wire::new(
        sign_jws(JwsMethod::Jwsd, &params(None), CONTENT, &signer).unwrap(),
        CONTENT,
        None,
    );
    assert!(unverified_attached_payload(&detached.request()).is_err());
    let mut mixed = attached;
    mixed.header("Signature-Input", "sig=()");
    assert!(matches!(
        unverified_attached_payload(&mixed.request()),
        Err(VerifyError::Rejected(_))
    ));
    let rotation = Wire::new(
        sign_jws_rotation(JwsMethod::Jws, &params(None), CONTENT, &signer, &es256()).unwrap(),
        CONTENT,
        None,
    );
    let outer = unverified_attached_payload(&rotation.request()).unwrap();
    assert_eq!(
        outer.split(|b| *b == b'.').count(),
        3,
        "only the outer layer"
    );
}

/// The unverified content of an attached rotation is the inner payload, two
/// layers down, and an ordinary attached JWS isn't one.
#[test]
fn the_unverified_rotation_content_reads_two_layers() {
    let rotation = Wire::new(
        sign_jws_rotation(JwsMethod::Jws, &params(None), CONTENT, &ed25519(), &es256()).unwrap(),
        CONTENT,
        None,
    );
    assert_eq!(
        unverified_rotation_content(&rotation.request()).unwrap(),
        CONTENT
    );
    let ordinary = Wire::new(
        sign_jws(JwsMethod::Jws, &params(None), CONTENT, &ed25519()).unwrap(),
        CONTENT,
        None,
    );
    assert!(matches!(
        unverified_rotation_content(&ordinary.request()),
        Err(VerifyError::Rejected(_))
    ));
}
