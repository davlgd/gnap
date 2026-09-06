//! Binding a new key to a held token (RFC 9635 §6.1.1, §7.3.1.1), from the
//! client side.
//!
//! The AS answers from a script; what the client sends is checked with the
//! paired-signature verifier of `gnap-crypto`, so the request the session
//! builds is the request a verifier accepts, and only with both proofs.

use gnap_client::{ClientError, HttpRequest, HttpResponse, HttpTransport, Session, Step};
use gnap_crypto::proof::{Signer, Verifier};
use gnap_crypto::ps256::{Ps256Signer, Ps256Verifier};
use gnap_crypto::{
    verify_key_rotation, verify_request_with_policy, Expectations, RotationProof, SignedRequest,
};
use gnap_types::key::Key;
use gnap_types::message::{ContinueRequest, GrantRequest};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::Mutex;

const RSA_PKCS1: &str = include_str!("../../gnap-crypto/tests/rfc9421-b12.pkcs1.pem");
const ENDPOINT: &str = "https://server.example.com/gnap";
const MANAGE_URI: &str = "https://as.example/token/PRY5NM33O";
const MANAGE_TOKEN: &str = "B8CDFONP21-4TB8N6.BW7ONM";
const ISSUED: &str = "OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0";
const REBOUND: &str = "FP6A8H6HY37MH13CK76LBZ6Y1UADG6VEUPEER5H2";

#[path = "key_rotation/owned.rs"]
mod owned;

struct FakeAs {
    replies: RefCell<Vec<HttpResponse>>,
    seen: RefCell<Vec<HttpRequest>>,
}

impl FakeAs {
    fn with(bodies: Vec<&str>) -> Self {
        Self {
            replies: RefCell::new(
                bodies
                    .into_iter()
                    .map(|b| HttpResponse {
                        status: if b.is_empty() { 204 } else { 200 },
                        headers: vec![("Cache-Control".into(), "no-store".into())],
                        body: b.as_bytes().to_vec(),
                    })
                    .rev()
                    .collect(),
            ),
            seen: RefCell::new(Vec::new()),
        }
    }
    fn sent(&self) -> usize {
        self.seen.borrow().len()
    }
    /// Queues a reply with an arbitrary status and headers.
    fn push(&self, status: u16, headers: Vec<(&str, &str)>, body: &str) {
        self.replies.borrow_mut().insert(
            0,
            HttpResponse {
                status,
                headers: headers
                    .into_iter()
                    .map(|(n, v)| (n.to_owned(), v.to_owned()))
                    .collect(),
                body: body.as_bytes().to_vec(),
            },
        );
    }
    fn last(&self) -> HttpRequest {
        self.seen.borrow().last().cloned().unwrap()
    }
}

impl HttpTransport for FakeAs {
    type Error = String;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        self.seen.borrow_mut().push(request);
        self.replies
            .borrow_mut()
            .pop()
            .ok_or_else(|| "the fake AS ran out of scripted replies".to_owned())
    }
}

/// Replay memory shared by both nonces, as the AS side would share it.
#[derive(Default)]
struct Memory(Mutex<HashSet<String>>);

impl gnap_crypto::RotationNonceMemory for Memory {
    fn remember_pair(&self, previous: Option<&str>, replacement: Option<&str>, _: u64) -> bool {
        let mut seen = self.0.lock().unwrap();
        let both: Vec<&str> = [previous, replacement].into_iter().flatten().collect();
        if both.iter().any(|nonce| seen.contains(*nonce)) {
            return false;
        }
        seen.extend(both.into_iter().map(str::to_owned));
        true
    }
}

fn signer() -> Ps256Signer {
    Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap()
}

fn replacement() -> Ps256Signer {
    Ps256Signer::generate(2048, "rotated-1").unwrap()
}

fn presented(key: &Ps256Signer) -> Key {
    serde_json::from_value(json!({"proof": "httpsig", "jwk": key.public_jwk().unwrap()})).unwrap()
}

fn request() -> GrantRequest {
    serde_json::from_str(
        r#"{"client":"client-541-ab","access_token":{"access":["dolphin-metadata"]}}"#,
    )
    .unwrap()
}

/// A token with a management API, as the AS issues it.
fn managed(with_continue: bool) -> String {
    let token = json!({
        "value": ISSUED, "access": ["dolphin-metadata"], "expires_in": 100,
        "manage": {"uri": MANAGE_URI, "access_token": {"value": MANAGE_TOKEN}}
    });
    let mut response = json!({"access_token": token});
    if with_continue {
        response["continue"] = json!({"uri": "https://as.example/continue",
            "access_token": {"value": "80UPRY5NM33OMUKMKSKU"}, "wait": 0});
    }
    response.to_string()
}

/// A rotated token object, with the given `key` member (or none).
fn rebound_token(value: &str, key: Option<Value>, handle: &str) -> Value {
    let mut token = json!({
        "value": value, "access": ["dolphin-metadata"], "expires_in": 100,
        "manage": {"uri": format!("https://as.example/token/{handle}"),
                   "access_token": {"value": format!("manage-{handle}")}}
    });
    if let Some(key) = key {
        token["key"] = key;
    }
    token
}

/// The answer to a rotation, with the given `key` member (or none).
fn rebound(value: &str, key: Option<Value>, handle: &str) -> String {
    json!({"access_token": rebound_token(value, key, handle)}).to_string()
}

const fn expectations(now: u64, kid: &'static str) -> Expectations<'static> {
    Expectations {
        now,
        max_clock_skew: 30,
        key_id: Some(kid),
    }
}

fn view(request: &HttpRequest) -> SignedRequest<'_> {
    SignedRequest {
        method: &request.method,
        target_uri: &request.url,
        headers: &request.headers,
        body: request.body.as_deref(),
    }
}

/// Whether the request carries one ordinary GNAP signature made by `key`.
fn signed_by(request: &HttpRequest, verifier: &dyn Verifier, kid: &'static str, now: u64) -> bool {
    verify_request_with_policy(
        &view(request),
        verifier,
        &expectations(now, kid),
        &|_: &str, _: u64| true,
        &|params| params.nonce.is_some(),
    )
    .is_ok()
}

fn verify_pair(
    request: &HttpRequest,
    new_verifier: &dyn Verifier,
    now: u64,
    memory: &Memory,
) -> Result<gnap_crypto::AcceptedRotation, gnap_crypto::VerifyError> {
    verify_key_rotation(
        &view(request),
        &RotationProof {
            verifier: &signer().verifier(),
            expectations: expectations(now, "gnap-demo"),
            policy: &|params| params.nonce.is_some(),
        },
        &RotationProof {
            verifier: new_verifier,
            expectations: expectations(now, "rotated-1"),
            policy: &|params| params.nonce.is_some(),
        },
        memory,
    )
}

/// GNAP-9635-§6.1.1-M03 — "The client instance MUST prove possession of both
/// the currently bound key and the newly requested key simultaneously in the
/// rotation request. Specifically, the signature from the previous key MUST
/// cover the value or reference of the new key, and the signature of the new
/// key MUST cover the signature value of the old key."
///
/// GNAP-9635-§7.3.1.1 — the second signature's "covered components MUST
/// include the Signature and Signature-Input values from the signature
/// generated with the old key" and "The tag value MUST be gnap-rotate".
#[test]
fn a_key_rotation_request_carries_two_linked_proofs_the_verifier_accepts() {
    let sk = signer();
    let new = replacement();
    let new_verifier = Ps256Verifier::from_public_jwk(&new.public_jwk().unwrap()).unwrap();
    let key = presented(&new);
    let key_json = serde_json::to_value(&key).unwrap();
    let as_ = FakeAs::with(vec![
        &managed(false),
        &rebound(REBOUND, Some(key_json.clone()), "R2"),
        &rebound("AGAIN-4TB8N6.BW7ONM", Some(key_json.clone()), "R3"),
        "",
    ]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request(), 1_000).unwrap();
    assert_eq!(s.signer_for(None).unwrap().key_id(), "gnap-demo");

    let token = s.rotate_key(None, &new, &key, 1_050).unwrap();
    assert_eq!(token.value.as_str(), REBOUND);
    assert_eq!(token.key.as_ref(), Some(&key));
    assert_eq!(s.usable_tokens(1_050).unwrap()[0].value.as_str(), REBOUND);
    assert_eq!(s.signer_for(None).unwrap().key_id(), "rotated-1");

    // What left the client: the new key in the body, the management
    // credential in Authorization, a digest, and two signatures the paired
    // verifier accepts, under the old key's kid and the new key's kid.
    let sent = as_.seen.borrow()[1].clone();
    assert_eq!(sent.method, "POST");
    assert_eq!(sent.url, MANAGE_URI);
    assert_eq!(
        serde_json::from_slice::<Value>(sent.body.as_deref().unwrap()).unwrap(),
        json!({"key": key_json})
    );
    assert_eq!(
        sent.header_value("Authorization"),
        Some(format!("GNAP {MANAGE_TOKEN}").as_str())
    );
    assert!(sent.header_value("Content-Digest").is_some());
    let memory = Memory::default();
    let accepted = verify_pair(&sent, &new_verifier, 1_050, &memory).unwrap();
    assert_eq!(accepted.previous.label, "previous");
    assert_eq!(accepted.replacement.label, "replacement");
    assert_ne!(
        accepted.previous.params.nonce,
        accepted.replacement.params.nonce
    );
    assert_eq!(memory.0.lock().unwrap().len(), 2);
    // The same request again is a replay of both nonces.
    assert!(verify_pair(&sent, &new_verifier, 1_050, &memory).is_err());

    // Without either proof the link is gone, whichever signature remains.
    for dropped in ["previous=", "replacement="] {
        let mut stripped = sent.clone();
        stripped
            .headers
            .retain(|(_, value)| !value.starts_with(dropped));
        assert!(
            verify_pair(&stripped, &new_verifier, 1_050, &Memory::default()).is_err(),
            "{dropped}"
        );
    }
    // The old proof alone is an ordinary GNAP signature: what makes the
    // request a rotation is the pair, which the verifier requires.
    assert!(signed_by(&sent, &signer().verifier(), "gnap-demo", 1_050));

    // From now on the token's management is signed with the new key, through
    // a value rotation that keeps the rotated signer, then a revocation.
    let again = s.rotate_token(None, 1_100).unwrap();
    assert_eq!(again.value.as_str(), "AGAIN-4TB8N6.BW7ONM");
    let sent = as_.last();
    assert!(signed_by(&sent, &new_verifier, "rotated-1", 1_100));
    assert!(!signed_by(&sent, &signer().verifier(), "gnap-demo", 1_100));
    assert_eq!(s.signer_for(None).unwrap().key_id(), "rotated-1");
    s.revoke_token(None, 1_150).unwrap();
    assert!(signed_by(&as_.last(), &new_verifier, "rotated-1", 1_150));
    assert!(s.signer_for(None).is_err(), "no token is held any more");
}

/// GNAP-9635-§6.1.1 — "keys passed by value are always public keys"; "The
/// proofing method and parameters for the new key MUST be the same as those
/// established for the previous key". GNAP-9635-§7.3.1 — a JWK's `kid` is the
/// `keyid`. This session refuses, before anything leaves, what it cannot
/// present under those rules.
#[test]
fn keys_this_session_cannot_present_are_refused_before_anything_leaves() {
    let sk = signer();
    let new = replacement();
    let jwk = new.public_jwk().unwrap();
    let mut private = jwk.clone();
    private.insert("d".into(), json!("AQAB"));
    let mut other_kid = jwk.clone();
    other_kid.insert("kid".into(), json!("someone-else"));
    let mut symmetric = jwk.clone();
    symmetric.insert("kty".into(), json!("oct"));
    let cases: Vec<(Value, &str)> = vec![
        (json!("a-key-reference"), "by value only"),
        (json!({"proof": "httpsig", "jwk": private}), "private"),
        (json!({"proof": "httpsig", "jwk": other_kid}), "kid"),
        (json!({"proof": "mtls", "jwk": jwk}), "httpsig"),
        (
            json!({"proof": {"method": "httpsig", "alg": "rsa-pss-sha512"}, "jwk": jwk}),
            "httpsig",
        ),
        (
            json!({"proof": {"method": "httpsig", "x-future": true}, "jwk": jwk}),
            "httpsig",
        ),
        (
            json!({"proof": "httpsig", "cert": "MIIC..."}),
            "certificate",
        ),
        (json!({"proof": "httpsig", "jwk": symmetric}), "symmetric"),
    ];
    for (key, expected) in cases {
        let key: Key = serde_json::from_value(key).unwrap();
        let as_ = FakeAs::with(vec![&managed(false)]);
        let mut s = Session::new(&as_, &sk, ENDPOINT);
        s.start(&request(), 1_000).unwrap();
        let e = s.rotate_key(None, &new, &key, 1_050).unwrap_err();
        assert!(matches!(e, ClientError::Usage(_)), "{e}");
        assert!(
            e.to_string().to_lowercase().contains(expected),
            "{expected}: {e}"
        );
        assert_eq!(as_.sent(), 1, "nothing left the client");
        assert_eq!(s.signer_for(None).unwrap().key_id(), "gnap-demo");
    }

    // The same `kid` on another key: the JWK must verify the new signer.
    let impostor = Ps256Signer::generate(2048, "rotated-1").unwrap();
    assert_eq!(impostor.key_id(), new.key_id());
    let as_ = FakeAs::with(vec![&managed(false)]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request(), 1_000).unwrap();
    let e = s
        .rotate_key(None, &new, &presented(&impostor), 1_050)
        .unwrap_err();
    assert!(matches!(e, ClientError::Usage(_)), "{e}");
    assert!(e.to_string().contains("does not verify"), "{e}");
    assert_eq!(as_.sent(), 1);

    // A token without a management API cannot be rotated at all.
    let as_ = FakeAs::with(vec![
        r#"{"access_token":{"value":"OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0","access":["dolphin-metadata"]}}"#,
    ]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request(), 1_000).unwrap();
    assert_eq!(s.signer_for(None).unwrap().key_id(), sk.key_id());
    let e = s
        .rotate_key(None, &new, &presented(&new), 1_050)
        .unwrap_err();
    assert!(e.to_string().contains("`manage`"), "{e}");
    assert_eq!(as_.sent(), 1);
}

#[test]
fn resource_signer_selection_does_not_require_a_management_api() {
    let sk = signer();
    let new = replacement();
    let key = presented(&new);
    let lot = json!({"access_token": [
        {"label": "documents", "value": ISSUED, "access": ["documents:read"],
         "manage": {"uri": MANAGE_URI, "access_token": {"value": MANAGE_TOKEN}}},
        {"label": "reports", "value": "reports-unmanaged", "access": ["reports:read"]}
    ]});
    let query: GrantRequest = serde_json::from_value(json!({
        "client": "client-541-ab", "access_token": [
            {"label": "documents", "access": ["documents:read"]},
            {"label": "reports", "access": ["reports:read"]}
        ]
    }))
    .unwrap();
    let mut changed = rebound_token(REBOUND, Some(serde_json::to_value(&key).unwrap()), "D2");
    changed["access"] = json!(["documents:read"]);
    let as_ = FakeAs::with(vec![
        &lot.to_string(),
        &json!({"access_token": changed}).to_string(),
    ]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&query, 1_000).unwrap();
    assert!(s.signer_for(None).is_err());
    assert!(s.signer_for(Some("missing")).is_err());
    assert_eq!(s.signer_for(Some("reports")).unwrap().key_id(), sk.key_id());
    s.rotate_key(Some("documents"), &new, &key, 1_010).unwrap();
    assert_eq!(
        s.signer_for(Some("documents")).unwrap().key_id(),
        new.key_id()
    );
    assert_eq!(s.signer_for(Some("reports")).unwrap().key_id(), sk.key_id());
    let before = as_.sent();
    let refused = s
        .rotate_key(Some("reports"), &new, &key, 1_020)
        .unwrap_err();
    assert!(matches!(refused, ClientError::Usage(_)));
    assert!(refused.to_string().contains("`manage`"));
    assert_eq!(as_.sent(), before);
}

/// GNAP-9635-§3.2.1 — `key` is "The key that the token is bound to, if
/// different from the client instance's presented key"; omitted, it means the
/// key of the grant request, not the key of this body. GNAP-9635-§6.1 — on an
/// error "the client instance MUST consider the access token to not have
/// changed its state."
#[test]
fn an_answer_that_does_not_name_the_new_key_leaves_everything_unchanged() {
    let sk = signer();
    let new = replacement();
    let key = presented(&new);
    let old_key = serde_json::to_value(presented(&sk)).unwrap();
    let cases: Vec<(String, &str)> = vec![
        (
            rebound(REBOUND, None, "R2"),
            "does not name the presented key",
        ),
        (
            rebound(REBOUND, Some(old_key), "R2"),
            "does not name the presented key",
        ),
        (
            {
                let mut labelled =
                    rebound_token(REBOUND, Some(serde_json::to_value(&key).unwrap()), "R2");
                labelled["label"] = json!("only");
                json!({"access_token": [labelled]}).to_string()
            },
            "several access tokens",
        ),
        (
            r#"{"error":{"code":"invalid_rotation"}}"#.to_owned(),
            "invalid_rotation",
        ),
        (
            r#"{"error":"key_rotation_not_supported"}"#.to_owned(),
            "key_rotation_not_supported",
        ),
    ];
    for (body, expected) in cases {
        let as_ = FakeAs::with(vec![&managed(false), &body, &rebound("V2", None, "V")]);
        let mut s = Session::new(&as_, &sk, ENDPOINT);
        s.start(&request(), 1_000).unwrap();
        let before = s.usable_tokens(1_000).unwrap()[0].clone();
        let e = s.rotate_key(None, &new, &key, 1_050).unwrap_err();
        assert!(
            matches!(e, ClientError::Protocol(_) | ClientError::Server(_)),
            "{e}"
        );
        assert!(e.to_string().contains(expected), "{expected}: {e}");
        assert_eq!(s.usable_tokens(1_050).unwrap()[0], &before);
        assert_eq!(s.signer_for(None).unwrap().key_id(), "gnap-demo");
        // The next management call is still made with the session's key.
        s.rotate_token(None, 1_100).unwrap();
        assert!(signed_by(
            &as_.last(),
            &signer().verifier(),
            "gnap-demo",
            1_100
        ));
    }
}

/// A newly issued lot is bound to the grant request's key (§3.2.1), whatever
/// values it reuses: a rotated key never carries over to it. A pending or
/// refused change, and any error, leave the rotated key in place.
#[test]
fn a_new_lot_resets_rotated_signers_even_when_a_value_repeats() {
    let sk = signer();
    let new = replacement();
    let key = presented(&new);
    let key_json = serde_json::to_value(&key).unwrap();
    // A pending answer to the change, then an approved lot reusing the very
    // value of the rebound token, with no `key`: bound to the session's key.
    let pending = r#"{
      "interact": {"redirect": "https://as.example/i/4CF492ML"},
      "continue": {"uri": "https://as.example/continue",
                   "access_token": {"value": "NEXT"}, "wait": 0}
    }"#;
    let reissued = format!(
        r#"{{"access_token":{{"value":"{REBOUND}","access":["dolphin-metadata"],"expires_in":100,
            "manage":{{"uri":"https://as.example/token/R9","access_token":{{"value":"manage-R9"}}}}}},
            "continue":{{"uri":"https://as.example/continue","access_token":{{"value":"NEXT2"}},"wait":0}}}}"#
    );
    let as_ = FakeAs::with(vec![
        &managed(true),
        &rebound(REBOUND, Some(key_json), "R2"),
        r#"{"error":{"code":"invalid_request"},
            "continue":{"uri":"https://as.example/continue",
                        "access_token":{"value":"NEXT0"},"wait":0}}"#,
        pending,
        &reissued,
    ]);
    let mut s = Session::new(&as_, &sk, ENDPOINT).supporting(&["redirect"]);
    let mut opening = request();
    opening.interact = serde_json::from_value(json!({"start": ["redirect"], "finish": {
        "method": "redirect", "uri": "https://client.example.net/cb", "nonce": "VJLO6A4CATR0KRO"}}))
    .unwrap();
    s.start(&opening, 1_000).unwrap();
    s.rotate_key(None, &new, &key, 1_010).unwrap();
    assert_eq!(s.signer_for(None).unwrap().key_id(), "rotated-1");

    let changes = ContinueRequest {
        access_token: request().access_token,
        interact: opening.interact.clone(),
        ..Default::default()
    };
    // A refused change: the rotated key stays.
    let step = s.modify_grant(&changes, 1_020).unwrap();
    assert!(matches!(step, Step::Recoverable(_)), "{step:?}");
    assert_eq!(s.signer_for(None).unwrap().key_id(), "rotated-1");
    // A change that needs the resource owner: no new lot, the key stays.
    let step = s.modify_grant(&changes, 1_030).unwrap();
    assert!(matches!(step, Step::Pending(_)), "{step:?}");
    assert_eq!(s.signer_for(None).unwrap().key_id(), "rotated-1");
    // The approved lot reuses the value but names no key: it is the grant
    // request's key again, so the rotated signer must not be reused.
    let step = s.continue_grant(1_040).unwrap();
    assert!(matches!(step, Step::Approved(_)), "{step:?}");
    assert_eq!(s.usable_tokens(1_040).unwrap()[0].value.as_str(), REBOUND);
    assert_eq!(s.signer_for(None).unwrap().key_id(), "gnap-demo");
}

/// GNAP-9635-§6.1.1 — "an attempt to rotate the key of a bearer token (which
/// has no key), MUST result in an invalid_rotation error code returned from
/// the AS". This session has nothing to send for one.
#[test]
fn a_bearer_token_is_refused_before_anything_leaves() {
    let sk = signer();
    let new = replacement();
    let bearer = json!({"access_token": {
        "value": ISSUED, "access": ["dolphin-metadata"], "flags": ["bearer"],
        "manage": {"uri": MANAGE_URI, "access_token": {"value": MANAGE_TOKEN}}
    }})
    .to_string();
    let mut rotated_bearer = rebound_token(REBOUND, None, "bearer2");
    rotated_bearer["flags"] = json!(["bearer"]);
    let as_ = FakeAs::with(vec![
        &bearer,
        &json!({"access_token": rotated_bearer}).to_string(),
        "",
    ]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request(), 1_000).unwrap();
    assert!(matches!(s.signer_for(None), Err(ClientError::Usage(_))));
    let e = s
        .rotate_key(None, &new, &presented(&new), 1_050)
        .unwrap_err();
    assert!(matches!(e, ClientError::Usage(_)), "{e}");
    assert!(e.to_string().contains("bearer"), "{e}");
    assert_eq!(as_.sent(), 1);
    // Resource presentation is bearer, but management proves the client key.
    s.rotate_token(None, 1_050).unwrap();
    assert!(signed_by(&as_.last(), &sk.verifier(), "gnap-demo", 1_050));
    s.revoke_token(None, 1_051).unwrap();
    assert!(signed_by(&as_.last(), &sk.verifier(), "gnap-demo", 1_051));
}

struct CountSignatures<'a> {
    signer: &'a Ps256Signer,
    calls: std::cell::Cell<usize>,
}
impl Signer for CountSignatures<'_> {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, gnap_crypto::ProofError> {
        self.calls.set(self.calls.get() + 1);
        self.signer.sign(data)
    }
    fn key_id(&self) -> &str {
        self.signer.key_id()
    }
    fn algorithm(&self) -> &'static str {
        self.signer.algorithm()
    }
}

#[test]
fn unknown_explicit_bindings_are_not_signed_or_sent_by_guessing() {
    let original = signer();
    let other = Ps256Signer::generate(2048, original.key_id()).unwrap();
    let new = replacement();
    let sk = CountSignatures {
        signer: &original,
        calls: std::cell::Cell::new(0),
    };
    let replacement = CountSignatures {
        signer: &new,
        calls: std::cell::Cell::new(0),
    };
    for key in [
        presented(&original),
        presented(&other),
        serde_json::from_value(json!("external-key")).unwrap(),
    ] {
        let body = json!({"access_token": {
            "value": ISSUED, "access": ["dolphin-metadata"], "key": key,
            "manage": {"uri": MANAGE_URI, "access_token": {"value": MANAGE_TOKEN}}
        }})
        .to_string();
        let as_ = FakeAs::with(vec![&body]);
        let mut s = Session::new(&as_, &sk, ENDPOINT);
        s.start(&request(), 1_000).unwrap();
        let signatures = sk.calls.get();
        let before = serde_json::to_value(s.usable_tokens(1_000).unwrap()).unwrap();
        assert!(matches!(s.signer_for(None), Err(ClientError::Usage(_))));
        assert!(matches!(
            s.rotate_key(None, &replacement, &presented(&new), 1_001),
            Err(ClientError::Usage(_))
        ));
        assert!(matches!(
            s.rotate_token(None, 1_001),
            Err(ClientError::Usage(_))
        ));
        assert!(matches!(
            s.revoke_token(None, 1_001),
            Err(ClientError::Usage(_))
        ));
        assert_eq!(sk.calls.get(), signatures);
        assert_eq!(replacement.calls.get(), 0);
        assert_eq!(as_.sent(), 1);
        assert_eq!(
            serde_json::to_value(s.usable_tokens(1_001).unwrap()).unwrap(),
            before
        );
    }
}

/// The session tells tokens, and their signers, apart by value. An answer
/// that reuses a sibling's value is refused, so a rotated sibling keeps its
/// own signer (§3.2.2: "each access token is expected to have a unique value").
#[test]
fn a_rotated_value_that_repeats_a_sibling_is_refused_and_both_keep_their_signers() {
    let sk = signer();
    let new = replacement();
    let key = presented(&new);
    let key_json = serde_json::to_value(&key).unwrap();
    let lot = json!({"access_token": [
        {"label": "documents", "value": ISSUED, "access": ["documents:read"], "expires_in": 100,
         "manage": {"uri": "https://as.example/token/D", "access_token": {"value": "manage-D"}}},
        {"label": "reports", "value": "REPORTS-4TB8N6.BW7ONM", "access": ["reports:read"],
         "expires_in": 100,
         "manage": {"uri": "https://as.example/token/R", "access_token": {"value": "manage-R"}}}
    ]})
    .to_string();
    let request: GrantRequest = serde_json::from_str(
        r#"{"client":"client-541-ab",
            "access_token":[{"label":"documents","access":["documents:read"]},
                            {"label":"reports","access":["reports:read"]}]}"#,
    )
    .unwrap();
    let mut rotated_documents = rebound_token(REBOUND, Some(key_json), "D2");
    rotated_documents["access"] = json!(["documents:read"]);
    // The reports rotation answers with the documents token's new value.
    let mut clashing = rebound_token(REBOUND, None, "R2");
    clashing["access"] = json!(["reports:read"]);
    let as_ = FakeAs::with(vec![
        &lot,
        &json!({"access_token": rotated_documents}).to_string(),
        &json!({"access_token": clashing}).to_string(),
    ]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request, 1_000).unwrap();
    s.rotate_key(Some("documents"), &new, &key, 1_010).unwrap();
    assert_eq!(
        s.signer_for(Some("documents")).unwrap().key_id(),
        "rotated-1"
    );
    assert_eq!(s.signer_for(Some("reports")).unwrap().key_id(), "gnap-demo");

    let e = s.rotate_token(Some("reports"), 1_020).unwrap_err();
    assert!(matches!(e, ClientError::Protocol(_)), "{e}");
    assert!(
        e.to_string().contains("repeats the value of another token"),
        "{e}"
    );
    let held = s.usable_tokens(1_020).unwrap();
    assert_eq!(held[0].value.as_str(), REBOUND);
    assert_eq!(held[1].value.as_str(), "REPORTS-4TB8N6.BW7ONM");
    assert_eq!(
        s.signer_for(Some("documents")).unwrap().key_id(),
        "rotated-1"
    );
    assert_eq!(s.signer_for(Some("reports")).unwrap().key_id(), "gnap-demo");
}

/// An HTTP answer that is not a usable GNAP message says nothing about the
/// token: a non-success status, a foreign media type, a transport failure or
/// unreadable content leave the token and its key exactly as they were, for
/// a key rotation and for a value rotation alike. A GNAP error keeps its
/// meaning whatever status carries it (§3.6).
#[test]
fn unusable_answers_leave_the_token_and_its_key_alone() {
    let sk = signer();
    let new = replacement();
    let key = presented(&new);
    let key_json = serde_json::to_value(&key).unwrap();
    let complete = rebound(REBOUND, Some(key_json.clone()), "R2");
    let no_store = ("Cache-Control", "no-store");

    // A complete, valid-looking body under a failure status, or under a
    // media type that is not JSON, is not adopted.
    for (status, headers, body, expected) in [
        (503, vec![no_store], complete.as_str(), "no GNAP error"),
        (500, vec![no_store], complete.as_str(), "no GNAP error"),
        (
            200,
            vec![no_store, ("Content-Type", "text/html")],
            complete.as_str(),
            "Content-Type",
        ),
        (
            200,
            vec![
                no_store,
                ("Content-Type", "application/json"),
                ("Content-Type", "application/json"),
            ],
            complete.as_str(),
            "Content-Type",
        ),
        (204, vec![no_store], "", "204"),
        (200, vec![no_store], "{not json", "parsing"),
    ] {
        let as_ = FakeAs::with(vec![&managed(false)]);
        as_.push(status, headers, body);
        let mut s = Session::new(&as_, &sk, ENDPOINT);
        s.start(&request(), 1_000).unwrap();
        let before = s.usable_tokens(1_000).unwrap()[0].clone();
        let e = s.rotate_key(None, &new, &key, 1_050).unwrap_err();
        assert!(
            matches!(e, ClientError::Protocol(_) | ClientError::Parse(_)),
            "{status}: {e}"
        );
        assert!(e.to_string().contains(expected), "{status}: {e}");
        assert_eq!(s.usable_tokens(1_050).unwrap()[0], &before);
        assert_eq!(s.signer_for(None).unwrap().key_id(), "gnap-demo");
        assert_eq!(as_.sent(), 2, "the request left, its answer was refused");
    }

    // A GNAP error carried by a failure status is still the AS's decision.
    let as_ = FakeAs::with(vec![&managed(false)]);
    as_.push(
        400,
        vec![no_store, ("Content-Type", "application/json")],
        r#"{"error":{"code":"key_rotation_not_supported"}}"#,
    );
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request(), 1_000).unwrap();
    let e = s.rotate_key(None, &new, &key, 1_050).unwrap_err();
    assert!(matches!(e, ClientError::Server(_)), "{e}");
    assert_eq!(s.signer_for(None).unwrap().key_id(), "gnap-demo");

    // Once a key is rotated, a transport failure, an unreadable answer or a
    // failure status on a later management call keep the rotated key.
    let as_ = FakeAs::with(vec![&managed(false), &complete]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request(), 1_000).unwrap();
    s.rotate_key(None, &new, &key, 1_050).unwrap();
    let rotated = s.usable_tokens(1_050).unwrap()[0].clone();
    // Out of scripted replies: the transport fails.
    let e = s.rotate_token(None, 1_100).unwrap_err();
    assert!(matches!(e, ClientError::Transport(_)), "{e}");
    assert_eq!(s.signer_for(None).unwrap().key_id(), "rotated-1");
    as_.push(200, vec![no_store], "{not json");
    let e = s.rotate_token(None, 1_110).unwrap_err();
    assert!(matches!(e, ClientError::Parse(_)), "{e}");
    as_.push(
        503,
        vec![no_store],
        &rebound("V3-4TB8N6.BW7ONM", Some(key_json), "V3"),
    );
    let e = s.rotate_token(None, 1_120).unwrap_err();
    assert!(matches!(e, ClientError::Protocol(_)), "{e}");
    assert_eq!(s.usable_tokens(1_120).unwrap()[0], &rotated);
    assert_eq!(s.signer_for(None).unwrap().key_id(), "rotated-1");
    assert!(signed_by(
        &as_.last(),
        &Ps256Verifier::from_public_jwk(&new.public_jwk().unwrap()).unwrap(),
        "rotated-1",
        1_120
    ));
}
