//! A full grant flow against an AS that lives in memory.
//!
//! The transport seam means no network is involved: the fake AS answers from a
//! script, which makes the hostile cases as easy to run as the happy path.

use gnap_client::{ClientError, HttpRequest, HttpResponse, HttpTransport, Session, Step};
use gnap_core::State;
use gnap_crypto::hash::{interaction_hash, HashMethod, InteractionHashInput};
use gnap_crypto::ps256::Ps256Signer;
use gnap_registry::ErrorCode;
use gnap_types::interact::InteractCallback;
use gnap_types::message::{ContinueRequest, GrantRequest};
use std::cell::RefCell;

#[path = "flow/finish_timeout.rs"]
mod finish_timeout;

#[path = "flow/subject_assertions.rs"]
mod subject_assertions;

const RSA_PKCS1: &str = include_str!("../../gnap-crypto/tests/rfc9421-b12.pkcs1.pem");
const ENDPOINT: &str = "https://server.example.com/gnap";
const CLIENT_NONCE: &str = "VJLO6A4CATR0KRO";
const AS_NONCE: &str = "MBDOFXG4Y5CVJCX821LH";

/// An AS that replies from a script, and records what it was sent.
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
                        status: 200,
                        headers: vec![("Cache-Control".into(), "no-store".into())],
                        body: b.as_bytes().to_vec(),
                    })
                    .rev()
                    .collect(),
            ),
            seen: RefCell::new(Vec::new()),
        }
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

/// The callback the scripted AS would send for `PENDING`.
fn valid_callback() -> InteractCallback {
    InteractCallback {
        hash: interaction_hash(
            &InteractionHashInput {
                client_nonce: CLIENT_NONCE,
                as_nonce: AS_NONCE,
                interact_ref: "4IFWWIKYBC2PQ6U56NL1",
                grant_endpoint: ENDPOINT,
            },
            HashMethod::Sha256,
        )
        .expect("the hash should compute"),
        interact_ref: "4IFWWIKYBC2PQ6U56NL1".into(),
    }
}

fn signer() -> Ps256Signer {
    Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap()
}

fn request() -> GrantRequest {
    serde_json::from_str(&format!(
        r#"{{"client":"client-541-ab",
             "access_token":{{"access":["dolphin-metadata"]}},
             "interact":{{"start":["redirect"],
                          "finish":{{"method":"redirect",
                                     "uri":"https://client.example.net/cb",
                                     "nonce":"{CLIENT_NONCE}"}}}}}}"#
    ))
    .unwrap()
}

const PENDING: &str = r#"{
  "interact": {"redirect": "https://as.example/i/4CF492ML", "finish": "MBDOFXG4Y5CVJCX821LH"},
  "continue": {"uri": "https://as.example/continue",
               "access_token": {"value": "80UPRY5NM33OMUKMKSKU"}, "wait": 0}
}"#;

/// A pending response with no `finish`: the AS has no way to call back, so the
/// client polls (§5.2). §3.3.5-MN02 forbids polling when a `finish` was
/// returned, which makes this the fixture for every wait-period test.
const POLLING: &str = r#"{
  "interact": {"redirect": "https://as.example/i/4CF492ML"},
  "continue": {"uri": "https://as.example/continue",
               "access_token": {"value": "80UPRY5NM33OMUKMKSKU"}, "wait": 0}
}"#;

const APPROVED: &str = r#"{
  "access_token": {"value": "OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0",
                   "access": ["dolphin-metadata"]}
}"#;

#[test]
fn empty_503_keeps_a_modification_retryable() {
    let sk = signer();
    let as_ = FakeAs::with(vec![POLLING, "", APPROVED]);
    as_.replies.borrow_mut()[1].status = 503;
    let mut session = Session::new(&as_, &sk, ENDPOINT);
    session.start(&request(), 1_000).unwrap();
    let continuation = session.continuation().cloned();
    assert!(session
        .modify_grant(&ContinueRequest::default(), 1_001)
        .is_err());
    assert_eq!(session.state(), State::Pending);
    assert_eq!(session.continuation(), continuation.as_ref());
    assert!(matches!(
        session.modify_grant(&ContinueRequest::default(), 1_002),
        Ok(Step::Approved(_))
    ));
}

#[test]
fn empty_503_after_callback_keeps_the_reference_retryable() {
    let sk = signer();
    let as_ = FakeAs::with(vec![PENDING, "", APPROVED]);
    as_.replies.borrow_mut()[1].status = 503;
    let mut session = Session::new(&as_, &sk, ENDPOINT);
    session.start(&request(), 1_000).unwrap();
    session.accept_callback(&valid_callback(), 1_001).unwrap();
    let continuation = session.continuation().cloned();
    assert!(session.continue_grant(1_002).is_err());
    assert_eq!(session.state(), State::Pending);
    assert_eq!(session.continuation(), continuation.as_ref());
    assert!(matches!(
        session.continue_grant(1_003),
        Ok(Step::Approved(_))
    ));
    let seen = as_.seen.borrow();
    assert_eq!(seen[1].body, seen[2].body);
    assert_ne!(
        seen[1].header_value("signature-input"),
        seen[2].header_value("signature-input")
    );
}

/// The whole redirect flow: request, interaction, callback, continuation, token.
///
/// GNAP-9635-§3.1-M03 — the client instance "MUST use this value exactly as
/// given when making a continuation request".
#[test]
fn a_full_redirect_flow() {
    let sk = signer();
    let as_ = FakeAs::with(vec![PENDING, APPROVED]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);

    // 1. The grant request comes back pending, with somewhere to send the user.
    let step = s.start(&request(), 1_000).unwrap();
    assert!(matches!(step, Step::Pending(_)), "{step:?}");
    assert_eq!(s.state(), State::Pending);
    assert_eq!(
        step.response()
            .interact
            .as_ref()
            .unwrap()
            .redirect
            .as_deref(),
        Some("https://as.example/i/4CF492ML")
    );

    // 2. The end user comes back through the callback. The AS computes the
    //    hash the same way the client will.
    let callback = InteractCallback {
        hash: interaction_hash(
            &InteractionHashInput {
                client_nonce: CLIENT_NONCE,
                as_nonce: AS_NONCE,
                interact_ref: "4IFWWIKYBC2PQ6U56NL1",
                grant_endpoint: ENDPOINT,
            },
            HashMethod::Sha256,
        )
        .unwrap(),
        interact_ref: "4IFWWIKYBC2PQ6U56NL1".into(),
    };
    s.accept_callback(&callback, 1_005).unwrap();

    // 3. Continuing yields the token.
    let step = s.continue_grant(1_100).unwrap();
    assert!(matches!(step, Step::Approved(_)), "{step:?}");
    assert_eq!(s.state(), State::Approved);
    let token = step.response().access_token.as_ref().unwrap();
    assert_eq!(
        token.tokens[0].value.as_str(),
        "OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0"
    );

    // Both requests were signed, and the continuation carried its token.
    let seen = as_.seen.borrow();
    assert_eq!(seen.len(), 2);
    for r in seen.iter() {
        assert!(
            r.header_value("signature-input").is_some(),
            "unsigned request"
        );
        assert!(r.header_value("signature").is_some(), "missing signature");
    }
    assert_eq!(
        seen[1].header_value("authorization"),
        Some("GNAP 80UPRY5NM33OMUKMKSKU"),
        "the continuation token travels with the GNAP scheme (§7.2)"
    );
    assert_eq!(
        seen[1].url, "https://as.example/continue",
        "the continuation URI is used as given"
    );
}

/// GNAP-9635-§4.2.1-M06, GNAP-9635-§4.2.1-MN07 — a callback whose hash does not
/// validate never turns into a request.
/// GNAP-9635-§2.5.2-M11 — "All interaction finish methods MUST use this nonce
/// to allow the client to verify the connection between the pending interaction
/// request and the callback."
/// GNAP-9635-§2.5.2-M12 — "All requests to the callback URI MUST be processed
/// as described in Section 4.2."
#[test]
fn a_forged_callback_is_refused_and_nothing_leaves() {
    let sk = signer();
    let as_ = FakeAs::with(vec![PENDING]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request(), 1_000).unwrap();

    let forged = InteractCallback {
        hash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
        interact_ref: "stolen".into(),
    };
    let e = s.accept_callback(&forged, 1_005).unwrap_err();
    assert!(
        matches!(e, ClientError::Interaction(_)),
        "a bad callback comes over the front channel; it is not the AS misbehaving: {e}"
    );
    assert!(e.to_string().contains("§4.2.1"), "{e}");

    // One request was sent — the initial one. The reference never left.
    assert_eq!(as_.seen.borrow().len(), 1);
}

/// GNAP-9635-§3.2.1-M30 — an AS that hands out a bearer token carrying a key.
#[test]
fn a_bearer_token_with_a_key_is_refused() {
    let sk = signer();
    let as_ = FakeAs::with(vec![
        r#"{"access_token":{"value":"AAA","flags":["bearer"],"key":"k-1"}}"#,
    ]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);

    let e = s.start(&request(), 1_000).unwrap_err();
    assert!(matches!(e, ClientError::Protocol(_)), "{e}");
    assert!(e.to_string().contains("§3.2.1"), "{e}");
}

/// GNAP-9635-§3.2.1-MN31 — an object request answered with an array.
#[test]
fn a_response_that_changes_shape_is_refused() {
    let sk = signer();
    let as_ = FakeAs::with(vec![r#"{"access_token":[{"label":"t1","value":"AAA"}]}"#]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);

    // The request asked for a single token, as an object.
    let e = s.start(&request(), 1_000).unwrap_err();
    assert!(e.to_string().contains("§3.2"), "{e}");
}

/// GNAP-9635-§5-MN07 — the client waits before calling the continuation URI.
/// GNAP-9635-§3.1-M05 — `wait` is "The amount of time in integer seconds the
/// client instance MUST wait after receiving this request continuation response
/// and calling the continuation URI".
#[test]
fn continuing_too_early_is_refused_before_anything_is_sent() {
    let sk = signer();
    let waited = POLLING.replace("\"wait\": 0", "\"wait\": 30");
    let as_ = FakeAs::with(vec![&waited]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request(), 1_000).unwrap();

    let e = s.continue_grant(1_010).unwrap_err();
    assert!(e.to_string().contains("too_fast"), "{e}");
    assert_eq!(as_.seen.borrow().len(), 1, "nothing should have been sent");

    // Once the wait has elapsed the call goes out.
    assert!(
        s.continue_grant(1_030).is_err(),
        "the fake AS has no reply left"
    );
    assert_eq!(as_.seen.borrow().len(), 2, "the second call did leave");
}

/// GNAP-9635-§5-MN13 — with no continuation offered, the client does not call.
#[test]
fn continuing_without_an_offer_is_refused() {
    let sk = signer();
    let as_ = FakeAs::with(vec![APPROVED]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request(), 1_000).unwrap();
    assert!(s.continuation().is_none());

    let e = s.continue_grant(1_100).unwrap_err();
    assert!(matches!(e, ClientError::Usage(_)), "{e}");
    assert_eq!(as_.seen.borrow().len(), 1);
}

/// GNAP-9635-§3-M08 — "The AS MUST include the HTTP `Cache-Control` response
/// header field [RFC9111] with a value set to `no-store`."
///
/// The AS is the one bound, and a client cannot make it comply — but it can
/// notice, which is how a non-conformant AS gets caught instead of followed.
#[test]
fn a_missing_no_store_is_observable() {
    let good = HttpResponse {
        status: 200,
        headers: vec![("Cache-Control".into(), "no-store".into())],
        body: b"{}".to_vec(),
    };
    assert!(good.has_no_store());

    let bad = HttpResponse {
        headers: vec![],
        ..good.clone()
    };
    assert!(
        !bad.has_no_store(),
        "a missing no-store must be visible (§3)"
    );

    // `no-store` is a directive of a comma-separated list, matched without
    // case (RFC 9111 §5.2) — not a substring.
    let with = |value: &str| HttpResponse {
        headers: vec![("cache-control".into(), value.into())],
        ..good.clone()
    };
    for present in [
        "No-Store",
        "max-age=0, no-store",
        "private,no-store ,must-revalidate",
    ] {
        assert!(with(present).has_no_store(), "{present:?}");
    }
    for absent in [
        "x-no-store",
        "foo=\"no-store\"",
        "foo=\"a, no-store\"",
        "no-store-please",
    ] {
        assert!(!with(absent).has_no_store(), "{absent:?}");
    }

    // Several Cache-Control fields are one list (RFC 9110 §5.3).
    let split = HttpResponse {
        headers: vec![
            ("Cache-Control".into(), "private".into()),
            ("Cache-Control".into(), "no-store".into()),
        ],
        ..good
    };
    assert!(split.has_no_store());
}

/// GNAP-9635-§3.3-MN09 — an AS that offers a mode the client never indicated.
///
/// The prohibition binds the AS. A client cannot prevent it, but acting on such
/// a mode would mean following an AS that is out of spec, so it refuses.
#[test]
fn an_unrequested_interaction_mode_is_refused() {
    let sk = signer();
    // The request offers `redirect` only; the AS answers with a user code.
    let as_ = FakeAs::with(vec![
        r#"{"interact":{"user_code":"A1BC3DFF"},
            "continue":{"uri":"https://as/c","access_token":{"value":"BBB"}}}"#,
    ]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);

    let e = s.start(&request(), 1_000).unwrap_err();
    assert!(matches!(e, ClientError::Protocol(_)), "{e}");
    assert!(e.to_string().contains("user_code"), "{e}");
    assert!(e.to_string().contains("§3.3"), "{e}");
}

/// GNAP-9635-§4.2.3 — the client validates the callback with the algorithm it
/// asked for, and refuses to ask for one it cannot compute.
///
/// Falling back to `sha-256` when the requested algorithm is unknown would let
/// an AS that ignored the request produce a hash the client accepts under
/// another name.
#[test]
fn an_unusable_hash_method_is_refused_before_interacting() {
    let sk = signer();
    let as_ = FakeAs::with(vec![PENDING]);
    let mut client = Session::new(&as_, &sk, ENDPOINT);

    let request: GrantRequest = serde_json::from_str(&format!(
        r#"{{"client":"client-541-ab",
             "access_token":{{"access":["dolphin-metadata"]}},
             "interact":{{"start":["redirect"],
                          "finish":{{"method":"redirect",
                                     "uri":"https://client.example.net/cb",
                                     "nonce":"{CLIENT_NONCE}",
                                     "hash_method":"blake2b-256"}}}}}}"#
    ))
    .unwrap();

    let error = client
        .start(&request, 1_000)
        .expect_err("the client cannot compute blake2b-256");
    assert!(error.to_string().contains("blake2b-256"), "{error}");
    assert!(
        as_.seen.borrow().is_empty(),
        "nothing should have been sent"
    );
}

/// GNAP-9635-§2.5.2-MN03 — the client does not ask for a callback URI the AS
/// is forbidden to use.
#[test]
fn a_callback_uri_with_a_fragment_never_leaves() {
    let sk = signer();
    let as_ = FakeAs::with(vec![PENDING]);
    let mut client = Session::new(&as_, &sk, ENDPOINT);

    let request: GrantRequest = serde_json::from_str(&format!(
        r#"{{"client":"client-541-ab",
             "access_token":{{"access":["dolphin-metadata"]}},
             "interact":{{"start":["redirect"],
                          "finish":{{"method":"redirect",
                                     "uri":"https://client.example.net/cb#here",
                                     "nonce":"{CLIENT_NONCE}"}}}}}}"#
    ))
    .unwrap();

    let error = client
        .start(&request, 1_000)
        .expect_err("a fragment makes the callback unusable");
    assert!(error.to_string().contains("fragment"), "{error}");
    assert!(as_.seen.borrow().is_empty());
}

/// GNAP-9635-§2.5.2-R09 with GNAP-9635-§4.2.3 — a nonce the hash base cannot
/// hold makes the callback unverifiable, so nothing is sent.
#[test]
fn a_nonce_the_hash_cannot_take_never_leaves() {
    let sk = signer();

    for nonce in ["", "caf\u{e9}", "one\ntwo"] {
        let as_ = FakeAs::with(vec![PENDING]);
        let mut client = Session::new(&as_, &sk, ENDPOINT);
        let request: GrantRequest = serde_json::from_value(serde_json::json!({
            "client": "client-541-ab",
            "access_token": {"access": ["dolphin-metadata"]},
            "interact": {"start": ["redirect"],
                         "finish": {"method": "redirect",
                                    "uri": "https://client.example.net/cb",
                                    "nonce": nonce}}
        }))
        .unwrap();

        let error = client
            .start(&request, 1_000)
            .expect_err("the nonce cannot feed the interaction hash");
        assert!(error.to_string().contains("nonce"), "{error}");
        assert!(
            as_.seen.borrow().is_empty(),
            "nothing should have been sent"
        );
    }
}

/// GNAP-9635-§5-M11 — an AS that refuses the call hands the grant back, and the
/// client carries on from there.
///
/// The AS did not act on the call, so the interaction reference is not spent:
/// the retry presents the same one, against the token the AS just issued. A
/// client that discarded it here could never continue the grant, and the RO
/// would have to be asked again for nothing.
#[test]
fn a_refused_continuation_is_retried_with_the_same_reference() {
    const TOO_FAST: &str = r#"{
      "error": {"code": "too_fast", "description": "wait a little longer"},
      "continue": {"uri": "https://as.example/continue",
                   "access_token": {"value": "SECONDTOKENFROMTHEAS"}, "wait": 0}
    }"#;

    let sk = signer();
    let as_ = FakeAs::with(vec![PENDING, TOO_FAST, APPROVED]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request(), 1_000).unwrap();

    let callback = InteractCallback {
        hash: interaction_hash(
            &InteractionHashInput {
                client_nonce: CLIENT_NONCE,
                as_nonce: AS_NONCE,
                interact_ref: "4IFWWIKYBC2PQ6U56NL1",
                grant_endpoint: ENDPOINT,
            },
            HashMethod::Sha256,
        )
        .unwrap(),
        interact_ref: "4IFWWIKYBC2PQ6U56NL1".into(),
    };
    s.accept_callback(&callback, 1_005).unwrap();

    // The client's own guard is satisfied, but the AS disagrees about the time.
    let step = s.continue_grant(1_100).unwrap();
    assert!(matches!(step, Step::Recoverable(_)), "{step:?}");
    assert_eq!(
        s.state(),
        State::Pending,
        "the AS did not act on the call, so the grant did not move"
    );

    let step = s.continue_grant(1_200).unwrap();
    assert!(matches!(step, Step::Approved(_)), "{step:?}");

    let seen = as_.seen.borrow();
    assert_eq!(seen.len(), 3);
    assert_eq!(
        seen[2].header_value("authorization"),
        Some("GNAP SECONDTOKENFROMTHEAS"),
        "§5-M12: the retry uses the token the AS handed back"
    );
    let body = String::from_utf8_lossy(seen[2].body.as_deref().unwrap_or_default());
    assert!(
        body.contains("4IFWWIKYBC2PQ6U56NL1"),
        "the same reference goes again: {body}"
    );
}

/// GNAP-9635-§7.2-M03 — "The access token MUST be sent using the HTTP
/// Authorization request header field and the `GNAP` authorization scheme along
/// with a key proof as described in Section 7.3 for the key bound to the access
/// token."
/// GNAP-9635-§7.2-M01 — the continuation token carries neither the `bearer`
/// flag nor a `key`, so it "MUST be sent using the same key and proofing
/// mechanism that the client instance used in its initial request".
/// GNAP-9635-§7.2-MN05 — "The Form-Encoded Body Parameter and URI Query
/// Parameter methods of [RFC6750] MUST NOT be used for GNAP access tokens."
///
/// GNAP-9635-§5-M01 — "when the client instance makes any calls to the
/// continuation URI, the client instance MUST present the continuation access
/// token as described in Section 7.2 and present proof of the client
/// instance's key [...] by signing the request as described in Section 7.3."
/// GNAP-9635-§3.1-M12 and GNAP-9635-§3.2.1-M26 — "The client instance MUST
/// present the continuation access token in all requests to the continuation
/// URI as described in Section 7.2."
/// GNAP-9635-§3.1-M15 — "the client instance MUST sign all continuation
/// requests with its key as described in Section 7.3 and MUST present the
/// continuation access token in its continuation request."
///
/// §5-M01 puts the continuation call squarely under these rules: the
/// continuation token is an access token in the §3.2.1 format, bound to the
/// client's key, and §5 says to present it the way §7.2 describes.
#[test]
fn the_continuation_token_travels_only_in_the_authorization_header() {
    let sk = signer();
    let as_ = FakeAs::with(vec![PENDING, APPROVED]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request(), 1_000).unwrap();
    s.accept_callback(&valid_callback(), 1_005).unwrap();
    s.continue_grant(1_100).unwrap();

    let seen = as_.seen.borrow();
    let (first, continuation) = (&seen[0], &seen[1]);
    let token = "80UPRY5NM33OMUKMKSKU";

    // §7.2-M03 — the header, the scheme, and nothing else around it.
    assert_eq!(
        continuation.header_value("authorization"),
        Some(format!("GNAP {token}").as_str())
    );

    // §7.2-MN05 — RFC 6750's other two methods are forbidden here, so the
    // value appears in no query string and in no request content.
    assert!(!continuation.url.contains(token), "{}", continuation.url);
    let body = String::from_utf8_lossy(continuation.body.as_deref().unwrap_or_default());
    assert!(!body.contains(token), "the token is in the content: {body}");

    // §7.2-M03 — "along with a key proof [...] for the key bound to the access
    // token": the proof has to cover the header the token travels in, or the
    // same signature would serve for any token.
    let input = continuation.header_value("signature-input").unwrap();
    assert!(input.contains("\"authorization\""), "{input}");

    // §7.2-M01 — the same key as the initial request, named the same way.
    let keyid = |request: &HttpRequest| {
        request
            .header_value("signature-input")
            .unwrap()
            .split(";keyid=")
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    };
    assert_eq!(keyid(continuation), keyid(first), "the key must not change");
}

/// GNAP-9635-§4.1.1-MN02 — "The client instance MUST NOT modify the URI when
/// launching it; in particular, the client instance MUST NOT add any parameters
/// to the URI."
///
/// GNAP-9635-§3.3.1-MN03 — "The client instance MUST NOT alter the URI in any
/// way."
///
/// Launching is the embedder's job, not this library's. What the library owes
/// is that nothing between the wire and the caller touches the URI: no
/// normalising, no parameter helpfully appended. That is what this pins.
#[test]
fn the_interaction_uri_reaches_the_caller_byte_for_byte() {
    const ODD_BUT_LEGAL: &str = r#"{
      "interact": {"redirect": "https://as.example/i/4CF492ML?state=a%20b&x=1",
                   "finish": "MBDOFXG4Y5CVJCX821LH"},
      "continue": {"uri": "https://as.example/continue",
                   "access_token": {"value": "80UPRY5NM33OMUKMKSKU"}, "wait": 0}
    }"#;

    let sk = signer();
    let as_ = FakeAs::with(vec![ODD_BUT_LEGAL]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    let step = s.start(&request(), 1_000).unwrap();

    assert_eq!(
        step.response()
            .interact
            .as_ref()
            .unwrap()
            .redirect
            .as_deref(),
        Some("https://as.example/i/4CF492ML?state=a%20b&x=1"),
        "the URI is handed on exactly as the AS sent it"
    );
}

/// GNAP-9635-§5-MN08 — "If no wait period is indicated, the client instance
/// MUST NOT poll immediately and SHOULD wait at least 5 seconds."
///
/// The absence of `wait` is not permission to hammer the AS; it selects the
/// default of §3.1.
#[test]
fn an_absent_wait_still_holds_the_client_back() {
    const NO_WAIT: &str = r#"{
      "interact": {"redirect": "https://as.example/i/4CF492ML"},
      "continue": {"uri": "https://as.example/continue",
                   "access_token": {"value": "80UPRY5NM33OMUKMKSKU"}}
    }"#;

    let sk = signer();
    let as_ = FakeAs::with(vec![NO_WAIT, APPROVED]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request(), 1_000).unwrap();

    let e = s.continue_grant(1_004).unwrap_err();
    assert!(e.to_string().contains("too_fast"), "{e}");
    assert_eq!(as_.seen.borrow().len(), 1, "nothing left the client");

    // Five seconds is the default the RFC names.
    assert!(s.continue_grant(1_005).is_ok());
}

/// GNAP-9635-§5-M15 — "For continuation functions that require the client
/// instance to send message content, the content MUST be a JSON object."
#[test]
fn continuation_content_is_a_json_object() {
    let sk = signer();
    let as_ = FakeAs::with(vec![PENDING, APPROVED]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request(), 1_000).unwrap();

    let callback = InteractCallback {
        hash: interaction_hash(
            &InteractionHashInput {
                client_nonce: CLIENT_NONCE,
                as_nonce: AS_NONCE,
                interact_ref: "4IFWWIKYBC2PQ6U56NL1",
                grant_endpoint: ENDPOINT,
            },
            HashMethod::Sha256,
        )
        .unwrap(),
        interact_ref: "4IFWWIKYBC2PQ6U56NL1".into(),
    };
    s.accept_callback(&callback, 1_005).unwrap();
    s.continue_grant(1_100).unwrap();

    let seen = as_.seen.borrow();
    let body = seen[1].body.as_deref().expect("§5.1 sends content");
    let parsed: serde_json::Value = serde_json::from_slice(body).expect("valid JSON");
    assert!(
        parsed.is_object(),
        "content must be a JSON object: {parsed}"
    );
    assert_eq!(
        seen[1].header_value("content-type"),
        Some("application/json")
    );
}

/// GNAP-9635-§3.4-M15 — "The client instance MUST interpret all subject
/// information in the context of the AS from which the subject information is
/// received."
///
/// §3.4 spells out why: two ASes can return the same email address for two
/// different people, and "a rogue AS could exploit this to take over a targeted
/// account asserted by a different AS". So the accessor never hands the
/// identifiers over on their own.
#[test]
fn subject_information_arrives_attributed_to_its_authorization_server() {
    const WITH_SUBJECT: &str = r#"{
      "access_token": {"value": "OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0",
                       "access": ["dolphin-metadata"]},
      "subject": {"sub_ids": [{"format": "email", "email": "user@example.com"}]}
    }"#;

    let sk = signer();

    // Nothing to attribute before an AS has said anything.
    let as_ = FakeAs::with(vec![PENDING, WITH_SUBJECT]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    assert!(s.subject().is_none());

    s.start(&request(), 1_000).unwrap();
    assert!(s.subject().is_none(), "the AS has released nothing yet");

    let callback = InteractCallback {
        hash: interaction_hash(
            &InteractionHashInput {
                client_nonce: CLIENT_NONCE,
                as_nonce: AS_NONCE,
                interact_ref: "4IFWWIKYBC2PQ6U56NL1",
                grant_endpoint: ENDPOINT,
            },
            HashMethod::Sha256,
        )
        .unwrap(),
        interact_ref: "4IFWWIKYBC2PQ6U56NL1".into(),
    };
    s.accept_callback(&callback, 1_005).unwrap();
    s.continue_grant(1_100).unwrap();

    let attributed = s.subject().expect("the AS released subject information");
    assert_eq!(
        attributed.as_endpoint, ENDPOINT,
        "the identifier means nothing without the AS that stated it"
    );
    assert!(attributed.subject.sub_ids.is_some());
}

/// GNAP-9635-§3.2.1-MN09 — "The client instance MUST NOT use the access token
/// past this time."
///
/// `expires_in` is a duration, not a date: only the client knows when it
/// started running. So the library refuses to hand the token out once it has
/// run, instead of handing it out with a warning.
#[test]
fn an_expired_token_is_not_handed_out() {
    const SHORT_LIVED: &str = r#"{
      "access_token": [
        {"label": "brief", "value": "OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0",
         "access": ["dolphin-metadata"], "expires_in": 60},
        {"label": "lasting", "value": "B8CDFONP21-4TB8N6.BW7ONM",
         "access": ["dolphin-metadata"]}
      ]
    }"#;

    let sk = signer();
    let as_ = FakeAs::with(vec![SHORT_LIVED]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);

    let multiple: GrantRequest = serde_json::from_str(
        r#"{"client":"client-541-ab",
            "access_token":[{"label":"brief","access":["dolphin-metadata"]},
                            {"label":"lasting","access":["dolphin-metadata"]}]}"#,
    )
    .unwrap();
    s.start(&multiple, 1_000).unwrap();

    // While it lasts, both are on offer.
    let live = s.usable_tokens(1_059).expect("both tokens are usable");
    assert_eq!(live.len(), 2);

    // One second past its life, the short-lived one is gone and the other stays.
    let live = s.usable_tokens(1_060).expect("one token is still usable");
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].label.as_deref(), Some("lasting"));

    // A token with no `expires_in` has no such limit to reach.
    assert_eq!(s.usable_tokens(9_999_999).unwrap().len(), 1);
}

/// GNAP-9635-§4.2.1-M03 — "The client instance MUST be able to process a
/// request on the URI."
/// GNAP-9635-§4.2.1-M04 — "If the URI is HTTP, the request MUST be an HTTP
/// GET", so the callback carries its values in the query and nowhere else.
/// GNAP-9635-§4.2.1-M05 — "the client instance MUST parse the query parameters
/// to extract the hash and interaction reference values."
/// GNAP-9635-§4.2.2-M04 — "the client instance MUST parse the JSON object and
/// validate the hash value as described in Section 4.2.3."
/// GNAP-9635-§4.2.2-M05 — "If either fails, the client instance MUST return an
/// `unknown_interaction` error."
/// GNAP-9635-§2.5.2.1-M02 and GNAP-9635-§2.5.2.2-M02 — "Requests to the
/// callback URI MUST be processed by the client instance as described in
/// Section 4.2.1" and "Section 4.2.2" respectively, which is what this does.
///
/// Parsing the callback is the client's job, so the library does it. Leaving it
/// to every caller is how a query with the client's own parameters alongside,
/// or a percent-encoded value, ends up validated against the wrong reference.
#[test]
fn a_callback_is_read_and_validated_by_the_client_itself() {
    let expected = |interact_ref: &str| {
        interaction_hash(
            &InteractionHashInput {
                client_nonce: CLIENT_NONCE,
                as_nonce: AS_NONCE,
                interact_ref,
                grant_endpoint: ENDPOINT,
            },
            HashMethod::Sha256,
        )
        .unwrap()
    };

    // §4.2.1 — the redirect, with the client's own state parameter alongside
    // and a percent-encoded hash, as base64url with padding would arrive.
    let sk = signer();
    let as_ = FakeAs::with(vec![PENDING, APPROVED]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request(), 1_000).unwrap();
    let hash = expected("4IFWWIKYBC2PQ6U56NL1").replace('-', "%2D");
    s.accept_redirect(
        &format!(
            "https://client.example.net/cb?state=abc&hash={hash}&interact_ref=4IFWWIKYBC2PQ6U56NL1"
        ),
        1_005,
    )
    .expect("the client reads its own callback");
    assert!(s.continue_grant(1_100).is_ok());

    // §4.2.2 — the same, pushed as JSON.
    let as_ = FakeAs::with(vec![PENDING, APPROVED]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request(), 1_000).unwrap();
    let pushed = serde_json::to_vec(&InteractCallback {
        hash: expected("4IFWWIKYBC2PQ6U56NL1"),
        interact_ref: "4IFWWIKYBC2PQ6U56NL1".into(),
    })
    .unwrap();
    s.accept_push(&pushed, 1_005)
        .expect("the pushed callback is read");

    // §4.2.2-M05 — a hash that does not validate carries the code the client
    // must answer the AS with.
    let as_ = FakeAs::with(vec![PENDING]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request(), 1_000).unwrap();
    let e = s
        .accept_push(
            br#"{"hash":"not-the-right-hash","interact_ref":"x"}"#,
            1_005,
        )
        .unwrap_err();
    let answer = e.as_callback_error().expect("an error to return to the AS");
    assert_eq!(answer.code, ErrorCode::UnknownInteraction);

    // A callback missing half of itself is not one, and fails the same way.
    let e = s
        .accept_redirect("https://client.example.net/cb?hash=abc", 1_005)
        .unwrap_err();
    assert!(e.to_string().contains("interact_ref"), "{e}");
    assert_eq!(
        e.as_callback_error().map(|g| g.code),
        Some(ErrorCode::UnknownInteraction)
    );
}

/// GNAP-9635-§3.3.5-MN02 — "If the AS returns the finish field, the client
/// instance MUST NOT continue a grant request before it receives the associated
/// interaction reference on the callback URI."
///
/// Polling in that window asks the AS to act on an interaction the client has
/// no evidence of, which is the very thing the reference exists to prove.
#[test]
fn a_promised_callback_is_waited_for_not_polled_around() {
    let sk = signer();
    let as_ = FakeAs::with(vec![PENDING, APPROVED]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request(), 1_000).unwrap();

    let e = s.continue_grant(1_100).unwrap_err();
    assert!(e.to_string().contains("§3.3.5"), "{e}");
    assert_eq!(as_.seen.borrow().len(), 1, "nothing left the client");

    // Once the callback has arrived, the reference goes with the call.
    s.accept_callback(&valid_callback(), 1_005).unwrap();
    assert!(s.continue_grant(1_100).is_ok());
}

/// GNAP-9635-§2.5-MN01 — "A client instance MUST NOT declare an interaction
/// mode it does not support."
///
/// What a mode costs to support — opening a browser, showing a code, receiving
/// a push — is the embedder's business, not this library's. So the library does
/// not guess: it refuses to let the claim stay implicit, and holds the request
/// to what the caller said it can do.
#[test]
fn a_client_does_not_declare_a_mode_it_cannot_drive() {
    let sk = signer();
    let as_ = FakeAs::with(vec![PENDING]);

    let asking_for_a_code: GrantRequest = serde_json::from_str(
        r#"{"client":"client-541-ab",
            "access_token":{"access":["dolphin-metadata"]},
            "interact":{"start":["redirect","user_code"]}}"#,
    )
    .unwrap();

    let mut s = Session::new(&as_, &sk, ENDPOINT).supporting(&["redirect"]);
    let e = s.start(&asking_for_a_code, 1_000).unwrap_err();
    assert!(e.to_string().contains("user_code"), "{e}");
    assert!(as_.seen.borrow().is_empty(), "nothing left the client");

    // The same request from a client that can show a code.
    let mut s = Session::new(&as_, &sk, ENDPOINT).supporting(&["redirect", "user_code"]);
    assert!(s.start(&asking_for_a_code, 1_000).is_ok());

    // Saying nothing leaves the declaration to the caller, as before.
    let as_ = FakeAs::with(vec![PENDING]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    assert!(s.start(&asking_for_a_code, 1_000).is_ok());
}

/// GNAP-9635-§5.1-M01 — "The client instance MUST include that value as the
/// field `interact_ref` in a POST request to the continuation URI."
/// GNAP-9635-§5.1-MN02 — "if the client instance needs to make additional
/// continuation calls after this request, the client instance MUST NOT include
/// the interaction reference in subsequent calls."
#[test]
fn the_interaction_reference_goes_once_and_only_once() {
    const STILL_PENDING: &str = r#"{
      "continue": {"uri": "https://as.example/continue",
                   "access_token": {"value": "SECONDTOKENFROMTHEAS"}, "wait": 0}
    }"#;

    let sk = signer();
    let as_ = FakeAs::with(vec![PENDING, STILL_PENDING, APPROVED]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request(), 1_000).unwrap();
    s.accept_callback(&valid_callback(), 1_005).unwrap();

    // §5.1-M01 — the first continuation carries it, in a POST.
    s.continue_grant(1_100).unwrap();
    let first = String::from_utf8_lossy(as_.seen.borrow()[1].body.as_deref().unwrap_or_default())
        .into_owned();
    assert_eq!(as_.seen.borrow()[1].method, "POST");
    assert!(first.contains("4IFWWIKYBC2PQ6U56NL1"), "{first}");

    // §5.1-MN02 — the next one does not, even though the client still knows it.
    s.continue_grant(1_200).unwrap();
    let second = as_.seen.borrow()[2].body.clone();
    assert!(
        second.is_none() || !String::from_utf8_lossy(&second.unwrap()).contains("4IFWWIKYB"),
        "the reference is single-use and must not be repeated"
    );
}

/// GNAP-9635-§6.1-M06 — "Upon receiving such an error, the client instance MUST
/// consider the access token to not have changed its state."
/// GNAP-9635-§6.1-M05 — the client checks that the rotated token carries the
/// same rights, since the AS is bound to keep them.
///
/// A rotation that fails must leave the client holding exactly what it held. A
/// client that dropped its token on an `invalid_rotation` would lose access it
/// still has.
#[test]
fn a_refused_rotation_leaves_the_token_as_it_was() {
    const MANAGED: &str = r#"{
      "access_token": {"value": "OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0",
                       "access": ["dolphin-metadata"],
                       "manage": {"uri": "https://as.example/token/PRY5NM33O",
                                  "access_token": {"value": "B8CDFONP21-4TB8N6.BW7ONM"}}}
    }"#;
    const REFUSED: &str = r#"{"error":{"code":"invalid_rotation"}}"#;
    const NARROWED: &str = r#"{
      "access_token": {"value": "FP6A8H6HY37MH13CK76LBZ6Y1UADG6VEUPEER5H2",
                       "access": ["something-narrower"],
                       "manage": {"uri": "https://as.example/token/NEW",
                                  "access_token": {"value": "AAAA"}}}
    }"#;

    let sk = signer();
    let as_ = FakeAs::with(vec![MANAGED, REFUSED, NARROWED]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request(), 1_000).unwrap();
    let before = s.usable_tokens(1_000).unwrap()[0].clone();

    // §6.1-M06 — the AS refuses; nothing the client holds changes.
    let e = s.rotate_token(None, 1_100).unwrap_err();
    assert!(e.to_string().contains("invalid_rotation"), "{e}");
    assert_eq!(s.usable_tokens(1_100).unwrap()[0], &before);

    // §6.1-M05 — an AS that comes back with different rights is caught, and
    // again nothing changes.
    let e = s.rotate_token(None, 1_200).unwrap_err();
    assert!(e.to_string().contains("same access rights"), "{e}");
    assert_eq!(s.usable_tokens(1_200).unwrap()[0], &before);

    // §6 — a token with no `manage` field offers no management API at all.
    let as_ = FakeAs::with(vec![APPROVED]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request(), 1_000).unwrap();
    let e = s.rotate_token(None, 1_100).unwrap_err();
    assert!(e.to_string().contains("`manage`"), "{e}");
    assert!(as_.seen.borrow().len() == 1, "nothing left the client");
}

/// GNAP-9635-§6.1-M01 — a rotation hands back a token "with the same rights
/// and properties as the original token, apart from an updated token value and
/// expiration time".
///
/// `expires_in` is a duration, so the rotated token's clock starts at the
/// rotation, not at the original issuance. A session that kept one instant for
/// every token it holds would declare the rotated token expired while the AS
/// still honours it.
#[test]
fn a_rotated_token_starts_its_own_expiry_clock() {
    const MANAGED: &str = r#"{
      "access_token": {"value": "OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0",
                       "access": ["dolphin-metadata"], "expires_in": 100,
                       "manage": {"uri": "https://as.example/token/PRY5NM33O",
                                  "access_token": {"value": "B8CDFONP21-4TB8N6.BW7ONM"}}}
    }"#;
    const ROTATED: &str = r#"{
      "access_token": {"value": "FP6A8H6HY37MH13CK76LBZ6Y1UADG6VEUPEER5H2",
                       "access": ["dolphin-metadata"], "expires_in": 100,
                       "manage": {"uri": "https://as.example/token/NEW",
                                  "access_token": {"value": "AAAA"}}}
    }"#;

    let sk = signer();
    let as_ = FakeAs::with(vec![MANAGED, ROTATED]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request(), 1_000).unwrap();

    // Issued at 1 000 for 100 s, rotated at 1 090 for another 100 s.
    let rotated = s.rotate_token(None, 1_090).unwrap();
    assert_eq!(
        rotated.value.as_str(),
        "FP6A8H6HY37MH13CK76LBZ6Y1UADG6VEUPEER5H2"
    );

    // Past the original expiry, still within the rotated one.
    let live = s
        .usable_tokens(1_150)
        .expect("the rotated token is still good");
    assert_eq!(live[0].value, rotated.value);

    // And it does run out, from the rotation.
    assert!(s.usable_tokens(1_190).is_none());
}

/// GNAP-9635-§2.3-MN09 — "The client instance MUST NOT send a symmetric key by
/// value in the key field of the request".
/// GNAP-9635-§2.3.2-M03 and GNAP-9635-§2.3.2-M05 — the display URIs are
/// absolute.
///
/// These bind the client, so the client library enforces them before anything
/// leaves: a type that knows how to refuse such a key is no protection if the
/// session never asks it.
#[test]
fn what_the_client_says_about_itself_is_checked_before_it_leaves() {
    const SYMMETRIC: &str = r#"{
      "client": {"key": {"proof": "httpsig",
                         "jwk": {"kty": "oct", "kid": "shared", "alg": "HS256", "k": "AAAA"}}},
      "access_token": {"access": ["dolphin-metadata"]}
    }"#;
    const RELATIVE_LOGO: &str = r#"{
      "client": {"key": {"proof": "httpsig",
                         "jwk": {"kty": "RSA", "kid": "gnap-demo", "alg": "PS256",
                                 "n": "AQAB", "e": "AQAB"}},
                 "display": {"name": "Demo", "logo_uri": "/logo.png"}},
      "access_token": {"access": ["dolphin-metadata"]}
    }"#;

    let sk = signer();
    for (body, expected) in [(SYMMETRIC, "symmetric"), (RELATIVE_LOGO, "logo_uri")] {
        let as_ = FakeAs::with(vec![APPROVED]);
        let mut s = Session::new(&as_, &sk, ENDPOINT);
        let request: GrantRequest = serde_json::from_str(body).unwrap();
        let e = s.start(&request, 1_000).unwrap_err();
        assert!(matches!(e, ClientError::Usage(_)), "{e}");
        assert!(e.to_string().contains(expected), "{e}");
        assert!(as_.seen.borrow().is_empty(), "nothing left the client");
    }
}

/// A `wait` that does not fit next to the clock is a response, not a reason to
/// panic — and not a reason to skip the wait either. Wrapping arithmetic would
/// turn "wait forever" into "call now", which is the opposite of what §5 asks.
#[test]
fn a_wait_beyond_the_clock_holds_the_client_back_without_panicking() {
    const FOREVER: &str = r#"{
      "interact": {"redirect": "https://as.example/i/4CF492ML"},
      "continue": {"uri": "https://as.example/continue",
                   "access_token": {"value": "80UPRY5NM33OMUKMKSKU"},
                   "wait": 18446744073709551615}
    }"#;

    let sk = signer();
    let as_ = FakeAs::with(vec![FOREVER]);
    let mut s = Session::new(&as_, &sk, ENDPOINT);
    s.start(&request(), 1_000).unwrap();

    let e = s.continue_grant(u64::MAX).unwrap_err();
    assert!(e.to_string().contains("wait period"), "{e}");
    assert_eq!(as_.seen.borrow().len(), 1, "nothing left the client");
}
fn pending_with_lifetime(seconds: u64) -> String {
    let mut response: serde_json::Value = serde_json::from_str(PENDING).unwrap();
    response["interact"]["expires_in"] = seconds.into();
    response.to_string()
}

#[test]
fn interaction_deadline_checks_all_callback_entrypoints_at_the_boundary() {
    let pending = pending_with_lifetime(20);
    let callback = valid_callback();
    let redirect = format!(
        "https://client.example.net/cb?hash={}&interact_ref={}",
        callback.hash, callback.interact_ref
    );
    let pushed = serde_json::to_vec(&callback).unwrap();
    for mode in ["parsed", "redirect", "push"] {
        for now in [999, 1_000, 1_019, 1_020, 1_021] {
            let sk = signer();
            let as_ = FakeAs::with(vec![&pending, APPROVED]);
            let mut session = Session::new(&as_, &sk, ENDPOINT);
            session.start(&request(), 1_000).unwrap();
            let result = match mode {
                "redirect" => session.accept_redirect(&redirect, now),
                "push" => session.accept_push(&pushed, now),
                _ => session.accept_callback(&callback, now),
            };
            assert_eq!(
                result.is_ok(),
                (1_000..1_020).contains(&now),
                "{mode}, {now}"
            );
            if let Err(error) = result {
                assert_eq!(
                    error.as_callback_error().unwrap().code,
                    ErrorCode::UnknownInteraction
                );
                assert_eq!(session.state(), State::Pending);
                assert!(session.continue_grant(1_021).is_err());
                assert_eq!(as_.seen.borrow().len(), 1);
            } else {
                // The deadline bounds arrival of the finish signal, not a
                // valid reference already held while waiting to continue.
                assert!(session.continue_grant(1_021).is_ok());
            }
        }
    }
}

#[test]
fn refused_callbacks_do_not_consume_or_replace_an_accepted_reference() {
    let pending = pending_with_lifetime(20);
    let sk = signer();
    let as_ = FakeAs::with(vec![&pending, APPROVED]);
    let mut session = Session::new(&as_, &sk, ENDPOINT);
    session.start(&request(), 1_000).unwrap();
    let forged = InteractCallback {
        hash: "invalid".into(),
        interact_ref: "attacker".into(),
    };
    assert!(session.accept_callback(&forged, 1_001).is_err());
    session.accept_callback(&valid_callback(), 1_005).unwrap();
    assert!(session.accept_callback(&forged, 1_006).is_err());
    assert!(
        session.accept_callback(&valid_callback(), 1_007).is_err(),
        "one-time callback"
    );
    assert!(session.accept_callback(&valid_callback(), 1_020).is_err());
    session.continue_grant(1_021).unwrap();
    let seen = as_.seen.borrow();
    let body: serde_json::Value = serde_json::from_slice(seen[1].body.as_ref().unwrap()).unwrap();
    assert_eq!(body["interact_ref"], valid_callback().interact_ref);
}

#[test]
fn interaction_expiration_omission_zero_and_overflow_are_explicit() {
    let sk = signer();
    let as_ = FakeAs::with(vec![PENDING]);
    let mut session = Session::new(&as_, &sk, ENDPOINT);
    session.start(&request(), 1_000).unwrap();
    assert!(session.accept_callback(&valid_callback(), 999).is_err());
    session
        .accept_callback(&valid_callback(), u64::MAX)
        .unwrap();

    let zero = pending_with_lifetime(0);
    let as_ = FakeAs::with(vec![&zero]);
    let mut session = Session::new(&as_, &sk, ENDPOINT);
    session.start(&request(), 1_000).unwrap();
    assert!(session.accept_callback(&valid_callback(), 1_000).is_err());

    let overflow = pending_with_lifetime(u64::MAX);
    let as_ = FakeAs::with(vec![&overflow]);
    let mut session = Session::new(&as_, &sk, ENDPOINT);
    session.start(&request(), 1_000).unwrap();
    assert!(session.continuation().is_some());
    assert!(session.accept_callback(&valid_callback(), 999).is_err());
    session
        .accept_callback(&valid_callback(), u64::MAX)
        .unwrap();

    let as_ = FakeAs::with(vec![&overflow]);
    let mut session = Session::new(&as_, &sk, ENDPOINT);
    session.start(&request(), 0).unwrap();
    assert!(session
        .accept_callback(&valid_callback(), u64::MAX)
        .is_err());
}

#[test]
fn only_a_new_interaction_response_replaces_the_finish_deadline() {
    use gnap_types::message::ContinueRequest;
    let sk = signer();
    let pending = pending_with_lifetime(20);
    let no_interaction = r#"{"continue":{"uri":"https://as.example/continue","access_token":{"value":"replacement"},"wait":0}}"#;
    for (response, may_finish) in [(no_interaction, false), (pending.as_str(), true)] {
        let as_ = FakeAs::with(vec![&pending, response]);
        let mut session = Session::new(&as_, &sk, ENDPOINT);
        session.start(&request(), 1_000).unwrap();
        let changes: ContinueRequest = serde_json::from_str("{}").unwrap();
        session.modify_grant(&changes, 1_010).unwrap();
        assert_eq!(
            session.accept_callback(&valid_callback(), 1_020).is_ok(),
            may_finish
        );
    }
}
