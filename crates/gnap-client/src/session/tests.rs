//! Atomic local state and deliberately non-atomic remote outcomes.

use super::*;
use gnap_crypto::hash::interaction_hash;
use gnap_crypto::ps256::Ps256Signer;
use gnap_crypto::verify::{verify_request, Expectations, SignedRequest};
use std::cell::RefCell;
use std::collections::{HashSet, VecDeque};

const ENDPOINT: &str = "https://as.example/gnap";
const PENDING: &str = r#"{"interact":{"redirect":"https://as.example/i","finish":"as-nonce","expires_in":30},"continue":{"uri":"https://as.example/c","access_token":{"value":"old-cont"},"wait":0}}"#;
const APPROVED: &str = r#"{"access_token":{"value":"old-token","access":["files"],"expires_in":20},"subject":{"sub_ids":[{"format":"email","email":"old@example.com"}]},"continue":{"uri":"https://as.example/c","access_token":{"value":"old-cont"},"wait":0}}"#;

struct Script {
    replies: RefCell<VecDeque<Result<HttpResponse, String>>>,
    seen: RefCell<Vec<HttpRequest>>,
}

impl Script {
    fn new(replies: Vec<Result<HttpResponse, String>>) -> Self {
        Self {
            replies: RefCell::new(replies.into()),
            seen: RefCell::default(),
        }
    }
}

impl HttpTransport for Script {
    type Error = String;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        self.seen.borrow_mut().push(request);
        self.replies.borrow_mut().pop_front().unwrap()
    }
}

fn response(status: u16, body: &str) -> HttpResponse {
    HttpResponse {
        status,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: body.as_bytes().to_vec(),
    }
}

fn signer() -> Ps256Signer {
    Ps256Signer::from_pkcs1_pem(
        include_str!("../../../gnap-crypto/tests/rfc9421-b12.pkcs1.pem"),
        "client-key",
    )
    .unwrap()
}

fn request() -> GrantRequest {
    serde_json::from_str(r#"{"client":"client","access_token":{"access":["files"]},"interact":{"start":["redirect"],"finish":{"method":"redirect","uri":"https://client.example/cb","nonce":"client-nonce"}}}"#).unwrap()
}

fn callback() -> InteractCallback {
    InteractCallback {
        hash: interaction_hash(
            &InteractionHashInput {
                client_nonce: "client-nonce",
                as_nonce: "as-nonce",
                interact_ref: "accepted-ref",
                grant_endpoint: ENDPOINT,
            },
            HashMethod::Sha256,
        )
        .unwrap(),
        interact_ref: "accepted-ref".into(),
    }
}

fn unusable_responses() -> Vec<Result<HttpResponse, String>> {
    let mut wrong_type = response(200, APPROVED);
    wrong_type.headers[0].1 = "text/html".into();
    let mut duplicate_type = response(200, APPROVED);
    duplicate_type
        .headers
        .push(("content-type".into(), "application/json".into()));
    vec![
        Err("connection lost".into()),
        Ok(response(503, "")),
        Ok(response(204, "")),
        Ok(response(502, "<html>upstream unavailable</html>")),
        Ok(wrong_type),
        Ok(duplicate_type),
        Ok(response(200, "{invalid")),
        Ok(response(200, "[]")),
        Ok(response(503, APPROVED)),
        // The continuation validator runs after subject/token absorption.
        Ok(response(
            200,
            &APPROVED
                .replace("old-token", "new-token")
                .replace("old@example.com", "new@example.com")
                .replace("https://as.example/c", "relative"),
        )),
        Ok(response(
            400,
            r#"{"error":"invalid_request","access_token":{"value":"forbidden"}}"#,
        )),
    ]
}

#[test]
fn no_content_grant_response_is_a_protocol_error() {
    let key = signer();
    let transport = Script::new(vec![Ok(response(204, ""))]);
    let mut session = Session::new(&transport, &key, ENDPOINT).supporting(&["redirect"]);
    let before = session.protocol.clone();

    assert!(matches!(
        session.start(&request(), 100),
        Err(ClientError::Protocol(_))
    ));
    assert_eq!(session.protocol, before);
}

#[test]
fn unusable_responses_restore_every_protocol_field() {
    let key = signer();
    for bad in unusable_responses() {
        // Initial request, poll, validated callback, pending modification and
        // approved modification exercise different transitions and metadata.
        for mode in 0..5 {
            let initial = if mode == 4 {
                APPROVED.to_owned()
            } else if mode == 1 {
                PENDING.replace(",\"finish\":\"as-nonce\"", "")
            } else {
                PENDING.to_owned()
            };
            let replies = if mode == 0 {
                vec![bad.clone()]
            } else {
                vec![Ok(response(200, &initial)), bad.clone()]
            };
            let transport = Script::new(replies);
            let mut session = Session::new(&transport, &key, ENDPOINT).supporting(&["redirect"]);
            if mode != 0 {
                session.start(&request(), 1_000).unwrap();
            }
            if mode == 2 {
                session.accept_callback(&callback(), 1_001).unwrap();
            }
            let before = session.protocol.clone();
            let result = match mode {
                0 => session.start(&request(), 1_002),
                1 | 2 => session.continue_grant(1_002),
                _ => session.modify_grant(&ContinueRequest::default(), 1_002),
            };
            assert!(result.is_err(), "mode {mode}: {bad:?}");
            assert!(!matches!(result, Err(ClientError::Server(_))));
            assert_eq!(session.protocol, before, "mode {mode}: {bad:?}");
            assert_eq!(session.supported_modes, Some(vec!["redirect".into()]));
            assert_eq!(session.endpoint, ENDPOINT);
            assert!(std::ptr::eq(session.transport, &raw const transport));
            assert!(std::ptr::eq(session.signer, &raw const key));
        }
    }
}

#[test]
fn valid_error_rotates_continuation_and_wait_without_spending_the_reference() {
    let key = signer();
    let transport = Script::new(vec![
        Ok(response(200, PENDING)),
        Ok(response(
            400,
            r#"{"error":"too_fast","continue":{"uri":"https://as.example/new","access_token":{"value":"new-cont"},"wait":5}}"#,
        )),
        Ok(response(200, APPROVED)),
    ]);
    let mut session = Session::new(&transport, &key, ENDPOINT);
    session.start(&request(), 1_000).unwrap();
    session.accept_callback(&callback(), 1_001).unwrap();
    let before = session.protocol.clone();
    assert!(matches!(
        session.continue_grant(1_002),
        Ok(Step::Recoverable(_))
    ));
    let mut expected = before;
    expected.grant.offer_continuation(1_002, Some(5));
    expected.continuation = Some(
        serde_json::from_str(
            r#"{"uri":"https://as.example/new","access_token":{"value":"new-cont"},"wait":5}"#,
        )
        .unwrap(),
    );
    assert_eq!(session.protocol, expected);
    assert!(matches!(
        session.continue_grant(1_006),
        Err(ClientError::Usage(_))
    ));
    assert_eq!(session.protocol, expected);
    assert!(matches!(
        session.continue_grant(1_007),
        Ok(Step::Approved(_))
    ));
}

#[test]
fn retry_after_uncommitted_failure_has_a_fresh_verifiable_proof() {
    let key = signer();
    let transport = Script::new(vec![
        Ok(response(200, PENDING)),
        Ok(response(503, "")),
        Ok(response(200, APPROVED)),
    ]);
    let mut session = Session::new(&transport, &key, ENDPOINT);
    session.start(&request(), 1_000).unwrap();
    session.accept_callback(&callback(), 1_001).unwrap();
    assert!(session.continue_grant(1_002).is_err());
    assert!(matches!(
        session.continue_grant(1_003),
        Ok(Step::Approved(_))
    ));
    let seen = transport.seen.borrow();
    assert_eq!(seen[1].body, seen[2].body);
    assert_eq!(
        seen[1].header_value("authorization"),
        seen[2].header_value("authorization")
    );
    let nonces = RefCell::new(HashSet::new());
    for request in &seen[1..] {
        verify_request(
            &SignedRequest {
                method: &request.method,
                target_uri: &request.url,
                headers: &request.headers,
                body: request.body.as_deref(),
            },
            &key.verifier(),
            &Expectations {
                now: 1_003,
                max_clock_skew: 30,
                key_id: Some("client-key"),
            },
            &|nonce: &str, _: u64| nonces.borrow_mut().insert(nonce.to_owned()),
        )
        .unwrap();
    }
    assert_eq!(nonces.borrow().len(), 2);
}

/// This fake AS actually commits before dropping its response. A scripted
/// success on retry would conceal the distributed-state limit being tested.
struct CommitThenLose {
    committed: RefCell<bool>,
    requests: RefCell<usize>,
}

impl HttpTransport for CommitThenLose {
    type Error = String;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        *self.requests.borrow_mut() += 1;
        if request.url == ENDPOINT {
            return Ok(response(200, PENDING));
        }
        assert_eq!(request.header_value("authorization"), Some("GNAP old-cont"));
        if self.committed.replace(true) {
            Ok(response(400, r#"{"error":"invalid_continuation"}"#))
        } else {
            Err("response lost after committing and retiring old-cont".into())
        }
    }
}

#[test]
fn lost_committed_response_does_not_make_retry_idempotent() {
    let key = signer();
    let transport = CommitThenLose {
        committed: RefCell::new(false),
        requests: RefCell::new(0),
    };
    let mut session = Session::new(&transport, &key, ENDPOINT);
    session.start(&request(), 1_000).unwrap();
    session.accept_callback(&callback(), 1_001).unwrap();
    let before = session.protocol.clone();
    assert!(matches!(
        session.continue_grant(1_002),
        Err(ClientError::Transport(_))
    ));
    assert_eq!(session.protocol, before);
    assert!(*transport.committed.borrow());
    assert_eq!(*transport.requests.borrow(), 2); // No automatic retry.
    assert!(matches!(
        session.continue_grant(1_003),
        Err(ClientError::Server(_))
    ));
    assert_eq!(session.state(), State::Finalized);
    assert!(session.continuation().is_none());
    assert!(session.protocol.validated_ref.is_none());
    assert!(matches!(
        session.continue_grant(1_004),
        Err(ClientError::Usage(_))
    ));
    assert_eq!(*transport.requests.borrow(), 3);
}

#[test]
fn terminal_polling_error_removes_the_continuation_and_prevents_another_call() {
    let key = signer();
    let polling = PENDING.replace(",\"finish\":\"as-nonce\"", "");
    let transport = Script::new(vec![
        Ok(response(200, &polling)),
        Ok(response(400, r#"{"error":"invalid_continuation"}"#)),
    ]);
    let mut session = Session::new(&transport, &key, ENDPOINT);
    session.start(&request(), 1_000).unwrap();
    assert!(matches!(
        session.continue_grant(1_001),
        Err(ClientError::Server(_))
    ));
    assert!(session.continuation().is_none());
    assert!(matches!(
        session.continue_grant(1_002),
        Err(ClientError::Usage(_))
    ));
    assert_eq!(transport.seen.borrow().len(), 2);
}

#[test]
fn json_media_type_parameters_and_casing_remain_accepted() {
    let key = signer();
    let mut reply = response(200, APPROVED);
    reply.headers[0].1 = "Application/JSON; charset=utf-8".into();
    let transport = Script::new(vec![Ok(reply)]);
    let mut session = Session::new(&transport, &key, ENDPOINT);
    assert!(matches!(
        session.start(&request(), 1_000),
        Ok(Step::Approved(_))
    ));
}
