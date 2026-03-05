/// Compliance tests for RFC 9635 Section 5 — Continuation
mod common;

use gnap_compliance::fixtures;
use gnap_compliance::types::*;

// ─── Section 5.1: Continuation after interaction ─────────────────────────────

#[test]
fn parse_continue_request() {
    let req: ContinueRequest =
        serde_json::from_str(fixtures::CONTINUE_REQUEST).expect("parse continue request");
    assert_eq!(req.interact_ref.as_deref(), Some("4IFWWIKYBC2PQ6U56NL1"));
}

#[test]
fn roundtrip_continue_request() {
    let req: ContinueRequest = serde_json::from_str(fixtures::CONTINUE_REQUEST).unwrap();
    common::serde_roundtrip(&req);
}

// ─── Section 5.2: Polling (empty continue request) ──────────────────────────

#[test]
fn parse_polling_continue_request() {
    let json = r#"{}"#;
    let req: ContinueRequest = serde_json::from_str(json).expect("parse empty continue");
    assert!(req.interact_ref.is_none());
}

#[test]
fn roundtrip_polling_continue_request() {
    let req = ContinueRequest { interact_ref: None };
    common::serde_roundtrip(&req);
}

// ─── Continue response types ────────────────────────────────────────────────

#[test]
fn roundtrip_continue_response() {
    let resp = ContinueResponse {
        access_token: ContinueAccessToken {
            value: "80UPRY5NM33OMUKMKSKU".to_string(),
        },
        uri: "https://server.example.com/continue/VGJKPTKC50".to_string(),
        wait: Some(30),
    };
    common::serde_roundtrip(&resp);
}

#[test]
fn continue_response_wait_is_optional() {
    let json = r#"{
        "access_token": { "value": "tok" },
        "uri": "https://as.example.com/continue/abc"
    }"#;
    let resp: ContinueResponse = serde_json::from_str(json).expect("parse without wait");
    assert!(resp.wait.is_none());
}
