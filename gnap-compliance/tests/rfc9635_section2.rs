/// Compliance tests for RFC 9635 Section 2 — Grant Request
mod common;

use gnap_compliance::fixtures;
use gnap_compliance::types::*;
use gnap_compliance::validation::validate_grant_request;

// ─── Deserialization tests ───────────────────────────────────────────────────

#[test]
fn parse_single_token_grant_request() {
    let req: GrantRequest =
        serde_json::from_str(fixtures::GRANT_REQUEST_SINGLE_TOKEN).expect("parse single token");

    // Section 2.1: access_token must be a single request
    match req.access_token.as_ref().expect("access_token required") {
        AccessTokenRequestField::Single(token_req) => {
            assert!(!token_req.access.is_empty(), "access must not be empty");
            match &token_req.access[0] {
                AccessRight::Structured(s) => {
                    assert_eq!(s.resource_type, "photo-api");
                    assert_eq!(s.actions.as_ref().unwrap(), &["read", "write", "delete"]);
                }
                AccessRight::Reference(_) => panic!("expected structured access right"),
            }
        }
        AccessTokenRequestField::Multiple(_) => panic!("expected single token request"),
    }

    // Section 2.3: client must have inline key
    match &req.client {
        ClientInstance::Inline(info) => match &info.key {
            KeyRef::Inline(key) => {
                assert_eq!(key.proof.method_name(), "httpsig");
                assert!(key.jwk.is_some());
            }
            KeyRef::Reference(_) => panic!("expected inline key"),
        },
        ClientInstance::Reference(_) => panic!("expected inline client"),
    }
}

#[test]
fn parse_multiple_token_grant_request() {
    let req: GrantRequest =
        serde_json::from_str(fixtures::GRANT_REQUEST_MULTIPLE_TOKENS).expect("parse multi token");

    // Section 2.1: access_token must be an array
    match req.access_token.as_ref().expect("access_token required") {
        AccessTokenRequestField::Multiple(reqs) => {
            assert_eq!(reqs.len(), 2);
            assert_eq!(reqs[0].label.as_deref(), Some("token1"));
            assert_eq!(reqs[1].label.as_deref(), Some("token2"));
        }
        AccessTokenRequestField::Single(_) => panic!("expected multiple token request"),
    }

    // Section 2.3: client by reference
    match &req.client {
        ClientInstance::Reference(id) => {
            assert_eq!(id, "client-instance-id-12345");
        }
        ClientInstance::Inline(_) => panic!("expected client reference"),
    }
}

#[test]
fn parse_grant_request_with_interaction() {
    let req: GrantRequest =
        serde_json::from_str(fixtures::GRANT_REQUEST_WITH_INTERACTION).expect("parse interaction");

    let interact = req.interact.as_ref().expect("interact must be present");
    assert_eq!(interact.start.len(), 1);

    let finish = interact.finish.as_ref().expect("finish must be present");
    assert_eq!(finish.method, "redirect");
    assert_eq!(finish.uri, "https://client.example.net/return/123455");
    assert!(!finish.nonce.is_empty());
}

#[test]
fn parse_grant_request_with_subject() {
    let req: GrantRequest =
        serde_json::from_str(fixtures::GRANT_REQUEST_WITH_SUBJECT).expect("parse subject");

    let subject = req.subject.as_ref().expect("subject must be present");
    let formats = subject.sub_id_formats.as_ref().unwrap();
    assert!(formats.contains(&"opaque".to_string()));
    assert!(formats.contains(&"iss_sub".to_string()));

    let assertions = subject.assertion_formats.as_ref().unwrap();
    assert!(assertions.contains(&"id_token".to_string()));
}

// ─── Roundtrip serialization tests ──────────────────────────────────────────

#[test]
fn roundtrip_single_token_request() {
    let req: GrantRequest = serde_json::from_str(fixtures::GRANT_REQUEST_SINGLE_TOKEN).unwrap();
    common::serde_roundtrip(&req);
}

#[test]
fn roundtrip_multiple_token_request() {
    let req: GrantRequest = serde_json::from_str(fixtures::GRANT_REQUEST_MULTIPLE_TOKENS).unwrap();
    common::serde_roundtrip(&req);
}

#[test]
fn roundtrip_interaction_request() {
    let req: GrantRequest = serde_json::from_str(fixtures::GRANT_REQUEST_WITH_INTERACTION).unwrap();
    common::serde_roundtrip(&req);
}

// ─── Validation tests ────────────────────────────────────────────────────────

#[test]
fn validate_valid_single_token_request() {
    let req: GrantRequest = serde_json::from_str(fixtures::GRANT_REQUEST_SINGLE_TOKEN).unwrap();
    assert!(validate_grant_request(&req).is_ok());
}

#[test]
fn validate_valid_multiple_token_request() {
    let req: GrantRequest = serde_json::from_str(fixtures::GRANT_REQUEST_MULTIPLE_TOKENS).unwrap();
    assert!(validate_grant_request(&req).is_ok());
}

#[test]
fn validate_rejects_empty_access() {
    let req = GrantRequest {
        access_token: Some(AccessTokenRequestField::Single(AccessTokenRequest {
            access: vec![],
            label: None,
            flags: None,
        })),
        client: ClientInstance::Reference("client-id".to_string()),
        interact: None,
        subject: None,
        user: None,
    };
    let errors = validate_grant_request(&req).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| format!("{e}").contains("access must not be empty"))
    );
}

#[test]
fn validate_rejects_multi_token_without_labels() {
    let req = GrantRequest {
        access_token: Some(AccessTokenRequestField::Multiple(vec![AccessTokenRequest {
            access: vec![AccessRight::Reference("read".to_string())],
            label: None,
            flags: None,
        }])),
        client: ClientInstance::Reference("client-id".to_string()),
        interact: None,
        subject: None,
        user: None,
    };
    let errors = validate_grant_request(&req).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| format!("{e}").contains("label is required"))
    );
}

#[test]
fn validate_rejects_interact_with_no_start_and_no_finish() {
    // RFC 9635 Section 2.5: interact must have start modes or a finish method.
    let req = GrantRequest {
        access_token: Some(AccessTokenRequestField::Single(AccessTokenRequest {
            access: vec![AccessRight::Reference("read".to_string())],
            label: None,
            flags: None,
        })),
        client: ClientInstance::Reference("client-id".to_string()),
        interact: Some(InteractRequest {
            start: vec![],
            finish: None,
            hints: None,
        }),
        subject: None,
        user: None,
    };
    let errors = validate_grant_request(&req).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| format!("{e}").contains("start modes or a finish method"))
    );
}

#[test]
fn validate_accepts_empty_start_with_push_finish() {
    // RFC 9635 Section 2.5: empty start is valid with push-only finish.
    let req = GrantRequest {
        access_token: Some(AccessTokenRequestField::Single(AccessTokenRequest {
            access: vec![AccessRight::Reference("read".to_string())],
            label: None,
            flags: None,
        })),
        client: ClientInstance::Reference("client-id".to_string()),
        interact: Some(InteractRequest {
            start: vec![],
            finish: Some(InteractFinish {
                method: "push".to_string(),
                uri: "https://client.example.com/callback".to_string(),
                nonce: "nonce123".to_string(),
                hash_method: None,
            }),
            hints: None,
        }),
        subject: None,
        user: None,
    };
    assert!(validate_grant_request(&req).is_ok());
}

#[test]
fn validate_rejects_invalid_finish_method() {
    let req = GrantRequest {
        access_token: Some(AccessTokenRequestField::Single(AccessTokenRequest {
            access: vec![AccessRight::Reference("read".to_string())],
            label: None,
            flags: None,
        })),
        client: ClientInstance::Reference("client-id".to_string()),
        interact: Some(InteractRequest {
            start: vec![StartMode::Name("redirect".to_string())],
            finish: Some(InteractFinish {
                method: "invalid".to_string(),
                uri: "https://client.example.com/callback".to_string(),
                nonce: "nonce123".to_string(),
                hash_method: None,
            }),
            hints: None,
        }),
        subject: None,
        user: None,
    };
    let errors = validate_grant_request(&req).unwrap_err();
    assert!(errors.iter().any(|e| format!("{e}").contains("redirect")));
}

#[test]
fn parse_extended_start_mode() {
    // RFC 9635 Section 2.5.1: extended start mode is an object with required `mode` field.
    let json = r#"{
        "access_token": {
            "access": [{ "type": "photo-api", "actions": ["read"] }]
        },
        "client": "client-id",
        "interact": {
            "start": [
                "redirect",
                { "mode": "app", "extra_param": "value" }
            ]
        }
    }"#;
    let req: GrantRequest = serde_json::from_str(json).expect("parse extended start mode");
    let interact = req.interact.as_ref().unwrap();
    assert_eq!(interact.start.len(), 2);
    match &interact.start[0] {
        StartMode::Name(n) => assert_eq!(n, "redirect"),
        StartMode::Extended(_) => panic!("expected Name"),
    }
    match &interact.start[1] {
        StartMode::Extended(ext) => {
            assert_eq!(ext.mode, "app");
            assert_eq!(ext.additional.get("extra_param").unwrap(), "value");
        }
        StartMode::Name(_) => panic!("expected Extended"),
    }
}

#[test]
fn reject_extended_start_mode_without_mode_field() {
    // RFC 9635 Section 2.5.1: `mode` field is REQUIRED in extended start mode.
    let json = r#"{
        "access_token": {
            "access": [{ "type": "photo-api", "actions": ["read"] }]
        },
        "client": "client-id",
        "interact": {
            "start": [
                { "extra_param": "value" }
            ]
        }
    }"#;
    assert!(
        serde_json::from_str::<GrantRequest>(json).is_err(),
        "Object start mode without `mode` field should fail to parse"
    );
}
