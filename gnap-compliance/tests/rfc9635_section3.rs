/// Compliance tests for RFC 9635 Section 3 — Grant Response
mod common;

use gnap_compliance::fixtures;
use gnap_compliance::types::*;
use gnap_compliance::validation::validate_grant_response;

// ─── Deserialization tests ───────────────────────────────────────────────────

#[test]
fn parse_response_with_token() {
    let resp: GrantResponse =
        serde_json::from_str(fixtures::GRANT_RESPONSE_WITH_TOKEN).expect("parse token response");

    // Section 3.1: continue must be present
    let cont = resp.continue_.as_ref().expect("continue required");
    assert!(!cont.access_token.value.is_empty());
    assert!(!cont.uri.is_empty());

    // Section 3.2: access_token
    match resp.access_token.as_ref().unwrap() {
        AccessTokenResponseField::Single(token) => {
            assert!(!token.value.is_empty());
            let manage = token.manage.as_ref().expect("manage required");
            assert!(!manage.uri.is_empty());
            assert!(!manage.access_token.value.is_empty());
            assert!(!token.access.is_empty());
        }
        AccessTokenResponseField::Multiple(_) => panic!("expected single token"),
    }
}

#[test]
fn parse_response_with_interaction() {
    let resp: GrantResponse = serde_json::from_str(fixtures::GRANT_RESPONSE_WITH_INTERACTION)
        .expect("parse interaction response");

    let cont = resp.continue_.as_ref().expect("continue required");
    assert_eq!(cont.wait, Some(30));

    let interact = resp.interact.as_ref().expect("interact required");
    assert!(interact.redirect.is_some());
    assert!(interact.finish.is_some());
}

#[test]
fn parse_response_multiple_tokens() {
    let resp: GrantResponse = serde_json::from_str(fixtures::GRANT_RESPONSE_MULTIPLE_TOKENS)
        .expect("parse multi-token response");

    match resp.access_token.as_ref().unwrap() {
        AccessTokenResponseField::Multiple(tokens) => {
            assert_eq!(tokens.len(), 2);
            assert_eq!(tokens[0].label.as_deref(), Some("token1"));
            assert_eq!(tokens[1].label.as_deref(), Some("token2"));
            assert_ne!(tokens[0].value, tokens[1].value);
        }
        AccessTokenResponseField::Single(_) => panic!("expected multiple tokens"),
    }
}

#[test]
fn parse_response_with_user_code() {
    let resp: GrantResponse =
        serde_json::from_str(fixtures::GRANT_RESPONSE_USER_CODE).expect("parse user_code response");

    let interact = resp.interact.as_ref().expect("interact required");
    let user_code = interact.user_code.as_ref().expect("user_code required");
    assert!(!user_code.is_empty(), "user_code string must not be empty");
}

// ─── Roundtrip tests ─────────────────────────────────────────────────────────

#[test]
fn roundtrip_response_with_token() {
    let resp: GrantResponse = serde_json::from_str(fixtures::GRANT_RESPONSE_WITH_TOKEN).unwrap();
    common::serde_roundtrip(&resp);
}

#[test]
fn roundtrip_response_with_interaction() {
    let resp: GrantResponse =
        serde_json::from_str(fixtures::GRANT_RESPONSE_WITH_INTERACTION).unwrap();
    common::serde_roundtrip(&resp);
}

#[test]
fn roundtrip_response_multiple_tokens() {
    let resp: GrantResponse =
        serde_json::from_str(fixtures::GRANT_RESPONSE_MULTIPLE_TOKENS).unwrap();
    common::serde_roundtrip(&resp);
}

// ─── Validation tests ────────────────────────────────────────────────────────

#[test]
fn validate_valid_response_with_token() {
    let resp: GrantResponse = serde_json::from_str(fixtures::GRANT_RESPONSE_WITH_TOKEN).unwrap();
    assert!(validate_grant_response(&resp).is_ok());
}

#[test]
fn validate_valid_response_with_interaction() {
    let resp: GrantResponse =
        serde_json::from_str(fixtures::GRANT_RESPONSE_WITH_INTERACTION).unwrap();
    assert!(validate_grant_response(&resp).is_ok());
}

#[test]
fn validate_rejects_empty_response() {
    let resp = GrantResponse {
        continue_: None,
        access_token: None,
        interact: None,
        subject: None,
        instance_id: None,
        error: None,
    };
    let errors = validate_grant_response(&resp).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| format!("{e}").contains("at least one field"))
    );
}

#[test]
fn validate_rejects_empty_token_value() {
    let resp = GrantResponse {
        continue_: Some(ContinueResponse {
            access_token: ContinueAccessToken {
                value: "valid-continue-token".to_string(),
            },
            uri: "https://as.example.com/continue".to_string(),
            wait: None,
        }),
        access_token: Some(AccessTokenResponseField::Single(Box::new(AccessToken {
            value: "".to_string(),
            label: None,
            manage: None,
            access: vec![],
            expires_in: None,
            key: None,
            flags: None,
        }))),
        interact: None,
        subject: None,
        instance_id: None,
        error: None,
    };
    let errors = validate_grant_response(&resp).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| format!("{e}").contains("value must not be empty"))
    );
}

#[test]
fn validate_rejects_empty_continue_uri() {
    let resp = GrantResponse {
        continue_: Some(ContinueResponse {
            access_token: ContinueAccessToken {
                value: "tok".to_string(),
            },
            uri: "".to_string(),
            wait: None,
        }),
        access_token: None,
        interact: None,
        subject: None,
        instance_id: None,
        error: None,
    };
    let errors = validate_grant_response(&resp).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| format!("{e}").contains("continue.uri must not be empty"))
    );
}

#[test]
fn validate_rejects_bearer_with_key() {
    let resp = GrantResponse {
        continue_: Some(ContinueResponse {
            access_token: ContinueAccessToken {
                value: "cont-tok".to_string(),
            },
            uri: "https://as.example.com/continue".to_string(),
            wait: None,
        }),
        access_token: Some(AccessTokenResponseField::Single(Box::new(AccessToken {
            value: "bearer-and-key".to_string(),
            label: None,
            manage: None,
            access: vec![AccessRight::Reference("read".to_string())],
            expires_in: None,
            key: Some(KeyRef::Reference("key-ref".to_string())),
            flags: Some(vec!["bearer".to_string()]),
        }))),
        interact: None,
        subject: None,
        instance_id: None,
        error: None,
    };
    let errors = validate_grant_response(&resp).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| format!("{e}").contains("bearer flag and key must not both be present"))
    );
}

#[test]
fn validate_rejects_duplicate_flags() {
    let resp = GrantResponse {
        continue_: Some(ContinueResponse {
            access_token: ContinueAccessToken {
                value: "cont-tok".to_string(),
            },
            uri: "https://as.example.com/continue".to_string(),
            wait: None,
        }),
        access_token: Some(AccessTokenResponseField::Single(Box::new(AccessToken {
            value: "dup-flags-tok".to_string(),
            label: None,
            manage: None,
            access: vec![AccessRight::Reference("read".to_string())],
            expires_in: None,
            key: None,
            flags: Some(vec!["bearer".to_string(), "bearer".to_string()]),
        }))),
        interact: None,
        subject: None,
        instance_id: None,
        error: None,
    };
    let errors = validate_grant_response(&resp).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| format!("{e}").contains("duplicate flag"))
    );
}

#[test]
fn validate_rejects_manage_token_same_value() {
    let resp = GrantResponse {
        continue_: Some(ContinueResponse {
            access_token: ContinueAccessToken {
                value: "cont-tok".to_string(),
            },
            uri: "https://as.example.com/continue".to_string(),
            wait: None,
        }),
        access_token: Some(AccessTokenResponseField::Single(Box::new(AccessToken {
            value: "same-value".to_string(),
            label: None,
            manage: Some(TokenManagement {
                uri: "https://as.example.com/manage/123".to_string(),
                access_token: ContinueAccessToken {
                    value: "same-value".to_string(),
                },
            }),
            access: vec![AccessRight::Reference("read".to_string())],
            expires_in: None,
            key: None,
            flags: None,
        }))),
        interact: None,
        subject: None,
        instance_id: None,
        error: None,
    };
    let errors = validate_grant_response(&resp).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| format!("{e}").contains("manage.access_token.value must differ"))
    );
}
