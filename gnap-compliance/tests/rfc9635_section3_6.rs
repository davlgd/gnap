/// Compliance tests for RFC 9635 Section 3.6 — Error Responses
mod common;

use gnap_compliance::fixtures;
use gnap_compliance::types::*;

#[test]
fn parse_user_denied_error() {
    let err: GnapError =
        serde_json::from_str(fixtures::ERROR_RESPONSE).expect("parse error response");
    assert_eq!(err.code, GnapErrorCode::UserDenied);
    assert!(err.description.is_some());
}

#[test]
fn parse_invalid_request_error() {
    let err: GnapError =
        serde_json::from_str(fixtures::ERROR_INVALID_REQUEST).expect("parse invalid_request");
    assert_eq!(err.code, GnapErrorCode::InvalidRequest);
}

#[test]
fn roundtrip_all_error_codes() {
    let codes = [
        GnapErrorCode::InvalidRequest,
        GnapErrorCode::InvalidClient,
        GnapErrorCode::InvalidInteraction,
        GnapErrorCode::InvalidFlag,
        GnapErrorCode::InvalidRotation,
        GnapErrorCode::KeyRotationNotSupported,
        GnapErrorCode::InvalidContinuation,
        GnapErrorCode::UserDenied,
        GnapErrorCode::RequestDenied,
        GnapErrorCode::UnknownUser,
        GnapErrorCode::UnknownInteraction,
        GnapErrorCode::TooFast,
        GnapErrorCode::TooManyAttempts,
    ];
    for code in codes {
        let err = GnapError {
            code: code.clone(),
            description: Some("test".to_string()),
        };
        common::serde_roundtrip(&err);
    }
}

#[test]
fn unknown_error_code_preserved() {
    let json = r#"{"code": "custom_error", "description": "something custom"}"#;
    let err: GnapError = serde_json::from_str(json).expect("parse unknown code");
    match &err.code {
        GnapErrorCode::Unknown(s) => assert_eq!(s, "custom_error"),
        other => panic!("expected Unknown, got {other:?}"),
    }
    common::serde_roundtrip(&err);
}

#[test]
fn error_without_description() {
    let json = r#"{"code": "user_denied"}"#;
    let err: GnapError = serde_json::from_str(json).expect("parse minimal error");
    assert_eq!(err.code, GnapErrorCode::UserDenied);
    assert!(err.description.is_none());
}

// ─── Error in grant response ────────────────────────────────────────────────

#[test]
fn parse_grant_response_with_error_object() {
    let resp: GrantResponse =
        serde_json::from_str(fixtures::GRANT_RESPONSE_WITH_ERROR).expect("parse error response");
    match resp.error.as_ref().expect("error field required") {
        GnapErrorField::Object(err) => {
            assert_eq!(err.code, GnapErrorCode::UserDenied);
            assert!(err.description.is_some());
        }
        GnapErrorField::Code(_) => panic!("expected object form"),
    }
}

#[test]
fn parse_grant_response_with_error_code_string() {
    let resp: GrantResponse = serde_json::from_str(fixtures::GRANT_RESPONSE_WITH_ERROR_CODE)
        .expect("parse error code response");
    match resp.error.as_ref().expect("error field required") {
        GnapErrorField::Code(code) => assert_eq!(code, "user_denied"),
        GnapErrorField::Object(_) => panic!("expected string form"),
    }
}

#[test]
fn roundtrip_grant_response_with_error() {
    let resp: GrantResponse =
        serde_json::from_str(fixtures::GRANT_RESPONSE_WITH_ERROR).unwrap();
    common::serde_roundtrip(&resp);
}
