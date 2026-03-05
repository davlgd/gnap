/// Compliance tests for RFC 9635 Section 6 — Token Management
mod common;

use gnap_compliance::types::*;

// ─── Section 6.1: Token Rotation ─────────────────────────────────────────────

#[test]
fn parse_token_rotation_response() {
    let json = r#"{
        "access_token": {
            "value": "NEW_TOKEN_VALUE_123",
            "manage": {
                "uri": "https://server.example.com/token/NEW_MANAGE_URI",
                "access_token": {
                    "value": "MGMT_TOKEN_123"
                }
            },
            "expires_in": 3600,
            "access": [
                {
                    "type": "photo-api",
                    "actions": ["read"]
                }
            ]
        }
    }"#;
    let resp: TokenRotationResponse = serde_json::from_str(json).expect("parse rotation response");
    assert_eq!(resp.access_token.value, "NEW_TOKEN_VALUE_123");
    let manage = resp.access_token.manage.as_ref().expect("manage required");
    assert_eq!(manage.uri, "https://server.example.com/token/NEW_MANAGE_URI");
    assert_eq!(manage.access_token.value, "MGMT_TOKEN_123");
    assert_eq!(resp.access_token.expires_in, Some(3600));
}

#[test]
fn roundtrip_token_rotation_response() {
    let resp = TokenRotationResponse {
        access_token: AccessToken {
            value: "rotated-value".to_string(),
            label: None,
            manage: Some(TokenManagement {
                uri: "https://as.example.com/manage/new".to_string(),
                access_token: ContinueAccessToken {
                    value: "mgmt-tok".to_string(),
                },
            }),
            access: vec![AccessRight::Reference("read".to_string())],
            expires_in: Some(7200),
            key: None,
            flags: None,
        },
    };
    common::serde_roundtrip(&resp);
}

// ─── Section 6.2: Token Revocation ───────────────────────────────────────────
// Revocation is a DELETE with no body and expects 204 No Content.
// No response body to parse — tested at integration level.

#[test]
fn access_token_with_bearer_flag() {
    let json = r#"{
        "value": "bearer-token-123",
        "flags": ["bearer"],
        "access": ["read", "write"]
    }"#;
    let token: AccessToken = serde_json::from_str(json).expect("parse bearer token");
    let flags = token.flags.as_ref().unwrap();
    assert!(flags.contains(&"bearer".to_string()));
}

#[test]
fn access_token_without_key_binds_to_client() {
    // RFC 9635 Section 3.2.1: If bearer flag and key field are both omitted,
    // the token is bound to the client instance's presented key.
    let json = r#"{
        "value": "bound-token-456",
        "access": ["read"]
    }"#;
    let token: AccessToken = serde_json::from_str(json).expect("parse token without key");
    assert!(token.key.is_none(), "absent key means bound to client's key");
    assert!(token.flags.is_none());
}

#[test]
fn access_token_with_specific_key_binding() {
    // RFC 9635 Section 3.2.1: key is object or string per Section 7.1.
    let json = r#"{
        "value": "bound-token-789",
        "key": {
            "proof": "httpsig",
            "jwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "x": "dGVzdA"
            }
        },
        "access": ["read"]
    }"#;
    let token: AccessToken = serde_json::from_str(json).expect("parse specific key token");
    match token.key.as_ref().unwrap() {
        KeyRef::Inline(key) => {
            assert_eq!(key.proof.method_name(), "httpsig");
            assert!(key.jwk.is_some());
        }
        KeyRef::Reference(_) => panic!("expected Inline key"),
    }
}
