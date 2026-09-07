//! A token changes presentation key without changing its client or siblings.

use gnap_as::{
    AuthorizationServer, Decision, Endpoints, GrantSelector, GrantSnapshot, GrantStore,
    KeyResolver, MemoryStorage, Nonces, Policy, TokenApproval, TokenRecord,
};
use gnap_client::sign_request;
use gnap_crypto::httpsig::{fresh_nonce, sign, Component, Message, SignatureInput, Tag};
use gnap_crypto::{Ps256Signer, Ps256Verifier, Signer, Verifier};
use gnap_types::client::Client;
use gnap_types::http::{HttpRequest, HttpResponse};
use gnap_types::key::{Key, KeyObject};
use gnap_types::message::{GrantRequest, GrantResponse};
use gnap_types::token::AccessToken;
use serde_json::{json, Value};
use std::cell::Cell;
use std::num::NonZeroU64;
use std::sync::{Arc, OnceLock};

const NOW: u64 = 1_700_000_000;
const GRANT: &str = "https://as.example/gnap";

#[path = "key_rotation/bindings.rs"]
mod bindings;
#[path = "key_rotation/concurrency.rs"]
mod concurrency;
#[path = "key_rotation/consumers.rs"]
mod consumers;
#[path = "key_rotation/session.rs"]
mod session;

fn old_key() -> &'static Ps256Signer {
    static KEY: OnceLock<Ps256Signer> = OnceLock::new();
    KEY.get_or_init(|| {
        Ps256Signer::from_pkcs1_pem(include_str!("fixtures/rfc9421-b12.pkcs1.pem"), "original")
            .unwrap()
    })
}

fn new_key() -> &'static Ps256Signer {
    static KEY: OnceLock<Ps256Signer> = OnceLock::new();
    KEY.get_or_init(|| Ps256Signer::generate(2048, "replacement").unwrap())
}

fn presented(signer: &Ps256Signer) -> KeyObject {
    serde_json::from_value(json!({"proof": "httpsig", "jwk": signer.public_jwk().unwrap()}))
        .unwrap()
}

struct Keys;
impl KeyResolver for Keys {
    fn resolve(&self, client: &Client) -> Option<Box<dyn Verifier>> {
        let key = client.as_value()?.key.as_value()?;
        let verifier = Ps256Verifier::from_public_jwk(key.jwk.as_ref()?).ok()?;
        Some(Box::new(verifier))
    }
}

struct Approve {
    key_rotation: bool,
    value_rotation: bool,
}
impl Policy for Approve {
    fn evaluate(&self, request: &GrantRequest) -> Decision {
        Decision::ApproveTokens {
            tokens: request
                .access_token
                .as_ref()
                .unwrap()
                .tokens
                .iter()
                .map(|token| TokenApproval {
                    requested_label: token.label.clone(),
                    access: token.access.clone(),
                })
                .collect(),
            subject: None,
        }
    }
    fn token_lifetime(&self, _: &GrantRequest) -> Option<NonZeroU64> {
        NonZeroU64::new(60)
    }
    fn may_rotate_key(&self, _: &TokenRecord, _: &KeyObject) -> bool {
        self.key_rotation
    }
    fn may_rotate(&self, _: &AccessToken) -> bool {
        self.value_rotation
    }
}

struct Counted(Cell<u64>);
impl Nonces for Counted {
    fn next(&self) -> String {
        let next = self.0.get() + 1;
        self.0.set(next);
        format!("credential-{next}")
    }
}

type Server<E = gnap_as::OpaqueTokenEncoder, K = Keys> =
    AuthorizationServer<Approve, K, Arc<MemoryStorage>, Counted, E>;

fn server(capability: bool, permission: bool) -> Server {
    configured_server(
        capability,
        Approve {
            key_rotation: permission,
            value_rotation: true,
        },
        Keys,
    )
}

fn configured_server<K: KeyResolver>(
    capability: bool,
    policy: Approve,
    keys: K,
) -> Server<gnap_as::OpaqueTokenEncoder, K> {
    AuthorizationServer::new(
        policy,
        keys,
        Arc::new(MemoryStorage::new()),
        Counted(Cell::new(0)),
        Endpoints {
            grant: GRANT.into(),
            continuation: "https://as.example/continue".into(),
            interaction: "https://as.example/interact".into(),
            token_management: "https://as.example/manage".into(),
        },
    )
    .with_key_rotation(capability)
}

fn grant<E: gnap_as::TokenEncoder, K: KeyResolver>(server: &Server<E, K>) -> Vec<AccessToken> {
    let body = serde_json::to_vec(&json!({
        "client": {"key": presented(old_key())},
        "access_token": [
            {"label": "documents", "access": ["documents:read"]},
            {"label": "reports", "access": ["reports:read"]}
        ]
    }))
    .unwrap();
    let request = sign_request(
        HttpRequest::new("POST", GRANT).json_body(body),
        old_key(),
        None,
        NOW,
    )
    .unwrap();
    let response = server.handle(&request, NOW);
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    let response: GrantResponse = serde_json::from_slice(&response.body).unwrap();
    response.access_token.unwrap().tokens
}

fn handle(token: &AccessToken) -> &str {
    token
        .manage
        .as_ref()
        .unwrap()
        .uri
        .rsplit('/')
        .next()
        .unwrap()
}

fn snapshot<E: gnap_as::TokenEncoder, K: KeyResolver>(
    server: &Server<E, K>,
    token: &AccessToken,
) -> GrantSnapshot {
    server
        .storage()
        .lookup(GrantSelector::Management(handle(token)))
        .unwrap()
        .unwrap()
}

fn rotate_request(
    token: &AccessToken,
    key: &KeyObject,
    body_override: Option<Value>,
) -> HttpRequest {
    let manage = token.manage.as_ref().unwrap();
    let body = serde_json::to_vec(&body_override.unwrap_or_else(|| json!({"key": key}))).unwrap();
    let request = sign_request(
        HttpRequest::new("POST", &manage.uri).json_body(body),
        old_key(),
        Some(&manage.access_token.value),
        NOW + 1,
    )
    .unwrap();
    add_new_proof(request, new_key())
}

fn add_new_proof(request: HttpRequest, signer: &Ps256Signer) -> HttpRequest {
    add_new_proof_with_nonce(request, signer, Some(fresh_nonce().unwrap()))
}

fn add_new_proof_with_nonce(
    request: HttpRequest,
    signer: &Ps256Signer,
    nonce: Option<String>,
) -> HttpRequest {
    let digest = request.combined_header_value("content-digest");
    let authorization = request.combined_header_value("authorization");
    let components = vec![
        Component::Method,
        Component::TargetUri,
        Component::ContentDigest,
        Component::Authorization,
        Component::DictionaryMember {
            field: "signature".into(),
            key: "sig1".into(),
        },
        Component::DictionaryMember {
            field: "signature-input".into(),
            key: "sig1".into(),
        },
    ];
    let message = Message {
        method: &request.method,
        target_uri: &request.url,
        content_digest: digest.as_deref(),
        authorization: authorization.as_deref(),
        other: Vec::new(),
    }
    .with_dictionary_fields(&components, |name| {
        request.header_values(name).collect::<Vec<_>>()
    })
    .unwrap();
    let input = SignatureInput {
        components,
        created: NOW + 1,
        keyid: signer.key_id().into(),
        nonce,
        tag: Tag::GnapRotate,
    };
    let (input, signature) = sign(&message, &input, signer, "replacement").unwrap();
    request
        .header("Signature-Input", input)
        .header("Signature", signature)
}

fn single(response: &HttpResponse) -> AccessToken {
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    assert_eq!(response.header_value("cache-control"), Some("no-store"));
    let response: GrantResponse = serde_json::from_slice(&response.body).unwrap();
    let tokens = response.access_token.unwrap();
    assert_eq!(tokens.cardinality, gnap_types::Cardinality::Single);
    assert_eq!(tokens.tokens.len(), 1);
    tokens.tokens.into_iter().next().unwrap()
}

fn error_code(response: &HttpResponse) -> String {
    assert_eq!(
        response.status,
        400,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    let response: GrantResponse = serde_json::from_slice(&response.body).unwrap();
    response.error.unwrap().code.as_str().into()
}

fn unchanged<E: gnap_as::TokenEncoder, K: KeyResolver>(
    server: &Server<E, K>,
    token: &AccessToken,
    before: &GrantSnapshot,
) {
    let after = snapshot(server, token);
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.aggregate.revoked, before.aggregate.revoked);
    assert_eq!(after.aggregate.tokens.len(), before.aggregate.tokens.len());
    assert_eq!(
        after.aggregate.record.request,
        before.aggregate.record.request
    );
    assert_eq!(
        after.aggregate.record.continuation_token,
        before.aggregate.record.continuation_token
    );
    for (handle, token) in &before.aggregate.tokens {
        let retained = &after.aggregate.tokens[handle];
        assert_eq!(retained.token, token.token);
        assert_eq!(retained.client, token.client);
        assert_eq!(retained.issued_at, token.issued_at);
        assert_eq!(retained.management_token, token.management_token);
        assert_eq!(retained.identifier, token.identifier);
        assert_eq!(retained.derivation, token.derivation);
    }
}

#[test]
fn rotating_one_token_preserves_client_identity_and_sibling_state() {
    let server = server(true, true);
    let tokens = grant(&server);
    let before = snapshot(&server, &tokens[0]);
    let request = rotate_request(&tokens[0], &presented(new_key()), None);
    let rotated = single(&server.handle(&request, NOW + 1));
    assert_ne!(rotated.value, tokens[0].value);
    assert_eq!(
        rotated.key,
        Some(Key::ByValue(Box::new(presented(new_key()))))
    );
    assert_eq!(rotated.access, tokens[0].access);
    assert_eq!(rotated.label, tokens[0].label);
    assert_eq!(rotated.flags, tokens[0].flags);
    let after = snapshot(&server, &rotated);
    assert_eq!(
        after.aggregate.record.request,
        before.aggregate.record.request
    );
    assert_eq!(
        after.aggregate.record.continuation_token,
        before.aggregate.record.continuation_token
    );
    assert_eq!(
        after.aggregate.tokens[handle(&rotated)].client,
        before.aggregate.tokens[handle(&tokens[0])].client
    );
    let sibling = &after.aggregate.tokens[handle(&tokens[1])];
    let old_sibling = &before.aggregate.tokens[handle(&tokens[1])];
    assert_eq!(sibling.token, old_sibling.token);
    assert_eq!(sibling.client, old_sibling.client);
    assert_eq!(sibling.issued_at, old_sibling.issued_at);
    assert_eq!(sibling.management_token, old_sibling.management_token);

    // Subsequent value rotation follows the token's explicit binding.
    let manage = rotated.manage.as_ref().unwrap();
    let old = sign_request(
        HttpRequest::new("POST", &manage.uri),
        old_key(),
        Some(&manage.access_token.value),
        NOW + 2,
    )
    .unwrap();
    assert_eq!(error_code(&server.handle(&old, NOW + 2)), "invalid_client");
    unchanged(&server, &rotated, &after);
    let current = sign_request(
        HttpRequest::new("POST", &manage.uri),
        new_key(),
        Some(&manage.access_token.value),
        NOW + 2,
    )
    .unwrap();
    let value_rotated = single(&server.handle(&current, NOW + 2));
    assert_eq!(value_rotated.key, rotated.key);
    let manage = value_rotated.manage.as_ref().unwrap();
    let revoke = sign_request(
        HttpRequest::new("DELETE", &manage.uri),
        new_key(),
        Some(&manage.access_token.value),
        NOW + 3,
    )
    .unwrap();
    assert_eq!(server.handle(&revoke, NOW + 3).status, 204);
    assert!(snapshot(&server, &tokens[1])
        .aggregate
        .tokens
        .contains_key(handle(&tokens[1])));
}

#[test]
fn either_missing_proof_or_removed_content_preserves_every_token_and_nonce() {
    for case in 0..4 {
        let server = server(true, true);
        let tokens = grant(&server);
        let before = snapshot(&server, &tokens[0]);
        let intact = rotate_request(&tokens[0], &presented(new_key()), None);
        let mut changed = intact.clone();
        match case {
            0 => changed
                .headers
                .retain(|(_, value)| !value.starts_with("replacement=")),
            1 => changed
                .headers
                .retain(|(_, value)| !value.starts_with("sig1=")),
            2 => changed.body = None,
            3 => {
                changed.body = None;
                changed
                    .headers
                    .retain(|(_, value)| !value.starts_with("replacement="));
            }
            _ => unreachable!(),
        }
        assert_eq!(server.handle(&changed, NOW + 1).status, 400, "case {case}");
        unchanged(&server, &tokens[0], &before);
        single(&server.handle(&intact, NOW + 1));
    }
}

#[test]
fn oversized_rotation_hints_do_not_fall_back_to_value_rotation_or_spend_nonces() {
    use gnap_crypto::rotation::MAX_ROTATION_SIGNATURE_BYTES;
    for capability in [false, true] {
        let server = server(capability, true);
        let tokens = grant(&server);
        let before = snapshot(&server, &tokens[0]);
        let manage = tokens[0].manage.as_ref().unwrap();
        let clean = sign_request(
            HttpRequest::new("POST", &manage.uri),
            old_key(),
            Some(&manage.access_token.value),
            NOW + 1,
        )
        .unwrap();
        let mut oversized = clean.clone();
        oversized.headers.push((
            "Signature-Input".into(),
            format!(
                "unmatched=(\"@method\");tag=\"gnap-rotate\";nonce=\"{}\"",
                "x".repeat(MAX_ROTATION_SIGNATURE_BYTES)
            ),
        ));
        assert_eq!(
            error_code(&server.handle(&oversized, NOW + 1)),
            "invalid_rotation"
        );
        unchanged(&server, &tokens[0], &before);
        // The unchanged ordinary request still succeeds: no proof nonce was spent.
        single(&server.handle(&clean, NOW + 1));
    }
}

#[test]
fn capability_permission_and_proof_parameters_have_distinct_refusals() {
    for (capability, permission) in [(false, true), (true, false)] {
        let server = server(capability, permission);
        let tokens = grant(&server);
        let before = snapshot(&server, &tokens[0]);
        let request = rotate_request(&tokens[0], &presented(new_key()), None);
        assert_eq!(
            error_code(&server.handle(&request, NOW + 1)),
            "key_rotation_not_supported"
        );
        unchanged(&server, &tokens[0], &before);
    }
    for proof in [json!("mtls"), json!({"method": "httpsig", "x-extra": true})] {
        let server = server(true, true);
        let tokens = grant(&server);
        let before = snapshot(&server, &tokens[0]);
        let mut key = serde_json::to_value(presented(new_key())).unwrap();
        key["proof"] = proof;
        let request = rotate_request(&tokens[0], &presented(new_key()), Some(json!({"key": key})));
        assert_eq!(
            error_code(&server.handle(&request, NOW + 1)),
            "invalid_rotation"
        );
        unchanged(&server, &tokens[0], &before);
    }
}

#[test]
fn unusable_replacement_keys_are_refused_without_reflecting_submitted_values() {
    let mut cases = vec![
        (
            json!({"proof":"httpsig","jwk":{"kty":"RSA","alg":"PS256","kid":"must-not-appear"}}),
            "invalid_rotation",
        ),
        (json!(null), "invalid_rotation"),
        (json!(""), "invalid_rotation"),
        (
            json!("unregistered-must-not-appear"),
            "key_rotation_not_supported",
        ),
    ];
    for member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        for value in [Value::Null, json!("must-not-appear")] {
            let mut key = serde_json::to_value(presented(new_key())).unwrap();
            key["jwk"][member] = value;
            cases.push((key, "invalid_rotation"));
        }
    }
    for capability in [false, true] {
        for (key, expected) in &cases {
            let server = server(capability, true);
            let tokens = grant(&server);
            let before = snapshot(&server, &tokens[0]);
            let request =
                rotate_request(&tokens[0], &presented(new_key()), Some(json!({"key": key})));
            let response = server.handle(&request, NOW + 1);
            assert_eq!(error_code(&response), *expected);
            assert!(!String::from_utf8_lossy(&response.body).contains("must-not-appear"));
            unchanged(&server, &tokens[0], &before);
        }
    }
}

#[test]
fn an_unrelated_body_is_not_misreported_as_unsupported_key_rotation() {
    for capability in [false, true] {
        let server = server(capability, true);
        let tokens = grant(&server);
        let before = snapshot(&server, &tokens[0]);
        let manage = tokens[0].manage.as_ref().unwrap();
        let request = sign_request(
            HttpRequest::new("POST", &manage.uri).json_body(b"{}".to_vec()),
            old_key(),
            Some(&manage.access_token.value),
            NOW + 1,
        )
        .unwrap();
        assert_eq!(
            error_code(&server.handle(&request, NOW + 1)),
            "invalid_request"
        );
        unchanged(&server, &tokens[0], &before);
    }
}

#[test]
fn permission_denial_keeps_tokens_but_requires_fresh_authenticated_proofs() {
    let server = server(true, false);
    let tokens = grant(&server);
    let before = snapshot(&server, &tokens[0]);
    let request = rotate_request(&tokens[0], &presented(new_key()), None);
    assert_eq!(
        error_code(&server.handle(&request, NOW + 1)),
        "key_rotation_not_supported"
    );
    unchanged(&server, &tokens[0], &before);
    assert_eq!(
        error_code(&server.handle(&request, NOW + 1)),
        "invalid_rotation"
    );
    unchanged(&server, &tokens[0], &before);
    let fresh = rotate_request(&tokens[0], &presented(new_key()), None);
    assert_eq!(
        error_code(&server.handle(&fresh, NOW + 1)),
        "key_rotation_not_supported"
    );
    unchanged(&server, &tokens[0], &before);
}

#[test]
fn a_completed_rotation_cannot_be_replayed_to_change_the_current_tokens() {
    let server = server(true, true);
    let tokens = grant(&server);
    let request = rotate_request(&tokens[0], &presented(new_key()), None);
    let rotated = single(&server.handle(&request, NOW + 1));
    let after = snapshot(&server, &rotated);
    // The old management handle and credential are no longer live. This
    // request cannot even reach a second publication or replace a sibling.
    assert_eq!(server.handle(&request, NOW + 1).status, 400);
    unchanged(&server, &rotated, &after);
}

#[test]
fn a_second_key_change_uses_the_current_binding_not_the_grant_key() {
    let server = server(true, true);
    let tokens = grant(&server);
    let first = rotate_request(&tokens[0], &presented(new_key()), None);
    let rotated = single(&server.handle(&first, NOW + 1));
    let before = snapshot(&server, &rotated);
    let third = Ps256Signer::generate(2048, "third-key").unwrap();
    let manage = rotated.manage.as_ref().unwrap();
    let body = serde_json::to_vec(&json!({"key": presented(&third)})).unwrap();
    let wrong = sign_request(
        HttpRequest::new("POST", &manage.uri).json_body(body.clone()),
        old_key(),
        Some(&manage.access_token.value),
        NOW + 1,
    )
    .unwrap();
    let wrong = add_new_proof(wrong, &third);
    assert_eq!(
        error_code(&server.handle(&wrong, NOW + 1)),
        "invalid_rotation"
    );
    unchanged(&server, &rotated, &before);
    let current = sign_request(
        HttpRequest::new("POST", &manage.uri).json_body(body),
        new_key(),
        Some(&manage.access_token.value),
        NOW + 1,
    )
    .unwrap();
    let current = add_new_proof(current, &third);
    let twice = single(&server.handle(&current, NOW + 1));
    assert_eq!(twice.key, Some(Key::ByValue(Box::new(presented(&third)))));
    assert_eq!(twice.access, tokens[0].access);
    assert_eq!(twice.label, tokens[0].label);
    let after = snapshot(&server, &twice);
    assert_eq!(
        after.aggregate.record.request,
        before.aggregate.record.request
    );
    assert_eq!(
        after.aggregate.tokens[handle(&tokens[1])].token,
        before.aggregate.tokens[handle(&tokens[1])].token
    );
}

#[test]
fn disabling_key_rotation_does_not_forget_an_already_rebound_token() {
    let server = server(true, true);
    let tokens = grant(&server);
    let request = rotate_request(&tokens[0], &presented(new_key()), None);
    let rotated = single(&server.handle(&request, NOW + 1));
    let server = server.with_key_rotation(false);
    let discovery = server.handle(&HttpRequest::new("OPTIONS", GRANT), NOW + 1);
    assert_eq!(discovery.status, 200);
    assert_eq!(
        serde_json::from_slice::<Value>(&discovery.body).unwrap()["key_rotation_supported"],
        false
    );
    let manage = rotated.manage.as_ref().unwrap();
    let request = sign_request(
        HttpRequest::new("POST", &manage.uri),
        new_key(),
        Some(&manage.access_token.value),
        NOW + 1,
    )
    .unwrap();
    let refreshed = single(&server.handle(&request, NOW + 1));
    assert_eq!(refreshed.key, rotated.key);
    let before = snapshot(&server, &refreshed);
    let another_change = rotate_request(&refreshed, &presented(new_key()), None);
    assert_eq!(
        error_code(&server.handle(&another_change, NOW + 1)),
        "key_rotation_not_supported"
    );
    unchanged(&server, &refreshed, &before);
}

#[test]
fn a_bearer_token_cannot_gain_a_binding_even_when_key_rotation_is_disabled() {
    for capability in [false, true] {
        let server = server(capability, true);
        let mut tokens = grant(&server);
        // The issuer above produces bound tokens. Install a valid bearer
        // record through the public store API to test the management boundary;
        // this is not evidence that the issuance path offers bearer tokens.
        let mut seeded = snapshot(&server, &tokens[0]);
        let record = seeded.aggregate.tokens.get_mut(handle(&tokens[0])).unwrap();
        record
            .token
            .flags
            .push(gnap_registry::AccessTokenFlag::Bearer);
        record.token.validate().unwrap();
        tokens[0] = record.token.clone();
        server
            .storage()
            .compare_exchange(seeded.id, seeded.revision, seeded.aggregate)
            .unwrap();
        assert!(tokens[0].is_bearer());
        let before = snapshot(&server, &tokens[0]);
        let request = rotate_request(&tokens[0], &presented(new_key()), None);
        assert_eq!(
            error_code(&server.handle(&request, NOW + 1)),
            "invalid_rotation"
        );
        unchanged(&server, &tokens[0], &before);
    }
}

fn old_proof_with_nonce(token: &AccessToken, nonce: Option<String>) -> HttpRequest {
    let manage = token.manage.as_ref().unwrap();
    let body = serde_json::to_vec(&json!({"key": presented(new_key())})).unwrap();
    let mut request = sign_request(
        HttpRequest::new("POST", &manage.uri).json_body(body),
        old_key(),
        Some(&manage.access_token.value),
        NOW + 1,
    )
    .unwrap();
    let digest = request.combined_header_value("content-digest");
    let authorization = request.combined_header_value("authorization");
    let message = Message {
        method: &request.method,
        target_uri: &request.url,
        content_digest: digest.as_deref(),
        authorization: authorization.as_deref(),
        other: Vec::new(),
    };
    let input = SignatureInput {
        components: vec![
            Component::Method,
            Component::TargetUri,
            Component::ContentDigest,
            Component::Authorization,
        ],
        created: NOW + 1,
        keyid: old_key().key_id().into(),
        nonce,
        tag: Tag::Gnap,
    };
    let (input, signature) = sign(&message, &input, old_key(), "sig1").unwrap();
    request.headers.retain(|(name, _)| {
        !name.eq_ignore_ascii_case("signature-input") && !name.eq_ignore_ascii_case("signature")
    });
    request
        .header("Signature-Input", input)
        .header("Signature", signature)
}

#[test]
fn both_proofs_need_nonempty_nonces_before_either_nonce_is_reserved() {
    // Nonempty nonces are this AS profile's replay policy, not an additional
    // RFC-wide mandate. Both linked signatures remain cryptographically valid.
    for invalid in [None, Some(String::new())] {
        for invalid_is_old in [false, true] {
            let server = server(true, true);
            let tokens = grant(&server);
            let before = snapshot(&server, &tokens[0]);
            let old = if invalid_is_old {
                invalid.clone()
            } else {
                Some("old-proof".into())
            };
            let new = if invalid_is_old {
                Some("new-proof".into())
            } else {
                invalid.clone()
            };
            let request =
                add_new_proof_with_nonce(old_proof_with_nonce(&tokens[0], old), new_key(), new);
            assert_eq!(
                error_code(&server.handle(&request, NOW + 1)),
                "invalid_rotation"
            );
            unchanged(&server, &tokens[0], &before);
            // Reuse the valid half's nonce. A refused pair must not have
            // consumed it merely because that half passed verification.
            let retry = add_new_proof_with_nonce(
                old_proof_with_nonce(&tokens[0], Some("old-proof".into())),
                new_key(),
                Some("new-proof".into()),
            );
            single(&server.handle(&retry, NOW + 1));
        }
    }
}
