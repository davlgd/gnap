//! Permission and public-binding boundaries of the optional rotation handler.

use super::*;
use gnap_as::ResolvedTokenKey;
use gnap_crypto::{Rs256Signer, Rs256Verifier};
use std::cell::RefCell;

fn old_proof(token: &AccessToken, key: &Key) -> HttpRequest {
    let manage = token.manage.as_ref().unwrap();
    sign_request(
        HttpRequest::new("POST", &manage.uri)
            .json_body(serde_json::to_vec(&json!({"key": key})).unwrap()),
        old_key(),
        Some(&manage.access_token.value),
        NOW + 1,
    )
    .unwrap()
}

#[test]
fn a_key_change_requires_permission_to_replace_the_value_too() {
    let server = configured_server(
        true,
        Approve {
            key_rotation: true,
            value_rotation: false,
        },
        Keys,
    );
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

    // The same policy still uses the value-only refusal for a bodyless POST.
    let manage = tokens[0].manage.as_ref().unwrap();
    let ordinary = sign_request(
        HttpRequest::new("POST", &manage.uri),
        old_key(),
        Some(&manage.access_token.value),
        NOW + 1,
    )
    .unwrap();
    assert_eq!(
        error_code(&server.handle(&ordinary, NOW + 1)),
        "invalid_rotation"
    );
    unchanged(&server, &tokens[0], &before);
}

#[test]
fn an_expired_value_is_refused_before_value_rotation_permission() {
    for value_rotation in [false, true] {
        let server = configured_server(
            true,
            Approve {
                key_rotation: true,
                value_rotation,
            },
            Keys,
        );
        let tokens = grant(&server);
        let before = snapshot(&server, &tokens[0]);
        let request = rotate_request(&tokens[0], &presented(new_key()), None);
        // Proofs remain within the skew window at the exact token deadline.
        let response = server.handle(&request, NOW + 60);
        assert_eq!(error_code(&response), "invalid_rotation");
        let wire: Value = serde_json::from_slice(&response.body).unwrap();
        assert!(wire["error"]["description"]
            .as_str()
            .unwrap()
            .contains("lifetime"));
        unchanged(&server, &tokens[0], &before);
    }
}

#[test]
fn the_new_proof_must_match_the_public_key_in_the_body_not_just_its_kid() {
    let server = server(true, true);
    let tokens = grant(&server);
    let before = snapshot(&server, &tokens[0]);
    // The identifier matches, but the private key does not. A kid comparison
    // alone must not let the caller bind public material it cannot prove.
    let impostor = Ps256Signer::generate(2048, new_key().key_id()).unwrap();
    let previous = old_proof(&tokens[0], &Key::ByValue(Box::new(presented(new_key()))));
    let nonce = fresh_nonce().unwrap();
    let forged = add_new_proof_with_nonce(previous.clone(), &impostor, Some(nonce.clone()));
    let refused = server.handle(&forged, NOW + 1);
    assert_eq!(error_code(&refused), "invalid_rotation");
    assert!(refused.has_no_store());
    unchanged(&server, &tokens[0], &before);

    // Both nonces are reused. A failed proof must not reserve either half.
    let correct = add_new_proof_with_nonce(previous, new_key(), Some(nonce));
    let rotated = single(&server.handle(&correct, NOW + 1));
    assert_eq!(
        rotated.key,
        Some(Key::ByValue(Box::new(presented(new_key()))))
    );
}

#[test]
fn two_fresh_linked_proofs_can_retain_the_same_public_key() {
    let server = server(true, true);
    let tokens = grant(&server);
    let key = Key::ByValue(Box::new(presented(old_key())));
    let request = add_new_proof(old_proof(&tokens[0], &key), old_key());
    let rotated = single(&server.handle(&request, NOW + 1));
    assert_ne!(rotated.value, tokens[0].value);
    assert_eq!(rotated.key, Some(key));
    assert_eq!(rotated.access, tokens[0].access);
    assert_eq!(rotated.label, tokens[0].label);
    assert_eq!(rotated.flags, tokens[0].flags);
    assert_eq!(
        snapshot(&server, &tokens[1]).aggregate.tokens[handle(&tokens[1])].token,
        tokens[1]
    );
}

struct AliasKeys<'a>(&'a RefCell<KeyObject>);

impl KeyResolver for AliasKeys<'_> {
    fn resolve(&self, client: &Client) -> Option<Box<dyn Verifier>> {
        Keys.resolve(client)
    }

    fn resolve_token_key(
        &self,
        client: &Client,
        binding: Option<&Key>,
    ) -> Option<ResolvedTokenKey> {
        if binding.and_then(Key::as_reference) == Some("next-presentation-key") {
            let key = self.0.borrow().clone();
            let verifier = Ps256Verifier::from_public_jwk(key.jwk.as_ref()?).ok()?;
            Some(ResolvedTokenKey {
                key,
                verifier: Box::new(verifier),
            })
        } else {
            Keys.resolve_token_key(client, binding)
        }
    }
}

#[test]
fn a_resolved_reference_is_pinned_by_value_for_subsequent_management() {
    let alias = RefCell::new(presented(new_key()));
    let server = configured_server(
        true,
        Approve {
            key_rotation: true,
            value_rotation: true,
        },
        AliasKeys(&alias),
    );
    let tokens = grant(&server);
    let before = snapshot(&server, &tokens[0]);
    let reference: Key = serde_json::from_value(json!("next-presentation-key")).unwrap();
    let request = add_new_proof(old_proof(&tokens[0], &reference), new_key());
    let rotated = single(&server.handle(&request, NOW + 1));
    let expected = Some(Key::ByValue(Box::new(presented(new_key()))));
    assert_eq!(rotated.key, expected);
    let stored = snapshot(&server, &rotated);
    assert_eq!(
        stored.aggregate.tokens[handle(&rotated)].token.key,
        expected
    );
    assert_eq!(
        stored.aggregate.record.request,
        before.aggregate.record.request
    );

    // Changing the alias must not silently change an already proven binding.
    *alias.borrow_mut() = presented(old_key());
    let manage = rotated.manage.as_ref().unwrap();
    let old = sign_request(
        HttpRequest::new("POST", &manage.uri),
        old_key(),
        Some(&manage.access_token.value),
        NOW + 2,
    )
    .unwrap();
    assert_eq!(error_code(&server.handle(&old, NOW + 2)), "invalid_client");
    unchanged(&server, &rotated, &stored);
    let current = sign_request(
        HttpRequest::new("POST", &manage.uri),
        new_key(),
        Some(&manage.access_token.value),
        NOW + 2,
    )
    .unwrap();
    let refreshed = single(&server.handle(&current, NOW + 2));
    assert_eq!(refreshed.key, expected);
}

/// A verifier that a deployment supplies for an algorithm this SDK doesn't
/// know, here built on a PS256 key for the test.
struct CustomAlgorithm(Ps256Verifier);

impl Verifier for CustomAlgorithm {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), gnap_crypto::ProofError> {
        self.0.verify(data, signature)
    }
    fn algorithm(&self) -> &'static str {
        "X-CUSTOM"
    }
    fn expected_key_id(&self) -> Option<&str> {
        self.0.expected_key_id()
    }
}

/// A replacement key of `RS256`, which this SDK implements only for the JOSE
/// proofs, and which a deployment may still verify `httpsig` with.
fn rs256_key() -> &'static Rs256Signer {
    static KEY: OnceLock<Rs256Signer> = OnceLock::new();
    KEY.get_or_init(|| Rs256Signer::generate(2048, "replacement").unwrap())
}

/// Resolves a by-value key of either algorithm itself: the unknown one, and
/// `RS256` with its own verifier.
struct CustomKeys;

impl KeyResolver for CustomKeys {
    fn resolve(&self, client: &Client) -> Option<Box<dyn Verifier>> {
        Keys.resolve(client)
    }

    fn resolve_token_key(
        &self,
        client: &Client,
        binding: Option<&Key>,
    ) -> Option<ResolvedTokenKey> {
        let key = binding.and_then(Key::as_value);
        let jwk = key.and_then(|key| key.jwk.as_ref());
        let verifier: Box<dyn Verifier> = match jwk.and_then(|jwk| jwk.get("alg")?.as_str()) {
            Some("X-CUSTOM") => Box::new(CustomAlgorithm(new_key().verifier())),
            Some("RS256") => Box::new(Rs256Verifier::from_public_jwk(jwk?).ok()?),
            _ => return Keys.resolve_token_key(client, binding),
        };
        Some(ResolvedTokenKey {
            key: key?.clone(),
            verifier,
        })
    }
}

/// Adds the replacement key's proof to a key-change request.
type Prove = dyn Fn(HttpRequest) -> HttpRequest;

/// A public key of an algorithm this SDK doesn't implement for `httpsig`
/// reaches the configured resolver when presented by value, as it would by
/// reference: an unknown one, and `RS256`, which this SDK verifies only for
/// the JOSE proofs. The default resolver refuses both.
#[test]
fn a_custom_algorithm_by_value_is_left_to_the_configured_resolver() {
    let mut unknown = new_key().public_jwk().unwrap();
    unknown.insert("alg".into(), json!("X-CUSTOM"));
    let cases: [(_, &Prove); 2] = [
        (unknown, &|request| add_new_proof(request, new_key())),
        (rs256_key().public_jwk().unwrap(), &|request| {
            add_new_proof(request, rs256_key())
        }),
    ];
    for (jwk, prove) in cases {
        let alg = jwk["alg"].clone();
        let custom: Key =
            serde_json::from_value(json!({"proof": "httpsig", "jwk": Value::Object(jwk)})).unwrap();

        let configured = configured_server(
            true,
            Approve {
                key_rotation: true,
                value_rotation: true,
            },
            CustomKeys,
        );
        let tokens = grant(&configured);
        let rotated = single(&configured.handle(&prove(old_proof(&tokens[0], &custom)), NOW + 1));
        assert_eq!(rotated.key, Some(custom.clone()), "{alg}");

        let default = server(true, true);
        let tokens = grant(&default);
        assert_eq!(
            error_code(&default.handle(&prove(old_proof(&tokens[0], &custom)), NOW + 1)),
            "key_rotation_not_supported",
            "{alg}"
        );
    }
}

/// `EdDSA` with a curve other than Ed25519 reaches the resolver, while an
/// Ed25519 candidate without a usable curve is refused before it.
#[test]
fn an_eddsa_key_of_another_curve_is_left_to_the_resolver_but_a_missing_curve_is_not() {
    let okp = |crv: &Value| -> Key {
        let mut jwk = json!({"kty":"OKP","alg":"EdDSA","kid":"replacement",
            "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"});
        if !crv.is_null() {
            jwk["crv"] = crv.clone();
        }
        serde_json::from_value(json!({"proof":"httpsig","jwk":jwk})).unwrap()
    };
    // The default resolver doesn't implement Ed448, so it reports that it
    // can't rotate to it, instead of the early refusal of a malformed key.
    for (crv, expected) in [
        (json!("Ed448"), "key_rotation_not_supported"),
        (Value::Null, "invalid_rotation"),
        (json!(25519), "invalid_rotation"),
    ] {
        let server = server(true, true);
        let tokens = grant(&server);
        let request = add_new_proof(old_proof(&tokens[0], &okp(&crv)), new_key());
        assert_eq!(
            error_code(&server.handle(&request, NOW + 1)),
            expected,
            "{crv}"
        );
    }
}
