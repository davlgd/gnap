//! Optional token-bound key rotation, separate from bodyless value rotation.
//!
//! Shape, public-key and bearer checks precede the capability check. This is
//! the SDK's refusal order: RFC 9635 §6.1.1 (invalid proof, changed proof method
//! or bearer token, and lack of permission or capability) names the errors
//! without assigning precedence when several conditions apply to one request.

use super::{
    check_presented_key, error, misconfigured, require_json_content, AuthorizationServer,
    GrantSnapshot, HttpRequest, HttpResponse, KeyResolver, Nonces, Policy, Storage, TokenEncoder,
    MAX_CLOCK_SKEW,
};
use crate::policy::parameterless_proof;
use crate::ResolvedTokenKey;
use gnap_crypto::{verify_key_rotation, Expectations, RotationProof, SignedRequest};
use gnap_registry::ErrorCode;
use gnap_types::key::{Key, KeyObject, Proof};

impl<P: Policy, K: KeyResolver, S: Storage, N: Nonces, E: TokenEncoder>
    AuthorizationServer<P, K, S, N, E>
{
    pub(super) fn rotate_bound_key(
        &self,
        snapshot: GrantSnapshot,
        handle: &str,
        request: &HttpRequest,
        now: u64,
    ) -> HttpResponse {
        let presented = match requested_key(request) {
            Ok(key) => key,
            Err(response) => return response,
        };
        let Some(record) = snapshot.aggregate.tokens.get(handle) else {
            return invalid_rotation("the managed token is no longer available");
        };
        // A bearer token has no presentation key to replace (§6.1.1).
        if record.token.is_bearer() {
            return invalid_rotation("a bearer token has no bound key to rotate");
        }
        // The reservation was captured with the capability; without it there is
        // no atomic nonce pair and therefore no key rotation on this server.
        let Some(reserve) = self.key_rotation else {
            return unsupported();
        };
        if record.derivation.is_some() {
            // This SDK's one-hop profile binds a child to the downstream RS
            // and an exact parent; rebinding that child is outside the profile.
            return unsupported();
        }
        let Some(previous) = self
            .keys
            .resolve_token_key(&record.client, record.token.key.as_ref())
        else {
            return unsupported();
        };
        let stored = record
            .token
            .key
            .as_ref()
            .or_else(|| record.client.as_value().map(|client| &client.key));
        if !valid_resolved_key(&previous)
            || stored.is_some_and(|key| !resolved_binding_matches(key, &previous))
        {
            return misconfigured(
                "the token key resolver returned an inconsistent current binding",
            );
        }
        // A changed method or parameter is invalid even if its implementation
        // would otherwise be unsupported (§6.1.1). By-value input is available
        // for this check before resolving its cryptographic implementation.
        if presented
            .as_value()
            .is_some_and(|key| !same_proof(&previous.key.proof, &key.proof))
        {
            return invalid_rotation("key rotation cannot change the proof method or parameters");
        }
        let Some(replacement) = self
            .keys
            .resolve_token_key(&record.client, Some(&presented))
        else {
            return unsupported();
        };
        if !resolved_binding_matches(&presented, &replacement) {
            return misconfigured("the token key resolver changed the requested public binding");
        }
        if !same_proof(&previous.key.proof, &replacement.key.proof) {
            return invalid_rotation("key rotation cannot change the proof method or parameters");
        }
        if !valid_resolved_key(&replacement) {
            return misconfigured(
                "the token key resolver returned an unusable replacement binding",
            );
        }
        let old_proof = required_proof(&previous, now);
        let new_proof = required_proof(&replacement, now);
        let remember =
            |old: Option<&str>, new: Option<&str>, at: u64| reserve(&self.storage, old, new, at);
        let proof = verify_key_rotation(
            &SignedRequest {
                method: &request.method,
                target_uri: &request.url,
                headers: &request.headers,
                body: request.body.as_deref(),
            },
            &old_proof,
            &new_proof,
            &remember,
        );
        if proof.is_err() {
            // §6.1.1 requires this code when either key's proof is missing or
            // invalid. Do not disclose signature parameters or key material.
            return invalid_rotation("both linked key proofs must be valid and fresh");
        }
        if !self.policy.may_rotate_key(record, &replacement.key) {
            return unsupported();
        }
        // The response names the public binding explicitly. Omitting `key`
        // would denote the original grant-request key under §3.2.1.
        self.replace_token(
            snapshot,
            handle,
            now,
            Some(Key::ByValue(Box::new(replacement.key))),
        )
    }
}

fn requested_key(request: &HttpRequest) -> Result<Key, HttpResponse> {
    let Some(body) = request.body.as_deref().filter(|body| !body.is_empty()) else {
        return Err(invalid_rotation(
            "key rotation requires a JSON body containing key",
        ));
    };
    // An implementation bound, before JSON parsing; not a GNAP message limit.
    if body.len() > 64 * 1024 {
        return Err(error(
            ErrorCode::InvalidRequest,
            "key-rotation content exceeds the size limit",
        ));
    }
    require_json_content(request)?;
    let raw: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(body).map_err(|_| {
            error(
                ErrorCode::InvalidRequest,
                "key rotation requires a JSON object",
            )
        })?;
    let value = raw.get("key").ok_or_else(|| {
        if has_rotation_proof(request) {
            invalid_rotation("key rotation requires the new key in its JSON body")
        } else {
            error(
                ErrorCode::InvalidRequest,
                "value rotation is bodyless; key rotation requires key",
            )
        }
    })?;
    let key: Key = serde_json::from_value(value.clone())
        .map_err(|_| invalid_rotation("the requested key cannot be read"))?;
    if let Some(object) = key.as_value() {
        if !public_key(object) {
            return Err(invalid_rotation(
                "the requested key must contain only public key material",
            ));
        }
        if let Some(jwk) = object.jwk.as_ref().filter(|jwk| {
            jwk.get("kty").and_then(serde_json::Value::as_str) == Some("RSA")
                && jwk.get("alg").and_then(serde_json::Value::as_str) == Some("PS256")
        }) {
            if gnap_crypto::Ps256Verifier::from_public_jwk(jwk).is_err() {
                return Err(invalid_rotation(
                    "the requested public PS256 key cannot be used",
                ));
            }
        }
    } else if key.as_reference().is_none_or(str::is_empty) {
        return Err(invalid_rotation("the requested key reference is empty"));
    }
    Ok(key)
}

/// A resolver may expand a reference, but may not substitute a by-value key.
pub(super) fn resolved_binding_matches(binding: &Key, resolved: &ResolvedTokenKey) -> bool {
    binding.as_value().is_none_or(|key| key == &resolved.key) && valid_resolved_key(resolved)
}

fn valid_resolved_key(resolved: &ResolvedTokenKey) -> bool {
    public_key(&resolved.key)
        && resolved.key.proof.method().as_str() == "httpsig"
        && parameterless_proof(&resolved.key.proof)
        && check_presented_key(&resolved.key, resolved.verifier.as_ref()).is_ok()
}

fn public_key(key: &KeyObject) -> bool {
    if key.validate().is_err() {
        return false;
    }
    if let Some(jwk) = &key.jwk {
        // KeyObject's shape validator is not a complete JWK parser. Explicitly
        // refuse private members even when null; actual key parsing belongs to
        // the resolver (the default uses the bounded public PS256 parser).
        if ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
            .iter()
            .any(|field| jwk.contains_key(*field))
        {
            return false;
        }
    }
    !key.cert
        .as_ref()
        .is_some_and(|pem| pem.contains("PRIVATE KEY"))
}

fn same_proof(previous: &Proof, replacement: &Proof) -> bool {
    if previous.method() != replacement.method() {
        return false;
    }
    if parameterless_proof(previous) && parameterless_proof(replacement) {
        return true;
    }
    previous == replacement
}

fn invalid_rotation(message: &str) -> HttpResponse {
    error(ErrorCode::InvalidRotation, message)
}

fn unsupported() -> HttpResponse {
    error(
        ErrorCode::KeyRotationNotSupported,
        "this token's key cannot be rotated by this server",
    )
}

/// An unauthenticated routing hint, never evidence of possession or permission.
pub(super) fn has_rotation_proof(request: &HttpRequest) -> bool {
    let Some(input) = request.combined_header_value("signature-input") else {
        return false;
    };
    if !input.contains("gnap-rotate") {
        return false;
    }
    let Some(signature) = request.combined_header_value("signature") else {
        return false;
    };
    gnap_crypto::parse_signatures(&input, &signature)
        .into_iter()
        .flatten()
        .any(|candidate| {
            gnap_crypto::parse_signature_params(&candidate.raw_params)
                .is_ok_and(|params| params.tag.as_deref() == Some("gnap-rotate"))
        })
}

fn required_proof(key: &ResolvedTokenKey, now: u64) -> RotationProof<'_> {
    RotationProof {
        verifier: key.verifier.as_ref(),
        expectations: Expectations {
            now,
            max_clock_skew: MAX_CLOCK_SKEW,
            key_id: key.key.jwk_key_id(),
        },
        policy: &|params| {
            params
                .nonce
                .as_deref()
                .is_some_and(|nonce| !nonce.is_empty())
        },
    }
}
