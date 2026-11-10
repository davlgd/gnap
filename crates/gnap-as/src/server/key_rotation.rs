//! Optional token-bound key rotation, separate from bodyless value rotation.
//!
//! Shape, public-key and bearer checks precede the capability check. This is
//! the SDK's refusal order: RFC 9635 §6.1.1 (invalid proof, changed proof method
//! or bearer token, and lack of permission or capability) names the errors
//! without assigning precedence when several conditions apply to one request.

use super::{
    AuthorizationServer, BothKeys, GrantSnapshot, HttpRequest, HttpResponse, KeyResolver,
    MAX_CLOCK_SKEW, Nonces, Policy, Storage, TokenEncoder, check_presented_key, error,
    misconfigured, require_json_content, signed_request,
};
use crate::ResolvedTokenKey;
use crate::policy::parameterless_proof;
use gnap_crypto::jws::{JwsMethod, ReplayId, unverified_rotation_content, verify_jws_rotation};
use gnap_crypto::{Expectations, PublicKey, RotationProof, Verifier as _, verify_key_rotation};
use gnap_registry::{ErrorCode, KeyProofingMethod};
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
        let Some(record) = snapshot.aggregate.tokens.get(handle) else {
            return invalid_rotation("the managed token is no longer available");
        };
        let stored = record
            .token
            .key
            .as_ref()
            .or_else(|| record.client.as_value().map(|client| &client.key));
        // The current binding's proof method decides how the request carries
        // the new key and both proofs (§6.1.1, §7.3.3.1, §7.3.4.1).
        let jose = jose_method(stored.and_then(Key::as_value));
        let presented = match requested_key(request, jose) {
            Ok(key) => key,
            Err(response) => return response,
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
        if jose.is_some() && self.jose.is_none() {
            return unsupported();
        }
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
        let enabled = self.jose.is_some();
        if !valid_resolved_key(&previous, enabled)
            || stored.is_some_and(|key| !resolved_binding_matches(key, &previous, enabled))
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
        if !resolved_binding_matches(&presented, &replacement, enabled) {
            return misconfigured("the token key resolver changed the requested public binding");
        }
        if !same_proof(&previous.key.proof, &replacement.key.proof) {
            return invalid_rotation("key rotation cannot change the proof method or parameters");
        }
        if !valid_resolved_key(&replacement, enabled) {
            return misconfigured(
                "the token key resolver returned an unusable replacement binding",
            );
        }
        let proven = jose.map_or_else(
            || {
                let remember = |old: Option<&str>, new: Option<&str>, at: u64| {
                    reserve(&self.storage, old, new, at)
                };
                verify_key_rotation(
                    &signed_request(request),
                    &required_proof(&previous, now),
                    &required_proof(&replacement, now),
                    &remember,
                )
                .is_ok()
            },
            |method| {
                self.verify_jose_rotation(method, request, &presented, &previous, &replacement, now)
            },
        );
        if !proven {
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

    /// Verifies the nested JOSE proofs of a key rotation: the previous key
    /// signs the request with the rotation `typ`, and the replacement signs
    /// that proof. Both verify under the JWK and the resolver's key, and are
    /// reserved together. The key the authenticated content asks for has to
    /// be the one the unverified content claimed.
    fn verify_jose_rotation(
        &self,
        method: JwsMethod,
        request: &HttpRequest,
        presented: &Key,
        previous: &ResolvedTokenKey,
        replacement: &ResolvedTokenKey,
        now: u64,
    ) -> bool {
        let (Some(reserve), Some(old), Some(new)) = (
            self.jose,
            jose_public(&previous.key),
            jose_public(&replacement.key),
        ) else {
            return false;
        };
        let old = BothKeys {
            presented: &old,
            resolved: previous.verifier.as_ref(),
        };
        let new = BothKeys {
            presented: &new,
            resolved: replacement.verifier.as_ref(),
        };
        let reserve = |ids: &[ReplayId], at: u64| reserve(&self.storage, ids, at);
        verify_jws_rotation(
            method,
            &signed_request(request),
            &old.jws_key(now),
            &new.jws_key(now),
            &reserve,
        )
        .is_ok_and(|accepted| key_in(&accepted.content, request).is_ok_and(|key| &key == presented))
    }
}

/// The JOSE method of a key, if it proves with one.
fn jose_method(key: Option<&KeyObject>) -> Option<JwsMethod> {
    match key?.proof.method() {
        KeyProofingMethod::Jws => Some(JwsMethod::Jws),
        KeyProofingMethod::Jwsd => Some(JwsMethod::Jwsd),
        _ => None,
    }
}

/// The public JWK of a JOSE key.
fn jose_public(key: &KeyObject) -> Option<PublicKey> {
    PublicKey::for_jws(key.jwk.as_ref()?).ok()
}

/// The key a rotation asks for, read before any proof is verified: from the
/// JSON content, or for `jws` from the inner JWS that the attached one carries.
fn requested_key(request: &HttpRequest, jose: Option<JwsMethod>) -> Result<Key, HttpResponse> {
    let Some(body) = request.body.as_deref().filter(|body| !body.is_empty()) else {
        return Err(invalid_rotation(
            "key rotation requires a JSON body containing key",
        ));
    };
    if body.len() > super::MAX_GRANT_BODY_BYTES {
        return Err(error(
            ErrorCode::InvalidRequest,
            "key-rotation content exceeds the size limit",
        ));
    }
    if jose == Some(JwsMethod::Jws) {
        let content = unverified_rotation_content(&signed_request(request))
            .map_err(|_| invalid_rotation("the key rotation's attached JWS cannot be read"))?;
        return key_in(&content, request);
    }
    require_json_content(request)?;
    key_in(body, request)
}

/// The `key` member of a rotation's JSON content, with its public checks.
fn key_in(content: &[u8], request: &HttpRequest) -> Result<Key, HttpResponse> {
    let raw: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(content).map_err(|_| {
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
        // A built-in algorithm is checked here; any other public key is left to
        // the configured resolver, by value as by reference.
        if let Some(jwk) = object
            .jwk
            .as_ref()
            .filter(|_| object.proof.method() == &KeyProofingMethod::Httpsig)
            .filter(|jwk| gnap_crypto::PublicKey::is_builtin_for_httpsig(jwk))
        {
            if gnap_crypto::PublicKey::for_httpsig(jwk).is_err() {
                return Err(invalid_rotation(
                    "the requested public key cannot be used with httpsig",
                ));
            }
        }
    } else if key.as_reference().is_none_or(str::is_empty) {
        return Err(invalid_rotation("the requested key reference is empty"));
    }
    Ok(key)
}

/// A resolver may expand a reference, but may not substitute a by-value key.
///
/// `jose` says whether the server accepts the JOSE proofs, without which a
/// `jws` or `jwsd` binding isn't one it can use.
pub(super) fn resolved_binding_matches(
    binding: &Key,
    resolved: &ResolvedTokenKey,
    jose: bool,
) -> bool {
    binding.as_value().is_none_or(|key| key == &resolved.key) && valid_resolved_key(resolved, jose)
}

fn valid_resolved_key(resolved: &ResolvedTokenKey, jose: bool) -> bool {
    if !public_key(&resolved.key) || !parameterless_proof(&resolved.key.proof) {
        return false;
    }
    if jose_method(Some(&resolved.key)).is_some() {
        return jose
            && jose_public(&resolved.key)
                .is_some_and(|public| public.algorithm() == resolved.verifier.algorithm());
    }
    resolved.key.proof.method() == &KeyProofingMethod::Httpsig
        && check_presented_key(&resolved.key, resolved.verifier.as_ref()).is_ok()
}

/// Whether `key` presents a public key: `KeyObject::validate` refuses a JWK
/// with a private member, even null, and a certificate field must not hold a
/// private key, which the shape validator doesn't parse.
fn public_key(key: &KeyObject) -> bool {
    key.validate().is_ok()
        && !key
            .cert
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
    if !request.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("signature-input") && value.contains("gnap-rotate")
    }) {
        return false;
    }
    // Bound allocation and parsing of a possible rotation hint. Oversized hints
    // route to refusal, never to bodyless value rotation; they are not proofs.
    // Ordinary requests without this hint keep their existing verification path.
    let mut size = 0_usize;
    for field in ["signature", "signature-input"] {
        for (index, (_, value)) in request
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(field))
            .enumerate()
        {
            size = size
                .saturating_add(value.len())
                .saturating_add(usize::from(index > 0) * 2);
            if size > gnap_crypto::rotation::MAX_ROTATION_SIGNATURE_BYTES {
                return true;
            }
        }
    }
    let Some(input) = request.combined_header_value("signature-input") else {
        return false;
    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use gnap_crypto::rotation::MAX_ROTATION_SIGNATURE_BYTES;

    #[test]
    fn rotation_hint_size_includes_both_fields_and_repeated_field_separators() {
        for field in ["SiGnAtUrE", "SiGnAtUrE-InPuT"] {
            for split in [false, true] {
                let mut request = HttpRequest::new("POST", "https://as.example/manage");
                request.headers = vec![
                    (
                        "Signature-Input".into(),
                        "unmatched=();tag=\"gnap-rotate\"".into(),
                    ),
                    ("Signature".into(), "invalid".into()),
                ];
                let index = if split {
                    request.headers.push((field.into(), String::new()));
                    2
                } else {
                    usize::from(field.eq_ignore_ascii_case("signature"))
                };
                let used: usize = request.headers.iter().map(|(_, value)| value.len()).sum();
                let separators = usize::from(split) * 2;
                request.headers[index]
                    .1
                    .push_str(&" ".repeat(MAX_ROTATION_SIGNATURE_BYTES - used - separators));
                assert!(
                    !has_rotation_proof(&request),
                    "at the limit, malformed proofs are parsed"
                );
                request.headers[index].1.push(' ');
                assert!(
                    has_rotation_proof(&request),
                    "above the limit, parsing is bypassed"
                );
            }
        }
    }

    #[test]
    fn oversized_ordinary_fields_are_not_rotation_hints() {
        let mut request = HttpRequest::new("POST", "https://as.example/manage");
        request.headers.push((
            "Signature-Input".into(),
            "x".repeat(MAX_ROTATION_SIGNATURE_BYTES + 1),
        ));
        assert!(!has_rotation_proof(&request));
    }
}
