//! Token management (§6): rotation and revocation of an issued token.

use super::{
    check_presented_key, credential_used, error, key_rotation, method_not_allowed, misconfigured,
    no_content, ok, presented_key, storage_failure, AuthorizationServer,
};
use crate::encoding::TokenEncoder;
use crate::nonce::Nonces;
use crate::policy::{KeyResolver, Policy};
use crate::storage::{GrantSelector, GrantSnapshot, Storage, StoreError, TokenRecord};
use gnap_registry::ErrorCode;
use gnap_types::http::{HttpRequest, HttpResponse};
use gnap_types::message::GrantResponse;
use gnap_types::token::{AccessTokenResponse, BoundToken, TokenManage, TokenValue};

impl<P: Policy, K: KeyResolver, S: Storage, N: Nonces, E: TokenEncoder>
    AuthorizationServer<P, K, S, N, E>
{
    /// A call to the token management API (§6).
    ///
    /// §6 defines two actions: POST rotates the token's value (§6.1) and may
    /// bind a new key when enabled (§6.1.1); DELETE revokes it (§6.2). "Other
    /// actions are undefined by this specification", so nothing else is answered.
    ///
    /// `now` is the current time in seconds since the Unix epoch; see
    /// [`unix_now`](gnap_types::unix_now).
    pub fn handle_token_management(&self, request: &HttpRequest, now: u64) -> HttpResponse {
        let rotating = request.method.eq_ignore_ascii_case("POST");
        if !rotating && !request.method.eq_ignore_ascii_case("DELETE") {
            return method_not_allowed("POST, DELETE");
        }

        let handle = request
            .url
            .strip_prefix(&self.endpoints.token_management)
            .map(|rest| rest.trim_start_matches('/'))
            .unwrap_or_default();

        let Some(presented) = gnap_token(request) else {
            return error(
                ErrorCode::InvalidClient,
                "no token management access token was presented (RFC 9635 §6, §7.2)",
            );
        };

        let snapshot = match self.storage.lookup(GrantSelector::Management(handle)) {
            Ok(Some(snapshot)) => snapshot,
            Ok(None) => return invalid_management_credentials(),
            Err(failure) => return storage_failure(failure),
        };
        let Some(record) = snapshot.aggregate.tokens.get(handle) else {
            // §6 requires validation of the proof and its binding to the token.
            // This store retains no revoked-token key metadata, so it cannot
            // authenticate a request for a deleted handle. That prevents the
            // idempotent success recommended by §6.2-S04. Report the same error
            // as bad credentials for a live handle, without exposing existence.
            return invalid_management_credentials();
        };

        // §6-M04 — "The AS MUST uniquely identify the token being managed from
        // the token management URI, the token management access token, or a
        // combination of both." This server uses both: the handle finds the
        // record, and the token still has to be the one that record names.
        if record.management_token != presented {
            return invalid_management_credentials();
        }

        // Decide on the request shape before ordinary verification consumes a
        // nonce. A key-rotation body must never fall through to value rotation,
        // including when one of its two signatures is absent or invalid.
        if rotating
            && (request.body.as_ref().is_some_and(|body| !body.is_empty())
                || key_rotation::has_rotation_proof(request))
        {
            return self.rotate_bound_key(snapshot, handle, request, now);
        }

        // §6-M03 — "The AS MUST validate the proof and ensure that it is
        // associated with the token management access token." The record names
        // its current binding, which may differ from the original grant key.
        let resolved_binding = if let Some(binding) = record.token.key.as_ref() {
            let Some(resolved) = self.keys.resolve_token_key(&record.client, Some(binding)) else {
                return invalid_management_credentials();
            };
            if !key_rotation::resolved_binding_matches(binding, &resolved) {
                return misconfigured("the token key resolver changed a stored binding");
            }
            Some(resolved)
        } else {
            None
        };
        let verifier = match resolved_binding.as_ref() {
            Some(_) => None,
            None => self.keys.resolve(&record.client),
        };
        let verifier = resolved_binding
            .as_ref()
            .map(|resolved| resolved.verifier.as_ref())
            .or(verifier.as_deref());
        let Some(verifier) = verifier else {
            return error(
                ErrorCode::InvalidClient,
                "the client instance is not recognised",
            );
        };
        let presented_kid = match resolved_binding
            .as_ref()
            .map(|resolved| &resolved.key)
            .or_else(|| presented_key(&record.client))
        {
            None => None,
            Some(key) => match check_presented_key(key, verifier) {
                Ok(kid) => kid,
                Err(r) => return r,
            },
        };
        if let Err(r) = self.verify_signature(request, verifier, presented_kid, now) {
            return r;
        }

        if rotating {
            self.replace_token(snapshot, handle, now, None)
        } else {
            // §6.2-M02 — "the AS MUST invalidate the access token, if possible,
            // and return an HTTP response code 204."
            let mut replacement = snapshot.aggregate.clone();
            replacement.tokens.remove(handle);
            if let Err(failure) =
                self.storage
                    .compare_exchange(snapshot.id, snapshot.revision, replacement)
            {
                return storage_failure(failure);
            }
            no_content()
        }
    }

    /// Checks renewal time and value permission after request authentication.
    fn check_rotation_policy(
        &self,
        record: &TokenRecord,
        now: u64,
        key_change: bool,
    ) -> Result<(), HttpResponse> {
        // §6.1 — "If the AS is unable or unwilling to rotate the value of the
        // access token, the AS responds with an invalid_rotation error." The
        // client then "MUST consider the access token to not have changed its
        // state", so a refusal performs no storage write.
        // SDK policy, not an RFC requirement: an expired or not-yet-issued
        // value cannot be renewed. A clock rollback or an unrepresentable new
        // deadline must not extend it either. Keep all original metadata.
        if !rotation_permitted_at(record, now) {
            return Err(error(
                ErrorCode::InvalidRotation,
                "token lifetime prevents rotation (RFC 9635 §6.1)",
            ));
        }
        if !self.policy.may_rotate(&record.token) {
            // A key change also replaces the value, so both permissions are
            // required. Use the key-specific refusal for that request (§6.1.1).
            return Err(error(
                if key_change {
                    ErrorCode::KeyRotationNotSupported
                } else {
                    ErrorCode::InvalidRotation
                },
                "server policy prevents rotation",
            ));
        }
        Ok(())
    }

    /// Publishes a replacement value, optionally with a newly proven binding.
    pub(super) fn replace_token(
        &self,
        mut snapshot: GrantSnapshot,
        handle: &str,
        now: u64,
        binding: Option<gnap_types::key::Key>,
    ) -> HttpResponse {
        // Work on the authenticated snapshot. Publication is a single CAS;
        // the original stays visible while policy and encoding run.
        let Some(record) = snapshot.aggregate.tokens.get(handle).cloned() else {
            return error(
                ErrorCode::InvalidRotation,
                "no access token is managed at this URI (RFC 9635 §6)",
            );
        };
        if let Err(response) = self.check_rotation_policy(&record, now, binding.is_some()) {
            return response;
        }

        let (Ok(candidate), Ok(management_token)) = (
            TokenValue::new(self.nonces.next()),
            TokenValue::new(self.nonces.next()),
        ) else {
            return error(
                ErrorCode::InvalidRotation,
                "unable to generate valid token values",
            );
        };

        // §6.1 — "issuing a new access token in place of an existing access
        // token, with the same rights and properties as the original token,
        // apart from an updated token value and expiration time." §6.1-M05
        // makes the rights explicit: they "MUST be included in the response and
        // MUST be the same as the token before rotation". Even a key change
        // preserves the rights, label and flags of the original token.
        let rotated_handle = self.nonces.next();
        let mut rotated = record.clone();
        if let Some(binding) = binding {
            rotated.token.key = Some(binding);
        }
        let Ok(encoded) = self.encode_rotated_token(
            &rotated,
            &snapshot.aggregate,
            now,
            &candidate,
            &management_token,
        ) else {
            return error(
                ErrorCode::InvalidRotation,
                "unable to encode a replacement access token",
            );
        };
        // Keep the original until the replacement is fully validated. A failed
        // rotation leaves the existing token unchanged (§6.1).
        rotated.issued_at = now;
        rotated.token.value = encoded.value;
        rotated.identifier = encoded.identifier;
        // §6.1-M03 — the response includes a management URI, and it may differ
        // from the one just called; §6.1-M04 has the client use the new one.
        rotated.token.manage = Some(TokenManage {
            uri: format!(
                "{}/{}",
                self.endpoints.token_management.trim_end_matches('/'),
                rotated_handle
            ),
            access_token: BoundToken::new(management_token.clone()),
        });
        management_token
            .as_str()
            .clone_into(&mut rotated.management_token);

        // §6.1-MN02 refers to the CURRENT management token. Validating the new
        // token alone only compares with the replacement management token.
        let invalid = if record.identifier.is_some() && rotated.identifier == record.identifier {
            Some("the rotated token repeats its previous format identifier".into())
        } else if credential_used(&snapshot.aggregate, rotated.token.value.as_str()) {
            Some("the rotated value repeats an existing access or management token".into())
        } else {
            rotated.token.validate().err().map(|e| e.to_string())
        };
        if let Some(reason) = invalid {
            return error(ErrorCode::InvalidRotation, &reason);
        }

        let response = GrantResponse {
            access_token: Some(AccessTokenResponse {
                cardinality: gnap_types::Cardinality::Single,
                tokens: vec![rotated.token.clone()],
            }),
            ..GrantResponse::default()
        };
        // §6.1-M01 — "the AS MUST invalidate the current access token value
        // associated with this URI, if possible". The replacement and removal of all
        // old indexes publish together; a stale candidate cannot restore them.
        if rotated_handle != handle && snapshot.aggregate.tokens.contains_key(&rotated_handle) {
            return error(
                ErrorCode::InvalidRotation,
                "token management handle collision",
            );
        }
        snapshot.aggregate.tokens.remove(handle);
        snapshot.aggregate.tokens.insert(rotated_handle, rotated);
        if let Err(failure) =
            self.storage
                .compare_exchange(snapshot.id, snapshot.revision, snapshot.aggregate)
        {
            return if matches!(
                failure,
                StoreError::Conflict | StoreError::Collision | StoreError::Invalid
            ) {
                error(
                    ErrorCode::InvalidRotation,
                    "the replacement token could not be committed",
                )
            } else {
                storage_failure(failure)
            };
        }
        ok(&response)
    }
}

/// A GNAP token in the HTTP credentials grammar (RFC 9110 §11.1, §11.4).
/// Authorization is not a list field: duplicate instances are ambiguous.
pub(super) fn gnap_token(request: &HttpRequest) -> Option<&str> {
    let mut fields = request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"));
    let (_, value) = fields.next()?;
    if fields.next().is_some() {
        return None;
    }
    let (scheme, token) = value.trim_matches([' ', '\t']).split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("GNAP") {
        return None;
    }
    let token = token.trim_start_matches(' ');
    TokenValue::new(token.to_owned()).ok()?;
    Some(token)
}

fn invalid_management_credentials() -> HttpResponse {
    error(
        ErrorCode::InvalidClient,
        "the token management credentials could not be validated (RFC 9635 §6)",
    )
}

fn rotation_permitted_at(record: &TokenRecord, now: u64) -> bool {
    record.derivation.is_none()
        && record.is_valid_at(now)
        && record
            .token
            .expires_in
            .is_none_or(|seconds| now.checked_add(seconds).is_some())
}
