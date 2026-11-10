//! Downstream token derivation (RFC 9767 §4): a resource server exchanging a token it received.

use super::{
    ApprovedDerivation, AuthorizationServer, MAX_GRANT_BODY_BYTES, error, is_jose_content,
    misconfigured, ok, require_json_content, storage_failure,
};
use crate::nonce::Nonces;
use crate::policy::{KeyResolver, Policy};
use crate::storage::{
    DerivedGrantStore, GrantAggregate, GrantRecord, GrantSelector, Storage, StoreError, TokenRecord,
};
use gnap_core::{Event, Grant};
use gnap_registry::ErrorCode;
use gnap_types::client::Client;
use gnap_types::http::{HttpRequest, HttpResponse};
use gnap_types::message::{GrantRequest, GrantResponse};
use gnap_types::token::{AccessToken, AccessTokenResponse, BoundToken, TokenManage};

impl<P: Policy, K: KeyResolver, S: Storage + DerivedGrantStore, N: Nonces>
    AuthorizationServer<P, K, S, N>
{
    /// Opts the grant endpoint into the one-hop opaque downstream profile.
    ///
    /// This handler exists only for stores implementing [`DerivedGrantStore`];
    /// a deployment whose store lacks that capability cannot enable derivation.
    ///
    /// ```
    /// use gnap_as::{
    ///     AuthorizationServer, DerivationPolicy, DerivedGrantStore, KeyResolver,
    ///     Nonces, NonceStore, Policy, ResourceServerResolver, Storage,
    /// };
    /// use gnap_types::http::{HttpRequest, HttpResponse};
    /// # #[allow(dead_code)]
    /// fn handle<P: Policy, K: KeyResolver, S: Storage + DerivedGrantStore, N: Nonces>(
    ///     server: &AuthorizationServer<P, K, S, N>,
    ///     request: &HttpRequest,
    ///     keys: &impl ResourceServerResolver,
    ///     policy: &impl DerivationPolicy,
    ///     nonces: &dyn NonceStore,
    ///     clock: &dyn Fn() -> u64,
    /// ) -> HttpResponse {
    ///     server.handle_grant_with_derivation(request, keys, policy, nonces, clock)
    /// }
    /// ```
    ///
    /// The same code without the capability bound does not compile:
    ///
    /// ```compile_fail,E0599
    /// use gnap_as::{
    ///     AuthorizationServer, DerivationPolicy, KeyResolver,
    ///     Nonces, NonceStore, Policy, ResourceServerResolver, Storage,
    /// };
    /// use gnap_types::http::{HttpRequest, HttpResponse};
    /// # #[allow(dead_code)]
    /// fn handle<P: Policy, K: KeyResolver, S: Storage, N: Nonces>(
    ///     server: &AuthorizationServer<P, K, S, N>,
    ///     request: &HttpRequest,
    ///     keys: &impl ResourceServerResolver,
    ///     policy: &impl DerivationPolicy,
    ///     nonces: &dyn NonceStore,
    ///     clock: &dyn Fn() -> u64,
    /// ) -> HttpResponse {
    ///     server.handle_grant_with_derivation(request, keys, policy, nonces, clock)
    /// }
    /// ```
    ///
    /// All POST grant bodies entering this handler are bounded to [`MAX_GRANT_BODY_BYTES`];
    /// ordinary requests then follow the normal flow. Derivation allows
    /// one token, no interaction/user/subject/continuation, and a finite
    /// parent. RS proof uses the trusted RS registry and separate replay memory.
    /// Every identity recognized by this derivation resolver must also resolve
    /// through [`KeyResolver`] to a verifier accepting the same proof, so child
    /// management remains usable. Restrict this resolver to eligible requester
    /// identities; it need not admit every RS known to introspection.
    /// The policy must establish parent suitability for this precise RS and the
    /// cross-API rights mapping. The child is bound to RS1, destined for another
    /// RS, and expires within 60 seconds and no later than its parent.
    ///
    /// `clock` is a trusted Unix-seconds source, reread after proof/policy and at
    /// the storage commit. It must be brief, non-reentrant and side-effect-free;
    /// the memory store calls it under its transaction lock. Neither this method
    /// nor the store retries policy, proof or a failed commit automatically.
    pub fn handle_grant_with_derivation(
        &self,
        request: &HttpRequest,
        keys: &impl crate::ResourceServerResolver,
        policy: &impl crate::DerivationPolicy,
        nonces: &dyn crate::NonceStore,
        clock: &dyn Fn() -> u64,
    ) -> HttpResponse {
        let now = clock();
        if request.url != self.endpoints.grant || !request.method.eq_ignore_ascii_case("POST") {
            return self.handle(request, now);
        }
        let Some(bytes) = request
            .body
            .as_deref()
            .filter(|body| body.len() <= MAX_GRANT_BODY_BYTES)
        else {
            return error(ErrorCode::InvalidRequest, "invalid grant request");
        };
        // An attached JWS is an ordinary grant request, within the same bound:
        // this handler derives only from requests proven with `httpsig`.
        if is_jose_content(request) {
            return self.handle(request, now);
        }
        let Ok(raw) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return error(ErrorCode::InvalidRequest, "invalid grant request");
        };
        if raw.get("existing_access_token").is_none() {
            return self.handle(request, now);
        }
        if let Err(response) = require_json_content(request) {
            return response;
        }
        let Ok(body) = serde_json::from_slice::<GrantRequest>(bytes) else {
            return error(ErrorCode::InvalidRequest, "invalid downstream request");
        };
        let Some(value) = body.existing_access_token.as_ref() else {
            return derivation_denied();
        };
        let identity = match derivation_identity(&body, &raw, request) {
            Ok(identity) => identity,
            Err(response) => return response,
        };
        // RFC 9767 §4: "the RS MUST identify itself with its own key in the client
        // field and sign the request just as any client instance would".
        let Some(rs) = crate::rs::authenticate_rs(keys, nonces, request, &identity, now) else {
            return derivation_denied();
        };
        if self.keys.resolve(&body.client).is_none_or(|verifier| {
            !crate::derivation::management_binding(request, &rs.key, verifier.as_ref(), now)
        }) {
            return misconfigured("inconsistent downstream management key");
        }
        let parent = match self
            .storage
            .lookup(GrantSelector::AccessToken(value.as_str()))
        {
            Ok(Some(parent)) => parent,
            Ok(None) => return derivation_denied(),
            Err(failure) => return storage_failure(failure),
        };
        let Some(source) = parent
            .aggregate
            .tokens
            .values()
            .find(|token| &token.token.value == value)
        else {
            return derivation_denied();
        };
        if parent.aggregate.revoked
            || !source.is_valid_at(now)
            || source.derivation.is_some()
            || source.identifier.is_some()
            || !source.token.flags.is_empty()
            || !source.token.extra.is_empty()
            || source.expires_at().is_none()
        {
            return derivation_denied();
        }
        // RFC 9767 §4: "The AS MUST determine that the token being presented is
        // appropriate for use at the RS making the token chaining request."
        let Some(approved) = policy.evaluate(&body, &rs, &parent, source) else {
            return derivation_denied();
        };
        if approved.audience == rs.id
            || approved.audience.0.is_empty()
            || approved.access.is_empty()
            || approved.access.len() > 64
        {
            return derivation_denied();
        }
        let issued_at = clock();
        let Some(ttl) = source
            .expires_at()
            .and_then(|deadline| deadline.checked_sub(issued_at))
            .filter(|ttl| *ttl > 0)
            .map(|ttl| ttl.min(crate::derivation::MAX_DERIVED_LIFETIME))
        else {
            return derivation_denied();
        };
        if issued_at < now || !source.is_valid_at(issued_at) {
            return derivation_denied();
        }
        self.issue_derived(
            ApprovedDerivation {
                request: body,
                access: approved,
                requester: rs,
                parent,
                issued_at,
                ttl,
            },
            clock,
        )
    }

    fn issue_derived(&self, approved: ApprovedDerivation, clock: &dyn Fn() -> u64) -> HttpResponse {
        let ApprovedDerivation {
            request: body,
            access: approved,
            requester: rs,
            parent,
            issued_at,
            ttl,
        } = approved;
        let Some(value) = body.existing_access_token.as_ref() else {
            return derivation_denied();
        };
        let Some(tokens) = body.access_token.as_ref() else {
            return derivation_denied();
        };
        // This snapshot reserves against parent/sibling credential collisions;
        // it does not copy or continue the parent grant's continuation.
        let prepared = match self.encode_issued_with_lifetime(
            &body,
            &approved.access,
            issued_at,
            false,
            Some(&parent),
            Some(ttl),
        ) {
            Ok(prepared) => prepared,
            Err(response) => return response,
        };
        let token = AccessToken {
            value: prepared.encoded.value,
            label: tokens.tokens[0].label.clone(),
            manage: Some(TokenManage {
                uri: format!(
                    "{}/{}",
                    self.endpoints.token_management.trim_end_matches('/'),
                    prepared.management
                ),
                access_token: BoundToken::new(prepared.management_token.clone()),
            }),
            access: Some(approved.access),
            expires_in: Some(ttl),
            key: Some(gnap_types::key::Key::ByValue(Box::new(rs.key))),
            flags: Vec::new(),
            extra: serde_json::Map::new(),
        };
        if token.validate().is_err() {
            return misconfigured("invalid derived token preparation");
        }
        let mut grant = Grant::new();
        if grant.apply(Event::AsNeedsNoInteraction, issued_at).is_err() {
            return misconfigured("invalid derived grant state");
        }
        let mut stored_request = body.clone();
        stored_request.existing_access_token = None;
        let mut child = GrantAggregate::new(GrantRecord {
            grant,
            request: stored_request,
            continuation_token: None,
            as_nonce: None,
            user_code: None,
            interact_handle: None,
            interact_expires_at: None,
            interact_ref: None,
            interaction_completed: false,
        });
        child.tokens.insert(
            prepared.management,
            TokenRecord {
                derivation: Some(crate::DerivedToken {
                    parent: crate::ParentToken::new(parent.id, value),
                    audience: approved.audience,
                }),
                identifier: None,
                issued_at,
                token: token.clone(),
                client: body.client,
                management_token: prepared.management_token.as_str().into(),
            },
        );
        match self
            .storage
            .create_derived(parent.id, parent.revision, value, child, clock)
        {
            Ok(_) => ok(&GrantResponse {
                access_token: Some(AccessTokenResponse {
                    cardinality: gnap_types::Cardinality::Single,
                    tokens: vec![token],
                }),
                ..GrantResponse::default()
            }),
            Err(StoreError::Conflict | StoreError::DerivationLimit) => derivation_denied(),
            Err(failure) => storage_failure(failure),
        }
    }
}

fn derivation_identity(
    body: &GrantRequest,
    raw: &serde_json::Value,
    request: &HttpRequest,
) -> Result<gnap_types::rs::ResourceServer, HttpResponse> {
    let Some(tokens) = body.access_token.as_ref() else {
        return Err(derivation_denied());
    };
    if request
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        || ["interact", "user", "subject"]
            .iter()
            .any(|field| raw.get(field).is_some())
        || !body.extra.is_empty()
        || tokens.cardinality != gnap_types::Cardinality::Single
        || tokens.tokens.len() != 1
        || tokens.tokens[0].access.is_empty()
        || tokens.tokens[0].access.len() > 64
        || !tokens.tokens[0].flags.is_empty()
        || !tokens.tokens[0].extra.is_empty()
    {
        return Err(error(
            ErrorCode::InvalidRequest,
            "unsupported downstream request shape",
        ));
    }
    match &body.client {
        Client::ByReference(reference) => Ok(gnap_types::rs::ResourceServer::ByReference(
            reference.clone(),
        )),
        Client::ByValue(client) => {
            if !client.extra.is_empty() || client.display.is_some() || client.class_id.is_some() {
                return Err(error(
                    ErrorCode::InvalidRequest,
                    "unsupported downstream client fields",
                ));
            }
            Ok(gnap_types::rs::ResourceServer::ByValue(Box::new(
                gnap_types::rs::ResourceServerObject {
                    key: client.key.clone(),
                    extra: serde_json::Map::new(),
                },
            )))
        }
    }
}

fn derivation_denied() -> HttpResponse {
    error(ErrorCode::RequestDenied, "downstream derivation denied")
}
