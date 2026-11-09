//! Grant requests: classification, policy evaluation, issuance, and interaction offers.

use super::{
    error, method_not_allowed, misconfigured, modifies, not_found, ok, require_json_content,
    storage_failure, AuthorizationServer, INTERACTION_LIFETIME,
};
use crate::encoding::TokenEncoder;
use crate::nonce::Nonces;
use crate::policy::{Decision, EvaluationContext, KeyResolver, Policy, TokenApproval};
use crate::storage::{GrantAggregate, GrantRecord, GrantSnapshot, Storage};
use gnap_core::{Event, Grant, State};
use gnap_registry::{ErrorCode, InteractionFinishMethod};
use gnap_types::http::{HttpRequest, HttpResponse};
use gnap_types::interact::{InteractFinish, InteractResponse, UserCodeUri};
use gnap_types::message::{Continue, ContinueRequest, GrantRequest, GrantResponse};
use gnap_types::token::{BoundToken, TokenValue};

impl<P: Policy, K: KeyResolver, S: Storage, N: Nonces, E: TokenEncoder>
    AuthorizationServer<P, K, S, N, E>
{
    /// `now` is the current time in seconds since the Unix epoch; see
    /// [`unix_now`](gnap_types::unix_now).
    ///
    /// A new grant request (§2).
    pub fn handle_grant_request(&self, request: &HttpRequest, now: u64) -> HttpResponse {
        // §2 — "The request MUST be sent as a JSON object in the content of the
        // HTTP POST request with Content-Type application/json."
        if !request.method.eq_ignore_ascii_case("POST") {
            return method_not_allowed("POST, OPTIONS");
        }
        // §4.2.3 hashes "the grant endpoint URI the client instance used to
        // make its initial request", and this server hashes the endpoint it was
        // configured with. Serving a grant request at any other URL would make
        // the two differ, and every interaction hash wrong.
        if request.url != self.endpoints.grant {
            return not_found();
        }
        if let Err(r) = require_json_content(request) {
            return r;
        }

        let body = match Self::parse::<GrantRequest>(request) {
            Ok(b) => b,
            Err(r) => return r,
        };
        if body.existing_access_token.is_some() {
            return error(
                ErrorCode::InvalidRequest,
                "downstream derivation is not enabled on this handler",
            );
        }

        // §7.1 — a key sent by value is presented in exactly one format, and a
        // JWK carries `alg` and `kid`. The AS checks that before trying to use
        // it: a key it cannot read is a request it cannot verify.
        if let Some(key) = presented_key(&body.client) {
            if let Err(e) = key.validate() {
                return error(ErrorCode::InvalidClient, &e.to_string());
            }
        }

        // §2.4.1 — a user reference is one the AS itself handed out. One it
        // does not know is not a hint to ignore; the RFC names the answer.
        if let Some(reference) = body
            .user
            .as_ref()
            .and_then(gnap_types::user::User::as_reference)
        {
            if !self.policy.recognises_user(reference) {
                return error(
                    ErrorCode::UnknownUser,
                    "the user reference is not one this AS recognises (RFC 9635 §2.4.1)",
                );
            }
        }

        // §2.3.2 — the display information is shown to the RO on a page the AS
        // serves, so its URIs have to stand on their own.
        if let Some(display) = body.client.as_value().and_then(|c| c.display.as_ref()) {
            if let Err(e) = display.validate() {
                return error(ErrorCode::InvalidClient, &e.to_string());
            }
        }

        // §2.5.2 — a callback the AS cannot use is refused now, not at the end
        // of an interaction the RO has already been through.
        if let Some(finish) = body.interact.as_ref().and_then(|i| i.finish.as_ref()) {
            if let Err(reason) = supported_finish(finish) {
                return error(ErrorCode::InvalidRequest, &reason);
            }
        }

        // §2.3 — the client identifies itself, and the AS resolves its key.
        let Some(verifier) = self.keys.resolve(&body.client) else {
            return error(
                ErrorCode::InvalidClient,
                "the client instance is not recognised",
            );
        };

        // §7.3.1-M15 — when the key is a JWK, the signature names it by its
        // `kid` and uses the algorithm its `alg` declares.
        let presented_kid = match presented_key(&body.client) {
            None => None,
            Some(key) => match check_presented_key(key, verifier.as_ref()) {
                Ok(kid) => kid,
                Err(r) => return r,
            },
        };

        if let Err(r) = self.verify_signature(request, verifier.as_ref(), presented_kid, now) {
            return r;
        }

        let decision = self
            .policy
            .evaluate_context(&body, EvaluationContext::Initial);
        let mut aggregate = GrantAggregate::new(GrantRecord {
            grant: Grant::new(),
            request: body,
            continuation_token: None,
            as_nonce: None,
            user_code: None,
            interact_handle: None,
            interact_expires_at: None,
            interact_ref: None,
            interaction_completed: false,
        });
        let response = self.settle(&mut aggregate, decision, now, None);
        if aggregate.record.continuation_token.is_some() || !aggregate.tokens.is_empty() {
            if let Err(failure) = self.storage.create(aggregate) {
                return storage_failure(failure);
            }
        }
        response
    }

    /// Prepares a decision and its response; the caller commits the aggregate.
    pub(super) fn settle(
        &self,
        aggregate: &mut GrantAggregate,
        decision: Decision,
        now: u64,
        authenticated: Option<&GrantSnapshot>,
    ) -> HttpResponse {
        let record = &mut aggregate.record;
        let grant = &mut record.grant;
        let event = match &decision {
            Decision::Approve { .. } | Decision::ApproveTokens { .. } => {
                Event::AsNeedsNoInteraction
            }
            Decision::RequireInteraction => Event::AsRequiresInteraction,
            Decision::Deny(_) => Event::AsCannotProceed,
        };
        if grant.state() != State::Processing {
            // Coming back from interaction the grant is processing again; any
            // other state here is a bug in this server, not in the request.
            let _ = grant.apply(Event::Modify, now);
        }
        if let Err(e) = grant.apply(event, now) {
            return error(e.code, &e.reason);
        }

        match decision {
            Decision::Approve { access, subject } => {
                // A shorthand for the only requested token: a policy facing
                // several slots must say which ones it approves.
                let slots = record
                    .request
                    .access_token
                    .as_ref()
                    .map(|a| a.tokens.as_slice());
                let tokens =
                    match slots {
                        // §2: a client that only wants subject information omits
                        // `access_token`, and gets no token.
                        None if access.is_empty() => Vec::new(),
                        None => return misconfigured(
                            "Decision::Approve grants rights to a request that asks for no token",
                        ),
                        Some([slot]) => vec![TokenApproval {
                            requested_label: slot.label.clone(),
                            access,
                        }],
                        Some(_) => {
                            return misconfigured(
                                "Decision::Approve needs exactly one requested token; \
                             select tokens with Decision::ApproveTokens",
                            )
                        }
                    };
                self.approve_selected(aggregate, tokens, subject, now, authenticated)
            }
            Decision::ApproveTokens { tokens, subject } => {
                self.approve_selected(aggregate, tokens, subject, now, authenticated)
            }
            Decision::Deny(code) => error(code, "the request was denied"),
            Decision::RequireInteraction => {
                // A new interaction gets a new finish nonce. An ordinary poll
                // of an unfinished interaction does not reach this branch.
                record.as_nonce = None;
                match self.offer_interaction(record, now) {
                    Ok(pending) => ok(&pending),
                    Err(response) => response,
                }
            }
        }
    }

    /// Generates a code not currently indexed, with a bounded collision budget.
    /// Publication still checks uniqueness atomically; a race is not retried.
    fn next_user_code(&self) -> Result<Option<String>, HttpResponse> {
        let Some(configuration) = &self.user_codes else {
            return Ok(None);
        };
        for _ in 0..3 {
            let code = crate::user_code::generate(&self.nonces)
                .ok_or_else(|| misconfigured("user-code randomness unavailable"))?;
            if !configuration.uri.to_ascii_uppercase().contains(&code)
                && (configuration.lookup)(&self.storage, &code)
                    .map_err(storage_failure)?
                    .is_none()
            {
                return Ok(Some(code));
            }
        }
        Err(misconfigured(
            "user-code generation exhausted its collision budget",
        ))
    }

    /// Answers `pending`: somewhere to send the end user, and a way back (§3.3).
    fn offer_interaction(
        &self,
        record: &mut GrantRecord,
        now: u64,
    ) -> Result<GrantResponse, HttpResponse> {
        let request = &record.request;
        let nonce = record.as_nonce.clone().map_or_else(|| self.nonce(), Ok)?;
        let mut interact = InteractResponse::default();

        // §3.3 — never answer with a mode the client did not offer.
        let mut handle = None;
        let mut user_code = None;
        if let Some(i) = &request.interact {
            let offers = |m: &str| i.start.iter().any(|s| s.method().as_str() == m);
            if offers("user_code") || offers("user_code_uri") {
                user_code = self.next_user_code()?;
            }
            if offers("redirect") {
                // §4.2 has to find this grant again once the RO is done, and
                // the interaction URI is all the AS will see at that point;
                // the handle in it is the link back.
                let issued = self.nonce()?;
                interact.redirect = Some(format!(
                    "{}/{}",
                    self.endpoints.interaction.trim_end_matches('/'),
                    issued
                ));
                handle = Some(issued);
                // §3.3 — the client is told how long the interaction lasts
                // rather than left to guess at the timeout §4-M04 asks for.
                interact.expires_in = Some(INTERACTION_LIFETIME);
            }
            if let Some(code) = &user_code {
                if handle.is_none() {
                    handle = Some(self.nonce()?);
                }
                if offers("user_code") {
                    interact.user_code = Some(code.clone());
                }
                if offers("user_code_uri") {
                    interact.user_code_uri = Some(UserCodeUri {
                        code: code.clone(),
                        uri: self
                            .user_codes
                            .as_ref()
                            .expect("configured code source")
                            .uri
                            .clone(),
                    });
                }
                interact.expires_in = Some(INTERACTION_LIFETIME);
            }
            if i.finish.is_some() {
                interact.finish = Some(nonce.clone());
            }
        }

        // §2.5 — when interaction is required, the client offers no mode this
        // AS can drive, and the AS has no way to reach the RO on its own, it
        // MUST say so. Answering `pending` with an empty `interact` would leave
        // the client polling a grant that can never advance.
        if interact.redirect.is_none() && interact.app.is_none() && user_code.is_none() {
            return Err(error(
                ErrorCode::InvalidInteraction,
                "interaction is required, the client instance offers no mechanism this AS \
                 supports, and the AS cannot reach the resource owner asynchronously \
                 (RFC 9635 §2.5)",
            ));
        }

        let token = self.nonce()?;
        let Ok(token_value) = TokenValue::new(token.clone()) else {
            return Err(misconfigured(
                "Nonces returned a continuation value outside token68 (RFC 9635 §3.2.1)",
            ));
        };

        let mut response = GrantResponse {
            interact: Some(interact),
            ..GrantResponse::default()
        };
        response.r#continue = Some(Continue {
            uri: self.endpoints.continuation.clone(),
            access_token: BoundToken::new(token_value),
            wait: Some(gnap_core::DEFAULT_WAIT),
            extra: serde_json::Map::default(),
        });
        record
            .grant
            .offer_continuation(now, Some(gnap_core::DEFAULT_WAIT));
        record.continuation_token = Some(token);
        record.as_nonce = Some(nonce);
        record.interact_handle = handle;
        record.user_code = user_code;
        record.interact_expires_at = Some(now.saturating_add(INTERACTION_LIFETIME));
        record.interact_ref = None;
        record.interaction_completed = false;
        Ok(response)
    }
}

/// The key a client presented by value, if it did (§2.3, §7.1).
///
/// A client named by reference has no key in the message; the AS knows it from
/// its own records, which is what the [`KeyResolver`] speaks for.
pub(super) fn presented_key(
    client: &gnap_types::client::Client,
) -> Option<&gnap_types::key::KeyObject> {
    client.as_value()?.key.as_value()
}

/// Checks the supported proof method and the algorithm half of §7.3.1-M15,
/// and returns the `kid` the other half needs.
///
/// "If the signer's key presented is a JWK, the keyid parameter of the
/// signature MUST be set to the kid value of the JWK, and the signing algorithm
/// used MUST be the JWS algorithm denoted by the key's alg field of the JWK."
///
/// The algorithm is a property of the verifier, of which there is one, so it is
/// settled here. The `kid` is a property of each candidate signature, so it
/// travels down to where each one is judged: checking it against *some*
/// signature in the message would let a forged candidate carry the right name
/// while a different, genuinely valid one carried the wrong one.
///
/// Both come from the key the client presented, not from the resolver's word
/// for it: nothing stops a resolver from returning a verifier whose algorithm
/// is not the one the JWK declares.
pub(super) fn check_presented_key<'a>(
    key: &'a gnap_types::key::KeyObject,
    verifier: &dyn gnap_crypto::proof::Verifier,
) -> Result<Option<&'a str>, HttpResponse> {
    if key.proof.method().as_str() != "httpsig" {
        return Err(error(
            ErrorCode::InvalidClient,
            "the presented key requires a proof method this server does not support \
             (RFC 9635 §2.3, §7.3)",
        ));
    }
    if let Some(declared) = key.jwk_algorithm() {
        // The JWS algorithm names are registered strings, so `ps256` is not
        // `PS256`; comparing loosely would accept a value the registry does
        // not contain.
        if declared != verifier.algorithm() {
            return Err(error(
                ErrorCode::InvalidClient,
                &format!(
                    "the key declares alg=`{declared}` but the signature would be verified \
                     with `{}`; the signing algorithm MUST be the one the JWK denotes \
                     (RFC 9635 §7.3.1)",
                    verifier.algorithm()
                ),
            ));
        }
    }
    Ok(key.jwk_key_id())
}

/// Checks that the AS can actually follow the callback the client asks for.
///
/// §4.2 makes following the finish method a MUST once one is associated with
/// the request. Announcing `interact.finish` and discovering at the end of the
/// interaction that the method or the hash algorithm is one this server does
/// not implement would strand a client whose RO has already answered, so the
/// request is refused before any of that happens.
pub(super) fn supported_finish(finish: &InteractFinish) -> Result<(), String> {
    finish.validate().map_err(|e| e.to_string())?;

    if let InteractionFinishMethod::Unregistered(name) = &finish.method {
        return Err(format!(
            "`{name}` is not a finish method this server implements (RFC 9635 §2.5.2)"
        ));
    }
    if gnap_crypto::hash::HashMethod::from_name(finish.effective_hash_method()).is_none() {
        return Err(format!(
            "hash_method `{}` is not one this server implements; names come from the IANA \
             \"Named Information Hash Algorithm\" registry (RFC 9635 §4.2.3)",
            finish.effective_hash_method()
        ));
    }
    Ok(())
}

/// Reads what a continuation call is asking for (§5.1, §5.2, §5.3).
///
/// §5 gives each operation its own method and its own shape, so both decide
/// together: a POST with no content polls (§5.2), a POST carrying the reference
/// the AS issued returns from interaction (§5.1), and a PATCH carrying the
/// fields to change modifies the request (§5.3). Inferring the operation from
/// the fields alone would let one request be read as two different things
/// depending on who reads it.
///
/// # Errors
///
/// Fails when the content does not belong on the method used.
pub(super) fn classify(
    modifying: bool,
    has_content: bool,
    continuation: &ContinueRequest,
) -> Result<Event, &'static str> {
    if modifying {
        // §5.3 — "the client instance makes an HTTP PATCH request to the
        // continuation URI and includes any fields it needs to modify."
        if !has_content {
            return Err(
                "a modification request carries the fields it needs to modify; this PATCH \
                 carries none (RFC 9635 §5.3)",
            );
        }
        // §5.3 — "The client instance MUST NOT include post-interaction
        // responses such as those described in Section 5.1."
        if continuation.interact_ref.is_some() {
            return Err(
                "a modification request carries an interaction reference; it MUST NOT \
                 include post-interaction responses (RFC 9635 §5.3)",
            );
        }
        return Ok(Event::Modify);
    }

    // §5.2 — "the client instance makes a POST request to the continuation URI
    // as in Section 5.1 but does not include message content."
    if !has_content {
        return Ok(Event::ContinuePoll);
    }

    // §5.1 — the only POST that carries content is the one returning the
    // reference the AS issued. An extension that defines another one is not
    // supported here, and saying so is better than guessing what it meant.
    let Some(reference) = &continuation.interact_ref else {
        return Err(
            "a POST to the continuation URI either polls with no content (RFC 9635 §5.2) \
             or returns from interaction with an interaction reference (§5.1); modifying \
             the request is a PATCH (§5.3)",
        );
    };
    if modifies(continuation) {
        return Err(
            "the request returns from interaction and modifies the grant at once; \
             modifying an existing request is a PATCH (RFC 9635 §5.3)",
        );
    }
    Ok(Event::ContinueWithInteractRef(reference.clone()))
}
