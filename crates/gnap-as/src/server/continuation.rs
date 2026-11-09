//! Grant continuation (§5): polling, modification, and revocation of a grant.

use super::{
    check_presented_key, classify, error, gnap_token, method_not_allowed, misconfigured,
    no_content, presented_key, require_json_content, storage_failure, supported_finish,
    AuthorizationServer,
};
use crate::encoding::TokenEncoder;
use crate::nonce::Nonces;
use crate::policy::{Decision, EvaluationContext, KeyResolver, Policy};
use crate::storage::{GrantAggregate, GrantRecord, GrantSelector, GrantSnapshot, Storage};
use gnap_core::{Event, State};
use gnap_registry::ErrorCode;
use gnap_types::http::{HttpRequest, HttpResponse};
use gnap_types::message::{Continue, ContinueRequest, GrantRequest, GrantResponse};
use gnap_types::token::{BoundToken, TokenValue};
use gnap_types::GnapError;

impl<P: Policy, K: KeyResolver, S: Storage, N: Nonces, E: TokenEncoder>
    AuthorizationServer<P, K, S, N, E>
{
    /// A call to the continuation API (§5).
    ///
    /// `now` is the current time in seconds since the Unix epoch; see
    /// [`unix_now`](gnap_types::unix_now).
    pub fn handle_continuation(&self, request: &HttpRequest, now: u64) -> HttpResponse {
        // §5 gives each operation its own method: POST continues, whether by
        // polling (§5.2) or by returning from interaction (§5.1), PATCH
        // modifies the request (§5.3), and DELETE revokes it (§5.4).
        let modifying = request.method.eq_ignore_ascii_case("PATCH");
        let revoking = request.method.eq_ignore_ascii_case("DELETE");
        if !revoking {
            if !modifying && !request.method.eq_ignore_ascii_case("POST") {
                return method_not_allowed("POST, PATCH, DELETE");
            }
            if let Err(r) = require_json_content(request) {
                return r;
            }
        }

        let snapshot = match self.authenticate_continuation(request, now) {
            Ok(snapshot) => snapshot,
            Err(r) => return r,
        };

        let mut aggregate = snapshot.aggregate.clone();
        let response = self.continue_authenticated(
            request,
            now,
            modifying,
            revoking,
            &mut aggregate,
            &snapshot,
        );
        // Preparation failed before publication. An internal 5xx is not a
        // GNAP decision to close or modify the grant. Keep the original; this
        // says nothing about a response lost after a successful CAS.
        if response.status >= 500 {
            return response;
        }
        if aggregate.record.continuation_token.is_some()
            && aggregate.record.continuation_token == snapshot.aggregate.record.continuation_token
        {
            return misconfigured(
                "the replacement continuation credential repeats its predecessor",
            );
        }
        if aggregate.record.continuation_token.is_none() {
            aggregate.record.interact_handle = None;
            aggregate.record.user_code = None;
            aggregate.record.interact_ref = None;
            aggregate.record.interact_expires_at = None;
            aggregate.record.grant.withhold_continuation();
        }
        match self
            .storage
            .compare_exchange(snapshot.id, snapshot.revision, aggregate)
        {
            Ok(_) => response,
            Err(failure) => storage_failure(failure),
        }
    }

    // Only prepares a replacement. No intermediate state is externally visible.
    fn continue_authenticated(
        &self,
        request: &HttpRequest,
        now: u64,
        modifying: bool,
        revoking: bool,
        aggregate: &mut GrantAggregate,
        authenticated: &GrantSnapshot,
    ) -> HttpResponse {
        let record = &mut aggregate.record;
        record.continuation_token = None;
        let has_content = request.body.as_ref().is_some_and(|b| !b.is_empty());
        let continuation: ContinueRequest = if revoking || !has_content {
            ContinueRequest::default()
        } else {
            match Self::parse(request) {
                Ok(c) => c,
                Err(_) => {
                    return self.recover(
                        record,
                        ErrorCode::InvalidRequest,
                        "the continuation request is not a JSON object this server can \
                         read (RFC 9635 §5)",
                        now,
                    )
                }
            }
        };
        // §5.3-Y05 — a modification may bring new interaction capabilities, and
        // §2.5.2 applies to them exactly as it does to the initial request.
        if let Some(finish) = continuation
            .interact
            .as_ref()
            .and_then(|i| i.finish.as_ref())
        {
            if let Err(reason) = supported_finish(finish) {
                return self.recover(record, ErrorCode::InvalidRequest, &reason, now);
            }
        }
        if continuation
            .user
            .as_ref()
            .and_then(gnap_types::user::User::as_reference)
            .is_some_and(|reference| !self.policy.recognises_user(reference))
        {
            return self.recover(
                record,
                ErrorCode::UnknownUser,
                "the user reference is not one this AS recognises (RFC 9635 §2.4.1)",
                now,
            );
        }

        let event = if revoking {
            Event::Revoke
        } else {
            match classify(modifying, has_content, &continuation) {
                Ok(event) => event,
                Err(reason) => return self.recover(record, ErrorCode::InvalidRequest, reason, now),
            }
        };

        // §4.2 — the reference is one the AS issued for this grant, and it is
        // one-time-use. Without this check any string would do, and anyone able
        // to reach the continuation endpoint could claim the interaction had
        // finished.
        let returning = matches!(event, Event::ContinueWithInteractRef(_));
        if let Event::ContinueWithInteractRef(presented) = &event {
            if record.interact_ref.as_deref() != Some(presented.as_str()) {
                // The grant survives: presenting a wrong reference is not a
                // reason to lose a pending request. It survives with a new
                // continuation token, which is what lets the client try again.
                return self.recover(
                    record,
                    ErrorCode::InvalidInteraction,
                    "the interaction reference is not the one issued for this grant \
                     (RFC 9635 §4.2)",
                    now,
                );
            }
        }

        // gnap-core owns the guards: wait period, one-time references, the
        // states a modification is allowed from, and the absorbing finalized.
        if let Err(e) = record.grant.apply(event, now) {
            // A recoverable refusal keeps a continuation in the candidate:
            // being told `too_fast` must not cost the client its request.
            // The exception is a guard that finalizes, where §5.1 wants the
            // request invalidated and no way back offered.
            if e.finalizes {
                return error(e.code, &e.reason);
            }
            return self.recover(record, e.code, &e.reason, now);
        }

        // §4.2-M05 — the reference is one-time-use, and this is the call that
        // used it. Spending it any earlier would let a `too_fast` refusal
        // destroy a reference the client can never obtain again.
        if returning {
            record.interact_ref = None;
        }

        if revoking {
            aggregate.revoked = true;
            aggregate.tokens.clear();
            return no_content();
        }

        self.resume_grant(
            aggregate,
            continuation,
            modifying,
            returning,
            now,
            authenticated,
        )
    }

    /// Re-evaluates an authenticated continuation after its state guards pass.
    fn resume_grant(
        &self,
        aggregate: &mut GrantAggregate,
        continuation: ContinueRequest,
        modifying: bool,
        returning: bool,
        now: u64,
        authenticated: &GrantSnapshot,
    ) -> HttpResponse {
        let record = &mut aggregate.record;
        // Approved POST keeps the grant open but does not issue another token
        // or reuse old interaction consent to evaluate a new request (§3.1).
        if record.grant.state() == State::Approved && !modifying && !returning {
            return self.hand_back(record, None, now);
        }
        // §4 — coming back from interaction, the AS re-evaluates the whole
        // context, whether the RO approved or denied.
        //
        // How the client comes back is not free, though. §2.5.2-M13 makes every
        // finish method "require presentation of an interaction reference for
        // continuing this grant request", and §2.5.2-M14 says that reference
        // "MUST be presented by the client as described in Section 5.1". So a
        // grant that negotiated a finish is re-evaluated only when the client
        // actually presents the reference; polling does not stand in for it,
        // which would hand the grant to anyone holding the continuation token
        // the moment the RO answered. A grant with no finish method has nothing
        // to present, and polling is the whole of §5.2.
        let expects_reference = record
            .request
            .interact
            .as_ref()
            .is_some_and(|i| i.finish.is_some());

        // The reference is owed and this call is not the one that pays it. The
        // AS has nothing to decide yet — re-running the policy here would offer
        // a second interaction and, with it, throw away the reference the
        // client is about to present. So the grant is handed back untouched,
        // under a fresh token, still pending (§5.2).
        if expects_reference && !returning && !modifying {
            return self.hand_back(record, None, now);
        }

        if modifying {
            // A modification negotiates a new context (§5.3). The previous
            // interaction reference cannot stand for consent to that context.
            record.interaction_completed = false;
            record.interact_ref = None;
            record.as_nonce = None;
            record.interact_handle = None;
            record.user_code = None;
            record.interact_expires_at = None;
        }
        let after_interaction = record.interaction_completed && (returning || !expects_reference);
        let request_now = apply_modification(record.request.clone(), continuation);
        let decision = if modifying {
            self.policy
                .evaluate_context(&request_now, EvaluationContext::Modification(authenticated))
        } else if after_interaction {
            self.policy.evaluate_context(
                &request_now,
                EvaluationContext::AfterInteraction(authenticated),
            )
        } else {
            self.policy.evaluate(&request_now)
        };
        if !modifying && !returning && matches!(decision, Decision::RequireInteraction) {
            // A poll changes neither the request nor the interaction already
            // open in the RO's browser. Keep its handle and original timeout.
            return self.hand_back(record, None, now);
        }

        record.request = request_now;
        self.settle(aggregate, decision, now, Some(authenticated))
    }

    /// Names the grant a continuation call is for, once the caller has proved
    /// it may make it (§5-M01, §5-M02).
    ///
    /// The grant is read without being consumed. The client's key is only known
    /// through the grant on file, so it has to be read before the signature can
    /// be verified — and a request that fails verification must leave the grant
    /// exactly as it was. Consuming here would let anyone holding a leaked
    /// continuation token destroy the grant with a signature that does not
    /// verify, and the legitimate client would never learn why.
    fn authenticate_continuation(
        &self,
        request: &HttpRequest,
        now: u64,
    ) -> Result<GrantSnapshot, HttpResponse> {
        let token = Self::continuation_token(request)?;
        let snapshot = self
            .storage
            .lookup(GrantSelector::Continuation(&token))
            .map_err(storage_failure)?
            .ok_or_else(unknown_continuation)?;
        let record = &snapshot.aggregate.record;

        let verifier = self.keys.resolve(&record.request.client).ok_or_else(|| {
            error(
                ErrorCode::InvalidClient,
                "the client instance is not recognised",
            )
        })?;
        let presented_kid = match presented_key(&record.request.client) {
            None => None,
            Some(key) => check_presented_key(key, verifier.as_ref())?,
        };
        self.verify_signature(request, verifier.as_ref(), presented_kid, now)?;
        Ok(snapshot)
    }

    /// Answers an error the grant can survive, and hands the client the way
    /// back (§5-M11, §5-M12).
    ///
    /// "If the AS determines that the client instance can make further requests
    /// to the continuation API, the AS MUST include a new continuation
    /// response", and that response "MUST include a continuation access token
    /// as well, and this token SHOULD be a new access token, invalidating the
    /// previous access token". The two rules that follow are why this matters:
    /// §5-MN13 forbids the client from calling again when no continuation came
    /// back, and §5-M14 obliges the AS to answer `invalid_continuation` if it
    /// does. An error that leaves the grant alive and says nothing would leave
    /// a grant that neither side may touch again.
    ///
    /// §3.6 allows `error` and `continue` together only while the grant is
    /// pending. When it is not, there is no way to say "carry on", so the
    /// record is dropped and the next call gets `invalid_continuation` — which
    /// is exactly what §5-M14 asks for.
    fn recover(
        &self,
        record: &mut GrantRecord,
        code: ErrorCode,
        reason: &str,
        now: u64,
    ) -> HttpResponse {
        if record.grant.state() != State::Pending {
            return error(code, reason);
        }
        self.hand_back(record, Some(GnapError::with_description(code, reason)), now)
    }

    /// Answers a call the AS is not going to act on, and hands the grant back.
    ///
    /// §5-M11 — "the AS MUST include a new continuation response" when the
    /// grant can continue. §5-M12 says the response "MUST include a continuation
    /// access token as well, and this token SHOULD be a new access token, invalidating
    /// the previous access token". This SDK follows that recommendation:
    /// committing the candidate removes the old index and publishes the new
    /// one together. A failed transaction publishes neither response nor token.
    fn hand_back(
        &self,
        record: &mut GrantRecord,
        failure: Option<GnapError>,
        now: u64,
    ) -> HttpResponse {
        let token = self.nonces.next();
        let Ok(value) = TokenValue::new(token.clone()) else {
            return misconfigured(
                "Nonces returned a continuation value outside token68 (RFC 9635 §3.2.1)",
            );
        };

        record
            .grant
            .offer_continuation(now, Some(gnap_core::DEFAULT_WAIT));
        record.continuation_token = Some(token);

        let status = if failure.is_some() { 400 } else { 200 };
        let response = GrantResponse {
            error: failure,
            r#continue: Some(Continue {
                uri: self.endpoints.continuation.clone(),
                access_token: BoundToken::new(value),
                wait: Some(gnap_core::DEFAULT_WAIT),
                extra: serde_json::Map::default(),
            }),
            ..GrantResponse::default()
        };

        HttpResponse {
            status,
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
                ("Cache-Control".into(), "no-store".into()),
            ],
            body: serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec()),
        }
    }

    /// Reads the continuation token a call presents (§5).
    ///
    /// §5 lets the AS identify the grant from the continuation URI, the
    /// continuation token, or both; this server uses the token, presented with
    /// the GNAP scheme (§7.2).
    fn continuation_token(request: &HttpRequest) -> Result<String, HttpResponse> {
        gnap_token(request).map(ToOwned::to_owned).ok_or_else(|| {
            error(
                ErrorCode::InvalidContinuation,
                "no continuation access token was presented (RFC 9635 §5)",
            )
        })
    }
}

/// Whether a continuation request changes what was asked for (§5.3).
///
/// Extension fields are deliberately not counted. Appendix D lets an extension
/// add fields to any message, including the §5.1 return, and reading one as a
/// modification would refuse a request the RFC allows. What an extension field
/// means is the extension's business; §5.3 names the four fields that modify a
/// request, and these are they.
pub(super) const fn modifies(continuation: &ContinueRequest) -> bool {
    continuation.access_token.is_some()
        || continuation.subject.is_some()
        || continuation.interact.is_some()
        || continuation.user.is_some()
}

/// Applies a modification to the request on file (§5.3).
///
/// "Fields that aren't included in the request are considered unchanged from
/// the original request", so each present field replaces its counterpart and
/// the rest is left alone.
fn apply_modification(mut request: GrantRequest, continuation: ContinueRequest) -> GrantRequest {
    if let Some(access_token) = continuation.access_token {
        request.access_token = Some(access_token);
    }
    if let Some(subject) = continuation.subject {
        request.subject = Some(subject);
    }
    if let Some(interact) = continuation.interact {
        request.interact = Some(interact);
    }
    // §5.3-Y07 — the client may "present new assertions or information about
    // the end user". §5.3-S08 asks the AS to check the new information against
    // what it already has; that judgement belongs to the policy, which sees the
    // request this returns.
    if let Some(user) = continuation.user {
        request.user = Some(user);
    }
    // "Fields that aren't included in the request are considered unchanged from
    // the original request" applies to extension fields too: a key that is
    // present replaces its counterpart, the rest is left alone.
    request.extra.extend(continuation.extra);
    request
}

/// The answer to a continuation token that names no live grant (§5).
fn unknown_continuation() -> HttpResponse {
    error(
        ErrorCode::InvalidContinuation,
        "the continuation access token does not map to a single active grant request \
         (RFC 9635 §5)",
    )
}
