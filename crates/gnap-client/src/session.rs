//! Driving one grant request from the client side.
//!
//! A [`Session`] holds the state of a single grant and enforces, on every
//! response, the rules RFC 9635 places on the client:
//!
//! - the response shape must match what was requested (§3.2.1, §3.2.2);
//! - the labels of a lot, or a label that was requested, must come back as
//!   requested; an unrequested label on a single token is the AS's to add
//!   (§3.2.1, §3.2.2);
//! - a `bearer` token must never carry a `key` (§3.2.1);
//! - the interaction hash must validate before the reference is sent on
//!   (§4.2.1);
//! - the `wait` period must have elapsed before the next continuation (§5);
//! - the continuation URI must be used exactly as given (§3.1).
//!
//! What the AS is allowed to put in a response depends on the state of the
//! grant, so the session carries a [`Grant`] from `gnap-core` and checks each
//! response against it.
//!
//! For initial, continuation and modification requests, an unusable response
//! or transport failure leaves the complete local state unchanged. This is not
//! a remote rollback: the AS may already have committed the request. Calls are
//! never retried automatically. A caller choosing to
//! retry sends a fresh proof, but the old continuation credential or interaction
//! reference may already be spent. With `jws` or `jwsd`, a proof is fresh only
//! from the next second: the AS's replay protection counts two proofs of the
//! same request in the same second as one; a terminal GNAP error then requires a new
//! grant in a new `Session`. Valid GNAP errors are absorbed, including a
//! replacement continuation.
//!
//! On these exchanges, a response must carry exactly one `Content-Type` field
//! naming `application/json`; this is not a complete MIME validator.

use crate::error::ClientError;
use crate::transport::{HttpRequest, HttpResponse, HttpTransport};
use gnap_core::{Event, Grant, State};
use gnap_crypto::hash::HashMethod;
use gnap_crypto::jws::JwsMethod;
use gnap_crypto::proof::Signer;
use gnap_types::message::{Continue, ContinueRequest, GrantRequest, GrantResponse};
use gnap_types::token::{AccessToken, Cardinality, TokenValue};
use gnap_types::user::SubjectResponse;
use std::collections::HashMap;
use std::num::NonZeroU64;
use std::sync::Arc;

/// Where a grant stands after a round trip with the AS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// The grant is approved; the response may carry tokens and subject
    /// information.
    Approved(Box<GrantResponse>),
    /// The grant is pending; the response carries what is needed to interact
    /// and to continue.
    Pending(Box<GrantResponse>),
    /// The AS returned an error but left the grant continuable (§3.6).
    Recoverable(Box<GrantResponse>),
}

impl Step {
    /// The response, whatever the outcome.
    #[must_use]
    pub fn response(&self) -> &GrantResponse {
        match self {
            Self::Approved(r) | Self::Pending(r) | Self::Recoverable(r) => r,
        }
    }
}

/// A single grant request, driven from the client side.
pub struct Session<T, S> {
    transport: T,
    signer: S,
    endpoint: String,
    protocol: SessionState,
    /// The interaction start modes this client can actually drive (§2.5).
    /// `None` leaves that check to the caller; see [`Session::supporting`].
    supported_modes: Option<Vec<String>>,
    /// Local finish-wait policy, independent of the AS's protocol state.
    finish_timeout: Option<NonZeroU64>,
    /// Signers of tokens whose key was rotated (§6.1.1), by token value.
    ///
    /// Kept outside [`SessionState`] so that an unusable response still rolls
    /// the protocol state back exactly; this map changes only on success. The
    /// session's own signer keeps signing the continuation and every token
    /// not listed here.
    rotated: HashMap<String, SharedSigner>,
}

/// A cryptographically verified identity attributed to the responding GNAP AS.
/// Account keys must include the AS endpoint as well as the issuer and subject.
pub struct VerifiedSubject<'a> {
    /// Actual grant endpoint used by this session.
    pub as_endpoint: &'a str,
    /// Only claims checked against the pinned assertion key and session context.
    pub identity: gnap_subject::VerifiedIdentity,
}

impl<T, S: gnap_crypto::JwkSigner> Session<T, S> {
    /// Verify a PS256 ID Token with this session's retained finish nonce.
    ///
    /// The audience convention here is the RFC 7638 thumbprint of the client's
    /// original proof key, whatever its algorithm; the assertion itself is
    /// signed with PS256 by the AS. Agree on it with the AS; GNAP does not define
    /// an OAuth client ID or this audience mapping. Token key rotation does
    /// not change the grant's proof key or identity recipient. The exact AS
    /// endpoint must match the configured trust. Raw `subject()` remains
    /// available for other formats and does not verify signatures.
    ///
    /// # Errors
    /// Refuses missing subject/finish nonce and any failed trust or claim check.
    pub fn verify_subject(
        &self,
        trust: &gnap_subject::Trust<'_>,
        now: u64,
    ) -> Result<VerifiedSubject<'_>, gnap_subject::AssertionError> {
        let response = self
            .protocol
            .subject
            .as_deref()
            .ok_or(gnap_subject::AssertionError::Context)?;
        let nonce = self
            .protocol
            .client_nonce
            .as_deref()
            .ok_or(gnap_subject::AssertionError::Context)?;
        let identity = trust.verify_subject(
            response,
            &self.endpoint,
            &self.signer.thumbprint(),
            nonce,
            now,
        )?;
        Ok(VerifiedSubject {
            as_endpoint: &self.endpoint,
            identity,
        })
    }
}

/// The signer of a token whose key was rotated, shared with the application.
pub type SharedSigner = Arc<dyn Signer + Send + Sync>;

/// The complete mutable protocol state, independent of transport and signing.
#[derive(Debug, Clone, PartialEq)]
struct SessionState {
    grant: Grant,
    continuation: Option<Continue>,
    client_nonce: Option<String>,
    as_nonce: Option<String>,
    /// The hash algorithm negotiated for the callback, already resolved.
    ///
    /// Resolving at request time is what makes an unsupported `hash_method` an
    /// error the client sees before interacting, rather than a silent fall back
    /// to `sha-256` when the callback arrives.
    hash_method: Option<HashMethod>,
    requested: Option<Cardinality>,
    /// The labels of the tokens last requested, one entry per token (§2.1).
    ///
    /// §3.2.1 makes `label` "REQUIRED for multiple access tokens or if a label
    /// was included in the single access token request", echoing the request;
    /// a response can only be checked against a request the session kept.
    requested_labels: Vec<Option<String>>,
    /// The interaction start modes this client offered (§2.5.1).
    offered_modes: Vec<String>,
    /// An interaction reference whose hash validated, waiting to be sent.
    validated_ref: Option<String>,
    /// The last subject information the AS released (§3.4).
    subject: Option<Box<SubjectResponse>>,
    /// The issued tokens, each with the moment its `expires_in` started
    /// running.
    ///
    /// One instant per token, not one for the lot: a rotation (§6.1) hands back
    /// "an updated token value and expiration time", so a rotated token's clock
    /// starts at the rotation, while its neighbours keep theirs.
    issued: Option<Vec<(u64, AccessToken)>>,
    /// Whether a callback has arrived on the interaction the AS promised.
    interaction_finished: bool,
    /// Receipt time and optional exclusive deadline for the current set of
    /// interaction responses. Responses without `interact` do not renew it.
    interaction_window: Option<InteractionWindow>,
    /// How the session proves its key, settled by the first request (§7.3).
    proof: Option<SessionProof>,
}

/// The proof method of the session's key (§7.3): the one its `client.key`
/// declares, and `httpsig` for a key named by reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionProof {
    /// HTTP Message Signatures (§7.3.1).
    Httpsig,
    /// A JOSE proof, attached or detached (§7.3.3, §7.3.4).
    Jose(JwsMethod),
}

/// Subject information and the AS that stated it (§3.4-M15).
///
/// An identifier names the RO *at one AS*. Carrying the two together is what
/// stops a caller from treating `user@example.com` from one AS as the same
/// person as `user@example.com` from another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttributedSubject<'a> {
    /// The grant endpoint of the AS that stated this, which identifies it
    /// (§1.2).
    pub as_endpoint: &'a str,
    /// What that AS said about the RO.
    pub subject: &'a SubjectResponse,
}

impl<T: HttpTransport, S: Signer> Session<T, S> {
    /// Starts a session against a grant endpoint.
    ///
    /// The endpoint URI identifies the AS (§1.2) and feeds the interaction hash
    /// (§4.2.3), so it is kept exactly as given.
    pub fn new(transport: T, signer: S, endpoint: impl Into<String>) -> Self {
        Self {
            transport,
            signer,
            endpoint: endpoint.into(),
            protocol: SessionState {
                grant: Grant::new(),
                continuation: None,
                client_nonce: None,
                as_nonce: None,
                hash_method: None,
                requested: None,
                requested_labels: Vec::new(),
                offered_modes: Vec::new(),
                validated_ref: None,
                subject: None,
                issued: None,
                interaction_finished: false,
                interaction_window: None,
                proof: None,
            },
            supported_modes: None,
            finish_timeout: None,
            rotated: HashMap::new(),
        }
    }

    /// Bounds interaction-finish acceptance by a local duration in seconds.
    ///
    /// RFC 9635 §4 recommends suitable finish timeouts. By default the session
    /// uses only the AS's optional `interact.expires_in`; this policy also
    /// bounds a window when that field is absent, and never extends it when
    /// the AS announces a shorter duration. Each window starts at the `now`
    /// supplied to the operation that received the interaction response.
    ///
    /// Calling this after an interaction response can only shorten its current
    /// window, measured from the original start, not restart or extend it.
    /// The new positive setting applies to later interaction windows. A
    /// callback accepted earlier remains usable.
    ///
    /// This is not a transport timeout, polling limit, session lifetime or
    /// token expiry. Applications still own those separate policies.
    #[must_use]
    pub fn with_finish_timeout(mut self, seconds: NonZeroU64) -> Self {
        self.finish_timeout = Some(seconds);
        if let Some(window) = &mut self.protocol.interaction_window {
            window.limit(seconds);
        }
        self
    }

    /// Subject information, tied to the AS that stated it (§3.4-M15).
    ///
    /// "The client instance MUST interpret all subject information in the
    /// context of the AS from which the subject information is received."
    /// §3.4 gives the reason plainly: two ASes can return the same email
    /// address for two different people, and a client that keys accounts on the
    /// identifier alone lets a rogue AS take over an account asserted by
    /// another one.
    ///
    /// So the accessor never hands the identifiers over on their own. Reading
    /// `GrantResponse::subject` directly is still possible — it is a wire type
    /// and its fields are public — but the path a caller reaches for first
    /// carries the attribution with it.
    #[must_use]
    pub fn subject(&self) -> Option<AttributedSubject<'_>> {
        Some(AttributedSubject {
            as_endpoint: &self.endpoint,
            subject: self.protocol.subject.as_deref()?,
        })
    }

    /// The access tokens the AS issued, if they can still be used (§3.2.1).
    ///
    /// §3.2.1-MN09: "The client instance MUST NOT use the access token past
    /// this time." `expires_in` is a duration, so only the client knows when it
    /// started running; that makes it the client's job to stop handing the
    /// token out, and the reason this accessor takes `now` rather than letting
    /// a caller read the value and forget.
    ///
    /// Returns `None` once every issued token has expired, and otherwise only
    /// those that have not.
    ///
    /// `now` is the current time in seconds since the Unix epoch; see
    /// [`unix_now`](gnap_types::unix_now).
    #[must_use]
    pub fn usable_tokens(&self, now: u64) -> Option<Vec<&AccessToken>> {
        let live: Vec<&AccessToken> = self
            .protocol
            .issued
            .as_ref()?
            .iter()
            .filter(|(issued_at, t)| {
                t.expires_in
                    .is_none_or(|seconds| now < issued_at.saturating_add(seconds))
            })
            .map(|(_, t)| t)
            .collect();
        (!live.is_empty()).then_some(live)
    }

    /// Names the interaction start modes this client can actually drive (§2.5).
    ///
    /// §2.5-MN01: "A client instance MUST NOT declare an interaction mode it
    /// does not support." Whether a mode is supported depends on what the
    /// embedder can do — open a browser, show a code, receive a push — which
    /// this library cannot see. What it can do is refuse to let that stay
    /// implicit: say what you support, and a request declaring anything else is
    /// stopped before it reaches the AS.
    ///
    /// Without this, no such check runs, and the declaration is the caller's
    /// word alone.
    #[must_use]
    pub fn supporting(mut self, modes: &[&str]) -> Self {
        self.supported_modes = Some(modes.iter().map(|m| (*m).to_owned()).collect());
        self
    }

    /// The state of the grant as the client understands it.
    #[must_use]
    pub const fn state(&self) -> State {
        self.protocol.grant.state()
    }

    /// What the AS offered for continuing, if anything.
    #[must_use]
    pub const fn continuation(&self) -> Option<&Continue> {
        self.protocol.continuation.as_ref()
    }

    /// Sends the initial grant request (§2).
    ///
    /// `now` is the current time in seconds since the Unix epoch; see
    /// [`unix_now`](gnap_types::unix_now).
    ///
    /// # Errors
    ///
    /// Fails when the request cannot be signed or sent, when the response
    /// cannot be parsed, or when the AS answers something the RFC forbids in
    /// the state its answer implies.
    pub fn start(&mut self, request: &GrantRequest, now: u64) -> Result<Step, ClientError> {
        self.transaction(|session| session.start_inner(request, now))
    }

    fn start_inner(&mut self, request: &GrantRequest, now: u64) -> Result<Step, ClientError> {
        // A session drives one grant: starting another would replace the
        // local state of one the AS may still hold. A start lost before any
        // GNAP answer leaves no grant, so it can be tried again.
        if self.protocol.proof.is_some() {
            return Err(ClientError::Usage(
                "this session already started a grant; start another grant in a new session".into(),
            ));
        }
        // §2.3 — what the client says about itself is checked before it leaves.
        // §2.3-MN09 binds the client, not the AS: "The client instance MUST NOT
        // send a symmetric key by value in the key field of the request". A
        // type that can refuse such a key is no use if the client never asks
        // it to.
        if let Some(client) = request.client.as_value() {
            if let Some(key) = client.key.as_value() {
                key.validate()
                    .map_err(|e| ClientError::Usage(format!("client.key: {e}")))?;
            }
            if let Some(display) = &client.display {
                display
                    .validate()
                    .map_err(|e| ClientError::Usage(e.to_string()))?;
            }
        }

        // §2.3-M07 — the key is used with "the proofing mechanism associated
        // with the key", and a grant keeps it: its continuation and tokens are
        // bound to the key the first request proved.
        let (proof, presented) = crate::signing::session_proof(request, &self.signer)?;
        self.protocol.proof = Some(proof);
        self.protocol.requested = request.access_token.as_ref().map(|a| a.cardinality);
        self.protocol.requested_labels = requested_labels(request.access_token.as_ref());
        self.prepare_interaction(request.interact.as_ref())?;

        let body = serde_json::to_vec(request)
            .map_err(|e| ClientError::Usage(format!("serializing the request: {e}")))?;
        let http = Self::signed_request(
            proof,
            "POST",
            &self.endpoint.clone(),
            Some(body),
            None,
            &self.signer,
            now,
        )?;
        if let (SessionProof::Jose(method), Some(presented)) = (proof, presented.as_ref()) {
            crate::signing::check_jose_proof(&http, method, presented, now)?;
        }
        let response = self.round_trip(http)?;
        self.absorb(&response, now)
    }

    /// Calls the continuation API (§5).
    ///
    /// Sends the validated interaction reference when there is one, and polls
    /// otherwise. The `wait` period is enforced before anything leaves.
    ///
    /// `now` is the current time in seconds since the Unix epoch; see
    /// [`unix_now`](gnap_types::unix_now).
    ///
    /// # Errors
    ///
    /// Fails when no continuation was offered, when a state guard refuses the
    /// call, or for the same reasons as [`Session::start`].
    pub fn continue_grant(&mut self, now: u64) -> Result<Step, ClientError> {
        self.transaction(|session| session.continue_inner(now))
    }

    fn continue_inner(&mut self, now: u64) -> Result<Step, ClientError> {
        let cont = self.protocol.continuation.clone().ok_or_else(|| {
            ClientError::Usage(
                "the AS offered no continuation, so the client MUST NOT call the \
                 continuation API (RFC 9635 §5)"
                    .into(),
            )
        })?;

        // §3.3.5-MN02 — "If the AS returns the finish field, the client
        // instance MUST NOT continue a grant request before it receives the
        // associated interaction reference on the callback URI." Polling in
        // that window asks the AS to act on an interaction the client has no
        // evidence of, which is the very thing the reference is for.
        if self.protocol.grant.state() == State::Pending
            && self.protocol.as_nonce.is_some()
            && !self.protocol.interaction_finished
        {
            return Err(ClientError::Usage(
                "the AS returned a `finish` nonce, so this grant continues on the \
                 interaction reference from the callback; it MUST NOT be continued before \
                 that arrives (RFC 9635 §3.3.5)"
                    .into(),
            ));
        }

        let event = self
            .protocol
            .validated_ref
            .clone()
            .map_or(Event::ContinuePoll, Event::ContinueWithInteractRef);

        // gnap-core owns the wait period and the state guards. The transition
        // is decided on a copy. An inconclusive exchange must not strand the
        // local session mid-transition; the AS may still have committed it.
        let mut attempt = self.protocol.grant.clone();
        attempt
            .apply(event.clone(), now)
            .map_err(|e| ClientError::Usage(e.to_string()))?;

        let body = match &event {
            Event::ContinueWithInteractRef(r) => {
                let req = ContinueRequest {
                    interact_ref: Some(r.clone()),
                    ..ContinueRequest::default()
                };
                Some(serde_json::to_vec(&req).map_err(|e| {
                    ClientError::Usage(format!("serializing the continuation: {e}"))
                })?)
            }
            _ => None,
        };

        // GNAP-9635-§3.1-M03 — the continuation URI is used exactly as given.
        let http = Self::signed_request(
            self.session_proof(),
            "POST",
            &cont.uri,
            body,
            Some(&cont.access_token.value),
            &self.signer,
            now,
        )?;
        let response = self.round_trip(http)?;
        let before = self.protocol.grant.clone();
        self.protocol.grant = attempt;
        let step = match self.absorb(&response, now) {
            Err(error @ ClientError::Server(_)) => {
                // A terminal GNAP error removed continuation; this reference
                // can no longer be submitted, whether or not the AS spent it.
                self.protocol.validated_ref = None;
                return Err(error);
            }
            result => result?,
        };

        if matches!(step, Step::Recoverable(_)) {
            self.rewind(before, now);
        } else {
            // The call went through, so the reference is spent: §4.2 makes it
            // one-time-use.
            self.protocol.validated_ref = None;
        }
        Ok(step)
    }

    /// Undoes a continuation call the AS refused but let the client retry.
    ///
    /// §5-M11 — an error the grant survives comes back with a new continuation.
    /// From the grant's point of view the call did not happen: the state is
    /// what it was, an interaction reference that was not accepted is still
    /// good, and the wait period starts again from the response the AS just
    /// sent. Leaving the transition applied would strand the session a step
    /// ahead of the AS.
    fn rewind(&mut self, before: Grant, now: u64) {
        self.protocol.grant = before;
        if let Some(wait) = self.protocol.continuation.as_ref().map(|c| c.wait) {
            self.protocol.grant.offer_continuation(now, wait);
        }
    }

    /// Modifies the request already on file (§5.3).
    ///
    /// "the client instance makes an HTTP PATCH request to the continuation URI
    /// and includes any fields it needs to modify. Fields that aren't included
    /// in the request are considered unchanged from the original request."
    ///
    /// # Errors
    ///
    /// Fails when the AS offered no continuation, when `changes` carries an
    /// interaction reference — §5.3 forbids a modification from carrying a
    /// post-interaction response — or when the exchange or the response does.
    pub fn modify_grant(
        &mut self,
        changes: &ContinueRequest,
        now: u64,
    ) -> Result<Step, ClientError> {
        self.transaction(|session| session.modify_inner(changes, now))
    }

    fn modify_inner(&mut self, changes: &ContinueRequest, now: u64) -> Result<Step, ClientError> {
        let cont = self.protocol.continuation.clone().ok_or_else(|| {
            ClientError::Usage(
                "the AS offered no continuation, so the client MUST NOT call the \
                 continuation API (RFC 9635 §5)"
                    .into(),
            )
        })?;
        if changes.interact_ref.is_some() {
            return Err(ClientError::Usage(
                "a modification request MUST NOT include post-interaction responses; \
                 send the interaction reference with `continue_grant` instead \
                 (RFC 9635 §5.3)"
                    .into(),
            ));
        }

        // gnap-core owns the states a modification is allowed from (§5.3-M01),
        // and the transition is committed only once the AS has answered.
        let mut attempt = self.protocol.grant.clone();
        attempt
            .apply(Event::Modify, now)
            .map_err(|e| ClientError::Usage(e.to_string()))?;

        let context_before = self.protocol.clone();
        if let Some(access) = &changes.access_token {
            self.protocol.requested = Some(access.cardinality);
            self.protocol.requested_labels = requested_labels(Some(access));
        }
        self.prepare_interaction(changes.interact.as_ref())?;

        let body = serde_json::to_vec(changes)
            .map_err(|e| ClientError::Usage(format!("serializing the modification: {e}")))?;
        let http = Self::signed_request(
            self.session_proof(),
            "PATCH",
            &cont.uri,
            Some(body),
            Some(&cont.access_token.value),
            &self.signer,
            now,
        )?;
        let response = self.round_trip(http)?;
        let before = self.protocol.grant.clone();
        self.protocol.grant = attempt;
        let step = match self.absorb(&response, now) {
            Err(ClientError::Server(error)) => {
                // The error closes continuation, not acceptance of the fields
                // proposed by this refused PATCH. Keep their previous context.
                self.protocol.client_nonce = context_before.client_nonce;
                self.protocol.hash_method = context_before.hash_method;
                self.protocol.requested = context_before.requested;
                self.protocol.requested_labels = context_before.requested_labels;
                self.protocol.offered_modes = context_before.offered_modes;
                return Err(ClientError::Server(error));
            }
            result => result?,
        };

        if matches!(step, Step::Recoverable(_)) {
            // A refused PATCH did not install the offered request context.
            let continuation = self.protocol.continuation.clone();
            let inferred_grant = self.protocol.grant.clone();
            self.protocol = context_before;
            self.protocol.continuation = continuation;
            if before.state() == State::Pending {
                self.rewind(before, now);
            } else {
                self.protocol.grant = inferred_grant;
            }
        } else {
            self.protocol.validated_ref = None;
        }
        Ok(step)
    }

    /// Revokes the ongoing grant and its associated tokens (§5.4).
    ///
    /// Only a 204 response with empty content confirms revocation. Inconclusive
    /// exchanges preserve local state; the server may still have committed the
    /// request, so retry is neither automatic nor guaranteed to succeed.
    /// Valid GNAP errors update continuation exactly as other grant responses.
    ///
    /// # Errors
    /// Fails when no continuation is offered, a state/wait guard refuses the
    /// request, the exchange fails, or the response does not confirm revocation.
    pub fn revoke_grant(&mut self, now: u64) -> Result<(), ClientError> {
        self.transaction(|session| session.revoke_grant_inner(now))
    }

    fn revoke_grant_inner(&mut self, now: u64) -> Result<(), ClientError> {
        let continuation = self.protocol.continuation.clone().ok_or_else(|| {
            ClientError::Usage("the AS offered no continuation (RFC 9635 §5)".into())
        })?;
        let mut revoked = self.protocol.grant.clone();
        revoked
            .apply(Event::Revoke, now)
            .map_err(|e| ClientError::Usage(e.to_string()))?;
        let request = Self::signed_request(
            self.session_proof(),
            "DELETE",
            &continuation.uri,
            None,
            Some(&continuation.access_token.value),
            &self.signer,
            now,
        )?;
        let response = self.round_trip(request)?;
        if response.status != 204 {
            let step = self.absorb(&response, now)?;
            if let Step::Recoverable(response) = step {
                if let Some(error) = response.error {
                    return Err(ClientError::Server(error));
                }
            }
            return Err(ClientError::Protocol(
                "grant revocation requires 204 No Content (RFC 9635 §5.4)".into(),
            ));
        }
        if !response.body.is_empty() {
            return Err(ClientError::Protocol(
                "a 204 revocation response must have no content".into(),
            ));
        }
        revoked.withhold_continuation();
        // Nothing is held any more, so no rotated key is either (§5.4).
        self.rotated.clear();
        self.protocol.grant = revoked;
        self.protocol.continuation = None;
        self.protocol.issued = None;
        self.protocol.subject = None;
        self.protocol.as_nonce = None;
        self.protocol.client_nonce = None;
        self.protocol.hash_method = None;
        self.protocol.validated_ref = None;
        self.protocol.interaction_window = None;
        self.protocol.interaction_finished = false;
        Ok(())
    }

    /// The proof method settled by the first request, `httpsig` before it.
    pub(crate) fn session_proof(&self) -> SessionProof {
        self.protocol.proof.unwrap_or(SessionProof::Httpsig)
    }

    /// Builds a request with the proof of `signer`'s key (§7.2, §7.3).
    pub(crate) fn signed_request(
        proof: SessionProof,
        method: &str,
        url: &str,
        body: Option<Vec<u8>>,
        token: Option<&TokenValue>,
        signer: &dyn Signer,
        now: u64,
    ) -> Result<HttpRequest, ClientError> {
        let http = HttpRequest::new(method, url);
        match proof {
            SessionProof::Httpsig => {
                let http = match body {
                    Some(body) => http.json_body(body),
                    None => http,
                };
                crate::sign_request(http, signer, token, now)
            }
            SessionProof::Jose(jose) => {
                crate::signing::sign_jose(http, jose, body, signer, token, now)
            }
        }
    }

    fn round_trip(&self, request: HttpRequest) -> Result<HttpResponse, ClientError> {
        self.transport
            .send(request)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// An unusable response says nothing authoritative about the remote grant.
    /// Retain all local state, but commit valid GNAP errors just like successes.
    fn transaction<R>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<R, ClientError>,
    ) -> Result<R, ClientError> {
        let before = self.protocol.clone();
        let result = operation(self);
        if result.is_err() && !matches!(&result, Err(ClientError::Server(_))) {
            self.protocol = before;
        }
        result
    }
}

mod interaction;
mod response;
mod tokens;

use interaction::InteractionWindow;
use response::requested_labels;

#[cfg(test)]
mod tests;
