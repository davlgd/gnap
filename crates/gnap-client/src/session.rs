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
//! reference may already be spent; a terminal GNAP error then requires a new
//! grant in a new `Session`. Valid GNAP errors are absorbed, including a
//! replacement continuation.
//!
//! On these exchanges, explicit incompatible or repeated `Content-Type` fields are
//! rejected. Missing fields remain accepted for compatibility; this is not a
//! complete MIME validator.

use crate::error::ClientError;
use crate::rotation;
use crate::transport::{HttpRequest, HttpResponse, HttpTransport};
use gnap_core::{check_response, Event, Grant, State};
use gnap_crypto::hash::{verify_interaction_hash, HashMethod, InteractionHashInput};
use gnap_crypto::proof::Signer;
use gnap_registry::AccessTokenFlag;
use gnap_types::interact::InteractCallback;
use gnap_types::key::Key;
use gnap_types::message::{Continue, ContinueRequest, GrantRequest, GrantResponse};
use gnap_types::token::{AccessToken, AccessTokenRequest, Cardinality, TokenManage, TokenValue};
use gnap_types::user::SubjectResponse;
use std::collections::HashMap;

/// Where a grant stands after a round trip with the AS.
#[derive(Debug, Clone, PartialEq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct InteractionWindow {
    received_at: u64,
    expires_at: Option<u128>,
}
impl InteractionWindow {
    fn new(received_at: u64, expires_in: Option<u64>) -> Self {
        // Two u64 inputs fit in u128. A legal, very long lifetime must not
        // discard an otherwise usable response or its continuation token.
        let expires_at = expires_in.map(|seconds| u128::from(received_at) + u128::from(seconds));
        Self {
            received_at,
            expires_at,
        }
    }
}

/// A single grant request, driven from the client side.
pub struct Session<'a, T, S> {
    transport: &'a T,
    signer: &'a S,
    endpoint: String,
    protocol: SessionState,
    /// The interaction start modes this client can actually drive (§2.5).
    /// `None` leaves that check to the caller; see [`Session::supporting`].
    supported_modes: Option<Vec<String>>,
    /// Signers of tokens whose key was rotated (§6.1.1), by token value.
    ///
    /// Kept outside [`SessionState`] so that an unusable response still rolls
    /// the protocol state back exactly; this map changes only on success. The
    /// session's own signer keeps signing the continuation and every token
    /// not listed here.
    rotated: HashMap<String, &'a dyn Signer>,
}

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

impl<'a, T: HttpTransport, S: Signer> Session<'a, T, S> {
    /// Starts a session against a grant endpoint.
    ///
    /// The endpoint URI identifies the AS (§1.2) and feeds the interaction hash
    /// (§4.2.3), so it is kept exactly as given.
    pub fn new(transport: &'a T, signer: &'a S, endpoint: impl Into<String>) -> Self {
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
            },
            supported_modes: None,
            rotated: HashMap::new(),
        }
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
        // §2.3 — what the client says about itself is checked before it leaves.
        // §2.3-MN09 binds the client, not the AS: "The client instance MUST NOT
        // send a symmetric key by value in the key field of the request". A
        // type that can refuse such a key is no use if the client never asks
        // it to.
        if let Some(client) = request.client.as_value() {
            if let Some(key) = client.key.as_value() {
                key.validate()
                    .map_err(|e| ClientError::Usage(format!("client.key: {e}")))?;
                // §2.3-M07 — the key is "the proofing mechanism associated with
                // the key", and the only one this session can perform is
                // `httpsig` (§7.3.1). Declaring another would promise the AS a
                // proof that never comes.
                let method = key.proof.method().as_str();
                if method != "httpsig" {
                    return Err(ClientError::Usage(format!(
                        "client.key.proof: this session signs with `httpsig` and cannot \
                         present a `{method}` proof; the key MUST be used with the proofing \
                         mechanism it declares (RFC 9635 §2.3, §7.3)"
                    )));
                }
            }
            if let Some(display) = &client.display {
                display
                    .validate()
                    .map_err(|e| ClientError::Usage(e.to_string()))?;
            }
        }

        self.protocol.requested = request.access_token.as_ref().map(|a| a.cardinality);
        self.protocol.requested_labels = requested_labels(request.access_token.as_ref());
        self.prepare_interaction(request.interact.as_ref())?;

        let body = serde_json::to_vec(request)
            .map_err(|e| ClientError::Usage(format!("serializing the request: {e}")))?;
        let http = Self::signed_request(
            "POST",
            &self.endpoint.clone(),
            Some(body),
            None,
            self.signer,
            now,
        )?;
        let response = self.round_trip(http)?;
        self.absorb(&response, now)
    }

    /// Validates the interaction context before sending an initial request or PATCH.
    fn prepare_interaction(
        &mut self,
        interaction: Option<&gnap_types::interact::InteractRequest>,
    ) -> Result<(), ClientError> {
        if interaction.is_some() {
            self.protocol.client_nonce = None;
            self.protocol.hash_method = None;
        }
        // The nonce the client chose feeds the interaction hash later (§4.2.3).
        if let Some(i) = interaction {
            if let Some(f) = &i.finish {
                // §2.5.2 — the callback is validated against this nonce and
                // this algorithm, so both have to be usable now.
                f.validate()
                    .map_err(|e| ClientError::Usage(e.to_string()))?;
                let name = f.effective_hash_method();
                let method = HashMethod::from_name(name).ok_or_else(|| {
                    ClientError::Usage(format!(
                        "interact.finish.hash_method `{name}` is not one this client can \
                         compute, so it could not validate the callback (RFC 9635 §4.2.3)"
                    ))
                })?;
                self.protocol.client_nonce = Some(f.nonce.clone());
                self.protocol.hash_method = Some(method);
            }
        }
        if let Some(i) = interaction {
            self.protocol.offered_modes = i
                .start
                .iter()
                .map(|m| m.method().as_str().to_owned())
                .collect();

            // §2.5-MN01 — declaring a mode this client cannot drive strands the
            // end user in front of something nobody will finish.
            if let Some(supported) = &self.supported_modes {
                if let Some(unsupported) = self
                    .protocol
                    .offered_modes
                    .iter()
                    .find(|m| !supported.contains(m))
                {
                    return Err(ClientError::Usage(format!(
                        "the request declares the `{unsupported}` interaction mode, which \
                         this client does not support; a client instance MUST NOT declare \
                         an interaction mode it does not support (RFC 9635 §2.5)"
                    )));
                }
            }
        }

        Ok(())
    }

    /// Reads and validates a callback arriving on the redirect URI (§4.2.1).
    ///
    /// §4.2.1-M05 has the client "parse the query parameters to extract the
    /// hash and interaction reference values"; this does that and then the
    /// validation of [`Session::accept_callback`]. The application must still
    /// bind this callback endpoint to the correct browser session.
    ///
    /// `uri` is what the browser arrived at, or just its query.
    /// `now` is the current Unix time in seconds, using the same clock as
    /// [`Session::start`] and [`Session::continue_grant`].
    ///
    /// # Errors
    ///
    /// Fails when the query does not carry both values, or for the same reasons
    /// as [`Session::accept_callback`].
    pub fn accept_redirect(&mut self, uri: &str, now: u64) -> Result<(), ClientError> {
        let callback = InteractCallback::from_redirect(uri)
            .map_err(|e| ClientError::Interaction(e.to_string()))?;
        self.accept_callback(&callback, now)
    }

    /// Reads and validates a callback pushed to the client (§4.2.2).
    ///
    /// §4.2.2-M04 has the client "parse the JSON object and validate the hash
    /// value as described in Section 4.2.3", and §4.2.2-M05 has it answer
    /// `unknown_interaction` if either fails — which is the error this returns.
    /// `now` is the current Unix time in seconds, on the session's clock.
    ///
    /// # Errors
    ///
    /// Fails when the content is not the JSON object §4.2.2 describes, or for
    /// the same reasons as [`Session::accept_callback`].
    pub fn accept_push(&mut self, body: &[u8], now: u64) -> Result<(), ClientError> {
        let callback = InteractCallback::from_push(body)
            .map_err(|e| ClientError::Interaction(e.to_string()))?;
        self.accept_callback(&callback, now)
    }

    /// Validates an interaction callback and holds on to its reference (§4.2).
    ///
    /// GNAP-9635-§4.2.1-M06 — the client calculates and validates the hash.
    /// GNAP-9635-§4.2.1-MN07 — if it does not validate, the reference is not
    /// sent to the AS. That is why the reference is stored here rather than
    /// handed straight to [`Session::continue_grant`].
    ///
    /// `now` is the current Unix time in seconds. An advertised interaction
    /// lifetime (§3.3) starts at the `now` supplied when its response was
    /// received. Callbacks at or after that deadline, or before receipt, are
    /// refused without changing the stored reference. RFC 9635 §4 recommends
    /// suitable finish timeouts (SHOULD); this enforces the AS's advertised
    /// duration, not an additional client timeout when the duration is absent.
    ///
    /// # Errors
    ///
    /// Fails when no finish was negotiated, its advertised lifetime has ended,
    /// the clock precedes receipt, the hash is invalid, or a valid callback was
    /// already accepted. A refused callback does not replace a validated one.
    pub fn accept_callback(
        &mut self,
        callback: &InteractCallback,
        now: u64,
    ) -> Result<(), ClientError> {
        let (Some(client_nonce), Some(as_nonce)) =
            (&self.protocol.client_nonce, &self.protocol.as_nonce)
        else {
            return Err(ClientError::Usage(
                "no interaction finish was negotiated, so no callback can be validated \
                 (RFC 9635 §2.5.2)"
                    .into(),
            ));
        };
        if self
            .protocol
            .interaction_window
            .as_ref()
            .is_some_and(|window| {
                now < window.received_at
                    || window
                        .expires_at
                        .is_some_and(|deadline| u128::from(now) >= deadline)
            })
        {
            return Err(ClientError::Interaction(
                "the interaction response has expired or the clock precedes its receipt (RFC 9635 §3.3; finish timeout recommendation in §4)".into(),
            ));
        }

        let input = InteractionHashInput {
            client_nonce,
            as_nonce,
            interact_ref: &callback.interact_ref,
            grant_endpoint: &self.endpoint,
        };
        // §4.2.3 — absence selects the default; a value that was present and
        // unusable never got this far.
        let method = self.protocol.hash_method.unwrap_or(HashMethod::DEFAULT);

        let ok = verify_interaction_hash(&input, method, &callback.hash)
            .map_err(|e| ClientError::Interaction(e.to_string()))?;

        if !ok {
            // §4.2.2-M05 — "If either fails, the client instance MUST return an
            // unknown_interaction error", which is the code this carries.
            return Err(ClientError::Interaction(
                "the interaction hash does not validate; the client MUST NOT send the \
                 interaction reference to the AS (RFC 9635 §4.2.1)"
                    .into(),
            ));
        }

        if self.protocol.interaction_finished || self.protocol.grant.state() != State::Pending {
            return Err(ClientError::Interaction(
                "this interaction is no longer awaiting a callback (RFC 9635 §4)".into(),
            ));
        }
        self.protocol.validated_ref = Some(callback.interact_ref.clone());
        self.protocol.interaction_finished = true;
        Ok(())
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
            "POST",
            &cont.uri,
            body,
            Some(&cont.access_token.value),
            self.signer,
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
            "PATCH",
            &cont.uri,
            Some(body),
            Some(&cont.access_token.value),
            self.signer,
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
            "DELETE",
            &continuation.uri,
            None,
            Some(&continuation.access_token.value),
            self.signer,
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

    /// Rotates a token's value through its management API (§6.1).
    ///
    /// "Rotating an access token consists of issuing a new access token in
    /// place of an existing access token, with the same rights and properties
    /// as the original token, apart from an updated token value and expiration
    /// time." The rights cannot be changed here: §6.1 sends a client that wants
    /// different access to the continuation API (§5.3) or to a new grant.
    ///
    /// `label` names the token when several are held (§3.2.2); `None` selects
    /// the token when exactly one is held, labelled or not. The rotated token
    /// replaces it in the session, with the new management URI §6.1-M04
    /// requires the client to use from then on.
    ///
    /// The rotation answers with one token in the form of §3.2.1, whatever
    /// the shape of the grant that issued it; the session refuses an array.
    ///
    /// §6.1 describes the rotated token as having "the same rights and
    /// properties as the original token, apart from an updated token value and
    /// expiration time". Of the properties compared here (rights, label, flags
    /// and key), only the rights carry a stated MUST (§6.1-M05). For the rest,
    /// this session compares meaning rather than bytes and refuses what it cannot
    /// keep presenting as the same token: a label the answer omits is kept, a
    /// changed label is refused since the label is how the session names the
    /// token; flags are compared as a set; a `key` field is unchanged only when
    /// both answers omit it or both spell out the same key, since the session
    /// holds no key material to compare and a `kid` is a name, not a key
    /// (§3.2.1). Binding another key is a different operation (§6.1.1) that
    /// this method does not perform; use [`Self::rotate_key`] instead.
    ///
    /// # Errors
    ///
    /// Fails when no such token is held, when it carries no `manage` field,
    /// when the AS refuses the rotation, or when the answer does not keep the
    /// rights §6.1-M05 requires it to keep, repeats the value §6.1 forbids it to
    /// repeat, or changes the label, flags or key binding as described above.
    pub fn rotate_token(
        &mut self,
        label: Option<&str>,
        now: u64,
    ) -> Result<AccessToken, ClientError> {
        let (index, manage) = self.managed(label)?;
        let previous_value = self.held_value(index)?;
        let signer = self.management_signer(index)?;
        let response = self.call_management("POST", &manage, None, signer, now)?;
        let parsed = grant_response(&response)?;

        let rotated = {
            let previous = &self.held(index)?.1;
            let rotated = checked_rotation(parsed, previous, &manage)?;
            if !same_binding(rotated.key.as_ref(), previous.key.as_ref()) {
                return Err(ClientError::Protocol(
                    "the session cannot establish that the rotated token keeps the original \
                     token's key binding; binding a new key is a separate operation, \
                     `rotate_key` (RFC 9635 §6.1, §6.1.1)"
                        .into(),
                ));
            }
            rotated
        };
        self.adopt_rotated(index, &previous_value, rotated, None, now)
    }

    /// Binds a new key to a held token (§6.1.1), keeping its value's lifecycle.
    ///
    /// The request carries `presented`, the new public key, in its body, and
    /// two signatures: the token's current key signs as usual, then
    /// `replacement` signs with the `gnap-rotate` tag over that first
    /// signature (§7.3.1.1). `presented` must be a public PS256 JWK by value
    /// whose `kid` is the `keyid` of `replacement`. A reference, another
    /// format, another proofing method or any proofing parameter, a private
    /// or symmetric member, a certificate or a mismatched `kid` is refused
    /// before anything is sent; these are the limits of this session.
    ///
    /// The answer is checked like a value rotation (one token in the form of
    /// §3.2.1, new value, same rights, kept label, same flags, a management
    /// URI) and, in addition, has to name the new key: §3.2.1 makes an omitted
    /// `key` mean the key of the grant request, so only a `key` equal to
    /// `presented` shows that the AS bound the token to the new key. From then
    /// on this session signs that token's management with `replacement`, and
    /// [`Session::signer_for`] hands it to the application for its resource
    /// requests. The continuation keeps the session's signer, and every other
    /// token keeps the signer it has, rotated or not. A bearer token has no key
    /// to rotate (§6.1.1) and is refused before anything is sent. Any refusal
    /// leaves the token, its key and this session unchanged (§6.1: the client
    /// "MUST consider the access token to not have changed its state").
    ///
    /// # Errors
    ///
    /// [`ClientError::Usage`] when the key cannot be presented by this session
    /// or no such managed token is held; [`ClientError::Server`] for a GNAP
    /// error such as `invalid_rotation` or `key_rotation_not_supported`;
    /// [`ClientError::Protocol`] when the answer breaks a rule above.
    pub fn rotate_key(
        &mut self,
        label: Option<&str>,
        replacement: &'a dyn Signer,
        presented: &Key,
        now: u64,
    ) -> Result<AccessToken, ClientError> {
        let (object, verifier) = rotation::presentable(presented, replacement)?;
        let (index, manage) = self.managed(label)?;
        let previous_value = self.held_value(index)?;
        let current = self.presentation_signer(index)?;
        let body = serde_json::to_vec(&serde_json::json!({ "key": object }))
            .map_err(|e| ClientError::Usage(format!("serializing the new key: {e}")))?;
        let http = HttpRequest::new("POST", &manage.uri).json_body(body);
        let http = rotation::sign_key_rotation(
            http,
            current,
            replacement,
            &verifier,
            &manage.access_token.value,
            now,
        )?;
        let response = self.round_trip(http)?;
        let parsed = grant_response(&response)?;

        let rotated = {
            let previous = &self.held(index)?.1;
            let rotated = checked_rotation(parsed, previous, &manage)?;
            // §3.2.1 — `key` is "The key that the token is bound to, if
            // different from the client instance's presented key"; omitted, it
            // means the grant request's key (§2.3), not the key of this body.
            // Only an explicit, identical key shows the new binding took.
            if rotated.key.as_ref() != Some(presented) {
                return Err(ClientError::Protocol(
                    "the key-rotation response does not name the presented key as the \
                     token's key binding; an omitted or different key means the AS did not \
                     bind the token to the new key (RFC 9635 §3.2.1, §6.1.1)"
                        .into(),
                ));
            }
            rotated
        };
        self.adopt_rotated(index, &previous_value, rotated, Some(replacement), now)
    }

    /// The signer that presents a held token: the key it was rotated to, or
    /// the session's key. The application signs its resource requests with it.
    /// A token does not need a management API to be presented to a resource.
    ///
    /// This session knows its implicit grant key and keys adopted by its own
    /// successful rotations. An initially issued explicit key is not resolved
    /// here, even if it might be equivalent to the grant key: matching a `kid`
    /// does not establish that equivalence. Such a token needs an application
    /// adapter. A bearer token is presented without a key proof.
    ///
    /// # Errors
    ///
    /// Fails when no such token is held, the token is bearer, or its explicit
    /// binding is not known to this session. `None` is ambiguous with several
    /// held tokens. No request is sent and no signature is made by this lookup.
    pub fn signer_for(&self, label: Option<&str>) -> Result<&'a dyn Signer, ClientError> {
        self.presentation_signer(self.select(label)?)
    }

    fn presentation_signer(&self, index: usize) -> Result<&'a dyn Signer, ClientError> {
        let token = &self.held(index)?.1;
        if token.is_bearer() {
            return Err(ClientError::Usage(
                "a bearer token has no presentation key; present it without a key proof".into(),
            ));
        }
        if let Some(signer) = self.rotated.get(token.value.as_str()) {
            return Ok(*signer);
        }
        if token.key.is_some() {
            return Err(ClientError::Usage(
                "this session cannot establish the signer for an initially explicit token key; \
                 an application key adapter is required"
                    .into(),
            ));
        }
        Ok(self.signer)
    }

    fn management_signer(&self, index: usize) -> Result<&'a dyn Signer, ClientError> {
        // §7.3 binds bearer-token management to the client instance's key.
        if self.held(index)?.1.is_bearer() {
            Ok(self.signer)
        } else {
            self.presentation_signer(index)
        }
    }

    fn held(&self, index: usize) -> Result<&(u64, AccessToken), ClientError> {
        self.protocol
            .issued
            .as_ref()
            .and_then(|held| held.get(index))
            .ok_or_else(|| {
                ClientError::Usage("the session no longer holds the token that was rotated".into())
            })
    }

    fn held_value(&self, index: usize) -> Result<TokenValue, ClientError> {
        Ok(self.held(index)?.1.value.clone())
    }

    /// Installs a rotated token and moves or sets its signer, on success only.
    fn adopt_rotated(
        &mut self,
        index: usize,
        previous_value: &TokenValue,
        rotated: AccessToken,
        new_signer: Option<&'a dyn Signer>,
        now: u64,
    ) -> Result<AccessToken, ClientError> {
        let Some(held) = self.protocol.issued.as_mut() else {
            return Err(ClientError::Usage(
                "the session no longer holds the token that was rotated".into(),
            ));
        };
        // The session tells its tokens, and their signers, apart by value. A
        // value that already names a sibling cannot be adopted without
        // confusing the two; GNAP expects distinct values anyway (§3.2.2:
        // "each access token is expected to have a unique value").
        if held
            .iter()
            .enumerate()
            .any(|(i, (_, token))| i != index && token.value == rotated.value)
        {
            return Err(ClientError::Protocol(
                "the rotated token repeats the value of another token this session holds; \
                 the session cannot tell them apart (RFC 9635 §3.2.2)"
                    .into(),
            ));
        }
        let carried = self.rotated.remove(previous_value.as_str());
        if let Some(signer) = new_signer.or(carried) {
            self.rotated
                .insert(rotated.value.as_str().to_owned(), signer);
        }
        // §6.1 — the rotation carries "an updated token value and expiration
        // time", so `expires_in` starts running again, from now.
        held[index] = (now, rotated.clone());
        Ok(rotated)
    }

    /// Revokes a token through its management API (§6.2).
    ///
    /// §6.2 is for the client's own use: when the user says they no longer want
    /// it to have access, or the application sees itself being uninstalled.
    ///
    /// # Errors
    ///
    /// Fails when no such token is held, when it carries no `manage` field, or
    /// when the exchange does.
    pub fn revoke_token(&mut self, label: Option<&str>, now: u64) -> Result<(), ClientError> {
        let (index, manage) = self.managed(label)?;
        let value = self.held_value(index)?;
        let signer = self.management_signer(index)?;
        let response = self.call_management("DELETE", &manage, None, signer, now)?;

        if response.status != 204 {
            return Err(ClientError::Protocol(format!(
                "revoking answered {} where §6.2 says 204 No Content",
                response.status
            )));
        }
        if let Some(tokens) = self.protocol.issued.as_mut() {
            tokens.remove(index);
        }
        self.rotated.remove(value.as_str());
        Ok(())
    }

    /// Finds a held token by label, independently of its management API.
    ///
    /// `None` names the only token held, whether or not it carries a label
    /// (§3.2.1 lets the AS label a single token); with several held, a caller
    /// has to say which one, since the labels are what tells them apart
    /// (§3.2.2).
    fn select(&self, label: Option<&str>) -> Result<usize, ClientError> {
        let tokens = self.protocol.issued.as_ref().ok_or_else(|| {
            ClientError::Usage("no access token has been issued to this session".into())
        })?;
        let index = match label {
            Some(wanted) => tokens
                .iter()
                .position(|(_, t)| t.label.as_deref() == Some(wanted))
                .ok_or_else(|| {
                    ClientError::Usage(format!("no access token is labelled {wanted:?}"))
                })?,
            None if tokens.len() == 1 => 0,
            None => {
                return Err(ClientError::Usage(format!(
                    "{} access tokens are held; select one by its label \
                     (RFC 9635 §3.2.2)",
                    tokens.len()
                )));
            }
        };
        Ok(index)
    }

    /// Finds the selected token's optional management API (§3.2.1).
    fn managed(&self, label: Option<&str>) -> Result<(usize, TokenManage), ClientError> {
        let index = self.select(label)?;
        let manage = self.held(index)?.1.manage.clone().ok_or_else(|| {
            ClientError::Usage(
                "this access token carries no `manage` field, so there is no management \
                 API to call (RFC 9635 §3.2.1, §6)"
                    .into(),
            )
        })?;
        Ok((index, manage))
    }

    /// Makes a signed call to a token management URI (§6, §7.2).
    fn call_management(
        &self,
        method: &str,
        manage: &TokenManage,
        body: Option<Vec<u8>>,
        signer: &dyn Signer,
        now: u64,
    ) -> Result<HttpResponse, ClientError> {
        // §6 — "The client instance MUST present proof of the key associated
        // with the token along with the value of the token management access
        // token", which is §7.2 applied to the management token. After a key
        // rotation (§6.1.1) that key is the token's new key, not the session's.
        let http = Self::signed_request(
            method,
            &manage.uri,
            body,
            Some(&manage.access_token.value),
            signer,
            now,
        )?;
        self.round_trip(http)
    }

    /// Builds a signed request (§7.2, §7.3.1).
    fn signed_request(
        method: &str,
        url: &str,
        body: Option<Vec<u8>>,
        token: Option<&TokenValue>,
        signer: &dyn Signer,
        now: u64,
    ) -> Result<HttpRequest, ClientError> {
        let mut http = HttpRequest::new(method, url);
        if let Some(b) = body {
            http = http.json_body(b);
        }
        crate::sign_request(http, signer, token, now)
    }

    fn round_trip(&self, request: HttpRequest) -> Result<HttpResponse, ClientError> {
        self.transport
            .send(request)
            .map_err(|e| ClientError::Transport(e.to_string()))
    }

    /// Applies the checks §3.2 places on the client, not on the AS.
    ///
    /// GNAP-9635-§3.2.1-M30 — a `bearer` token carrying a `key` is rejected.
    /// GNAP-9635-§3.2.1-MN31, GNAP-9635-§3.2.2-MN03 — the response shape must
    /// follow the request's, even when a single token comes back.
    fn check_tokens(&self, response: &GrantResponse) -> Result<(), ClientError> {
        let Some(tokens) = &response.access_token else {
            return Ok(());
        };
        tokens
            .validate()
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        let Some(requested) = self.protocol.requested else {
            return Ok(());
        };
        tokens
            .check_cardinality(requested)
            .map_err(|e| ClientError::Protocol(e.to_string()))?;
        match requested {
            // §3.2.2 — "Each object MUST have a unique label field,
            // corresponding to the token labels chosen by the client instance
            // in the request for multiple access tokens". Presence and
            // uniqueness are checked when the array is read; correspondence
            // needs the request, which only the session has. A requested label
            // that does not come back is a token the AS refused, which §3.2.2
            // allows "for any reason"; a label that was never requested is not
            // a token of this grant.
            Cardinality::Multiple => {
                for token in &tokens.tokens {
                    let label = token.label.as_deref();
                    if !self
                        .protocol
                        .requested_labels
                        .iter()
                        .any(|wanted| wanted.as_deref() == label)
                    {
                        return Err(ClientError::Protocol(format!(
                            "the response carries an access token labelled {label:?}, which the \
                             request did not ask for; labels correspond to the request \
                             (RFC 9635 §3.2.2)"
                        )));
                    }
                }
            }
            // §3.2.1 — `label` is "REQUIRED for multiple access tokens or if a
            // label was included in the single access token request; OPTIONAL
            // for a single access token where no label was included in the
            // request". So a requested label has to come back as it was, and
            // an unrequested one is the AS's to add.
            Cardinality::Single => {
                if let Some(Some(wanted)) = self.protocol.requested_labels.first() {
                    let answered = tokens.tokens.first().and_then(|t| t.label.as_deref());
                    if answered != Some(wanted.as_str()) {
                        return Err(ClientError::Protocol(format!(
                            "the single access token was requested with the label {wanted:?} \
                             and came back labelled {answered:?}; the label is REQUIRED when \
                             the request included one (RFC 9635 §3.2.1)"
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Catches an AS offering an interaction mode that was never on the table.
    ///
    /// GNAP-9635-§3.3-MN09 binds the AS, not the client: "The AS MUST NOT
    /// respond with any interaction mode that the client instance did not
    /// indicate in its request." A client cannot stop it, but it can refuse to
    /// act on a mode it never offered — which is how a non-conformant AS gets
    /// noticed instead of followed.
    fn check_interaction(&self, response: &GrantResponse) -> Result<(), ClientError> {
        let Some(interact) = &response.interact else {
            return Ok(());
        };
        let offered = |mode: &str| self.protocol.offered_modes.iter().any(|m| m == mode);

        for (mode, present) in [
            ("redirect", interact.redirect.is_some()),
            ("app", interact.app.is_some()),
            ("user_code", interact.user_code.is_some()),
            ("user_code_uri", interact.user_code_uri.is_some()),
        ] {
            if present && !offered(mode) {
                return Err(ClientError::Protocol(format!(
                    "the response offers the `{mode}` interaction mode, which this client \
                     never indicated; the AS MUST NOT respond with a mode the client did \
                     not offer (RFC 9635 §3.3)"
                )));
            }
        }
        Ok(())
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

    /// Parses a response, checks what the client must check, and advances the
    /// grant.
    fn absorb(&mut self, http: &HttpResponse, now: u64) -> Result<Step, ClientError> {
        let response = grant_response(http)?;

        self.check_tokens(&response)?;
        self.check_interaction(&response)?;

        let interaction_window = response
            .interact
            .as_ref()
            .map(|interaction| InteractionWindow::new(now, interaction.expires_in));

        // The AS decides the state; the client infers it from what came back.
        let event = if response.access_token.is_some() || response.subject.is_some() {
            Event::AsNeedsNoInteraction
        } else if response.interact.is_some() || response.r#continue.is_some() {
            Event::AsRequiresInteraction
        } else {
            Event::AsCannotProceed
        };
        // §5.2 — polling a pending grant can find it approved: the RO answered
        // somewhere the client cannot see, and the AS re-evaluated the request.
        // The response is the only notice the client gets, so it has to be
        // willing to leave `pending` on the strength of it. Refusing would
        // strand the client polling a grant that has already been decided.
        if self.protocol.grant.state() == State::Pending
            && (response.access_token.is_some() || response.subject.is_some())
        {
            self.protocol
                .grant
                .apply(Event::OutOfBandRoDecision, now)
                .map_err(|e| ClientError::Protocol(e.to_string()))?;
        }

        if self.protocol.grant.state() == State::Processing {
            self.protocol
                .grant
                .apply(event, now)
                .map_err(|e| ClientError::Protocol(e.to_string()))?;
        }

        // What the AS sent must be legal in the state it implies.
        let violations = check_response(self.protocol.grant.state(), &response);
        if let Some(v) = violations.first() {
            return Err(ClientError::Protocol(v.to_string()));
        }

        if let Some(subject) = &response.subject {
            // §3.4-M14 — everything the AS states has to name one party.
            subject
                .validate()
                .map_err(|e| ClientError::Protocol(e.to_string()))?;
            self.protocol.subject = Some(Box::new(subject.clone()));
        }

        // §3.2.1 — `expires_in` is a duration; it starts running when the
        // response arrives, which is here and nowhere else.
        if let Some(tokens) = &response.access_token {
            self.protocol.issued = Some(tokens.tokens.iter().map(|t| (now, t.clone())).collect());
        }

        if let Some(c) = &response.r#continue {
            // §3.1-M02 with §3.1-M03: the client must use this URI exactly as
            // given, so it has to be one that can be used as it stands.
            c.validate()
                .map_err(|e| ClientError::Protocol(e.to_string()))?;
            self.protocol.grant.offer_continuation(now, c.wait);
            self.protocol.continuation = Some(c.clone());
        } else {
            self.protocol.grant.withhold_continuation();
            self.protocol.continuation = None;
        }

        if let Some(i) = &response.interact {
            self.protocol.as_nonce.clone_from(&i.finish);
            self.protocol.interaction_window = interaction_window;
            self.protocol.interaction_finished = false;
            self.protocol.validated_ref = None;
        }

        // A newly issued lot binds its tokens to the grant request's key
        // (§3.2.1), whatever values it reuses: no rotated key carries over.
        // Management calls never come through here, so their signers stay.
        if response.access_token.is_some() {
            self.rotated.clear();
        }

        Ok(match (&response.error, self.protocol.grant.state()) {
            (Some(e), _) if response.r#continue.is_none() => Err(ClientError::Server(e.clone()))?,
            (Some(_), _) => Step::Recoverable(Box::new(response)),
            (None, State::Approved) => Step::Approved(Box::new(response)),
            (None, _) => Step::Pending(Box::new(response)),
        })
    }
}

/// The labels a token request carries, in order, one per token (§2.1).
///
/// A request for several tokens labels each of them (§2.1.2); a single token
/// may or may not be labelled (§2.1.1). No `access_token` field asks for no
/// token.
fn requested_labels(request: Option<&AccessTokenRequest>) -> Vec<Option<String>> {
    request
        .map(|tokens| tokens.tokens.iter().map(|t| t.label.clone()).collect())
        .unwrap_or_default()
}

/// Reads a grant response the way every POST/PATCH exchange has to: an HTTP
/// answer that is not a usable GNAP message says nothing authoritative about
/// the grant or a token, and must not be acted on.
///
/// A 204 supplies no message (§5.4 uses it for DELETE only); an incompatible
/// or repeated Content-Type is not the JSON the protocol speaks (§3); a
/// non-success status without a GNAP error is an inconclusive failure, while a
/// valid GNAP error keeps its meaning whatever the status carries it (§3.6).
fn grant_response(http: &HttpResponse) -> Result<GrantResponse, ClientError> {
    if http.status == 204 {
        // §5.4 uses 204 for DELETE, not for these POST/PATCH exchanges.
        // It supplies no grant response from which to infer local state.
        return Err(ClientError::Protocol(
            "the AS answered 204 No Content without a usable grant response".into(),
        ));
    }

    let mut content_types = http.header_values("content-type");
    if let Some(content_type) = content_types.next() {
        if content_types.next().is_some()
            || !content_type
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case("application/json")
        {
            return Err(ClientError::Protocol(
                "the response has an incompatible or repeated Content-Type".into(),
            ));
        }
    }

    let response: GrantResponse =
        serde_json::from_slice(&http.body).map_err(|e| ClientError::Parse(e.to_string()))?;

    if !(200..300).contains(&http.status) && response.error.is_none() {
        return Err(ClientError::Protocol(
            "a non-success HTTP response carries no GNAP error".into(),
        ));
    }
    Ok(response)
}

/// The checks a rotation answer has to pass before either kind of rotation
/// looks at the key binding (§6.1).
fn checked_rotation(
    parsed: GrantResponse,
    previous: &AccessToken,
    manage: &TokenManage,
) -> Result<AccessToken, ClientError> {
    if let Some(e) = parsed.error {
        // §6.1-M06 — "Upon receiving such an error, the client instance
        // MUST consider the access token to not have changed its state."
        // Nothing here has touched what the session holds.
        return Err(ClientError::Server(e));
    }

    // §6.1 — the AS responds with "the rotated access token in the
    // access_token field described in Section 3.2.1": one token object,
    // even when the grant issued several (§3.2.2). Taking the first entry
    // of an array would silently accept a different exchange.
    let Some(tokens) = parsed.access_token else {
        return Err(ClientError::Protocol(
            "the rotation response carries no access token (RFC 9635 §6.1)".into(),
        ));
    };
    if tokens.cardinality != Cardinality::Single || tokens.tokens.len() != 1 {
        return Err(ClientError::Protocol(
            "the rotation response carries several access tokens where §6.1 describes \
             one rotated token in the form of §3.2.1"
                .into(),
        ));
    }
    let mut rotated = tokens
        .tokens
        .into_iter()
        .next()
        .ok_or_else(|| ClientError::Protocol("the rotation response is empty".into()))?;
    rotated
        .validate()
        .map_err(|e| ClientError::Protocol(e.to_string()))?;

    // §6.1 — "The value of the access token MUST NOT be the same as the
    // current value of the access token used to access the management API."
    if rotated.value == manage.access_token.value {
        return Err(ClientError::Protocol(
            "the rotated token reuses the previous management credential (RFC 9635 §6.1)".into(),
        ));
    }
    // The same section describes replacing the resource token with an
    // updated value. Its old value and the management credential above
    // are distinct: neither may become the new resource token.
    if rotated.value == previous.value {
        return Err(ClientError::Protocol(
            "the rotated token repeats the value it was meant to replace (RFC 9635 §6.1)".into(),
        ));
    }
    // §6.1-M05 — "The access rights in the access array for the rotated
    // access token MUST be included in the response and MUST be the same as
    // the token before rotation."
    if rotated.access != previous.access {
        return Err(ClientError::Protocol(
            "the rotated token does not carry the same access rights as the token it \
             replaces (RFC 9635 §6.1)"
                .into(),
        ));
    }
    // §6.1 — a rotation issues a token "with the same rights and properties
    // as the original token, apart from an updated token value and
    // expiration time". That sentence describes the operation; it states
    // no MUST beyond the rights. What follows is this session's reading of
    // it: the label is the name the session manages the token by (§3.2.2),
    // and the flags decide how it is presented (§7.2), so a token that
    // changes them is not one the session can go on using as the same.
    match (&rotated.label, &previous.label) {
        (None, kept) => rotated.label.clone_from(kept),
        (Some(answered), Some(kept)) if answered == kept => {}
        (Some(_), _) => {
            return Err(ClientError::Protocol(
                "the rotated token changes the label the session manages the token by; \
                 this session keeps a rotated token under its original label \
                 (RFC 9635 §6.1 describes a rotation as keeping the token's properties)"
                    .into(),
            ));
        }
    }
    if !same_flags(&rotated.flags, &previous.flags) {
        return Err(ClientError::Protocol(
            "the rotated token changes the flags of the token it replaces; this session \
             does not present a rotated token differently from the original \
             (RFC 9635 §6.1)"
                .into(),
        ));
    }
    // §6.1-M03 — "The response MUST include an access token management
    // URI", which §6.1-M04 has the client use from now on.
    if rotated.manage.is_none() {
        return Err(ClientError::Protocol(
            "the rotated token carries no management URI (RFC 9635 §6.1)".into(),
        ));
    }
    Ok(rotated)
}

/// Whether two flag lists say the same thing (§3.2.1).
///
/// Flags are a set: §3.2.1 forbids repeating one, and their order carries no
/// meaning, so `["durable", "x"]` and `["x", "durable"]` are the same flags.
fn same_flags(answered: &[AccessTokenFlag], previous: &[AccessTokenFlag]) -> bool {
    answered.len() == previous.len() && answered.iter().all(|flag| previous.contains(flag))
}

/// Whether two `key` fields are known to name the same binding (§3.2.1).
///
/// An omitted `key` binds the token to the key the client presented, which is
/// the session's signer. The session holds no copy of its public key, only
/// the `kid` it signs with, and a `kid` is a name, not a key: two different
/// keys can carry the same one. So an answer that spells a key out where the
/// original omitted it, or the reverse, cannot be established as unchanged
/// and is refused; two explicit fields have to match as written. A caller
/// that can compare key material has to do so outside the session.
fn same_binding(answered: Option<&Key>, previous: Option<&Key>) -> bool {
    match (answered, previous) {
        (None, None) => true,
        (Some(a), Some(p)) => a == p,
        (Some(_), None) | (None, Some(_)) => false,
    }
}

#[cfg(test)]
mod tests;
