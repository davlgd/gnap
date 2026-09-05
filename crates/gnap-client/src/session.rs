//! Driving one grant request from the client side.
//!
//! A [`Session`] holds the state of a single grant and enforces, on every
//! response, the rules RFC 9635 places on the client:
//!
//! - the response shape must match what was requested (§3.2.1, §3.2.2);
//! - a `bearer` token must never carry a `key` (§3.2.1);
//! - the interaction hash must validate before the reference is sent on
//!   (§4.2.1);
//! - the `wait` period must have elapsed before the next continuation (§5);
//! - the continuation URI must be used exactly as given (§3.1).
//!
//! What the AS is allowed to put in a response depends on the state of the
//! grant, so the session carries a [`Grant`] from `gnap-core` and checks each
//! response against it.

use crate::error::ClientError;
use crate::transport::{HttpRequest, HttpResponse, HttpTransport};
use gnap_core::{check_response, Event, Grant, State};
use gnap_crypto::hash::{verify_interaction_hash, HashMethod, InteractionHashInput};
use gnap_crypto::proof::Signer;
use gnap_types::interact::InteractCallback;
use gnap_types::message::{Continue, ContinueRequest, GrantRequest, GrantResponse};
use gnap_types::token::{AccessToken, Cardinality, TokenManage, TokenValue};
use gnap_types::user::SubjectResponse;

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
    /// The interaction start modes this client can actually drive (§2.5).
    ///
    /// `None` means the caller has not said, and the check of §2.5-MN01 does
    /// not run; see [`Session::supporting`].
    supported_modes: Option<Vec<String>>,
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
            grant: Grant::new(),
            continuation: None,
            client_nonce: None,
            as_nonce: None,
            hash_method: None,
            requested: None,
            offered_modes: Vec::new(),
            validated_ref: None,
            subject: None,
            issued: None,
            interaction_finished: false,
            interaction_window: None,
            supported_modes: None,
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
            subject: self.subject.as_deref()?,
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
        self.grant.state()
    }

    /// What the AS offered for continuing, if anything.
    #[must_use]
    pub const fn continuation(&self) -> Option<&Continue> {
        self.continuation.as_ref()
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

        // The nonce the client chose feeds the interaction hash later (§4.2.3).
        if let Some(i) = &request.interact {
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
                self.client_nonce = Some(f.nonce.clone());
                self.hash_method = Some(method);
            }
        }
        self.requested = request.access_token.as_ref().map(|a| a.cardinality);
        if let Some(i) = &request.interact {
            self.offered_modes = i
                .start
                .iter()
                .map(|m| m.method().as_str().to_owned())
                .collect();

            // §2.5-MN01 — declaring a mode this client cannot drive strands the
            // end user in front of something nobody will finish.
            if let Some(supported) = &self.supported_modes {
                if let Some(unsupported) =
                    self.offered_modes.iter().find(|m| !supported.contains(m))
                {
                    return Err(ClientError::Usage(format!(
                        "the request declares the `{unsupported}` interaction mode, which \
                         this client does not support; a client instance MUST NOT declare \
                         an interaction mode it does not support (RFC 9635 §2.5)"
                    )));
                }
            }
        }

        let body = serde_json::to_vec(request)
            .map_err(|e| ClientError::Usage(format!("serializing the request: {e}")))?;
        let http = self.signed_request("POST", &self.endpoint.clone(), Some(body), None, now)?;
        let response = self.round_trip(http)?;
        self.absorb(&response, now)
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
        let (Some(client_nonce), Some(as_nonce)) = (&self.client_nonce, &self.as_nonce) else {
            return Err(ClientError::Usage(
                "no interaction finish was negotiated, so no callback can be validated \
                 (RFC 9635 §2.5.2)"
                    .into(),
            ));
        };
        if self.interaction_window.as_ref().is_some_and(|window| {
            now < window.received_at
                || window
                    .expires_at
                    .is_some_and(|deadline| u128::from(now) >= deadline)
        }) {
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
        let method = self.hash_method.unwrap_or(HashMethod::DEFAULT);

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

        if self.interaction_finished || self.grant.state() != State::Pending {
            return Err(ClientError::Interaction(
                "this interaction is no longer awaiting a callback (RFC 9635 §4)".into(),
            ));
        }
        self.validated_ref = Some(callback.interact_ref.clone());
        self.interaction_finished = true;
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
        let cont = self.continuation.clone().ok_or_else(|| {
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
        if self.as_nonce.is_some() && !self.interaction_finished {
            return Err(ClientError::Usage(
                "the AS returned a `finish` nonce, so this grant continues on the \
                 interaction reference from the callback; it MUST NOT be continued before \
                 that arrives (RFC 9635 §3.3.5)"
                    .into(),
            ));
        }

        let event = self
            .validated_ref
            .clone()
            .map_or(Event::ContinuePoll, Event::ContinueWithInteractRef);

        // gnap-core owns the wait period and the state guards. The transition
        // is decided on a copy: a signing or transport failure happens before
        // the AS has seen anything, and must leave the session able to try
        // again rather than stranded mid-transition.
        let mut attempt = self.grant.clone();
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
        let http =
            self.signed_request("POST", &cont.uri, body, Some(&cont.access_token.value), now)?;
        let response = self.round_trip(http)?;
        let before = self.grant.clone();
        self.grant = attempt;
        let step = self.absorb(&response, now)?;

        if matches!(step, Step::Recoverable(_)) {
            self.rewind(before, now);
        } else {
            // The call went through, so the reference is spent: §4.2 makes it
            // one-time-use.
            self.validated_ref = None;
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
        self.grant = before;
        if let Some(wait) = self.continuation.as_ref().map(|c| c.wait) {
            self.grant.offer_continuation(now, wait);
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
        let cont = self.continuation.clone().ok_or_else(|| {
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
        let mut attempt = self.grant.clone();
        attempt
            .apply(Event::Modify, now)
            .map_err(|e| ClientError::Usage(e.to_string()))?;

        let body = serde_json::to_vec(changes)
            .map_err(|e| ClientError::Usage(format!("serializing the modification: {e}")))?;
        let http = self.signed_request(
            "PATCH",
            &cont.uri,
            Some(body),
            Some(&cont.access_token.value),
            now,
        )?;
        let response = self.round_trip(http)?;
        let before = self.grant.clone();
        self.grant = attempt;
        let step = self.absorb(&response, now)?;

        if matches!(step, Step::Recoverable(_)) {
            self.rewind(before, now);
        }
        Ok(step)
    }

    /// Rotates a token's value through its management API (§6.1).
    ///
    /// "Rotating an access token consists of issuing a new access token in
    /// place of an existing access token, with the same rights and properties
    /// as the original token, apart from an updated token value and expiration
    /// time." The rights cannot be changed here: §6.1 sends a client that wants
    /// different access to the continuation API (§5.3) or to a new grant.
    ///
    /// `label` names the token when several were issued (§3.2.2); pass `None`
    /// for a single one. The rotated token replaces it in the session, with the
    /// new management URI §6.1-M04 requires the client to use from then on.
    ///
    /// # Errors
    ///
    /// Fails when no such token is held, when it carries no `manage` field,
    /// when the AS refuses the rotation, or when the answer does not keep the
    /// rights §6.1-M05 requires it to keep.
    pub fn rotate_token(
        &mut self,
        label: Option<&str>,
        now: u64,
    ) -> Result<AccessToken, ClientError> {
        let (index, manage) = self.managed(label)?;
        let response = self.call_management("POST", &manage, None, now)?;

        let parsed: GrantResponse = serde_json::from_slice(&response.body)
            .map_err(|e| ClientError::Parse(e.to_string()))?;
        if let Some(e) = parsed.error {
            // §6.1-M06 — "Upon receiving such an error, the client instance
            // MUST consider the access token to not have changed its state."
            // Nothing here has touched what the session holds.
            return Err(ClientError::Server(e));
        }

        let rotated = parsed
            .access_token
            .and_then(|t| t.tokens.into_iter().next())
            .ok_or_else(|| {
                ClientError::Protocol(
                    "the rotation response carries no access token (RFC 9635 §6.1)".into(),
                )
            })?;
        rotated
            .validate()
            .map_err(|e| ClientError::Protocol(e.to_string()))?;

        let Some(held) = self.issued.as_mut() else {
            return Err(ClientError::Usage(
                "the session no longer holds the token that was rotated".into(),
            ));
        };
        // §6.1-M05 — "The access rights in the access array for the rotated
        // access token MUST be included in the response and MUST be the same as
        // the token before rotation."
        if rotated.access != held[index].1.access {
            return Err(ClientError::Protocol(
                "the rotated token does not carry the same access rights as the token it \
                 replaces (RFC 9635 §6.1)"
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
        let response = self.call_management("DELETE", &manage, None, now)?;

        if response.status != 204 {
            return Err(ClientError::Protocol(format!(
                "revoking answered {} where §6.2 says 204 No Content",
                response.status
            )));
        }
        if let Some(tokens) = self.issued.as_mut() {
            tokens.remove(index);
        }
        Ok(())
    }

    /// Finds a held token by label, and the management API it offers (§3.2.1).
    fn managed(&self, label: Option<&str>) -> Result<(usize, TokenManage), ClientError> {
        let tokens = self.issued.as_ref().ok_or_else(|| {
            ClientError::Usage("no access token has been issued to this session".into())
        })?;
        let index = tokens
            .iter()
            .position(|(_, t)| t.label.as_deref() == label)
            .ok_or_else(|| ClientError::Usage(format!("no access token is labelled {label:?}")))?;
        let manage = tokens[index].1.manage.clone().ok_or_else(|| {
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
        now: u64,
    ) -> Result<HttpResponse, ClientError> {
        // §6 — "The client instance MUST present proof of the key associated
        // with the token along with the value of the token management access
        // token", which is §7.2 applied to the management token.
        let http = self.signed_request(
            method,
            &manage.uri,
            body,
            Some(&manage.access_token.value),
            now,
        )?;
        self.round_trip(http)
    }

    /// Builds a signed request (§7.2, §7.3.1).
    fn signed_request(
        &self,
        method: &str,
        url: &str,
        body: Option<Vec<u8>>,
        token: Option<&TokenValue>,
        now: u64,
    ) -> Result<HttpRequest, ClientError> {
        let mut http = HttpRequest::new(method, url);
        if let Some(b) = body {
            http = http.json_body(b);
        }
        crate::sign_request(http, self.signer, token, now)
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
        if let Some(requested) = self.requested {
            tokens
                .check_cardinality(requested)
                .map_err(|e| ClientError::Protocol(e.to_string()))?;
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
        let offered = |mode: &str| self.offered_modes.iter().any(|m| m == mode);

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

    /// Parses a response, checks what the client must check, and advances the
    /// grant.
    fn absorb(&mut self, http: &HttpResponse, now: u64) -> Result<Step, ClientError> {
        if http.status == 204 {
            // §5.4 — a revocation is answered with 204 and no content.
            return Err(ClientError::Usage(
                "the AS answered 204 No Content; the grant is revoked (RFC 9635 §5.4)".into(),
            ));
        }

        let response: GrantResponse =
            serde_json::from_slice(&http.body).map_err(|e| ClientError::Parse(e.to_string()))?;

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
        if self.grant.state() == State::Pending
            && (response.access_token.is_some() || response.subject.is_some())
        {
            self.grant
                .apply(Event::OutOfBandRoDecision, now)
                .map_err(|e| ClientError::Protocol(e.to_string()))?;
        }

        if self.grant.state() == State::Processing {
            self.grant
                .apply(event, now)
                .map_err(|e| ClientError::Protocol(e.to_string()))?;
        }

        // What the AS sent must be legal in the state it implies.
        let violations = check_response(self.grant.state(), &response);
        if let Some(v) = violations.first() {
            return Err(ClientError::Protocol(v.to_string()));
        }

        if let Some(subject) = &response.subject {
            // §3.4-M14 — everything the AS states has to name one party.
            subject
                .validate()
                .map_err(|e| ClientError::Protocol(e.to_string()))?;
            self.subject = Some(Box::new(subject.clone()));
        }

        // §3.2.1 — `expires_in` is a duration; it starts running when the
        // response arrives, which is here and nowhere else.
        if let Some(tokens) = &response.access_token {
            self.issued = Some(tokens.tokens.iter().map(|t| (now, t.clone())).collect());
        }

        if let Some(c) = &response.r#continue {
            // §3.1-M02 with §3.1-M03: the client must use this URI exactly as
            // given, so it has to be one that can be used as it stands.
            c.validate()
                .map_err(|e| ClientError::Protocol(e.to_string()))?;
            self.grant.offer_continuation(now, c.wait);
            self.continuation = Some(c.clone());
        } else {
            self.grant.withhold_continuation();
            self.continuation = None;
        }

        if let Some(i) = &response.interact {
            self.as_nonce.clone_from(&i.finish);
            self.interaction_window = interaction_window;
            self.interaction_finished = false;
            self.validated_ref = None;
        }

        Ok(match (&response.error, self.grant.state()) {
            (Some(e), _) if response.r#continue.is_none() => Err(ClientError::Server(e.clone()))?,
            (Some(_), _) => Step::Recoverable(Box::new(response)),
            (None, State::Approved) => Step::Approved(Box::new(response)),
            (None, _) => Step::Pending(Box::new(response)),
        })
    }
}
