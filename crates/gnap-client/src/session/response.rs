//! Grant responses (§3): parsing, and the checks that precede absorbing one.

use super::interaction::InteractionWindow;
use super::{Session, Step};
use crate::error::ClientError;
use crate::transport::{HttpResponse, HttpTransport};
use gnap_core::{check_response, Event, State};
use gnap_crypto::proof::Signer;
use gnap_types::message::GrantResponse;
use gnap_types::token::{AccessTokenRequest, Cardinality};

impl<T: HttpTransport, S: Signer> Session<T, S> {
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

    /// Parses a response, checks what the client must check, and advances the
    /// grant.
    pub(super) fn absorb(&mut self, http: &HttpResponse, now: u64) -> Result<Step, ClientError> {
        let response = grant_response(http)?;

        self.check_tokens(&response)?;
        self.check_interaction(&response)?;

        let interaction_window = response.interact.as_ref().map(|interaction| {
            let mut window = InteractionWindow::new(now, interaction.expires_in);
            if let Some(seconds) = self.finish_timeout {
                window.limit(seconds);
            }
            window
        });

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
pub(super) fn requested_labels(request: Option<&AccessTokenRequest>) -> Vec<Option<String>> {
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
pub(super) fn grant_response(http: &HttpResponse) -> Result<GrantResponse, ClientError> {
    if http.status == 204 {
        // §5.4 uses 204 for DELETE, not for these POST/PATCH exchanges.
        // It supplies no grant response from which to infer local state.
        return Err(ClientError::Protocol(
            "the AS answered 204 No Content without a usable grant response".into(),
        ));
    }

    // §3: the response "MUST be sent as a JSON object in the content of the
    // HTTP response with Content-Type application/json".
    if !http.has_json_content_type() {
        return Err(ClientError::Protocol(
            "the response doesn't carry exactly one application/json Content-Type".into(),
        ));
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
