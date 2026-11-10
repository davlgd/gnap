//! Interaction (§4): what the client offers, and the callbacks it accepts.

use super::Session;
use crate::error::ClientError;
use crate::transport::HttpTransport;
use gnap_core::State;
use gnap_crypto::hash::{HashMethod, InteractionHashInput, verify_interaction_hash};
use gnap_crypto::proof::Signer;
use gnap_types::interact::InteractCallback;
use gnap_types::message::GrantResponse;
use std::num::NonZeroU64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InteractionWindow {
    received_at: u64,
    expires_at: Option<u128>,
    client_limited: bool,
}

impl InteractionWindow {
    pub(super) fn new(received_at: u64, expires_in: Option<u64>) -> Self {
        // Two u64 inputs fit in u128. A legal, very long lifetime must not
        // discard an otherwise usable response or its continuation token.
        let expires_at = expires_in.map(|seconds| u128::from(received_at) + u128::from(seconds));
        Self {
            received_at,
            expires_at,
            client_limited: false,
        }
    }

    pub(super) fn limit(&mut self, seconds: NonZeroU64) {
        let maximum = u128::from(self.received_at) + u128::from(seconds.get());
        if self.expires_at.is_none_or(|end| maximum < end) {
            self.expires_at = Some(maximum);
            self.client_limited = true;
        }
    }

    fn refusal(&self, now: u64) -> Option<&'static str> {
        if now < self.received_at {
            Some("the callback clock precedes receipt of the interaction response")
        } else if self.expires_at.is_some_and(|end| u128::from(now) >= end) {
            Some(if self.client_limited {
                "the client-configured interaction finish timeout has elapsed"
            } else {
                "the AS-advertised interaction lifetime has elapsed (RFC 9635 §3.3)"
            })
        } else {
            None
        }
    }
}

impl<T: HttpTransport, S: Signer> Session<T, S> {
    /// Validates the interaction context before sending an initial request or PATCH.
    pub(super) fn prepare_interaction(
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
    /// suitable finish timeouts (SHOULD); [`Session::with_finish_timeout`]
    /// supplies an optional client maximum, including when the AS omits one.
    ///
    /// # Errors
    ///
    /// Fails when no finish was negotiated, either finish deadline has passed,
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
        if let Some(reason) = self
            .protocol
            .interaction_window
            .as_ref()
            .and_then(|window| window.refusal(now))
        {
            return Err(ClientError::Interaction(reason.into()));
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

    /// Catches an AS offering an interaction mode that was never on the table.
    ///
    /// GNAP-9635-§3.3-MN09 binds the AS, not the client: "The AS MUST NOT
    /// respond with any interaction mode that the client instance did not
    /// indicate in its request." A client cannot stop it, but it can refuse to
    /// act on a mode it never offered — which is how a non-conformant AS gets
    /// noticed instead of followed.
    pub(super) fn check_interaction(&self, response: &GrantResponse) -> Result<(), ClientError> {
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
}
