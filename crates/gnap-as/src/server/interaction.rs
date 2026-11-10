//! Interaction completion (§4): user codes, finish callbacks, and redirect URIs.

use super::{AuthorizationServer, Finish, InteractionError};
use crate::encoding::TokenEncoder;
use crate::nonce::Nonces;
use crate::policy::{KeyResolver, Policy};
use crate::storage::{GrantRecord, GrantSelector, Storage};
use gnap_core::State;
use gnap_crypto::hash::{InteractionHashInput, interaction_hash_named};
use gnap_registry::InteractionFinishMethod;
use gnap_types::interact::InteractCallback;

impl<P: Policy, K: KeyResolver, S: Storage, N: Nonces, E: TokenEncoder>
    AuthorizationServer<P, K, S, N, E>
{
    /// Resolves a human-entered code to the pending request's opaque handle.
    ///
    /// This neither authenticates the resource owner nor approves or consumes
    /// anything. The interaction component must enforce admission limits and
    /// obtain consent before calling [`Self::complete_interaction`]. Keep the
    /// returned handle inside that trusted component, not in the entry URI.
    /// Invalid or expired codes must display an error, never a client redirect.
    /// Show the same generic message for unknown and expired codes and count
    /// both against admission limits; the SDK's distinction is diagnostic only.
    /// # Errors
    /// Refuses disabled, malformed, unknown, expired or completed interactions;
    /// reports storage failure separately without reflecting the supplied code.
    pub fn resolve_user_code(&self, input: &str, now: u64) -> Result<String, InteractionError> {
        let configuration = self
            .user_codes
            .as_ref()
            .ok_or(InteractionError::UnknownInteraction)?;
        let code = crate::normalize_user_code(input).ok_or(InteractionError::UnknownInteraction)?;
        let snapshot = (configuration.lookup)(&self.storage, &code)
            .map_err(InteractionError::Storage)?
            .ok_or(InteractionError::UnknownInteraction)?;
        let record = &snapshot.aggregate.record;
        if record.grant.state() != State::Pending || record.interaction_completed {
            return Err(InteractionError::UnknownInteraction);
        }
        if record.interact_expires_at.is_none_or(|end| now >= end) {
            return Err(InteractionError::Expired);
        }
        record
            .interact_handle
            .clone()
            .ok_or(InteractionError::UnknownInteraction)
    }

    /// Signals that the RO is done interacting (§4.2).
    ///
    /// `handle` is the value the AS put in the interaction URI it handed the
    /// client; it names the grant the RO was working on. The AS creates the
    /// interaction reference here, binds it to that grant, computes the hash of
    /// §4.2.3, and returns what has to happen next.
    ///
    /// §4.2 associates the reference with "the current interaction and the
    /// underlying pending request". Spending the interaction handle and
    /// publishing that reference use one compare-and-exchange; only its winner
    /// receives a finish directive to carry out.
    ///
    /// Carrying the directive out is left to the caller, which is what keeps
    /// this crate free of an HTTP client. [`Finish::Push`] in particular is an
    /// outbound call to a URI the client supplied, so whoever performs it MUST
    /// apply the SSRF protection of §11.34 (§4.2.2).
    ///
    /// # Errors
    ///
    /// Returns the cases in which §4.2 says the AS MUST NOT follow the finish
    /// method: an unknown interaction, or a grant that is no longer pending.
    /// [`InteractionError::Storage`] also reports unavailable storage or a
    /// compare-and-exchange conflict. The caller must not carry out the finish
    /// method unless the state change committed and this call returned `Ok`.
    pub fn complete_interaction(&self, handle: &str, now: u64) -> Result<Finish, InteractionError> {
        let snapshot = self
            .storage
            .lookup(GrantSelector::Interaction(handle))
            .map_err(InteractionError::Storage)?
            .ok_or(InteractionError::UnknownInteraction)?;
        let mut aggregate = snapshot.aggregate.clone();
        let outcome = self.finish_interaction(&mut aggregate.record, now)?;
        self.storage
            .compare_exchange(snapshot.id, snapshot.revision, aggregate)
            .map_err(InteractionError::Storage)?;
        Ok(outcome)
    }

    /// Decides what a completed interaction owes the client, mutating `record`.
    ///
    /// The caller keeps the mutation only on `Ok`, so every refusal below
    /// leaves the grant untouched: an interaction the AS will not finish must
    /// not be marked as having happened.
    fn finish_interaction(
        &self,
        record: &mut GrantRecord,
        now: u64,
    ) -> Result<Finish, InteractionError> {
        // §4.2 — the AS MUST NOT follow the finish method when "The ongoing
        // grant request has been canceled or otherwise blocked".
        if record.interaction_completed {
            return Err(InteractionError::UnknownInteraction);
        }
        if record.grant.state() != State::Pending {
            return Err(InteractionError::NotPending(record.grant.state()));
        }

        // §4.1-M02 — past the timeout the AS "MUST reject attempts to use the
        // interaction start modes". An interaction URI outlives the tab it was
        // opened in; this is what stops one found later from still working.
        if record.interact_expires_at.is_some_and(|at| now >= at) {
            return Err(InteractionError::Expired);
        }

        let finish = record
            .request
            .interact
            .as_ref()
            .and_then(|i| i.finish.clone());

        // Everything that can refuse runs before anything is written.
        let directive = match &finish {
            None => None,
            Some(finish) => {
                let uri = finish
                    .uri
                    .as_deref()
                    .ok_or(InteractionError::Misconfigured(
                        "the finish method carries no URI to call back (RFC 9635 §2.5.2)",
                    ))?;
                // §2.5.2 — the URI is absolute and carries no fragment. A
                // fragment would swallow the query the callback travels in.
                if uri.contains('#') {
                    return Err(InteractionError::Misconfigured(
                        "the finish URI carries a fragment, so the callback parameters \
                         could not be read from its query (RFC 9635 §2.5.2)",
                    ));
                }
                match finish.method {
                    InteractionFinishMethod::Redirect | InteractionFinishMethod::Push => {}
                    InteractionFinishMethod::Unregistered(ref name) => {
                        return Err(InteractionError::UnsupportedFinish(name.clone()));
                    }
                }
                Some((finish, uri.to_owned()))
            }
        };

        // RFC 9635 §4.2 — "The interaction reference value MUST be
        // sufficiently random so as not to be guessable by an attacker", and
        // is an ASCII string of unreserved characters (RFC 3986 §2.3). Randomness is the nonce
        // source's contract; the character set is checked here because a
        // reference that has to survive a query parameter cannot hold anything
        // else.
        let interact_ref = self
            .nonces
            .next()
            .map_err(|_| InteractionError::Misconfigured("the nonce source is unavailable"))?;
        if interact_ref.is_empty() || !interact_ref.bytes().all(is_unreserved) {
            return Err(InteractionError::Misconfigured(
                "the interaction reference must be a non-empty ASCII string of unreserved \
                 characters (RFC 9635 §4.2)",
            ));
        }

        let Some((finish, uri)) = directive else {
            // §4.2 — with no finish method the AS should send the RO back to
            // the client instance, which is polling the continuation endpoint.
            record.interaction_completed = true;
            record.interact_handle = None;
            record.user_code = None;
            return Ok(Finish::SendTheUserBack);
        };

        let as_nonce = record
            .as_nonce
            .as_deref()
            .ok_or(InteractionError::Misconfigured(
                "the grant carries no AS nonce, so the interaction hash cannot be computed \
                 (RFC 9635 §3.3.5)",
            ))?;
        let hash = interaction_hash_named(
            &InteractionHashInput {
                client_nonce: &finish.nonce,
                as_nonce,
                interact_ref: &interact_ref,
                grant_endpoint: &self.endpoints.grant,
            },
            finish.hash_method.as_deref(),
        )
        .map_err(|e| InteractionError::Hash(e.to_string()))?;

        let callback = InteractCallback {
            hash,
            interact_ref: interact_ref.clone(),
        };
        let directive = match finish.method {
            // §4.2.1 — the AS secures the redirect by adding the hash and the
            // reference as query parameters to the client's redirect URI.
            InteractionFinishMethod::Redirect => Finish::Redirect {
                uri: with_callback_query(&uri, &callback),
            },
            _ => Finish::Push {
                uri,
                body: serde_json::to_vec(&callback)
                    .map_err(|e| InteractionError::Serialization(e.to_string()))?,
            },
        };

        // Nothing can fail past here, so the writes land together.
        record.interaction_completed = true;
        record.interact_ref = Some(interact_ref);
        // §4.2 — the interaction is spent; a second completion finds nothing.
        record.interact_handle = None;
        record.user_code = None;
        Ok(directive)
    }
}

/// Whether a byte is `unreserved` as RFC 3986 §2.3 defines it.
const fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

/// Adds the callback parameters to a redirect URI (§4.2.1).
///
/// The client's URI may already carry a query of its own, which §2.5.2.1 does
/// not forbid, so the parameters are appended rather than assumed to be first.
fn with_callback_query(uri: &str, callback: &InteractCallback) -> String {
    let separator = if uri.contains('?') { '&' } else { '?' };
    format!(
        "{uri}{separator}hash={}&interact_ref={}",
        callback.hash, callback.interact_ref
    )
}
