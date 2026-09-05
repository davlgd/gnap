//! Checking a response against the state it claims to come from.
//!
//! §3.2, §3.3 and §3.4 each tie a response field to a state. A client that does
//! not check them will happily accept a token from a grant that was never
//! approved, which is exactly what a compromised or broken AS would send.

use crate::grant::Allowed;
use crate::state::State;
use core::fmt;
use gnap_types::message::GrantResponse;

/// A response field that cannot be present in the state it arrived in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// The offending field.
    pub field: &'static str,
    /// The state the grant was in.
    pub state: State,
    /// What the RFC says, and where.
    pub reason: &'static str,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "`{}` in the {} state: {}",
            self.field, self.state, self.reason
        )
    }
}

impl std::error::Error for Violation {}

/// Checks a response against the state the grant is in.
///
/// Returns every violation rather than the first, so a diagnostic can list them
/// all at once.
///
/// ```
/// use gnap_core::{check_response, State};
/// use gnap_types::message::GrantResponse;
///
/// // An AS that hands out a token while the grant is still pending.
/// let response: GrantResponse = serde_json::from_str(
///     r#"{"access_token":{"value":"AAA"},
///         "continue":{"uri":"https://as/c","access_token":{"value":"BBB"}}}"#,
/// ).unwrap();
///
/// let violations = check_response(State::Pending, &response);
/// assert_eq!(violations.len(), 1);
/// assert_eq!(violations[0].field, "access_token");
///
/// // Drop the continuation and a second rule is broken: §3.1 requires it
/// // while pending.
/// let stranded: GrantResponse =
///     serde_json::from_str(r#"{"access_token":{"value":"AAA"}}"#).unwrap();
/// assert_eq!(check_response(State::Pending, &stranded).len(), 2);
/// ```
#[must_use]
pub fn check_response(state: State, response: &GrantResponse) -> Vec<Violation> {
    let allowed = Allowed::for_state(state);
    let mut found = Vec::new();

    // §3.6 — an error response carries the error and, when the grant is still
    // pending so the client can recover, a continuation. "Other fields MUST NOT
    // be included in the response." An error arriving with a token or with
    // subject information is not a response this client will act on.
    if response.error.is_some() {
        for (field, present) in [
            ("access_token", response.access_token.is_some()),
            ("subject", response.subject.is_some()),
            ("interact", response.interact.is_some()),
            ("instance_id", response.instance_id.is_some()),
            // §3.6 says "other fields", not "other known fields": an extension
            // field alongside an error is exactly as forbidden.
            ("extension fields", !response.extra.is_empty()),
        ] {
            if present {
                found.push(Violation {
                    field,
                    state,
                    reason: "the response carries an error; apart from `continue` while the \
                             grant is pending, other fields MUST NOT be included \
                             (RFC 9635 §3.6)",
                });
            }
        }
        if response.r#continue.is_some() && state != State::Pending {
            found.push(Violation {
                field: "continue",
                state,
                reason: "the response carries an error together with a continuation, which \
                         §3.6 allows only while the grant is pending (RFC 9635 §3.6)",
            });
        }
        // The state-based rules below describe a successful response; an error
        // response has already been judged against §3.6.
        return found;
    }

    if response.access_token.is_some() && !allowed.access_token {
        found.push(Violation {
            field: "access_token",
            state,
            reason: "the grant request MUST be in the approved state to include this \
                     field (RFC 9635 §3.2)",
        });
    }

    if response.subject.is_some() && !allowed.subject {
        found.push(Violation {
            field: "subject",
            state,
            reason: "the grant request MUST be in the approved state to return this \
                     field (RFC 9635 §3.4)",
        });
    }

    if response.interact.is_some() && !allowed.interact {
        found.push(Violation {
            field: "interact",
            state,
            reason: "the grant request MUST be in the pending state to include this \
                     field (RFC 9635 §3.3)",
        });
    }

    if response.r#continue.is_none() && Allowed::continuation_required(state) {
        found.push(Violation {
            field: "continue",
            state,
            reason: "this field is REQUIRED while the grant request is pending \
                     (RFC 9635 §3.1)",
        });
    }

    // §5.4 — a finalized grant "is dead and cannot be revived", so offering a
    // way to continue it is a contradiction the client should not follow.
    if response.r#continue.is_some() && !allowed.continuation {
        found.push(Violation {
            field: "continue",
            state,
            reason: if state == State::Finalized {
                "the response offers a continuation for a finalized grant; once finalized \
                 it MUST NOT be moved to any other state (RFC 9635 §5.4)"
            } else {
                "the response offers a continuation the grant cannot use in this state \
                 (RFC 9635 §3.1)"
            },
        });
    }

    found
}
