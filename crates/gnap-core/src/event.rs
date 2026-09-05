//! What can happen to a grant request — the triggers of §1.5, §4 and §5.

use core::fmt;

/// A trigger applied to a grant request.
///
/// The names match the `trigger` field of the state machine specification, so
/// the two cannot drift apart unnoticed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The AS decided that interaction with an RO is required (§4).
    AsRequiresInteraction,

    /// The AS decided the request can be granted without interaction (§4).
    AsNeedsNoInteraction,

    /// The AS cannot proceed: a timeout, or an unrecoverable error (§1.5).
    AsCannotProceed,

    /// The client polls the continuation endpoint with no content (§5.2).
    ContinuePoll,

    /// The client continues after interaction, presenting a reference (§5.1).
    ContinueWithInteractRef(String),

    /// The RO acted outside the protocol, and the AS learned of it (§1.5).
    OutOfBandRoDecision,

    /// The client modifies its request (§5.3).
    Modify,

    /// The client revokes the request (§5.4).
    Revoke,

    /// An interaction start mode was completed by the end user (§4.1).
    InteractionStartCompleted(String),
}

impl Event {
    /// The trigger name used in the state machine specification.
    #[must_use]
    pub const fn trigger(&self) -> &'static str {
        match self {
            Self::AsRequiresInteraction => "as_requires_interaction",
            Self::AsNeedsNoInteraction => "as_needs_no_interaction",
            Self::AsCannotProceed => "as_cannot_proceed",
            Self::ContinuePoll => "continue_poll",
            Self::ContinueWithInteractRef(_) => "continue_with_interact_ref",
            Self::OutOfBandRoDecision => "out_of_band_ro_decision",
            Self::Modify => "modify",
            Self::Revoke => "revoke",
            Self::InteractionStartCompleted(_) => "interaction_start",
        }
    }

    /// Whether this event is a call to the continuation API (§5).
    ///
    /// The guards on `wait`, on a missing continuation offer, and on a
    /// finalized grant apply to every one of them.
    #[must_use]
    pub const fn is_continuation(&self) -> bool {
        matches!(
            self,
            Self::ContinuePoll | Self::ContinueWithInteractRef(_) | Self::Modify | Self::Revoke
        )
    }
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.trigger())
    }
}
