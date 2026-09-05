//! The four states a grant request moves through — RFC 9635 §1.5.

use core::fmt;

/// The state of a grant request, as the AS sees it.
///
/// The AS owns this state; §1.5 notes that the client keeps its own view of the
/// request, and that the means of managing either are out of the protocol's
/// scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    /// The AS is deciding what the request needs.
    ///
    /// Entered on creation, on modification, and when interaction completes. A
    /// request must leave this state before any response is returned.
    Processing,

    /// Approval from an RO, or interaction with the end user, is required.
    ///
    /// No access token and no subject information may be released while here.
    Pending,

    /// The request is approved and needs no further interaction.
    Approved,

    /// The request is dead and cannot be revived (§5.4).
    Finalized,
}

impl State {
    /// Whether the state is terminal.
    ///
    /// Only `Finalized` is: "Once the grant request is in the _finalized_
    /// state, it MUST NOT be moved to any other state" (§5.4).
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Finalized)
    }

    /// The name used in the state machine specification and in diagnostics.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Processing => "processing",
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Finalized => "finalized",
        }
    }

    /// Resolves a name from the specification.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "processing" => Self::Processing,
            "pending" => Self::Pending,
            "approved" => Self::Approved,
            "finalized" => Self::Finalized,
            _ => return None,
        })
    }

    /// Every state, in the order of §1.5.
    pub const ALL: [Self; 4] = [
        Self::Processing,
        Self::Pending,
        Self::Approved,
        Self::Finalized,
    ];
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
