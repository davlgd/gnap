//! What can go wrong while driving a grant from the client side.

use core::fmt;
use gnap_registry::ErrorCode;
use gnap_types::GnapError;

/// A failure while running the client role.
#[derive(Debug)]
#[non_exhaustive]
pub enum ClientError {
    /// The transport could not move the request.
    Transport(String),
    /// The request could not be signed.
    Signing(gnap_crypto::ProofError),
    /// The response could not be parsed.
    Parse(String),
    /// The AS answered with a GNAP error (§3.6).
    Server(GnapError),
    /// The response breaks a rule the client has to enforce.
    ///
    /// This is the interesting variant: the AS sent something the RFC forbids,
    /// and the client noticed rather than going along with it.
    Protocol(String),

    /// An interaction callback could not be trusted.
    ///
    /// Kept apart from [`ClientError::Protocol`] on purpose: a callback arrives
    /// over the front channel and may come from anyone, so a bad one says
    /// nothing about the AS (§11.29).
    Interaction(String),
    /// The client was asked to do something the protocol does not allow here.
    Usage(String),
}

impl ClientError {
    /// The GNAP error a client's callback endpoint must answer with (§3.6).
    ///
    /// §4.2.2-M05 makes this concrete for a pushed callback: "If either fails,
    /// the client instance MUST return an `unknown_interaction` error." This
    /// library serves no HTTP of its own, so it supplies the error and the
    /// endpoint that received the push sends it.
    ///
    /// `None` for the errors that are not answers to anybody.
    #[must_use]
    pub fn as_callback_error(&self) -> Option<GnapError> {
        match self {
            Self::Interaction(m) => Some(GnapError::with_description(
                ErrorCode::UnknownInteraction,
                m.clone(),
            )),
            _ => None,
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(m) => write!(f, "transport: {m}"),
            Self::Signing(e) => write!(f, "signing: {e}"),
            Self::Parse(m) => write!(f, "parsing the response: {m}"),
            Self::Server(e) => write!(f, "the AS returned an error: {e}"),
            Self::Protocol(m) => write!(f, "protocol violation by the AS: {m}"),
            Self::Interaction(m) => write!(f, "untrusted interaction callback: {m}"),
            Self::Usage(m) => write!(f, "misuse: {m}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<gnap_crypto::ProofError> for ClientError {
    fn from(e: gnap_crypto::ProofError) -> Self {
        Self::Signing(e)
    }
}
