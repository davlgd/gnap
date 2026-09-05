//! Identifying the client instance — RFC 9635 §2.3.

use crate::key::Key;
use crate::object_or_reference;
use serde::{Deserialize, Serialize};

/// What the client says about itself (§2.3).
///
/// `display` and `class_id` are self-declared: §2.3 reminds the AS to treat
/// them as hints, never as proof of identity. Only the key authenticates the
/// instance (§2.3.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClientObject {
    /// The key the client will use to protect this request. Required.
    pub key: Key,

    /// An identifier for the client software, in a format the AS chooses.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub class_id: Option<String>,

    /// What the AS may show the RO during interaction.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub display: Option<ClientDisplay>,

    /// Extension fields, kept as they are (Appendix D).
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// What the AS may display to the RO about the client (§2.3.2).
///
/// These values come from the client itself: §2.3.2 forbids taking them as
/// proof of identity, and §11.16 warns about a client-hosted `logo_uri`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ClientDisplay {
    /// The display name of the software.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,

    /// An informational page. Absolute URI.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub uri: Option<String>,

    /// An image representing the software. Absolute URI, `data:` accepted.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub logo_uri: Option<String>,

    /// Extension fields, kept as they are.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl ClientDisplay {
    /// Checks the two URIs §2.3.2 requires to be absolute (M03, M05).
    ///
    /// Both are shown to the RO during interaction, on a page served by the AS.
    /// A relative one would resolve against the AS's own origin, quietly
    /// turning the client's claim into something the AS appears to say.
    ///
    /// # Errors
    ///
    /// Fails on the first URI that is not an absolute URI, naming the field.
    pub fn validate(&self) -> Result<(), DisplayError> {
        for (field, value) in [("uri", &self.uri), ("logo_uri", &self.logo_uri)] {
            if let Some(value) = value {
                if !crate::uri::is_absolute(value) {
                    return Err(DisplayError::NotAbsolute {
                        field,
                        uri: value.clone(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// What makes displayable client information unusable (§2.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisplayError {
    /// A URI meant to be absolute is not.
    NotAbsolute {
        /// Which of the two fields it is.
        field: &'static str,
        /// The value as it was received.
        uri: String,
    },
}

impl std::fmt::Display for DisplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAbsolute { field, uri } => write!(
                f,
                "client.display.{field}: `{uri}` is not an absolute URI, and this one MUST \
                 be (RFC 9635 §2.3.2, RFC 3986)"
            ),
        }
    }
}

impl std::error::Error for DisplayError {}

object_or_reference!(
    /// The client, sent in full or by its instance identifier (§2.3.1).
    ///
    /// This field is neither sent nor accepted on continuation requests: §2.3
    /// states that the AS finds the client through the continuation token.
    Client,
    ClientObject,
    "client"
);
