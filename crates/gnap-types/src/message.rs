//! The protocol messages — RFC 9635 §2, §3 and §5.

use crate::client::Client;
use crate::error::GnapError;
use crate::interact::{InteractRequest, InteractResponse};
use crate::token::{AccessTokenRequest, AccessTokenResponse, BoundToken};
use crate::user::{SubjectRequest, SubjectResponse, User};
use serde::{de, Deserialize, Deserializer, Serialize};
use std::fmt;

/// The request sent to the AS grant endpoint (§2).
///
/// Sent as a POST with `application/json` content — unless the proofing method
/// says otherwise, as attached JWS (§7.3.4) does by wrapping the object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GrantRequest {
    /// The requesting client. Required on an initial request, never present
    /// on a continuation (§2.3, §5.3).
    pub client: Client,

    /// The tokens requested.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub access_token: Option<AccessTokenRequest>,

    /// The information requested about the RO.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub subject: Option<SubjectRequest>,

    /// What the client knows about the end user.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub user: Option<User>,

    /// What the client can do about interaction.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub interact: Option<InteractRequest>,

    /// Extension fields, kept as they are (Appendix D).
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// The AS response (§3).
///
/// The AS **must** send it with `Cache-Control: no-store` (§3) — a transport
/// constraint, so outside this type.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct GrantResponse {
    /// What is needed to continue the request (§3.1).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub r#continue: Option<Continue>,

    /// The tokens issued. Requires the _approved_ state (§3.2).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub access_token: Option<AccessTokenResponse>,

    /// The interaction modes offered. Requires the _pending_ state (§3.3).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub interact: Option<InteractResponse>,

    /// Information about the RO. Requires the _approved_ state (§3.4).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub subject: Option<SubjectResponse>,

    /// An instance identifier to reuse (§3.5).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub instance_id: Option<String>,

    /// The error, if any (§3.6).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<GnapError>,

    /// Extension fields, kept as they are.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// What is needed to continue the request (§3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Continue {
    /// The continuation URI. Absolute, to be used exactly as given.
    pub uri: String,

    /// The continuation token. Bound to the client's key, never `bearer`.
    pub access_token: BoundToken,

    /// The minimum wait before the next call, in seconds.
    ///
    /// §3.1 recommends at least five seconds; an absent value means five.
    /// See [`Continue::effective_wait`].
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub wait: Option<u64>,

    /// Extension fields, kept as they are.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl Continue {
    /// The default wait when `wait` is absent: five seconds (§3.1, §5).
    pub const DEFAULT_WAIT: u64 = 5;

    /// The wait to honour before the next call.
    ///
    /// Ignoring it earns a `too_fast` response (§5).
    #[must_use]
    pub fn effective_wait(&self) -> u64 {
        self.wait.unwrap_or(Self::DEFAULT_WAIT)
    }

    /// Checks what §3.1 requires of a continuation response.
    ///
    /// §3.1-M02 makes the URI absolute, and §3.1-M03 has the client use it
    /// "exactly as given". Those two go together: a client that may not adjust
    /// the value has to be handed one it can use as it stands.
    ///
    /// # Errors
    ///
    /// Fails when the continuation URI is not an absolute URI.
    pub fn validate(&self) -> Result<(), ContinueError> {
        if crate::uri::is_absolute(&self.uri) {
            Ok(())
        } else {
            Err(ContinueError::UriNotAbsolute(self.uri.clone()))
        }
    }
}

/// What makes a continuation response unusable (§3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContinueError {
    /// The continuation URI is not an absolute URI.
    UriNotAbsolute(String),
}

impl fmt::Display for ContinueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UriNotAbsolute(uri) => write!(
                f,
                "continue.uri: `{uri}` is not an absolute URI, and this one MUST be; the \
                 client instance MUST use it exactly as given, so it has to be usable as \
                 it stands (RFC 9635 §3.1, RFC 3986)"
            ),
        }
    }
}

impl std::error::Error for ContinueError {}

/// A continuation request (§5).
///
/// §5.3-MN09 forbids repeating `client` here: "the client instance is assumed
/// not to have changed", and the AS finds it through the continuation token.
/// The field is therefore absent from this type, and refused on the way in
/// rather than absorbed as an extension.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct ContinueRequest {
    /// The interaction reference, after a callback (§5.1). Single use.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub interact_ref: Option<String>,

    /// The tokens requested, amending the initial request (§5.3).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub access_token: Option<AccessTokenRequest>,

    /// The information requested, amended (§5.3).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub subject: Option<SubjectRequest>,

    /// New interaction capabilities (§5.3).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub interact: Option<InteractRequest>,

    /// New information about the end user (§5.3).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub user: Option<User>,

    /// Extension fields, kept as they are.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl<'de> Deserialize<'de> for ContinueRequest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(default)]
            interact_ref: Option<String>,
            #[serde(default)]
            access_token: Option<AccessTokenRequest>,
            #[serde(default)]
            subject: Option<SubjectRequest>,
            #[serde(default)]
            interact: Option<InteractRequest>,
            #[serde(default)]
            user: Option<User>,
            #[serde(flatten)]
            extra: serde_json::Map<String, serde_json::Value>,
        }

        let raw = Raw::deserialize(deserializer)?;
        if raw.extra.contains_key("client") {
            return Err(de::Error::custom(
                "a continuation request carries `client`; the client instance MUST NOT \
                 include it, since it is assumed not to have changed (RFC 9635 §5.3)",
            ));
        }
        Ok(Self {
            interact_ref: raw.interact_ref,
            access_token: raw.access_token,
            subject: raw.subject,
            interact: raw.interact,
            user: raw.user,
            extra: raw.extra,
        })
    }
}

/// The AS discovery document (§9).
///
/// Fetched with an OPTIONS on the grant endpoint. Advisory only: §9 is a
/// reminder that the AS may deny a request for a capability it advertises.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsDiscovery {
    /// The grant endpoint, which must equal the URL that was queried.
    pub grant_request_endpoint: String,

    /// The interaction start modes supported.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub interaction_start_modes_supported: Option<Vec<gnap_registry::InteractionStartMode>>,

    /// The interaction finish methods supported.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub interaction_finish_methods_supported: Option<Vec<gnap_registry::InteractionFinishMethod>>,

    /// The key proofing methods supported.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub key_proofs_supported: Option<Vec<gnap_registry::KeyProofingMethod>>,

    /// The Subject Identifier formats supported.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sub_id_formats_supported: Option<Vec<String>>,

    /// The assertion formats supported.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub assertion_formats_supported: Option<Vec<gnap_registry::AssertionFormat>>,

    /// Whether the AS supports rotating a token-bound key (§6.1.1).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub key_rotation_supported: Option<bool>,

    /// Extension fields, kept as they are.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}
