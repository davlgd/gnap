/// GNAP error types — RFC 9635 Section 3.6
use serde::{Deserialize, Serialize};

/// Error field in a grant response. Can be an object or a string.
/// RFC 9635 Section 3.6:
///   "This field is either an object or a string."
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GnapErrorField {
    /// Object form: { "code": "...", "description": "..." }
    Object(GnapError),
    /// String form: just the error code.
    Code(String),
}

/// Error response object from the AS.
/// RFC 9635 Section 3.6
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GnapError {
    /// Error code as defined in the GNAP error registry.
    pub code: GnapErrorCode,

    /// Human-readable description of the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// GNAP error codes — RFC 9635 Section 3.6
///
/// All codes from the IANA "GNAP Error Codes" registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GnapErrorCode {
    /// The request is missing a required parameter or is malformed.
    #[serde(rename = "invalid_request")]
    InvalidRequest,

    /// The client is not recognized or allowed, or signature validation failed.
    #[serde(rename = "invalid_client")]
    InvalidClient,

    /// The interaction reference is incorrect or interaction modes have expired.
    #[serde(rename = "invalid_interaction")]
    InvalidInteraction,

    /// The flag configuration is not valid.
    #[serde(rename = "invalid_flag")]
    InvalidFlag,

    /// The token rotation request is not valid.
    #[serde(rename = "invalid_rotation")]
    InvalidRotation,

    /// The AS does not allow rotation of this access token's key.
    #[serde(rename = "key_rotation_not_supported")]
    KeyRotationNotSupported,

    /// The continuation of the referenced grant could not be processed.
    #[serde(rename = "invalid_continuation")]
    InvalidContinuation,

    /// The RO denied the request.
    #[serde(rename = "user_denied")]
    UserDenied,

    /// The request was denied for an unspecified reason.
    #[serde(rename = "request_denied")]
    RequestDenied,

    /// The user presented in the request is not known to the AS.
    #[serde(rename = "unknown_user")]
    UnknownUser,

    /// The interaction integrity could not be established.
    #[serde(rename = "unknown_interaction")]
    UnknownInteraction,

    /// The client instance did not respect the timeout in the wait response.
    #[serde(rename = "too_fast")]
    TooFast,

    /// A limit has been reached in the total number of reasonable attempts.
    #[serde(rename = "too_many_attempts")]
    TooManyAttempts,

    /// Unrecognized error code for forward compatibility.
    #[serde(untagged)]
    Unknown(String),
}

/// Library-level error type for compliance operations.
#[derive(Debug, thiserror::Error)]
pub enum ComplianceError {
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Crypto error: {0}")]
    Crypto(String),
}
