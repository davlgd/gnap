/// Access token types — RFC 9635 Sections 2.1, 3.2, 5, 6
use serde::{Deserialize, Serialize};

use super::{AccessRight, KeyRef};

/// Access token request within a grant request.
/// RFC 9635 Section 2.1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessTokenRequest {
    /// Requested access rights for this token.
    pub access: Vec<AccessRight>,

    /// Label for this token request (required when requesting multiple tokens).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// Flags for this token (e.g., "bearer").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<Vec<String>>,
}

/// Single or multiple access token requests.
/// RFC 9635 Section 2.1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AccessTokenRequestField {
    /// Single token request.
    Single(AccessTokenRequest),
    /// Multiple token requests (each must have a label).
    Multiple(Vec<AccessTokenRequest>),
}

/// Access token returned in a grant response.
/// RFC 9635 Section 3.2
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessToken {
    /// The token value.
    pub value: String,

    /// Label matching the request label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// Token management information (rotation, revocation).
    /// RFC 9635 Section 3.2.1: object with `uri` and `access_token`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manage: Option<TokenManagement>,

    /// Access rights granted to this token. REQUIRED per RFC 9635 Section 3.2.1.
    pub access: Vec<AccessRight>,

    /// Seconds until token expiration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,

    /// Key bound to this token (true = use the client's key).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<AccessTokenKey>,

    /// Flags (e.g., "bearer" indicates no key binding).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<Vec<String>>,
}

/// Token management information.
/// RFC 9635 Section 3.2.1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenManagement {
    /// The URI of the token management API for this access token.
    pub uri: String,

    /// Access token for calling the management API.
    pub access_token: ContinueAccessToken,
}

/// Key binding for an access token in a response.
/// RFC 9635 Section 3.2.1: key is object or string (Section 7.1 format).
/// If omitted, the token is bound to the client instance's presented key.
/// Boolean `true` is NOT valid in responses (only used in request context).
pub type AccessTokenKey = KeyRef;

/// Single or multiple access tokens in a response.
/// RFC 9635 Section 3.2
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AccessTokenResponseField {
    /// Single token.
    Single(Box<AccessToken>),
    /// Multiple tokens (each has a label).
    Multiple(Vec<AccessToken>),
}

/// Continuation information in a grant response.
/// RFC 9635 Section 3.1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinueResponse {
    /// Access token for continuation requests.
    pub access_token: ContinueAccessToken,

    /// URI for continuation requests.
    pub uri: String,

    /// Seconds the client should wait before polling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait: Option<u64>,
}

/// Access token specifically for continuation requests.
/// RFC 9635 Section 3.1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinueAccessToken {
    /// The continuation token value.
    pub value: String,
}

/// Continuation request body.
/// RFC 9635 Section 5.1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinueRequest {
    /// Interaction reference from the callback.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interact_ref: Option<String>,
}

/// Token management: rotation response.
/// RFC 9635 Section 6.1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRotationResponse {
    /// The new access token.
    pub access_token: AccessToken,
}
