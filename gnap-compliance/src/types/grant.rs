/// Grant request and response types — RFC 9635 Sections 2, 3
use serde::{Deserialize, Serialize};

use super::{
    AccessTokenRequestField, AccessTokenResponseField, ClientInstance, ContinueResponse,
    GnapErrorField, InteractRequest, InteractResponse, SubjectAssertion, SubjectRequest,
    SubjectResponse,
};

/// A GNAP grant request sent from the client to the AS.
/// RFC 9635 Section 2
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRequest {
    /// Access token(s) requested. REQUIRED if requesting an access token.
    /// RFC 9635 Section 2: optional for subject-only requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<AccessTokenRequestField>,

    /// Client instance identification.
    pub client: ClientInstance,

    /// Interaction modes requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interact: Option<InteractRequest>,

    /// Subject information requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<SubjectRequest>,

    /// End-user information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserRef>,
}

/// User reference in a grant request.
/// RFC 9635 Section 2.4
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UserRef {
    /// Reference to a user by identifier.
    Reference(String),
    /// Inline user information.
    Inline(UserInfo),
}

/// Inline user information.
/// RFC 9635 Section 2.4
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfo {
    /// User sub-identifiers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_ids: Option<Vec<serde_json::Value>>,

    /// Assertions about the user.
    /// RFC 9635 Section 2.4: each assertion has format and value fields (Section 3.4.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertions: Option<Vec<SubjectAssertion>>,
}

/// A GNAP grant response from the AS.
/// RFC 9635 Section 3
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantResponse {
    /// Continuation information for further requests.
    #[serde(rename = "continue", skip_serializing_if = "Option::is_none")]
    pub continue_: Option<ContinueResponse>,

    /// Access token(s) issued.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<AccessTokenResponseField>,

    /// Interaction information for the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interact: Option<InteractResponse>,

    /// Subject information about the resource owner.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<SubjectResponse>,

    /// Instance identifier assigned by the AS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,

    /// Error information from the AS.
    /// RFC 9635 Section 3.6
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<GnapErrorField>,
}
