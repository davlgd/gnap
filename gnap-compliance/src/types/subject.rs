/// Subject information types — RFC 9635 Sections 2.2 and 3.4
use serde::{Deserialize, Serialize};

/// Subject information request.
/// RFC 9635 Section 2.2
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectRequest {
    /// Subject identifiers identifying the subject being requested.
    /// RFC 9635 Section 2.2: array of Subject Identifiers per RFC 9493.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_ids: Option<Vec<serde_json::Value>>,

    /// Requested subject identifier formats.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_id_formats: Option<Vec<String>>,

    /// Requested assertion formats (e.g., "id_token", "saml2").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion_formats: Option<Vec<String>>,
}

/// Subject information response.
/// RFC 9635 Section 3.4
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectResponse {
    /// Subject identifiers returned by the AS.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_ids: Option<Vec<SubjectIdentifier>>,

    /// Assertions about the subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertions: Option<Vec<SubjectAssertion>>,

    /// Timestamp of when the subject information was last updated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// A subject identifier.
/// RFC 9635 Section 3.4.1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectIdentifier {
    /// The format of the identifier (e.g., "opaque", "email", "iss_sub").
    pub format: String,

    /// Additional fields depending on the format.
    #[serde(flatten)]
    pub fields: serde_json::Map<String, serde_json::Value>,
}

/// A subject assertion.
/// RFC 9635 Section 3.4.2
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectAssertion {
    /// The format of the assertion (e.g., "id_token", "saml2").
    pub format: String,

    /// The assertion value.
    pub value: String,
}
