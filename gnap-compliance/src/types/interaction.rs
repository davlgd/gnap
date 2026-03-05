/// Interaction types — RFC 9635 Sections 2.5, 3.3, 4
use serde::{Deserialize, Serialize};

/// Interaction request from client to AS.
/// RFC 9635 Section 2.5
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractRequest {
    /// Start modes the client can use (e.g., "redirect", "app", "user_code", "user_code_uri").
    pub start: Vec<StartMode>,

    /// How the client wants to be notified when interaction is complete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish: Option<InteractFinish>,

    /// Hints about the interaction (e.g., preferred UI locale).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hints: Option<InteractHints>,
}

/// Start mode for interaction.
/// RFC 9635 Section 2.5.1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StartMode {
    /// Simple string mode: "redirect", "app", "user_code", "user_code_uri"
    Name(String),
    /// Extended mode with additional parameters.
    /// RFC 9635 Section 2.5.1: the `mode` field is REQUIRED.
    Extended(ExtendedStartMode),
}

/// Extended start mode object.
/// RFC 9635 Section 2.5.1: MUST contain `mode` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedStartMode {
    /// The interaction start mode. REQUIRED.
    pub mode: String,
    /// Additional parameters for this start mode.
    #[serde(flatten)]
    pub additional: serde_json::Map<String, serde_json::Value>,
}

/// Finish method for interaction callback.
/// RFC 9635 Section 2.5.2
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractFinish {
    /// Callback method: "redirect" or "push".
    pub method: String,

    /// URI the AS will use to contact the client after interaction.
    pub uri: String,

    /// Unique nonce value for interaction hash verification.
    pub nonce: String,

    /// Hash algorithm for the finish hash (default: "sha-256").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_method: Option<String>,
}

/// Hints for interaction preferences.
/// RFC 9635 Section 2.5.3
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractHints {
    /// Preferred UI locales (BCP 47 language tags).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ui_locales: Option<Vec<String>>,
}

/// Interaction response from AS to client.
/// RFC 9635 Section 3.3
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractResponse {
    /// URI for redirect-based interaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<String>,

    /// URI for app-based interaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,

    /// User code for secondary-device interaction (plain string).
    /// RFC 9635 Section 3.3.3
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_code: Option<String>,

    /// User code with URI for direct entry.
    /// RFC 9635 Section 3.3.4
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_code_uri: Option<UserCodeUri>,

    /// Nonce for interaction hash computation (finish).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish: Option<String>,

    /// Expiration time for the interaction in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
}

/// User code with URI for direct entry.
/// RFC 9635 Section 3.3.4
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserCodeUri {
    /// The user-facing code value.
    pub code: String,

    /// URI where the user should enter the code (with code pre-filled).
    pub uri: String,
}
