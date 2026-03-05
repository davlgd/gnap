/// Client instance types — RFC 9635 Section 2.3
use serde::{Deserialize, Serialize};

use super::KeyRef;

/// Client instance identification.
/// Can be a reference string or an inline object.
/// RFC 9635 Section 2.3
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClientInstance {
    /// Reference to a pre-registered client by instance ID.
    Reference(String),
    /// Inline client instance with key and optional display info.
    Inline(ClientInstanceInfo),
}

/// Inline client instance information.
/// RFC 9635 Section 2.3.1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientInstanceInfo {
    /// The key used by this client instance.
    pub key: KeyRef,

    /// Pre-registered class identifier for this client software.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_id: Option<String>,

    /// Display information about the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<ClientDisplay>,
}

/// Display information for a client instance.
/// RFC 9635 Section 2.3.2
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientDisplay {
    /// Human-readable name of the client. RECOMMENDED per RFC 9635 Section 2.3.2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// URI of the client's logo.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,

    /// URI of the client's logo image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
}
