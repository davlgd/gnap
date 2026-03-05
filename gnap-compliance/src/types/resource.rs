/// Access rights and resource types — RFC 9635 Section 8
use serde::{Deserialize, Serialize};

/// A single access right, either a string reference or a structured object.
/// RFC 9635 Section 8
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AccessRight {
    /// Reference to a pre-defined access right by string.
    Reference(String),
    /// Structured access right with type, actions, locations, datatypes.
    Structured(StructuredAccessRight),
}

/// A structured access right definition.
/// RFC 9635 Section 8.1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredAccessRight {
    /// The type of resource being accessed.
    #[serde(rename = "type")]
    pub resource_type: String,

    /// Actions the client wishes to perform.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,

    /// Locations of the resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locations: Option<Vec<String>>,

    /// Data types being requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datatypes: Option<Vec<String>>,

    /// Identifier for a specific resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,

    /// Privileges associated with this access.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileges: Option<Vec<String>>,
}
