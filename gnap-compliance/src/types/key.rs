/// Key and proofing types — RFC 9635 Section 7.1
use serde::{Deserialize, Serialize};

/// A key used by a client instance or bound to an access token.
/// RFC 9635 Section 7.1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Key {
    /// The proof method used with this key.
    pub proof: ProofMethod,

    /// JSON Web Key (RFC 7517).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<serde_json::Value>,

    /// PEM-encoded X.509 certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,

    /// SHA-256 thumbprint of the certificate.
    #[serde(rename = "cert#S256", skip_serializing_if = "Option::is_none")]
    pub cert_s256: Option<String>,
}

/// Proof method for demonstrating possession of a key.
/// RFC 9635 Section 7.3
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProofMethod {
    /// Simple string form: "httpsig", "mtls", "jwsd", "jws"
    Name(String),
    /// Object form with method name.
    Object { method: String },
}

impl ProofMethod {
    pub fn method_name(&self) -> &str {
        match self {
            Self::Name(name) => name,
            Self::Object { method } => method,
        }
    }
}

/// A key reference or inline key.
/// Used in client instance and access token key fields.
/// RFC 9635 Section 7.1
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeyRef {
    /// Inline key definition.
    Inline(Key),
    /// Reference by key ID string.
    Reference(String),
}
