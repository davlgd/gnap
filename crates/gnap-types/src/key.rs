//! Keys and proof of possession — RFC 9635 §7.1 and §7.3.

use crate::object_or_reference;
use crate::polymorphic::MethodOrObject;
use gnap_registry::KeyProofingMethod;
use serde::{Deserialize, Serialize};

/// The proofing method, in named or detailed form (§7.3).
pub type Proof = MethodOrObject<KeyProofingMethod>;

/// A public key and the proofing method bound to it (§7.1).
///
/// A key sent by value **must** be a public key and must be presented in only
/// one format (§7.1, §11.35). [`KeyObject::validate`] checks that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyObject {
    /// The proofing method used. Required.
    pub proof: Proof,

    /// The key as a JSON Web Key. Must carry `alg` and `kid`, and `alg` must
    /// not be `none`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub jwk: Option<serde_json::Map<String, serde_json::Value>>,

    /// The certificate serialized as PEM.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cert: Option<String>,

    /// The certificate thumbprint, computed as in RFC 8705.
    #[serde(rename = "cert#S256", skip_serializing_if = "Option::is_none", default)]
    pub cert_s256: Option<String>,
}

/// What prevents a key from being valid as the RFC defines it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// No key format was supplied.
    NoFormat,
    /// Several formats were supplied at once (§7.1, §11.35).
    MultipleFormats(Vec<&'static str>),
    /// The JWK lacks the named parameter, which §7.1 requires.
    JwkMissing(&'static str),
    /// The JWK carries the parameter, but not as a string.
    JwkNotAString(&'static str),
    /// The JWK declares `alg: "none"`, which §7.1 forbids.
    JwkAlgNone,
    /// The key sent by value is symmetric, which §2.3 forbids.
    SymmetricByValue,
}

impl core::fmt::Display for KeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoFormat => write!(
                f,
                "key: no format supplied; expected `jwk`, `cert` or `cert#S256` \
                 (RFC 9635 §7.1)"
            ),
            Self::MultipleFormats(v) => write!(
                f,
                "key: {} formats supplied ({}); a key MUST be presented in only \
                 one format (RFC 9635 §7.1, §11.35)",
                v.len(),
                v.join(", ")
            ),
            Self::JwkMissing(p) => write!(
                f,
                "key.jwk: the `{p}` parameter is required (RFC 9635 §7.1)"
            ),
            Self::JwkNotAString(p) => write!(
                f,
                "key.jwk: the `{p}` parameter is not a string, so there is nothing to \
                 compare a signature against (RFC 7517 §4, RFC 9635 §7.1)"
            ),
            Self::JwkAlgNone => write!(f, "key.jwk: `alg` MUST NOT be \"none\" (RFC 9635 §7.1)"),
            Self::SymmetricByValue => write!(
                f,
                "key.jwk: `kty` is `oct`, so this is a symmetric key. The client instance \
                 MUST NOT send a symmetric key by value, since that hands over the key \
                 itself instead of proving possession of it (RFC 9635 §2.3, §11.5)"
            ),
        }
    }
}

impl std::error::Error for KeyError {}

impl KeyObject {
    /// Checks the §7.1 constraints on how the key is presented.
    ///
    /// ```
    /// use gnap_types::key::{KeyObject, KeyError};
    ///
    /// let k: KeyObject = serde_json::from_str(r#"{"proof":"httpsig"}"#).unwrap();
    /// assert_eq!(k.validate(), Err(KeyError::NoFormat));
    /// ```
    /// # Errors
    ///
    /// Fails when no format is supplied, when several are, when a JWK is
    /// missing `alg` or `kid`, declares `alg: "none"`, or is a symmetric key.
    ///
    pub fn validate(&self) -> Result<(), KeyError> {
        let mut formats = Vec::new();
        if self.jwk.is_some() {
            formats.push("jwk");
        }
        if self.cert.is_some() {
            formats.push("cert");
        }
        if self.cert_s256.is_some() {
            formats.push("cert#S256");
        }

        match formats.len() {
            0 => return Err(KeyError::NoFormat),
            1 => {}
            _ => return Err(KeyError::MultipleFormats(formats)),
        }

        if let Some(jwk) = &self.jwk {
            // `alg` and `kid` are what §7.3.1 compares a signature against, so
            // their presence is not enough: they have to be strings, as RFC
            // 7517 §4 defines them.
            for p in ["alg", "kid"] {
                match jwk.get(p) {
                    None => return Err(KeyError::JwkMissing(p)),
                    Some(v) if !v.is_string() => return Err(KeyError::JwkNotAString(p)),
                    Some(_) => {}
                }
            }
            if jwk.get("alg").and_then(serde_json::Value::as_str) == Some("none") {
                return Err(KeyError::JwkAlgNone);
            }
            // §2.3 — "The client instance MUST NOT send a symmetric key by
            // value in the key field of the request, as doing so would expose
            // the key directly instead of simply proving possession of it."
            // RFC 7518 §6.1 names the symmetric key type `oct`.
            if jwk.get("kty").and_then(serde_json::Value::as_str) == Some("oct") {
                return Err(KeyError::SymmetricByValue);
            }
        }

        Ok(())
    }

    /// The JWK's `kid`, which a signature's `keyid` has to name (§7.3.1).
    ///
    /// `None` when the key is not a JWK, or has not been through
    /// [`validate`](Self::validate).
    #[must_use]
    pub fn jwk_key_id(&self) -> Option<&str> {
        self.jwk.as_ref()?.get("kid")?.as_str()
    }

    /// The JWS algorithm the JWK declares, which the signature must use
    /// (§7.3.1).
    #[must_use]
    pub fn jwk_algorithm(&self) -> Option<&str> {
        self.jwk.as_ref()?.get("alg")?.as_str()
    }
}

object_or_reference!(
    /// A key sent in full, or by reference (§7.1.1).
    ///
    /// A reference may point at a symmetric key, which a value cannot: §7.1.2
    /// forbids sending a symmetric key in the clear.
    Key,
    KeyObject,
    "key"
);
