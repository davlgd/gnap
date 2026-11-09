//! Public JWK import for the key types this crate verifies.
//!
//! GNAP presents a key as a JWK that names its signature algorithm in `alg`
//! (RFC 9635 §7.1, Appendix C). [`PublicKey::from_jwk`] selects the verifier
//! from `kty`, `crv`, and `alg` together, and refuses any other combination:
//! the algorithm comes from the trusted key, never from a signature header.

use crate::ed25519::Ed25519Verifier;
use crate::es256::Es256Verifier;
use crate::proof::{ProofError, Verifier};
use crate::ps256::Ps256Verifier;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use std::collections::HashSet;

/// Longest `kid`, in bytes.
pub(crate) const MAX_KEY_ID_BYTES: usize = 1024;

/// Longest `key_ops` entry, in bytes.
const MAX_KEY_OPERATION_BYTES: usize = 1024;

/// Most `key_ops` entries in an imported JWK.
const MAX_KEY_OPERATIONS: usize = 32;

/// A public key imported from a JWK, with the verifier its algorithm calls for.
#[derive(Clone)]
pub enum PublicKey {
    /// RSASSA-PSS with SHA-256: `kty` `RSA`, `alg` `PS256`.
    Ps256(Ps256Verifier),
    /// ECDSA on P-256 with SHA-256: `kty` `EC`, `crv` `P-256`, `alg` `ES256`.
    Es256(Es256Verifier),
    /// Ed25519: `kty` `OKP`, `crv` `Ed25519`, `alg` `EdDSA`.
    Ed25519(Ed25519Verifier),
}

impl PublicKey {
    /// Imports a public JWK, choosing the verifier from `kty`, `crv`, and `alg`.
    ///
    /// The key must name its algorithm and carry a `kid`, which becomes the
    /// `keyid` a signature has to present (RFC 9635 §7.3.1). Private members,
    /// certificate members, and a `use` or `key_ops` that doesn't permit
    /// verification are refused. Each key type then checks its own members.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::Key`] for an unsupported combination of `kty`,
    /// `crv`, and `alg`, or for a key its type refuses.
    pub fn from_jwk(jwk: &Map<String, Value>) -> Result<Self, ProofError> {
        let kty = string(jwk, "kty")?;
        let alg = string(jwk, "alg")?;
        let crv = jwk.get("crv").and_then(Value::as_str);
        match (kty, crv, alg) {
            ("RSA", None, "PS256") => Ps256Verifier::from_public_jwk(jwk).map(Self::Ps256),
            ("EC", Some("P-256"), "ES256") => Es256Verifier::from_public_jwk(jwk).map(Self::Es256),
            ("OKP", Some("Ed25519"), "EdDSA") => {
                Ed25519Verifier::from_public_jwk(jwk).map(Self::Ed25519)
            }
            _ => Err(error(&format!(
                "unsupported key: kty {kty}, crv {}, alg {alg}",
                crv.unwrap_or("absent")
            ))),
        }
    }

    /// Imports a public JWK for HTTP Message Signatures (`httpsig`).
    ///
    /// This is the one place that says which algorithms a proof method
    /// accepts: `httpsig` takes `PS256`, `ES256`, and `EdDSA`, the algorithms
    /// RFC 9421 and RFC 9635 §7.3.1 define a signature for.
    ///
    /// # Errors
    ///
    /// Fails as [`Self::from_jwk`] does, or for an algorithm `httpsig`
    /// doesn't accept.
    pub fn for_httpsig(jwk: &Map<String, Value>) -> Result<Self, ProofError> {
        let key = Self::from_jwk(jwk)?;
        match key {
            Self::Ps256(_) | Self::Es256(_) | Self::Ed25519(_) => Ok(key),
        }
    }

    /// The SHA-256 JWK thumbprint of the key (RFC 7638).
    ///
    /// It covers only the key's required members, not `alg` or `kid`, so it
    /// identifies a key, never an algorithm a key may be used with.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        match self {
            Self::Ps256(key) => key.thumbprint(),
            Self::Es256(key) => key.thumbprint(),
            Self::Ed25519(key) => key.thumbprint(),
        }
    }

    fn verifier(&self) -> &dyn Verifier {
        match self {
            Self::Ps256(key) => key,
            Self::Es256(key) => key,
            Self::Ed25519(key) => key,
        }
    }
}

impl Verifier for PublicKey {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), ProofError> {
        self.verifier().verify(data, signature)
    }

    fn algorithm(&self) -> &'static str {
        self.verifier().algorithm()
    }

    fn expected_key_id(&self) -> Option<&str> {
        self.verifier().expected_key_id()
    }
}

/// A JWK error, with the prefix every key import uses.
pub(crate) fn error(message: &str) -> ProofError {
    ProofError::Key(format!("JWK: {message}"))
}

/// A string member of the JWK.
pub(crate) fn string<'a>(jwk: &'a Map<String, Value>, field: &str) -> Result<&'a str, ProofError> {
    jwk.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| error(&format!("{field} must be a string")))
}

/// The private and symmetric members of every key type (RFC 7518 §6), refused
/// in a public key whatever its type, even when null.
const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// The checks every public key import applies: a bounded `kid`, no private,
/// symmetric, or certificate member, and a usage that permits verification.
/// Returns the `kid`.
pub(crate) fn common(jwk: &Map<String, Value>) -> Result<&str, ProofError> {
    let key_id = string(jwk, "kid")?;
    validate_key_id(key_id)?;
    if PRIVATE_MEMBERS.iter().any(|field| jwk.contains_key(*field)) {
        return Err(error("private key parameters are not accepted"));
    }
    if ["x5c", "x5u", "x5t", "x5t#S256"]
        .iter()
        .any(|field| jwk.contains_key(*field))
    {
        return Err(error(
            "certificate parameters need a certificate-aware adapter",
        ));
    }
    validate_usage(jwk)?;
    Ok(key_id)
}

/// A `kid` of 1 to [`MAX_KEY_ID_BYTES`] bytes.
pub(crate) fn validate_key_id(key_id: &str) -> Result<(), ProofError> {
    if key_id.is_empty() || key_id.len() > MAX_KEY_ID_BYTES {
        return Err(error(&format!(
            "kid must contain 1–{MAX_KEY_ID_BYTES} bytes"
        )));
    }
    Ok(())
}

/// A base64url member that decodes to exactly `length` bytes.
pub(crate) fn fixed_bytes(
    jwk: &Map<String, Value>,
    field: &str,
    length: usize,
) -> Result<Vec<u8>, ProofError> {
    let encoded = string(jwk, field)?;
    if encoded.len() != (length * 8).div_ceil(6) {
        return Err(error(&format!("{field} must encode {length} bytes")));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| error(&format!("{field} must be unpadded base64url")))?;
    if bytes.len() == length {
        Ok(bytes)
    } else {
        Err(error(&format!("{field} must encode {length} bytes")))
    }
}

/// The SHA-256 thumbprint of a key's required members, given in their
/// lexicographic order with base64url values (RFC 7638 §3.2). Those values
/// contain no JSON escapes, so the canonical form needs no serializer.
pub(crate) fn thumbprint(members: &[(&str, &str)]) -> String {
    let canonical = members
        .iter()
        .map(|(name, value)| format!(r#""{name}":"{value}""#))
        .collect::<Vec<_>>()
        .join(",");
    URL_SAFE_NO_PAD.encode(Sha256::digest(format!("{{{canonical}}}").as_bytes()))
}

fn validate_usage(jwk: &Map<String, Value>) -> Result<(), ProofError> {
    if jwk.contains_key("use") && string(jwk, "use")? != "sig" {
        return Err(error("use must be sig for signature verification"));
    }
    let Some(operations) = jwk.get("key_ops") else {
        return Ok(());
    };
    let operations = operations
        .as_array()
        .ok_or_else(|| error("key_ops must be an array"))?;
    if operations.len() > MAX_KEY_OPERATIONS {
        return Err(error(&format!(
            "key_ops exceeds the {MAX_KEY_OPERATIONS}-operation limit"
        )));
    }
    let mut seen = HashSet::new();
    for operation in operations {
        let operation = operation
            .as_str()
            .ok_or_else(|| error("key_ops entries must be strings"))?;
        if operation.len() > MAX_KEY_OPERATION_BYTES || !seen.insert(operation) {
            return Err(error("key_ops contains a duplicate or oversized operation"));
        }
        if matches!(
            operation,
            "encrypt" | "decrypt" | "wrapKey" | "unwrapKey" | "deriveKey" | "deriveBits"
        ) {
            return Err(error("key_ops includes an incompatible operation"));
        }
    }
    if !seen.contains("verify") {
        return Err(error("key_ops does not permit verification"));
    }
    Ok(())
}
