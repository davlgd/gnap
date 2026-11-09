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
use crate::rs256::Rs256Verifier;
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

/// The algorithms this crate accepts for HTTP Message Signatures.
///
/// RFC 9421 §3.3.7 admits any JWA algorithm that isn't prohibited: this crate
/// keeps the `PS256` of the profiles in RFC 9635 Appendix C and the two
/// algorithms RFC 9421 also registers under its own names, and leaves `RS256`
/// to the JOSE proofs.
pub const HTTPSIG_ALGORITHMS: [&str; 3] = ["PS256", "ES256", "EdDSA"];

/// The algorithms this crate accepts for the JOSE proofs, `jws` and `jwsd`.
///
/// `RS256` is the algorithm of the RFC 9635 §7.3.3 and §7.3.4 examples.
/// `PS256` stays with `httpsig`, so that each RSA padding has one proof method.
pub const JWS_ALGORITHMS: [&str; 3] = ["RS256", "ES256", "EdDSA"];

/// A public key imported from a JWK, with the verifier its algorithm calls for.
#[derive(Clone)]
#[non_exhaustive]
pub enum PublicKey {
    /// RSASSA-PSS with SHA-256: `kty` `RSA`, `alg` `PS256`.
    Ps256(Ps256Verifier),
    /// RSASSA-PKCS1-v1_5 with SHA-256: `kty` `RSA`, `alg` `RS256`.
    Rs256(Rs256Verifier),
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
            ("RSA", None, "RS256") => Rs256Verifier::from_public_jwk(jwk).map(Self::Rs256),
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

    /// Imports a public JWK for HTTP Message Signatures (`httpsig`), whose
    /// `alg` must be one of [`HTTPSIG_ALGORITHMS`].
    ///
    /// # Errors
    ///
    /// Fails for an algorithm `httpsig` doesn't accept, checked before the
    /// key is decoded, or as [`Self::from_jwk`] does.
    pub fn for_httpsig(jwk: &Map<String, Value>) -> Result<Self, ProofError> {
        Self::for_method(jwk, "httpsig", &HTTPSIG_ALGORITHMS)
    }

    /// Imports a public JWK for the JOSE proofs, `jws` and `jwsd`, whose
    /// `alg` must be one of [`JWS_ALGORITHMS`].
    ///
    /// # Errors
    ///
    /// Fails for an algorithm these proofs don't accept, checked before the
    /// key is decoded, or as [`Self::from_jwk`] does.
    pub fn for_jws(jwk: &Map<String, Value>) -> Result<Self, ProofError> {
        Self::for_method(jwk, "jws and jwsd", &JWS_ALGORITHMS)
    }

    fn for_method(
        jwk: &Map<String, Value>,
        method: &str,
        algorithms: &[&str],
    ) -> Result<Self, ProofError> {
        let alg = string(jwk, "alg")?;
        if !algorithms.contains(&alg) {
            return Err(error(&format!("alg {alg} isn't accepted for {method}")));
        }
        Self::from_jwk(jwk)
    }

    /// Whether the JWK is a candidate for the built-in validation: its `kty`,
    /// `alg`, and, for `EdDSA`, its curve name an algorithm this crate
    /// implements, so that [`Self::from_jwk`] is the import to apply.
    ///
    /// `true` doesn't mean the key is valid, only that [`Self::from_jwk`]
    /// decides. A JWK of another algorithm or curve isn't refused by this
    /// check: a deployment may verify it through its own key resolver.
    #[must_use]
    pub fn is_builtin(jwk: &Map<String, Value>) -> bool {
        let kty = jwk.get("kty").and_then(Value::as_str);
        let alg = jwk.get("alg").and_then(Value::as_str);
        match (kty, alg) {
            (Some("RSA"), Some("PS256" | "RS256")) | (Some("EC"), Some("ES256")) => true,
            // `EdDSA` also names Ed448 (RFC 8037 §3.1): only Ed25519 is built
            // in, and a missing or malformed curve is refused as a candidate.
            (Some("OKP"), Some("EdDSA")) => jwk
                .get("crv")
                .is_none_or(|crv| crv.as_str().is_none_or(|crv| crv == "Ed25519")),
            _ => false,
        }
    }

    /// Whether the JWK is a built-in candidate, as [`Self::is_builtin`] says,
    /// of an algorithm in [`HTTPSIG_ALGORITHMS`].
    ///
    /// A server that validates an `httpsig` key early uses this test: a key
    /// that this crate implements for another proof method, such as an
    /// `RS256` key, stays the configured resolver's to accept or refuse.
    #[must_use]
    pub fn is_builtin_for_httpsig(jwk: &Map<String, Value>) -> bool {
        Self::is_builtin(jwk)
            && jwk
                .get("alg")
                .and_then(Value::as_str)
                .is_some_and(|alg| HTTPSIG_ALGORITHMS.contains(&alg))
    }

    /// The SHA-256 JWK thumbprint of the key (RFC 7638).
    ///
    /// It covers only the key's required members, not `alg` or `kid`, so it
    /// identifies a key, never an algorithm a key may be used with.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        match self {
            Self::Ps256(key) => key.thumbprint(),
            Self::Rs256(key) => key.thumbprint(),
            Self::Es256(key) => key.thumbprint(),
            Self::Ed25519(key) => key.thumbprint(),
        }
    }

    fn verifier(&self) -> &dyn Verifier {
        match self {
            Self::Ps256(key) => key,
            Self::Rs256(key) => key,
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
