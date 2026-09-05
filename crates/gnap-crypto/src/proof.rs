//! The key-proofing abstraction — RFC 9635 §7.3.
//!
//! GNAP defines four proofing methods (`httpsig`, `mtls`, `jwsd`, `jws`) and
//! expects more to be registered. The traits in this module separate what signs
//! bytes from what builds the bytes to sign, for two reasons:
//!
//! - the cryptographic primitive stays replaceable — the Appendix C profiles
//!   mandate `PS256`, which the `httpsig` crate does not expose;
//! - the three other proofing methods can land later without touching their
//!   callers.

use core::fmt;

/// What prevents a proof from being produced or validated.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProofError {
    /// The key could not be read.
    Key(String),
    /// The signature could not be produced.
    Signing(String),
    /// The signature does not match.
    Verification(String),
    /// The signature base could not be built.
    Base(String),
    /// A GNAP coverage requirement is not met (§7.3.1).
    Coverage(String),
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(m) => write!(f, "key: {m}"),
            Self::Signing(m) => write!(f, "signing: {m}"),
            Self::Verification(m) => write!(f, "verification: {m}"),
            Self::Base(m) => write!(f, "signature base: {m}"),
            Self::Coverage(m) => write!(f, "coverage: {m}"),
        }
    }
}

impl std::error::Error for ProofError {}

/// Produces a signature over a byte string.
///
/// The implementation carries the algorithm; GNAP never puts it in the message,
/// it is derived from the key (§7.3.1: "The explicit alg signature parameter
/// MUST NOT be included").
pub trait Signer {
    /// Signs the given bytes.
    ///
    /// # Errors
    ///
    /// Fails when the key material cannot produce a signature.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, ProofError>;

    /// The key identifier, carried by the `keyid` parameter.
    ///
    /// When the key is a JWK, §7.3.1 requires this to be its `kid`.
    fn key_id(&self) -> &str;

    /// The algorithm name, for information only.
    ///
    /// It does not travel in the message: it serves logs and error messages.
    fn algorithm(&self) -> &'static str;
}

/// Validates a signature over a byte string.
pub trait Verifier {
    /// Returns `Ok(())` when the signature matches, an error otherwise.
    ///
    /// # Errors
    ///
    /// Fails when the signature does not match the data under this key.
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), ProofError>;

    /// The algorithm name, for information only.
    fn algorithm(&self) -> &'static str;

    /// The identity the `keyid` parameter has to name, when the key form has
    /// one (§7.3.1).
    ///
    /// "If the signer's key presented is a JWK, the keyid parameter of the
    /// signature MUST be set to the kid value of the JWK." A key that carries
    /// no identifier of its own — a bare PEM, a certificate thumbprint — has
    /// nothing for the verifier to compare against, so the default is `None`
    /// and the check does not apply.
    fn expected_key_id(&self) -> Option<&str> {
        None
    }
}
