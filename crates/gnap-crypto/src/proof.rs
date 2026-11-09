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

    /// The JWA name of the algorithm (RFC 7518), such as `PS256` or `EdDSA`.
    ///
    /// An `httpsig` signature never carries it (§7.3.1). A verifier compares it
    /// with the `alg` of the key the client presented, which must match.
    fn algorithm(&self) -> &'static str;
}

/// Forwards to the signer behind a reference or a smart pointer, so that a
/// holder can own its signer or share one.
macro_rules! forward_signer {
    ($($pointer:ty),*) => {$(
        impl<S: Signer + ?Sized> Signer for $pointer {
            fn sign(&self, data: &[u8]) -> Result<Vec<u8>, ProofError> {
                (**self).sign(data)
            }
            fn key_id(&self) -> &str {
                (**self).key_id()
            }
            fn algorithm(&self) -> &'static str {
                (**self).algorithm()
            }
        }
    )*};
}

forward_signer!(&S, Box<S>, std::sync::Arc<S>);

/// A signer whose public key travels as a JWK that names its algorithm, as
/// GNAP presents keys (RFC 9635 §7.1).
pub trait JwkSigner: Signer {
    /// The public key as a JWK, with its `alg` and this signer's `kid`.
    ///
    /// # Errors
    ///
    /// Fails when the key can't be presented under the import bounds of
    /// [`crate::jwk::PublicKey::from_jwk`].
    fn public_jwk(&self) -> Result<serde_json::Map<String, serde_json::Value>, ProofError>;

    /// The SHA-256 JWK thumbprint of the public key (RFC 7638).
    fn thumbprint(&self) -> String;
}

macro_rules! forward_jwk_signer {
    ($($pointer:ty),*) => {$(
        impl<S: JwkSigner + ?Sized> JwkSigner for $pointer {
            fn public_jwk(
                &self,
            ) -> Result<serde_json::Map<String, serde_json::Value>, ProofError> {
                (**self).public_jwk()
            }
            fn thumbprint(&self) -> String {
                (**self).thumbprint()
            }
        }
    )*};
}

forward_jwk_signer!(&S, Box<S>, std::sync::Arc<S>);

/// Validates a signature over a byte string.
pub trait Verifier {
    /// Returns `Ok(())` when the signature matches, an error otherwise.
    ///
    /// # Errors
    ///
    /// Fails when the signature does not match the data under this key.
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), ProofError>;

    /// The JWA name of the algorithm (RFC 7518), as [`Signer::algorithm`] gives it.
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
