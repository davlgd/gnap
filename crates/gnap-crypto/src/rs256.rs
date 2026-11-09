//! `RS256` — RSASSA-PKCS1-v1_5 with SHA-256 ([RFC 7518 §3.3]).
//!
//! GNAP reaches this algorithm through its JOSE proofs, `jws` and `jwsd`
//! ([RFC 9635 §7.3.3] and [§7.3.4]), whose examples sign with it. This crate
//! doesn't offer it for `httpsig`, where the interoperability profiles of
//! Appendix C name `PS256`: see [`PublicKey::for_jws`](crate::PublicKey::for_jws).
//!
//! [RFC 7518 §3.3]: https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3
//! [RFC 9635 §7.3.3]: https://www.rfc-editor.org/rfc/rfc9635.html#section-7.3.3
//! [§7.3.4]: https://www.rfc-editor.org/rfc/rfc9635.html#section-7.3.4

use crate::proof::{JwkSigner, ProofError, Signer, Verifier};
use crate::rsa_key;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier as _};
use rsa::{PrivateKey, PublicKey};
use serde_json::{Map, Value};
use sha2::Sha256;

/// An RSA private key used with `RS256`.
pub struct Rs256Signer {
    inner: SigningKey<Sha256>,
    public: PublicKey,
    key_id: String,
}

impl Rs256Signer {
    /// SHA-256 JWK thumbprint (RFC 7638), independent of `kid` and algorithm metadata.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        rsa_key::thumbprint(&self.public)
    }

    /// Size of the RSA modulus, for profiles that constrain key strength.
    #[must_use]
    pub fn modulus_bits(&self) -> usize {
        rsa_key::modulus_bits(&self.public)
    }

    /// Loads a PKCS#8 private key, `BEGIN PRIVATE KEY` format.
    ///
    /// # Errors
    ///
    /// Fails when the PEM cannot be read as a PKCS#8 RSA private key, or when
    /// its modulus is outside [`MIN_MODULUS_BITS`](crate::MIN_MODULUS_BITS)..=[`MAX_MODULUS_BITS`](crate::MAX_MODULUS_BITS).
    pub fn from_pkcs8_pem(pem: &str, key_id: impl Into<String>) -> Result<Self, ProofError> {
        Ok(Self::from_key(rsa_key::from_pkcs8_pem(pem)?, key_id))
    }

    /// Loads a PKCS#1 private key, `BEGIN RSA PRIVATE KEY` format.
    ///
    /// # Errors
    ///
    /// Fails when the PEM cannot be read as a PKCS#1 RSA private key, or when
    /// its modulus is outside the bounds.
    pub fn from_pkcs1_pem(pem: &str, key_id: impl Into<String>) -> Result<Self, ProofError> {
        Ok(Self::from_key(rsa_key::from_pkcs1_pem(pem)?, key_id))
    }

    /// Generates a fresh RSA key, for tests and examples.
    ///
    /// # Errors
    ///
    /// Fails when `bits` is outside the bounds, or when the random source is
    /// unavailable.
    pub fn generate(bits: usize, key_id: impl Into<String>) -> Result<Self, ProofError> {
        Ok(Self::from_key(rsa_key::generate(bits)?, key_id))
    }

    /// Wraps a key whose modulus [`rsa_key`] has already bounded.
    fn from_key(sk: PrivateKey, key_id: impl Into<String>) -> Self {
        Self {
            public: sk.to_public_key(),
            inner: SigningKey::<Sha256>::new(sk),
            key_id: key_id.into(),
        }
    }

    /// The verifier matching this key, named the same way.
    #[must_use]
    pub fn verifier(&self) -> Rs256Verifier {
        Rs256Verifier {
            inner: VerifyingKey::<Sha256>::new(self.public.clone()),
            key_id: Some(self.key_id.clone()),
        }
    }

    /// Exports the public JWK, with `alg: RS256`, `kid`, and `key_ops: [verify]`.
    ///
    /// # Errors
    ///
    /// Fails if the key identifier is outside the limits that
    /// [`Rs256Verifier::from_public_jwk`] accepts.
    pub fn public_jwk(&self) -> Result<Map<String, Value>, ProofError> {
        rsa_key::public_jwk(&self.public, "RS256", &self.key_id)
    }
}

impl JwkSigner for Rs256Signer {
    fn public_jwk(&self) -> Result<Map<String, Value>, ProofError> {
        Self::public_jwk(self)
    }

    fn thumbprint(&self) -> String {
        Self::thumbprint(self)
    }
}

impl Signer for Rs256Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, ProofError> {
        // The padding is deterministic, but the private operation blinds its
        // base with fresh randomness, so a missing entropy source is an error
        // rather than an unblinded signature.
        self.inner
            .try_sign_with_rng(&mut getrandom::SysRng, data)
            .map(|s| s.to_vec())
            .map_err(|e| ProofError::Signing(format!("RS256 signature: {e}")))
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn algorithm(&self) -> &'static str {
        "RS256"
    }
}

/// An RSA public key used with `RS256`.
#[derive(Clone)]
pub struct Rs256Verifier {
    inner: VerifyingKey<Sha256>,
    key_id: Option<String>,
}

impl Rs256Verifier {
    /// SHA-256 JWK thumbprint (RFC 7638), independent of `kid` and algorithm metadata.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        rsa_key::thumbprint(self.inner.as_ref())
    }

    /// Size of the RSA modulus, for profiles that constrain key strength.
    #[must_use]
    pub fn modulus_bits(&self) -> usize {
        rsa_key::modulus_bits(self.inner.as_ref())
    }

    /// Imports a public RSA JWK whose `alg` is `RS256`.
    ///
    /// The checks are those of [`Ps256Verifier::from_public_jwk`](crate::Ps256Verifier::from_public_jwk),
    /// apart from the algorithm: a nonempty `kid`, canonical RSA integers, a
    /// modulus within the bounds, and no private or certificate member.
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::Key`] for unsupported metadata, private material,
    /// malformed integers, or an RSA key outside these constraints.
    pub fn from_public_jwk(jwk: &Map<String, Value>) -> Result<Self, ProofError> {
        let (public, key_id) = rsa_key::public_from_jwk(jwk, "RS256")?;
        Ok(Self {
            inner: VerifyingKey::<Sha256>::new(public),
            key_id: Some(key_id),
        })
    }

    /// Loads a public key in `BEGIN PUBLIC KEY` format.
    ///
    /// The key carries no identity of its own; see [`Self::with_key_id`].
    ///
    /// # Errors
    ///
    /// Fails when the PEM cannot be read as an RSA public key within the bounds.
    pub fn from_public_key_pem(pem: &str) -> Result<Self, ProofError> {
        Ok(Self {
            inner: VerifyingKey::<Sha256>::new(rsa_key::public_from_pem(pem)?),
            key_id: None,
        })
    }

    /// Names the key, so a signature has to claim that identity.
    #[must_use]
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }
}

impl Verifier for Rs256Verifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), ProofError> {
        let sig = Signature::try_from(signature)
            .map_err(|e| ProofError::Verification(format!("unreadable signature: {e}")))?;
        self.inner
            .verify(data, &sig)
            .map_err(|e| ProofError::Verification(e.to_string()))
    }

    fn algorithm(&self) -> &'static str {
        "RS256"
    }

    fn expected_key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }
}
