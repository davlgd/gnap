//! `EdDSA` with Ed25519 (RFC 8032), for HTTP Message Signatures.
//!
//! RFC 9421 §3.3.6 registers it as `ed25519`; GNAP reaches it through the key,
//! a JWK of type `OKP` with `crv` `Ed25519` and `alg` `EdDSA` (RFC 8037 §2).
//! Verification uses `verify_strict`, which refuses weak public keys and
//! malleable signatures that a plain RFC 8032 verifier would accept; there is
//! no fallback to the permissive check.

use crate::jwk;
use crate::proof::{JwkSigner, ProofError, Signer, Verifier};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde_json::{Map, Value};
use zeroize::Zeroizing;

/// Length, in bytes, of an Ed25519 public key and of its private seed.
const KEY_BYTES: usize = 32;

/// Length, in bytes, of an Ed25519 signature (RFC 8032 §5.1.6). The type of
/// `Signature::from_bytes` must agree with it, or this crate doesn't compile.
const SIGNATURE_BYTES: usize = 64;

/// An Ed25519 private key used for `EdDSA` signatures.
pub struct Ed25519Signer {
    inner: SigningKey,
    key_id: String,
}

impl Ed25519Signer {
    /// Generates a fresh key from the operating system's random source.
    ///
    /// # Errors
    ///
    /// Fails when the random source is unavailable.
    pub fn generate(key_id: impl Into<String>) -> Result<Self, ProofError> {
        let mut seed = Zeroizing::new([0u8; KEY_BYTES]);
        getrandom::fill(seed.as_mut()).map_err(|e| ProofError::Key(format!("generation: {e}")))?;
        Ok(Self {
            inner: SigningKey::from_bytes(&seed),
            key_id: key_id.into(),
        })
    }

    /// Loads a PKCS#8 private key, `BEGIN PRIVATE KEY` format.
    ///
    /// # Errors
    ///
    /// Fails when the PEM can't be read as an Ed25519 private key.
    pub fn from_pkcs8_pem(pem: &str, key_id: impl Into<String>) -> Result<Self, ProofError> {
        let inner = SigningKey::from_pkcs8_pem(pem).map_err(|e| ProofError::Key(e.to_string()))?;
        Ok(Self {
            inner,
            key_id: key_id.into(),
        })
    }

    /// The verifier matching this key, named the same way.
    #[must_use]
    pub fn verifier(&self) -> Ed25519Verifier {
        Ed25519Verifier {
            inner: self.inner.verifying_key(),
            key_id: Some(self.key_id.clone()),
        }
    }

    /// The public key as a JWK, with `alg` `EdDSA` and this key's `kid`.
    ///
    /// # Errors
    ///
    /// Fails when the key identifier is outside the bounds that
    /// [`Ed25519Verifier::from_public_jwk`] accepts.
    pub fn public_jwk(&self) -> Result<Map<String, Value>, ProofError> {
        jwk::validate_key_id(&self.key_id)?;
        Ok(public_members(&self.inner.verifying_key(), &self.key_id))
    }

    /// The SHA-256 JWK thumbprint of the public key (RFC 7638).
    #[must_use]
    pub fn thumbprint(&self) -> String {
        thumbprint(&self.inner.verifying_key())
    }
}

impl JwkSigner for Ed25519Signer {
    fn public_jwk(&self) -> Result<Map<String, Value>, ProofError> {
        Self::public_jwk(self)
    }

    fn thumbprint(&self) -> String {
        Self::thumbprint(self)
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, ProofError> {
        use ed25519_dalek::Signer as _;
        Ok(self.inner.sign(data).to_bytes().to_vec())
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn algorithm(&self) -> &'static str {
        "EdDSA"
    }
}

/// An Ed25519 public key, used to verify `EdDSA` signatures.
#[derive(Clone)]
pub struct Ed25519Verifier {
    inner: VerifyingKey,
    key_id: Option<String>,
}

impl Ed25519Verifier {
    /// Imports a public JWK: `kty` `OKP`, `crv` `Ed25519`, `alg` `EdDSA`.
    ///
    /// `x` must encode exactly 32 bytes of a valid, non-weak curve point.
    /// Private and symmetric members are refused, and `kid`, `use`, and
    /// `key_ops` follow the same rules as [`crate::jwk::PublicKey::from_jwk`].
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::Key`] for other metadata, private material, or a
    /// public key that isn't a valid, non-weak point.
    pub fn from_public_jwk(jwk: &Map<String, Value>) -> Result<Self, ProofError> {
        if jwk::string(jwk, "kty")? != "OKP"
            || jwk::string(jwk, "crv")? != "Ed25519"
            || jwk::string(jwk, "alg")? != "EdDSA"
        {
            return Err(jwk::error("expected kty OKP, crv Ed25519, and alg EdDSA"));
        }
        let key_id = jwk::common(jwk)?;
        let x = jwk::fixed_bytes(jwk, "x", KEY_BYTES)?;
        let inner = public_key(&x)?;
        Ok(Self {
            inner,
            key_id: Some(key_id.into()),
        })
    }

    /// Loads a public key in `BEGIN PUBLIC KEY` format, without an identifier;
    /// see [`Self::with_key_id`].
    ///
    /// # Errors
    ///
    /// Fails when the PEM can't be read as a valid, non-weak Ed25519 key.
    pub fn from_public_key_pem(pem: &str) -> Result<Self, ProofError> {
        let inner =
            VerifyingKey::from_public_key_pem(pem).map_err(|e| ProofError::Key(e.to_string()))?;
        if inner.is_weak() {
            return Err(ProofError::Key("weak Ed25519 public key".into()));
        }
        Ok(Self {
            inner,
            key_id: None,
        })
    }

    /// Names the key, so a signature has to claim that identity (§7.3.1).
    #[must_use]
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }

    /// The SHA-256 JWK thumbprint of the key (RFC 7638).
    #[must_use]
    pub fn thumbprint(&self) -> String {
        thumbprint(&self.inner)
    }
}

impl Verifier for Ed25519Verifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), ProofError> {
        let bytes: &[u8; SIGNATURE_BYTES] = signature.try_into().map_err(|_| {
            ProofError::Verification(format!("an Ed25519 signature has {SIGNATURE_BYTES} bytes"))
        })?;
        self.inner
            .verify_strict(data, &Signature::from_bytes(bytes))
            .map_err(|e| ProofError::Verification(e.to_string()))
    }

    fn algorithm(&self) -> &'static str {
        "EdDSA"
    }

    fn expected_key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }
}

fn public_key(x: &[u8]) -> Result<VerifyingKey, ProofError> {
    let bytes: &[u8; KEY_BYTES] = x
        .try_into()
        .map_err(|_| jwk::error("x must encode 32 bytes"))?;
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| jwk::error("x isn't a curve point"))?;
    if key.is_weak() {
        return Err(jwk::error("x is a weak Ed25519 public key"));
    }
    Ok(key)
}

fn public_members(key: &VerifyingKey, key_id: &str) -> Map<String, Value> {
    Map::from_iter([
        ("kty".into(), Value::String("OKP".into())),
        ("crv".into(), Value::String("Ed25519".into())),
        (
            "x".into(),
            Value::String(URL_SAFE_NO_PAD.encode(key.as_bytes())),
        ),
        ("alg".into(), Value::String("EdDSA".into())),
        ("kid".into(), Value::String(key_id.into())),
    ])
}

fn thumbprint(key: &VerifyingKey) -> String {
    let x = URL_SAFE_NO_PAD.encode(key.as_bytes());
    jwk::thumbprint(&[("crv", "Ed25519"), ("kty", "OKP"), ("x", &x)])
}
