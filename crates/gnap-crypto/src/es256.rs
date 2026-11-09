//! `ES256`: ECDSA on the P-256 curve with SHA-256, for HTTP Message Signatures.
//!
//! RFC 9421 §3.3.4 registers it as `ecdsa-p256-sha256`; GNAP reaches it
//! through the key, a JWK of type `EC` with `crv` `P-256` and `alg` `ES256`
//! (RFC 7518 §3.4). A signature is the 64-byte concatenation of `r` and `s`,
//! never a DER structure.
//!
//! ECDSA signatures are malleable: `(r, n − s)` verifies wherever `(r, s)` does.
//! The verifier accepts both, as RFC 7518 and RFC 9421 do, so a replay defence
//! must not identify a request by its signature bytes.

use crate::jwk;
use crate::proof::{JwkSigner, ProofError, Signer, Verifier};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::DecodePrivateKey;
use p256::pkcs8::DecodePublicKey;
use serde_json::{Map, Value};
use zeroize::Zeroizing;

/// Length, in bytes, of a P-256 field element, and so of each coordinate and
/// of each half of a signature.
const FIELD_BYTES: usize = 32;

/// Draws of random bytes before generation gives up: a draw is outside the
/// scalar range with probability below 2⁻³², so the bound is never reached by
/// a working source.
const MAX_GENERATION_DRAWS: usize = 8;

/// A P-256 private key used for `ES256` signatures.
pub struct Es256Signer {
    inner: SigningKey,
    key_id: String,
}

impl Es256Signer {
    /// Generates a fresh key from the operating system's random source.
    ///
    /// # Errors
    ///
    /// Fails when the random source is unavailable.
    pub fn generate(key_id: impl Into<String>) -> Result<Self, ProofError> {
        for _ in 0..MAX_GENERATION_DRAWS {
            let mut scalar = Zeroizing::new([0u8; FIELD_BYTES]);
            getrandom::fill(scalar.as_mut())
                .map_err(|e| ProofError::Key(format!("generation: {e}")))?;
            if let Ok(inner) = SigningKey::from_slice(scalar.as_ref()) {
                return Ok(Self {
                    inner,
                    key_id: key_id.into(),
                });
            }
        }
        Err(ProofError::Key("generation: no valid scalar drawn".into()))
    }

    /// Loads a PKCS#8 private key, `BEGIN PRIVATE KEY` format.
    ///
    /// # Errors
    ///
    /// Fails when the PEM can't be read as a P-256 private key.
    pub fn from_pkcs8_pem(pem: &str, key_id: impl Into<String>) -> Result<Self, ProofError> {
        let inner = SigningKey::from_pkcs8_pem(pem).map_err(|e| ProofError::Key(e.to_string()))?;
        Ok(Self {
            inner,
            key_id: key_id.into(),
        })
    }

    /// Loads a SEC1 private key, `BEGIN EC PRIVATE KEY` format.
    ///
    /// # Errors
    ///
    /// Fails when the PEM can't be read as a P-256 private key.
    pub fn from_sec1_pem(pem: &str, key_id: impl Into<String>) -> Result<Self, ProofError> {
        let secret =
            p256::SecretKey::from_sec1_pem(pem).map_err(|e| ProofError::Key(e.to_string()))?;
        Ok(Self {
            inner: SigningKey::from(secret),
            key_id: key_id.into(),
        })
    }

    /// The verifier matching this key, named the same way.
    #[must_use]
    pub fn verifier(&self) -> Es256Verifier {
        Es256Verifier {
            inner: *self.inner.verifying_key(),
            key_id: Some(self.key_id.clone()),
        }
    }

    /// The public key as a JWK, with `alg` `ES256` and this key's `kid`.
    ///
    /// # Errors
    ///
    /// Fails when the key identifier is outside the bounds that
    /// [`Es256Verifier::from_public_jwk`] accepts.
    pub fn public_jwk(&self) -> Result<Map<String, Value>, ProofError> {
        jwk::validate_key_id(&self.key_id)?;
        let (x, y) = coordinates(self.inner.verifying_key());
        Ok(Map::from_iter([
            ("kty".into(), Value::String("EC".into())),
            ("crv".into(), Value::String("P-256".into())),
            ("x".into(), Value::String(x)),
            ("y".into(), Value::String(y)),
            ("alg".into(), Value::String("ES256".into())),
            ("kid".into(), Value::String(self.key_id.clone())),
        ]))
    }

    /// The SHA-256 JWK thumbprint of the public key (RFC 7638).
    #[must_use]
    pub fn thumbprint(&self) -> String {
        thumbprint(self.inner.verifying_key())
    }
}

impl JwkSigner for Es256Signer {
    fn public_jwk(&self) -> Result<Map<String, Value>, ProofError> {
        Self::public_jwk(self)
    }

    fn thumbprint(&self) -> String {
        Self::thumbprint(self)
    }
}

impl Signer for Es256Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, ProofError> {
        let signature: Signature = self
            .inner
            .try_sign(data)
            .map_err(|e| ProofError::Signing(format!("ES256 signature: {e}")))?;
        Ok(signature.to_bytes().to_vec())
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn algorithm(&self) -> &'static str {
        "ES256"
    }
}

/// A P-256 public key, used to verify `ES256` signatures.
#[derive(Clone)]
pub struct Es256Verifier {
    inner: VerifyingKey,
    key_id: Option<String>,
}

impl Es256Verifier {
    /// Imports a public JWK: `kty` `EC`, `crv` `P-256`, `alg` `ES256`.
    ///
    /// `x` and `y` must each encode exactly 32 bytes, and together a point of
    /// the curve other than the identity. Private and symmetric members are
    /// refused, and `kid`, `use`, and `key_ops` follow the same rules as
    /// [`crate::jwk::PublicKey::from_jwk`].
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::Key`] for other metadata, private material, or
    /// coordinates that aren't a valid point.
    pub fn from_public_jwk(jwk: &Map<String, Value>) -> Result<Self, ProofError> {
        if jwk::string(jwk, "kty")? != "EC"
            || jwk::string(jwk, "crv")? != "P-256"
            || jwk::string(jwk, "alg")? != "ES256"
        {
            return Err(jwk::error("expected kty EC, crv P-256, and alg ES256"));
        }
        let key_id = jwk::common(jwk)?;
        let x = jwk::fixed_bytes(jwk, "x", FIELD_BYTES)?;
        let y = jwk::fixed_bytes(jwk, "y", FIELD_BYTES)?;
        let mut point = Vec::with_capacity(1 + 2 * FIELD_BYTES);
        point.push(0x04);
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);
        let inner = VerifyingKey::from_sec1_bytes(&point)
            .map_err(|_| jwk::error("x and y aren't a point of P-256"))?;
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
    /// Fails when the PEM can't be read as a P-256 public key.
    pub fn from_public_key_pem(pem: &str) -> Result<Self, ProofError> {
        let inner =
            VerifyingKey::from_public_key_pem(pem).map_err(|e| ProofError::Key(e.to_string()))?;
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

impl Verifier for Es256Verifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), ProofError> {
        if signature.len() != 2 * FIELD_BYTES {
            return Err(ProofError::Verification(format!(
                "an ES256 signature has {} bytes, r then s",
                2 * FIELD_BYTES
            )));
        }
        let signature = Signature::from_slice(signature)
            .map_err(|e| ProofError::Verification(format!("unreadable signature: {e}")))?;
        self.inner
            .verify(data, &signature)
            .map_err(|e| ProofError::Verification(e.to_string()))
    }

    fn algorithm(&self) -> &'static str {
        "ES256"
    }

    fn expected_key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }
}

fn coordinates(key: &VerifyingKey) -> (String, String) {
    let point = key.to_sec1_point(false);
    let bytes = point.as_bytes();
    let x = URL_SAFE_NO_PAD.encode(&bytes[1..=FIELD_BYTES]);
    let y = URL_SAFE_NO_PAD.encode(&bytes[1 + FIELD_BYTES..]);
    (x, y)
}

fn thumbprint(key: &VerifyingKey) -> String {
    let (x, y) = coordinates(key);
    jwk::thumbprint(&[("crv", "P-256"), ("kty", "EC"), ("x", &x), ("y", &y)])
}
