//! `PS256` — RSASSA-PSS with SHA-256.
//!
//! Both interoperability profiles in Appendix C of RFC 9635 mandate this
//! algorithm. It is nevertheless absent from RFC 9421's "HTTP Signature
//! Algorithms" registry, which holds `rsa-pss-sha512` and not
//! `rsa-pss-sha256`: GNAP reaches it through the JWS path of §3.3.7, where the
//! algorithm comes from the key and "the explicit alg signature parameter is
//! not used at all".
//!
//! That is also why the `httpsig` crate cannot provide it: its `AlgorithmName`
//! follows the registry. So it is implemented here.

use crate::jwk;
use crate::proof::{JwkSigner, ProofError, Signer, Verifier};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::pss::{Signature, SigningKey, VerifyingKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier as _};
use rsa::traits::PublicKeyParts;
use rsa::{BoxedUint, PrivateKey, PublicKey};
use serde_json::{Map, Value};
use sha2::Sha256;

/// An RSA private key used with `PS256`.
pub struct Ps256Signer {
    inner: SigningKey<Sha256>,
    public: PublicKey,
    key_id: String,
}

impl Ps256Signer {
    /// SHA-256 JWK thumbprint (RFC 7638), independent of `kid` and algorithm metadata.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        thumbprint(&self.public)
    }

    /// Size of the RSA modulus, for profiles that constrain key strength.
    #[must_use]
    pub fn modulus_bits(&self) -> usize {
        self.public.n().bit_width() as usize
    }

    /// Loads a PKCS#8 private key, `BEGIN PRIVATE KEY` format.
    ///
    /// A PKCS#8 key carrying the RSASSA-PSS OID (`1.2.840.113549.1.1.10`) is
    /// rejected on this path — which is the case for the test key in Appendix
    /// B.1.2 of RFC 9421. Use [`Ps256Signer::from_pkcs1_pem`] for those.
    /// # Errors
    ///
    /// Fails when the PEM cannot be read as a PKCS#8 RSA private key — which
    /// includes a key carrying the RSASSA-PSS OID.
    pub fn from_pkcs8_pem(pem: &str, key_id: impl Into<String>) -> Result<Self, ProofError> {
        let sk = PrivateKey::from_pkcs8_pem(pem).map_err(|e| ProofError::Key(e.to_string()))?;
        Self::from_key(sk, key_id)
    }

    /// Loads a PKCS#1 private key, `BEGIN RSA PRIVATE KEY` format.
    /// # Errors
    ///
    /// Fails when the PEM cannot be read as a PKCS#1 RSA private key.
    pub fn from_pkcs1_pem(pem: &str, key_id: impl Into<String>) -> Result<Self, ProofError> {
        let sk = PrivateKey::from_pkcs1_pem(pem).map_err(|e| ProofError::Key(e.to_string()))?;
        Self::from_key(sk, key_id)
    }

    /// Generates a fresh RSA key.
    ///
    /// Meant for tests and examples: a production key is managed elsewhere, and
    /// §11.5 is a reminder that protecting it is a deployment concern.
    /// # Errors
    ///
    /// Fails when `bits` is outside [`MIN_MODULUS_BITS`]..=[`MAX_MODULUS_BITS`],
    /// or when the random source is unavailable.
    pub fn generate(bits: usize, key_id: impl Into<String>) -> Result<Self, ProofError> {
        check_modulus_bits(bits)?;
        let mut rng = getrandom::SysRng;
        let sk = PrivateKey::new(&mut rng, bits)
            .map_err(|e| ProofError::Key(format!("generation: {e}")))?;
        Self::from_key(sk, key_id)
    }

    fn from_key(sk: PrivateKey, key_id: impl Into<String>) -> Result<Self, ProofError> {
        let public = sk.to_public_key();
        check_modulus_bits(public.n().bit_width() as usize)?;
        Ok(Self {
            inner: SigningKey::<Sha256>::new(sk),
            public,
            key_id: key_id.into(),
        })
    }

    /// The verifier matching this key, named the same way.
    #[must_use]
    pub fn verifier(&self) -> Ps256Verifier {
        Ps256Verifier {
            inner: VerifyingKey::<Sha256>::from(self.public.clone()),
            key_id: Some(self.key_id.clone()),
        }
    }

    /// Exports only the public JWK for a GNAP `httpsig` key object.
    ///
    /// Includes `kty`, `n`, `e`, `alg: PS256`, `kid` and `key_ops: [verify]`.
    /// The returned map can be assigned directly to `KeyObject::jwk` in
    /// `gnap-types`; this crate has no dependency on GNAP message types.
    ///
    /// # Errors
    ///
    /// Fails if the key identifier is outside the limits that
    /// [`Ps256Verifier::from_public_jwk`] accepts.
    pub fn public_jwk(&self) -> Result<Map<String, Value>, ProofError> {
        jwk::validate_key_id(&self.key_id)?;
        Ok(Map::from_iter([
            ("kty".into(), Value::String("RSA".into())),
            (
                "n".into(),
                Value::String(
                    URL_SAFE_NO_PAD.encode(self.public.n().to_be_bytes_trimmed_vartime()),
                ),
            ),
            (
                "e".into(),
                Value::String(
                    URL_SAFE_NO_PAD.encode(self.public.e().to_be_bytes_trimmed_vartime()),
                ),
            ),
            ("alg".into(), Value::String("PS256".into())),
            ("kid".into(), Value::String(self.key_id.clone())),
            ("key_ops".into(), serde_json::json!(["verify"])),
        ]))
    }
}

impl JwkSigner for Ps256Signer {
    fn public_jwk(&self) -> Result<Map<String, Value>, ProofError> {
        Self::public_jwk(self)
    }

    fn thumbprint(&self) -> String {
        Self::thumbprint(self)
    }
}

impl Signer for Ps256Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, ProofError> {
        // `RSASSA-PSS` needs fresh randomness for both the salt and the RSA
        // base blinding, so a missing entropy source is an error rather than a
        // weaker signature.
        let mut rng = getrandom::SysRng;
        self.inner
            .try_sign_with_rng(&mut rng, data)
            .map(|s| s.to_vec())
            .map_err(|e| ProofError::Signing(format!("PS256 signature: {e}")))
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn algorithm(&self) -> &'static str {
        "PS256"
    }
}

/// An RSA public key used with `PS256`.
#[derive(Clone)]
pub struct Ps256Verifier {
    inner: VerifyingKey<Sha256>,
    key_id: Option<String>,
}

impl Ps256Verifier {
    /// SHA-256 JWK thumbprint (RFC 7638), independent of `kid` and algorithm metadata.
    #[must_use]
    pub fn thumbprint(&self) -> String {
        thumbprint(self.inner.as_ref())
    }

    /// Size of the RSA modulus, for profiles that constrain key strength.
    #[must_use]
    pub fn modulus_bits(&self) -> usize {
        self.inner.as_ref().n().bit_width() as usize
    }

    /// Imports a public RSA JWK for GNAP's PS256 HTTP signatures.
    ///
    /// GNAP requires `alg` and `kid` ([RFC 9635 §7.1]); this path requires
    /// `alg: PS256`, `kty: RSA` and a nonempty `kid` of at most 1024 bytes.
    /// The imported `kid` becomes the exact expected HTTP signature `keyid`.
    ///
    /// RSA integers must use canonical, unpadded `Base64urlUInt` encoding
    /// ([RFC 7518 §6.3.1]). Moduli must be 2048–4096 bits, odd, and larger
    /// than the odd exponent (3 through 2³³−1, the `rsa` backend's limit).
    /// The upper bounds are implementation limits, not GNAP requirements.
    /// These structural checks do not prove that a modulus has two prime
    /// factors or that the sender owns the private key: verify the request.
    ///
    /// If present, `use` must be `sig`; `key_ops` must include `verify`,
    /// contain no duplicates or known encryption/derivation operations, and
    /// have at most 32 entries of at most 1024 bytes. `sign` alongside `verify`
    /// is permitted by RFC 7517 §4.3; it grants this verifier no signing ability.
    /// Unknown operation names alongside `verify` and unknown JWK members are
    /// ignored. Private key parameters are rejected, even when null.
    ///
    /// Certificate parameters (`x5c`, `x5u`, `x5t`, `x5t#S256`) are not
    /// supported by this bare-key adapter and are rejected. It does not fetch
    /// keys or establish certificate trust, client identity or authorization.
    /// Callers must bound the enclosing JSON before parsing; this method limits
    /// only the members it processes, before decoding or RSA construction.
    ///
    /// [RFC 9635 §7.1]: https://www.rfc-editor.org/rfc/rfc9635.html#section-7.1
    /// [RFC 7518 §6.3.1]: https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.1
    ///
    /// # Errors
    ///
    /// Returns [`ProofError::Key`] for unsupported metadata, private material,
    /// malformed integers or an RSA key outside the constraints above.
    pub fn from_public_jwk(jwk: &Map<String, Value>) -> Result<Self, ProofError> {
        if jwk::string(jwk, "kty")? != "RSA" || jwk::string(jwk, "alg")? != "PS256" {
            return Err(jwk::error("expected kty RSA and alg PS256"));
        }
        let key_id = jwk::common(jwk, &["d", "p", "q", "dp", "dq", "qi", "oth", "k"])?;
        let n = jwk_uint(jwk, "n", MAX_MODULUS_BITS / 8)?;
        let e = jwk_uint(jwk, "e", MAX_EXPONENT_BYTES)?;
        let public = PublicKey::new(n, e).map_err(|error| jwk::error(&error.to_string()))?;
        check_modulus_bits(public.n().bit_width() as usize)?;
        Ok(Self {
            inner: VerifyingKey::<Sha256>::from(public),
            key_id: Some(key_id.into()),
        })
    }

    /// Loads a public key in `BEGIN PUBLIC KEY` format.
    ///
    /// The key carries no identity of its own, so the `keyid` a signature
    /// presents is not checked against anything; see [`Self::with_key_id`].
    ///
    /// # Errors
    ///
    /// Fails when the PEM cannot be read as an RSA public key.
    pub fn from_public_key_pem(pem: &str) -> Result<Self, ProofError> {
        let pk = PublicKey::from_public_key_pem(pem).map_err(|e| ProofError::Key(e.to_string()))?;
        check_modulus_bits(pk.n().bit_width() as usize)?;
        Ok(Self {
            inner: VerifyingKey::<Sha256>::from(pk),
            key_id: None,
        })
    }

    /// Names the key, so a signature has to claim that identity (§7.3.1).
    ///
    /// Pass the JWK's `kid` when the client presented its key as a JWK: §7.3.1
    /// then requires the signature's `keyid` to be exactly that value.
    #[must_use]
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Self {
        self.key_id = Some(key_id.into());
        self
    }
}

impl Verifier for Ps256Verifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), ProofError> {
        let sig = Signature::try_from(signature)
            .map_err(|e| ProofError::Verification(format!("unreadable signature: {e}")))?;
        self.inner
            .verify(data, &sig)
            .map_err(|e| ProofError::Verification(e.to_string()))
    }

    fn algorithm(&self) -> &'static str {
        "PS256"
    }

    fn expected_key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }
}

/// Smallest RSA modulus, in bits, that this profile accepts for any key.
pub const MIN_MODULUS_BITS: usize = 2048;

/// Largest RSA modulus, in bits, that this profile accepts for any key.
///
/// This is the project's own bound, not the `rsa` crate's `MAX_SIZE`: that
/// constant moved from 4096 to 8192 in rsa 0.10, so borrowing it would have
/// silently widened what this profile accepts.
pub const MAX_MODULUS_BITS: usize = 4096;

/// Longest public exponent, in bytes: the `rsa` backend accepts at most 2³³−1.
const MAX_EXPONENT_BYTES: usize = 5;

fn check_modulus_bits(bits: usize) -> Result<(), ProofError> {
    if (MIN_MODULUS_BITS..=MAX_MODULUS_BITS).contains(&bits) {
        Ok(())
    } else {
        Err(ProofError::Key(format!(
            "RSA modulus must contain {MIN_MODULUS_BITS}–{MAX_MODULUS_BITS} bits"
        )))
    }
}

fn jwk_uint(
    jwk: &Map<String, Value>,
    field: &str,
    max_bytes: usize,
) -> Result<BoxedUint, ProofError> {
    let encoded = jwk::string(jwk, field)?;
    if encoded.is_empty() || encoded.len() > (max_bytes * 8).div_ceil(6) {
        return Err(jwk::error(&format!(
            "{field} has an unsupported encoded size"
        )));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| jwk::error(&format!("{field} must be unpadded base64url")))?;
    if bytes.first() == Some(&0) || bytes.len() > max_bytes {
        return Err(jwk::error(&format!(
            "{field} must be a minimal positive integer"
        )));
    }
    Ok(BoxedUint::from_be_slice_vartime(&bytes))
}

fn thumbprint(key: &PublicKey) -> String {
    let e = URL_SAFE_NO_PAD.encode(key.e().to_be_bytes_trimmed_vartime());
    let n = URL_SAFE_NO_PAD.encode(key.n().to_be_bytes_trimmed_vartime());
    jwk::thumbprint(&[("e", &e), ("kty", "RSA"), ("n", &n)])
}

#[cfg(test)]
mod thumbprint_tests {
    use super::*;

    #[test]
    fn rfc7638_section_3_1() {
        // Public RSA numbers from RFC 7638 §3.1; RS256 metadata in that
        // example is irrelevant to the thumbprint, not a PS256 import policy.
        let n = concat!(
            "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt",
            "VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6",
            "4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD",
            "W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9",
            "1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH",
            "aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
        );
        let key = PublicKey::new(
            BoxedUint::from_be_slice_vartime(&URL_SAFE_NO_PAD.decode(n).unwrap()),
            BoxedUint::from(65537_u32),
        )
        .unwrap();
        assert_eq!(
            thumbprint(&key),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }
}
