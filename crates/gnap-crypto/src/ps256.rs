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

use crate::proof::{ProofError, Signer, Verifier};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::pss::{BlindedSigningKey, Signature, VerifyingKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier as _};
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use serde_json::{Map, Value};
use sha2::Sha256;

/// An RSA private key used with `PS256`.
pub struct Ps256Signer {
    inner: BlindedSigningKey<Sha256>,
    public: RsaPublicKey,
    key_id: String,
}

impl Ps256Signer {
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
        let sk = RsaPrivateKey::from_pkcs8_pem(pem).map_err(|e| ProofError::Key(e.to_string()))?;
        Ok(Self::from_key(sk, key_id))
    }

    /// Loads a PKCS#1 private key, `BEGIN RSA PRIVATE KEY` format.
    /// # Errors
    ///
    /// Fails when the PEM cannot be read as a PKCS#1 RSA private key.
    pub fn from_pkcs1_pem(pem: &str, key_id: impl Into<String>) -> Result<Self, ProofError> {
        let sk = RsaPrivateKey::from_pkcs1_pem(pem).map_err(|e| ProofError::Key(e.to_string()))?;
        Ok(Self::from_key(sk, key_id))
    }

    /// Generates a fresh RSA key.
    ///
    /// Meant for tests and examples: a production key is managed elsewhere, and
    /// §11.5 is a reminder that protecting it is a deployment concern.
    /// # Errors
    ///
    /// Fails when key generation does, which in practice means the random
    /// source is unavailable or `bits` is too small.
    pub fn generate(bits: usize, key_id: impl Into<String>) -> Result<Self, ProofError> {
        let mut rng = OsRng;
        let sk = RsaPrivateKey::new(&mut rng, bits)
            .map_err(|e| ProofError::Key(format!("generation: {e}")))?;
        Ok(Self::from_key(sk, key_id))
    }

    fn from_key(sk: RsaPrivateKey, key_id: impl Into<String>) -> Self {
        let public = sk.to_public_key();
        Self {
            inner: BlindedSigningKey::<Sha256>::new(sk),
            public,
            key_id: key_id.into(),
        }
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
    /// Fails if the key falls outside [`Ps256Verifier::from_public_jwk`]'s
    /// supported size or identifier limits. Existing PEM constructors do not
    /// enforce those JWK import/export limits.
    pub fn public_jwk(&self) -> Result<Map<String, Value>, ProofError> {
        validate_key_id(&self.key_id)?;
        validate_public_size(&self.public)?;
        Ok(Map::from_iter([
            ("kty".into(), Value::String("RSA".into())),
            (
                "n".into(),
                Value::String(URL_SAFE_NO_PAD.encode(self.public.n().to_bytes_be())),
            ),
            (
                "e".into(),
                Value::String(URL_SAFE_NO_PAD.encode(self.public.e().to_bytes_be())),
            ),
            ("alg".into(), Value::String("PS256".into())),
            ("kid".into(), Value::String(self.key_id.clone())),
            ("key_ops".into(), serde_json::json!(["verify"])),
        ]))
    }
}

impl Signer for Ps256Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, ProofError> {
        let mut rng = OsRng;
        Ok(self.inner.sign_with_rng(&mut rng, data).to_vec())
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn algorithm(&self) -> &'static str {
        "PS256"
    }
}

/// An RSA public key used with `PS256`.
pub struct Ps256Verifier {
    inner: VerifyingKey<Sha256>,
    key_id: Option<String>,
}

impl Ps256Verifier {
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
        if jwk_string(jwk, "kty")? != "RSA" || jwk_string(jwk, "alg")? != "PS256" {
            return Err(jwk_error("expected kty RSA and alg PS256"));
        }
        let key_id = jwk_string(jwk, "kid")?;
        validate_key_id(key_id)?;
        for field in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
            if jwk.contains_key(field) {
                return Err(jwk_error("private key parameters are not accepted"));
            }
        }
        for field in ["x5c", "x5u", "x5t", "x5t#S256"] {
            if jwk.contains_key(field) {
                return Err(jwk_error(
                    "certificate parameters need a certificate-aware adapter",
                ));
            }
        }
        validate_jwk_usage(jwk)?;
        let n = jwk_uint(jwk, "n", RsaPublicKey::MAX_SIZE / 8)?;
        let e = jwk_uint(jwk, "e", 5)?;
        let public =
            RsaPublicKey::new(n, e).map_err(|error| ProofError::Key(format!("JWK: {error}")))?;
        validate_public_size(&public)?;
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
        let pk =
            RsaPublicKey::from_public_key_pem(pem).map_err(|e| ProofError::Key(e.to_string()))?;
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

fn jwk_error(message: &str) -> ProofError {
    ProofError::Key(format!("JWK: {message}"))
}

fn jwk_string<'a>(jwk: &'a Map<String, Value>, field: &str) -> Result<&'a str, ProofError> {
    jwk.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| jwk_error(&format!("{field} must be a string")))
}

fn validate_key_id(key_id: &str) -> Result<(), ProofError> {
    if key_id.is_empty() || key_id.len() > 1024 {
        return Err(jwk_error("kid must contain 1–1024 bytes"));
    }
    Ok(())
}

fn validate_public_size(public: &RsaPublicKey) -> Result<(), ProofError> {
    if !(2048..=RsaPublicKey::MAX_SIZE).contains(&public.n().bits()) {
        return Err(jwk_error("RSA modulus must contain 2048–4096 bits"));
    }
    Ok(())
}

fn jwk_uint(
    jwk: &Map<String, Value>,
    field: &str,
    max_bytes: usize,
) -> Result<BigUint, ProofError> {
    let encoded = jwk_string(jwk, field)?;
    if encoded.is_empty() || encoded.len() > (max_bytes * 8).div_ceil(6) {
        return Err(jwk_error(&format!(
            "{field} has an unsupported encoded size"
        )));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| jwk_error(&format!("{field} must be unpadded base64url")))?;
    if bytes.first() == Some(&0) || bytes.len() > max_bytes {
        return Err(jwk_error(&format!(
            "{field} must be a minimal positive integer"
        )));
    }
    Ok(BigUint::from_bytes_be(&bytes))
}

fn validate_jwk_usage(jwk: &Map<String, Value>) -> Result<(), ProofError> {
    if jwk.contains_key("use") && jwk_string(jwk, "use")? != "sig" {
        return Err(jwk_error("use must be sig for signature verification"));
    }
    let Some(operations) = jwk.get("key_ops") else {
        return Ok(());
    };
    let operations = operations
        .as_array()
        .ok_or_else(|| jwk_error("key_ops must be an array"))?;
    if operations.len() > 32 {
        return Err(jwk_error("key_ops exceeds the 32-operation limit"));
    }
    let mut seen = std::collections::HashSet::new();
    for operation in operations {
        let operation = operation
            .as_str()
            .ok_or_else(|| jwk_error("key_ops entries must be strings"))?;
        if operation.len() > 1024 || !seen.insert(operation) {
            return Err(jwk_error(
                "key_ops contains a duplicate or oversized operation",
            ));
        }
        if matches!(
            operation,
            "encrypt" | "decrypt" | "wrapKey" | "unwrapKey" | "deriveKey" | "deriveBits"
        ) {
            return Err(jwk_error("key_ops includes an incompatible operation"));
        }
    }
    if !seen.contains("verify") {
        return Err(jwk_error("key_ops does not permit verification"));
    }
    Ok(())
}

/// The OS randomness source, adapted to the interface the `rsa` crate expects.
///
/// `RSASSA-PSS` needs a fresh random salt on every signature.
struct OsRng;

impl rsa::rand_core::RngCore for OsRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::getrandom(dest).expect("OS randomness source unavailable");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        getrandom::getrandom(dest).map_err(|e| rsa::rand_core::Error::new(e.to_string()))
    }
}

impl rsa::rand_core::CryptoRng for OsRng {}
