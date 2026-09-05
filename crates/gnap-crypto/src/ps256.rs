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
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::pss::{BlindedSigningKey, Signature, VerifyingKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier as _};
use rsa::{RsaPrivateKey, RsaPublicKey};
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
