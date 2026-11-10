//! The RSA keys of the RSA signature schemes: bounds, PEM and JWK import, JWK
//! export, and thumbprint. Each scheme keeps only its signature padding.

use crate::jwk;
use crate::proof::ProofError;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::traits::PublicKeyParts;
use rsa::{BoxedUint, PrivateKey, PublicKey};
use serde_json::{Map, Value};

/// Smallest RSA modulus, in bits, that this crate accepts for any key.
pub const MIN_MODULUS_BITS: usize = 2048;

/// Largest RSA modulus, in bits, that this crate accepts for any key.
///
/// This is the project's own bound, not the `rsa` crate's `MAX_SIZE`: that
/// constant moved from 4096 to 8192 in rsa 0.10, so borrowing it would have
/// silently widened what this crate accepts.
pub const MAX_MODULUS_BITS: usize = 4096;

/// Longest public exponent, in bytes: the `rsa` backend accepts at most 2³³−1.
const MAX_EXPONENT_BYTES: usize = 5;

pub(crate) fn check_modulus_bits(bits: usize) -> Result<(), ProofError> {
    if (MIN_MODULUS_BITS..=MAX_MODULUS_BITS).contains(&bits) {
        Ok(())
    } else {
        Err(ProofError::Key(format!(
            "RSA modulus must contain {MIN_MODULUS_BITS}–{MAX_MODULUS_BITS} bits"
        )))
    }
}

/// The size of a public key's modulus, in bits.
pub(crate) fn modulus_bits(key: &PublicKey) -> usize {
    key.n().bit_width() as usize
}

/// A private key whose modulus is within the bounds.
fn bounded(key: PrivateKey) -> Result<PrivateKey, ProofError> {
    check_modulus_bits(modulus_bits(&key.to_public_key()))?;
    Ok(key)
}

/// Loads a PKCS#8 private key, `BEGIN PRIVATE KEY` format.
pub(crate) fn from_pkcs8_pem(pem: &str) -> Result<PrivateKey, ProofError> {
    bounded(PrivateKey::from_pkcs8_pem(pem).map_err(|e| ProofError::Key(e.to_string()))?)
}

/// Loads a PKCS#1 private key, `BEGIN RSA PRIVATE KEY` format.
pub(crate) fn from_pkcs1_pem(pem: &str) -> Result<PrivateKey, ProofError> {
    bounded(PrivateKey::from_pkcs1_pem(pem).map_err(|e| ProofError::Key(e.to_string()))?)
}

/// Generates a key of `bits` bits from the operating system's random source.
pub(crate) fn generate(bits: usize) -> Result<PrivateKey, ProofError> {
    check_modulus_bits(bits)?;
    PrivateKey::new(&mut getrandom::SysRng, bits)
        .map_err(|e| ProofError::Key(format!("generation: {e}")))
}

/// Loads a public key in `BEGIN PUBLIC KEY` format.
pub(crate) fn public_from_pem(pem: &str) -> Result<PublicKey, ProofError> {
    let key = PublicKey::from_public_key_pem(pem).map_err(|e| ProofError::Key(e.to_string()))?;
    check_modulus_bits(modulus_bits(&key))?;
    Ok(key)
}

/// Imports a public RSA JWK whose `alg` is `alg`, and returns it with its `kid`.
///
/// RSA integers must use canonical, unpadded `Base64urlUInt` encoding
/// ([RFC 7518 §6.3.1]); the modulus must be within the bounds, odd, and
/// larger than the odd exponent. These structural checks don't prove that a
/// modulus has two prime factors or that the sender owns the private key.
///
/// [RFC 7518 §6.3.1]: https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.1
pub(crate) fn public_from_jwk(
    jwk: &Map<String, Value>,
    alg: &str,
) -> Result<(PublicKey, String), ProofError> {
    if jwk::string(jwk, "kty")? != "RSA" || jwk::string(jwk, "alg")? != alg {
        return Err(jwk::error(&format!("expected kty RSA and alg {alg}")));
    }
    let key_id = jwk::common(jwk)?;
    let n = uint(jwk, "n", MAX_MODULUS_BITS / 8)?;
    let e = uint(jwk, "e", MAX_EXPONENT_BYTES)?;
    let public = PublicKey::new(n, e).map_err(|error| jwk::error(&error.to_string()))?;
    check_modulus_bits(modulus_bits(&public))?;
    Ok((public, key_id.into()))
}

/// The public JWK of `key`, with its `alg` and `kid`, and `key_ops: [verify]`.
pub(crate) fn public_jwk(
    key: &PublicKey,
    alg: &str,
    key_id: &str,
) -> Result<Map<String, Value>, ProofError> {
    jwk::validate_key_id(key_id)?;
    Ok(Map::from_iter([
        ("kty".into(), Value::String("RSA".into())),
        (
            "n".into(),
            Value::String(URL_SAFE_NO_PAD.encode(key.n().to_be_bytes_trimmed_vartime())),
        ),
        (
            "e".into(),
            Value::String(URL_SAFE_NO_PAD.encode(key.e().to_be_bytes_trimmed_vartime())),
        ),
        ("alg".into(), Value::String(alg.into())),
        ("kid".into(), Value::String(key_id.into())),
        ("key_ops".into(), serde_json::json!(["verify"])),
    ]))
}

/// The SHA-256 JWK thumbprint of an RSA key (RFC 7638).
pub(crate) fn thumbprint(key: &PublicKey) -> String {
    let e = URL_SAFE_NO_PAD.encode(key.e().to_be_bytes_trimmed_vartime());
    let n = URL_SAFE_NO_PAD.encode(key.n().to_be_bytes_trimmed_vartime());
    jwk::thumbprint(&[("e", &e), ("kty", "RSA"), ("n", &n)])
}

fn uint(jwk: &Map<String, Value>, field: &str, max_bytes: usize) -> Result<BoxedUint, ProofError> {
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
