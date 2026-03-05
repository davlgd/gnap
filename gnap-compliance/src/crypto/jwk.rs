/// JWK (JSON Web Key) utilities — RFC 7517, used by RFC 9635 Section 7.1
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::types::ComplianceError;

/// An Ed25519 JSON Web Key.
/// This is the primary key type used in GNAP (RFC 9635 Section 7.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519Jwk {
    pub kty: String,
    pub crv: String,
    pub alg: String,
    pub x: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
}

impl Ed25519Jwk {
    /// Create a JWK from an Ed25519 verifying (public) key.
    pub fn from_verifying_key(key: &VerifyingKey, kid: Option<String>) -> Self {
        Self {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            alg: "EdDSA".to_string(),
            x: URL_SAFE_NO_PAD.encode(key.as_bytes()),
            kid,
            use_: Some("sig".to_string()),
        }
    }

    /// Create a JWK from a signing (private) key, exposing only the public part.
    pub fn from_signing_key(key: &SigningKey, kid: Option<String>) -> Self {
        Self::from_verifying_key(&key.verifying_key(), kid)
    }

    /// Extract the verifying key from this JWK.
    pub fn to_verifying_key(&self) -> Result<VerifyingKey, ComplianceError> {
        self.validate()?;
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.x)
            .map_err(|e| ComplianceError::Crypto(format!("Invalid base64url in JWK x: {e}")))?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            ComplianceError::Crypto("JWK x field must be exactly 32 bytes for Ed25519".to_string())
        })?;
        VerifyingKey::from_bytes(&bytes)
            .map_err(|e| ComplianceError::Crypto(format!("Invalid Ed25519 public key: {e}")))
    }

    /// Validate this JWK structure for GNAP compliance.
    /// RFC 9635 Section 7.1: A JWK MUST contain alg and kid. alg MUST NOT be "none".
    pub fn validate(&self) -> Result<(), ComplianceError> {
        if self.kty != "OKP" {
            return Err(ComplianceError::Validation(format!(
                "Expected kty=\"OKP\", got \"{}\"",
                self.kty
            )));
        }
        if self.crv != "Ed25519" {
            return Err(ComplianceError::Validation(format!(
                "Expected crv=\"Ed25519\", got \"{}\"",
                self.crv
            )));
        }
        if self.x.is_empty() {
            return Err(ComplianceError::Validation(
                "JWK x field must not be empty".to_string(),
            ));
        }
        if self.alg == "none" {
            return Err(ComplianceError::Validation(
                "JWK alg must not be \"none\" (Section 7.1)".to_string(),
            ));
        }
        if self.alg != "EdDSA" {
            return Err(ComplianceError::Validation(format!(
                "Expected alg=\"EdDSA\" for OKP/Ed25519, got \"{}\"",
                self.alg
            )));
        }
        if self.kid.is_none() {
            return Err(ComplianceError::Validation(
                "JWK kid is required for GNAP (Section 7.1)".to_string(),
            ));
        }
        Ok(())
    }

    /// Serialize as a JWKS (JSON Web Key Set) containing this single key.
    pub fn to_jwks_json(&self) -> String {
        serde_json::json!({ "keys": [self] }).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_test_key() -> SigningKey {
        SigningKey::generate(&mut rand::rngs::OsRng)
    }

    #[test]
    fn jwk_from_signing_key_roundtrip() {
        let signing_key = generate_test_key();
        let jwk = Ed25519Jwk::from_signing_key(&signing_key, Some("test-kid".to_string()));

        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, "Ed25519");
        assert_eq!(jwk.alg, "EdDSA");
        assert_eq!(jwk.kid.as_deref(), Some("test-kid"));

        let recovered = jwk.to_verifying_key().unwrap();
        assert_eq!(recovered, signing_key.verifying_key());
    }

    #[test]
    fn jwk_validation_rejects_bad_kty() {
        let jwk = Ed25519Jwk {
            kty: "EC".to_string(),
            crv: "Ed25519".to_string(),
            alg: "EdDSA".to_string(),
            x: "AAAA".to_string(),
            kid: Some("k1".to_string()),
            use_: None,
        };
        assert!(jwk.validate().is_err());
    }

    #[test]
    fn jwk_validation_rejects_empty_x() {
        let jwk = Ed25519Jwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            alg: "EdDSA".to_string(),
            x: "".to_string(),
            kid: Some("k1".to_string()),
            use_: None,
        };
        assert!(jwk.validate().is_err());
    }

    #[test]
    fn jwk_validation_rejects_missing_kid() {
        let jwk = Ed25519Jwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            alg: "EdDSA".to_string(),
            x: "AAAA".to_string(),
            kid: None,
            use_: None,
        };
        assert!(jwk.validate().is_err());
    }

    #[test]
    fn jwk_validation_rejects_alg_none() {
        let jwk = Ed25519Jwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            alg: "none".to_string(),
            x: "AAAA".to_string(),
            kid: Some("k1".to_string()),
            use_: None,
        };
        assert!(jwk.validate().is_err());
    }

    #[test]
    fn jwks_serialization() {
        let signing_key = generate_test_key();
        let jwk = Ed25519Jwk::from_signing_key(&signing_key, Some("k1".to_string()));
        let jwks = jwk.to_jwks_json();
        let parsed: serde_json::Value = serde_json::from_str(&jwks).unwrap();
        assert!(parsed["keys"].is_array());
        assert_eq!(parsed["keys"].as_array().unwrap().len(), 1);
    }
}
