/// Interaction hash computation — RFC 9635 Section 4.2.3
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256, Sha512};

/// Compute the interaction hash for finish callback verification.
///
/// The hash is computed as:
///   hash = BASE64URL(SHA-256(nonce + "\n" + server_nonce + "\n" + interact_ref + "\n" + grant_endpoint))
///
/// RFC 9635 Section 4.2.3
pub fn compute_interaction_hash(
    client_nonce: &str,
    server_nonce: &str,
    interact_ref: &str,
    grant_endpoint: &str,
    hash_method: HashMethod,
) -> String {
    let input = format!("{client_nonce}\n{server_nonce}\n{interact_ref}\n{grant_endpoint}");

    match hash_method {
        HashMethod::Sha256 => {
            let digest = Sha256::digest(input.as_bytes());
            URL_SAFE_NO_PAD.encode(digest)
        }
        HashMethod::Sha512 => {
            let digest = Sha512::digest(input.as_bytes());
            URL_SAFE_NO_PAD.encode(digest)
        }
    }
}

/// Hash methods supported for interaction hash.
/// RFC 9635 Section 4.2.3
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashMethod {
    /// SHA-256 (default per RFC 9635).
    Sha256,
    /// SHA-512.
    Sha512,
}

impl HashMethod {
    /// Parse a hash method from its IANA Named Information Hash Algorithm Registry name.
    /// RFC 9635 Section 4.2.3: values MUST be from the IANA registry.
    pub fn from_str_rfc(s: &str) -> Option<Self> {
        match s {
            "sha-256" => Some(Self::Sha256),
            "sha-512" => Some(Self::Sha512),
            _ => None,
        }
    }
}

/// Content-Digest algorithms for RFC 9530.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Sha256,
    Sha512,
}

/// Compute a content digest for HTTP request bodies.
///
/// Returns the digest in the format: `sha-256=:BASE64(digest):` or `sha-512=:BASE64(digest):`
/// as specified for Content-Digest header (RFC 9530).
pub fn compute_content_digest(body: &[u8], algorithm: DigestAlgorithm) -> String {
    let (name, encoded) = match algorithm {
        DigestAlgorithm::Sha256 => {
            ("sha-256", base64::engine::general_purpose::STANDARD.encode(Sha256::digest(body)))
        }
        DigestAlgorithm::Sha512 => {
            ("sha-512", base64::engine::general_purpose::STANDARD.encode(Sha512::digest(body)))
        }
    };
    format!("{name}=:{encoded}:")
}

/// Convenience: compute SHA-256 content digest.
pub fn compute_content_digest_sha256(body: &[u8]) -> String {
    compute_content_digest(body, DigestAlgorithm::Sha256)
}

/// Convenience: compute SHA-512 content digest.
pub fn compute_content_digest_sha512(body: &[u8]) -> String {
    compute_content_digest(body, DigestAlgorithm::Sha512)
}

/// Verify a Content-Digest header value against a body.
///
/// Parses the `algorithm=:base64:` format per RFC 9530 and recomputes the digest.
/// RFC 9635 Section 7.3.1: the verifier MUST validate this field value.
pub fn verify_content_digest(
    header_value: &str,
    body: &[u8],
) -> Result<(), crate::types::ComplianceError> {
    let (algo_str, _) = header_value
        .split_once("=:")
        .ok_or_else(|| crate::types::ComplianceError::Validation(
            "Invalid Content-Digest format, expected algorithm=:base64:".to_string(),
        ))?;
    let algorithm = match algo_str {
        "sha-256" => DigestAlgorithm::Sha256,
        "sha-512" => DigestAlgorithm::Sha512,
        other => {
            return Err(crate::types::ComplianceError::Validation(format!(
                "Unsupported Content-Digest algorithm: \"{other}\""
            )));
        }
    };
    let expected = compute_content_digest(body, algorithm);
    if header_value == expected {
        Ok(())
    } else {
        Err(crate::types::ComplianceError::Validation(
            "Content-Digest mismatch".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interaction_hash_deterministic() {
        let hash1 = compute_interaction_hash(
            "client-nonce-1",
            "server-nonce-1",
            "interact-ref-1",
            "https://as.example.com/gnap",
            HashMethod::Sha256,
        );
        let hash2 = compute_interaction_hash(
            "client-nonce-1",
            "server-nonce-1",
            "interact-ref-1",
            "https://as.example.com/gnap",
            HashMethod::Sha256,
        );
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn interaction_hash_varies_with_input() {
        let hash1 = compute_interaction_hash(
            "nonce-a",
            "nonce-b",
            "ref-1",
            "https://as.example.com/gnap",
            HashMethod::Sha256,
        );
        let hash2 = compute_interaction_hash(
            "nonce-a",
            "nonce-b",
            "ref-2",
            "https://as.example.com/gnap",
            HashMethod::Sha256,
        );
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn content_digest_sha512_format() {
        let digest = compute_content_digest_sha512(b"hello");
        assert!(digest.starts_with("sha-512=:"));
        assert!(digest.ends_with(':'));
    }

    #[test]
    fn content_digest_sha256_format() {
        let digest = compute_content_digest_sha256(b"hello");
        assert!(digest.starts_with("sha-256=:"));
        assert!(digest.ends_with(':'));
    }
}
