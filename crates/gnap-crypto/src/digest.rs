//! The `Content-Digest` field — RFC 9530.
//!
//! §7.3.1 of RFC 9635 requires the signer to compute this field and cover it
//! with the signature whenever the request has content, and requires the
//! verifier to validate it. Without it the signature does not protect the body.

use crate::httpsig::{dictionary_members, validate_parameters, SF_BASE64};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use core::fmt;
use sha2::Digest as _;
use subtle::ConstantTimeEq;

/// The digest algorithms supported for `Content-Digest`.
///
/// RFC 9530 registers others; these cover what GNAP uses — `sha-256` is the
/// default for the `httpsig` method in string form (§7.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DigestAlgorithm {
    /// `sha-256`. The default for the `httpsig` method in string form.
    Sha256,
    /// `sha-512`.
    Sha512,
}

impl DigestAlgorithm {
    /// The name used in the field.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha-256",
            Self::Sha512 => "sha-512",
        }
    }

    /// Resolves an algorithm name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "sha-256" => Some(Self::Sha256),
            "sha-512" => Some(Self::Sha512),
            _ => None,
        }
    }

    fn digest(self, content: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => sha2::Sha256::digest(content).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(content).to_vec(),
        }
    }
}

impl fmt::Display for DigestAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Computes the `Content-Digest` field value for some content.
///
/// The output follows Structured Fields syntax: a dictionary whose value is a
/// byte sequence, delimited by colons.
///
/// ```
/// use gnap_crypto::digest::{content_digest, DigestAlgorithm};
///
/// // Body of the test request from RFC 9421, Appendix B.2.
/// let v = content_digest(br#"{"hello": "world"}"#, DigestAlgorithm::Sha512);
/// assert_eq!(
///     v,
///     "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"
/// );
/// ```
#[must_use]
pub fn content_digest(content: &[u8], algorithm: DigestAlgorithm) -> String {
    format!(
        "{}=:{}:",
        algorithm.name(),
        STANDARD.encode(algorithm.digest(content))
    )
}

/// What prevents a received `Content-Digest` from being validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestError {
    /// The value does not have the `algorithm=:value:` shape.
    Malformed(String),
    /// The announced algorithm is not supported.
    UnsupportedAlgorithm(String),
    /// The value is not valid base64.
    NotBase64,
    /// The digest does not match the received content.
    Mismatch {
        /// The algorithm used for the comparison.
        algorithm: &'static str,
    },
}

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(v) => write!(
                f,
                "content-digest: `{v}` does not have the `algorithm=:value:` shape (RFC 9530)"
            ),
            Self::UnsupportedAlgorithm(a) => {
                write!(f, "content-digest: unsupported algorithm `{a}`")
            }
            Self::NotBase64 => write!(f, "content-digest: the value is not valid base64"),
            Self::Mismatch { algorithm } => write!(
                f,
                "content-digest: the {algorithm} digest does not match the content; \
                 the verifier MUST validate this field (RFC 9635 §7.3.1)"
            ),
        }
    }
}

impl std::error::Error for DigestError {}

/// Validates a received `Content-Digest` against the message content.
///
/// RFC 9635 §7.3.1 requires it of the verifier: "If the HTTP message includes content,
/// the verifier MUST calculate and verify the value of the Content-Digest
/// header".
///
/// RFC 9530 §2 defines the field as a Structured Fields Dictionary whose keys
/// name the algorithm and whose values are Byte Sequences. It is read as one
/// (RFC 9651 §4.2.2), not split on commas: a trailing comma or a space before
/// the `=` is not a field, a repeated key denotes its last member, a member may
/// carry parameters, and the base64 may come without padding (§4.2.7).
///
/// A value carrying several digests is accepted when at least one known digest
/// matches; a known digest that does not match is a failure.
/// # Errors
///
/// Fails when the value is not a Dictionary of Byte Sequences, when it carries
/// no algorithm this library supports, or when a supported digest does not
/// match the content.
pub fn verify_content_digest(content: &[u8], header_value: &str) -> Result<(), DigestError> {
    // Every member is parsed, whether or not its algorithm is known and whether
    // or not a later member repeats its key: the Dictionary grammar parses each
    // value, so a field with one unreadable member is not a field. Only then
    // does a repeated key fold to its last member (§4.2.2).
    let mut digests: Vec<(String, Vec<u8>)> = Vec::new();
    for (key, item) in dictionary_members(header_value)
        .map_err(|e| DigestError::Malformed(format!("{header_value} — {e}")))?
    {
        // A Byte Sequence is `:` base64 `:`, then any parameters (§3.3.5).
        let Some((encoded, parameters)) =
            item.strip_prefix(':').and_then(|rest| rest.split_once(':'))
        else {
            return Err(DigestError::Malformed(item));
        };
        validate_parameters(parameters)
            .map_err(|e| DigestError::Malformed(format!("{item} — {e}")))?;
        let received = SF_BASE64
            .decode(encoded)
            .map_err(|_| DigestError::NotBase64)?;
        if let Some(existing) = digests.iter_mut().find(|(k, _)| *k == key) {
            existing.1 = received;
        } else {
            digests.push((key, received));
        }
    }

    let mut seen = false;
    for (algorithm, received) in digests {
        let Some(algorithm) = DigestAlgorithm::from_name(&algorithm) else {
            continue; // unknown algorithm: skip it, another one may match
        };
        seen = true;
        let expected = algorithm.digest(content);
        if !bool::from(received.ct_eq(&expected)) {
            return Err(DigestError::Mismatch {
                algorithm: algorithm.name(),
            });
        }
    }
    if seen {
        Ok(())
    } else {
        Err(DigestError::UnsupportedAlgorithm(header_value.to_owned()))
    }
}
