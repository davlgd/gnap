//! Interaction hash — RFC 9635 §4.2.3.
//!
//! The hash ties the interaction-finish callback back to the pending request by
//! combining values only the two parties know. §4.2.3 requires it on both
//! sides: the AS always supplies it, the client always validates it, and a
//! client that cannot validate it must not pass the interaction reference on to
//! the AS (§4.2.1).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use core::fmt;
use sha2::Digest;
use subtle::ConstantTimeEq;

/// An algorithm from the IANA "Named Information Hash Algorithm" registry.
///
/// Watch out for the trap: GNAP's `hash_method` field uses that registry's
/// names — `sha-256`, `sha3-512` — not the JOSE ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HashMethod {
    /// `sha-256`. The default, and the only one required by both
    /// interoperability profiles of Appendix C.
    Sha256,
    /// `sha-384`.
    Sha384,
    /// `sha-512`.
    Sha512,
    /// `sha3-224`.
    Sha3_224,
    /// `sha3-256`.
    Sha3_256,
    /// `sha3-384`.
    Sha3_384,
    /// `sha3-512`.
    Sha3_512,
}

impl HashMethod {
    /// The algorithm applied when the client names none (§4.2.3).
    pub const DEFAULT: Self = Self::Sha256;

    /// The IANA registry name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha-256",
            Self::Sha384 => "sha-384",
            Self::Sha512 => "sha-512",
            Self::Sha3_224 => "sha3-224",
            Self::Sha3_256 => "sha3-256",
            Self::Sha3_384 => "sha3-384",
            Self::Sha3_512 => "sha3-512",
        }
    }

    /// Resolves a registry name.
    ///
    /// Returns `None` for a name that is valid but unsupported here: the
    /// truncated variants (`sha-256-128`) and the BLAKE2 family are not covered.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "sha-256" => Self::Sha256,
            "sha-384" => Self::Sha384,
            "sha-512" => Self::Sha512,
            "sha3-224" => Self::Sha3_224,
            "sha3-256" => Self::Sha3_256,
            "sha3-384" => Self::Sha3_384,
            "sha3-512" => Self::Sha3_512,
            _ => return None,
        })
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(data).to_vec(),
            Self::Sha3_224 => sha3::Sha3_224::digest(data).to_vec(),
            Self::Sha3_256 => sha3::Sha3_256::digest(data).to_vec(),
            Self::Sha3_384 => sha3::Sha3_384::digest(data).to_vec(),
            Self::Sha3_512 => sha3::Sha3_512::digest(data).to_vec(),
        }
    }
}

impl fmt::Display for HashMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What prevents an interaction hash from being computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashError {
    /// The algorithm name is not supported by this library.
    UnsupportedMethod(String),
    /// One of the four values contains a newline, which would make the hash
    /// base ambiguous since a newline is the separator.
    NewlineInInput(&'static str),
    /// One of the four values is not ASCII, and §4.2.3 hashes the ASCII
    /// encoding of the base.
    NotAscii(&'static str),
}

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedMethod(m) => write!(
                f,
                "hash_method `{m}`: unsupported. Names come from the IANA \
                 \"Named Information Hash Algorithm\" registry (RFC 9635 §4.2.3)"
            ),
            Self::NewlineInInput(which) => write!(
                f,
                "{which} contains a newline; that is the separator of the hash base, \
                 so the value would be ambiguous (RFC 9635 §4.2.3)"
            ),
            Self::NotAscii(which) => write!(
                f,
                "{which} is not ASCII; §4.2.3 hashes the ASCII encoding of the base, \
                 which this value has no way of producing (RFC 9635 §4.2.3)"
            ),
        }
    }
}

impl std::error::Error for HashError {}

/// The four values that feed the hash, in the order given by §4.2.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteractionHashInput<'a> {
    /// The nonce the client sent in `interact.finish.nonce` (§2.5.2).
    pub client_nonce: &'a str,
    /// The nonce the AS returned in `interact.finish` (§3.3.5).
    pub as_nonce: &'a str,
    /// The interaction reference conveyed to the callback (§4.2).
    pub interact_ref: &'a str,
    /// The grant endpoint URI used for the initial request (§2).
    pub grant_endpoint: &'a str,
}

impl InteractionHashInput<'_> {
    /// Builds the hash base: the four values joined by a single newline.
    ///
    /// No whitespace and no trailing newline, as §4.2.3 requires.
    /// # Errors
    ///
    /// Fails when one of the four values contains a newline, which is the
    /// separator: the base would be ambiguous.
    pub fn base(&self) -> Result<String, HashError> {
        for (v, which) in [
            (self.client_nonce, "interact.finish.nonce"),
            (self.as_nonce, "the AS nonce"),
            (self.interact_ref, "interact_ref"),
            (self.grant_endpoint, "the grant endpoint URI"),
        ] {
            // §4.2.3 hashes "the ASCII encoding" of the base. A value outside
            // ASCII has no such encoding, so there is no hash both sides would
            // agree on: hashing its UTF-8 bytes instead would quietly invent
            // one. All four values are constrained elsewhere — the nonces and
            // the reference to unreserved characters, the URI to a URI — so
            // this refuses input that was already out of bounds.
            if !v.is_ascii() {
                return Err(HashError::NotAscii(which));
            }
            if v.contains('\n') {
                return Err(HashError::NewlineInInput(which));
            }
        }
        Ok(format!(
            "{}\n{}\n{}\n{}",
            self.client_nonce, self.as_nonce, self.interact_ref, self.grant_endpoint
        ))
    }
}

/// Computes the interaction hash (§4.2.3).
///
/// The base is hashed over its ASCII encoding and the result is encoded with
/// URL-safe base64 without padding.
///
/// ```
/// use gnap_crypto::hash::{interaction_hash, HashMethod, InteractionHashInput};
///
/// // Test vector from RFC 9635 §4.2.3.
/// let input = InteractionHashInput {
///     client_nonce: "VJLO6A4CATR0KRO",
///     as_nonce: "MBDOFXG4Y5CVJCX821LH",
///     interact_ref: "4IFWWIKYB2PQ6U56NL1",
///     grant_endpoint: "https://server.example.com/tx",
/// };
/// assert_eq!(
///     interaction_hash(&input, HashMethod::Sha256).unwrap(),
///     "x-gguKWTj8rQf7d7i3w3UhzvuJ5bpOlKyAlVpLxBffY"
/// );
/// ```
/// # Errors
///
/// Fails when [`InteractionHashInput::base`] does.
pub fn interaction_hash(
    input: &InteractionHashInput<'_>,
    method: HashMethod,
) -> Result<String, HashError> {
    let base = input.base()?;
    Ok(URL_SAFE_NO_PAD.encode(method.digest(base.as_bytes())))
}

/// Computes the hash, resolving the name carried by the `hash_method` field.
///
/// `None` selects the default algorithm, `sha-256` (§4.2.3).
/// # Errors
///
/// Fails when the name is not one this library supports, or when
/// [`InteractionHashInput::base`] fails.
pub fn interaction_hash_named(
    input: &InteractionHashInput<'_>,
    method_name: Option<&str>,
) -> Result<String, HashError> {
    let method = match method_name {
        None => HashMethod::DEFAULT,
        Some(n) => {
            HashMethod::from_name(n).ok_or_else(|| HashError::UnsupportedMethod(n.to_owned()))?
        }
    };
    interaction_hash(input, method)
}

/// Verifies a received hash, in constant time.
///
/// §4.2.1 is explicit: if the hash does not validate, the client **must not**
/// send the interaction reference to the AS.
/// # Errors
///
/// Fails when the expected hash cannot be computed. A hash that simply does
/// not match is `Ok(false)`, not an error.
pub fn verify_interaction_hash(
    input: &InteractionHashInput<'_>,
    method: HashMethod,
    received: &str,
) -> Result<bool, HashError> {
    let expected = interaction_hash(input, method)?;
    // The value is public, but an early-exit comparison is not a habit worth
    // picking up on an authentication path.
    Ok(expected.as_bytes().ct_eq(received.as_bytes()).into())
}
