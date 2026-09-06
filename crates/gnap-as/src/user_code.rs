//! The SDK's bounded, case-insensitive user-code profile (RFC 9635 §3.3).
//!
//! Codes locate requests, not resource owners. The interaction component must
//! authenticate the owner as appropriate, obtain consent and limit attempts.
//! Forty bits of code space are not a replacement for those controls.

use crate::{GrantSnapshot, Nonces, StoreError};
use sha2::{Digest, Sha256};

/// Canonical Crockford base32 symbols, excluding ambiguous letters.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub(crate) struct Configuration<S> {
    pub uri: String,
    pub lookup: fn(&S, &str) -> Result<Option<GrantSnapshot>, StoreError>,
}

/// Normalizes a human-entered code for this SDK's eight-symbol profile.
///
/// Input is limited to 128 UTF-8 bytes before allocation. ASCII case is ignored;
/// O aliases zero and I/L alias one. Other characters outside the alphabet are
/// removed, as RFC 9635 §§4.1.2–4.1.3 require. Exactly eight symbols must remain.
/// This does not authenticate anyone or determine whether a request exists.
#[must_use]
pub fn normalize_user_code(input: &str) -> Option<String> {
    if input.len() > 128 {
        return None;
    }
    let code: String = input
        .bytes()
        .map(|byte| match byte.to_ascii_uppercase() {
            b'O' => b'0',
            b'I' | b'L' => b'1',
            other => other,
        })
        .filter(|byte| ALPHABET.contains(byte))
        .map(char::from)
        .collect();
    is_canonical(&code).then_some(code)
}

pub(crate) fn is_canonical(code: &str) -> bool {
    code.len() == 8 && code.bytes().all(|byte| ALPHABET.contains(&byte))
}

/// A dedicated nonce draw feeds a domain-separated hash, truncated to 40 bits.
/// Each five-bit group selects one symbol without modulo bias. The nonce source
/// must be unpredictable; hashing a test counter does not make it secure.
pub(crate) fn generate(source: &impl Nonces) -> Option<String> {
    let seed = source.next();
    if seed.is_empty() || seed.len() > 512 {
        return None;
    }
    let digest = Sha256::new()
        .chain_update(b"GNAP-user-code-v1\0")
        .chain_update(seed.as_bytes())
        .finalize();
    let mut bytes = [0u8; 8];
    bytes[3..].copy_from_slice(&digest[..5]);
    let bits = u64::from_be_bytes(bytes);
    Some(
        (0..8)
            .rev()
            .map(|n| char::from(ALPHABET[((bits >> (n * 5)) & 31) as usize]))
            .collect(),
    )
}

/// A deliberately narrow, short web-entry profile; not a general URI policy.
pub(crate) fn valid_uri(uri: &str) -> bool {
    if uri.len() > 256 || uri.contains(['?', '#', '%', '@']) || !gnap_types::uri::is_absolute(uri) {
        return false;
    }
    let Some((scheme, rest)) = uri.split_once("://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or_default();
    let host = authority.strip_prefix('[').map_or_else(
        || authority.split(':').next().unwrap_or_default(),
        |literal| literal.split(']').next().unwrap_or_default(),
    );
    !host.is_empty()
        && (scheme.eq_ignore_ascii_case("https")
            || scheme.eq_ignore_ascii_case("http")
                && (host.eq_ignore_ascii_case("localhost")
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())))
}
