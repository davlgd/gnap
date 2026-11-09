//! Unguessable values the AS has to mint.
//!
//! The RFC insists on unguessability in several places: interaction references
//! (§4.2), user codes (§3.3.3), redirect URIs (§3.3.1) and instance identifiers
//! (§3.5) must all resist an attacker guessing them within the window they are
//! accepted. §11.28 warns about exhausting the random value space.

use std::fmt;

/// Mints unguessable values.
///
/// A trait rather than a function so tests can be deterministic; §11.28 is a
/// reminder that the real implementation needs a real random source.
/// The optional user-code profile takes a separate draw of 1–512 bytes and
/// hashes it to an eight-symbol code. That hash preserves no security if this
/// source is predictable; counter implementations belong only in tests.
pub trait Nonces {
    /// A fresh value, unguessable by an attacker.
    ///
    /// The value must stay inside the `token68` character set (§3.2.1), since
    /// it may end up in an `Authorization` header. A server given values
    /// outside it answers 500 rather than emitting a malformed token.
    ///
    /// # Errors
    ///
    /// Fails when no unguessable value can be produced. The server then
    /// answers 500 before it stores anything.
    fn next(&self) -> Result<String, NonceError>;
}

/// The random source couldn't produce an unguessable value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceError;

impl fmt::Display for NonceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the random source is unavailable")
    }
}

impl std::error::Error for NonceError {}

/// The characters a minted value may use: the URL-safe base64 alphabet.
///
/// It sits inside `token68` (§3.2.1), for values that travel in an
/// `Authorization` header, and inside the unreserved characters of RFC 3986,
/// for those that travel in a URI. Its 64 symbols take six bits each, so every
/// symbol is equally likely.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Symbols in each value, one per random byte: 144 bits of entropy.
const SYMBOLS: usize = 24;

/// Draws from the operating system's random source.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsNonces;

impl Nonces for OsNonces {
    fn next(&self) -> Result<String, NonceError> {
        let mut bytes = [0u8; SYMBOLS];
        getrandom::fill(&mut bytes).map_err(|_| NonceError)?;
        Ok(bytes
            .iter()
            .map(|b| char::from(ALPHABET[usize::from(b & 0x3f)]))
            .collect())
    }
}
