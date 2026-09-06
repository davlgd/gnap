//! Unguessable values the AS has to mint.
//!
//! The RFC insists on unguessability in several places: interaction references
//! (§4.2), user codes (§3.3.3), redirect URIs (§3.3.1) and instance identifiers
//! (§3.5) must all resist an attacker guessing them within the window they are
//! accepted. §11.28 warns about exhausting the random value space.

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
    fn next(&self) -> String;
}

/// The characters a minted value may use.
///
/// `token68` covers the values that travel in an `Authorization` header
/// (§3.2.1), so the alphabet stays inside it.
const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// Draws from the operating system's random source.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsNonces;

impl Nonces for OsNonces {
    /// # Panics
    ///
    /// Panics when the operating system's random source is unavailable. There
    /// is no safe way to mint an unguessable value without it, and §11.28
    /// treats predictable values as a security failure — carrying on would be
    /// worse than stopping.
    fn next(&self) -> String {
        let mut bytes = [0u8; 24];
        getrandom::getrandom(&mut bytes).expect("OS randomness source unavailable");
        bytes
            .iter()
            .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
            .collect()
    }
}
