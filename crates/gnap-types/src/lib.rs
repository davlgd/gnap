//! Data model for the GNAP protocol.
//!
//! This crate performs no network or file I/O and no cryptography: it describes
//! the messages of
//! RFC [9635] and RFC [9767], serializes them, and enforces the shape
//! constraints the RFC imposes.
//!
//! # Two deliberate choices
//!
//! **No `#[serde(untagged)]`.** Each of GNAP's eight polymorphic fields has its
//! own visitor. Measured, not assumed: `untagged` loses the offending field on
//! a nested error, and silently accepts several RFC violations. Every error
//! message produced here names the field, cites the RFC section, and gives the
//! GNAP error code where one exists.
//!
//! ```
//! use gnap_types::message::GrantRequest;
//!
//! let e = serde_json::from_str::<GrantRequest>(
//!     r#"{"client":"c","access_token":[{"access":["a"]},{"access":["b"]}]}"#
//! ).unwrap_err();
//! assert!(e.to_string().contains("invalid_request"));
//! ```
//!
//! **Unknown fields are kept.** Appendix D expects extension through newly
//! registered fields; dropping them would prevent relaying an extension one
//! does not understand. They land in an `extra` field.
//!
//! # What is not here
//!
//! Rules that depend on the grant's state (§1.5) belong to the state machine,
//! not to the data model: these types do not know that a token cannot be issued
//! in the _pending_ state. Likewise `Cache-Control: no-store` (§3) is a
//! transport constraint.
//!
//! [9635]: https://www.rfc-editor.org/rfc/rfc9635
//! [9767]: https://www.rfc-editor.org/rfc/rfc9767

pub mod access;
pub mod client;
pub mod error;
pub mod http;
pub mod interact;
pub mod key;
pub mod message;
pub mod polymorphic;
pub mod rs;
pub mod token;
pub mod uri;
pub mod user;

pub use error::GnapError;
pub use message::{ContinueRequest, GrantRequest, GrantResponse};
pub use token::Cardinality;

/// The current time, in seconds since the Unix epoch.
///
/// Every function in these crates that needs the time takes it as a `u64` of
/// Unix **seconds**, rather than reading a clock itself. That is what makes the
/// state machine testable: a test drives the wait periods of §5 by passing the
/// numbers it wants, with no sleeping and no flakiness.
///
/// This helper is for callers who just want the real clock.
///
/// # Panics
///
/// Panics if the system clock is set before the Unix epoch.
///
/// ```
/// use gnap_types::unix_now;
///
/// assert!(unix_now() > 1_700_000_000, "the clock should be past 2023");
/// ```
#[must_use]
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the system clock is set before the Unix epoch")
        .as_secs()
}
