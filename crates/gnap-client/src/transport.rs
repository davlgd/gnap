//! The HTTP transport seam.
//!
//! GNAP is an HTTP protocol, but this crate does not pick an HTTP client. It
//! describes requests and responses as bytes and asks the caller to move them.
//!
//! # Why a trait rather than a concrete client
//!
//! The conformance harness this project is built around has to send
//! deliberately malformed requests — a broken signature, a forbidden field, a
//! replayed interaction reference. A well-behaved typed HTTP client fights that.
//! Through this seam the harness supplies exactly the bytes it wants and
//! observes exactly what comes back.
//!
//! Two consequences follow: the client is testable with no network at all, and
//! no runtime is forced on anyone depending on this crate.
//!
//! # Blocking, for now
//!
//! [`HttpTransport::send`] is blocking. An async counterpart is a follow-up: at
//! this crate's MSRV an `async fn` in a trait cannot be made object-safe without
//! an extra dependency, and everything that consumes the seam today — the tests
//! and the harness — is synchronous. Driving it from async code goes through
//! whatever blocking-task facility the runtime offers.

use std::fmt;

pub use gnap_types::http::{HttpRequest, HttpResponse};

/// Moves an HTTP request and brings back the response.
///
/// Implementations must not alter the request: the URI, the header order and
/// the body all feed the signature the caller already computed.
pub trait HttpTransport {
    /// What can go wrong at the transport level.
    type Error: fmt::Display;

    /// Sends the request and returns the response.
    ///
    /// # Errors
    ///
    /// Fails when the request cannot be delivered or the response cannot be
    /// read.
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error>;
}
