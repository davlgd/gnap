//! The GNAP client instance role — RFC 9635.
//!
//! Builds, signs and sends grant requests, and validates what comes back. The
//! HTTP transport is a trait, so this crate forces no runtime on its users and
//! can be driven with no network at all.
//!
//! What makes this more than a wrapper around an HTTP call is what it refuses:
//! the client-side MUSTs of the RFC are enforced on every response, so an AS
//! that breaks them is caught rather than followed.
//!
//! # Supplying a transport
//!
//! One trait method stands between this crate and the network. Here it answers
//! from a canned reply instead:
//!
//! ```
//! use gnap_client::{HttpRequest, HttpResponse, HttpTransport, Session, Step};
//! use gnap_crypto::ps256::Ps256Signer;
//! use gnap_types::message::GrantRequest;
//!
//! struct Canned;
//!
//! impl HttpTransport for Canned {
//!     type Error = std::convert::Infallible;
//!
//!     fn send(&self, _request: HttpRequest) -> Result<HttpResponse, Self::Error> {
//!         Ok(HttpResponse {
//!             status: 200,
//!             headers: vec![("Cache-Control".into(), "no-store".into())],
//!             body: br#"{"access_token":{"value":"OS9M2PMHKUR64TB8","access":["read"]}}"#
//!                 .to_vec(),
//!         })
//!     }
//! }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let signer = Ps256Signer::generate(2048, "my-key")?;
//! let mut session = Session::new(&Canned, &signer, "https://as.example/gnap");
//!
//! let request: GrantRequest =
//!     serde_json::from_str(r#"{"client":"my-client","access_token":{"access":["read"]}}"#)?;
//!
//! let step = session.start(&request, 1_700_000_000)?;
//! assert!(matches!(step, Step::Approved(_)));
//! # Ok(())
//! # }
//! ```

//! # Callback clocks and API migration
//!
//! `accept_callback`, `accept_redirect` and `accept_push` now require a `now`
//! argument, in Unix seconds. Pass the current time when processing the
//! callback, on the same clock used by `start`, `modify_grant` and
//! `continue_grant`. The synchronous API does not read a system clock itself.
//! An interaction window starts at the timestamp supplied to the operation
//! that returned it; transport latency therefore shortens the usable window
//! rather than extending the advertised duration.
//!
//! An advertised `interact.expires_in` bounds callback acceptance: the exact
//! deadline is already too late. A clock reading before that window's start
//! is refused. Deadlines use wider arithmetic, so a legal duration extending
//! beyond the input clock's range does not discard a continuation. Invalid or
//! late callbacks do not replace a reference already validated; receiving a new interaction set
//! replaces the previous finish context. A response without `interact` does
//! not renew the window.
//!
//! RFC 9635 §4 recommends suitable finish timeouts (SHOULD). This client uses
//! an AS-advertised lifetime but does not impose its own maximum when
//! `expires_in` is absent: §3.3 makes that field optional. Applications that
//! require a maximum finish wait must bound their session lifetime as well.
//! This is not a claim to implement a configurable client timeout policy.

pub mod error;
pub mod session;
pub mod transport;

pub use error::ClientError;
pub use session::{AttributedSubject, Session, Step};
pub use transport::{HttpRequest, HttpResponse, HttpTransport};
