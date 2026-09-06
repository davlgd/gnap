//! The GNAP client instance role — RFC 9635.
//!
//! Builds, signs and sends grant requests, and validates what comes back. The
//! HTTP transport is a trait, so this crate forces no runtime on its users and
//! can be driven with no network at all.
//!
//! The session checks response shape, requested token labels and interaction
//! data before adopting them. Its implemented checks and adapter limits do not
//! amount to a claim of complete RFC conformance.
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
//! use std::num::NonZeroU64;
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
//! let mut session = Session::new(&Canned, &signer, "https://as.example/gnap")
//!     .with_finish_timeout(NonZeroU64::new(300).unwrap());
//!
//! let request: GrantRequest =
//!     serde_json::from_str(r#"{"client":"my-client","access_token":{"access":["read"]}}"#)?;
//!
//! let step = session.start(&request, 1_700_000_000)?;
//! assert!(matches!(step, Step::Approved(_)));
//! # Ok(())
//! # }
//! ```

//! # Ongoing grants and local state
//!
//! An approved response can retain a continuation. `continue_grant` accepts a
//! continuation-only response without discarding held tokens; `modify_grant`
//! validates responses against the replacement cardinality and interaction
//! capabilities it sent. New callback nonces and hash methods are adopted only
//! as part of a usable exchange. An inconclusive response restores the complete
//! previous local state, not the server's state: the request may already have
//! committed remotely. No operation retries automatically.
//!
//! `revoke_grant` uses the offered continuation to send DELETE and requires a
//! 204 response with empty content. Only confirmed revocation clears the local
//! tokens and subject information. Valid GNAP errors still replace or remove
//! continuation; losing the continuation does not itself revoke held tokens.
//! Applications needing remote live-state guarantees must enforce them at the RS.
//!
//! # Token presentation keys
//!
//! [`Session::rotate_key`] proves the old and new keys together and adopts the
//! new signer only after a valid response. Each token keeps its own signer;
//! the grant continuation keeps the original client key. [`Session::signer_for`]
//! selects a resource-request signer without requiring a token management API.
//! It refuses bearer tokens and initially explicit bindings the session cannot
//! resolve. Management also refuses unknown explicit bindings before signing.
//! These are adapter limits, not GNAP prohibitions on those token forms.
//! A new session does not recover another session's rotated-key registry.
//! Use [`Session::rotate_key_owned`] to let a session retain a runtime-generated
//! signer's `Arc`; [`Session::rotate_key`] still accepts a borrowed signer.
//! `signer_for` now borrows the session, so its result cannot be held across a
//! mutation that might release the owned key. This is a lifetime migration for
//! callers that previously kept the returned reference independently.
//!
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
//! RFC 9635 §4 recommends suitable finish timeouts (SHOULD), without specifying
//! a duration. [`Session::with_finish_timeout`] accepts a positive number of
//! seconds and bounds callbacks even when the AS omits `expires_in`. When both
//! limits exist, the shorter wins. For example, configure a five-minute local
//! maximum with `.with_finish_timeout(NonZeroU64::new(300).unwrap())`, importing
//! [`std::num::NonZeroU64`]. The default remains the AS-advertised lifetime only.
//! Reconfiguring a live session may shorten its current window but cannot
//! extend or restart it; a new interaction response uses the latest setting.
//! Diagnostics distinguish the effective AS or client limit from a clock value
//! preceding the interaction response. The caller remains responsible for a
//! reliable clock; the session does not track every intervening clock change.
//!
//! This policy bounds finish callbacks, not polling without a finish method,
//! transport calls, token expiry or the entire session. A validated reference
//! can still be sent after the finish deadline. A negotiated finish continues
//! to prohibit polling before a valid callback, so refusing a late callback
//! does not authorize a polling fallback. Local expiry neither revokes a remote
//! grant nor discards its continuation; session cleanup remains application work.

pub mod error;
pub mod rotation;
pub mod session;
pub mod signing;
pub mod transport;

pub use error::ClientError;
pub use session::{AttributedSubject, Session, Step, VerifiedSubject};
pub use signing::sign_request;
pub use transport::{HttpRequest, HttpResponse, HttpTransport};
