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

pub mod error;
pub mod session;
pub mod transport;

pub use error::ClientError;
pub use session::{AttributedSubject, Session, Step};
pub use transport::{HttpRequest, HttpResponse, HttpTransport};
