//! The GNAP authorization server role — RFC 9635.
//!
//! Takes a described HTTP request and returns a described HTTP response, with
//! no HTTP framework and no runtime in the way. What the RFC leaves to the
//! deployment — who is trusted, what is granted, whether an RO must approve —
//! sits behind the [`Policy`], [`KeyResolver`] and [`Storage`] traits.
//!
//! The protocol rules stay here: signature verification (§7.3.1), the state
//! guards (§1.5, §5) delegated to `gnap-core`, response shapes tied to state
//! (§3.2, §3.3, §3.4), and `Cache-Control: no-store` on every response (§3).
//!
//! # Assembling a server
//!
//! ```
//! use gnap_as::{
//!     AuthorizationServer, Decision, Endpoints, KeyResolver, MemoryStorage, OsNonces, Policy,
//! };
//! use gnap_crypto::proof::Verifier;
//! use gnap_types::client::Client;
//! use gnap_types::http::HttpRequest;
//! use gnap_types::message::GrantRequest;
//!
//! /// Refuses everything. A real policy would consult an RO (§4).
//! struct RefuseAll;
//!
//! impl Policy for RefuseAll {
//!     fn evaluate(&self, _request: &GrantRequest) -> Decision {
//!         Decision::Deny(gnap_registry::ErrorCode::RequestDenied)
//!     }
//! }
//!
//! /// Recognises nobody. A real resolver would look the client up (§2.3).
//! struct NoClients;
//!
//! impl KeyResolver for NoClients {
//!     fn resolve(&self, _client: &Client) -> Option<Box<dyn Verifier>> {
//!         None
//!     }
//! }
//!
//! let server = AuthorizationServer::new(
//!     RefuseAll,
//!     NoClients,
//!     MemoryStorage::new(),
//!     OsNonces,
//!     Endpoints {
//!         grant: "https://as.example/gnap".into(),
//!         continuation: "https://as.example/continue".into(),
//!         interaction: "https://as.example/interact".into(),
//!         token_management: "https://as.example/token".into(),
//!     },
//! );
//!
//! // An unknown client is answered with `invalid_client` (§2.3.1), and every
//! // response carries the cache directive §3 requires.
//! let request = HttpRequest::new("POST", "https://as.example/gnap")
//!     .json_body(br#"{"client":"stranger"}"#.to_vec());
//! let response = server.handle(&request, 1_700_000_000);
//!
//! assert_eq!(response.status, 400);
//! assert!(String::from_utf8_lossy(&response.body).contains("invalid_client"));
//! assert!(response.has_no_store());
//! ```

//! # Access-token lifetimes
//!
//! [`Policy::token_lifetime`] optionally selects a positive duration for each
//! approved request. The server advertises it as `expires_in` and records the
//! issuance time in [`TokenRecord::issued_at`]. The default remains no advertised
//! expiration. On successful rotation, the duration and rights stay unchanged
//! while the issuance time becomes the supplied `now`.
//! As with the other server operations, that time is provided by the caller;
//! the synchronous server does not resample a system clock during processing.
//!
//! This server refuses to rotate an expired value, a value issued in the future,
//! or one whose renewed deadline would overflow. These are SDK policies, not
//! additional GNAP requirements. A failed rotation preserves the original
//! value, metadata and timestamp. Revocation can still remove an expired record
//! if the deployment's store retains it long enough to authenticate the request.
//!
//! Stores do not have to run an expiration scheduler: a resource server can call
//! [`TokenRecord::is_valid_at`] on each access, in addition to verifying the
//! proof and rights. [`MemoryStorage`] does not sweep expired tokens. Production
//! clock handling, authoritative RS metadata, persistence and garbage collection
//! remain deployment responsibilities; these helpers do not implement RFC 9767
//! introspection or grant-to-token revocation cascades.

pub mod nonce;
pub mod policy;
pub mod server;
pub mod storage;

pub use nonce::{Nonces, OsNonces};
pub use policy::{Decision, KeyResolver, Policy, ReleasedSubject, SubjectGround};
pub use server::{
    AuthorizationServer, Endpoints, Finish, InteractionError, INTERACTION_LIFETIME, MAX_CLOCK_SKEW,
};
pub use storage::{
    GrantRecord, GrantStore, MemoryStorage, NonceStore, Storage, TokenRecord, TokenStore,
};
