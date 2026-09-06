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
//! introspection. An open grant's DELETE atomically clears its associated tokens
//! and indexes. A separate resource server must consult or receive authoritative
//! live state; the SDK does not itself propagate revocation across services.

//! # Continuing an approved grant
//!
//! [`Policy::keep_grant_open`] opts into returning `continue` after approval
//! (§3.1); the default preserves one-shot grants. Approved POST rotates only the
//! continuation credential, without issuing another token or reusing consent.
//! PATCH replaces the fields it includes and reevaluates the resulting request.
//! [`Policy::evaluate_context`] receives the authenticated snapshot for a
//! modification or completed interaction, so consent can be bound to a
//! [`GrantId`], the exact request and the current interaction reference.
//!
//! Previously issued tokens stay usable while a new interaction is pending.
//! Successful reapproval replaces all of them in the same transaction as the
//! new token and optional continuation. This is an SDK choice permitted by §5.3,
//! not a change to old tokens' rights. Native identifiers must be fresh as well,
//! so an attenuated descendant cannot survive by sharing a replacement's index.
//! No `durable` flag or retain-old-tokens mode is implemented.
//!
//! A valid error without `continue` closes continuation and invalidates its old
//! credential (§5), but does not itself revoke prior access tokens. Errors with
//! `continue` are possible only for a genuinely pending grant (§3.6); an approved
//! grant is not moved to pending merely to keep an error recoverable. Internal
//! preparation failures (5xx) publish nothing. A response lost after a successful
//! commit is different: retrying old credentials may fail and is never automatic.
//! DELETE on an open grant marks the aggregate revoked and removes every token.

//! # Access-token representation
//!
//! [`AuthorizationServer::with_token_encoder`] selects a trusted encoder for
//! issuance and rotation. It receives approved rights and lifetime metadata,
//! not management credentials or mutable authorization storage. The default
//! [`OpaqueTokenEncoder`] keeps the reference-token representation unchanged.
//! Selecting an encoder is deployment configuration, not format negotiation.
//!
//! A format-native identifier may be retained in [`TokenRecord::identifier`]
//! for the deployment's live-token index. It is not a GNAP response field and
//! does not publish revocation state to resource servers. Empty identifiers
//! are rejected, as is reusing the current identifier on rotation. An encoding
//! error or invalid replacement leaves the old record intact. The extension
//! point alone is not support for any particular structured token format.
//!
//! Identifiers remain optional on rotation, including after a token with an
//! identifier. Deployments that rely on them must enforce their presence in
//! the encoder and resource-server adapter. Changing an encoder or its
//! configuration does not guarantee continuity between token formats. Storage
//! rejects duplicate live identifiers and access-token values across grants
//! before publishing either an issuance or a rotation.
//!
//! # Migrating a storage adapter
//!
//! The former independent grant/token stores are replaced by [`GrantStore`].
//! A [`GrantAggregate`] owns a [`GrantRecord`] and every [`TokenRecord`] issued
//! by that grant, keyed by token-management handle. Its [`GrantId`] stays fixed
//! when credentials rotate. [`GrantRecord::continuation_token`] is now optional:
//! ending continuation does not itself revoke the issued tokens.
//!
//! Implement [`GrantStore::create`], [`GrantStore::lookup`],
//! [`GrantStore::compare_exchange`] and [`GrantStore::remove`] as transactions.
//! A lookup returns one [`GrantSnapshot`], including its [`Revision`]. Authenticate
//! and prepare changes from that snapshot, then replace the whole aggregate
//! against that revision. All continuation, interaction, management, access-value
//! and native-identifier indexes must change in that same transaction. A missing
//! aggregate cannot be recreated through compare-and-exchange; IDs must never be
//! reused, revisions must never wrap, and explicit revocation is terminal.
//!
//! [`GrantSelector::Management`] replaces token-handle reads; select the token
//! from the returned aggregate. [`GrantSelector::AccessToken`] and
//! [`GrantSelector::TokenIdentifier`] support live resource-server adapters, but
//! a snapshot alone is not an authorization decision: verify proof, rights and
//! time, and coordinate the final live-state check with concurrent revocation.
//! Storage absence and storage failure are distinct results. [`NonceStore`]
//! remains separate, with atomic replay reservation and failure closed.
//!
//! The AS never automatically reruns proof verification or policy on a CAS
//! conflict. A stale, colliding or structurally invalid rotation returns
//! `invalid_rotation` (§6.1); other transaction
//! conflicts and unavailable storage return HTTP 503 without a GNAP response
//! claiming that the candidate committed. Broken/colliding state generated
//! outside rotation returns HTTP 500. Every response still has `Cache-Control: no-store`.
//! Deployments decide whether to retry with a fresh signed request.
//!
//! [`GrantStore::remove`] is explicit retention/expiration maintenance, not the
//! protocol DELETE operation. It removes all indexes at an expected revision,
//! without making the ID reusable. [`MemoryStorage`] otherwise retains closed
//! aggregates, does not enforce capacity limits and is not persistent. Its
//! fallible `len` and `is_empty` inspect continuable grants, not retained history.
//! Store implementations must enforce one credential namespace across access,
//! management and continuation values, including collisions within a candidate.
//! Public interaction and management URI handles are separate identifiers, not
//! credentials. An existing credential cannot change roles during replacement.

pub mod encoding;
pub mod nonce;
pub mod policy;
pub mod server;
pub mod storage;

pub use encoding::{
    EncodedToken, OpaqueTokenEncoder, TokenEncoder, TokenEncodingContext, TokenEncodingError,
};
pub use nonce::{Nonces, OsNonces};
pub use policy::{
    Decision, EvaluationContext, KeyResolver, Policy, ReleasedSubject, SubjectGround,
};
pub use server::{
    AuthorizationServer, Endpoints, Finish, InteractionError, INTERACTION_LIFETIME, MAX_CLOCK_SKEW,
};
pub use storage::{
    GrantAggregate, GrantId, GrantRecord, GrantSelector, GrantSnapshot, GrantStore, MemoryStorage,
    NonceStore, Revision, Storage, StoreError, TokenRecord,
};
