//! The GNAP authorization server role — RFC 9635 and an RFC 9767 RS-facing API.
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
//! remain deployment responsibilities; these lifetime helpers alone are not
//! introspection. An open grant's DELETE atomically clears its associated tokens
//! and indexes. A separate resource server must consult or receive authoritative
//! live state; the SDK does not itself propagate revocation across services.

//! # Opaque-token introspection
//!
//! [`AuthorizationServer::resource_server_api`] opts an opaque-encoder AS into
//! RFC 9767 discovery and introspection. It borrows a separate preregistered
//! [`ResourceServerResolver`], [`IntrospectionPolicy`] and RS [`NonceStore`].
//! The caller routes discovery GET and signed introspection POST requests to
//! the returned [`ResourceServerApi`]. Discovery derives its well-known URL
//! from the configured grant endpoint, advertises `httpsig`, and omits token
//! formats: opaque references have no registered GNAP token-format name.
//!
//! RS authentication requires a PS256 public JWK and a nonce. Proof parameter
//! objects with nonempty extensions are outside this profile. The introspected
//! value is in the signed JSON body, never an Authorization header. RS-management
//! access tokens, dynamic RS-key registration, derivation and structured-token
//! introspection are not implemented. The builder is unavailable with a custom
//! encoder, and records with native identifiers are also refused.
//!
//! The policy establishes suitability for the authenticated RS and understands
//! every requested minimum access description. It can disclose only an exact
//! subset of the stored descriptions, possibly empty; this conservative profile
//! does not attempt a universal comparison of GNAP rights objects. It resolves
//! the client's public key when stored only by reference. That is a trusted
//! deployment decision, checked against any known by-value token/client binding.
//! The RS must then verify the actual resource request with that client key,
//! enforce its own rights, and check the returned issuer and timestamps.
//!
//! Every introspection rereads the grant revision after policy and key processing.
//! A changed revision, unavailable store, unrecognized token or unhandled request
//! parameter produces only `active: false`; indeterminate is not proof that a
//! token is intrinsically invalid. Storage adapters should observe outages without
//! logging credentials. There is no positive cache or claim that revocation cannot
//! happen after the final read but before delivery. The RS remains responsible for
//! its final authorization decision and fresh time checks after network/crypto work.
//! RS API errors are HTTP 400 with only `error`, independently of client API rules.
//!
//! # Registering resource sets
//!
//! [`ResourceServerApi::with_resource_registration`] enables RFC 9767 §3.4 and
//! adds its endpoint to discovery; registration is otherwise absent and returns
//! 404. [`ResourceServerResolver`] now returns [`ResolvedResourceServer`], pairing
//! a canonical [`RsId`] with the trusted public key. Migrate existing resolvers
//! by assigning that ID from their key registry, never from an unverified input
//! or JWK `kid`. Aliases of the same RS must retain one owner identity.
//!
//! After proof verification, [`ResourceRegistrationPolicy`] checks every right's
//! meaning and ownership. Approval also attests that this RS can introspect
//! tokens, even when it did not explicitly request introspection. The opaque
//! profile accepts omitted token formats but refuses every explicit list,
//! including an empty one: opaque tokens have no registered format name.
//! Unknown top-level parameters are preserved by the types and refused by this
//! handler. Empty access, more than 64 rights and JSON bodies exceeding 64 KiB
//! are profile limits, not generic GNAP restrictions.
//!
//! [`ResourceSetStore`] atomically creates or retrieves an immutable registration
//! for the authenticated owner and canonical rights. Outer right ordering and
//! duplicates do not matter; nested arrays, strings and URI spelling stay exact.
//! References are public JSON strings, not access credentials. The SDK generates
//! them in the reserved `rsr_` namespace using a trusted [`Nonces`] source. The
//! deployment must reserve that namespace against built-in rights, reject recursive
//! registrations, and resolve references during grant evaluation. Retain resolved
//! approved rights in tokens, rather than dynamically expanding their authority.
//!
//! [`MemoryResourceSetStore`] is bounded and volatile. There is no mutation, TTL,
//! deletion or eviction: restarting loses the catalog and requires registration
//! again before new grants. Durable adapters must commit before replying with
//! success. After a lost response, a fresh signed registration can retrieve the
//! same reference; replaying the old proof is refused. These persistence decisions
//! are unrelated to the GNAP `durable` access-token flag.
//! Allocation, collision, storage-capacity and infrastructure failures receive a redacted
//! HTTP 503 text response with `no-store`, outside the GNAP error envelope. This
//! separates infrastructure unavailability from an invalid RS request; it is not
//! a new registered error or a claim that the RFC explicitly exempts such failures.
//! In contrast, rights exceeding the store's count, depth, node or serialized-size
//! input limits return `invalid_request`. Trusted owner/candidate metadata and a
//! record budget too small for that metadata remain infrastructure failures.
//!
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

pub mod derivation;
pub mod encoding;
pub mod nonce;
pub mod policy;
pub mod resource_sets;
pub mod rs;
pub mod server;
pub mod storage;

pub use derivation::{DerivationPolicy, DerivedAccess, DerivedToken, ParentToken};
pub use encoding::{
    EncodedToken, OpaqueTokenEncoder, TokenEncoder, TokenEncodingContext, TokenEncodingError,
};
pub use nonce::{Nonces, OsNonces};
pub use policy::{
    Decision, EvaluationContext, KeyResolver, Policy, ReleasedSubject, SubjectGround, TokenApproval,
};
pub use resource_sets::{
    MemoryResourceSetStore, ResourceSet, ResourceSetError, ResourceSetLimits, ResourceSetStore,
    RsId,
};
pub use rs::{
    IntrospectionDecision, IntrospectionPolicy, ResolvedResourceServer, ResourceRegistrationPolicy,
    ResourceServerApi, ResourceServerResolver,
};
pub use server::{
    AuthorizationServer, Endpoints, Finish, InteractionError, INTERACTION_LIFETIME, MAX_CLOCK_SKEW,
};
pub use storage::{
    GrantAggregate, GrantId, GrantRecord, GrantSelector, GrantSnapshot, GrantStore, MemoryStorage,
    NonceStore, Revision, Storage, StoreError, TokenRecord,
};
