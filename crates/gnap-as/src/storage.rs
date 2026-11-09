//! Where the AS keeps its grants.
//!
//! §1.5 notes that GNAP is a stateful protocol and that a stateless deployment
//! still needs a way to track a grant "in a secure and deterministic fashion".
//! The means are left to the implementation, hence this trait.

use crate::derivation::DerivedToken;
use gnap_core::Grant;
use gnap_types::client::Client;
use gnap_types::message::GrantRequest;
use gnap_types::token::{AccessToken, TokenValue};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

/// Everything the AS remembers about one grant request.
///
/// `Debug` hides the credentials, nonces, handles, and codes it holds.
#[derive(Clone)]
pub struct GrantRecord {
    /// The protocol state (§1.5).
    pub grant: Grant,
    /// The request as it was last received, after any modification (§5.3).
    pub request: GrantRequest,
    /// Current continuation credential (§3.1), or `None` after continuation ends.
    pub continuation_token: Option<String>,
    /// The nonce the AS returned in `interact.finish` (§3.3.5).
    pub as_nonce: Option<String>,
    /// The handle the AS put in the interaction URI it handed the client
    /// (§3.3.1); how a completed interaction finds its way back to this grant.
    ///
    /// It is spent by the completion that uses it, which is the one-time-use
    /// §4-M04 requires of any interaction the AS starts.
    pub interact_handle: Option<String>,
    /// Optional canonical human code, indexed separately from credentials.
    /// A completion through any offered mode removes both code and handle.
    pub user_code: Option<String>,
    /// When the interaction stops being usable, in seconds since the epoch.
    ///
    /// §4-M04 asks the AS to "apply suitable timeouts to any interaction start
    /// methods provided", and §4.1-M02 makes the consequence a MUST: past this
    /// point the AS "MUST reject attempts to use the interaction start modes".
    pub interact_expires_at: Option<u64>,
    /// The interaction reference issued when the interaction completed (§4.2).
    ///
    /// It is one-time-use, so the continuation that presents it clears it.
    pub interact_ref: Option<String>,
    /// Whether the RO has been through the interaction (§4).
    ///
    /// The AS re-evaluates the whole context on the way back, whether the
    /// client returns with a reference (§5.1) or by polling (§5.2).
    pub interaction_completed: bool,
}

/// An access token the AS issued, and what it needs to manage it (§6).
///
/// `Debug` hides the management credential; the token value hides itself.
#[derive(Clone)]
pub struct TokenRecord {
    /// AS-only one-hop provenance and audience; not token response extensions.
    pub derivation: Option<DerivedToken>,
    /// Optional format-native identifier for a deployment's live-token index.
    /// The SDK does not publish or synchronize this state with resource servers.
    pub identifier: Option<Vec<u8>>,
    /// When this value was issued, in seconds since the Unix epoch.
    /// Successful value rotation replaces this timestamp as well as the value.
    pub issued_at: u64,
    /// The token as it was issued, in the §3.2.1 format.
    pub token: AccessToken,
    /// The original client it was issued to. This identity does not change
    /// when the token's presentation key is rotated. An explicit `token.key`
    /// takes precedence over the client's key for resource and management proof.
    pub client: Client,
    /// The token that protects the management API (§3.2.1).
    pub management_token: String,
}

/// Shows whether a secret field is set, never its value.
const fn redacted(value: Option<&String>) -> &'static str {
    if value.is_some() {
        "Some(<redacted>)"
    } else {
        "None"
    }
}

impl fmt::Debug for GrantRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrantRecord")
            .field("grant", &self.grant)
            .field("request", &self.request)
            .field(
                "continuation_token",
                &redacted(self.continuation_token.as_ref()),
            )
            .field("as_nonce", &redacted(self.as_nonce.as_ref()))
            .field("interact_handle", &redacted(self.interact_handle.as_ref()))
            .field("user_code", &redacted(self.user_code.as_ref()))
            .field("interact_expires_at", &self.interact_expires_at)
            .field("interact_ref", &redacted(self.interact_ref.as_ref()))
            .field("interaction_completed", &self.interaction_completed)
            .finish()
    }
}

impl fmt::Debug for TokenRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenRecord")
            .field("derivation", &self.derivation)
            .field(
                "identifier",
                &self.identifier.as_ref().map(|_| "<redacted>"),
            )
            .field("issued_at", &self.issued_at)
            .field("token", &self.token)
            .field("client", &self.client)
            .field("management_token", &"<redacted>")
            .finish()
    }
}

impl TokenRecord {
    /// A record with no derivation metadata or format-native identifier.
    ///
    /// Prefer this constructor to a struct literal when neither is needed.
    /// It stores what it is given; it does not validate the token, the client
    /// or the credential, which is the issuing server's job.
    #[must_use]
    pub fn new(
        token: AccessToken,
        client: Client,
        management_token: impl Into<String>,
        issued_at: u64,
    ) -> Self {
        Self {
            derivation: None,
            identifier: None,
            issued_at,
            token,
            client,
            management_token: management_token.into(),
        }
    }

    /// Exclusive expiration deadline, or `None` when no lifetime was issued.
    ///
    /// The duration comes from `token.expires_in`. For externally constructed
    /// records, a zero duration or an overflowing deadline expires immediately
    /// at `issued_at`, rather than silently becoming an unlimited lifetime.
    /// The server never issues either of these invalid finite lifetimes.
    #[must_use]
    pub fn expires_at(&self) -> Option<u64> {
        self.token.expires_in.map(|seconds| {
            self.issued_at
                .checked_add(seconds)
                .unwrap_or(self.issued_at)
        })
    }

    /// Whether the record's issuance time and lifetime permit use at `now`.
    ///
    /// Times before issuance and at or after a finite deadline are rejected.
    /// This only checks time: a resource server must also establish that the
    /// record is authoritative and live, verify proof, and enforce its rights.
    /// It does not sweep storage or invalidate related grant records.
    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && self.expires_at().is_none_or(|deadline| now < deadline)
    }
}

/// A stable, internal grant identity. It is never a bearer credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GrantId(pub u64);

/// A monotonically increasing version of one grant aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revision(pub u64);

/// All state whose changes must be published together for one grant.
#[derive(Debug, Clone)]
pub struct GrantAggregate {
    /// Request, interaction and continuation state.
    pub record: GrantRecord,
    /// Issued tokens, keyed by their management URI handle.
    pub tokens: HashMap<String, TokenRecord>,
    /// Explicit revocation, distinct from ending continuation normally.
    /// A revoked aggregate cannot be reactivated or acquire new tokens.
    pub revoked: bool,
}

impl GrantAggregate {
    /// Starts an aggregate without issued tokens.
    #[must_use]
    pub fn new(record: GrantRecord) -> Self {
        Self {
            record,
            tokens: HashMap::new(),
            revoked: false,
        }
    }
}

/// A consistent read of an aggregate and its compare-and-exchange version.
#[derive(Debug, Clone)]
pub struct GrantSnapshot {
    /// Internal identity, allocated once by the store and never reused.
    pub id: GrantId,
    /// Version against which a replacement must be committed.
    pub revision: Revision,
    /// Owned snapshot; changing this copy does not change the store.
    pub aggregate: GrantAggregate,
}

/// An index through which a caller locates one grant aggregate.
#[derive(Debug, Clone, Copy)]
pub enum GrantSelector<'a> {
    /// Internal identity.
    Id(GrantId),
    /// Current continuation credential.
    Continuation(&'a str),
    /// Unspent interaction handle.
    Interaction(&'a str),
    /// Current token-management URI handle.
    ///
    /// §6-M04 requires the AS to "uniquely identify the token being managed
    /// from the token management URI, the token management access token, or a
    /// combination of both". This selector locates the record; the server must
    /// still authenticate its management credential and associated proof.
    Management(&'a str),
    /// Current access-token value, for a resource-server adapter.
    AccessToken(&'a str),
    /// Current format-native token identifier, for a live-state adapter.
    TokenIdentifier(&'a [u8]),
}

/// A storage failure; none of these outcomes may partially publish a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// The aggregate disappeared, was revoked, or no longer has that revision.
    Conflict,
    /// The exact parent already has the profile's maximum active children.
    DerivationLimit,
    /// An index value is already in use, including within the candidate.
    Collision,
    /// The candidate violates structural or terminal-state invariants.
    Invalid,
    /// The backing store cannot establish a reliable result.
    Unavailable,
    /// A counter cannot advance or a configured/profile capacity is exhausted.
    Exhausted,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::DerivationLimit => "downstream derivation profile limit reached",
            Self::Conflict => "grant snapshot is no longer current",
            Self::Collision => "grant index value is already in use",
            Self::Invalid => "grant aggregate violates storage invariants",
            Self::Unavailable => "grant storage is unavailable",
            Self::Exhausted => "grant storage counter is exhausted",
        })
    }
}
impl std::error::Error for StoreError {}

/// Transactional grant storage, including every token issued by that grant.
///
/// Reads include the version of the aggregate used to authenticate a request.
/// A replacement commits only against that version. The aggregate and all its
/// indexes change atomically; there is no take/restore operation. Implementations
/// must reject collisions before publication, never reuse IDs or wrap revisions,
/// and must not resurrect missing or revoked aggregates through `compare_exchange`.
/// Access, management and continuation credentials share a unique namespace:
/// a value must not occur twice or switch roles during replacement. Public URI
/// handles are indexed separately and are not credentials.
///
/// The server prepares policy decisions, proofs and encodings outside the store.
/// A conflict does not automatically retry those operations.
pub trait GrantStore {
    /// Creates a new aggregate and all its indexes, allocating a fresh identity.
    /// # Errors
    /// Returns a collision, invalid candidate, capacity or availability failure.
    fn create(&self, aggregate: GrantAggregate) -> Result<GrantSnapshot, StoreError>;

    /// Reads one consistent snapshot through an index.
    /// # Errors
    /// Returns an availability failure rather than disguising it as absence.
    fn lookup(&self, selector: GrantSelector<'_>) -> Result<Option<GrantSnapshot>, StoreError>;

    /// Replaces an existing aggregate and all indexes in one atomic operation.
    /// # Errors
    /// A stale version, revoked/missing aggregate or invalid/colliding replacement
    /// is refused without publishing any part of the candidate.
    fn compare_exchange(
        &self,
        id: GrantId,
        revision: Revision,
        replacement: GrantAggregate,
    ) -> Result<GrantSnapshot, StoreError>;

    /// Removes an aggregate and every index at an expected revision.
    ///
    /// This is deployment maintenance (retention or expiration), not GNAP
    /// revocation. The removed identity must never be allocated again, and a
    /// stale compare-and-exchange must not recreate it. Protocol DELETE uses
    /// compare-and-exchange so its terminal state remains distinguishable.
    /// # Errors
    /// A missing identity or stale revision is a conflict; failures publish no
    /// partial removal.
    fn remove(&self, id: GrantId, revision: Revision) -> Result<(), StoreError>;
}

/// Optional storage capability: atomic creation of one-hop derived grants.
///
/// Downstream derivation is a deployment choice, not a base requirement of
/// [`GrantStore`]. A server exposes the derivation handler only for stores
/// implementing this trait. Calling that handler without the capability is
/// refused by the compiler rather than reported at run time as a storage outage
/// or a policy denial. Stores used only with the ordinary grant handler do not
/// need to implement this trait.
pub trait DerivedGrantStore: GrantStore {
    /// Atomically creates an independent child grant against a live parent token.
    ///
    /// Validate the expected parent revision, exact value, one-hop provenance,
    /// child expiry and all indexes under the transaction. Reread `clock` at
    /// that decision point, including after waiting for a lock. This trusted
    /// callback must be brief, non-reentrant and side-effect-free. Cascade parent
    /// token removal/replacement through every write path, including maintenance.
    /// No partial state may be published on failure and no callback is retried.
    /// # Errors
    /// Refuses stale/dead parents, invalid children, collisions, budgets or outages.
    fn create_derived(
        &self,
        parent: GrantId,
        revision: Revision,
        value: &TokenValue,
        child: GrantAggregate,
        clock: &dyn Fn() -> u64,
    ) -> Result<GrantSnapshot, StoreError>;
}

/// Optional user-code index, updated atomically with the entire grant.
///
/// Implementations must reject active code collisions and remove old mappings
/// on replacement, completion, revocation and maintenance. A code is a request
/// locator, not a credential or resource-owner authentication. Ordinary stores
/// need not implement this capability; enabling it on an AS requires this trait.
pub trait UserCodeStore: GrantStore {
    /// Reads a consistent snapshot for an already normalized, canonical code.
    /// This lookup neither checks expiry nor consumes the interaction.
    /// # Errors
    /// Storage failure must be distinguished from an unknown code.
    fn lookup_user_code(&self, code: &str) -> Result<Option<GrantSnapshot>, StoreError>;
}

/// Signature replay state may use a separate, short-lived shared store.
pub trait NonceStore {
    /// Atomically remembers a nonce at `now`, or returns false for replay/failure.
    /// Retain entries for the entire signature acceptance window.
    fn remember_nonce(&self, nonce: &str, now: u64) -> bool;
}

/// Optional replay-memory capability: atomic reservation of a nonce pair.
///
/// Linked key rotation (RFC 9635 §6.1.1 and §7.3.1.1) presents two signatures.
/// This SDK requires their nonces to be reserved together or not at all; that
/// atomic storage contract is a project choice, not an additional RFC mandate.
/// A server can enable key rotation only for stores implementing this trait.
/// The capability is captured when `with_key_rotation` is called, so the
/// ordinary grant and management handlers keep working with a plain
/// [`NonceStore`]. Stores used only with ordinary handlers need not implement
/// this trait.
pub trait RotationNonceStore: NonceStore {
    /// Atomically reserves the old and new nonces of a key-rotation proof.
    ///
    /// Both use the same namespace and retention as
    /// [`NonceStore::remember_nonce`]. Return false without recording either
    /// value if one is already seen, both present values are equal, or storage
    /// fails. An absent nonce needs no entry. Implementing this as two ordinary
    /// insertions is not atomic.
    fn remember_nonce_pair(
        &self,
        previous: Option<&str>,
        replacement: Option<&str>,
        now: u64,
    ) -> bool;
}

/// The state required by an authorization server.
pub trait Storage: GrantStore + NonceStore {}
impl<T: GrantStore + NonceStore> Storage for T {}

macro_rules! forward_storage {
    ($pointer:ty) => {
        impl<T: GrantStore + ?Sized> GrantStore for $pointer {
            fn create(&self, aggregate: GrantAggregate) -> Result<GrantSnapshot, StoreError> {
                (**self).create(aggregate)
            }
            fn lookup(
                &self,
                selector: GrantSelector<'_>,
            ) -> Result<Option<GrantSnapshot>, StoreError> {
                (**self).lookup(selector)
            }
            fn compare_exchange(
                &self,
                id: GrantId,
                revision: Revision,
                replacement: GrantAggregate,
            ) -> Result<GrantSnapshot, StoreError> {
                (**self).compare_exchange(id, revision, replacement)
            }
            fn remove(&self, id: GrantId, revision: Revision) -> Result<(), StoreError> {
                (**self).remove(id, revision)
            }
        }
        impl<T: DerivedGrantStore + ?Sized> DerivedGrantStore for $pointer {
            fn create_derived(
                &self,
                parent: GrantId,
                revision: Revision,
                value: &TokenValue,
                child: GrantAggregate,
                clock: &dyn Fn() -> u64,
            ) -> Result<GrantSnapshot, StoreError> {
                (**self).create_derived(parent, revision, value, child, clock)
            }
        }
        impl<T: UserCodeStore + ?Sized> UserCodeStore for $pointer {
            fn lookup_user_code(&self, code: &str) -> Result<Option<GrantSnapshot>, StoreError> {
                (**self).lookup_user_code(code)
            }
        }
        impl<T: NonceStore + ?Sized> NonceStore for $pointer {
            fn remember_nonce(&self, nonce: &str, now: u64) -> bool {
                (**self).remember_nonce(nonce, now)
            }
        }
        impl<T: RotationNonceStore + ?Sized> RotationNonceStore for $pointer {
            fn remember_nonce_pair(
                &self,
                previous: Option<&str>,
                replacement: Option<&str>,
                now: u64,
            ) -> bool {
                (**self).remember_nonce_pair(previous, replacement, now)
            }
        }
    };
}
forward_storage!(Arc<T>);
forward_storage!(&T);

mod memory;

pub use memory::MemoryStorage;
