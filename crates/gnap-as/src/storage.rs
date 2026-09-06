//! Where the AS keeps its grants.
//!
//! §1.5 notes that GNAP is a stateful protocol and that a stateless deployment
//! still needs a way to track a grant "in a secure and deterministic fashion".
//! The means are left to the implementation, hence this trait.

use crate::derivation::{
    DerivedToken, ParentToken, MAX_DERIVED_CHILDREN, MAX_DERIVED_GRANTS, MAX_DERIVED_LIFETIME,
};
use crate::server::MAX_CLOCK_SKEW;
use gnap_core::Grant;
use gnap_types::client::Client;
use gnap_types::message::GrantRequest;
use gnap_types::token::{AccessToken, TokenValue};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

/// Everything the AS remembers about one grant request.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
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
    /// The client it was issued to, which is how its key is resolved (§6).
    pub client: Client,
    /// The token that protects the management API (§3.2.1).
    pub management_token: String,
}

impl TokenRecord {
    /// A record with no derivation metadata or format-native identifier.
    ///
    /// Prefer this constructor to a struct literal when neither is needed.
    /// Optional metadata can then receive defaults here as the
    /// record evolves; existing struct literals still need every public field.
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

/// Signature replay state may use a separate, short-lived shared store.
pub trait NonceStore {
    /// Atomically remembers a nonce at `now`, or returns false for replay/failure.
    /// Retain entries for the entire signature acceptance window.
    fn remember_nonce(&self, nonce: &str, now: u64) -> bool;
}

/// The state required by an authorization server.
pub trait Storage: GrantStore + NonceStore {}
impl<T: GrantStore + NonceStore> Storage for T {}

macro_rules! forward_storage {
    ($pointer:ty) => {
        impl<T: GrantStore + ?Sized> GrantStore for $pointer {
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
        impl<T: NonceStore + ?Sized> NonceStore for $pointer {
            fn remember_nonce(&self, nonce: &str, now: u64) -> bool {
                (**self).remember_nonce(nonce, now)
            }
        }
    };
}
forward_storage!(Arc<T>);
forward_storage!(&T);

const NONCE_MEMORY: u64 = 2 * MAX_CLOCK_SKEW;

#[derive(Debug, Default)]
struct Indices {
    continuation: HashMap<String, GrantId>,
    interaction: HashMap<String, GrantId>,
    management: HashMap<String, GrantId>,
    values: HashMap<String, GrantId>,
    identifiers: HashMap<Vec<u8>, GrantId>,
    credentials: HashMap<String, (GrantId, CredentialRole)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialRole {
    Continuation,
    Access,
    Management,
}

impl Indices {
    fn locate(&self, selector: GrantSelector<'_>) -> Option<GrantId> {
        match selector {
            GrantSelector::Id(id) => Some(id),
            GrantSelector::Continuation(key) => self.continuation.get(key).copied(),
            GrantSelector::Interaction(key) => self.interaction.get(key).copied(),
            GrantSelector::Management(key) => self.management.get(key).copied(),
            GrantSelector::AccessToken(key) => self.values.get(key).copied(),
            GrantSelector::TokenIdentifier(key) => self.identifiers.get(key).copied(),
        }
    }

    fn candidate(aggregate: &GrantAggregate, id: GrantId) -> Result<Self, StoreError> {
        let mut indices = Self::default();
        if aggregate.revoked
            && (aggregate.record.continuation_token.is_some()
                || aggregate.record.interact_handle.is_some()
                || !aggregate.tokens.is_empty())
        {
            return Err(StoreError::Invalid);
        }
        if let Some(key) = &aggregate.record.continuation_token {
            if key.is_empty() {
                return Err(StoreError::Invalid);
            }
            indices.continuation.insert(key.clone(), id);
            indices
                .credentials
                .insert(key.clone(), (id, CredentialRole::Continuation));
        }
        if let Some(key) = &aggregate.record.interact_handle {
            if key.is_empty() || aggregate.record.continuation_token.is_none() {
                return Err(StoreError::Invalid);
            }
            indices.interaction.insert(key.clone(), id);
        }
        for (handle, token) in &aggregate.tokens {
            if handle.is_empty()
                || token.management_token.is_empty()
                || token.client != aggregate.record.request.client
            {
                return Err(StoreError::Invalid);
            }
            indices.management.insert(handle.clone(), id);
            for (value, role) in [
                (token.token.value.as_str(), CredentialRole::Access),
                (token.management_token.as_str(), CredentialRole::Management),
            ] {
                if indices
                    .credentials
                    .insert(value.to_owned(), (id, role))
                    .is_some()
                {
                    return Err(StoreError::Collision);
                }
            }
            if indices
                .values
                .insert(token.token.value.as_str().to_owned(), id)
                .is_some()
            {
                return Err(StoreError::Collision);
            }
            if let Some(identifier) = &token.identifier {
                if identifier.is_empty() {
                    return Err(StoreError::Invalid);
                }
                if indices.identifiers.insert(identifier.clone(), id).is_some() {
                    return Err(StoreError::Collision);
                }
            }
        }
        Ok(indices)
    }

    fn check(&self, candidate: &Self, own_id: GrantId) -> Result<(), StoreError> {
        fn collides<K: Eq + std::hash::Hash>(
            current: &HashMap<K, GrantId>,
            candidate: &HashMap<K, GrantId>,
            own: GrantId,
        ) -> bool {
            candidate
                .keys()
                .any(|key| current.get(key).is_some_and(|id| *id != own))
        }
        if collides(&self.continuation, &candidate.continuation, own_id)
            || collides(&self.interaction, &candidate.interaction, own_id)
            || collides(&self.management, &candidate.management, own_id)
            || collides(&self.values, &candidate.values, own_id)
            || collides(&self.identifiers, &candidate.identifiers, own_id)
            || candidate.credentials.iter().any(|(value, (_, role))| {
                self.credentials
                    .get(value)
                    .is_some_and(|(owner, previous_role)| *owner != own_id || role != previous_role)
            })
        {
            return Err(StoreError::Collision);
        }
        Ok(())
    }

    fn replace(&mut self, id: GrantId, candidate: Self) {
        self.continuation.retain(|_, owner| *owner != id);
        self.interaction.retain(|_, owner| *owner != id);
        self.management.retain(|_, owner| *owner != id);
        self.values.retain(|_, owner| *owner != id);
        self.identifiers.retain(|_, owner| *owner != id);
        self.credentials.retain(|_, (owner, _)| *owner != id);
        self.continuation.extend(candidate.continuation);
        self.interaction.extend(candidate.interaction);
        self.management.extend(candidate.management);
        self.values.extend(candidate.values);
        self.identifiers.extend(candidate.identifiers);
        self.credentials.extend(candidate.credentials);
    }
}

#[derive(Debug, Default)]
struct State {
    last_id: u64,
    grants: HashMap<GrantId, GrantSnapshot>,
    indices: Indices,
    children: HashMap<ParentToken, HashSet<GrantId>>,
    derived_origins: HashMap<GrantId, ParentToken>,
}

impl State {
    fn publish(&mut self, snapshot: GrantSnapshot, indices: Indices) {
        if let Some(parent) = self.derived_origins.get(&snapshot.id) {
            if snapshot.aggregate.tokens.is_empty() {
                if let Some(children) = self.children.get_mut(parent) {
                    children.remove(&snapshot.id);
                    if children.is_empty() {
                        self.children.remove(parent);
                    }
                }
            } else {
                self.children
                    .entry(parent.clone())
                    .or_default()
                    .insert(snapshot.id);
            }
        }
        self.indices.replace(snapshot.id, indices);
        self.grants.insert(snapshot.id, snapshot);
    }

    // Prepare every fallible revision increment before publishing any mutation.
    fn cascade(
        &self,
        previous: &GrantSnapshot,
        replacement: Option<&GrantAggregate>,
    ) -> Result<Vec<GrantSnapshot>, StoreError> {
        let mut cascade = Vec::new();
        for token in previous.aggregate.tokens.values() {
            let unchanged = replacement.is_some_and(|aggregate| {
                !aggregate.revoked
                    && aggregate.tokens.values().any(|next| {
                        next.token == token.token
                            && next.client == token.client
                            && next.issued_at == token.issued_at
                            && next.identifier == token.identifier
                            && next.derivation == token.derivation
                    })
            });
            if unchanged {
                continue;
            }
            let parent = ParentToken::new(previous.id, &token.token.value);
            for id in self.children.get(&parent).into_iter().flatten() {
                let mut child = self.grants.get(id).ok_or(StoreError::Invalid)?.clone();
                child.revision = Revision(
                    child
                        .revision
                        .0
                        .checked_add(1)
                        .ok_or(StoreError::Exhausted)?,
                );
                child.aggregate.revoked = true;
                child.aggregate.tokens.clear();
                let record = &mut child.aggregate.record;
                record.continuation_token = None;
                record.interact_handle = None;
                record.interact_ref = None;
                record.as_nonce = None;
                record.interact_expires_at = None;
                record.grant.withhold_continuation();
                cascade.push(child);
            }
        }
        Ok(cascade)
    }
}

/// Reference single-process store. One lock publishes aggregates and all indexes.
///
/// Revoked/closed aggregates are retained until explicit maintenance removal.
/// Production stores must define retention and capacity limits. Removed IDs
/// are never reused. No policy, signature verification or token encoding runs
/// under this lock; local index hashing and the trusted clock callback do.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    state: Mutex<State>,
    nonces: Mutex<HashMap<String, u64>>,
}

impl MemoryStorage {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of grants currently reachable through a continuation token.
    /// # Errors
    /// Fails closed when the store lock is poisoned.
    pub fn len(&self) -> Result<usize, StoreError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .indices
            .continuation
            .len())
    }

    /// Whether no grant is currently continuable.
    /// # Errors
    /// Returns storage unavailability.
    pub fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(self.len()? == 0)
    }

    /// Number of locally remembered signature nonces.
    /// # Errors
    /// Returns storage unavailability.
    pub fn remembered_nonces(&self) -> Result<usize, StoreError> {
        Ok(self
            .nonces
            .lock()
            .map_err(|_| StoreError::Unavailable)?
            .len())
    }
}

impl GrantStore for MemoryStorage {
    fn create(&self, aggregate: GrantAggregate) -> Result<GrantSnapshot, StoreError> {
        if aggregate.record.request.existing_access_token.is_some()
            || aggregate
                .tokens
                .values()
                .any(|token| token.derivation.is_some())
        {
            return Err(StoreError::Invalid);
        }
        let mut state = self.state.lock().map_err(|_| StoreError::Unavailable)?;
        let next = state.last_id.checked_add(1).ok_or(StoreError::Exhausted)?;
        let id = GrantId(next);
        let indices = Indices::candidate(&aggregate, id)?;
        state.indices.check(&indices, id)?;
        let snapshot = GrantSnapshot {
            id,
            revision: Revision(0),
            aggregate,
        };
        state.publish(snapshot.clone(), indices);
        state.last_id = next;
        drop(state);
        Ok(snapshot)
    }

    fn create_derived(
        &self,
        parent: GrantId,
        revision: Revision,
        value: &TokenValue,
        child: GrantAggregate,
        clock: &dyn Fn() -> u64,
    ) -> Result<GrantSnapshot, StoreError> {
        let mut state = self.state.lock().map_err(|_| StoreError::Unavailable)?;
        let snapshot = state.grants.get(&parent).ok_or(StoreError::Conflict)?;
        if snapshot.revision != revision || snapshot.aggregate.revoked {
            return Err(StoreError::Conflict);
        }
        let source = snapshot
            .aggregate
            .tokens
            .values()
            .find(|token| &token.token.value == value)
            .ok_or(StoreError::Conflict)?;
        let now = clock();
        if !source.is_valid_at(now) {
            return Err(StoreError::Conflict);
        }
        let parent_exp = source.expires_at().ok_or(StoreError::Invalid)?;
        let origin = ParentToken::new(parent, value);
        if state.derived_origins.contains_key(&parent)
            || source.derivation.is_some()
            || source.identifier.is_some()
            || !source.token.flags.is_empty()
            || child.revoked
            || child.tokens.len() != 1
            || child.record.grant.state() != gnap_core::State::Approved
            || child.record.continuation_token.is_some()
            || child.record.interact_handle.is_some()
            || child.record.interact_ref.is_some()
            || child.record.interact_expires_at.is_some()
            || child.record.as_nonce.is_some()
            || child.record.interaction_completed
            || child.record.request.existing_access_token.is_some()
            || child.record.request.interact.is_some()
            || child.record.request.subject.is_some()
            || child.record.request.user.is_some()
        {
            return Err(StoreError::Invalid);
        }
        let token = child.tokens.values().next().ok_or(StoreError::Invalid)?;
        if !token.is_valid_at(now)
            || token.identifier.is_some()
            || !token.token.flags.is_empty()
            || token
                .token
                .expires_in
                .is_none_or(|ttl| ttl == 0 || ttl > MAX_DERIVED_LIFETIME)
            || token.expires_at().is_none_or(|expiry| expiry > parent_exp)
            || token
                .derivation
                .as_ref()
                .is_none_or(|metadata| metadata.parent != origin || metadata.audience.0.is_empty())
        {
            return Err(StoreError::Invalid);
        }
        let active_children = state
            .children
            .get(&origin)
            .into_iter()
            .flatten()
            .filter(|id| {
                state.grants.get(id).is_some_and(|child| {
                    !child.aggregate.revoked
                        && child
                            .aggregate
                            .tokens
                            .values()
                            .any(|token| token.is_valid_at(now))
                })
            })
            .count();
        if active_children >= MAX_DERIVED_CHILDREN {
            return Err(StoreError::DerivationLimit);
        }
        if state.derived_origins.len() >= MAX_DERIVED_GRANTS {
            return Err(StoreError::Exhausted);
        }
        let next = state.last_id.checked_add(1).ok_or(StoreError::Exhausted)?;
        let id = GrantId(next);
        let indices = Indices::candidate(&child, id)?;
        state.indices.check(&indices, id)?;
        let snapshot = GrantSnapshot {
            id,
            revision: Revision(0),
            aggregate: child,
        };
        state.derived_origins.insert(id, origin);
        state.publish(snapshot.clone(), indices);
        state.last_id = next;
        drop(state);
        Ok(snapshot)
    }

    fn lookup(&self, selector: GrantSelector<'_>) -> Result<Option<GrantSnapshot>, StoreError> {
        let state = self.state.lock().map_err(|_| StoreError::Unavailable)?;
        Ok(state
            .indices
            .locate(selector)
            .and_then(|id| state.grants.get(&id))
            .cloned())
    }

    fn compare_exchange(
        &self,
        id: GrantId,
        revision: Revision,
        replacement: GrantAggregate,
    ) -> Result<GrantSnapshot, StoreError> {
        let mut state = self.state.lock().map_err(|_| StoreError::Unavailable)?;
        let previous = state.grants.get(&id).ok_or(StoreError::Conflict)?;
        if previous.revision != revision || previous.aggregate.revoked {
            return Err(StoreError::Conflict);
        }
        if previous.aggregate.record.grant.state() == gnap_core::State::Finalized
            && replacement.record.grant.state() != gnap_core::State::Finalized
        {
            return Err(StoreError::Invalid);
        }
        if previous.aggregate.record.request.client != replacement.record.request.client {
            return Err(StoreError::Invalid);
        }
        if state.derived_origins.contains_key(&id) {
            // A child is one-shot: only removal of its token is allowed. No
            // reparenting, clearing provenance, rotation or renewed authority.
            if replacement.record.request != previous.aggregate.record.request
                || replacement.record.continuation_token.is_some()
                || replacement.tokens.iter().any(|(handle, token)| {
                    previous.aggregate.tokens.get(handle).is_none_or(|old| {
                        token.token != old.token
                            || token.client != old.client
                            || token.issued_at != old.issued_at
                            || token.identifier != old.identifier
                            || token.derivation != old.derivation
                            || token.management_token != old.management_token
                    })
                })
            {
                return Err(StoreError::Invalid);
            }
        } else if replacement.record.request.existing_access_token.is_some()
            || replacement
                .tokens
                .values()
                .any(|token| token.derivation.is_some())
        {
            return Err(StoreError::Invalid);
        }
        let cascade = state.cascade(previous, Some(&replacement))?;
        let next = revision.0.checked_add(1).ok_or(StoreError::Exhausted)?;
        let indices = Indices::candidate(&replacement, id)?;
        state.indices.check(&indices, id)?;
        let snapshot = GrantSnapshot {
            id,
            revision: Revision(next),
            aggregate: replacement,
        };
        for child in cascade {
            state.publish(child, Indices::default());
        }
        state.publish(snapshot.clone(), indices);
        drop(state);
        Ok(snapshot)
    }

    fn remove(&self, id: GrantId, revision: Revision) -> Result<(), StoreError> {
        let mut state = self.state.lock().map_err(|_| StoreError::Unavailable)?;
        let previous = state.grants.get(&id).ok_or(StoreError::Conflict)?;
        if previous.revision != revision {
            return Err(StoreError::Conflict);
        }
        let cascade = state.cascade(previous, None)?;
        for child in cascade {
            state.publish(child, Indices::default());
        }
        if let Some(parent) = state.derived_origins.remove(&id) {
            if let Some(children) = state.children.get_mut(&parent) {
                children.remove(&id);
                if children.is_empty() {
                    state.children.remove(&parent);
                }
            }
        }
        state.indices.replace(id, Indices::default());
        state.grants.remove(&id);
        drop(state);
        Ok(())
    }
}

impl NonceStore for MemoryStorage {
    fn remember_nonce(&self, nonce: &str, now: u64) -> bool {
        let Ok(mut seen) = self.nonces.lock() else {
            return false;
        };
        seen.retain(|_, first| now.saturating_sub(*first) <= NONCE_MEMORY);
        seen.insert(nonce.to_owned(), now).is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aggregate() -> GrantAggregate {
        GrantAggregate::new(GrantRecord {
            grant: Grant::new(),
            request: serde_json::from_str(r#"{"client":"client"}"#).unwrap(),
            continuation_token: Some("continuation".into()),
            as_nonce: None,
            interact_handle: None,
            interact_expires_at: None,
            interact_ref: None,
            interaction_completed: false,
        })
    }

    #[test]
    fn identity_overflow_publishes_nothing_and_purge_does_not_reset_it() {
        let storage = MemoryStorage::new();
        storage.state.lock().unwrap().last_id = u64::MAX - 1;
        let last = storage.create(aggregate()).unwrap();
        assert_eq!(last.id, GrantId(u64::MAX));
        storage.remove(last.id, last.revision).unwrap();
        assert!(matches!(
            storage.create(aggregate()),
            Err(StoreError::Exhausted)
        ));
        assert!(storage
            .lookup(GrantSelector::Continuation("continuation"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn revision_overflow_preserves_record_and_indexes() {
        let storage = MemoryStorage::new();
        let original = storage.create(aggregate()).unwrap();
        storage
            .state
            .lock()
            .unwrap()
            .grants
            .get_mut(&original.id)
            .unwrap()
            .revision = Revision(u64::MAX);
        let mut candidate = original.aggregate;
        candidate.record.continuation_token = Some("replacement".into());
        assert!(matches!(
            storage.compare_exchange(original.id, Revision(u64::MAX), candidate),
            Err(StoreError::Exhausted)
        ));
        assert_eq!(
            storage
                .lookup(GrantSelector::Continuation("continuation"))
                .unwrap()
                .unwrap()
                .revision,
            Revision(u64::MAX)
        );
        assert!(storage
            .lookup(GrantSelector::Continuation("replacement"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn poisoned_locks_are_failures_not_absence_or_replay_acceptance() {
        let storage = MemoryStorage::new();
        let _ = std::panic::catch_unwind(|| {
            let _lock = storage.state.lock().unwrap();
            panic!("poison aggregate state");
        });
        assert!(matches!(
            storage.lookup(GrantSelector::Id(GrantId(1))),
            Err(StoreError::Unavailable)
        ));
        assert!(matches!(
            storage.create(aggregate()),
            Err(StoreError::Unavailable)
        ));
        assert!(matches!(
            storage.compare_exchange(GrantId(1), Revision(0), aggregate()),
            Err(StoreError::Unavailable)
        ));
        assert_eq!(
            storage.remove(GrantId(1), Revision(0)),
            Err(StoreError::Unavailable)
        );
        assert_eq!(storage.len(), Err(StoreError::Unavailable));
        let _ = std::panic::catch_unwind(|| {
            let _lock = storage.nonces.lock().unwrap();
            panic!("poison replay state");
        });
        assert!(!storage.remember_nonce("fresh", 1_000));
        assert_eq!(storage.remembered_nonces(), Err(StoreError::Unavailable));
    }
}
