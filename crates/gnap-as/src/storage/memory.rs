//! The in-memory reference store: every index and lock behind one mutex.

use super::{
    DerivedGrantStore, GrantAggregate, GrantId, GrantSelector, GrantSnapshot, GrantStore,
    NonceStore, Revision, RotationNonceStore, StoreError, UserCodeStore,
};
use crate::derivation::{
    ParentToken, MAX_DERIVED_CHILDREN, MAX_DERIVED_GRANTS, MAX_DERIVED_LIFETIME,
};
use crate::server::MAX_CLOCK_SKEW;
use gnap_types::token::TokenValue;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

const NONCE_MEMORY: u64 = 2 * MAX_CLOCK_SKEW;

#[derive(Debug, Default)]
struct Indices {
    continuation: HashMap<String, GrantId>,
    interaction: HashMap<String, GrantId>,
    user_codes: HashMap<String, GrantId>,
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
                || aggregate.record.user_code.is_some()
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
        if let Some(code) = &aggregate.record.user_code {
            if !crate::user_code::is_canonical(code)
                || aggregate.record.interact_handle.is_none()
                || aggregate.record.interact_expires_at.is_none()
                || aggregate.record.grant.state() != gnap_core::State::Pending
                || aggregate.record.interaction_completed
            {
                return Err(StoreError::Invalid);
            }
            indices.user_codes.insert(code.clone(), id);
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
            || collides(&self.user_codes, &candidate.user_codes, own_id)
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
        self.user_codes.retain(|_, owner| *owner != id);
        self.management.retain(|_, owner| *owner != id);
        self.values.retain(|_, owner| *owner != id);
        self.identifiers.retain(|_, owner| *owner != id);
        self.credentials.retain(|_, (owner, _)| *owner != id);
        self.continuation.extend(candidate.continuation);
        self.interaction.extend(candidate.interaction);
        self.user_codes.extend(candidate.user_codes);
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
                record.user_code = None;
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

impl UserCodeStore for MemoryStorage {
    fn lookup_user_code(&self, code: &str) -> Result<Option<GrantSnapshot>, StoreError> {
        let state = self.state.lock().map_err(|_| StoreError::Unavailable)?;
        Ok(state
            .indices
            .user_codes
            .get(code)
            .and_then(|id| state.grants.get(id))
            .cloned())
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

impl DerivedGrantStore for MemoryStorage {
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
            || child.record.user_code.is_some()
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

impl RotationNonceStore for MemoryStorage {
    fn remember_nonce_pair(
        &self,
        previous: Option<&str>,
        replacement: Option<&str>,
        now: u64,
    ) -> bool {
        if previous.is_some() && previous == replacement {
            return false;
        }
        let Ok(mut seen) = self.nonces.lock() else {
            return false;
        };
        seen.retain(|_, first| now.saturating_sub(*first) <= NONCE_MEMORY);
        if [previous, replacement]
            .into_iter()
            .flatten()
            .any(|nonce| seen.contains_key(nonce))
        {
            return false;
        }
        for nonce in [previous, replacement].into_iter().flatten() {
            seen.insert(nonce.to_owned(), now);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{GrantRecord, TokenRecord};
    use gnap_core::Grant;
    use gnap_types::client::Client;
    use gnap_types::token::AccessToken;

    fn aggregate() -> GrantAggregate {
        GrantAggregate::new(GrantRecord {
            grant: Grant::new(),
            request: serde_json::from_str(r#"{"client":"client"}"#).unwrap(),
            continuation_token: Some("continuation".into()),
            as_nonce: None,
            user_code: None,
            interact_handle: None,
            interact_expires_at: None,
            interact_ref: None,
            interaction_completed: false,
        })
    }

    #[test]
    fn debug_output_hides_every_credential() {
        let mut aggregate = aggregate();
        aggregate.record.continuation_token = Some("SECRET-CONTINUATION".into());
        aggregate.record.as_nonce = Some("SECRET-NONCE".into());
        aggregate.record.interact_handle = Some("SECRET-HANDLE".into());
        aggregate.record.user_code = Some("SECRET-CODE".into());
        aggregate.record.interact_ref = Some("SECRET-REF".into());
        let token: AccessToken = serde_json::from_str(
            r#"{"value":"SECRET-ACCESS","access":["read"],"manage":{"uri":"https://as.example/token/1","access_token":{"value":"SECRET-MANAGE"}}}"#,
        )
        .unwrap();
        let record = TokenRecord::new(
            token,
            Client::ByReference("client".into()),
            "SECRET-MANAGEMENT",
            0,
        );
        let shown = format!("{:?} {record:?}", aggregate.record);
        assert!(!shown.contains("SECRET"), "a credential leaked: {shown}");
        assert!(shown.contains("Some(<redacted>)"));
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
