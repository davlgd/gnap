//! Where the AS keeps its grants.
//!
//! §1.5 notes that GNAP is a stateful protocol and that a stateless deployment
//! still needs a way to track a grant "in a secure and deterministic fashion".
//! The means are left to the implementation, hence this trait.

use crate::server::MAX_CLOCK_SKEW;
use gnap_core::Grant;
use gnap_types::client::Client;
use gnap_types::message::GrantRequest;
use gnap_types::token::AccessToken;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

/// Everything the AS remembers about one grant request.
#[derive(Debug, Clone)]
pub struct GrantRecord {
    /// The protocol state (§1.5).
    pub grant: Grant,
    /// The request as it was last received, after any modification (§5.3).
    pub request: GrantRequest,
    /// The continuation token value the client must present (§3.1).
    pub continuation_token: String,
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
    /// The token as it was issued, in the §3.2.1 format.
    pub token: AccessToken,
    /// The client it was issued to, which is how its key is resolved (§6).
    pub client: Client,
    /// The token that protects the management API (§3.2.1).
    pub management_token: String,
}

/// Where the AS keeps grant requests, by continuation token (§5).
///
/// The token is the handle: §5 requires the AS to identify the grant from the
/// continuation URI, the continuation token, or both.
///
/// This is one of three stores the server needs, and they are separate traits
/// on purpose. They hold different things with different lifetimes — a grant
/// lives until it is finalized, an issued token until it is revoked, a nonce
/// for minutes — and a deployment will often want them in different places. A
/// single type may implement all three, as [`MemoryStorage`] does.
pub trait GrantStore {
    /// Stores a new or updated grant.
    fn put(&self, token: &str, record: GrantRecord);

    /// Retrieves a grant by its continuation token, without consuming it.
    fn get(&self, token: &str) -> Option<GrantRecord>;

    /// Takes the grant a continuation token names, removing it in one step.
    ///
    /// §5 rotates the continuation token on every call, so the old one must
    /// stop working the moment it is used. Reading and removing separately
    /// leaves a window in which two concurrent calls both succeed and the grant
    /// forks; this is the operation that closes it.
    fn take(&self, token: &str) -> Option<GrantRecord>;

    /// Runs `update` on the grant an interaction handle names, atomically.
    ///
    /// §4.2 has the AS create the interaction reference, associate it with "the
    /// current interaction and the underlying pending request", and spend the
    /// interaction — three writes that have to land as one. Reading a copy,
    /// deciding, and writing it back leaves a window in which a concurrent
    /// continuation takes the grant and the late write puts it back, reviving a
    /// request that was already finished.
    ///
    /// Returns `false` when no grant is waiting on this handle. When `update`
    /// returns `false` the record is left exactly as it was, so a completion
    /// the AS refuses costs the grant nothing.
    fn update_by_interaction(
        &self,
        handle: &str,
        update: &mut dyn FnMut(&mut GrantRecord) -> bool,
    ) -> bool;
}

/// Where the AS keeps the tokens it issued, by management handle (§6).
///
/// Only a token that offers a `manage` field needs to be here: this store is
/// what makes §6 answerable, and an AS that issues no management API needs
/// none of it.
pub trait TokenStore {
    /// Stores an issued access token under its management handle (§6).
    ///
    /// The handle is what the AS puts in the management URI. §6-M04 requires
    /// the AS to "uniquely identify the token being managed from the token
    /// management URI, the token management access token, or a combination of
    /// both"; this server uses both, so the handle finds the record and the
    /// management token still has to match it.
    fn put_token(&self, handle: &str, record: TokenRecord);

    /// Takes the token a management handle names, removing it in one step.
    ///
    /// Rotation replaces a token and revocation destroys it; both have to be
    /// atomic, for the same reason continuation does (§6.1, §6.2).
    fn take_token(&self, handle: &str) -> Option<TokenRecord>;

    /// Reads an issued token without consuming it.
    ///
    /// The client's key is only known through the record, and it has to be read
    /// before the request can be verified — so reading and consuming are two
    /// steps here, exactly as they are for a continuation call.
    fn get_token(&self, handle: &str) -> Option<TokenRecord>;
}

/// Where the AS remembers the signature nonces it has already seen (§7.3.1).
///
/// The shortest-lived of the three, and the one most likely to live somewhere
/// else: a shared cache in front of several servers, rather than a database.
pub trait NonceStore {
    /// Records a signature nonce, returning `false` if it was already seen.
    ///
    /// §7.3.1: "the verifier MUST determine that the nonce value is unique
    /// within a reasonably short time period such as several minutes". A real
    /// deployment bounds this set by time; [`MemoryStorage`] keeps a nonce for
    /// as long as a signature carrying it could still be accepted, and drops it
    /// after that.
    fn remember_nonce(&self, nonce: &str, now: u64) -> bool;
}

/// Everything the server stores, in one bound.
///
/// A convenience, so a signature reads `S: Storage` rather than naming the
/// three. Implementing the three is what gives you this one.
pub trait Storage: GrantStore + TokenStore + NonceStore {}

impl<T: GrantStore + TokenStore + NonceStore> Storage for T {}

// A store behind a shared or borrowed pointer is the same store. The server
// takes its storage by value, and a deployment that also runs a resource
// server, or several servers, over the same records hands each of them an
// `Arc` of it; without these, every such deployment writes the same three
// forwarding impls on a newtype of its own.

impl<T: GrantStore + ?Sized> GrantStore for Arc<T> {
    fn put(&self, token: &str, record: GrantRecord) {
        (**self).put(token, record);
    }
    fn get(&self, token: &str) -> Option<GrantRecord> {
        (**self).get(token)
    }
    fn take(&self, token: &str) -> Option<GrantRecord> {
        (**self).take(token)
    }
    fn update_by_interaction(
        &self,
        handle: &str,
        update: &mut dyn FnMut(&mut GrantRecord) -> bool,
    ) -> bool {
        (**self).update_by_interaction(handle, update)
    }
}

impl<T: GrantStore + ?Sized> GrantStore for &T {
    fn put(&self, token: &str, record: GrantRecord) {
        (**self).put(token, record);
    }
    fn get(&self, token: &str) -> Option<GrantRecord> {
        (**self).get(token)
    }
    fn take(&self, token: &str) -> Option<GrantRecord> {
        (**self).take(token)
    }
    fn update_by_interaction(
        &self,
        handle: &str,
        update: &mut dyn FnMut(&mut GrantRecord) -> bool,
    ) -> bool {
        (**self).update_by_interaction(handle, update)
    }
}

impl<T: TokenStore + ?Sized> TokenStore for Arc<T> {
    fn put_token(&self, handle: &str, record: TokenRecord) {
        (**self).put_token(handle, record);
    }
    fn take_token(&self, handle: &str) -> Option<TokenRecord> {
        (**self).take_token(handle)
    }
    fn get_token(&self, handle: &str) -> Option<TokenRecord> {
        (**self).get_token(handle)
    }
}

impl<T: TokenStore + ?Sized> TokenStore for &T {
    fn put_token(&self, handle: &str, record: TokenRecord) {
        (**self).put_token(handle, record);
    }
    fn take_token(&self, handle: &str) -> Option<TokenRecord> {
        (**self).take_token(handle)
    }
    fn get_token(&self, handle: &str) -> Option<TokenRecord> {
        (**self).get_token(handle)
    }
}

impl<T: NonceStore + ?Sized> NonceStore for Arc<T> {
    fn remember_nonce(&self, nonce: &str, now: u64) -> bool {
        (**self).remember_nonce(nonce, now)
    }
}

impl<T: NonceStore + ?Sized> NonceStore for &T {
    fn remember_nonce(&self, nonce: &str, now: u64) -> bool {
        (**self).remember_nonce(nonce, now)
    }
}

/// How long a nonce stays remembered.
///
/// A signature is accepted while its `created` sits within [`MAX_CLOCK_SKEW`]
/// of now, on either side, so the same nonce can come back for at most twice
/// that span. Past it the `created` check refuses the replay on its own and
/// holding the nonce any longer would only grow the set.
const NONCE_MEMORY: u64 = 2 * MAX_CLOCK_SKEW;

/// An in-memory store, enough for tests and single-process deployments.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    grants: Mutex<HashMap<String, GrantRecord>>,
    tokens: Mutex<HashMap<String, TokenRecord>>,
    nonces: Mutex<HashMap<String, u64>>,
}

impl MemoryStorage {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many grants are held.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the store holds nothing.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How many nonces are remembered.
    pub fn remembered_nonces(&self) -> usize {
        self.nonces
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, GrantRecord>> {
        // A poisoned lock means another thread panicked mid-update. The map is
        // still structurally sound, so recovering beats bringing the AS down.
        self.grants.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl GrantStore for MemoryStorage {
    fn put(&self, token: &str, record: GrantRecord) {
        self.lock().insert(token.to_owned(), record);
    }

    fn get(&self, token: &str) -> Option<GrantRecord> {
        self.lock().get(token).cloned()
    }

    fn take(&self, token: &str) -> Option<GrantRecord> {
        // One lock, one lookup, one removal: no window for a second caller.
        self.lock().remove(token)
    }

    #[allow(clippy::significant_drop_tightening)]
    fn update_by_interaction(
        &self,
        handle: &str,
        update: &mut dyn FnMut(&mut GrantRecord) -> bool,
    ) -> bool {
        // Holding the lock across the whole read-decide-write is the point of
        // this method, so the usual advice to narrow its scope does not apply.
        let mut grants = self.lock();
        let Some(record) = grants
            .values_mut()
            .find(|record| record.interact_handle.as_deref() == Some(handle))
        else {
            return false;
        };

        // The update works on a copy, so refusing leaves the original intact.
        let mut candidate = record.clone();
        if update(&mut candidate) {
            *record = candidate;
        }
        true
    }
}

impl TokenStore for MemoryStorage {
    fn put_token(&self, handle: &str, record: TokenRecord) {
        self.tokens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(handle.to_owned(), record);
    }

    fn take_token(&self, handle: &str) -> Option<TokenRecord> {
        self.tokens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(handle)
    }

    fn get_token(&self, handle: &str) -> Option<TokenRecord> {
        self.tokens
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(handle)
            .cloned()
    }
}

impl NonceStore for MemoryStorage {
    fn remember_nonce(&self, nonce: &str, now: u64) -> bool {
        let mut seen = self.nonces.lock().unwrap_or_else(PoisonError::into_inner);
        // Expiring on the way in keeps the set bounded without a background
        // task. It costs one pass over a set whose size is the traffic of the
        // last few minutes, which is the trade a reference store should make.
        seen.retain(|_, first| now.saturating_sub(*first) <= NONCE_MEMORY);
        seen.insert(nonce.to_owned(), now).is_none()
    }
}
