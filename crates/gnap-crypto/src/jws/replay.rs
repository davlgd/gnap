//! Replay protection for JWS proofs.

use sha2::{Digest as _, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;

/// The identity of an accepted JWS proof, for replay protection.
///
/// It digests the key's identity, the protected header, and the payload, and
/// not the signature: an `ES256` signature is malleable, and a second
/// encoding of the same proof must not count as a new one. Two requests
/// identical to the second, by the same key, share an identifier, so such a
/// request can't be retried as is: the client signs it again.
///
/// Two identifiers are equal, and hash alike, when their digests are: the
/// creation time isn't part of the identity.
#[derive(Debug, Clone, Copy)]
pub struct ReplayId {
    digest: [u8; 32],
    created: u64,
}

impl ReplayId {
    /// Derives the identifier of a proof. Each part is prefixed by its
    /// length, so that no two inputs share an encoding.
    pub(super) fn new(key_identity: &str, protected: &str, payload: &str, created: u64) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"gnap-jws-replay\0");
        for part in [key_identity, protected, payload] {
            digest.update((part.len() as u64).to_be_bytes());
            digest.update(part.as_bytes());
        }
        Self {
            digest: digest.finalize().into(),
            created,
        }
    }

    /// The digest that identifies the proof.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// The `created` of the proof, in seconds since the Unix epoch, from
    /// which the memory computes how long to hold the identifier.
    #[must_use]
    pub const fn created(&self) -> u64 {
        self.created
    }
}

impl PartialEq for ReplayId {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest
    }
}

impl Eq for ReplayId {}

impl core::hash::Hash for ReplayId {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.digest.hash(state);
    }
}

/// Where a verifier reserves the JWS proofs it accepts.
///
/// The verifier calls it once per request, after every other check has
/// passed, with one identifier for an ordinary proof and two for a key
/// rotation. An implementation has to:
///
/// - **reserve atomically**: record every identifier, or none if any is
///   already held, in one operation, so that two concurrent requests can't
///   both succeed;
/// - **own its window**: hold each identifier through its
///   [`ReplayId::created`] plus the largest clock skew any verifier using the
///   memory tolerates, that second included, and refuse a proof whose
///   `created` is farther than that from the latest time it has seen. The
///   memory can't take the window from each call: a proof forgotten under a
///   narrow window would be accepted again under a wider one, or after the
///   clock went back;
/// - **refuse when full** rather than evict an identifier still within its
///   retention, which would make its proof replayable;
/// - stay **separate from the nonces of `httpsig`**, which a client chooses:
///   a shared namespace would let a chosen nonce collide with a digest.
///
/// [`ReplayCache`] does all four within one process. A closure
/// `Fn(&[ReplayId], u64) -> bool` implements the trait too.
pub trait JwsReplayMemory {
    /// Reserves every identifier at `now`, returning `false`, and reserving
    /// none, if any of them is already held or the memory can't hold them.
    fn reserve(&self, ids: &[ReplayId], now: u64) -> bool;
}

impl<F: Fn(&[ReplayId], u64) -> bool> JwsReplayMemory for F {
    fn reserve(&self, ids: &[ReplayId], now: u64) -> bool {
        self(ids, now)
    }
}

/// A bounded in-process [`JwsReplayMemory`].
///
/// It has its own clock skew, the window of the trait's contract, and never
/// lets its clock go back: it reasons from the latest `now` it has seen. It
/// forgets an identifier once that window has passed, and refuses a
/// reservation that would exceed its capacity. A deployment of several
/// verifiers needs a memory they share instead.
#[derive(Debug)]
pub struct ReplayCache {
    capacity: usize,
    max_clock_skew: u64,
    state: Mutex<CacheState>,
}

#[derive(Debug, Default)]
struct CacheState {
    latest: u64,
    held: HashMap<[u8; 32], u64>,
    by_expiry: BTreeSet<(u64, [u8; 32])>,
}

impl ReplayCache {
    /// A cache that holds at most `capacity` identifiers at once, and accepts
    /// proofs created within `max_clock_skew` seconds of its clock: give it
    /// the largest skew of the verifiers that use it. It refuses a proof
    /// outside its own window even when the verifier's tolerance is wider.
    #[must_use]
    pub fn new(capacity: usize, max_clock_skew: u64) -> Self {
        Self {
            capacity,
            max_clock_skew,
            state: Mutex::new(CacheState::default()),
        }
    }

    /// How many identifiers the cache holds, expired ones included until the
    /// next reservation forgets them.
    #[must_use]
    pub fn len(&self) -> usize {
        self.state.lock().map_or(0, |state| state.held.len())
    }

    /// Whether the cache holds no identifier.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl JwsReplayMemory for ReplayCache {
    fn reserve(&self, ids: &[ReplayId], now: u64) -> bool {
        // A poisoned lock may hide a half-made reservation: refuse.
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        state.latest = state.latest.max(now);
        let now = state.latest;
        while let Some(&(keep_until, digest)) = state.by_expiry.first() {
            if keep_until >= now {
                break;
            }
            state.by_expiry.pop_first();
            state.held.remove(&digest);
        }
        if ids
            .iter()
            .any(|id| id.created.abs_diff(now) > self.max_clock_skew)
        {
            return false;
        }
        let distinct = ids
            .iter()
            .enumerate()
            .all(|(i, id)| ids[..i].iter().all(|other| other.digest != id.digest));
        if !distinct
            || ids.iter().any(|id| state.held.contains_key(&id.digest))
            || state.held.len().saturating_add(ids.len()) > self.capacity
        {
            return false;
        }
        for id in ids {
            let keep_until = id.created.saturating_add(self.max_clock_skew);
            state.held.insert(id.digest, keep_until);
            state.by_expiry.insert((keep_until, id.digest));
        }
        true
    }
}
