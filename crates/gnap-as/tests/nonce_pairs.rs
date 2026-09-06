//! The production memory adapter reserves a key-rotation nonce pair atomically.

use gnap_as::{MemoryStorage, NonceStore, RotationNonceStore};
use std::sync::{Arc, Barrier};

const NOW: u64 = 1_700_000_000;

#[test]
fn a_replayed_nonce_never_consumes_the_other_half() {
    for spent_is_old in [false, true] {
        let storage = MemoryStorage::new();
        assert!(storage.remember_nonce("spent", NOW));
        let (old, new) = if spent_is_old {
            ("spent", "fresh")
        } else {
            ("fresh", "spent")
        };
        assert!(!storage.remember_nonce_pair(Some(old), Some(new), NOW));
        assert!(storage.remember_nonce("fresh", NOW));
    }
}

#[test]
fn accepted_pairs_share_the_ordinary_nonce_namespace_through_both_adapters() {
    let storage = Arc::new(MemoryStorage::new());
    assert!(storage.remember_nonce_pair(Some("old"), Some("new"), NOW));
    let forwarded: &dyn RotationNonceStore = &storage;
    assert!(!forwarded.remember_nonce("old", NOW));
    assert!(!forwarded.remember_nonce("new", NOW));
    assert!(!forwarded.remember_nonce_pair(Some("old"), Some("unused"), NOW));
    assert!(forwarded.remember_nonce("unused", NOW));
}

#[test]
fn equal_nonces_are_refused_without_consumption_and_absent_nonces_need_no_entry() {
    let storage = MemoryStorage::new();
    assert!(!storage.remember_nonce_pair(Some("same"), Some("same"), NOW));
    assert!(storage.remember_nonce("same", NOW));
    assert!(storage.remember_nonce_pair(None, None, NOW));
    assert!(storage.remember_nonce_pair(None, Some("one"), NOW));
    assert!(!storage.remember_nonce_pair(Some("one"), None, NOW));
    assert!(storage.remember_nonce_pair(Some("two"), None, NOW));
    assert!(!storage.remember_nonce("two", NOW));
}

#[test]
fn two_pairs_with_a_shared_old_nonce_cannot_both_commit() {
    let storage = MemoryStorage::new();
    let barrier = Barrier::new(2);
    let outcomes = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            storage.remember_nonce_pair(Some("old"), Some("one"), NOW)
        });
        let second = scope.spawn(|| {
            barrier.wait();
            storage.remember_nonce_pair(Some("old"), Some("two"), NOW)
        });
        [first.join().unwrap(), second.join().unwrap()]
    });
    assert_eq!(outcomes.into_iter().filter(|accepted| *accepted).count(), 1);
    assert!(!storage.remember_nonce("old", NOW));
    let unused = if outcomes[0] { "two" } else { "one" };
    assert!(storage.remember_nonce(unused, NOW));
}

#[test]
fn a_pair_and_an_ordinary_request_share_one_transaction_boundary() {
    let storage = MemoryStorage::new();
    let barrier = Barrier::new(2);
    let (pair, ordinary) = std::thread::scope(|scope| {
        let pair = scope.spawn(|| {
            barrier.wait();
            storage.remember_nonce_pair(Some("old"), Some("new"), NOW)
        });
        let ordinary = scope.spawn(|| {
            barrier.wait();
            storage.remember_nonce("old", NOW)
        });
        (pair.join().unwrap(), ordinary.join().unwrap())
    });
    assert_ne!(pair, ordinary);
    assert_eq!(storage.remember_nonce("new", NOW), ordinary);
}

#[test]
fn pair_retention_covers_both_clock_skews_and_refusal_does_not_renew_it() {
    let storage = MemoryStorage::new();
    let window = 2 * gnap_as::MAX_CLOCK_SKEW;
    assert!(storage.remember_nonce_pair(Some("old"), Some("new"), NOW));
    assert!(!storage.remember_nonce_pair(Some("old"), Some("unspent"), NOW + window));
    assert!(storage.remember_nonce_pair(Some("old"), Some("new"), NOW + window + 1));
    assert!(storage.remember_nonce("unspent", NOW + window + 1));
}
