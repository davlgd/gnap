//! The guarantees the store itself has to make.
//!
//! §4.2 asks the AS to create the interaction reference, bind it to the pending
//! request and spend the interaction. Those are three writes that have to land
//! as one, and that is a property of the store, not of the caller.

use gnap_as::{GrantRecord, GrantStore, MemoryStorage};
use gnap_core::Grant;
use std::sync::{Arc, Barrier};

fn pending(token: &str, handle: &str) -> GrantRecord {
    GrantRecord {
        grant: Grant::new(),
        request: serde_json::from_str(r#"{"client":"client-541-ab"}"#).unwrap(),
        continuation_token: token.to_owned(),
        as_nonce: Some("as-nonce".into()),
        interact_handle: Some(handle.to_owned()),
        interact_expires_at: None,
        interact_ref: None,
        interaction_completed: false,
    }
}

/// GNAP-9635-§4.2 — an interaction is completed once, by one caller.
///
/// Two completions racing on the same handle would each issue a reference, and
/// the client would be holding the one that lost. The store settles it: the
/// handle is cleared inside the same lock that decides, so the second caller
/// finds nothing to complete.
#[test]
fn two_threads_cannot_complete_the_same_interaction() {
    let storage = Arc::new(MemoryStorage::new());
    storage.put("token-1", pending("token-1", "handle-1"));

    // Both threads have to be running before either proceeds, or the race the
    // test is about never happens.
    let start = Arc::new(Barrier::new(2));
    let complete = || {
        let storage = Arc::clone(&storage);
        let start = Arc::clone(&start);
        move || {
            start.wait();
            let mut completed = false;
            storage.update_by_interaction("handle-1", &mut |record| {
                // What the AS does: refuse a handle already spent, then spend
                // it in the same breath.
                if record.interact_handle.is_none() {
                    return false;
                }
                record.interact_handle = None;
                record.interact_ref = Some("the-reference".into());
                record.interaction_completed = true;
                completed = true;
                true
            });
            completed
        }
    };

    let winners = std::thread::scope(|scope| {
        let first = scope.spawn(complete());
        let second = scope.spawn(complete());
        [first.join().unwrap(), second.join().unwrap()]
    });

    assert_eq!(
        winners.iter().filter(|w| **w).count(),
        1,
        "exactly one completion may win the race"
    );

    let record = storage.get("token-1").expect("the grant survives");
    assert_eq!(record.interact_handle, None, "the handle is spent");
    assert_eq!(record.interact_ref.as_deref(), Some("the-reference"));
}

/// A refused completion leaves the grant exactly as it was.
#[test]
fn a_refused_completion_writes_nothing() {
    let storage = MemoryStorage::new();
    storage.put("token-1", pending("token-1", "handle-1"));

    let found = storage.update_by_interaction("handle-1", &mut |record| {
        record.interact_ref = Some("never-issued".into());
        record.interaction_completed = true;
        false
    });

    assert!(found, "the handle names a grant");
    let record = storage.get("token-1").unwrap();
    assert_eq!(record.interact_ref, None);
    assert!(!record.interaction_completed);
    assert_eq!(record.interact_handle.as_deref(), Some("handle-1"));

    assert!(
        !storage.update_by_interaction("handle-2", &mut |_| true),
        "an unknown handle names nothing"
    );
}

/// A store behind an `Arc`, or borrowed, is the same store: a deployment that
/// runs an AS and a resource server over one set of records hands each an
/// `Arc` of it, and both have to see every write the other makes.
#[test]
fn a_shared_store_is_the_store_itself() {
    use gnap_as::{NonceStore, Storage, TokenRecord, TokenStore};

    fn accepts<S: Storage>(_: &S) {}

    let inner = MemoryStorage::new();
    let shared = Arc::new(inner);
    let borrowed: &MemoryStorage = &shared;
    accepts(&shared);
    accepts(&borrowed);

    // Grants: written through one owner, taken through another, gone for both.
    shared.put("token-1", pending("token-1", "handle-1"));
    assert!(borrowed.update_by_interaction("handle-1", &mut |record| {
        record.interaction_completed = true;
        true
    }));
    let taken = Arc::clone(&shared)
        .take("token-1")
        .expect("the same record");
    assert!(taken.interaction_completed);
    assert!(shared.get("token-1").is_none());

    // Tokens: the same handle names the same record on every side.
    let issued = TokenRecord {
        identifier: None,
        issued_at: 1_000,
        token: serde_json::from_str(r#"{"value":"AAA","access":["read"]}"#).unwrap(),
        client: serde_json::from_str(r#""client-541-ab""#).unwrap(),
        management_token: "MMM".into(),
    };
    borrowed.put_token("handle-t", issued);
    assert!(shared.get_token("handle-t").is_some());
    assert!(shared.take_token("handle-t").is_some());
    assert!(borrowed.get_token("handle-t").is_none());

    // Nonces: spent once, whoever spends it.
    assert!(shared.remember_nonce("n", 1_000));
    assert!(!borrowed.remember_nonce("n", 1_000));
}
#[test]
fn token_record_lifetime_boundaries_and_invalid_external_records() {
    let mut record = gnap_as::TokenRecord {
        identifier: None,
        issued_at: 100,
        token: serde_json::from_str(r#"{"value":"AAA","expires_in":20}"#).unwrap(),
        client: serde_json::from_str(r#""client""#).unwrap(),
        management_token: "MMM".into(),
    };
    assert_eq!(record.expires_at(), Some(120));
    assert!(!record.is_valid_at(99));
    assert!(record.is_valid_at(100));
    assert!(record.is_valid_at(119));
    assert!(!record.is_valid_at(120));
    assert!(!record.is_valid_at(u64::MAX));
    record.token.expires_in = None;
    assert_eq!(record.expires_at(), None);
    assert!(!record.is_valid_at(99));
    assert!(record.is_valid_at(u64::MAX));
    for lifetime in [0, u64::MAX] {
        record.token.expires_in = Some(lifetime);
        assert_eq!(record.expires_at(), Some(100));
        assert!(!record.is_valid_at(100));
        assert!(!record.is_valid_at(u64::MAX));
    }
    record.issued_at = u64::MAX - 1;
    record.token.expires_in = Some(1);
    assert_eq!(record.expires_at(), Some(u64::MAX));
    assert!(record.is_valid_at(u64::MAX - 1));
    assert!(!record.is_valid_at(u64::MAX));
}
