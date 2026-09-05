//! Atomic aggregate publication, independent of protocol and cryptographic work.

use gnap_as::{
    GrantAggregate, GrantId, GrantRecord, GrantSelector, GrantStore, MemoryStorage, NonceStore,
    Revision, Storage, StoreError, TokenRecord,
};
use gnap_core::Grant;
use std::sync::Arc;

fn pending(token: &str, handle: &str) -> GrantAggregate {
    GrantAggregate::new(GrantRecord {
        grant: Grant::new(),
        request: serde_json::from_str(r#"{"client":"client"}"#).unwrap(),
        continuation_token: Some(token.into()),
        as_nonce: Some("as-nonce".into()),
        interact_handle: Some(handle.into()),
        interact_expires_at: None,
        interact_ref: None,
        interaction_completed: false,
    })
}

fn issued(value: &str, identifier: &[u8]) -> TokenRecord {
    TokenRecord {
        identifier: Some(identifier.into()),
        issued_at: 1_000,
        token: serde_json::from_value(serde_json::json!({"value":value,"access":["read"]}))
            .unwrap(),
        client: serde_json::from_str(r#""client""#).unwrap(),
        management_token: format!("management-{value}"),
    }
}

fn populated(suffix: &str) -> GrantAggregate {
    let mut aggregate = pending(&format!("continue-{suffix}"), &format!("interact-{suffix}"));
    aggregate.tokens.insert(
        format!("handle-{suffix}"),
        issued(&format!("value-{suffix}"), suffix.as_bytes()),
    );
    aggregate
}

/// Both callers prepare from the same revision; only one may spend the handle.
#[test]
fn two_callers_cannot_complete_the_same_interaction() {
    let storage = Arc::new(MemoryStorage::new());
    let original = storage.create(pending("token", "handle")).unwrap();
    let first = storage
        .lookup(GrantSelector::Interaction("handle"))
        .unwrap()
        .unwrap();
    let second = storage
        .lookup(GrantSelector::Interaction("handle"))
        .unwrap()
        .unwrap();
    let complete = |mut snapshot: gnap_as::GrantSnapshot| {
        let storage = Arc::clone(&storage);
        std::thread::spawn(move || {
            snapshot.aggregate.record.interact_handle = None;
            snapshot.aggregate.record.interact_ref = Some("reference".into());
            snapshot.aggregate.record.interaction_completed = true;
            storage.compare_exchange(snapshot.id, snapshot.revision, snapshot.aggregate)
        })
    };
    let first = complete(first);
    let second = complete(second);
    let outcomes = [first.join().unwrap(), second.join().unwrap()];
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(StoreError::Conflict)))
            .count(),
        1
    );
    let current = storage
        .lookup(GrantSelector::Id(original.id))
        .unwrap()
        .unwrap();
    assert_eq!(current.revision, Revision(1));
    assert_eq!(
        current.aggregate.record.interact_ref.as_deref(),
        Some("reference")
    );
    assert!(storage
        .lookup(GrantSelector::Interaction("handle"))
        .unwrap()
        .is_none());
}

#[test]
fn abandoned_and_stale_candidates_write_nothing() {
    let storage = MemoryStorage::new();
    let original = storage.create(pending("token", "handle")).unwrap();
    let mut candidate = original.aggregate.clone();
    candidate.record.interact_ref = Some("not-issued".into());
    candidate.record.interaction_completed = true;
    assert_eq!(
        storage
            .lookup(GrantSelector::Id(original.id))
            .unwrap()
            .unwrap()
            .aggregate
            .record
            .interact_ref,
        None
    );
    assert!(matches!(
        storage.compare_exchange(original.id, Revision(42), candidate),
        Err(StoreError::Conflict)
    ));
    let current = storage
        .lookup(GrantSelector::Id(original.id))
        .unwrap()
        .unwrap();
    assert_eq!(current.revision, Revision(0));
    assert!(!current.aggregate.record.interaction_completed);
    assert_eq!(
        current.aggregate.record.interact_handle.as_deref(),
        Some("handle")
    );
}

#[test]
fn a_shared_store_is_the_store_itself() {
    fn accepts<S: Storage>(_: &S) {}
    let shared = Arc::new(MemoryStorage::new());
    let borrowed: &MemoryStorage = &shared;
    accepts(&shared);
    accepts(&borrowed);
    let original = shared.create(populated("one")).unwrap();
    let mut candidate = borrowed
        .lookup(GrantSelector::Management("handle-one"))
        .unwrap()
        .unwrap();
    candidate.aggregate.record.continuation_token = Some("next".into());
    let updated = borrowed
        .compare_exchange(candidate.id, candidate.revision, candidate.aggregate)
        .unwrap();
    assert_eq!(updated.id, original.id);
    assert_eq!(
        Arc::clone(&shared)
            .lookup(GrantSelector::Continuation("next"))
            .unwrap()
            .unwrap()
            .revision,
        Revision(1)
    );
    assert!(shared
        .lookup(GrantSelector::Continuation("continue-one"))
        .unwrap()
        .is_none());
    assert!(shared.remember_nonce("n", 1_000));
    assert!(!borrowed.remember_nonce("n", 1_000));
}

#[test]
fn every_index_moves_with_the_same_revision() {
    let storage = MemoryStorage::new();
    let first = storage.create(populated("old")).unwrap();
    let updated = storage
        .compare_exchange(first.id, first.revision, populated("new"))
        .unwrap();
    assert_eq!(updated.id, first.id);
    assert_eq!(updated.revision, Revision(1));
    for selector in [
        GrantSelector::Continuation("continue-old"),
        GrantSelector::Interaction("interact-old"),
        GrantSelector::Management("handle-old"),
        GrantSelector::AccessToken("value-old"),
        GrantSelector::TokenIdentifier(b"old"),
    ] {
        assert!(storage.lookup(selector).unwrap().is_none());
    }
    for selector in [
        GrantSelector::Continuation("continue-new"),
        GrantSelector::Interaction("interact-new"),
        GrantSelector::Management("handle-new"),
        GrantSelector::AccessToken("value-new"),
        GrantSelector::TokenIdentifier(b"new"),
    ] {
        let found = storage.lookup(selector).unwrap().unwrap();
        assert_eq!((found.id, found.revision), (first.id, Revision(1)));
    }
}

#[test]
fn collisions_never_partially_publish_creation_or_replacement() {
    let storage = MemoryStorage::new();
    let first = storage.create(populated("one")).unwrap();
    let second = storage.create(populated("two")).unwrap();
    for index in 0..5 {
        let mut candidate = populated("candidate");
        match index {
            0 => candidate.record.continuation_token = Some("continue-one".into()),
            1 => candidate.record.interact_handle = Some("interact-one".into()),
            2 => {
                let token = candidate.tokens.remove("handle-candidate").unwrap();
                candidate.tokens.insert("handle-one".into(), token);
            }
            3 => {
                candidate
                    .tokens
                    .get_mut("handle-candidate")
                    .unwrap()
                    .token
                    .value = gnap_types::token::TokenValue::new("value-one").unwrap();
            }
            4 => {
                candidate
                    .tokens
                    .get_mut("handle-candidate")
                    .unwrap()
                    .identifier = Some(b"one".to_vec());
            }
            _ => unreachable!(),
        }
        assert!(matches!(
            storage.create(candidate.clone()),
            Err(StoreError::Collision)
        ));
        assert!(matches!(
            storage.compare_exchange(second.id, second.revision, candidate),
            Err(StoreError::Collision)
        ));
        assert!(storage
            .lookup(GrantSelector::Continuation("continue-candidate"))
            .unwrap()
            .is_none());
        assert!(storage
            .lookup(GrantSelector::AccessToken("value-candidate"))
            .unwrap()
            .is_none());
        assert_eq!(
            storage
                .lookup(GrantSelector::Id(second.id))
                .unwrap()
                .unwrap()
                .revision,
            second.revision
        );
        assert_eq!(
            storage
                .lookup(GrantSelector::Management("handle-one"))
                .unwrap()
                .unwrap()
                .id,
            first.id
        );
    }
    assert_eq!(
        storage.create(populated("three")).unwrap().id,
        GrantId(3),
        "failed creates publish neither IDs nor aliases"
    );
}

#[test]
fn duplicate_values_and_identifiers_inside_one_candidate_are_refused() {
    for duplicate_value in [false, true] {
        let storage = MemoryStorage::new();
        let mut aggregate = populated("one");
        let extra = if duplicate_value {
            issued("value-one", b"different")
        } else {
            issued("different", b"one")
        };
        aggregate.tokens.insert("extra".into(), extra);
        assert!(matches!(
            storage.create(aggregate),
            Err(StoreError::Collision)
        ));
        assert!(storage.is_empty().unwrap());
    }
}

#[test]
fn revocation_is_terminal_and_clears_all_aliases() {
    let storage = MemoryStorage::new();
    let original = storage.create(populated("one")).unwrap();
    let mut revoked = original.aggregate.clone();
    revoked.record.continuation_token = None;
    revoked.record.interact_handle = None;
    revoked.tokens.clear();
    revoked.revoked = true;
    let terminal = storage
        .compare_exchange(original.id, original.revision, revoked)
        .unwrap();
    assert!(matches!(
        storage.compare_exchange(original.id, original.revision, original.aggregate.clone()),
        Err(StoreError::Conflict)
    ));
    assert!(matches!(
        storage.compare_exchange(terminal.id, terminal.revision, original.aggregate),
        Err(StoreError::Conflict)
    ));
    assert!(matches!(
        storage.compare_exchange(GrantId(99), Revision(0), populated("missing")),
        Err(StoreError::Conflict)
    ));
    assert!(storage
        .lookup(GrantSelector::Continuation("continue-one"))
        .unwrap()
        .is_none());
    assert!(storage
        .lookup(GrantSelector::Interaction("interact-one"))
        .unwrap()
        .is_none());
    assert!(storage
        .lookup(GrantSelector::Management("handle-one"))
        .unwrap()
        .is_none());
    assert!(storage
        .lookup(GrantSelector::AccessToken("value-one"))
        .unwrap()
        .is_none());
    assert!(storage
        .lookup(GrantSelector::TokenIdentifier(b"one"))
        .unwrap()
        .is_none());
}

#[test]
fn normal_closure_preserves_token_management() {
    let storage = MemoryStorage::new();
    let original = storage.create(populated("one")).unwrap();
    let mut closed = original.aggregate;
    closed.record.continuation_token = None;
    closed.record.interact_handle = None;
    closed.record.grant.withhold_continuation();
    let closed = storage
        .compare_exchange(original.id, original.revision, closed)
        .unwrap();
    assert!(!closed.aggregate.revoked);
    assert!(storage
        .lookup(GrantSelector::Management("handle-one"))
        .unwrap()
        .is_some());
    let mut deletion = closed.aggregate;
    deletion.tokens.clear();
    storage
        .compare_exchange(closed.id, closed.revision, deletion)
        .unwrap();
    assert!(storage
        .lookup(GrantSelector::Management("handle-one"))
        .unwrap()
        .is_none());
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

#[test]
fn maintenance_removes_every_index_without_reusing_the_identity() {
    let storage = MemoryStorage::new();
    let original = storage.create(populated("one")).unwrap();
    assert_eq!(
        storage.remove(original.id, Revision(99)),
        Err(StoreError::Conflict)
    );
    for selector in [
        GrantSelector::Continuation("continue-one"),
        GrantSelector::Interaction("interact-one"),
        GrantSelector::Management("handle-one"),
        GrantSelector::AccessToken("value-one"),
        GrantSelector::TokenIdentifier(b"one"),
        GrantSelector::Id(original.id),
    ] {
        assert_eq!(
            storage.lookup(selector).unwrap().unwrap().revision,
            original.revision
        );
    }
    storage.remove(original.id, original.revision).unwrap();
    for selector in [
        GrantSelector::Continuation("continue-one"),
        GrantSelector::Interaction("interact-one"),
        GrantSelector::Management("handle-one"),
        GrantSelector::AccessToken("value-one"),
        GrantSelector::TokenIdentifier(b"one"),
        GrantSelector::Id(original.id),
    ] {
        assert!(storage.lookup(selector).unwrap().is_none());
    }
    assert_eq!(
        storage.remove(original.id, original.revision),
        Err(StoreError::Conflict)
    );
    assert!(matches!(
        storage.compare_exchange(original.id, original.revision, original.aggregate),
        Err(StoreError::Conflict)
    ));
    let next = storage.create(populated("one")).unwrap();
    assert_ne!(
        next.id, original.id,
        "reusing index values does not reuse an identity"
    );
    assert!(matches!(
        storage.compare_exchange(original.id, next.revision, next.aggregate),
        Err(StoreError::Conflict)
    ));
}

#[test]
fn a_replacement_cannot_change_the_authenticated_client() {
    let storage = MemoryStorage::new();
    let original = storage.create(populated("one")).unwrap();
    let mut candidate = original.aggregate;
    let other = serde_json::from_str(r#""other-client""#).unwrap();
    candidate.record.request.client = other;
    for token in candidate.tokens.values_mut() {
        token.client = candidate.record.request.client.clone();
    }
    assert!(matches!(
        storage.compare_exchange(original.id, original.revision, candidate),
        Err(StoreError::Invalid)
    ));
    assert_eq!(
        storage
            .lookup(GrantSelector::Id(original.id))
            .unwrap()
            .unwrap()
            .revision,
        original.revision
    );
}

#[test]
fn malformed_candidates_are_refused_without_consuming_an_identity() {
    let storage = MemoryStorage::new();
    for malformed in 0..8 {
        let mut candidate = populated("one");
        match malformed {
            0 => candidate.record.continuation_token = Some(String::new()),
            1 => candidate.record.interact_handle = Some(String::new()),
            2 => candidate.record.continuation_token = None,
            3 => {
                let token = candidate.tokens.remove("handle-one").unwrap();
                candidate.tokens.insert(String::new(), token);
            }
            4 => candidate
                .tokens
                .get_mut("handle-one")
                .unwrap()
                .management_token
                .clear(),
            5 => candidate.tokens.get_mut("handle-one").unwrap().identifier = Some(Vec::new()),
            6 => {
                candidate.tokens.get_mut("handle-one").unwrap().client =
                    serde_json::from_str(r#""other""#).unwrap();
            }
            7 => candidate.revoked = true,
            _ => unreachable!(),
        }
        assert!(matches!(
            storage.create(candidate),
            Err(StoreError::Invalid)
        ));
        assert!(storage
            .lookup(GrantSelector::Management("handle-one"))
            .unwrap()
            .is_none());
    }
    assert_eq!(storage.create(populated("one")).unwrap().id, GrantId(1));
}

#[test]
fn a_finalized_core_state_cannot_be_reopened() {
    let storage = MemoryStorage::new();
    let mut closed = populated("one");
    closed
        .record
        .grant
        .apply(gnap_core::Event::AsCannotProceed, 1_000)
        .unwrap();
    closed.record.continuation_token = None;
    closed.record.interact_handle = None;
    let original = storage.create(closed).unwrap();
    assert!(matches!(
        storage.compare_exchange(original.id, original.revision, populated("new")),
        Err(StoreError::Invalid)
    ));
    assert!(storage
        .lookup(GrantSelector::Continuation("continue-new"))
        .unwrap()
        .is_none());
    assert_eq!(
        storage
            .lookup(GrantSelector::Id(original.id))
            .unwrap()
            .unwrap()
            .revision,
        original.revision
    );
}
