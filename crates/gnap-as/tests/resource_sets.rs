//! Immutable, bounded resource references belong to authenticated RS identities.

use gnap_as::{
    MemoryResourceSetStore, ResourceSetError, ResourceSetLimits, ResourceSetStore, RsId,
};
use gnap_types::access::AccessItem;
use std::sync::{Arc, Barrier};

fn rights(names: &[&str]) -> Vec<AccessItem> {
    names
        .iter()
        .map(|name| AccessItem::Reference((*name).into()))
        .collect()
}

#[test]
fn canonical_registration_is_owner_scoped_and_collision_never_overwrites() {
    let store = MemoryResourceSetStore::new(ResourceSetLimits::default());
    let owner = RsId("files".into());
    let first = store
        .register_or_get(
            &owner,
            "reference with spaces / 雪",
            &rights(&["read", "write"]),
        )
        .unwrap();
    assert_eq!(
        store
            .register_or_get(&owner, "unused", &rights(&["write", "read"]))
            .unwrap(),
        first
    );
    assert_eq!(store.lookup("unused").unwrap(), None);
    assert_eq!(
        store.register_or_get(&RsId("other".into()), &first.reference, &first.access),
        Err(ResourceSetError::Collision)
    );
    assert_eq!(
        store.register_or_get(&owner, &first.reference, &rights(&["delete"])),
        Err(ResourceSetError::Collision)
    );
    assert_eq!(store.lookup(&first.reference).unwrap(), Some(first));
}

#[test]
fn concurrent_identical_registration_has_one_reference() {
    let store = Arc::new(MemoryResourceSetStore::new(ResourceSetLimits::default()));
    let start = Arc::new(Barrier::new(2));
    std::thread::scope(|scope| {
        // Array::map spawns both workers eagerly before either join can block.
        let tasks = ["first", "second"].map(|candidate| {
            let store = &store;
            let start = &start;
            scope.spawn(move || {
                start.wait();
                store
                    .register_or_get(&RsId("files".into()), candidate, &rights(&["read"]))
                    .unwrap()
            })
        });
        let records = tasks.map(|task| task.join().unwrap());
        assert_eq!(records[0], records[1]);
    });
}

#[test]
fn quotas_do_not_evict_and_retries_work_at_capacity() {
    let store = MemoryResourceSetStore::new(ResourceSetLimits {
        max_sets: 2,
        max_sets_per_owner: 1,
        ..ResourceSetLimits::default()
    });
    let owner = RsId("files".into());
    let first = store
        .register_or_get(&owner, "first", &rights(&["read"]))
        .unwrap();
    assert_eq!(
        store.register_or_get(&owner, "second", &rights(&["write"])),
        Err(ResourceSetError::Capacity)
    );
    store
        .register_or_get(&RsId("other".into()), "second", &rights(&["write"]))
        .unwrap();
    assert_eq!(
        store.register_or_get(&RsId("third".into()), "third", &rights(&["read"])),
        Err(ResourceSetError::Capacity)
    );
    assert_eq!(
        store
            .register_or_get(&owner, "unused", &rights(&["read"]))
            .unwrap(),
        first
    );
    assert_eq!(store.lookup("first").unwrap(), Some(first));
}

#[test]
fn same_content_with_a_colliding_new_candidate_returns_its_original_reference() {
    let store = MemoryResourceSetStore::new(ResourceSetLimits::default());
    let owner = RsId("files".into());
    let first = store
        .register_or_get(&owner, "first", &rights(&["read"]))
        .unwrap();
    let other = store
        .register_or_get(&RsId("other".into()), "other", &rights(&["read"]))
        .unwrap();
    assert_ne!(first.reference, other.reference);
    assert_eq!(
        store
            .register_or_get(&owner, "other", &rights(&["read"]))
            .unwrap(),
        first
    );
    assert_eq!(store.lookup("other").unwrap(), Some(other));
}

#[test]
fn object_key_order_is_canonical_but_nested_arrays_and_uri_spelling_are_not() {
    let store = MemoryResourceSetStore::new(ResourceSetLimits::default());
    let owner = RsId("files".into());
    let original: Vec<AccessItem> = serde_json::from_str(r#"[{"type":"files","actions":["read","write"],"locations":["https://rs.example/a"],"custom":{"b":2,"a":1}}]"#).unwrap();
    let first = store.register_or_get(&owner, "first", &original).unwrap();
    let reordered: Vec<AccessItem> = serde_json::from_str(r#"[{"custom":{"a":1,"b":2},"locations":["https://rs.example/a"],"actions":["read","write"],"type":"files"}]"#).unwrap();
    assert_eq!(
        store.register_or_get(&owner, "unused", &reordered).unwrap(),
        first
    );
    for (candidate, source) in [
        (
            "array",
            r#"[{"type":"files","actions":["write","read"],"locations":["https://rs.example/a"],"custom":{"b":2,"a":1}}]"#,
        ),
        (
            "uri",
            r#"[{"type":"files","actions":["read","write"],"locations":["https://rs.example/%61"],"custom":{"b":2,"a":1}}]"#,
        ),
    ] {
        let access: Vec<AccessItem> = serde_json::from_str(source).unwrap();
        assert_ne!(
            store.register_or_get(&owner, candidate, &access).unwrap(),
            first
        );
    }
}

#[test]
fn byte_count_item_count_and_json_shape_budgets_leave_no_partial_record() {
    let owner = RsId("files".into());
    for limits in [
        ResourceSetLimits {
            max_record_bytes: 1,
            ..ResourceSetLimits::default()
        },
        ResourceSetLimits {
            max_reference_bytes: 2,
            ..ResourceSetLimits::default()
        },
    ] {
        let store = MemoryResourceSetStore::new(limits);
        assert_eq!(
            store.register_or_get(&owner, "first", &rights(&["read"])),
            Err(ResourceSetError::Invalid)
        );
        assert_eq!(store.lookup("first").unwrap(), None);
    }
    let access: Vec<AccessItem> =
        serde_json::from_str(r#"[{"type":"files","nested":{"array":[1,2,3]}}]"#).unwrap();
    for limits in [
        ResourceSetLimits {
            max_access_items: 0,
            ..ResourceSetLimits::default()
        },
        ResourceSetLimits {
            max_record_bytes: 12,
            ..ResourceSetLimits::default()
        },
        ResourceSetLimits {
            max_json_depth: 2,
            ..ResourceSetLimits::default()
        },
        ResourceSetLimits {
            max_json_nodes: 4,
            ..ResourceSetLimits::default()
        },
    ] {
        let store = MemoryResourceSetStore::new(limits);
        assert_eq!(
            store.register_or_get(&owner, "first", &access),
            Err(ResourceSetError::InvalidAccessInput)
        );
        assert_eq!(store.lookup("first").unwrap(), None);
    }
    let store = MemoryResourceSetStore::new(ResourceSetLimits::default());
    assert_eq!(
        store.register_or_get(&owner, "first", &[]),
        Err(ResourceSetError::InvalidAccessInput)
    );
    assert_eq!(
        store.register_or_get(&RsId(String::new()), "first", &rights(&["read"])),
        Err(ResourceSetError::Invalid)
    );
    store.register_or_get(&owner, "first", &access).unwrap();
    // A new volatile store cannot recover the old reference after restart.
    assert_eq!(
        MemoryResourceSetStore::new(ResourceSetLimits::default())
            .lookup("first")
            .unwrap(),
        None
    );
}
