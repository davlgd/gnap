//! Deliberate interleavings at the optional index and publication boundary.
use super::*;
use gnap_as::{GrantAggregate, GrantId, GrantSnapshot, NonceStore, Revision, StoreError};
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Default)]
struct RacingStore {
    inner: MemoryStorage,
    mode: AtomicU8,
    rejected: Mutex<Option<GrantAggregate>>,
    readers: Option<Barrier>,
}
impl RacingStore {
    fn insert_competitor(&self, candidate: &GrantAggregate) {
        let mut competitor = candidate.clone();
        competitor.record.continuation_token = Some("competing-continuation".into());
        competitor.record.interact_handle = Some("competing-handle".into());
        self.inner.create(competitor).unwrap();
        *self.rejected.lock().unwrap() = Some(candidate.clone());
    }
}
impl GrantStore for RacingStore {
    fn create(&self, candidate: GrantAggregate) -> Result<GrantSnapshot, StoreError> {
        if self.mode.load(Ordering::SeqCst) == 1 {
            self.insert_competitor(&candidate);
        }
        self.inner.create(candidate)
    }
    fn lookup(&self, selector: GrantSelector<'_>) -> Result<Option<GrantSnapshot>, StoreError> {
        let result = self.inner.lookup(selector);
        if self.mode.load(Ordering::SeqCst) == 4
            && matches!(selector, GrantSelector::Interaction(_))
        {
            self.readers.as_ref().unwrap().wait();
        }
        result
    }
    fn compare_exchange(
        &self,
        id: GrantId,
        revision: Revision,
        candidate: GrantAggregate,
    ) -> Result<GrantSnapshot, StoreError> {
        if self.mode.load(Ordering::SeqCst) == 2 {
            self.insert_competitor(&candidate);
        }
        self.inner.compare_exchange(id, revision, candidate)
    }
    fn remove(&self, id: GrantId, revision: Revision) -> Result<(), StoreError> {
        self.inner.remove(id, revision)
    }
}
impl NonceStore for RacingStore {
    fn remember_nonce(&self, nonce: &str, now: u64) -> bool {
        self.inner.remember_nonce(nonce, now)
    }
}
impl UserCodeStore for RacingStore {
    fn lookup_user_code(&self, code: &str) -> Result<Option<GrantSnapshot>, StoreError> {
        if self.mode.load(Ordering::SeqCst) == 3 {
            return Err(StoreError::Unavailable);
        }
        self.inner.lookup_user_code(code)
    }
}

#[test]
fn a_code_collision_at_create_or_cas_never_partially_publishes_the_candidate() {
    let signer = Ps256Signer::from_pkcs1_pem(KEY, "client").unwrap();
    for mode in [1, 2] {
        let store = Arc::new(RacingStore::default());
        let server = engine(store.clone(), Source::default())
            .with_user_code_uri(ENTRY)
            .unwrap();
        let direct = Direct {
            server: &server,
            now: Cell::new(1_000),
        };
        let mut client = Session::new(&direct, &signer, ENDPOINT);
        let prior = if mode == 2 {
            let step = client.start(&request(&["user_code"], None), 1_000).unwrap();
            Some(store.lookup_user_code(code(&step)).unwrap().unwrap())
        } else {
            None
        };
        store.mode.store(mode, Ordering::SeqCst);
        let result = if mode == 1 {
            client.start(&request(&["user_code"], None), 1_000)
        } else {
            direct.now.set(1_005);
            client.modify_grant(
                &serde_json::from_value(json!({"interact":{"start":["user_code"]}})).unwrap(),
                1_005,
            )
        };
        assert!(result.is_err());
        let attempted = store.rejected.lock().unwrap().clone().unwrap();
        assert!(store
            .inner
            .lookup(GrantSelector::Continuation(
                attempted.record.continuation_token.as_deref().unwrap()
            ))
            .unwrap()
            .is_none());
        assert!(store
            .inner
            .lookup(GrantSelector::Interaction(
                attempted.record.interact_handle.as_deref().unwrap()
            ))
            .unwrap()
            .is_none());
        let winner = store
            .inner
            .lookup_user_code(attempted.record.user_code.as_deref().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(
            winner.aggregate.record.interact_handle.as_deref(),
            Some("competing-handle")
        );
        if let Some(prior) = prior {
            let current = store
                .inner
                .lookup(GrantSelector::Id(prior.id))
                .unwrap()
                .unwrap();
            assert_eq!(current.revision, prior.revision);
            assert_eq!(
                current.aggregate.record.user_code,
                prior.aggregate.record.user_code
            );
            assert_eq!(
                client.continuation().unwrap().access_token.value.as_str(),
                prior
                    .aggregate
                    .record
                    .continuation_token
                    .as_deref()
                    .unwrap()
            );
            assert_eq!(store.inner.len().unwrap(), 2);
        } else {
            assert!(client.continuation().is_none());
            assert_eq!(store.inner.len().unwrap(), 1);
        }
    }
}

#[test]
fn both_completion_readers_reach_cas_but_only_one_gets_a_finish_directive() {
    let store = Arc::new(RacingStore {
        readers: Some(Barrier::new(2)),
        ..Default::default()
    });
    let server = engine(store.clone(), Source::default())
        .with_user_code_uri(ENTRY)
        .unwrap();
    let signer = Ps256Signer::from_pkcs1_pem(KEY, "client").unwrap();
    let direct = Direct {
        server: &server,
        now: Cell::new(1_000),
    };
    let step = Session::new(&direct, &signer, ENDPOINT)
        .start(&request(&["redirect", "user_code_uri"], None), 1_000)
        .unwrap();
    let handle = server.resolve_user_code(code(&step), 1_001).unwrap();
    store.mode.store(4, Ordering::SeqCst);
    std::thread::scope(|scope| {
        let left = scope.spawn(|| server.complete_interaction(&handle, 1_001));
        let right = scope.spawn(|| server.complete_interaction(&handle, 1_001));
        let results = [left.join().unwrap(), right.join().unwrap()];
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Err(InteractionError::Storage(StoreError::Conflict))))
                .count(),
            1
        );
    });
    store.mode.store(0, Ordering::SeqCst);
    assert!(server.resolve_user_code(code(&step), 1_001).is_err());
}

#[test]
fn unavailable_code_index_does_not_look_like_absence_or_publish_an_offer() {
    let store = Arc::new(RacingStore::default());
    let server = engine(store.clone(), Source::default())
        .with_user_code_uri(ENTRY)
        .unwrap();
    let signer = Ps256Signer::from_pkcs1_pem(KEY, "client").unwrap();
    let direct = Direct {
        server: &server,
        now: Cell::new(1_000),
    };
    let step = Session::new(&direct, &signer, ENDPOINT)
        .start(&request(&["user_code"], None), 1_000)
        .unwrap();
    store.mode.store(3, Ordering::SeqCst);
    assert!(matches!(
        server.resolve_user_code(code(&step), 1_001),
        Err(InteractionError::Storage(StoreError::Unavailable))
    ));
    assert!(Session::new(&direct, &signer, ENDPOINT)
        .start(&request(&["user_code"], None), 1_000)
        .is_err());
    assert_eq!(store.inner.len().unwrap(), 1);
}

#[test]
fn optional_index_forwarders_invariants_and_revocation_match_the_aggregate() {
    fn lookup<S: UserCodeStore>(store: S, code: &str) -> GrantSnapshot {
        store.lookup_user_code(code).unwrap().unwrap()
    }
    let mut f = fixture();
    f.server = f.server.with_user_code_uri(ENTRY).unwrap();
    let signer = Ps256Signer::from_pkcs1_pem(KEY, "client").unwrap();
    let direct = Direct {
        server: &f.server,
        now: Cell::new(1_000),
    };
    let mut client = Session::new(&direct, &signer, ENDPOINT);
    let step = client.start(&request(&["user_code"], None), 1_000).unwrap();
    let saved = lookup(&*f.storage, code(&step));
    assert_eq!(lookup(f.storage.clone(), code(&step)).id, saved.id);
    for invalid in 0..5 {
        let mut candidate = saved.aggregate.clone();
        match invalid {
            0 => candidate.record.user_code = Some("lowercase".into()),
            1 => candidate.record.interact_handle = None,
            2 => candidate.record.interact_expires_at = None,
            3 => candidate.record.interaction_completed = true,
            _ => candidate.revoked = true,
        }
        assert!(matches!(
            f.storage
                .compare_exchange(saved.id, saved.revision, candidate),
            Err(StoreError::Invalid)
        ));
        assert_eq!(lookup(&*f.storage, code(&step)).revision, saved.revision);
    }
    direct.now.set(1_005);
    client.revoke_grant(1_005).unwrap();
    assert!(f.storage.lookup_user_code(code(&step)).unwrap().is_none());
    assert!(f
        .storage
        .lookup(GrantSelector::Id(saved.id))
        .unwrap()
        .unwrap()
        .aggregate
        .record
        .user_code
        .is_none());
}
