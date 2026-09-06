//! Deterministic races between authenticated token management requests.

use gnap_as::{
    AuthorizationServer, Decision, Endpoints, GrantAggregate, GrantId, GrantRecord, GrantSelector,
    GrantSnapshot, GrantStore, KeyResolver, MemoryStorage, NonceStore, OsNonces, Policy, Revision,
    StoreError, TokenRecord,
};
use gnap_client::{sign_request, HttpRequest};
use gnap_crypto::{proof::Verifier, ps256::Ps256Signer};
use gnap_types::{client::Client, message::GrantRequest, token::AccessToken, token::TokenValue};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, Mutex,
};

/// A one-way gate: both the worker and the controller have a finite wait.
struct Gate {
    sender: mpsc::Sender<()>,
    receiver: Mutex<mpsc::Receiver<()>>,
}
impl Gate {
    fn new() -> Self {
        let (sender, receiver) = mpsc::channel();
        Self {
            sender,
            receiver: Mutex::new(receiver),
        }
    }
    fn signal(&self) {
        self.sender.send(()).unwrap();
    }
    fn wait(&self) {
        self.receiver
            .lock()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("concurrent operation reached its checkpoint");
    }
}

const NOW: u64 = 1_700_000_000;
const HANDLE: &str = "original";
const URL: &str = "https://as.example/token/original";

fn signer() -> Ps256Signer {
    Ps256Signer::from_pkcs1_pem(
        include_str!("../../gnap-crypto/tests/rfc9421-b12.pkcs1.pem"),
        "client-key",
    )
    .unwrap()
}

struct Keys;
impl KeyResolver for Keys {
    fn resolve(&self, _: &Client) -> Option<Box<dyn Verifier>> {
        Some(Box::new(signer().verifier()))
    }
}

struct RotationPolicy {
    entered: Arc<Gate>,
    release: Arc<Gate>,
    allow: bool,
}
impl Policy for RotationPolicy {
    fn evaluate(&self, _: &GrantRequest) -> Decision {
        Decision::RequireInteraction
    }
    fn may_rotate(&self, _: &AccessToken) -> bool {
        self.entered.signal();
        self.release.wait();
        self.allow
    }
}

struct PausedRead {
    inner: MemoryStorage,
    pause_first: AtomicBool,
    captured: Arc<Gate>,
    release: Arc<Gate>,
}
impl GrantStore for PausedRead {
    fn create(&self, aggregate: GrantAggregate) -> Result<GrantSnapshot, StoreError> {
        self.inner.create(aggregate)
    }
    fn lookup(&self, selector: GrantSelector<'_>) -> Result<Option<GrantSnapshot>, StoreError> {
        let snapshot = self.inner.lookup(selector);
        if matches!(selector, GrantSelector::Management(_))
            && self.pause_first.swap(false, Ordering::SeqCst)
        {
            self.captured.signal();
            self.release.wait();
        }
        snapshot
    }
    fn compare_exchange(
        &self,
        id: GrantId,
        revision: Revision,
        aggregate: GrantAggregate,
    ) -> Result<GrantSnapshot, StoreError> {
        self.inner.compare_exchange(id, revision, aggregate)
    }
    fn remove(&self, id: GrantId, revision: Revision) -> Result<(), StoreError> {
        self.inner.remove(id, revision)
    }
}
impl NonceStore for PausedRead {
    fn remember_nonce(&self, nonce: &str, now: u64) -> bool {
        self.inner.remember_nonce(nonce, now)
    }
}

fn revocation_wins(allow_rotation: bool) {
    let captured = Arc::new(Gate::new());
    let release_delete = Arc::new(Gate::new());
    let rotating = Arc::new(Gate::new());
    let release_rotation = Arc::new(Gate::new());
    let storage = Arc::new(PausedRead {
        inner: MemoryStorage::new(),
        pause_first: AtomicBool::new(true),
        captured: captured.clone(),
        release: release_delete.clone(),
    });
    let mut aggregate = GrantAggregate::new(GrantRecord {
        grant: gnap_core::Grant::new(),
        request: serde_json::from_str(r#"{"client":"client"}"#).unwrap(),
        continuation_token: None,
        as_nonce: None,
        interact_handle: None,
        interact_expires_at: None,
        interact_ref: None,
        interaction_completed: false,
    });
    aggregate.tokens.insert(
        HANDLE.into(),
        TokenRecord {
            issued_at: NOW,
            identifier: None,
            token: serde_json::from_value(serde_json::json!({
                "value": "original-access", "access": ["read"], "expires_in": 1200
            }))
            .unwrap(),
            client: serde_json::from_str("\"client\"").unwrap(),
            management_token: "management".into(),
        },
    );
    let original = storage.create(aggregate).unwrap();
    let server = Arc::new(AuthorizationServer::new(
        RotationPolicy {
            entered: rotating.clone(),
            release: release_rotation.clone(),
            allow: allow_rotation,
        },
        Keys,
        storage.clone(),
        OsNonces,
        Endpoints {
            grant: "https://as.example/gnap".into(),
            continuation: "https://as.example/continue".into(),
            interaction: "https://as.example/interact".into(),
            token_management: "https://as.example/token".into(),
        },
    ));
    let management = TokenValue::new("management").unwrap();
    let deletion = sign_request(
        HttpRequest::new("DELETE", URL),
        &signer(),
        Some(&management),
        NOW,
    )
    .unwrap();
    let rotation = sign_request(
        HttpRequest::new("POST", URL),
        &signer(),
        Some(&management),
        NOW,
    )
    .unwrap();
    let deleting_server = server.clone();
    let deleting = std::thread::spawn(move || deleting_server.handle(&deletion, NOW));
    captured.wait(); // DELETE has the authenticatable record, but has not acted.
    let rotating_server = server;
    let rotating_call = std::thread::spawn(move || rotating_server.handle(&rotation, NOW));
    rotating.wait(); // Rotation is evaluating policy, with no response committed.
    release_delete.signal();
    let deleted = deleting.join().unwrap();
    release_rotation.signal();
    let rotated = rotating_call.join().unwrap();
    assert_eq!(deleted.status, 204);
    assert_ne!(
        rotated.status, 200,
        "a stale rotation cannot report success"
    );
    let current = storage
        .lookup(GrantSelector::Id(original.id))
        .unwrap()
        .unwrap();
    assert_eq!(current.revision, Revision(1), "only DELETE committed");
    assert!(
        current.aggregate.tokens.is_empty(),
        "rotation published or restored a token after DELETE returned 204"
    );
    assert!(storage
        .lookup(GrantSelector::Management(HANDLE))
        .unwrap()
        .is_none());
    assert!(storage
        .lookup(GrantSelector::AccessToken("original-access"))
        .unwrap()
        .is_none());
}

#[test]
fn refused_rotation_cannot_restore_a_concurrently_revoked_token() {
    revocation_wins(false);
}

#[test]
fn successful_rotation_cannot_publish_after_concurrent_revocation() {
    revocation_wins(true);
}
