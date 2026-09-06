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
            derivation: None,
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

/// Stops exactly one prepared CAS, after policy and proof but before publication.
struct PausedCas {
    inner: MemoryStorage,
    pause: AtomicBool,
    reached: Arc<Gate>,
    release: Arc<Gate>,
}
impl GrantStore for PausedCas {
    fn create(&self, aggregate: GrantAggregate) -> Result<GrantSnapshot, StoreError> {
        self.inner.create(aggregate)
    }
    fn lookup(&self, selector: GrantSelector<'_>) -> Result<Option<GrantSnapshot>, StoreError> {
        self.inner.lookup(selector)
    }
    fn compare_exchange(
        &self,
        id: GrantId,
        revision: Revision,
        replacement: GrantAggregate,
    ) -> Result<GrantSnapshot, StoreError> {
        if self.pause.swap(false, Ordering::SeqCst) {
            self.reached.signal();
            self.release.wait();
        }
        self.inner.compare_exchange(id, revision, replacement)
    }
    fn remove(&self, id: GrantId, revision: Revision) -> Result<(), StoreError> {
        self.inner.remove(id, revision)
    }
}
impl NonceStore for PausedCas {
    fn remember_nonce(&self, nonce: &str, now: u64) -> bool {
        self.inner.remember_nonce(nonce, now)
    }
}
struct OpenApprove;
impl Policy for OpenApprove {
    fn evaluate(&self, request: &GrantRequest) -> Decision {
        Decision::Approve {
            access: request.access_token.as_ref().unwrap().tokens[0]
                .access
                .clone(),
            subject: None,
        }
    }
    fn keep_grant_open(&self, _: &GrantRequest) -> bool {
        true
    }
}

fn ongoing_race(winning_method: &str) {
    let reached = Arc::new(Gate::new());
    let release = Arc::new(Gate::new());
    let storage = Arc::new(PausedCas {
        inner: MemoryStorage::new(),
        pause: AtomicBool::new(true),
        reached: reached.clone(),
        release: release.clone(),
    });
    let server = Arc::new(AuthorizationServer::new(
        OpenApprove,
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
    let initial = sign_request(
        HttpRequest::new("POST", "https://as.example/gnap").json_body(
            br#"{"client":"client","access_token":{"access":["read","write"]}}"#.to_vec(),
        ),
        &signer(),
        None,
        NOW,
    )
    .unwrap();
    let initial = server.handle(&initial, NOW);
    assert_eq!(initial.status, 200);
    let initial: gnap_types::message::GrantResponse =
        serde_json::from_slice(&initial.body).unwrap();
    let token = &initial.access_token.unwrap().tokens[0];
    let management = token.manage.as_ref().unwrap();
    let continuation = initial.r#continue.unwrap();
    let before = storage
        .lookup(GrantSelector::AccessToken(token.value.as_str()))
        .unwrap()
        .unwrap();
    let build = |method: &str| {
        let (uri, credential) = if method == "POST" {
            (&management.uri, &management.access_token.value)
        } else {
            (&continuation.uri, &continuation.access_token.value)
        };
        let mut request = HttpRequest::new(method, uri);
        if method == "PATCH" {
            request = request.json_body(br#"{"access_token":{"access":["read"]}}"#.to_vec());
        }
        sign_request(request, &signer(), Some(credential), NOW + 5).unwrap()
    };
    let losing_method = if winning_method == "PATCH" {
        "POST"
    } else {
        "PATCH"
    };
    let delayed_request = build(losing_method);
    let delayed_server = server.clone();
    let delayed = std::thread::spawn(move || delayed_server.handle(&delayed_request, NOW + 5));
    reached.wait(); // The losing operation holds an authenticated, prepared snapshot.
    let winner = server.handle(&build(winning_method), NOW + 5);
    release.signal();
    let loser = delayed.join().unwrap();
    assert_eq!(
        winner.status,
        if winning_method == "DELETE" { 204 } else { 200 }
    );
    assert_ne!(loser.status, 200);
    let current = storage
        .lookup(GrantSelector::Id(before.id))
        .unwrap()
        .unwrap();
    assert_eq!(current.revision, Revision(1));
    assert!(storage
        .lookup(GrantSelector::AccessToken(token.value.as_str()))
        .unwrap()
        .is_none());
    if winning_method == "DELETE" {
        assert!(current.aggregate.revoked);
        assert!(current.aggregate.tokens.is_empty());
        assert!(current.aggregate.record.continuation_token.is_none());
    } else {
        assert_eq!(current.aggregate.tokens.len(), 1);
        let live = current.aggregate.tokens.values().next().unwrap();
        let expected: Vec<_> = if winning_method == "PATCH" {
            vec!["read"]
        } else {
            vec!["read", "write"]
        }
        .into_iter()
        .map(|right| gnap_types::access::AccessItem::Reference(right.into()))
        .collect();
        assert_eq!(live.token.access.as_ref().unwrap(), &expected);
        assert_eq!(
            current.aggregate.record.continuation_token.as_deref()
                == Some(continuation.access_token.value.as_str()),
            winning_method == "POST"
        );
    }
}

#[test]
fn a_successful_patch_prevents_a_stale_rotation_from_publishing() {
    ongoing_race("PATCH");
}
#[test]
fn a_successful_rotation_prevents_a_stale_patch_from_publishing() {
    ongoing_race("POST");
}
#[test]
fn a_grant_delete_prevents_a_stale_patch_from_restoring_access() {
    ongoing_race("DELETE");
}
