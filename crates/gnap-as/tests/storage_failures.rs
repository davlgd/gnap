//! An unavailable store must not be mistaken for absence or a committed grant.

use gnap_as::{
    AuthorizationServer, Decision, Endpoints, GrantAggregate, GrantId, GrantSelector,
    GrantSnapshot, GrantStore, KeyResolver, MemoryStorage, NonceStore, OsNonces, Policy, Revision,
    StoreError,
};
use gnap_client::{sign_request, HttpRequest};
use gnap_crypto::{proof::Verifier, ps256::Ps256Signer};
use gnap_types::{client::Client, message::GrantRequest, message::GrantResponse};
use std::cell::Cell;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    Create,
    Read,
    Replace,
}

struct Faults {
    inner: MemoryStorage,
    fault: Cell<Fault>,
}
impl GrantStore for Faults {
    fn create_derived(
        &self,
        parent: GrantId,
        revision: Revision,
        value: &gnap_types::token::TokenValue,
        child: GrantAggregate,
        clock: &dyn Fn() -> u64,
    ) -> Result<GrantSnapshot, StoreError> {
        if self.fault.get() == Fault::Create {
            return Err(StoreError::Unavailable);
        }
        self.inner
            .create_derived(parent, revision, value, child, clock)
    }
    fn create(&self, aggregate: GrantAggregate) -> Result<GrantSnapshot, StoreError> {
        if self.fault.get() == Fault::Create {
            return Err(StoreError::Unavailable);
        }
        self.inner.create(aggregate)
    }
    fn lookup(&self, selector: GrantSelector<'_>) -> Result<Option<GrantSnapshot>, StoreError> {
        if self.fault.get() == Fault::Read {
            return Err(StoreError::Unavailable);
        }
        self.inner.lookup(selector)
    }
    fn compare_exchange(
        &self,
        id: GrantId,
        revision: Revision,
        aggregate: GrantAggregate,
    ) -> Result<GrantSnapshot, StoreError> {
        if self.fault.get() == Fault::Replace {
            return Err(StoreError::Unavailable);
        }
        self.inner.compare_exchange(id, revision, aggregate)
    }
    fn remove(&self, id: GrantId, revision: Revision) -> Result<(), StoreError> {
        self.inner.remove(id, revision)
    }
}
impl NonceStore for Faults {
    fn remember_nonce(&self, nonce: &str, now: u64) -> bool {
        self.inner.remember_nonce(nonce, now)
    }
}

struct Approve;
impl Policy for Approve {
    fn evaluate(&self, _: &GrantRequest) -> Decision {
        Decision::Approve {
            access: vec![gnap_types::access::AccessItem::Reference("read".into())],
            subject: None,
        }
    }
}
struct Keys;
impl KeyResolver for Keys {
    fn resolve(&self, _: &Client) -> Option<Box<dyn Verifier>> {
        Some(Box::new(signer().verifier()))
    }
}
fn signer() -> Ps256Signer {
    Ps256Signer::from_pkcs1_pem(
        include_str!("../../gnap-crypto/tests/rfc9421-b12.pkcs1.pem"),
        "client-key",
    )
    .unwrap()
}

fn server<P: Policy>(policy: P) -> AuthorizationServer<P, Keys, Faults, OsNonces> {
    AuthorizationServer::new(
        policy,
        Keys,
        Faults {
            inner: MemoryStorage::new(),
            fault: Cell::new(Fault::None),
        },
        OsNonces,
        Endpoints {
            grant: "https://as.example/gnap".into(),
            continuation: "https://as.example/continue".into(),
            interaction: "https://as.example/interact".into(),
            token_management: "https://as.example/token".into(),
        },
    )
}

#[test]
fn storage_failure_never_returns_a_success_or_an_absence_error() {
    let server = server(Approve);
    server.storage().fault.set(Fault::Create);
    let grant = || {
        sign_request(
            HttpRequest::new("POST", "https://as.example/gnap")
                .json_body(br#"{"client":"client","access_token":{"access":["read"]}}"#.to_vec()),
            &signer(),
            None,
            1_000,
        )
        .unwrap()
    };
    let refused = server.handle(&grant(), 1_000);
    assert_eq!(refused.status, 503);
    assert!(refused.body.is_empty());
    assert!(refused.has_no_store());
    server.storage().fault.set(Fault::None);
    let issued = server.handle(&grant(), 1_000);
    assert_eq!(issued.status, 200);
    let response: GrantResponse = serde_json::from_slice(&issued.body).unwrap();
    let token = &response.access_token.unwrap().tokens[0];
    let original = server
        .storage()
        .lookup(GrantSelector::AccessToken(token.value.as_str()))
        .unwrap()
        .unwrap();
    assert_eq!(
        original.id,
        GrantId(1),
        "failed create did not publish an identity"
    );
    let manage = token.manage.as_ref().unwrap();
    for fault in [Fault::Read, Fault::Replace] {
        server.storage().fault.set(fault);
        for method in ["POST", "DELETE"] {
            let request = sign_request(
                HttpRequest::new(method, &manage.uri),
                &signer(),
                Some(&manage.access_token.value),
                1_001,
            )
            .unwrap();
            let before = server.storage().inner.remembered_nonces().unwrap();
            let refused = server.handle(&request, 1_001);
            assert_eq!(refused.status, 503);
            assert!(refused.body.is_empty());
            assert!(refused.has_no_store());
            if fault == Fault::Read {
                assert_eq!(
                    server.storage().inner.remembered_nonces().unwrap(),
                    before,
                    "failed lookup did not authenticate or spend a nonce"
                );
            }
            let current = server
                .storage()
                .inner
                .lookup(GrantSelector::Id(original.id))
                .unwrap()
                .unwrap();
            assert_eq!(current.revision, original.revision);
            assert_eq!(
                current.aggregate.tokens.values().next().unwrap().token,
                *token
            );
        }
    }
}

struct Interact;
impl Policy for Interact {
    fn evaluate(&self, _: &GrantRequest) -> Decision {
        Decision::RequireInteraction
    }
}

#[test]
fn continuation_and_interaction_responses_require_a_committed_revision() {
    let server = server(Interact);
    let grant = sign_request(
        HttpRequest::new("POST", "https://as.example/gnap")
            .json_body(br#"{"client":"client","interact":{"start":["redirect"]}}"#.to_vec()),
        &signer(),
        None,
        1_000,
    )
    .unwrap();
    let pending = server.handle(&grant, 1_000);
    assert_eq!(pending.status, 200);
    let response: GrantResponse = serde_json::from_slice(&pending.body).unwrap();
    let continuation = response.r#continue.unwrap();
    let original = server
        .storage()
        .lookup(GrantSelector::Continuation(
            continuation.access_token.value.as_str(),
        ))
        .unwrap()
        .unwrap();
    let handle = original
        .aggregate
        .record
        .interact_handle
        .as_deref()
        .unwrap();
    for fault in [Fault::Read, Fault::Replace] {
        server.storage().fault.set(fault);
        for method in ["POST", "DELETE"] {
            let request = sign_request(
                HttpRequest::new(method, &continuation.uri),
                &signer(),
                Some(&continuation.access_token.value),
                1_010,
            )
            .unwrap();
            let refused = server.handle(&request, 1_010);
            assert_eq!(refused.status, 503);
            assert!(refused.body.is_empty());
            assert!(refused.has_no_store());
        }
        assert!(matches!(
            server.complete_interaction(handle, 1_010),
            Err(gnap_as::InteractionError::Storage(StoreError::Unavailable))
        ));
        let current = server
            .storage()
            .inner
            .lookup(GrantSelector::Id(original.id))
            .unwrap()
            .unwrap();
        assert_eq!(current.revision, original.revision);
        assert_eq!(
            current.aggregate.record.continuation_token,
            original.aggregate.record.continuation_token
        );
        assert_eq!(
            current.aggregate.record.interact_handle.as_deref(),
            Some(handle)
        );
        assert!(!current.aggregate.record.interaction_completed);
        assert!(!current.aggregate.revoked);
    }
    server.storage().fault.set(Fault::None);
    assert!(server.complete_interaction(handle, 1_010).is_ok());
    let current = server
        .storage()
        .lookup(GrantSelector::Id(original.id))
        .unwrap()
        .unwrap();
    assert_eq!(current.revision, Revision(1));
    assert!(current.aggregate.record.interaction_completed);
}
