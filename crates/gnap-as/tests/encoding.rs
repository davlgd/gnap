//! The encoder sees approved inputs; the server owns committing its output.

pub mod support;
use support::TokenLookup;

use gnap_as::{
    AuthorizationServer, Decision, EncodedToken, Endpoints, KeyResolver, MemoryStorage, Nonces,
    OpaqueTokenEncoder, Policy, TokenEncoder, TokenEncodingContext, TokenEncodingError,
    TokenRecord,
};
use gnap_client::{HttpRequest, HttpResponse, HttpTransport, Session};
use gnap_crypto::{
    proof::Verifier,
    ps256::{Ps256Signer, Ps256Verifier},
};
use gnap_types::{access::AccessItem, client::Client, message::GrantRequest, token::TokenValue};
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    num::NonZeroU64,
    rc::Rc,
    sync::Arc,
};

const ENDPOINT: &str = "https://as.example/gnap";
const PRIVATE: &str = include_str!("../../gnap-crypto/tests/rfc9421-b12.pkcs1.pem");
const PUBLIC: &str = include_str!("../../gnap-crypto/tests/rfc9421-b12.spki.pem");

struct ReadOnly;
impl Policy for ReadOnly {
    fn evaluate(&self, _: &GrantRequest) -> Decision {
        Decision::Approve {
            access: vec![AccessItem::Reference("read".into())],
            subject: None,
        }
    }
    fn token_lifetime(&self, _: &GrantRequest) -> Option<NonZeroU64> {
        NonZeroU64::new(20)
    }
}
struct Key;
impl KeyResolver for Key {
    fn resolve(&self, _: &Client) -> Option<Box<dyn Verifier>> {
        Some(Box::new(
            Ps256Verifier::from_public_key_pem(PUBLIC).unwrap(),
        ))
    }
}
struct Counter(Rc<Cell<u64>>);
impl Nonces for Counter {
    fn next(&self) -> String {
        self.0.set(self.0.get() + 1);
        format!("nonce{:04}", self.0.get())
    }
}

#[derive(Debug)]
struct Seen {
    issuer: String,
    client: Client,
    access: Vec<AccessItem>,
    issued_at: u64,
    expires_in: Option<u64>,
    candidate: String,
}
enum Outcome {
    Refuse,
    Value(&'static str, Option<Vec<u8>>),
}
struct Probe {
    seen: Rc<RefCell<Vec<Seen>>>,
    outcomes: RefCell<VecDeque<Outcome>>,
}
impl TokenEncoder for Probe {
    fn encode(
        &self,
        context: &TokenEncodingContext<'_>,
    ) -> Result<EncodedToken, TokenEncodingError> {
        self.seen.borrow_mut().push(Seen {
            issuer: context.issuer.into(),
            client: context.client.clone(),
            access: context.access.to_vec(),
            issued_at: context.issued_at,
            expires_in: context.expires_in,
            candidate: context.candidate_nonce.into(),
        });
        match self
            .outcomes
            .borrow_mut()
            .pop_front()
            .expect("encoder script exhausted")
        {
            Outcome::Refuse => Err(TokenEncodingError),
            Outcome::Value(value, identifier) => Ok(EncodedToken {
                value: TokenValue::new(value).unwrap(),
                identifier,
            }),
        }
    }
}
type Server<E = Probe> = AuthorizationServer<ReadOnly, Key, Arc<MemoryStorage>, Counter, E>;
struct Fixture {
    server: Server,
    seen: Rc<RefCell<Vec<Seen>>>,
    counter: Rc<Cell<u64>>,
}
fn fixture(outcomes: Vec<Outcome>) -> Fixture {
    let seen = Rc::new(RefCell::new(Vec::new()));
    let counter = Rc::new(Cell::new(0));
    let server = AuthorizationServer::new(
        ReadOnly,
        Key,
        Arc::new(MemoryStorage::new()),
        Counter(counter.clone()),
        Endpoints {
            grant: ENDPOINT.into(),
            continuation: "https://as.example/continue".into(),
            interaction: "https://as.example/interact".into(),
            token_management: "https://as.example/token".into(),
        },
    )
    .with_token_encoder(Probe {
        seen: seen.clone(),
        outcomes: RefCell::new(outcomes.into()),
    });
    Fixture {
        server,
        seen,
        counter,
    }
}
struct Direct<'a, E>(&'a Server<E>, Cell<u64>);
impl<E: TokenEncoder> HttpTransport for Direct<'_, E> {
    type Error = String;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        Ok(self.0.handle(&request, self.1.get()))
    }
}
fn request() -> GrantRequest {
    serde_json::from_str(r#"{"client":"known-client","access_token":{"access":["read","write"]}}"#)
        .unwrap()
}
fn signer() -> Ps256Signer {
    Ps256Signer::from_pkcs1_pem(PRIVATE, "test-key").unwrap()
}

#[test]
fn a_collision_with_another_grant_publishes_neither_issuance_nor_rotation() {
    use gnap_as::{GrantSelector, GrantStore};
    use gnap_client::sign_request;
    for duplicate_value in [false, true] {
        let duplicate = if duplicate_value {
            Outcome::Value("first", Some(vec![3]))
        } else {
            Outcome::Value("third", Some(vec![1]))
        };
        let f = fixture(vec![
            Outcome::Value("first", Some(vec![1])),
            Outcome::Value("second", Some(vec![2])),
            duplicate,
        ]);
        let grant = |now| {
            sign_request(
                HttpRequest::new("POST", ENDPOINT)
                    .json_body(serde_json::to_vec(&request()).unwrap()),
                &signer(),
                None,
                now,
            )
            .unwrap()
        };
        assert_eq!(f.server.handle(&grant(1_000), 1_000).status, 200);
        let original = f
            .server
            .storage()
            .lookup(GrantSelector::AccessToken("first"))
            .unwrap()
            .unwrap();
        assert_eq!(f.server.handle(&grant(1_001), 1_001).status, 200);
        let second = f.server.storage().get_token("nonce0005").unwrap();
        let management = second.token.manage.as_ref().unwrap();
        let rotation = sign_request(
            HttpRequest::new("POST", &management.uri),
            &signer(),
            Some(&management.access_token.value),
            1_002,
        )
        .unwrap();
        let response = f.server.handle(&rotation, 1_002);
        assert_eq!(response.status, 400);
        assert!(String::from_utf8_lossy(&response.body).contains("invalid_rotation"));
        assert!(response.has_no_store());
        assert_unchanged(&second, &f.server.storage().get_token("nonce0005").unwrap());
        assert_eq!(
            f.server
                .storage()
                .lookup(GrantSelector::Id(original.id))
                .unwrap()
                .unwrap()
                .revision,
            original.revision
        );

        let f = fixture(vec![
            Outcome::Value("first", Some(vec![1])),
            if duplicate_value {
                Outcome::Value("first", Some(vec![2]))
            } else {
                Outcome::Value("second", Some(vec![1]))
            },
        ]);
        assert_eq!(f.server.handle(&grant(1_000), 1_000).status, 200);
        let response = f.server.handle(&grant(1_001), 1_001);
        assert_eq!(response.status, 500);
        assert!(response.body.is_empty());
        assert!(f.server.storage().get_token("nonce0002").is_some());
        assert!(f.server.storage().get_token("nonce0005").is_none());
    }
}
fn assert_unchanged(before: &TokenRecord, after: &TokenRecord) {
    assert_eq!(after.identifier, before.identifier);
    assert_eq!(after.issued_at, before.issued_at);
    assert_eq!(after.token, before.token);
    assert_eq!(after.client, before.client);
    assert_eq!(after.management_token, before.management_token);
}

#[test]
fn issuance_and_rotation_encode_only_approved_context_and_store_native_identifiers() {
    let f = fixture(vec![
        Outcome::Value("encoded-initial", Some(vec![1])),
        Outcome::Value("encoded-rotated", Some(vec![2])),
    ]);
    let transport = Direct(&f.server, Cell::new(1_000));
    let signer = signer();
    let mut client = Session::new(&transport, &signer, ENDPOINT);
    let response = client.start(&request(), 1_000).unwrap();
    let token = &response.response().access_token.as_ref().unwrap().tokens[0];
    assert_eq!(token.value.as_str(), "encoded-initial");
    assert_eq!(
        token.access,
        Some(vec![AccessItem::Reference("read".into())])
    );
    assert_eq!(
        f.server
            .storage()
            .get_token("nonce0002")
            .unwrap()
            .identifier,
        Some(vec![1])
    );
    assert!(!serde_json::to_string(response.response())
        .unwrap()
        .contains("identifier"));
    transport.1.set(1_010);
    let rotated = client.rotate_token(None, 1_010).unwrap();
    assert_eq!(rotated.value.as_str(), "encoded-rotated");
    assert_eq!(rotated.access, token.access);
    assert_eq!(rotated.expires_in, Some(20));
    assert!(f.server.storage().get_token("nonce0002").is_none());
    let record = f.server.storage().get_token("nonce0006").unwrap();
    assert_eq!(record.identifier, Some(vec![2]));
    assert_eq!(record.issued_at, 1_010);
    assert_eq!(record.expires_at(), Some(1_030));
    let seen = f.seen.borrow();
    assert_eq!(seen.len(), 2);
    for (i, context) in seen.iter().enumerate() {
        assert_eq!(context.issuer, ENDPOINT);
        assert_eq!(context.client, request().client);
        assert_eq!(context.access, vec![AccessItem::Reference("read".into())]);
        assert_eq!(context.issued_at, 1_000 + u64::try_from(i).unwrap() * 10);
        assert_eq!(context.expires_in, Some(20));
        assert_ne!(context.candidate, "nonce0003");
        assert_ne!(context.candidate, "nonce0005");
    }
    assert_eq!(seen[0].candidate, "nonce0001");
    assert_eq!(seen[1].candidate, "nonce0004");
}

#[test]
fn rotation_can_drop_optional_native_metadata_without_retaining_the_old_identifier() {
    let f = fixture(vec![
        Outcome::Value("encoded-initial", Some(vec![1])),
        Outcome::Value("encoded-rotated", None),
    ]);
    let transport = Direct(&f.server, Cell::new(1_000));
    let signer = signer();
    let mut client = Session::new(&transport, &signer, ENDPOINT);
    client.start(&request(), 1_000).unwrap();
    transport.1.set(1_010);
    let rotated = client.rotate_token(None, 1_010).unwrap();
    assert_eq!(rotated.value.as_str(), "encoded-rotated");
    assert!(f.server.storage().get_token("nonce0002").is_none());
    let record = f.server.storage().get_token("nonce0006").unwrap();
    assert_eq!(record.identifier, None);
    assert_eq!(record.issued_at, 1_010);
    assert_eq!(record.expires_at(), Some(1_030));
}

#[test]
fn initial_encoder_refusal_and_invalid_output_store_no_access_token() {
    for outcome in [
        Outcome::Refuse,
        Outcome::Value("encoded", Some(vec![])),
        Outcome::Value("nonce0003", Some(vec![1])),
    ] {
        let f = fixture(vec![outcome]);
        let transport = Direct(&f.server, Cell::new(1_000));
        let signer = signer();
        let mut client = Session::new(&transport, &signer, ENDPOINT);
        assert!(client.start(&request(), 1_000).is_err());
        assert!(f.server.storage().get_token("nonce0002").is_none());
        assert!(f.server.storage().is_empty().unwrap());
        assert_eq!(f.seen.borrow().len(), 1);
    }
}

#[test]
fn issuance_rejects_a_candidate_repeating_the_management_credential_before_encoding() {
    struct Repeating(RefCell<VecDeque<&'static str>>);
    impl Nonces for Repeating {
        fn next(&self) -> String {
            self.0
                .borrow_mut()
                .pop_front()
                .expect("nonce script exhausted")
                .into()
        }
    }
    let seen = Rc::new(RefCell::new(Vec::new()));
    let server = AuthorizationServer::new(
        ReadOnly,
        Key,
        Arc::new(MemoryStorage::new()),
        Repeating(RefCell::new(
            ["management-secret", "handle", "management-secret"].into(),
        )),
        Endpoints {
            grant: ENDPOINT.into(),
            continuation: "https://as.example/continue".into(),
            interaction: "https://as.example/interact".into(),
            token_management: "https://as.example/token".into(),
        },
    )
    .with_token_encoder(Probe {
        seen: seen.clone(),
        outcomes: RefCell::new([Outcome::Value("encoded", Some(vec![1]))].into()),
    });
    let request = gnap_client::sign_request(
        HttpRequest::new("POST", ENDPOINT).json_body(serde_json::to_vec(&request()).unwrap()),
        &signer(),
        None,
        1_000,
    )
    .unwrap();
    let response = server.handle(&request, 1_000);
    assert!(
        seen.borrow().is_empty(),
        "the encoder must never receive the management credential"
    );
    assert!(!(200..300).contains(&response.status));
    assert!(response.has_no_store());
    assert!(!String::from_utf8_lossy(&response.body).contains("management-secret"));
    assert!(server.storage().get_token("handle").is_none());
    assert!(server.storage().is_empty().unwrap());
}

#[test]
fn issuance_rejects_an_encoded_value_equal_to_the_management_credential_before_storage() {
    let f = fixture(vec![Outcome::Value("nonce0003", Some(vec![1]))]);
    let request = gnap_client::sign_request(
        HttpRequest::new("POST", ENDPOINT).json_body(serde_json::to_vec(&request()).unwrap()),
        &signer(),
        None,
        1_000,
    )
    .unwrap();
    let response = f.server.handle(&request, 1_000);
    assert!(!(200..300).contains(&response.status));
    assert!(response.has_no_store());
    assert!(f.server.storage().get_token("nonce0002").is_none());
    assert!(f.server.storage().is_empty().unwrap());
    let seen = f.seen.borrow();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].candidate, "nonce0001");
    assert_eq!(f.counter.get(), 3);
}

#[test]
fn encoder_failures_and_identifier_or_value_collisions_preserve_the_entire_record() {
    for outcome in [
        Outcome::Refuse,
        Outcome::Value("new-value", Some(vec![])),
        Outcome::Value("new-value", Some(vec![1])),
        Outcome::Value("encoded-initial", Some(vec![2])),
        Outcome::Value("nonce0003", Some(vec![2])),
        Outcome::Value("nonce0005", Some(vec![2])),
    ] {
        let f = fixture(vec![
            Outcome::Value("encoded-initial", Some(vec![1])),
            outcome,
            Outcome::Value("valid-retry", Some(vec![3])),
        ]);
        let transport = Direct(&f.server, Cell::new(1_000));
        let signer = signer();
        let mut client = Session::new(&transport, &signer, ENDPOINT);
        client.start(&request(), 1_000).unwrap();
        let original = f.server.storage().get_token("nonce0002").unwrap();
        transport.1.set(1_010);
        let error = client.rotate_token(None, 1_010).unwrap_err();
        assert!(error.to_string().contains("invalid_rotation"));
        assert_unchanged(
            &original,
            &f.server.storage().get_token("nonce0002").unwrap(),
        );
        assert!(f.server.storage().get_token("nonce0006").is_none());
        transport.1.set(1_011);
        assert_eq!(
            client.rotate_token(None, 1_011).unwrap().value.as_str(),
            "valid-retry"
        );
    }
}

#[test]
fn nonce_collisions_do_not_pass_management_credentials_to_the_encoder() {
    let f = fixture(vec![Outcome::Value("encoded-initial", Some(vec![1]))]);
    let transport = Direct(&f.server, Cell::new(1_000));
    let signer = signer();
    let mut client = Session::new(&transport, &signer, ENDPOINT);
    client.start(&request(), 1_000).unwrap();
    let original = f.server.storage().get_token("nonce0002").unwrap();
    f.counter.set(2); // The broken source now repeats the current management value.
    transport.1.set(1_010);
    assert!(client.rotate_token(None, 1_010).is_err());
    assert_eq!(
        f.seen.borrow().len(),
        1,
        "the encoder was not called for rotation"
    );
    assert_unchanged(
        &original,
        &f.server.storage().get_token("nonce0002").unwrap(),
    );
}

#[test]
fn default_opaque_encoder_preserves_nonce_order_and_has_no_native_identifier() {
    let f = fixture(vec![]);
    let server = f.server.with_token_encoder(OpaqueTokenEncoder);
    let transport = Direct(&server, Cell::new(1_000));
    let signer = signer();
    let mut client = Session::new(&transport, &signer, ENDPOINT);
    let response = client.start(&request(), 1_000).unwrap();
    assert_eq!(
        response.response().access_token.as_ref().unwrap().tokens[0]
            .value
            .as_str(),
        "nonce0001"
    );
    let record = server.storage().get_token("nonce0002").unwrap();
    assert_eq!(record.management_token, "nonce0003");
    assert_eq!(record.identifier, None);
    transport.1.set(1_010);
    assert_eq!(
        client.rotate_token(None, 1_010).unwrap().value.as_str(),
        "nonce0004"
    );
    let record = server.storage().get_token("nonce0006").unwrap();
    assert_eq!(record.management_token, "nonce0005");
    assert_eq!(record.identifier, None);
    assert!(f.seen.borrow().is_empty());
}

struct OpenReadOnly;
impl Policy for OpenReadOnly {
    fn evaluate(&self, request: &GrantRequest) -> Decision {
        ReadOnly.evaluate(request)
    }
    fn keep_grant_open(&self, _: &GrantRequest) -> bool {
        true
    }
}
struct ScriptedNonces(RefCell<VecDeque<String>>);
impl Nonces for ScriptedNonces {
    fn next(&self) -> String {
        self.0
            .borrow_mut()
            .pop_front()
            .expect("nonce script exhausted")
    }
}

type OpenServer = AuthorizationServer<OpenReadOnly, Key, MemoryStorage, ScriptedNonces, Probe>;

fn open_server(
    values: &[&str],
    outcomes: Vec<Outcome>,
    seen: &Rc<RefCell<Vec<Seen>>>,
) -> OpenServer {
    AuthorizationServer::new(
        OpenReadOnly,
        Key,
        MemoryStorage::new(),
        ScriptedNonces(RefCell::new(
            values.iter().map(|value| (*value).to_owned()).collect(),
        )),
        Endpoints {
            grant: ENDPOINT.into(),
            continuation: "https://as.example/continue".into(),
            interaction: "https://as.example/interact".into(),
            token_management: "https://as.example/token".into(),
        },
    )
    .with_token_encoder(Probe {
        seen: seen.clone(),
        outcomes: RefCell::new(outcomes.into()),
    })
}

fn grant_request(now: u64) -> HttpRequest {
    gnap_client::sign_request(
        HttpRequest::new("POST", ENDPOINT).json_body(serde_json::to_vec(&request()).unwrap()),
        &signer(),
        None,
        now,
    )
    .unwrap()
}

#[test]
fn open_issuance_reserves_the_continuation_before_calling_the_encoder() {
    use gnap_as::{GrantSelector, GrantStore};
    for values in [
        ["candidate", "handle", "management", "candidate"],
        ["candidate", "handle", "management", "management"],
    ] {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let server = open_server(&values, vec![], &seen);
        assert_eq!(server.handle(&grant_request(1_000), 1_000).status, 500);
        assert!(seen.borrow().is_empty());
        assert!(server
            .storage()
            .lookup(GrantSelector::Management("handle"))
            .unwrap()
            .is_none());
        assert!(server.storage().is_empty().unwrap());
    }
}

#[test]
fn encoded_values_cannot_repeat_new_continuation_or_management_credentials() {
    use gnap_as::{GrantSelector, GrantStore};
    for encoded in ["continue", "management"] {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let server = open_server(
            &["candidate", "handle", "management", "continue"],
            vec![Outcome::Value(encoded, Some(vec![1]))],
            &seen,
        );
        assert_eq!(server.handle(&grant_request(1_000), 1_000).status, 500);
        assert_eq!(seen.borrow().len(), 1);
        assert!(server
            .storage()
            .lookup(GrantSelector::Management("handle"))
            .unwrap()
            .is_none());
        assert!(server.storage().is_empty().unwrap());
    }
}

fn assert_snapshot_unchanged(before: &gnap_as::GrantSnapshot, after: &gnap_as::GrantSnapshot) {
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.aggregate.record.grant, before.aggregate.record.grant);
    assert_eq!(
        after.aggregate.record.request,
        before.aggregate.record.request
    );
    assert_eq!(
        after.aggregate.record.continuation_token,
        before.aggregate.record.continuation_token
    );
    assert_eq!(after.id, before.id);
    assert_eq!(after.aggregate.revoked, before.aggregate.revoked);
    assert_eq!(
        after.aggregate.record.as_nonce,
        before.aggregate.record.as_nonce
    );
    assert_eq!(
        after.aggregate.record.interact_handle,
        before.aggregate.record.interact_handle
    );
    assert_eq!(
        after.aggregate.record.interact_ref,
        before.aggregate.record.interact_ref
    );
    assert_eq!(
        after.aggregate.record.interact_expires_at,
        before.aggregate.record.interact_expires_at
    );
    assert_eq!(
        after.aggregate.record.interaction_completed,
        before.aggregate.record.interaction_completed
    );
    assert_eq!(after.aggregate.tokens.len(), before.aggregate.tokens.len());
    for (handle, token) in &before.aggregate.tokens {
        assert_unchanged(token, &after.aggregate.tokens[handle]);
    }
}

fn add_native_sibling(
    storage: &impl gnap_as::GrantStore,
    mut snapshot: gnap_as::GrantSnapshot,
) -> gnap_as::GrantSnapshot {
    let mut token = snapshot.aggregate.tokens["handle1"].clone();
    token.token.value = TokenValue::new("sibling-access").unwrap();
    token.management_token = "sibling-management".into();
    token.identifier = Some(vec![2]);
    let manage = token.token.manage.as_mut().unwrap();
    manage.uri = "https://as.example/token/sibling".into();
    manage.access_token.value = TokenValue::new("sibling-management").unwrap();
    snapshot.aggregate.tokens.insert("sibling".into(), token);
    storage
        .compare_exchange(snapshot.id, snapshot.revision, snapshot.aggregate)
        .unwrap()
}

#[test]
fn a_failed_ongoing_issuance_preserves_the_snapshot_and_allows_a_fresh_retry() {
    use gnap_as::{GrantSelector, GrantStore};
    // Refusal, reuse of an old native identifier, and old/new credentials are
    // all preparation failures, before the transaction can replace old access.
    for failure in [
        Outcome::Refuse,
        Outcome::Value("new-value", Some(vec![1])),
        Outcome::Value("new-value", Some(vec![2])),
        Outcome::Value("continue1", Some(vec![2])),
        Outcome::Value("management1", Some(vec![2])),
        Outcome::Value("continue2", Some(vec![2])),
    ] {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let server = open_server(
            &[
                "candidate1",
                "handle1",
                "management1",
                "continue1",
                "candidate2",
                "handle2",
                "management2",
                "continue2",
                "candidate3",
                "handle3",
                "management3",
                "continue3",
            ],
            vec![
                Outcome::Value("value1", Some(vec![1])),
                failure,
                Outcome::Value("value3", Some(vec![3])),
            ],
            &seen,
        );
        assert_eq!(server.handle(&grant_request(1_000), 1_000).status, 200);
        let before = server
            .storage()
            .lookup(GrantSelector::Continuation("continue1"))
            .unwrap()
            .unwrap();
        let before = add_native_sibling(server.storage(), before);
        let patch = |now| {
            gnap_client::sign_request(
                HttpRequest::new("PATCH", "https://as.example/continue").json_body(b"{}".to_vec()),
                &signer(),
                Some(&TokenValue::new("continue1").unwrap()),
                now,
            )
            .unwrap()
        };
        assert_eq!(server.handle(&patch(1_005), 1_005).status, 500);
        let after = server
            .storage()
            .lookup(GrantSelector::Id(before.id))
            .unwrap()
            .unwrap();
        assert_snapshot_unchanged(&before, &after);
        for selector in [
            GrantSelector::Continuation("continue1"),
            GrantSelector::Management("handle1"),
            GrantSelector::AccessToken("value1"),
            GrantSelector::TokenIdentifier(&[1]),
            GrantSelector::TokenIdentifier(&[2]),
        ] {
            assert_eq!(
                server.storage().lookup(selector).unwrap().unwrap().revision,
                before.revision
            );
        }
        assert!(server
            .storage()
            .lookup(GrantSelector::AccessToken("new-value"))
            .unwrap()
            .is_none());
        assert!(server
            .storage()
            .lookup(GrantSelector::Management("handle2"))
            .unwrap()
            .is_none());
        assert_eq!(server.handle(&patch(1_006), 1_006).status, 200);
        assert!(server
            .storage()
            .lookup(GrantSelector::TokenIdentifier(&[1]))
            .unwrap()
            .is_none());
        assert!(server
            .storage()
            .lookup(GrantSelector::TokenIdentifier(&[2]))
            .unwrap()
            .is_none());
        assert!(server
            .storage()
            .lookup(GrantSelector::AccessToken("value1"))
            .unwrap()
            .is_none());
        assert!(server
            .storage()
            .lookup(GrantSelector::AccessToken("value3"))
            .unwrap()
            .is_some());
    }
}

#[test]
fn ongoing_candidate_reservations_cannot_expose_snapshot_credentials_to_the_encoder() {
    use gnap_as::{GrantSelector, GrantStore};
    for secret in ["continue1", "management1", "value1"] {
        let seen = Rc::new(RefCell::new(Vec::new()));
        let server = open_server(
            &[
                "candidate1",
                "handle1",
                "management1",
                "continue1",
                secret,
                "handle2",
                "management2",
                "continue2",
            ],
            vec![Outcome::Value("value1", Some(vec![1]))],
            &seen,
        );
        assert_eq!(server.handle(&grant_request(1_000), 1_000).status, 200);
        let before = server
            .storage()
            .lookup(GrantSelector::Continuation("continue1"))
            .unwrap()
            .unwrap();
        let patch = gnap_client::sign_request(
            HttpRequest::new("PATCH", "https://as.example/continue").json_body(b"{}".to_vec()),
            &signer(),
            Some(&TokenValue::new("continue1").unwrap()),
            1_005,
        )
        .unwrap();
        assert_eq!(server.handle(&patch, 1_005).status, 500);
        assert_eq!(
            seen.borrow().len(),
            1,
            "only initial issuance reached the encoder"
        );
        let after = server
            .storage()
            .lookup(GrantSelector::Continuation("continue1"))
            .unwrap()
            .unwrap();
        assert_snapshot_unchanged(&before, &after);
    }
}

#[test]
fn a_repeated_poll_credential_is_not_published_as_a_rotation() {
    use gnap_as::{GrantSelector, GrantStore};
    let seen = Rc::new(RefCell::new(Vec::new()));
    let server = open_server(
        &[
            "candidate",
            "handle",
            "management",
            "continue1",
            "continue1",
            "continue2",
        ],
        vec![Outcome::Value("access", Some(vec![1]))],
        &seen,
    );
    assert_eq!(server.handle(&grant_request(1_000), 1_000).status, 200);
    let before = server
        .storage()
        .lookup(GrantSelector::Continuation("continue1"))
        .unwrap()
        .unwrap();
    let poll = |now| {
        gnap_client::sign_request(
            HttpRequest::new("POST", "https://as.example/continue"),
            &signer(),
            Some(&TokenValue::new("continue1").unwrap()),
            now,
        )
        .unwrap()
    };
    let failure = server.handle(&poll(1_005), 1_005);
    assert_eq!(failure.status, 500);
    assert_eq!(
        failure.header_value("content-type"),
        Some("text/plain; charset=utf-8")
    );
    assert_eq!(failure.header_value("cache-control"), Some("no-store"));
    assert_eq!(
        failure.body,
        b"server configuration: the replacement continuation credential repeats its predecessor"
    );
    let after = server
        .storage()
        .lookup(GrantSelector::Continuation("continue1"))
        .unwrap()
        .unwrap();
    assert_snapshot_unchanged(&before, &after);
    assert_eq!(server.handle(&poll(1_006), 1_006).status, 200);
    assert_eq!(seen.borrow().len(), 1);
    assert!(server
        .storage()
        .lookup(GrantSelector::Continuation("continue1"))
        .unwrap()
        .is_none());
    assert!(server
        .storage()
        .lookup(GrantSelector::Continuation("continue2"))
        .unwrap()
        .is_some());
}

struct OpenDirect<'a> {
    server: &'a OpenServer,
    now: Cell<u64>,
    seen: RefCell<Vec<HttpRequest>>,
}
impl HttpTransport for OpenDirect<'_> {
    type Error = String;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        self.seen.borrow_mut().push(request.clone());
        Ok(self.server.handle(&request, self.now.get()))
    }
}

#[test]
fn an_encoder_refusal_keeps_both_the_real_client_and_server_retryable() {
    use gnap_as::{GrantSelector, GrantStore};
    let seen = Rc::new(RefCell::new(Vec::new()));
    let server = open_server(
        &[
            "candidate1",
            "handle1",
            "management1",
            "continue1",
            "candidate2",
            "handle2",
            "management2",
            "continue2",
            "candidate3",
            "handle3",
            "management3",
            "continue3",
        ],
        vec![
            Outcome::Value("value1", Some(vec![1])),
            Outcome::Refuse,
            Outcome::Value("value3", Some(vec![3])),
        ],
        &seen,
    );
    let transport = OpenDirect {
        server: &server,
        now: Cell::new(1_000),
        seen: RefCell::default(),
    };
    let key = signer();
    let mut client = Session::new(&transport, &key, ENDPOINT);
    client.start(&request(), 1_000).unwrap();
    let old_token = client.usable_tokens(1_000).unwrap()[0].clone();
    let old_continuation = client.continuation().cloned();
    let old_state = client.state();
    let old_subject = client.subject().map(|subject| subject.subject.clone());
    let before = server
        .storage()
        .lookup(GrantSelector::Continuation("continue1"))
        .unwrap()
        .unwrap();
    let changes =
        serde_json::from_str(r#"{"access_token":[{"label":"updated","access":["read"]}]}"#)
            .unwrap();
    transport.now.set(1_005);
    let failure = client.modify_grant(&changes, 1_005);
    assert!(
        matches!(
            failure,
            Err(gnap_client::ClientError::Parse(_) | gnap_client::ClientError::Protocol(_))
        ),
        "{failure:?}"
    );
    assert_eq!(client.state(), old_state);
    assert_eq!(client.continuation(), old_continuation.as_ref());
    assert_eq!(client.usable_tokens(1_005).unwrap(), vec![&old_token]);
    assert_eq!(
        client.subject().map(|subject| subject.subject.clone()),
        old_subject
    );
    let after = server
        .storage()
        .lookup(GrantSelector::Continuation("continue1"))
        .unwrap()
        .unwrap();
    assert_snapshot_unchanged(&before, &after);
    for selector in [
        GrantSelector::Management("handle1"),
        GrantSelector::AccessToken("value1"),
        GrantSelector::TokenIdentifier(&[1]),
    ] {
        assert_eq!(
            server.storage().lookup(selector).unwrap().unwrap().revision,
            before.revision
        );
    }
    for selector in [
        GrantSelector::Continuation("continue2"),
        GrantSelector::Management("handle2"),
        GrantSelector::AccessToken("candidate2"),
    ] {
        assert!(server.storage().lookup(selector).unwrap().is_none());
    }
    transport.now.set(1_006);
    client.modify_grant(&changes, 1_006).unwrap();
    assert_eq!(
        client.usable_tokens(1_006).unwrap()[0].value.as_str(),
        "value3"
    );
    let requests = transport.seen.borrow();
    assert_eq!(requests.len(), 3);
    assert_ne!(
        requests[1].header_value("signature-input"),
        requests[2].header_value("signature-input")
    );
}
