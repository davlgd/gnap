//! The encoder sees approved inputs; the server owns committing its output.
use gnap_as::{
    AuthorizationServer, Decision, EncodedToken, Endpoints, KeyResolver, MemoryStorage, Nonces,
    OpaqueTokenEncoder, Policy, TokenEncoder, TokenEncodingContext, TokenEncodingError,
    TokenRecord, TokenStore,
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
        assert!(f.server.storage().is_empty());
        assert_eq!(f.seen.borrow().len(), 1);
    }
}

#[test]
fn encoder_failures_and_identifier_or_value_collisions_restore_the_entire_record() {
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
