//! Batch issuance is selected by label and published as one grant aggregate.

use gnap_as::{
    AuthorizationServer, Decision, EncodedToken, Endpoints, GrantSelector, GrantStore, KeyResolver,
    MemoryStorage, Nonces, Policy, TokenApproval, TokenEncoder, TokenEncodingContext,
    TokenEncodingError,
};
use gnap_client::{sign_request, HttpRequest, HttpResponse};
use gnap_crypto::{
    proof::Verifier,
    ps256::{Ps256Signer, Ps256Verifier},
};
use gnap_types::{access::AccessItem, client::Client, message::GrantRequest, token::TokenValue};
use serde_json::{json, Value};
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    num::NonZeroU64,
    rc::Rc,
};

const ENDPOINT: &str = "https://as.example/gnap";
const PRIVATE: &str = include_str!("fixtures/rfc9421-b12.pkcs1.pem");
const PUBLIC: &str = include_str!("fixtures/rfc9421-b12.spki.pem");

struct Selection(Vec<TokenApproval>);
impl Policy for Selection {
    fn evaluate(&self, _: &GrantRequest) -> Decision {
        Decision::ApproveTokens {
            tokens: self.0.clone(),
            subject: None,
        }
    }
    fn keep_grant_open(&self, _: &GrantRequest) -> bool {
        true
    }
    fn token_lifetime(&self, _: &GrantRequest) -> Option<NonZeroU64> {
        NonZeroU64::new(60)
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
struct Counter {
    count: Cell<u64>,
    script: RefCell<VecDeque<String>>,
}
impl Nonces for Counter {
    fn next(&self) -> String {
        self.count.set(self.count.get() + 1);
        self.script
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| format!("nonce{}", self.count.get()))
    }
}
enum Outcome {
    Candidate,
    Fail,
    Value(&'static str, Option<Vec<u8>>),
}
struct Encoder {
    calls: Rc<Cell<usize>>,
    outcomes: RefCell<VecDeque<Outcome>>,
}
impl TokenEncoder for Encoder {
    fn encode(
        &self,
        context: &TokenEncodingContext<'_>,
    ) -> Result<EncodedToken, TokenEncodingError> {
        self.calls.set(self.calls.get() + 1);
        match self
            .outcomes
            .borrow_mut()
            .pop_front()
            .unwrap_or(Outcome::Candidate)
        {
            Outcome::Candidate => Ok(EncodedToken {
                value: TokenValue::new(context.candidate_nonce).unwrap(),
                identifier: None,
            }),
            Outcome::Fail => Err(TokenEncodingError),
            Outcome::Value(value, identifier) => Ok(EncodedToken {
                value: TokenValue::new(value).unwrap(),
                identifier,
            }),
        }
    }
}
type Server = AuthorizationServer<Selection, Key, MemoryStorage, Counter, Encoder>;
fn approval(label: Option<&str>, right: &str) -> TokenApproval {
    TokenApproval {
        requested_label: label.map(str::to_owned),
        access: vec![AccessItem::Reference(right.into())],
    }
}
fn fixture(
    tokens: Vec<TokenApproval>,
    script: &[&str],
    outcomes: Vec<Outcome>,
) -> (Server, Rc<Cell<usize>>) {
    let calls = Rc::new(Cell::new(0));
    let server = AuthorizationServer::new(
        Selection(tokens),
        Key,
        MemoryStorage::new(),
        Counter {
            count: Cell::new(0),
            script: RefCell::new(script.iter().map(|s| (*s).into()).collect()),
        },
        Endpoints {
            grant: ENDPOINT.into(),
            continuation: "https://as.example/continue".into(),
            interaction: "https://as.example/interact".into(),
            token_management: "https://as.example/token".into(),
        },
    )
    .with_token_encoder(Encoder {
        calls: calls.clone(),
        outcomes: RefCell::new(outcomes.into()),
    });
    (server, calls)
}
fn request() -> Value {
    json!({"client":"known-client", "access_token":[
        {"label":"documents", "access":["read", "write"]},
        {"label":"reports", "access":["reports"]}
    ]})
}
fn send(
    server: &Server,
    method: &str,
    uri: &str,
    body: Option<&Value>,
    credential: Option<&str>,
    now: u64,
) -> HttpResponse {
    let signer = Ps256Signer::from_pkcs1_pem(PRIVATE, "test-key").unwrap();
    let mut request = HttpRequest::new(method, uri);
    if let Some(body) = body {
        request = request.json_body(serde_json::to_vec(body).unwrap());
    }
    let credential = credential.map(|v| TokenValue::new(v).unwrap());
    server.handle(
        &sign_request(request, &signer, credential.as_ref(), now).unwrap(),
        now,
    )
}
fn grant(server: &Server) -> Value {
    let response = send(server, "POST", ENDPOINT, Some(&request()), None, 1_000);
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    serde_json::from_slice(&response.body).unwrap()
}
fn both() -> Vec<TokenApproval> {
    vec![
        approval(Some("reports"), "reports"),
        approval(Some("documents"), "read"),
    ]
}

#[test]
fn selection_is_correlated_by_label_with_independent_rights() {
    let (server, calls) = fixture(both(), &[], vec![]);
    let response = grant(&server);
    let tokens = response["access_token"].as_array().unwrap();
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0]["label"], "documents");
    assert_eq!(tokens[0]["access"], json!(["read"]));
    assert_eq!(tokens[1]["label"], "reports");
    assert_eq!(tokens[1]["access"], json!(["reports"]));
    assert_ne!(tokens[0]["value"], tokens[1]["value"]);
    assert_ne!(tokens[0]["manage"], tokens[1]["manage"]);
    assert_eq!(calls.get(), 2);
    let first = server
        .storage()
        .lookup(GrantSelector::AccessToken(
            tokens[0]["value"].as_str().unwrap(),
        ))
        .unwrap()
        .unwrap();
    let second = server
        .storage()
        .lookup(GrantSelector::AccessToken(
            tokens[1]["value"].as_str().unwrap(),
        ))
        .unwrap()
        .unwrap();
    assert_eq!(first.id, second.id);
    assert_eq!(first.aggregate.tokens.len(), 2);
}

#[test]
fn partial_approval_of_the_second_slot_stays_an_array() {
    let (server, calls) = fixture(vec![approval(Some("reports"), "reports")], &[], vec![]);
    let response = grant(&server);
    let tokens = response["access_token"].as_array().unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0]["label"], "reports");
    assert_eq!(calls.get(), 1);
}

#[test]
fn singleton_selection_preserves_its_optional_label() {
    for label in [None, Some("documents")] {
        let (server, _) = fixture(vec![approval(label, "read")], &[], vec![]);
        let mut request = json!({"client":"known-client", "access_token":{"access":["read"]}});
        if let Some(label) = label {
            request["access_token"]["label"] = label.into();
        }
        let response = send(&server, "POST", ENDPOINT, Some(&request), None, 1_000);
        assert_eq!(response.status, 200);
        let response: Value = serde_json::from_slice(&response.body).unwrap();
        assert!(response["access_token"].is_object());
        assert_eq!(response["access_token"]["label"].as_str(), label);
    }
}

#[test]
fn invalid_policy_selection_never_reaches_the_encoder() {
    for tokens in [
        vec![],
        vec![approval(Some("unknown"), "read")],
        vec![approval(None, "read")],
        vec![approval(Some("documents"), "read"); 2],
    ] {
        let (server, calls) = fixture(tokens, &[], vec![]);
        let response = send(&server, "POST", ENDPOINT, Some(&request()), None, 1_000);
        assert_eq!(response.status, 500);
        assert!(response.has_no_store());
        assert!(serde_json::from_slice::<Value>(&response.body).is_err());
        assert_eq!(calls.get(), 0);
        assert!(server.storage().is_empty().unwrap());
    }
}

#[test]
fn an_encoder_failure_or_duplicate_native_id_publishes_nothing() {
    for outcomes in [
        vec![Outcome::Candidate, Outcome::Fail],
        vec![
            Outcome::Value("first", Some(vec![1])),
            Outcome::Value("second", Some(vec![1])),
        ],
        vec![Outcome::Value("same", None), Outcome::Value("same", None)],
    ] {
        let (server, calls) = fixture(both(), &[], outcomes);
        let response = send(&server, "POST", ENDPOINT, Some(&request()), None, 1_000);
        assert_eq!(response.status, 500);
        assert_eq!(calls.get(), 2);
        assert!(server.storage().is_empty().unwrap());
        for value in ["first", "second", "same", "nonce1", "nonce4"] {
            assert!(server
                .storage()
                .lookup(GrantSelector::AccessToken(value))
                .unwrap()
                .is_none());
        }
    }
}

#[test]
fn rotation_and_revocation_leave_the_sibling_unchanged() {
    let (server, _) = fixture(both(), &[], vec![]);
    let issued = grant(&server);
    let documents = &issued["access_token"][0];
    let reports = &issued["access_token"][1];
    let before = server
        .storage()
        .lookup(GrantSelector::AccessToken(
            documents["value"].as_str().unwrap(),
        ))
        .unwrap()
        .unwrap();
    let response = send(
        &server,
        "POST",
        reports["manage"]["uri"].as_str().unwrap(),
        None,
        reports["manage"]["access_token"]["value"].as_str(),
        1_001,
    );
    assert_eq!(response.status, 200);
    let rotated: Value = serde_json::from_slice(&response.body).unwrap();
    assert!(rotated["access_token"].is_object());
    assert_eq!(rotated["access_token"]["label"], "reports");
    assert!(server
        .storage()
        .lookup(GrantSelector::AccessToken(
            reports["value"].as_str().unwrap()
        ))
        .unwrap()
        .is_none());
    let management = &rotated["access_token"]["manage"];
    assert_eq!(
        send(
            &server,
            "DELETE",
            management["uri"].as_str().unwrap(),
            None,
            management["access_token"]["value"].as_str(),
            1_002
        )
        .status,
        204
    );
    let after = server
        .storage()
        .lookup(GrantSelector::Id(before.id))
        .unwrap()
        .unwrap();
    assert_eq!(after.aggregate.tokens.len(), 1);
    let survivor = after.aggregate.tokens.values().next().unwrap();
    let previous = before
        .aggregate
        .tokens
        .values()
        .find(|token| token.token.label.as_deref() == Some("documents"))
        .unwrap();
    assert_eq!(survivor.token, previous.token);
    assert_eq!(survivor.issued_at, previous.issued_at);
    assert_eq!(survivor.management_token, previous.management_token);
}

#[test]
fn every_sibling_credential_is_reserved_before_encoding() {
    // Candidate, management handle, management credential, repeated for the
    // second token, then the single continuation credential.
    let baseline = [
        "candidate1",
        "handle1",
        "manage1",
        "candidate2",
        "handle2",
        "manage2",
        "continue",
    ];
    for (target, source) in [
        (3, 0),
        (3, 2),
        (5, 0),
        (5, 2),
        (6, 0),
        (6, 2),
        (6, 3),
        (4, 1),
    ] {
        let mut script = baseline;
        script[target] = script[source];
        let (server, calls) = fixture(both(), &script, vec![]);
        let response = send(&server, "POST", ENDPOINT, Some(&request()), None, 1_000);
        assert_eq!(response.status, 500, "collision at {target} with {source}");
        assert_eq!(calls.get(), 0);
        assert!(server.storage().is_empty().unwrap());
    }
    for forbidden in ["candidate2", "manage1", "manage2", "continue"] {
        let (server, calls) = fixture(both(), &baseline, vec![Outcome::Value(forbidden, None)]);
        assert_eq!(
            send(&server, "POST", ENDPOINT, Some(&request()), None, 1_000).status,
            500
        );
        assert_eq!(calls.get(), 1);
        assert!(server.storage().is_empty().unwrap());
    }
}

#[test]
fn failed_reapproval_keeps_all_old_credentials_and_the_revision() {
    let (server, calls) = fixture(
        both(),
        &[],
        vec![
            Outcome::Candidate,
            Outcome::Candidate,
            Outcome::Candidate,
            Outcome::Fail,
        ],
    );
    let issued = grant(&server);
    let continuation = &issued["continue"];
    let credential = continuation["access_token"]["value"].as_str().unwrap();
    let before = server
        .storage()
        .lookup(GrantSelector::Continuation(credential))
        .unwrap()
        .unwrap();
    let response = send(
        &server,
        "PATCH",
        continuation["uri"].as_str().unwrap(),
        Some(&json!({"access_token": request()["access_token"]})),
        Some(credential),
        1_010,
    );
    assert_eq!(response.status, 500);
    assert_eq!(calls.get(), 4);
    let after = server
        .storage()
        .lookup(GrantSelector::Id(before.id))
        .unwrap()
        .unwrap();
    assert_eq!(after.revision, before.revision);
    assert_eq!(
        after.aggregate.record.continuation_token,
        before.aggregate.record.continuation_token
    );
    assert_eq!(
        after.aggregate.record.request,
        before.aggregate.record.request
    );
    assert_eq!(after.aggregate.tokens.len(), 2);
    for (handle, previous) in before.aggregate.tokens {
        let kept = &after.aggregate.tokens[&handle];
        assert_eq!(kept.token, previous.token);
        assert_eq!(kept.issued_at, previous.issued_at);
        assert_eq!(kept.management_token, previous.management_token);
    }
}

#[test]
fn successful_reapproval_replaces_the_whole_lot_in_one_revision() {
    let (server, _) = fixture(both(), &[], vec![]);
    let issued = grant(&server);
    let continuation = &issued["continue"];
    let credential = continuation["access_token"]["value"].as_str().unwrap();
    let before = server
        .storage()
        .lookup(GrantSelector::Continuation(credential))
        .unwrap()
        .unwrap();
    let response = send(
        &server,
        "PATCH",
        continuation["uri"].as_str().unwrap(),
        Some(&json!({"access_token": request()["access_token"]})),
        Some(credential),
        1_010,
    );
    assert_eq!(response.status, 200);
    let response: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(response["access_token"].as_array().unwrap().len(), 2);
    let after = server
        .storage()
        .lookup(GrantSelector::Id(before.id))
        .unwrap()
        .unwrap();
    assert_ne!(before.revision, after.revision);
    assert_eq!(after.aggregate.tokens.len(), 2);
    assert!(server
        .storage()
        .lookup(GrantSelector::Continuation(credential))
        .unwrap()
        .is_none());
    for (handle, old) in before.aggregate.tokens {
        assert!(!after.aggregate.tokens.contains_key(&handle));
        assert!(server
            .storage()
            .lookup(GrantSelector::AccessToken(old.token.value.as_str()))
            .unwrap()
            .is_none());
        assert!(server
            .storage()
            .lookup(GrantSelector::Management(&handle))
            .unwrap()
            .is_none());
    }
}
