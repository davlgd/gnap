//! An open grant, exercised through the real client, AS and proof verifier.

use gnap_as::{
    AuthorizationServer, Decision, Endpoints, EvaluationContext, Finish, GrantId, GrantSelector,
    GrantStore, KeyResolver, MemoryStorage, Nonces, Policy,
};
use gnap_client::{
    sign_request, ClientError, HttpRequest, HttpResponse, HttpTransport, Session, Step,
};
use gnap_core::State;
use gnap_crypto::{
    proof::Verifier,
    ps256::Ps256Signer,
    verify::{verify_request, Expectations, SignedRequest},
};
use gnap_types::{
    access::AccessItem,
    client::Client,
    interact::InteractCallback,
    message::{ContinueRequest, GrantRequest, GrantResponse},
    token::{AccessToken, TokenValue},
};
use std::{
    cell::{Cell, RefCell},
    collections::HashSet,
    rc::Rc,
};

const GRANT: &str = "https://as.example/gnap";
const CONTINUE: &str = "https://as.example/continue";
const RESOURCE: &str = "https://rs.example/files";

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
struct Counter(Cell<u64>);
impl Nonces for Counter {
    fn next(&self) -> String {
        let next = self.0.get() + 1;
        self.0.set(next);
        format!("value{next}")
    }
}

#[derive(Clone, Copy)]
enum Choice {
    Approve,
    Interact,
    Deny,
}
struct Control {
    choice: Cell<Choice>,
    open: Cell<bool>,
    contexts: RefCell<Vec<ObservedContext>>,
}
struct ObservedContext {
    id: Option<GrantId>,
    reference: Option<String>,
    previous: GrantRequest,
}
struct OpenPolicy(Rc<Control>);
impl Policy for OpenPolicy {
    fn evaluate(&self, request: &GrantRequest) -> Decision {
        match self.0.choice.get() {
            Choice::Approve => Decision::Approve {
                access: request.access_token.as_ref().unwrap().tokens[0]
                    .access
                    .clone(),
                subject: None,
            },
            Choice::Interact => Decision::RequireInteraction,
            Choice::Deny => Decision::Deny(gnap_registry::ErrorCode::RequestDenied),
        }
    }
    fn evaluate_context(&self, request: &GrantRequest, context: EvaluationContext<'_>) -> Decision {
        let (id, reference, previous) = match context {
            EvaluationContext::Initial => (None, None, request.clone()),
            EvaluationContext::Modification(snapshot)
            | EvaluationContext::AfterInteraction(snapshot) => (
                Some(snapshot.id),
                snapshot.aggregate.record.interact_ref.clone(),
                snapshot.aggregate.record.request.clone(),
            ),
        };
        self.0.contexts.borrow_mut().push(ObservedContext {
            id,
            reference,
            previous,
        });
        self.evaluate(request)
    }
    fn keep_grant_open(&self, _: &GrantRequest) -> bool {
        self.0.open.get()
    }
}
type Server = AuthorizationServer<OpenPolicy, Keys, MemoryStorage, Counter>;
fn server() -> (Server, Rc<Control>) {
    let control = Rc::new(Control {
        choice: Cell::new(Choice::Approve),
        open: Cell::new(true),
        contexts: RefCell::default(),
    });
    let server = AuthorizationServer::new(
        OpenPolicy(control.clone()),
        Keys,
        MemoryStorage::new(),
        Counter(Cell::new(0)),
        Endpoints {
            grant: GRANT.into(),
            continuation: CONTINUE.into(),
            interaction: "https://as.example/interact".into(),
            token_management: "https://as.example/token".into(),
        },
    );
    (server, control)
}
struct Direct<'a> {
    server: &'a Server,
    now: Cell<u64>,
}
impl HttpTransport for Direct<'_> {
    type Error = String;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        Ok(self.server.handle(&request, self.now.get()))
    }
}
fn request() -> GrantRequest {
    serde_json::from_str(r#"{"client":"client","access_token":{"access":["read","write"]},"interact":{"start":["redirect"],"finish":{"method":"redirect","uri":"https://client.example/cb","nonce":"client-first"}}}"#).unwrap()
}
fn patch() -> ContinueRequest {
    serde_json::from_str(r#"{"access_token":{"access":["read"]}}"#).unwrap()
}
fn call(
    server: &Server,
    method: &str,
    url: &str,
    token: &TokenValue,
    body: Option<Vec<u8>>,
    now: u64,
) -> HttpResponse {
    let mut request = HttpRequest::new(method, url);
    if let Some(body) = body {
        request = request.json_body(body);
    }
    let signed = sign_request(request, &signer(), Some(token), now).unwrap();
    server.handle(&signed, now)
}
fn rs_accepts(server: &Server, token: &TokenValue, right: &str, now: u64) -> bool {
    let request = sign_request(
        HttpRequest::new("GET", RESOURCE),
        &signer(),
        Some(token),
        now,
    )
    .unwrap();
    let Some(snapshot) = server
        .storage()
        .lookup(GrantSelector::AccessToken(token.as_str()))
        .unwrap()
    else {
        return false;
    };
    let Some(record) = snapshot
        .aggregate
        .tokens
        .values()
        .find(|record| &record.token.value == token)
    else {
        return false;
    };
    let nonces = RefCell::new(HashSet::new());
    record.is_valid_at(now)
        && record
            .token
            .access
            .as_ref()
            .unwrap()
            .contains(&AccessItem::Reference(right.into()))
        && verify_request(
            &SignedRequest {
                method: &request.method,
                target_uri: &request.url,
                headers: &request.headers,
                body: request.body.as_deref(),
            },
            &signer().verifier(),
            &Expectations {
                now,
                max_clock_skew: 30,
                key_id: Some("client-key"),
            },
            &|nonce: &str, _: u64| nonces.borrow_mut().insert(nonce.to_owned()),
        )
        .is_ok()
}
fn held(session: &Session<'_, Direct<'_>, Ps256Signer>, now: u64) -> AccessToken {
    session.usable_tokens(now).unwrap()[0].clone()
}
fn management_refused(server: &Server, token: &AccessToken, now: u64) {
    let manage = token.manage.as_ref().unwrap();
    assert_eq!(
        call(
            server,
            "POST",
            &manage.uri,
            &manage.access_token.value,
            None,
            now
        )
        .status,
        400
    );
}

/// Exercise a multi-token aggregate without claiming multi-token issuance.
fn add_sibling(server: &Server, token: &AccessToken) -> AccessToken {
    let mut snapshot = server
        .storage()
        .lookup(GrantSelector::AccessToken(token.value.as_str()))
        .unwrap()
        .unwrap();
    let mut sibling = snapshot.aggregate.tokens.values().next().unwrap().clone();
    sibling.token.value = TokenValue::new("sibling-access").unwrap();
    sibling.management_token = "sibling-management".into();
    sibling.identifier = Some(vec![77]);
    let manage = sibling.token.manage.as_mut().unwrap();
    manage.uri = "https://as.example/token/sibling".into();
    manage.access_token.value = TokenValue::new("sibling-management").unwrap();
    let token = sibling.token.clone();
    snapshot.aggregate.tokens.insert("sibling".into(), sibling);
    server
        .storage()
        .compare_exchange(snapshot.id, snapshot.revision, snapshot.aggregate)
        .unwrap();
    token
}

#[test]
fn approved_poll_rotates_only_continuation_and_patch_replaces_the_old_tokens() {
    let (server, control) = server();
    let key = signer();
    let transport = Direct {
        server: &server,
        now: Cell::new(1_000),
    };
    let mut client = Session::new(&transport, &key, GRANT);
    client.start(&request(), 1_000).unwrap();
    let old = held(&client, 1_000);
    let sibling = add_sibling(&server, &old);
    let first_cont = client.continuation().unwrap().access_token.value.clone();
    let first = server
        .storage()
        .lookup(GrantSelector::AccessToken(old.value.as_str()))
        .unwrap()
        .unwrap();
    assert!(rs_accepts(&server, &old.value, "write", 1_000));
    transport.now.set(1_005);
    let poll = client.continue_grant(1_005).unwrap();
    assert!(matches!(poll, Step::Approved(_)));
    assert!(poll.response().access_token.is_none());
    assert_ne!(
        client.continuation().unwrap().access_token.value,
        first_cont
    );
    assert_eq!(held(&client, 1_005), old);
    assert_eq!(control.contexts.borrow().len(), 1);
    assert_eq!(
        call(&server, "POST", CONTINUE, &first_cont, None, 1_005).status,
        400
    );
    transport.now.set(1_010);
    client.modify_grant(&patch(), 1_010).unwrap();
    let new = held(&client, 1_010);
    assert!(!rs_accepts(&server, &old.value, "read", 1_010));
    assert!(rs_accepts(&server, &new.value, "read", 1_010));
    assert!(!rs_accepts(&server, &new.value, "write", 1_010));
    management_refused(&server, &old, 1_010);
    management_refused(&server, &sibling, 1_010);
    assert!(!rs_accepts(&server, &sibling.value, "read", 1_010));
    assert!(server
        .storage()
        .lookup(GrantSelector::TokenIdentifier(&[77]))
        .unwrap()
        .is_none());
    let current = server
        .storage()
        .lookup(GrantSelector::AccessToken(new.value.as_str()))
        .unwrap()
        .unwrap();
    assert_eq!(current.id, first.id);
    assert_eq!(current.aggregate.tokens.len(), 1);
    assert_eq!(control.contexts.borrow()[1].id, Some(first.id));
    assert_eq!(control.contexts.borrow()[1].previous, request());
}

#[test]
fn new_interaction_keeps_old_access_until_approval_and_exposes_authenticated_context() {
    let (server, control) = server();
    let key = signer();
    let transport = Direct {
        server: &server,
        now: Cell::new(1_000),
    };
    let mut client = Session::new(&transport, &key, GRANT);
    client.start(&request(), 1_000).unwrap();
    let old = held(&client, 1_000);
    control.choice.set(Choice::Interact);
    let changes: ContinueRequest = serde_json::from_str(r#"{"access_token":[{"label":"subset","access":["read"]}],"interact":{"start":["redirect"],"finish":{"method":"redirect","uri":"https://client.example/new","nonce":"client-second","hash_method":"sha3-512"}}}"#).unwrap();
    transport.now.set(1_005);
    let pending = client.modify_grant(&changes, 1_005).unwrap();
    assert!(matches!(pending, Step::Pending(_)));
    assert_eq!(held(&client, 1_005), old);
    assert!(rs_accepts(&server, &old.value, "write", 1_005));
    let handle = pending
        .response()
        .interact
        .as_ref()
        .unwrap()
        .redirect
        .as_ref()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap();
    let Finish::Redirect { uri } = server.complete_interaction(handle, 1_006).unwrap() else {
        panic!("redirect expected");
    };
    let callback = InteractCallback::from_redirect(&uri).unwrap();
    client.accept_callback(&callback, 1_006).unwrap();
    control.choice.set(Choice::Approve);
    transport.now.set(1_010);
    client.continue_grant(1_010).unwrap();
    let new = held(&client, 1_010);
    assert_eq!(new.label.as_deref(), Some("subset"));
    assert!(!rs_accepts(&server, &old.value, "read", 1_010));
    assert!(rs_accepts(&server, &new.value, "read", 1_010));
    management_refused(&server, &old, 1_010);
    let contexts = control.contexts.borrow();
    assert_eq!(contexts[1].id, contexts[2].id);
    assert_eq!(
        contexts[2].reference.as_deref(),
        Some(callback.interact_ref.as_str())
    );
    assert_eq!(
        contexts[2]
            .previous
            .access_token
            .as_ref()
            .unwrap()
            .cardinality,
        gnap_types::Cardinality::Multiple
    );
}

#[test]
fn terminal_error_closes_continuation_without_revoking_existing_tokens() {
    for invalid_content in [false, true] {
        let (server, control) = server();
        let key = signer();
        let transport = Direct {
            server: &server,
            now: Cell::new(1_000),
        };
        let mut client = Session::new(&transport, &key, GRANT);
        client.start(&request(), 1_000).unwrap();
        let old = held(&client, 1_000);
        let continuation = client.continuation().unwrap().access_token.value.clone();
        control.choice.set(Choice::Deny);
        transport.now.set(1_005);
        if invalid_content {
            let response = call(
                &server,
                "PATCH",
                CONTINUE,
                &continuation,
                Some(b"not json".to_vec()),
                1_005,
            );
            assert_eq!(response.status, 400);
            let body: GrantResponse = serde_json::from_slice(&response.body).unwrap();
            assert!(body.error.is_some());
            assert!(body.r#continue.is_none());
        } else {
            assert!(matches!(
                client.modify_grant(&patch(), 1_005),
                Err(ClientError::Server(_))
            ));
            assert!(client.continuation().is_none());
            assert_eq!(held(&client, 1_005), old);
        }
        assert_eq!(
            call(&server, "POST", CONTINUE, &continuation, None, 1_010).status,
            400
        );
        assert!(rs_accepts(&server, &old.value, "write", 1_010));
    }
}

#[test]
fn revoking_an_open_grant_removes_all_credentials_and_local_tokens() {
    let (server, _) = server();
    let key = signer();
    let transport = Direct {
        server: &server,
        now: Cell::new(1_000),
    };
    let mut client = Session::new(&transport, &key, GRANT);
    client.start(&request(), 1_000).unwrap();
    let old = held(&client, 1_000);
    let sibling = add_sibling(&server, &old);
    let continuation = client.continuation().unwrap().access_token.value.clone();
    let before = server
        .storage()
        .lookup(GrantSelector::AccessToken(old.value.as_str()))
        .unwrap()
        .unwrap();
    transport.now.set(1_005);
    client.revoke_grant(1_005).unwrap();
    assert_eq!(client.state(), State::Finalized);
    assert!(client.usable_tokens(1_005).is_none());
    assert!(client.continuation().is_none());
    assert!(!rs_accepts(&server, &old.value, "read", 1_005));
    management_refused(&server, &old, 1_005);
    management_refused(&server, &sibling, 1_005);
    assert!(!rs_accepts(&server, &sibling.value, "read", 1_005));
    assert!(server
        .storage()
        .lookup(GrantSelector::TokenIdentifier(&[77]))
        .unwrap()
        .is_none());
    assert_eq!(
        call(&server, "POST", CONTINUE, &continuation, None, 1_005).status,
        400
    );
    let revoked = server
        .storage()
        .lookup(GrantSelector::Id(before.id))
        .unwrap()
        .unwrap();
    assert!(revoked.aggregate.revoked);
    assert!(revoked.aggregate.tokens.is_empty());
    assert!(server
        .storage()
        .compare_exchange(before.id, before.revision, before.aggregate)
        .is_err());
}

#[test]
fn live_credentials_cannot_be_used_in_another_protocol_role_even_with_a_valid_signature() {
    let (server, _) = server();
    let key = signer();
    let transport = Direct {
        server: &server,
        now: Cell::new(1_000),
    };
    let mut client = Session::new(&transport, &key, GRANT);
    client.start(&request(), 1_000).unwrap();
    let token = held(&client, 1_000);
    let management = token.manage.as_ref().unwrap();
    let continuation = client.continuation().unwrap().access_token.value.clone();
    for wrong in [&token.value, &management.access_token.value] {
        assert_eq!(
            call(&server, "DELETE", CONTINUE, wrong, None, 1_005).status,
            400
        );
    }
    for wrong in [&token.value, &continuation] {
        assert_eq!(
            call(&server, "DELETE", &management.uri, wrong, None, 1_005).status,
            400
        );
    }
    for wrong in [&continuation, &management.access_token.value] {
        assert!(!rs_accepts(&server, wrong, "read", 1_005));
    }
    assert!(rs_accepts(&server, &token.value, "write", 1_005));
}

#[test]
fn each_approval_reconsiders_whether_to_keep_the_grant_open() {
    let (server, control) = server();
    let key = signer();
    let transport = Direct {
        server: &server,
        now: Cell::new(1_000),
    };
    let mut client = Session::new(&transport, &key, GRANT);
    client.start(&request(), 1_000).unwrap();
    let old = held(&client, 1_000);
    control.open.set(false);
    transport.now.set(1_005);
    client.modify_grant(&patch(), 1_005).unwrap();
    assert!(client.continuation().is_none());
    assert!(!rs_accepts(&server, &old.value, "read", 1_005));
    assert!(rs_accepts(
        &server,
        &held(&client, 1_005).value,
        "read",
        1_005
    ));
}

#[test]
fn approving_a_pending_modification_does_not_leave_the_client_waiting_for_an_old_callback() {
    let (server, control) = server();
    control.choice.set(Choice::Interact);
    let key = signer();
    let transport = Direct {
        server: &server,
        now: Cell::new(1_000),
    };
    let mut client = Session::new(&transport, &key, GRANT);
    let pending = client.start(&request(), 1_000).unwrap();
    let old_handle = pending
        .response()
        .interact
        .as_ref()
        .unwrap()
        .redirect
        .as_ref()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap();
    control.choice.set(Choice::Approve);
    transport.now.set(1_005);
    client.modify_grant(&patch(), 1_005).unwrap();
    assert!(server.complete_interaction(old_handle, 1_006).is_err());
    transport.now.set(1_010);
    assert!(matches!(
        client.continue_grant(1_010),
        Ok(Step::Approved(_))
    ));
}

#[test]
fn replacing_pending_interaction_invalidates_the_old_handle_and_callback() {
    let (server, control) = server();
    control.choice.set(Choice::Interact);
    let key = signer();
    let transport = Direct {
        server: &server,
        now: Cell::new(1_000),
    };
    let mut client = Session::new(&transport, &key, GRANT);
    let first = client.start(&request(), 1_000).unwrap();
    let first_interaction = first.response().interact.as_ref().unwrap();
    let handle = first_interaction
        .redirect
        .as_ref()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap();
    let Finish::Redirect { uri } = server.complete_interaction(handle, 1_001).unwrap() else {
        panic!("redirect expected");
    };
    let old_callback = InteractCallback::from_redirect(&uri).unwrap();
    transport.now.set(1_005);
    let second = client.modify_grant(&patch(), 1_005).unwrap();
    let second_interaction = second.response().interact.as_ref().unwrap();
    assert_ne!(first_interaction.finish, second_interaction.finish);
    assert_ne!(first_interaction.redirect, second_interaction.redirect);
    assert!(client.accept_callback(&old_callback, 1_006).is_err());
    assert!(server.complete_interaction(handle, 1_006).is_err());
    let continuation = client.continuation().unwrap().access_token.value.clone();
    let reference_body =
        serde_json::to_vec(&serde_json::json!({"interact_ref":old_callback.interact_ref})).unwrap();
    let refused = call(
        &server,
        "POST",
        CONTINUE,
        &continuation,
        Some(reference_body),
        1_010,
    );
    let refused: GrantResponse = serde_json::from_slice(&refused.body).unwrap();
    assert!(refused.error.is_some());
    assert!(refused.r#continue.is_some());
    let snapshot = server
        .storage()
        .lookup(GrantSelector::Continuation(
            refused
                .r#continue
                .as_ref()
                .unwrap()
                .access_token
                .value
                .as_str(),
        ))
        .unwrap()
        .unwrap();
    assert!(!snapshot.aggregate.record.interaction_completed);
    assert!(snapshot.aggregate.record.interact_ref.is_none());
}
