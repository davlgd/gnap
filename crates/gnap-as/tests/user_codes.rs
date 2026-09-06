//! Real SDK exchanges for the optional human-code profile, without HTTP.
use gnap_as::{
    normalize_user_code, AuthorizationServer, Decision, Endpoints, Finish, GrantSelector,
    GrantStore, InteractionError, KeyResolver, MemoryStorage, Nonces, Policy, UserCodeStore,
};
use gnap_client::{HttpRequest, HttpResponse, HttpTransport, Session, Step};
use gnap_crypto::{Ps256Signer, Ps256Verifier, Verifier};
use gnap_types::{
    client::Client,
    message::{ContinueRequest, GrantRequest},
};
use serde_json::{json, Value};
use std::{
    cell::Cell,
    collections::VecDeque,
    sync::{Arc, Barrier, Mutex},
};

#[path = "user_codes/storage.rs"]
mod storage_tests;

const ENDPOINT: &str = "https://as.example/gnap";
const ENTRY: &str = "https://as.example/code";
const KEY: &str = include_str!("../../gnap-crypto/tests/rfc9421-b12.pkcs1.pem");
const PUBLIC: &str = include_str!("../../gnap-crypto/tests/rfc9421-b12.spki.pem");

struct Consent;
impl Policy for Consent {
    fn evaluate(&self, _: &GrantRequest) -> Decision {
        Decision::RequireInteraction
    }
    fn evaluate_after_interaction(&self, _: &GrantRequest) -> Decision {
        Decision::Approve {
            access: vec![gnap_types::access::AccessItem::Reference("files".into())],
            subject: None,
        }
    }
    fn keep_grant_open(&self, _: &GrantRequest) -> bool {
        true
    }
}
struct Keys;
impl KeyResolver for Keys {
    fn resolve(&self, _: &Client) -> Option<Box<dyn Verifier>> {
        Some(Box::new(
            Ps256Verifier::from_public_key_pem(PUBLIC).unwrap(),
        ))
    }
}
#[derive(Default)]
struct Draws {
    next: u64,
    forced: VecDeque<String>,
    seen: Vec<String>,
}
#[derive(Clone, Default)]
struct Source(Arc<Mutex<Draws>>);
impl Nonces for Source {
    fn next(&self) -> String {
        let mut draws = self.0.lock().unwrap();
        draws.next += 1;
        let value = draws
            .forced
            .pop_front()
            .unwrap_or_else(|| format!("test-nonce-{}", draws.next));
        draws.seen.push(value.clone());
        value
    }
}
type Server<S = Arc<MemoryStorage>> = AuthorizationServer<Consent, Keys, S, Source>;
struct Fixture {
    server: Server,
    storage: Arc<MemoryStorage>,
    source: Source,
}
fn fixture() -> Fixture {
    let storage = Arc::new(MemoryStorage::new());
    let source = Source::default();
    let server = engine(storage.clone(), source.clone());
    Fixture {
        server,
        storage,
        source,
    }
}

fn engine<S: gnap_as::Storage>(storage: S, source: Source) -> Server<S> {
    AuthorizationServer::new(
        Consent,
        Keys,
        storage,
        source,
        Endpoints {
            grant: ENDPOINT.into(),
            continuation: "https://as.example/continue".into(),
            interaction: "https://as.example/interact".into(),
            token_management: "https://as.example/token".into(),
        },
    )
}
struct Direct<'a, S: gnap_as::Storage = Arc<MemoryStorage>> {
    server: &'a Server<S>,
    now: Cell<u64>,
}
impl<S: gnap_as::Storage> HttpTransport for Direct<'_, S> {
    type Error = std::convert::Infallible;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        Ok(self.server.handle(&request, self.now.get()))
    }
}
fn request(modes: &[&str], finish: Option<&str>) -> GrantRequest {
    let mut value = json!({"client":"test-client", "access_token":{"access":["files"]}, "interact":{"start":modes}});
    if let Some(method) = finish {
        value["interact"]["finish"] =
            json!({"method":method,"uri":"https://client.example/finish","nonce":"client-nonce"});
    }
    serde_json::from_value(value).unwrap()
}
fn code(step: &Step) -> &str {
    let interaction = step.response().interact.as_ref().unwrap();
    interaction
        .user_code
        .as_deref()
        .unwrap_or_else(|| &interaction.user_code_uri.as_ref().unwrap().code)
}

#[test]
fn requested_code_modes_preserve_uri_and_complete_by_poll_redirect_or_push() {
    let signer = Ps256Signer::from_pkcs1_pem(KEY, "client").unwrap();
    for modes in [
        vec!["user_code"],
        vec!["user_code_uri"],
        vec!["user_code", "user_code_uri"],
        vec!["redirect", "user_code", "user_code_uri"],
    ] {
        for finish in [None, Some("redirect"), Some("push")] {
            let mut f = fixture();
            f.server = f.server.with_user_code_uri(ENTRY).unwrap();
            let direct = Direct {
                server: &f.server,
                now: Cell::new(1_000),
            };
            let mut client = Session::new(&direct, &signer, ENDPOINT).supporting(&modes);
            let pending = client.start(&request(&modes, finish), 1_000).unwrap();
            let response = pending.response().interact.as_ref().unwrap();
            assert_eq!(response.user_code.is_some(), modes.contains(&"user_code"));
            assert_eq!(
                response.user_code_uri.is_some(),
                modes.contains(&"user_code_uri")
            );
            assert_eq!(response.redirect.is_some(), modes.contains(&"redirect"));
            assert_eq!(response.expires_in, Some(600));
            let code = code(&pending);
            assert_eq!(normalize_user_code(code).as_deref(), Some(code));
            if let Some(pair) = &response.user_code_uri {
                assert_eq!(pair.uri, ENTRY);
                assert_eq!(pair.code, code);
                assert!(!pair.uri.to_ascii_uppercase().contains(code));
            }
            let formatted = format!("{} - {}", code[..4].to_ascii_lowercase(), &code[4..]);
            let handle = f.server.resolve_user_code(&formatted, 1_001).unwrap();
            assert_ne!(handle, code);
            if let Some(redirect) = &response.redirect {
                assert!(redirect.ends_with(&handle));
            }
            let saved = f.storage.lookup_user_code(code).unwrap().unwrap();
            assert!(!saved.aggregate.record.interaction_completed);
            match f.server.complete_interaction(&handle, 1_001).unwrap() {
                Finish::SendTheUserBack => assert!(finish.is_none()),
                Finish::Redirect { uri } => client.accept_redirect(&uri, 1_001).unwrap(),
                Finish::Push { body, .. } => client.accept_push(&body, 1_001).unwrap(),
            }
            assert!(f.server.resolve_user_code(code, 1_002).is_err());
            assert!(f.server.complete_interaction(&handle, 1_002).is_err());
            assert!(f.storage.lookup_user_code(code).unwrap().is_none());
            let saved = f
                .storage
                .lookup(GrantSelector::Id(saved.id))
                .unwrap()
                .unwrap();
            assert!(saved.aggregate.record.user_code.is_none());
            assert!(saved.aggregate.record.interact_handle.is_none());
            direct.now.set(1_005);
            assert!(matches!(
                client.continue_grant(1_005).unwrap(),
                Step::Approved(_)
            ));
        }
    }
}

#[test]
fn normalization_has_one_bounded_case_insensitive_crockford_meaning() {
    for input in [
        "A10B2345",
        "a l o b 2 3 4 5",
        "a-i-o-b-2-3-4-5",
        "A\n1\t0B!23🙂45",
    ] {
        assert_eq!(normalize_user_code(input).as_deref(), Some("A10B2345"));
    }
    for input in ["", "1234567", "123456789", "éééééééé", "!!!!!!!!"] {
        assert!(normalize_user_code(input).is_none());
    }
    assert!(normalize_user_code(&format!("{}12345678", " ".repeat(121))).is_none());
    assert_eq!(
        normalize_user_code(&format!("{}12345678", " ".repeat(120))).as_deref(),
        Some("12345678")
    );
}

#[test]
fn configuration_is_opt_in_bounded_and_preserved_by_encoder_changes() {
    let signer = Ps256Signer::from_pkcs1_pem(KEY, "client").unwrap();
    let f = fixture();
    let direct = Direct {
        server: &f.server,
        now: Cell::new(1_000),
    };
    let mut client = Session::new(&direct, &signer, ENDPOINT);
    assert!(client.start(&request(&["user_code"], None), 1_000).is_err());
    assert!(f.storage.is_empty().unwrap());
    assert!(f.server.resolve_user_code("12345678", 1_000).is_err());
    let fallback = Session::new(&direct, &signer, ENDPOINT)
        .start(
            &request(&["redirect", "user_code", "user_code_uri"], None),
            1_000,
        )
        .unwrap();
    let interaction = fallback.response().interact.as_ref().unwrap();
    assert!(interaction.redirect.is_some());
    assert!(interaction.user_code.is_none());
    assert!(interaction.user_code_uri.is_none());
    for uri in [
        "/code",
        "http://as.example/code",
        "https:///code",
        "https://a/code?x=1",
        "https://a/code#x",
        "https://a/%63ode",
        "https://name:secret@a/code",
        "http://[::1]evil/code",
    ] {
        let error = fixture().server.with_user_code_uri(uri).err().unwrap();
        assert_eq!(error.to_string(), "invalid user-code entry URI");
    }
    assert!(fixture()
        .server
        .with_user_code_uri(format!("https://a/{}", "x".repeat(256)))
        .is_err());
    for uri in [
        ENTRY,
        "http://localhost:18081/code",
        "http://127.0.0.1/code",
        "http://[::1]/code",
    ] {
        let server = fixture()
            .server
            .with_user_code_uri(uri)
            .unwrap()
            .with_token_encoder(gnap_as::OpaqueTokenEncoder);
        let response = server.handle(&HttpRequest::new("OPTIONS", ENDPOINT), 1_000);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            body["interaction_start_modes_supported"],
            json!(["redirect", "user_code", "user_code_uri"])
        );
    }
}

#[test]
fn expiry_replacement_and_removal_retire_codes_without_changing_other_grants() {
    let mut f = fixture();
    f.server = f.server.with_user_code_uri(ENTRY).unwrap();
    let signer = Ps256Signer::from_pkcs1_pem(KEY, "client").unwrap();
    let direct = Direct {
        server: &f.server,
        now: Cell::new(1_000),
    };
    let mut client = Session::new(&direct, &signer, ENDPOINT);
    let pending = client
        .start(&request(&["user_code_uri"], None), 1_000)
        .unwrap();
    let old = code(&pending).to_owned();
    let old_handle = f.server.resolve_user_code(&old, 1_599).unwrap();
    assert!(matches!(
        f.server.resolve_user_code(&old, 1_600),
        Err(InteractionError::Expired)
    ));
    assert!(matches!(
        f.server.complete_interaction(&old_handle, 1_600),
        Err(InteractionError::Expired)
    ));
    let mut sibling = Session::new(&direct, &signer, ENDPOINT);
    let sibling = sibling
        .start(&request(&["user_code"], None), 1_000)
        .unwrap();
    direct.now.set(1_605);
    let changes: ContinueRequest =
        serde_json::from_value(json!({"interact":{"start":["user_code_uri"]}})).unwrap();
    let next = client.modify_grant(&changes, 1_605).unwrap();
    assert_ne!(code(&next), old);
    assert!(f.server.resolve_user_code(&old, 1_605).is_err());
    assert!(f.server.complete_interaction(&old_handle, 1_605).is_err());
    assert!(f
        .storage
        .lookup_user_code(code(&sibling))
        .unwrap()
        .is_some());
    let saved = f.storage.lookup_user_code(code(&next)).unwrap().unwrap();
    f.storage.remove(saved.id, saved.revision).unwrap();
    assert!(f.storage.lookup_user_code(code(&next)).unwrap().is_none());
}

#[test]
fn simultaneous_completions_of_the_two_modes_have_one_winner() {
    let mut f = fixture();
    f.server = f.server.with_user_code_uri(ENTRY).unwrap();
    let signer = Ps256Signer::from_pkcs1_pem(KEY, "client").unwrap();
    let direct = Direct {
        server: &f.server,
        now: Cell::new(1_000),
    };
    let mut client = Session::new(&direct, &signer, ENDPOINT);
    let pending = client
        .start(&request(&["redirect", "user_code_uri"], None), 1_000)
        .unwrap();
    let handle = f.server.resolve_user_code(code(&pending), 1_001).unwrap();
    let redirect = pending
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
    assert_eq!(handle, redirect);
    let gate = Barrier::new(3);
    std::thread::scope(|scope| {
        let workers = [&handle[..], redirect].map(|handle| {
            scope.spawn(|| {
                gate.wait();
                f.server.complete_interaction(handle, 1_001).is_ok()
            })
        });
        gate.wait();
        assert_eq!(
            workers
                .into_iter()
                .map(|worker| usize::from(worker.join().unwrap()))
                .sum::<usize>(),
            1
        );
    });
    assert!(f.server.resolve_user_code(code(&pending), 1_001).is_err());
}

#[test]
fn code_generation_retries_active_collisions_but_never_publishes_on_exhaustion() {
    let signer = Ps256Signer::from_pkcs1_pem(KEY, "client").unwrap();
    for collisions in [1, 3] {
        let mut f = fixture();
        f.server = f.server.with_user_code_uri(ENTRY).unwrap();
        let direct = Direct {
            server: &f.server,
            now: Cell::new(1_000),
        };
        let mut first = Session::new(&direct, &signer, ENDPOINT);
        let original = first.start(&request(&["user_code"], None), 1_000).unwrap();
        let seed = f.source.0.lock().unwrap().seen[1].clone();
        {
            let mut draws = f.source.0.lock().unwrap();
            assert_eq!(
                draws.seen.len(),
                4,
                "dedicated nonce, code seed, handle, continuation"
            );
            draws.forced.push_back("new-as-nonce".into());
            draws
                .forced
                .extend(std::iter::repeat_n(seed.clone(), collisions));
        }
        let saved = f
            .storage
            .lookup_user_code(code(&original))
            .unwrap()
            .unwrap();
        let mut second = Session::new(&direct, &signer, ENDPOINT);
        let result = second.start(&request(&["user_code"], None), 1_000);
        if collisions == 1 {
            let next = result.unwrap();
            assert_ne!(code(&next), code(&original));
            assert_eq!(f.storage.len().unwrap(), 2);
        } else {
            let message = result.unwrap_err().to_string();
            assert!(!message.contains(&seed));
            assert!(!message.contains(code(&original)));
            assert_eq!(f.storage.len().unwrap(), 1);
        }
        let current = f
            .storage
            .lookup_user_code(code(&original))
            .unwrap()
            .unwrap();
        assert_eq!(current.id, saved.id);
        assert_eq!(current.revision, saved.revision);
    }
}

#[test]
fn malformed_nonce_seeds_and_codes_embedded_in_the_entry_uri_are_not_emitted() {
    let signer = Ps256Signer::from_pkcs1_pem(KEY, "client").unwrap();
    for seed in [String::new(), "x".repeat(513)] {
        let mut f = fixture();
        f.server = f.server.with_user_code_uri(ENTRY).unwrap();
        f.source
            .0
            .lock()
            .unwrap()
            .forced
            .extend(["as-nonce".into(), seed]);
        let direct = Direct {
            server: &f.server,
            now: Cell::new(1_000),
        };
        assert!(Session::new(&direct, &signer, ENDPOINT)
            .start(&request(&["user_code"], None), 1_000)
            .is_err());
        assert!(f.storage.is_empty().unwrap());
    }
    let mut f = fixture();
    f.server = f.server.with_user_code_uri(ENTRY).unwrap();
    let direct = Direct {
        server: &f.server,
        now: Cell::new(1_000),
    };
    let first = Session::new(&direct, &signer, ENDPOINT)
        .start(&request(&["user_code_uri"], None), 1_000)
        .unwrap();
    let uri = format!("{ENTRY}/{}", code(&first).to_ascii_lowercase());
    let mut other = fixture();
    other.server = other.server.with_user_code_uri(&uri).unwrap();
    let direct = Direct {
        server: &other.server,
        now: Cell::new(1_000),
    };
    let second = Session::new(&direct, &signer, ENDPOINT)
        .start(&request(&["user_code_uri"], None), 1_000)
        .unwrap();
    assert_ne!(code(&first), code(&second));
    assert_eq!(
        second
            .response()
            .interact
            .as_ref()
            .unwrap()
            .user_code_uri
            .as_ref()
            .unwrap()
            .uri,
        uri
    );
}
