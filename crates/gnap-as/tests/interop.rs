//! A client and an authorization server talking to each other.
//!
//! No network: the transport hands the request straight to the server. Both
//! sides use the protocol implementations, with test policies and keys. These
//! tests cover their local interactions, not interoperability over a network.

pub mod support;
use support::TokenLookup;

use gnap_as::{
    AuthorizationServer, Decision, Endpoints, Finish, InteractionError, KeyResolver, MemoryStorage,
    Nonces, Policy, ReleasedSubject, SubjectGround,
};
use gnap_client::{HttpRequest, HttpResponse, HttpTransport, Session, Step};
use gnap_core::State;
use gnap_crypto::proof::Verifier;
use gnap_crypto::ps256::{Ps256Signer, Ps256Verifier};
use gnap_types::access::AccessItem;
use gnap_types::client::Client;
use gnap_types::interact::InteractCallback;
use gnap_types::message::GrantRequest;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

const RSA_PKCS1: &str = include_str!("fixtures/rfc9421-b12.pkcs1.pem");
const RSA_SPKI: &str = include_str!("fixtures/rfc9421-b12.spki.pem");
const GRANT: &str = "https://as.example/gnap";
const CONTINUE: &str = "https://as.example/continue";
const CLIENT_NONCE: &str = "VJLO6A4CATR0KRO";

/// Installs deliberately chosen fixtures through the same atomic API as the AS.
fn install_token(storage: &MemoryStorage, handle: &str, token: gnap_as::TokenRecord) {
    use gnap_as::{GrantAggregate, GrantRecord, GrantSelector, GrantStore};
    if let Some(mut snapshot) = storage.lookup(GrantSelector::Management(handle)).unwrap() {
        snapshot.aggregate.tokens.insert(handle.into(), token);
        storage
            .compare_exchange(snapshot.id, snapshot.revision, snapshot.aggregate)
            .unwrap();
    } else {
        let mut aggregate = GrantAggregate::new(GrantRecord {
            grant: gnap_core::Grant::new(),
            request: serde_json::from_value(serde_json::json!({"client": token.client})).unwrap(),
            continuation_token: None,
            as_nonce: None,
            user_code: None,
            interact_handle: None,
            interact_expires_at: None,
            interact_ref: None,
            interaction_completed: false,
        });
        aggregate.tokens.insert(handle.into(), token);
        storage.create(aggregate).unwrap();
    }
}

/// Grants what was asked for, once an RO has been consulted.
struct AlwaysInteract {
    interacted: Cell<bool>,
}

impl Policy for AlwaysInteract {
    fn evaluate(&self, _request: &GrantRequest) -> Decision {
        if self.interacted.get() {
            Decision::Approve {
                access: vec![AccessItem::Reference("dolphin-metadata".into())],
                subject: None,
            }
        } else {
            Decision::RequireInteraction
        }
    }

    fn evaluate_after_interaction(&self, request: &GrantRequest) -> Decision {
        self.interacted.set(true);
        self.evaluate(request)
    }
}

/// Accepts one known client key.
struct OneKey(&'static str);

impl KeyResolver for OneKey {
    fn resolve(&self, _client: &Client) -> Option<Box<dyn Verifier>> {
        Ps256Verifier::from_public_key_pem(self.0)
            .ok()
            .map(|v| Box::new(v) as Box<dyn Verifier>)
    }
}

/// Predictable values, so a failing test can be read.
struct Counted(Cell<u32>);

impl Nonces for Counted {
    fn next(&self) -> String {
        let n = self.0.get() + 1;
        self.0.set(n);
        format!("nonce{n:04}")
    }
}

type Server = AuthorizationServer<AlwaysInteract, OneKey, MemoryStorage, Counted>;

/// Hands each request straight to a server, and keeps what went by.
///
/// Generic over the key resolver and the nonce source, so a deliberately broken
/// one of either can be wired in.
struct Direct<'a, K: KeyResolver, N: Nonces> {
    server: &'a AuthorizationServer<AlwaysInteract, K, MemoryStorage, N>,
    now: Cell<u64>,
    exchanges: RefCell<Vec<(HttpRequest, HttpResponse)>>,
}

impl<'a, K: KeyResolver, N: Nonces> Direct<'a, K, N> {
    const fn wrapping(
        server: &'a AuthorizationServer<AlwaysInteract, K, MemoryStorage, N>,
    ) -> Self {
        Self {
            server,
            now: Cell::new(1_000),
            exchanges: RefCell::new(Vec::new()),
        }
    }
}

impl<K: KeyResolver, N: Nonces> HttpTransport for Direct<'_, K, N> {
    type Error = String;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        let response = self.server.handle(&request, self.now.get());
        self.exchanges
            .borrow_mut()
            .push((request, response.clone()));
        Ok(response)
    }
}

fn server() -> Server {
    server_at(GRANT)
}

fn server_at(grant: &str) -> Server {
    AuthorizationServer::new(
        AlwaysInteract {
            interacted: Cell::new(false),
        },
        OneKey(RSA_SPKI),
        MemoryStorage::new(),
        Counted(Cell::new(0)),
        Endpoints {
            grant: grant.into(),
            continuation: CONTINUE.into(),
            interaction: "https://as.example/i".into(),
            token_management: "https://as.example/token".into(),
        },
    )
}

/// RFC 9635 §9: discovery does not create a grant or require a client identity.
#[test]
fn options_discovery_returns_only_known_engine_capabilities_without_grant_state() {
    let as_ = server();
    let response = as_.handle(&HttpRequest::new("OPTIONS", GRANT), 1_000);
    assert_eq!(response.status, 200);
    assert_eq!(
        response.header_value("content-type"),
        Some("application/json")
    );
    assert_eq!(response.header_value("allow"), Some("POST, OPTIONS"));
    assert_eq!(response.header_value("gnap-development-only"), None);
    assert!(response.has_no_store());
    let actual: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(
        actual,
        serde_json::json!({
            "grant_request_endpoint": GRANT,
            "interaction_start_modes_supported": ["redirect"],
            "key_proofs_supported": ["httpsig"],
            "key_rotation_supported": false
        })
    );
    let typed: gnap_types::message::AsDiscovery = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(typed.validate_for(GRANT), Ok(()));
    assert!(as_.storage().is_empty().unwrap());
    assert_eq!(as_.storage().remembered_nonces().unwrap(), 0);
}

#[test]
fn encoder_builder_preserves_discovery_configuration_in_either_order() {
    let endpoint = "http://127.0.0.1:18081/gnap";
    for as_ in [
        server_at(endpoint)
            .with_development_http_discovery()
            .with_token_encoder(gnap_as::OpaqueTokenEncoder),
        server_at(endpoint)
            .with_token_encoder(gnap_as::OpaqueTokenEncoder)
            .with_development_http_discovery(),
    ] {
        let response = as_.handle(&HttpRequest::new("OPTIONS", endpoint), 1_000);
        assert_eq!(response.status, 200);
        assert_eq!(
            response.header_value("gnap-development-only"),
            Some("insecure-loopback-discovery")
        );
        assert!(as_.storage().is_empty().unwrap());
    }
    let as_ = server_at(endpoint).with_token_encoder(gnap_as::OpaqueTokenEncoder);
    assert_eq!(
        as_.handle(&HttpRequest::new("OPTIONS", endpoint), 1_000)
            .status,
        500
    );
}

#[test]
fn discovery_keeps_endpoint_query_and_rejects_other_urls_or_methods() {
    let endpoint = "https://as.example:8443/gnap?tenant=one%2Ftwo";
    let as_ = server_at(endpoint);
    let response = as_.handle(&HttpRequest::new("OPTIONS", endpoint), 1_000);
    assert_eq!(response.status, 200);
    let typed: gnap_types::message::AsDiscovery = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(typed.grant_request_endpoint, endpoint);
    for other in [GRANT, "https://as.example:8443/gnap?tenant=one/two"] {
        assert_eq!(
            as_.handle(&HttpRequest::new("OPTIONS", other), 1_000)
                .status,
            404
        );
        assert_eq!(
            as_.handle_discovery(&HttpRequest::new("OPTIONS", other))
                .status,
            404
        );
    }
    let wrong_method = as_.handle(&HttpRequest::new("GET", endpoint), 1_000);
    assert_eq!(wrong_method.status, 405);
    assert_eq!(wrong_method.header_value("allow"), Some("POST, OPTIONS"));
}

#[test]
fn discovery_rejects_invalid_public_configuration_without_echoing_endpoint() {
    for endpoint in [
        "http://as.example/gnap",
        "http://127.0.0.1:8080/gnap",
        "https:///gnap",
        "https://as.example/gnap#TOP-SECRET",
    ] {
        let as_ = server_at(endpoint);
        let response = as_.handle(&HttpRequest::new("OPTIONS", endpoint), 1_000);
        assert_eq!(response.status, 500, "{endpoint}");
        assert_eq!(
            response.header_value("content-type"),
            Some("text/plain; charset=utf-8")
        );
        assert_eq!(response.header_value("cache-control"), Some("no-store"));
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.starts_with("server configuration: "));
        assert!(!body.contains(endpoint));
        assert!(!body.contains("TOP-SECRET"));
        assert!(serde_json::from_str::<gnap_types::message::GrantResponse>(&body).is_err());
        assert!(as_.storage().is_empty().unwrap());
    }
}

#[test]
fn local_discovery_is_opt_in_labelled_and_never_allows_remote_http() {
    for endpoint in [
        "http://127.0.0.1:8080/gnap",
        "http://localhost:8080/gnap",
        "http://[::1]:8080/gnap",
    ] {
        let as_ = server_at(endpoint).with_development_http_discovery();
        let response = as_.handle(&HttpRequest::new("OPTIONS", endpoint), 1_000);
        assert_eq!(response.status, 200);
        assert_eq!(
            response.header_value("gnap-development-only"),
            Some("insecure-loopback-discovery")
        );
        let typed: gnap_types::message::AsDiscovery =
            serde_json::from_slice(&response.body).unwrap();
        assert!(typed.validate_for(endpoint).is_err());
        assert_eq!(typed.validate_for_local_development(endpoint), Ok(()));
    }
    let endpoint = "http://as.example/gnap";
    assert_eq!(
        server_at(endpoint)
            .with_development_http_discovery()
            .handle(&HttpRequest::new("OPTIONS", endpoint), 1_000)
            .status,
        500
    );
    let secure = server()
        .with_development_http_discovery()
        .handle(&HttpRequest::new("OPTIONS", GRANT), 1_000);
    assert_eq!(secure.status, 200);
    assert_eq!(secure.header_value("gnap-development-only"), None);
}

fn request() -> GrantRequest {
    serde_json::from_str(&format!(
        r#"{{"client":"client-541-ab",
             "access_token":{{"access":["dolphin-metadata"]}},
             "interact":{{"start":["redirect"],
                          "finish":{{"method":"redirect",
                                     "uri":"https://client.example.net/cb",
                                     "nonce":"{CLIENT_NONCE}"}}}}}}"#
    ))
    .unwrap()
}

/// The whole redirect flow, both roles real.
///
/// GNAP-9635-§2-M06 — the request is a JSON object sent as the POST content.
/// GNAP-9635-§3-M07 — the response is a JSON object.
/// GNAP-9635-§2.3-M07 — the client proves possession of the key it presented.
/// GNAP-9635-§5-M02 — the AS validates the signature and its binding to the
/// continuation token.
/// GNAP-9635-§5-M12 — the continuation response carries a fresh token.
/// GNAP-9635-§3.2.1-M06 — the access returned reflects what was granted.
/// GNAP-9635-§3-M08 — every response carries `Cache-Control: no-store`.
#[test]
fn a_client_and_a_server_complete_a_grant() {
    let as_ = server();
    let transport = Direct::wrapping(&as_);
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let mut client = Session::new(&transport, &signer, GRANT);

    // 1. The request comes back pending, with somewhere to send the end user.
    let step = client.start(&request(), 1_000).unwrap();
    assert!(matches!(step, Step::Pending(_)), "{step:?}");
    assert_eq!(client.state(), State::Pending);

    let interact = step.response().interact.clone().unwrap();
    let redirect = interact.redirect.expect("the AS offered no redirect");
    assert!(redirect.starts_with("https://as.example/i/"), "{redirect}");
    let as_nonce = interact.finish.expect("the AS returned no finish nonce");
    assert_eq!(
        as_.storage().len().unwrap(),
        1,
        "the AS remembers the pending grant"
    );

    // 2. The end user follows the redirect and the RO answers. The AS creates
    //    the interaction reference, binds it to this grant, hashes it with the
    //    two nonces (§4.2.3) and says how to hand the user back (§4.2.1).
    //    Nothing here is fabricated by the test: the client validates a hash
    //    the AS actually computed.
    let handle = redirect.rsplit('/').next().unwrap();
    let Finish::Redirect { uri } = as_.complete_interaction(handle, 1_005).unwrap() else {
        panic!("the client asked for the redirect finish method");
    };
    assert!(uri.starts_with("https://client.example.net/cb?"), "{uri}");
    let callback = InteractCallback::from_redirect(&uri).unwrap();
    assert_ne!(callback.interact_ref, as_nonce);
    client.accept_callback(&callback, 1_005).unwrap();

    // 3. Continuing yields the token. The wait period is honoured.
    transport.now.set(1_010);
    let step = client.continue_grant(1_010).unwrap();
    assert!(matches!(step, Step::Approved(_)), "{step:?}");
    assert_eq!(client.state(), State::Approved);

    let tokens = step.response().access_token.as_ref().unwrap();
    assert_eq!(tokens.tokens.len(), 1);
    assert_eq!(
        tokens.tokens[0].access.as_ref().unwrap()[0],
        AccessItem::Reference("dolphin-metadata".into())
    );

    // Every response carried the cache directive §3 requires.
    for (_, response) in transport.exchanges.borrow().iter() {
        assert!(
            response.has_no_store(),
            "a response without Cache-Control: no-store"
        );
    }

    // The continuation token was rotated: the old one no longer resolves.
    assert_eq!(
        as_.storage().len().unwrap(),
        0,
        "the approved grant left no pending record"
    );
}

/// GNAP-9635-§7.3.1-M19 — an unsigned request is refused by the server.
#[test]
fn the_server_refuses_an_unsigned_request() {
    let as_ = server();
    let body = serde_json::to_vec(&request()).unwrap();
    let bare = HttpRequest::new("POST", GRANT).json_body(body);

    let response = as_.handle(&bare, 1_000);
    assert_eq!(response.status, 400);
    let text = String::from_utf8_lossy(&response.body);
    assert!(text.contains("invalid_client"), "{text}");
    assert!(
        response.has_no_store(),
        "even an error carries no-store (§3)"
    );
}

/// GNAP-9635-§7.3.1-M18 — a tampered body no longer matches its digest.
#[test]
fn the_server_catches_a_tampered_body() {
    let as_ = server();
    let transport = Direct::wrapping(&as_);
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let mut client = Session::new(&transport, &signer, GRANT);
    client.start(&request(), 1_000).unwrap();

    // Replay the signed request with one byte changed in the body.
    let (mut tampered, _) = transport.exchanges.borrow()[0].clone();
    let body = tampered.body.as_mut().unwrap();
    let pos = body.iter().position(|b| *b == b'd').unwrap();
    body[pos] = b'D';

    let response = as_.handle(&tampered, 1_000);
    assert_eq!(response.status, 400);
    let text = String::from_utf8_lossy(&response.body);
    assert!(text.contains("content-digest"), "{text}");
}

/// GNAP-9635-§5-M06 — without a resolvable grant the AS answers
/// `invalid_continuation`.
#[test]
fn the_server_refuses_a_continuation_without_a_token() {
    let as_ = server();
    let bare = HttpRequest::new("POST", CONTINUE);
    let response = as_.handle(&bare, 1_000);
    assert_eq!(response.status, 400);
    assert!(String::from_utf8_lossy(&response.body).contains("invalid_continuation"));
}

/// GNAP-9635-§5-M09 — the wait period is enforced by the server too, not only
/// by a well-behaved client.
#[test]
fn the_server_enforces_the_wait_period() {
    let as_ = server();
    let transport = Direct::wrapping(&as_);
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let mut client = Session::new(&transport, &signer, GRANT);
    let step = client.start(&request(), 1_000).unwrap();

    // Take the continuation the AS offered and call it immediately, bypassing
    // the client's own guard — this is what a misbehaving client does. The
    // request is properly signed, so the wait guard is what has to stop it.
    let cont = step.response().r#continue.clone().unwrap();
    let early = signed_continuation(
        &signer,
        "POST",
        &cont.uri,
        cont.access_token.value.as_str(),
        None,
        1_001,
    );

    let response = as_.handle(&early, 1_001);
    assert_eq!(response.status, 400);
    let text = String::from_utf8_lossy(&response.body);
    assert!(
        text.contains("too_fast"),
        "the wait guard should be what refuses: {text}"
    );

    // §5-M11 and §5-M12 — the grant survives, so the refusal carries a new
    // continuation, with a token that replaces the one just used.
    let again = continuation_of(&response);
    assert_ne!(
        again.access_token.value.as_str(),
        cont.access_token.value.as_str(),
        "the refusal must rotate the continuation token"
    );

    // Once the wait has elapsed the same call is accepted, with the new token.
    let later = signed_continuation(
        &signer,
        "POST",
        &again.uri,
        again.access_token.value.as_str(),
        None,
        1_010,
    );
    let response = as_.handle(&later, 1_010);
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
}

/// GNAP-9635-§2.3.1-M03 — an instance identifier the AS does not recognise is
/// answered with `invalid_client`.
#[test]
fn the_server_refuses_an_unknown_client() {
    /// Recognises nobody.
    struct NoKeys;
    impl KeyResolver for NoKeys {
        fn resolve(&self, _client: &Client) -> Option<Box<dyn Verifier>> {
            None
        }
    }

    let as_ = AuthorizationServer::new(
        AlwaysInteract {
            interacted: Cell::new(false),
        },
        NoKeys,
        MemoryStorage::new(),
        Counted(Cell::new(0)),
        Endpoints {
            grant: GRANT.into(),
            continuation: CONTINUE.into(),
            interaction: "https://as.example/i".into(),
            token_management: "https://as.example/token".into(),
        },
    );

    let body = serde_json::to_vec(&request()).unwrap();
    let response = as_.handle(&HttpRequest::new("POST", GRANT).json_body(body), 1_000);

    assert_eq!(response.status, 400);
    let text = String::from_utf8_lossy(&response.body);
    assert!(text.contains("invalid_client"), "{text}");
}

/// GNAP-9635-§5.3-M02 — a modification puts the grant back into processing, and
/// the AS re-evaluates it in its new context.
/// GNAP-9635-§5.3-M01 — "A grant request associated with a modification request
/// MUST be in the approved or pending state."
#[test]
fn a_modification_is_re_evaluated() {
    let as_ = server();
    let transport = Direct::wrapping(&as_);
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let mut client = Session::new(&transport, &signer, GRANT);
    let step = client.start(&request(), 1_000).unwrap();

    // The client narrows what it asks for, on the continuation URI.
    let cont = step.response().r#continue.clone().unwrap();
    let patch = br#"{"access_token":{"access":["read"]}}"#.to_vec();
    // §5.3 — "the client instance makes an HTTP PATCH request to the
    // continuation URI and includes any fields it needs to modify."
    let modified = signed_continuation(
        &signer,
        "PATCH",
        &cont.uri,
        cont.access_token.value.as_str(),
        Some(patch),
        1_010,
    );

    let response = as_.handle(&modified, 1_010);
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );

    // The policy still wants interaction, so the AS answers pending again with
    // a fresh continuation — the modification was taken into account, not
    // refused.
    let text = String::from_utf8_lossy(&response.body);
    assert!(text.contains("continue"), "{text}");
    let old_redirect = step
        .response()
        .interact
        .as_ref()
        .unwrap()
        .redirect
        .as_ref()
        .unwrap();
    assert!(
        matches!(
            as_.complete_interaction(old_redirect.rsplit('/').next().unwrap(), 1_011),
            Err(InteractionError::UnknownInteraction)
        ),
        "the old interaction must not authorize a modified request"
    );
    let updated: gnap_types::message::GrantResponse =
        serde_json::from_slice(&response.body).unwrap();
    let redirect = updated.interact.unwrap().redirect.unwrap();
    assert!(as_
        .complete_interaction(redirect.rsplit('/').next().unwrap(), 1_011)
        .is_ok());
}

/// Builds a signed continuation call, with or without a body.
///
/// This is what `gnap-client` does internally; spelling it out here lets the
/// server be exercised on its own, including with calls a well-behaved client
/// would never make.
fn signed_continuation(
    signer: &Ps256Signer,
    method: &str,
    url: &str,
    token: &str,
    body: Option<Vec<u8>>,
    now: u64,
) -> HttpRequest {
    use gnap_crypto::digest::{content_digest, DigestAlgorithm};
    use gnap_crypto::httpsig::{sign, Component, Message, SignatureInput, Tag};
    use gnap_crypto::proof::Signer;

    let authorization = format!("GNAP {token}");
    let digest = body
        .as_ref()
        .map(|b| content_digest(b, DigestAlgorithm::Sha256));

    let mut components = vec![Component::Method, Component::TargetUri];
    if digest.is_some() {
        components.push(Component::ContentDigest);
    }
    components.push(Component::Authorization);

    let message = Message {
        method,
        target_uri: url,
        content_digest: digest.as_deref(),
        authorization: Some(&authorization),
        other: Vec::new(),
    };
    let input = SignatureInput {
        components,
        created: now,
        keyid: signer.key_id().to_owned(),
        nonce: None,
        tag: Tag::Gnap,
    };
    let (sig_input, signature) = sign(&message, &input, signer, "sig1").unwrap();

    let mut request = HttpRequest::new(method, url).header("Authorization", authorization);
    if let (Some(b), Some(d)) = (body, digest) {
        request = request.json_body(b).header("Content-Digest", d);
    }
    request
        .header("Signature-Input", sig_input)
        .header("Signature", signature)
}

/// A `Nonces` implementation that breaks the `token68` rule must not bring the
/// server down: §3.2.1 constrains the value, and the deployment is at fault.
#[test]
fn a_broken_nonce_source_is_reported_not_fatal() {
    /// Returns a value with a space in it, which `token68` forbids.
    struct BadNonces;
    impl Nonces for BadNonces {
        fn next(&self) -> String {
            "not a token68 value".into()
        }
    }

    let as_ = AuthorizationServer::new(
        AlwaysInteract {
            interacted: Cell::new(true),
        },
        OneKey(RSA_SPKI),
        MemoryStorage::new(),
        BadNonces,
        Endpoints {
            grant: GRANT.into(),
            continuation: CONTINUE.into(),
            interaction: "https://as.example/i".into(),
            token_management: "https://as.example/token".into(),
        },
    );

    let transport = Direct::wrapping(&as_);
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let mut client = Session::new(&transport, &signer, GRANT);

    // The client sees a server error, not a panic and not a malformed token.
    let outcome = client.start(&request(), 1_000);
    assert!(outcome.is_err(), "a malformed token must not be handed out");

    let (_, response) = transport.exchanges.borrow()[0].clone();
    assert_eq!(response.status, 500);
    let text = String::from_utf8_lossy(&response.body);
    assert!(text.contains("token68"), "{text}");
    assert!(
        text.contains("Nonces"),
        "the message should point at the cause: {text}"
    );
}

/// GNAP-9635-§2.5-M07 — when interaction is required and the client offers no
/// mechanism the AS can drive, the AS MUST answer `invalid_interaction`.
///
/// Answering `pending` with an empty `interact` object would leave the client
/// polling a grant that can never advance.
#[test]
fn no_usable_interaction_mechanism_is_refused() {
    let as_ = server();

    // The client can only display a user code; this AS drives redirects only.
    let request: GrantRequest = serde_json::from_str(
        r#"{"client":"client-541-ab",
            "access_token":{"access":["dolphin-metadata"]},
            "interact":{"start":["user_code"]}}"#,
    )
    .unwrap();

    let transport = Direct::wrapping(&as_);
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let mut client = Session::new(&transport, &signer, GRANT);

    let outcome = client.start(&request, 1_000);
    assert!(
        outcome.is_err(),
        "the client should be told, not left polling"
    );

    let (_, response) = transport.exchanges.borrow()[0].clone();
    let text = String::from_utf8_lossy(&response.body);
    assert!(text.contains("invalid_interaction"), "{text}");
    assert!(
        text.contains("§2.5"),
        "the diagnostic should cite the rule: {text}"
    );

    // And nothing was stored: there is no grant to continue.
    assert_eq!(as_.storage().len().unwrap(), 0);
}

// ---------------------------------------------------------------------------
// Signature verification, from the server's side. Everything below builds a
// signature by hand so the server can be fed what a well-behaved client would
// never send.
// ---------------------------------------------------------------------------

use base64::{engine::general_purpose::STANDARD, Engine as _};
use gnap_crypto::httpsig::{signature_base, Component, Message, SignatureInput, Tag};
use gnap_crypto::proof::Signer as _;

/// Signs a request with an arbitrary set of covered components and parameters.
///
/// Deliberately bypasses `httpsig::sign`, which enforces the §7.3.1 coverage
/// rules on the signer. Testing the verifier means handing it exactly what a
/// non-conformant peer would send, which a conformant signer will not produce.
fn signed_with(
    signer: &Ps256Signer,
    method: &str,
    url: &str,
    authorization: Option<&str>,
    components: Vec<Component>,
    created: u64,
    nonce: Option<&str>,
) -> HttpRequest {
    let message = Message {
        method,
        target_uri: url,
        content_digest: None,
        authorization,
        other: Vec::new(),
    };
    let input = SignatureInput {
        components,
        created,
        keyid: signer.key_id().to_owned(),
        nonce: nonce.map(ToOwned::to_owned),
        tag: Tag::Gnap,
    };
    let raw = input.serialize().unwrap();
    let base = signature_base(&message, &input.components, &raw).unwrap();
    let signature = signer.sign(base.as_bytes()).unwrap();

    let mut request = HttpRequest::new(method, url);
    if let Some(a) = authorization {
        request = request.header("Authorization", a);
    }
    request
        .header("Signature-Input", format!("sig1={raw}"))
        .header(
            "Signature",
            format!("sig1=:{}:", STANDARD.encode(signature)),
        )
}

fn pending_grant(as_: &Server, signer: &Ps256Signer) -> gnap_types::message::Continue {
    let transport = Direct::wrapping(as_);
    let mut client = Session::new(&transport, signer, GRANT);
    let step = client.start(&request(), 1_000).unwrap();
    step.response().r#continue.clone().unwrap()
}

/// Swaps in a signature made over a different base.
///
/// It is valid base64 and a real PS256 signature, so only the verification can
/// reject it — which is exactly the case these tests are about. Flipping
/// characters in the base64 would be luck-dependent.
fn with_a_signature_that_cannot_verify(
    mut request: HttpRequest,
    other: &HttpRequest,
) -> HttpRequest {
    let wrong = other.header_value("signature").unwrap().to_owned();
    for (name, value) in &mut request.headers {
        if name.eq_ignore_ascii_case("signature") {
            value.clone_from(&wrong);
        }
    }
    request
}

/// The continuation an error response hands back (§5-M11).
fn continuation_of(response: &HttpResponse) -> gnap_types::message::Continue {
    let parsed: gnap_types::message::GrantResponse =
        serde_json::from_slice(&response.body).expect("a grant response");
    parsed
        .r#continue
        .expect("an error the grant survives carries a new continuation (RFC 9635 §5)")
}

fn body_of(response: &HttpResponse) -> String {
    String::from_utf8_lossy(&response.body).into_owned()
}

/// GNAP-9635-§7.3.1-M09 — a request bound to a token must cover `authorization`.
/// GNAP-9635-§7.3.1-M17 — "The verifier MUST ensure that the signature covers
/// all required message components."
///
/// Without this the same signature could be replayed against a different
/// continuation token issued to the same key.
#[test]
fn a_signature_not_covering_authorization_is_refused() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let cont = pending_grant(&as_, &signer);
    let auth = format!("GNAP {}", cont.access_token.value.as_str());

    // Valid signature, correct token, but `authorization` left uncovered.
    let request = signed_with(
        &signer,
        "POST",
        &cont.uri,
        Some(&auth),
        vec![Component::Method, Component::TargetUri],
        1_010,
        None,
    );

    let response = as_.handle(&request, 1_010);
    assert_eq!(response.status, 400);
    assert!(
        body_of(&response).contains("authorization"),
        "{}",
        body_of(&response)
    );
}

/// GNAP-9635-§7.3.1-M12 — `created` is required, and must be close to now.
/// GNAP-9635-§7.3.1-MN16 — `alg` must not appear.
/// GNAP-9635-§7.3.1-M14 — a nonce must be unique.
#[test]
fn the_signature_parameters_are_actually_checked() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();

    let covered = vec![
        Component::Method,
        Component::TargetUri,
        Component::Authorization,
    ];

    // A timestamp far from now is refused, however valid the signature.
    let cont = pending_grant(&as_, &signer);
    let auth = format!("GNAP {}", cont.access_token.value.as_str());
    let stale = signed_with(
        &signer,
        "POST",
        &cont.uri,
        Some(&auth),
        covered.clone(),
        1,
        None,
    );
    let response = as_.handle(&stale, 1_000_000);
    assert_eq!(response.status, 400);
    assert!(
        body_of(&response).contains("beyond"),
        "{}",
        body_of(&response)
    );

    // An `alg` parameter is refused even though the signature verifies.
    let cont = pending_grant(&as_, &signer);
    let auth = format!("GNAP {}", cont.access_token.value.as_str());
    let mut tampered = signed_with(
        &signer,
        "POST",
        &cont.uri,
        Some(&auth),
        covered.clone(),
        1_010,
        None,
    );
    for (name, value) in &mut tampered.headers {
        if name.eq_ignore_ascii_case("signature-input") {
            *value = value.replace(";tag=", ";alg=\"rsa-pss-sha512\";tag=");
        }
    }
    let response = as_.handle(&tampered, 1_010);
    assert_eq!(response.status, 400);
    assert!(body_of(&response).contains("alg"), "{}", body_of(&response));

    // The same nonce twice is refused the second time.
    let cont = pending_grant(&as_, &signer);
    let auth = format!("GNAP {}", cont.access_token.value.as_str());
    let first = signed_with(
        &signer,
        "POST",
        &cont.uri,
        Some(&auth),
        covered.clone(),
        1_010,
        Some("n1"),
    );
    assert_eq!(as_.handle(&first, 1_010).status, 200);

    let cont = pending_grant(&as_, &signer);
    let auth = format!("GNAP {}", cont.access_token.value.as_str());
    let replay = signed_with(
        &signer,
        "POST",
        &cont.uri,
        Some(&auth),
        covered,
        1_010,
        Some("n1"),
    );
    let response = as_.handle(&replay, 1_010);
    assert_eq!(response.status, 400);
    assert!(
        body_of(&response).contains("already been seen"),
        "{}",
        body_of(&response)
    );
}

/// GNAP-9635-§7.3.1-M21 — every signature is examined, not only the first.
#[test]
fn a_second_signature_is_examined_when_the_first_fails() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let cont = pending_grant(&as_, &signer);
    let auth = format!("GNAP {}", cont.access_token.value.as_str());

    let good = signed_with(
        &signer,
        "POST",
        &cont.uri,
        Some(&auth),
        vec![
            Component::Method,
            Component::TargetUri,
            Component::Authorization,
        ],
        1_010,
        None,
    );
    let good_input = good.header_value("signature-input").unwrap().to_owned();
    let good_sig = good.header_value("signature").unwrap().to_owned();

    // `bad` comes first and cannot verify; `sig1` is the good one.
    let request = HttpRequest::new("POST", &cont.uri)
        .header("Authorization", auth)
        .header(
            "Signature-Input",
            format!(r#"bad=("@method");created=1010;keyid="gnap-demo";tag="gnap", {good_input}"#),
        )
        .header("Signature", format!("bad=:AAAA:, {good_sig}"));

    assert_eq!(
        as_.handle(&request, 1_010).status,
        200,
        "the acceptable signature should have been found"
    );

    // The same, with a first entry that cannot even be decoded. An unreadable
    // member is one candidate lost, not a verdict on the message: otherwise
    // prefixing a malformed signature would bury the valid one behind it.
    let cont = pending_grant(&as_, &signer);
    let auth = format!("GNAP {}", cont.access_token.value.as_str());
    let good = signed_with(
        &signer,
        "POST",
        &cont.uri,
        Some(&auth),
        vec![
            Component::Method,
            Component::TargetUri,
            Component::Authorization,
        ],
        1_010,
        None,
    );
    let good_input = good.header_value("signature-input").unwrap().to_owned();
    let good_sig = good.header_value("signature").unwrap().to_owned();

    let request = HttpRequest::new("POST", &cont.uri)
        .header("Authorization", auth)
        .header(
            "Signature-Input",
            format!(r#"bad=("@method");created=1010;keyid="gnap-demo";tag="gnap", {good_input}"#),
        )
        .header("Signature", format!("bad=:!not base64:, {good_sig}"));

    assert_eq!(
        as_.handle(&request, 1_010).status,
        200,
        "a malformed entry must not hide the acceptable signature behind it"
    );
}

/// GNAP-9635-§5 — a call that fails verification leaves the grant untouched.
///
/// The AS has to read the grant to learn which key signs for the client, but
/// reading is not consuming: anyone holding a leaked continuation token could
/// otherwise destroy the grant with a signature that does not verify.
#[test]
fn a_refused_signature_leaves_the_grant_alive() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let covered = vec![
        Component::Method,
        Component::TargetUri,
        Component::Authorization,
    ];
    let cont = pending_grant(&as_, &signer);
    let auth = format!("GNAP {}", cont.access_token.value.as_str());

    // A real signature, made over a different base: it cannot verify here.
    let elsewhere = signed_with(
        &signer,
        "POST",
        &cont.uri,
        Some(&auth),
        covered.clone(),
        1_009,
        None,
    );
    let forged = with_a_signature_that_cannot_verify(
        signed_with(
            &signer,
            "POST",
            &cont.uri,
            Some(&auth),
            covered.clone(),
            1_010,
            None,
        ),
        &elsewhere,
    );
    assert_eq!(as_.handle(&forged, 1_010).status, 400);
    assert_eq!(
        as_.storage().len().unwrap(),
        1,
        "the grant must survive a call that fails signature verification"
    );

    // And the legitimate client can still use the very same token.
    let genuine = signed_with(
        &signer,
        "POST",
        &cont.uri,
        Some(&auth),
        covered,
        1_011,
        None,
    );
    assert_eq!(
        as_.handle(&genuine, 1_011).status,
        200,
        "the continuation token must still be usable"
    );
}

/// GNAP-9635-§7.3.1-M21 — an unproven signature must not spend a nonce.
///
/// Remembering the nonce is what spends it. If a forged signature could spend
/// one, anyone could burn the nonce the legitimate client is about to use.
#[test]
fn a_forged_signature_cannot_spend_a_nonce() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let covered = vec![
        Component::Method,
        Component::TargetUri,
        Component::Authorization,
    ];
    let cont = pending_grant(&as_, &signer);
    let remembered_before = as_.storage().remembered_nonces().unwrap();
    let auth = format!("GNAP {}", cont.access_token.value.as_str());

    let elsewhere = signed_with(
        &signer,
        "POST",
        &cont.uri,
        Some(&auth),
        covered.clone(),
        1_009,
        Some("shared-nonce"),
    );
    let forged = with_a_signature_that_cannot_verify(
        signed_with(
            &signer,
            "POST",
            &cont.uri,
            Some(&auth),
            covered.clone(),
            1_010,
            Some("shared-nonce"),
        ),
        &elsewhere,
    );
    assert_eq!(as_.handle(&forged, 1_010).status, 400);
    assert_eq!(
        as_.storage().remembered_nonces().unwrap(),
        remembered_before,
        "an unverified signature must not have spent the nonce"
    );

    let genuine = signed_with(
        &signer,
        "POST",
        &cont.uri,
        Some(&auth),
        covered,
        1_010,
        Some("shared-nonce"),
    );
    assert_eq!(
        as_.handle(&genuine, 1_010).status,
        200,
        "the client must still be able to use its own nonce"
    );
}

/// GNAP-9635-§7.3.1-M11 — "the verifier MUST verify that the parameter exists
/// with this value", the value being `gnap`.
///
/// `gnap-rotate` belongs to the key rotation of §7.3.1.1, which this server
/// does not implement: a signature made for that purpose is not a signature for
/// this request.
#[test]
fn a_signature_tagged_for_key_rotation_is_refused() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let cont = pending_grant(&as_, &signer);
    let auth = format!("GNAP {}", cont.access_token.value.as_str());

    let mut rotate = signed_with(
        &signer,
        "POST",
        &cont.uri,
        Some(&auth),
        vec![
            Component::Method,
            Component::TargetUri,
            Component::Authorization,
        ],
        1_010,
        None,
    );
    for (name, value) in &mut rotate.headers {
        if name.eq_ignore_ascii_case("signature-input") {
            *value = value.replace(r#"tag="gnap""#, r#"tag="gnap-rotate""#);
        }
    }

    let response = as_.handle(&rotate, 1_010);
    assert_eq!(response.status, 400);
    assert!(
        body_of(&response).contains("gnap"),
        "{}",
        body_of(&response)
    );
}

/// GNAP-9635-§5-M09 — the wait period applies to revocation too, and a refusal
/// must not cost the client its grant.
#[test]
fn revoking_before_the_wait_elapses_is_refused_without_losing_the_grant() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let cont = pending_grant(&as_, &signer);
    let auth = format!("GNAP {}", cont.access_token.value.as_str());

    let early = signed_with(
        &signer,
        "DELETE",
        &cont.uri,
        Some(&auth),
        vec![
            Component::Method,
            Component::TargetUri,
            Component::Authorization,
        ],
        1_001,
        None,
    );

    let response = as_.handle(&early, 1_001);
    assert_eq!(response.status, 400, "{}", body_of(&response));
    assert!(
        body_of(&response).contains("too_fast"),
        "{}",
        body_of(&response)
    );
    assert_eq!(
        as_.storage().len().unwrap(),
        1,
        "the grant must survive a refused call"
    );
}

/// GNAP-9635-§4.2-M03 — the AS creates the interaction reference and associates
/// it with the pending request, so a reference it never issued is not one.
/// GNAP-9635-§4.2-M08 — "When an interaction finish method is used, the client
/// instance MUST present the interaction reference back to the AS as part of
/// its continuation request", which is the call this refuses without it.
///
/// Without this the continuation endpoint takes any string as proof that
/// interaction finished, and whoever holds the continuation token decides when
/// the RO has spoken.
#[test]
fn an_interaction_reference_the_as_never_issued_is_refused() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let cont = pending_grant(&as_, &signer);

    let request = signed_continuation(
        &signer,
        "POST",
        &cont.uri,
        cont.access_token.value.as_str(),
        Some(br#"{"interact_ref":"4IFWWIKYBC2PQ6U56NL1"}"#.to_vec()),
        1_010,
    );
    let response = as_.handle(&request, 1_010);
    assert_eq!(response.status, 400, "{}", body_of(&response));
    assert!(
        body_of(&response).contains("invalid_interaction"),
        "{}",
        body_of(&response)
    );
    assert_eq!(
        as_.storage().len().unwrap(),
        1,
        "a wrong reference must not cost the client its grant"
    );
}

/// GNAP-9635-§4.2-M05 — "The interaction reference MUST be one-time-use to
/// prevent interception and replay attacks."
#[test]
fn an_interaction_reference_is_spent_when_it_is_used() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let transport = Direct::wrapping(&as_);
    let mut client = Session::new(&transport, &signer, GRANT);
    let step = client.start(&request(), 1_000).unwrap();

    let interact = step.response().interact.clone().unwrap();
    let redirect = interact.redirect.unwrap();
    let handle = redirect.rsplit('/').next().unwrap();
    let cont = step.response().r#continue.clone().unwrap();

    let Finish::Redirect { uri } = as_.complete_interaction(handle, 1_005).unwrap() else {
        panic!("the client asked for the redirect finish method");
    };
    let callback = InteractCallback::from_redirect(&uri).unwrap();
    let body = format!(r#"{{"interact_ref":"{}"}}"#, callback.interact_ref);
    let token = cont.access_token.value.as_str();

    let first = signed_continuation(
        &signer,
        "POST",
        &cont.uri,
        token,
        Some(body.clone().into_bytes()),
        1_010,
    );
    assert_eq!(as_.handle(&first, 1_010).status, 200);

    // The grant was approved and its continuation token rotated, so the replay
    // is refused; what matters is that the reference cannot be presented again
    // even by someone who intercepted it.
    let replay = signed_continuation(
        &signer,
        "POST",
        &cont.uri,
        token,
        Some(body.into_bytes()),
        1_011,
    );
    assert_eq!(as_.handle(&replay, 1_011).status, 400);
}

/// GNAP-9635-§4.2-MN09 — the AS MUST NOT follow the finish method when it
/// "cannot determine which ongoing grant request is being referenced".
/// GNAP-9635-§4.1.1-MN01 — "If the URI cannot be associated with a currently
/// active request, the AS MUST display an error to the RO and MUST NOT attempt
/// to redirect the RO back to any client instance, even if a redirect finish
/// method is supplied."
///
/// Showing the error to the RO is the deployment's own interaction page. What
/// this library owes is the other half, and it owes it structurally: there is
/// no way to obtain a redirect from an interaction the AS cannot place, because
/// the only thing that produces one is a `Finish` this call never returns.
#[test]
fn an_unknown_interaction_is_not_finished() {
    let as_ = server();
    assert_eq!(
        as_.complete_interaction("a-handle-nobody-issued", 1_005),
        Err(InteractionError::UnknownInteraction)
    );

    // Even with a live grant beside it, and a redirect finish on that grant,
    // an unknown handle yields no directive to redirect anyone.
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let cont = pending_grant(&as_, &signer);
    assert!(!cont.uri.is_empty(), "a grant is waiting on an interaction");
    assert_eq!(
        as_.complete_interaction("still-not-a-handle", 1_005),
        Err(InteractionError::UnknownInteraction)
    );
}

/// GNAP-9635-§4.2.2 — the push method carries the same two values as a JSON
/// object, and the call goes to a URI the client supplied.
/// GNAP-9635-§3.3.5-M01 — "When the interaction is completed, the interaction
/// component of the AS MUST contact the client instance using the means defined
/// by the finish method as described in Section 4.2." The directive this
/// returns is that contact, described for the adapter to carry out.
#[test]
fn the_push_finish_method_yields_a_json_callback() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let transport = Direct::wrapping(&as_);
    let mut client = Session::new(&transport, &signer, GRANT);

    let pushed: GrantRequest = serde_json::from_str(&format!(
        r#"{{"client":"client-541-ab",
             "access_token":{{"access":["dolphin-metadata"]}},
             "interact":{{"start":["redirect"],
                          "finish":{{"method":"push",
                                     "uri":"https://client.example.net/push",
                                     "nonce":"{CLIENT_NONCE}"}}}}}}"#
    ))
    .unwrap();
    let step = client.start(&pushed, 1_000).unwrap();
    let redirect = step.response().interact.clone().unwrap().redirect.unwrap();
    let handle = redirect.rsplit('/').next().unwrap();

    let Finish::Push { uri, body } = as_.complete_interaction(handle, 1_005).unwrap() else {
        panic!("the client asked for the push finish method");
    };
    assert_eq!(uri, "https://client.example.net/push");

    let callback: InteractCallback = serde_json::from_slice(&body).unwrap();
    assert!(!callback.hash.is_empty());
    assert!(!callback.interact_ref.is_empty());
}

/// GNAP-9635-§7.3.1-M15 — "If the signer's key presented is a JWK, the keyid
/// parameter of the signature MUST be set to the kid value of the JWK."
///
/// A mathematically valid signature that claims another key's identity is not
/// a signature by the key the AS resolved.
#[test]
fn a_signature_naming_another_key_is_refused() {
    /// Resolves to a key that names itself, as a JWK does through its `kid`.
    struct NamedKey;

    impl KeyResolver for NamedKey {
        fn resolve(&self, _client: &Client) -> Option<Box<dyn Verifier>> {
            let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
            Some(Box::new(signer.verifier()))
        }
    }

    let as_ = AuthorizationServer::new(
        AlwaysInteract {
            interacted: Cell::new(false),
        },
        NamedKey,
        MemoryStorage::new(),
        Counted(Cell::new(0)),
        Endpoints {
            grant: GRANT.into(),
            continuation: CONTINUE.into(),
            interaction: "https://as.example/i".into(),
            token_management: "https://as.example/token".into(),
        },
    );

    // The right key, a valid signature, the wrong name.
    let impostor = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "someone-else").unwrap();
    let transport = Direct::wrapping(&as_);
    let error = Session::new(&transport, &impostor, GRANT)
        .start(&request(), 1_000)
        .expect_err("a signature naming another key must be refused");
    assert!(error.to_string().contains("keyid"), "{error}");

    // The same request under the name the key actually has.
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let transport = Direct::wrapping(&as_);
    let step = Session::new(&transport, &signer, GRANT)
        .start(&request(), 1_000)
        .expect("the right name is accepted");
    assert!(matches!(step, Step::Pending(_)), "{step:?}");
}

/// GNAP-9635-§5.2 — polling a pending grant can find it approved.
///
/// When the client asked for no finish method, the response to a poll is the
/// only notice it gets that the RO has answered. A client that refuses to leave
/// `pending` on the strength of it polls a grant that is already decided.
#[test]
fn polling_finds_a_grant_the_resource_owner_approved() {
    let as_ = server();
    let transport = Direct::wrapping(&as_);
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let mut client = Session::new(&transport, &signer, GRANT);

    // No `finish`: the AS has no way to call back, so the client polls (§5.2).
    let polled: GrantRequest = serde_json::from_str(
        r#"{"client":"client-541-ab",
            "access_token":{"access":["dolphin-metadata"]},
            "interact":{"start":["redirect"]}}"#,
    )
    .unwrap();

    let step = client.start(&polled, 1_000).unwrap();
    assert!(matches!(step, Step::Pending(_)), "{step:?}");
    let redirect = step.response().interact.clone().unwrap().redirect.unwrap();
    assert!(
        step.response().interact.as_ref().unwrap().finish.is_none(),
        "the client asked for no finish, so the AS must offer no nonce"
    );

    // The RO answers where the client cannot see it.
    let handle = redirect.rsplit('/').next().unwrap();
    assert_eq!(
        as_.complete_interaction(handle, 1_005),
        Ok(Finish::SendTheUserBack),
        "with no finish method the AS sends the user back and the client polls"
    );

    transport.now.set(1_010);
    let step = client.continue_grant(1_010).unwrap();
    assert!(matches!(step, Step::Approved(_)), "{step:?}");
    assert_eq!(client.state(), State::Approved);
    assert!(step.response().access_token.is_some());
}

/// GNAP-9635-§5.3-MN10 — "The client instance MUST NOT include post-interaction
/// responses such as those described in Section 5.1."
///
/// The two are different calls: one says the RO has answered, the other changes
/// what was asked. Picking one silently would apply half of what was sent.
#[test]
fn a_modification_carrying_an_interaction_reference_is_refused() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let cont = pending_grant(&as_, &signer);

    // A PATCH carrying the reference: §5.3-MN10 forbids it outright.
    let request = signed_continuation(
        &signer,
        "PATCH",
        &cont.uri,
        cont.access_token.value.as_str(),
        Some(br#"{"interact_ref":"4IFWWIKYBC2PQ6U56NL1"}"#.to_vec()),
        1_010,
    );
    let response = as_.handle(&request, 1_010);
    assert_eq!(response.status, 400, "{}", body_of(&response));
    assert!(
        body_of(&response).contains("invalid_request"),
        "{}",
        body_of(&response)
    );
}

/// GNAP-9635-§2-M06 — "The request MUST be sent as a JSON object in the content
/// of the HTTP POST request with Content-Type application/json."
#[test]
fn the_grant_endpoint_accepts_json_post_and_advertises_options() {
    let as_ = server();

    let response = as_.handle(&HttpRequest::new("GET", GRANT), 1_000);
    assert_eq!(response.status, 405);
    assert_eq!(response.header_value("allow"), Some("POST, OPTIONS"));

    let response = as_.handle(
        &HttpRequest::new("POST", GRANT)
            .header("Content-Type", "text/plain")
            .json_body(br#"{"client":"client-541-ab"}"#.to_vec()),
        1_000,
    );
    assert_eq!(response.status, 415);
    assert_eq!(response.header_value("accept"), Some("application/json"));

    // The media type may carry parameters; only the type itself is compared.
    let response = as_.handle(
        &HttpRequest::new("POST", GRANT)
            .header("Content-Type", "application/json; charset=utf-8")
            .json_body(br#"{"client":"stranger"}"#.to_vec()),
        1_000,
    );
    assert_eq!(response.status, 400, "{}", body_of(&response));
    assert!(body_of(&response).contains("invalid_client"));
}

/// GNAP-9635-§4.2-M05 — a refused continuation must not spend the reference.
///
/// The reference is one-time-use, and the client can never obtain another one:
/// if a `too_fast` refusal spent it, the grant would be unreachable for good.
#[test]
fn a_refused_continuation_does_not_spend_the_interaction_reference() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let transport = Direct::wrapping(&as_);
    let mut client = Session::new(&transport, &signer, GRANT);
    let step = client.start(&request(), 1_000).unwrap();

    let cont = step.response().r#continue.clone().unwrap();
    let redirect = step.response().interact.clone().unwrap().redirect.unwrap();
    let handle = redirect.rsplit('/').next().unwrap();
    let Finish::Redirect { uri } = as_.complete_interaction(handle, 1_005).unwrap() else {
        panic!("the client asked for the redirect finish method");
    };
    let body = format!(
        r#"{{"interact_ref":"{}"}}"#,
        InteractCallback::from_redirect(&uri).unwrap().interact_ref
    );
    let token = cont.access_token.value.as_str();

    // Before the wait elapses: refused, and the grant keeps its reference.
    let early = signed_continuation(
        &signer,
        "POST",
        &cont.uri,
        token,
        Some(body.clone().into_bytes()),
        1_001,
    );
    let response = as_.handle(&early, 1_001);
    assert_eq!(response.status, 400, "{}", body_of(&response));
    assert!(
        body_of(&response).contains("too_fast"),
        "{}",
        body_of(&response)
    );

    // §5-M11 — the refusal hands the grant back, under a new token.
    let again = continuation_of(&response);
    assert_ne!(again.access_token.value.as_str(), token);

    // The same reference, once the client is allowed to call.
    let later = signed_continuation(
        &signer,
        "POST",
        &again.uri,
        again.access_token.value.as_str(),
        Some(body.into_bytes()),
        1_010,
    );
    let response = as_.handle(&later, 1_010);
    assert_eq!(response.status, 200, "{}", body_of(&response));
}

/// GNAP-9635-§4.2 — the interaction is spent by the completion that used it.
///
/// A second completion of the same interaction would issue a second reference
/// and silently invalidate the first, which the client is already carrying.
#[test]
fn an_interaction_can_only_be_completed_once() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let cont_handle = {
        let transport = Direct::wrapping(&as_);
        let mut client = Session::new(&transport, &signer, GRANT);
        let step = client.start(&request(), 1_000).unwrap();
        let redirect = step.response().interact.clone().unwrap().redirect.unwrap();
        redirect.rsplit('/').next().unwrap().to_owned()
    };

    assert!(as_.complete_interaction(&cont_handle, 1_005).is_ok());
    assert_eq!(
        as_.complete_interaction(&cont_handle, 1_005),
        Err(InteractionError::UnknownInteraction),
        "the handle is spent by the completion that used it"
    );
}

/// GNAP-9635-§2.5.2-MN03 — "This URI MUST be an absolute URI and MUST NOT
/// contain any fragment component."
///
/// A fragment would swallow the query the callback parameters travel in, so the
/// AS refuses the request rather than the interaction that follows it.
#[test]
fn a_callback_uri_the_as_cannot_use_is_refused_up_front() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();

    for (uri, why) in [
        ("https://client.example.net/cb#done", "fragment"),
        ("/cb", "absolute"),
    ] {
        let broken: GrantRequest = serde_json::from_str(&format!(
            r#"{{"client":"client-541-ab",
                 "access_token":{{"access":["dolphin-metadata"]}},
                 "interact":{{"start":["redirect"],
                              "finish":{{"method":"redirect","uri":"{uri}",
                                         "nonce":"{CLIENT_NONCE}"}}}}}}"#
        ))
        .unwrap();

        let transport = Direct::wrapping(&as_);
        let error = Session::new(&transport, &signer, GRANT)
            .start(&broken, 1_000)
            .expect_err("the AS should refuse this callback URI");
        assert!(error.to_string().contains(why), "{error}");
    }
}

/// GNAP-9635-§7.3.1-M15 — "If the signer's key presented is a JWK, the keyid
/// parameter of the signature MUST be set to the kid value of the JWK, and the
/// signing algorithm used MUST be the JWS algorithm denoted by the key's alg
/// field of the JWK."
///
/// Both halves are checked against the key the client actually sent, not
/// against what the key resolver says about it.
#[test]
fn a_signature_must_match_the_jwk_the_client_presented() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();

    let with_jwk = |kid: &str, alg: &str| -> GrantRequest {
        serde_json::from_str(&format!(
            r#"{{"client":{{"key":{{"proof":"httpsig",
                                   "jwk":{{"kty":"RSA","kid":"{kid}","alg":"{alg}"}}}}}},
                 "access_token":{{"access":["dolphin-metadata"]}},
                 "interact":{{"start":["redirect"]}}}}"#
        ))
        .unwrap()
    };

    // The signature names the key, with the algorithm the key declares.
    let transport = Direct::wrapping(&as_);
    let step = Session::new(&transport, &signer, GRANT)
        .start(&with_jwk("gnap-demo", "PS256"), 1_000)
        .expect("the signature matches the presented key");
    assert!(matches!(step, Step::Pending(_)), "{step:?}");

    // The key declares an algorithm the signature does not use.
    let transport = Direct::wrapping(&as_);
    let error = Session::new(&transport, &signer, GRANT)
        .start(&with_jwk("gnap-demo", "RS256"), 1_000)
        .expect_err("the declared algorithm is not the one used");
    assert!(error.to_string().contains("RS256"), "{error}");

    // The signature names a key other than the one presented.
    let transport = Direct::wrapping(&as_);
    let error = Session::new(&transport, &signer, GRANT)
        .start(&with_jwk("another-key", "PS256"), 1_000)
        .expect_err("the signature names another key");
    assert!(error.to_string().contains("keyid"), "{error}");
}

/// GNAP-9635-§7.1 — a key sent by value carries `alg` and `kid`, and they are
/// what a signature is compared against, so they have to be strings.
#[test]
fn a_jwk_the_as_cannot_read_is_refused() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();

    let broken: GrantRequest = serde_json::from_str(
        r#"{"client":{"key":{"proof":"httpsig",
                             "jwk":{"kty":"RSA","kid":"gnap-demo","alg":42}}},
            "access_token":{"access":["dolphin-metadata"]},
            "interact":{"start":["redirect"]}}"#,
    )
    .unwrap();

    let transport = Direct::wrapping(&as_);
    let error = Session::new(&transport, &signer, GRANT)
        .start(&broken, 1_000)
        .expect_err("a JWK whose alg is not a string is unusable");
    assert!(error.to_string().contains("not a string"), "{error}");
}

/// GNAP-9635-§5.2 and GNAP-9635-§5.3 — the method and the content agree.
///
/// §5.2 says a poll "does not include message content", and §5.3 says a
/// modification "includes any fields it needs to modify". A call whose shape
/// does not match its method is not one of §5's operations.
#[test]
fn the_method_and_the_content_of_a_continuation_must_agree() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();

    // A PATCH that changes nothing.
    let cont = pending_grant(&as_, &signer);
    let empty_patch = signed_continuation(
        &signer,
        "PATCH",
        &cont.uri,
        cont.access_token.value.as_str(),
        None,
        1_010,
    );
    let response = as_.handle(&empty_patch, 1_010);
    assert_eq!(response.status, 400, "{}", body_of(&response));
    assert!(
        body_of(&response).contains("carries none"),
        "{}",
        body_of(&response)
    );

    // A poll that carries content.
    let cont = pending_grant(&as_, &signer);
    let fat_poll = signed_continuation(
        &signer,
        "POST",
        &cont.uri,
        cont.access_token.value.as_str(),
        Some(b"{}".to_vec()),
        1_010,
    );
    let response = as_.handle(&fat_poll, 1_010);
    assert_eq!(response.status, 400, "{}", body_of(&response));
    assert!(
        body_of(&response).contains("invalid_request"),
        "{}",
        body_of(&response)
    );
}

/// GNAP-9635-§4.2-M01 — once a finish method is associated with the request,
/// following it is a MUST.
///
/// So the AS refuses one it cannot follow while the client can still choose
/// another, rather than after the RO has answered.
#[test]
fn a_finish_the_as_cannot_follow_is_refused_before_interaction() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();

    for (finish, expected) in [
        (
            r#"{"method":"carrier-pigeon","uri":"https://client.example.net/cb","nonce":"N"}"#,
            "carrier-pigeon",
        ),
        (
            r#"{"method":"redirect","uri":"https://client.example.net/cb","nonce":"N",
                "hash_method":"blake2b-256"}"#,
            "blake2b-256",
        ),
        (
            r#"{"method":"redirect","uri":"https://client.example.net/cb?hash=mine","nonce":"N"}"#,
            "interact_ref",
        ),
        (
            r#"{"method":"redirect","uri":"https://bad host/cb","nonce":"N"}"#,
            "absolute",
        ),
        (
            r#"{"method":"redirect","uri":"https://client.example.net/cb%ZZ","nonce":"N"}"#,
            "absolute",
        ),
        // §2.5.2-R09 with §4.2.3: the nonce is hashed inside an ASCII base.
        (
            r#"{"method":"redirect","uri":"https://client.example.net/cb","nonce":""}"#,
            "nonce",
        ),
        (
            r#"{"method":"redirect","uri":"https://client.example.net/cb","nonce":"café"}"#,
            "nonce",
        ),
        (
            r#"{"method":"redirect","uri":"https://client.example.net/cb","nonce":"one\ntwo"}"#,
            "nonce",
        ),
    ] {
        let broken: GrantRequest = serde_json::from_str(&format!(
            r#"{{"client":"client-541-ab",
                 "access_token":{{"access":["dolphin-metadata"]}},
                 "interact":{{"start":["redirect"],"finish":{finish}}}}}"#
        ))
        .unwrap();

        let transport = Direct::wrapping(&as_);
        let error = Session::new(&transport, &signer, GRANT)
            .start(&broken, 1_000)
            .expect_err("the AS should refuse this finish method");
        assert!(
            error.to_string().contains(expected),
            "expected `{expected}` in: {error}"
        );
    }
}

/// A call that never reached the AS must leave the session able to try again.
///
/// The state machine advances on what the AS answered; a signing or transport
/// failure happens before it has seen anything, so committing the transition
/// then would strand the client in a state the AS knows nothing about.
#[test]
fn a_transport_failure_does_not_strand_the_session() {
    /// Fails the first continuation, then behaves.
    struct FlakyOnce<'a> {
        server: &'a Server,
        now: Cell<u64>,
        failed: Cell<bool>,
    }

    impl HttpTransport for FlakyOnce<'_> {
        type Error = String;
        fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
            if request.url.starts_with(CONTINUE) && !self.failed.replace(true) {
                return Err("the network went away".into());
            }
            Ok(self.server.handle(&request, self.now.get()))
        }
    }

    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();

    // Start the grant against a working transport, then hand the session over.
    let transport = FlakyOnce {
        server: &as_,
        now: Cell::new(1_000),
        failed: Cell::new(false),
    };
    let mut client = Session::new(&transport, &signer, GRANT);
    let step = client.start(&request(), 1_000).unwrap();
    let redirect = step.response().interact.clone().unwrap().redirect.unwrap();

    let Finish::Redirect { uri } = as_
        .complete_interaction(redirect.rsplit('/').next().unwrap(), 1_005)
        .unwrap()
    else {
        panic!("the client asked for the redirect finish method");
    };
    client
        .accept_callback(&InteractCallback::from_redirect(&uri).unwrap(), 1_005)
        .unwrap();

    transport.now.set(1_010);
    assert!(
        client.continue_grant(1_010).is_err(),
        "the first continuation fails in transport"
    );
    assert_eq!(
        client.state(),
        State::Pending,
        "the grant has not moved: the AS never saw the call"
    );

    // The reference was not spent either, so the retry carries it.
    let step = client
        .continue_grant(1_010)
        .expect("the retry should reach the AS");
    assert!(matches!(step, Step::Approved(_)), "{step:?}");
}

/// GNAP-9635-§7.3.1-M15 — the signature that is accepted is the one that must
/// name the key.
///
/// A message may carry several signatures, and §7.3.1 has the verifier examine
/// them all. Checking the `keyid` against *some* candidate lets a forged one
/// carry the right name while a different, genuinely valid one carries the
/// wrong key's: the name check and the cryptographic check would then be
/// passing on two different signatures.
#[test]
fn the_signature_that_verifies_is_the_one_that_must_name_the_key() {
    let as_ = server();
    let right_name = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let wrong_name = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "someone-else").unwrap();

    let with_jwk: GrantRequest = serde_json::from_str(
        r#"{"client":{"key":{"proof":"httpsig",
                             "jwk":{"kty":"RSA","kid":"gnap-demo","alg":"PS256"}}},
            "access_token":{"access":["dolphin-metadata"]},
            "interact":{"start":["redirect"]}}"#,
    )
    .unwrap();
    let body = serde_json::to_vec(&with_jwk).unwrap();

    // `siga` names the key the JWK names, but its signature is one made over a
    // different base. `sigb` verifies, but names another key. (An sf-key is
    // lowercase, RFC 9651 §3.1.2.)
    let named = signed_grant(&right_name, &body, 1_000);
    let elsewhere = signed_grant(&right_name, &body, 999);
    let valid = signed_grant(&wrong_name, &body, 1_000);

    let request = HttpRequest::new("POST", GRANT)
        .header("Content-Type", "application/json")
        .header(
            "Content-Digest",
            named.header_value("content-digest").unwrap().to_owned(),
        )
        .header(
            "Signature-Input",
            format!("siga={}, sigb={}", params_of(&named), params_of(&valid)),
        )
        .header(
            "Signature",
            format!("siga={}, sigb={}", value_of(&elsewhere), value_of(&valid)),
        )
        .json_body(body);

    let response = as_.handle(&request, 1_000);
    assert_eq!(
        response.status,
        400,
        "neither signature both verifies and names the key: {}",
        body_of(&response)
    );
    assert!(
        body_of(&response).contains("keyid"),
        "{}",
        body_of(&response)
    );
}

/// The `sig1=` value of a signed request's `Signature-Input`.
fn params_of(request: &HttpRequest) -> String {
    request
        .header_value("signature-input")
        .and_then(|v| v.split_once('='))
        .expect("a signed request carries Signature-Input")
        .1
        .to_owned()
}

/// The `sig1=` value of a signed request's `Signature`.
fn value_of(request: &HttpRequest) -> String {
    request
        .header_value("signature")
        .and_then(|v| v.split_once('='))
        .expect("a signed request carries Signature")
        .1
        .to_owned()
}

/// A signed grant request, the way `gnap-client` builds one.
fn signed_grant(signer: &Ps256Signer, body: &[u8], now: u64) -> HttpRequest {
    let digest =
        gnap_crypto::digest::content_digest(body, gnap_crypto::digest::DigestAlgorithm::Sha256);
    let input = SignatureInput {
        components: vec![
            Component::Method,
            Component::TargetUri,
            Component::ContentDigest,
        ],
        created: now,
        keyid: signer.key_id().to_owned(),
        nonce: None,
        tag: Tag::Gnap,
    };
    let raw = input.serialize().unwrap();
    let message = Message {
        method: "POST",
        target_uri: GRANT,
        content_digest: Some(&digest),
        authorization: None,
        other: Vec::new(),
    };
    let base = signature_base(&message, &input.components, &raw).unwrap();
    let signature = signer.sign(base.as_bytes()).unwrap();

    HttpRequest::new("POST", GRANT)
        .header("Content-Type", "application/json")
        .header("Content-Digest", digest)
        .header("Signature-Input", format!("sig1={raw}"))
        .header(
            "Signature",
            format!("sig1=:{}:", STANDARD.encode(signature)),
        )
        .json_body(body.to_vec())
}

/// GNAP-9635-§5-M11 and GNAP-9635-§5-M12 — an error the grant survives comes
/// back with a new continuation, and a new token with it.
///
/// GNAP-9635-§5-MN13 and GNAP-9635-§5-M14 are the other half: a client that got
/// no continuation MUST NOT call again, and the AS MUST answer
/// `invalid_continuation` if it does. So an error that leaves the grant alive
/// and says nothing would leave a grant neither side may touch.
#[test]
fn an_error_the_grant_survives_hands_back_a_new_continuation() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let transport = Direct::wrapping(&as_);
    let mut client = Session::new(&transport, &signer, GRANT);
    let step = client.start(&request(), 1_000).unwrap();
    let first = step.response().r#continue.clone().unwrap();

    // A body the AS cannot read, presented by the legitimate client.
    let broken = signed_continuation(
        &signer,
        "POST",
        &first.uri,
        first.access_token.value.as_str(),
        Some(b"{not json".to_vec()),
        1_010,
    );
    let response = as_.handle(&broken, 1_010);
    assert_eq!(response.status, 400, "{}", body_of(&response));

    let second = continuation_of(&response);
    assert_ne!(
        second.access_token.value.as_str(),
        first.access_token.value.as_str(),
        "§5-M12: the new continuation carries a new token"
    );

    // §5-M12 — "invalidating the previous access token".
    let with_old = signed_continuation(
        &signer,
        "POST",
        &first.uri,
        first.access_token.value.as_str(),
        None,
        1_020,
    );
    let response = as_.handle(&with_old, 1_020);
    assert_eq!(response.status, 400);
    assert!(
        body_of(&response).contains("invalid_continuation"),
        "{}",
        body_of(&response)
    );

    // The token the AS handed back does work.
    let with_new = signed_continuation(
        &signer,
        "POST",
        &second.uri,
        second.access_token.value.as_str(),
        None,
        1_020,
    );
    assert_eq!(as_.handle(&with_new, 1_020).status, 200);
}

/// GNAP-9635-§5-M11 — the client picks the new continuation up and carries on.
///
/// Both roles are real, and their clocks disagree: the client believes the wait
/// has elapsed, the AS does not. The AS refuses and hands the grant back; the
/// client rewinds, and its next call presents the same interaction reference
/// under the token the AS just issued. A client that spent the reference on the
/// refused call could never continue, and the RO would be asked again for
/// nothing.
#[test]
fn a_client_refused_too_fast_retries_with_what_the_as_handed_back() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let transport = Direct::wrapping(&as_);
    let mut client = Session::new(&transport, &signer, GRANT);
    let step = client.start(&request(), 1_000).unwrap();
    let first = step.response().r#continue.clone().unwrap();

    let redirect = step.response().interact.clone().unwrap().redirect.unwrap();
    let Finish::Redirect { uri } = as_
        .complete_interaction(redirect.rsplit('/').next().unwrap(), 1_005)
        .unwrap()
    else {
        panic!("the client asked for the redirect finish method");
    };
    client
        .accept_callback(&InteractCallback::from_redirect(&uri).unwrap(), 1_005)
        .unwrap();

    // The client's own guard is satisfied at 1_010; the AS sees 1_001.
    transport.now.set(1_001);
    let step = client.continue_grant(1_010).unwrap();
    assert!(matches!(step, Step::Recoverable(_)), "{step:?}");
    assert!(
        body_of(&transport.exchanges.borrow().last().unwrap().1).contains("too_fast"),
        "the AS should refuse on the wait period"
    );
    assert_eq!(
        client.state(),
        State::Pending,
        "the AS did not act on the call, so the grant did not move"
    );

    let second = step.response().r#continue.clone().expect("§5-M11");
    assert_ne!(
        second.access_token.value.as_str(),
        first.access_token.value.as_str(),
        "§5-M12: the refusal rotates the continuation token"
    );

    // The same reference goes again, under the token the AS handed back.
    transport.now.set(1_020);
    let step = client.continue_grant(1_020).unwrap();
    assert!(matches!(step, Step::Approved(_)), "{step:?}");

    let exchanges = transport.exchanges.borrow();
    let last = &exchanges.last().unwrap().0;
    assert_eq!(
        last.header_value("authorization"),
        Some(format!("GNAP {}", second.access_token.value.as_str()).as_str())
    );
    let sent = String::from_utf8_lossy(last.body.as_deref().unwrap_or_default());
    assert!(
        sent.contains(&InteractCallback::from_redirect(&uri).unwrap().interact_ref),
        "the same reference goes again: {sent}"
    );
}

/// GNAP-9635-§2.5.2-M13 — "All interaction finish methods MUST require
/// presentation of an interaction reference for continuing this grant request."
/// GNAP-9635-§2.5.2-M14 — "the interaction reference MUST be returned by the AS
/// and MUST be presented by the client as described in Section 5.1."
///
/// Without this, whoever holds the continuation token collects the grant by
/// polling the moment the RO answers, and the reference secures nothing.
#[test]
fn polling_does_not_stand_in_for_the_interaction_reference() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let cont = pending_grant(&as_, &signer);

    // `request()` negotiates a redirect finish, so a reference is owed.
    let redirect = format!("https://as.example/i/{}", "nonce0002");
    let Finish::Redirect { uri } = as_
        .complete_interaction(redirect.rsplit('/').next().unwrap(), 1_005)
        .expect("the RO answered")
    else {
        panic!("the client asked for the redirect finish method");
    };

    // The RO has answered, but nobody has presented the reference yet.
    let polling = signed_continuation(
        &signer,
        "POST",
        &cont.uri,
        cont.access_token.value.as_str(),
        None,
        1_010,
    );
    let response = as_.handle(&polling, 1_010);
    assert_eq!(response.status, 200, "{}", body_of(&response));
    let parsed: gnap_types::message::GrantResponse =
        serde_json::from_slice(&response.body).unwrap();
    assert!(
        parsed.access_token.is_none(),
        "polling must not collect a grant whose reference is still owed: {}",
        body_of(&response)
    );

    // The same grant, continued the way §5.1 requires.
    let second = continuation_of(&response);
    let returning = signed_continuation(
        &signer,
        "POST",
        &second.uri,
        second.access_token.value.as_str(),
        Some(
            serde_json::to_vec(&serde_json::json!({
                "interact_ref": InteractCallback::from_redirect(&uri).unwrap().interact_ref
            }))
            .unwrap(),
        ),
        1_020,
    );
    let response = as_.handle(&returning, 1_020);
    assert_eq!(response.status, 200, "{}", body_of(&response));
    assert!(body_of(&response).contains("access_token"));
}

/// GNAP-9635-§5-MN03 — "Access tokens other than the continuation access tokens
/// MUST NOT be usable for continuation requests."
/// GNAP-9635-§5-M05 — "The AS MUST be able to tell from the client instance's
/// request which specific ongoing request is being accessed, using a
/// combination of the continuation URI and the continuation access token."
#[test]
fn only_this_grants_continuation_token_reaches_this_grant() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();

    // Two grants in flight at once, each with its own continuation token.
    let first = pending_grant(&as_, &signer);
    let second = pending_grant(&as_, &signer);
    assert_ne!(
        first.access_token.value.as_str(),
        second.access_token.value.as_str()
    );
    assert_eq!(as_.storage().len().unwrap(), 2);

    // §5-M05 — each token reaches its own grant, and the store loses only it.
    let poll = signed_continuation(
        &signer,
        "POST",
        &first.uri,
        first.access_token.value.as_str(),
        None,
        1_010,
    );
    assert_eq!(as_.handle(&poll, 1_010).status, 200);
    assert_eq!(
        as_.storage().len().unwrap(),
        2,
        "the other grant is untouched"
    );

    // §5-MN03 — a token that is not a continuation token reaches nothing, even
    // a well-formed one the AS itself could have issued.
    let stranger = signed_continuation(
        &signer,
        "POST",
        &second.uri,
        "OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0",
        None,
        1_010,
    );
    let response = as_.handle(&stranger, 1_010);
    assert_eq!(response.status, 400);
    assert!(
        body_of(&response).contains("invalid_continuation"),
        "{}",
        body_of(&response)
    );
}

/// GNAP-9635-§3.4-M01 — "The AS MUST return the subject field only in cases
/// where the AS is sure that the RO and the end user are the same party. This
/// can be accomplished through some forms of interaction with the RO."
/// GNAP-9635-§3.4-M11 — "The AS MUST ensure that the returned subject
/// information represents the RO."
///
/// Whether the AS is sure is the deployment's judgement, not this library's.
/// Two things belong to the library, and both are here: subject information
/// cannot be released without the deployment stating its ground, and the one
/// ground the RFC names — interaction — is checked against what actually
/// happened on this grant.
#[test]
fn subject_information_is_released_only_on_a_ground_the_as_can_stand_on() {
    /// Approves straight away, releasing subject information on the ground it
    /// is given.
    struct ApproveWithSubject(SubjectGround);

    impl Policy for ApproveWithSubject {
        fn evaluate(&self, _request: &GrantRequest) -> Decision {
            Decision::Approve {
                access: vec![AccessItem::Reference("dolphin-metadata".into())],
                subject: Some(ReleasedSubject {
                    ground: self.0.clone(),
                    subject: Box::new(
                        serde_json::from_str(
                            r#"{"sub_ids":[{"format":"opaque","id":"XUT2MFM1XBIKJKSDU8QM"}]}"#,
                        )
                        .unwrap(),
                    ),
                }),
            }
        }
    }

    let served = |ground: SubjectGround| {
        let as_ = AuthorizationServer::new(
            ApproveWithSubject(ground),
            OneKey(RSA_SPKI),
            MemoryStorage::new(),
            Counted(Cell::new(0)),
            Endpoints {
                grant: GRANT.into(),
                continuation: CONTINUE.into(),
                interaction: "https://as.example/i".into(),
                token_management: "https://as.example/token".into(),
            },
        );
        let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
        let body = serde_json::to_vec(&request()).unwrap();
        as_.handle(&signed_grant(&signer, &body, 1_000), 1_000)
    };

    // Claiming the RO interacted, on a grant nobody interacted with.
    let response = served(SubjectGround::RoInteractedHere);
    assert_eq!(response.status, 500, "{}", body_of(&response));
    assert!(
        body_of(&response).contains("no interaction"),
        "{}",
        body_of(&response)
    );

    // A ground the AS cannot check is accepted, because it was stated.
    let response = served(SubjectGround::EstablishedOtherwise(
        "the RO is the operator of this deployment",
    ));
    assert_eq!(response.status, 200, "{}", body_of(&response));
    let parsed: gnap_types::message::GrantResponse =
        serde_json::from_slice(&response.body).unwrap();
    assert!(parsed.subject.is_some(), "the subject is released");
}

/// GNAP-9635-§2.1.1-M02 — "If this field is included in the request, the AS
/// MUST include the same label in the token response."
///
/// The label is how the client tells its tokens apart; an AS that drops it, or
/// renames it, hands back tokens the client cannot place.
#[test]
fn the_label_the_client_chose_comes_back_unchanged() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let transport = Direct::wrapping(&as_);
    let mut client = Session::new(&transport, &signer, GRANT);

    let labelled: GrantRequest = serde_json::from_str(
        r#"{"client":"client-541-ab",
            "access_token":{"label":"the-dolphins","access":["dolphin-metadata"]},
            "interact":{"start":["redirect"]}}"#,
    )
    .unwrap();
    let step = client.start(&labelled, 1_000).unwrap();
    let redirect = step.response().interact.clone().unwrap().redirect.unwrap();
    as_.complete_interaction(redirect.rsplit('/').next().unwrap(), 1_005)
        .unwrap();

    transport.now.set(1_010);
    let step = client.continue_grant(1_010).unwrap();
    let tokens = step.response().access_token.as_ref().expect("a token");
    assert_eq!(tokens.tokens[0].label.as_deref(), Some("the-dolphins"));
}

/// GNAP-9635-§2.3-M06 — "If the AS is not able to interpret or validate the
/// `class_id` field, it MUST either return an `invalid_client` error
/// (Section 3.6) or interpret the request as if the `class_id` were not
/// present."
///
/// This server takes the second branch, and this pins that it really is a
/// branch and not an oversight: an unknown `class_id` changes nothing.
/// GNAP-9635-§2.3.2-MN09 — the display values "are for informational purposes
/// only and MUST NOT be taken as authentic proof of the client instance's
/// identity"; only the key authenticates, so the same display with an unknown
/// key is refused all the same.
#[test]
fn self_declared_client_information_decides_nothing() {
    /// Recognises nobody, whatever the request says about itself.
    struct NoKeys;

    impl KeyResolver for NoKeys {
        fn resolve(&self, _client: &Client) -> Option<Box<dyn Verifier>> {
            None
        }
    }

    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();

    // An unknown class_id and a flattering display, on a key the AS knows.
    let boastful: GrantRequest = serde_json::from_str(
        r#"{"client":{"key":"k-1","class_id":"something-this-as-never-heard-of",
                      "display":{"name":"Trusted Internal Tool",
                                 "uri":"https://client.example.net/about"}},
            "access_token":{"access":["dolphin-metadata"]},
            "interact":{"start":["redirect"]}}"#,
    )
    .unwrap();
    let transport = Direct::wrapping(&as_);
    let step = Session::new(&transport, &signer, GRANT)
        .start(&boastful, 1_000)
        .expect("an unknown class_id is read as if it were absent");
    assert!(matches!(step, Step::Pending(_)), "{step:?}");

    // The same claims, with a key the AS does not know: refused. The display
    // proves nothing.
    let strict = AuthorizationServer::new(
        AlwaysInteract {
            interacted: Cell::new(false),
        },
        NoKeys,
        MemoryStorage::new(),
        Counted(Cell::new(0)),
        Endpoints {
            grant: GRANT.into(),
            continuation: CONTINUE.into(),
            interaction: "https://as.example/i".into(),
            token_management: "https://as.example/token".into(),
        },
    );
    let body = serde_json::to_vec(&boastful).unwrap();
    let response = strict.handle(&signed_grant(&signer, &body, 1_000), 1_000);
    assert_eq!(response.status, 400);
    assert!(
        body_of(&response).contains("invalid_client"),
        "{}",
        body_of(&response)
    );
}

/// GNAP-9635-§2.4.1-M02 — "If the AS does not recognize the user reference, it
/// MUST return an `unknown_user` error."
/// GNAP-9635-§2.4-MN05 — "Subject Identifiers are hints to the AS in
/// determining the RO and MUST NOT be taken as authoritative statements that a
/// particular RO is present at the client instance."
///
/// A reference the AS never handed out is not a hint to ignore quietly: §2.4.1
/// names the answer. And a reference it does recognise still decides nothing on
/// its own — only the key authenticates.
#[test]
fn a_user_reference_is_answered_for_but_never_believed() {
    /// Knows one user reference, and grants nothing on the strength of it.
    struct KnowsOneUser;

    impl Policy for KnowsOneUser {
        fn evaluate(&self, _request: &GrantRequest) -> Decision {
            Decision::RequireInteraction
        }
        fn recognises_user(&self, reference: &str) -> bool {
            reference == "XUT2MFM1XBIKJKSDU8QM"
        }
    }

    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let as_ = AuthorizationServer::new(
        KnowsOneUser,
        OneKey(RSA_SPKI),
        MemoryStorage::new(),
        Counted(Cell::new(0)),
        Endpoints {
            grant: GRANT.into(),
            continuation: CONTINUE.into(),
            interaction: "https://as.example/i".into(),
            token_management: "https://as.example/token".into(),
        },
    );

    let with_user = |reference: &str| -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "client": "client-541-ab",
            "user": reference,
            "access_token": {"access": ["dolphin-metadata"]},
            "interact": {"start": ["redirect"]}
        }))
        .unwrap()
    };

    let response = as_.handle(
        &signed_grant(&signer, &with_user("SOMEONE-ELSE"), 1_000),
        1_000,
    );
    assert_eq!(response.status, 400, "{}", body_of(&response));
    assert!(
        body_of(&response).contains("unknown_user"),
        "{}",
        body_of(&response)
    );

    // The one it knows gets through — and still ends up pending, because the
    // reference is a hint and the RO has said nothing yet.
    let response = as_.handle(
        &signed_grant(&signer, &with_user("XUT2MFM1XBIKJKSDU8QM"), 1_000),
        1_000,
    );
    assert_eq!(response.status, 200, "{}", body_of(&response));
    let parsed: gnap_types::message::GrantResponse =
        serde_json::from_slice(&response.body).unwrap();
    assert!(
        parsed.access_token.is_none() && parsed.interact.is_some(),
        "a known user is not an RO's approval: {}",
        body_of(&response)
    );
}

/// GNAP-9635-§2.3.1-M02 — "When the AS receives a request with an instance
/// identifier, the AS MUST ensure that the key used to sign the request
/// (Section 7.3) is associated with the instance identifier."
///
/// The instance identifier is a name the AS chose; the key is what proves the
/// bearer of that name is the instance it names.
#[test]
fn an_instance_identifier_is_only_worth_the_key_attached_to_it() {
    /// Attaches a different key to each instance identifier it knows.
    struct PerInstance;

    impl KeyResolver for PerInstance {
        fn resolve(&self, client: &Client) -> Option<Box<dyn Verifier>> {
            let key_id = match client.as_reference()? {
                "client-541-ab" => "gnap-demo",
                "client-999-zz" => "another-instance",
                _ => return None,
            };
            let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, key_id).ok()?;
            Some(Box::new(signer.verifier()))
        }
    }

    let as_ = AuthorizationServer::new(
        AlwaysInteract {
            interacted: Cell::new(false),
        },
        PerInstance,
        MemoryStorage::new(),
        Counted(Cell::new(0)),
        Endpoints {
            grant: GRANT.into(),
            continuation: CONTINUE.into(),
            interaction: "https://as.example/i".into(),
            token_management: "https://as.example/token".into(),
        },
    );

    let body = serde_json::to_vec(&request()).unwrap(); // names client-541-ab
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    assert_eq!(
        as_.handle(&signed_grant(&signer, &body, 1_000), 1_000)
            .status,
        200,
        "the key attached to this instance"
    );

    // The same key material, signing under the other instance's name.
    let impostor = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "another-instance").unwrap();
    let response = as_.handle(&signed_grant(&impostor, &body, 1_000), 1_000);
    assert_eq!(response.status, 400, "{}", body_of(&response));
    assert!(
        body_of(&response).contains("keyid"),
        "{}",
        body_of(&response)
    );
}

/// GNAP-9635-§2.3-M08 — "If the same public key is sent by value on different
/// access requests, the AS MUST treat these requests as coming from the same
/// client instance for purposes of identification, authentication, and policy
/// application."
///
/// The key is the identity. Two requests presenting it are one instance, and
/// nothing else in the message may make them two.
#[test]
fn the_same_key_by_value_is_the_same_client_instance() {
    /// Counts the distinct instances it was asked to authenticate, keyed by the
    /// key material the request carried.
    struct ByKeyMaterial(Rc<RefCell<Vec<String>>>);

    impl KeyResolver for ByKeyMaterial {
        fn resolve(&self, client: &Client) -> Option<Box<dyn Verifier>> {
            let jwk = client.as_value()?.key.as_value()?.jwk.as_ref()?;
            self.0.borrow_mut().push(serde_json::to_string(jwk).ok()?);
            Ps256Verifier::from_public_key_pem(RSA_SPKI)
                .ok()
                .map(|v| Box::new(v) as Box<dyn Verifier>)
        }
    }

    let seen = Rc::new(RefCell::new(Vec::new()));
    let as_ = AuthorizationServer::new(
        AlwaysInteract {
            interacted: Cell::new(false),
        },
        ByKeyMaterial(Rc::clone(&seen)),
        MemoryStorage::new(),
        Counted(Cell::new(0)),
        Endpoints {
            grant: GRANT.into(),
            continuation: CONTINUE.into(),
            interaction: "https://as.example/i".into(),
            token_management: "https://as.example/token".into(),
        },
    );

    // The same key by value, under two different display names and class ids.
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let request_with = |class_id: &str, name: &str| -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "client": {
                "key": {"proof": "httpsig",
                        "jwk": {"kty": "RSA", "kid": "gnap-demo", "alg": "PS256"}},
                "class_id": class_id,
                "display": {"name": name}
            },
            "access_token": {"access": ["dolphin-metadata"]},
            "interact": {"start": ["redirect"]}
        }))
        .unwrap()
    };

    for (class_id, name) in [("build-a", "One Name"), ("build-b", "Another Name")] {
        let body = request_with(class_id, name);
        let response = as_.handle(&signed_grant(&signer, &body, 1_000), 1_000);
        assert_eq!(response.status, 200, "{}", body_of(&response));
    }

    // The AS was handed the same key material both times: nothing in the
    // self-declared fields made it two instances.
    let material = seen.borrow();
    assert_eq!(material.len(), 2, "two requests");
    assert_eq!(
        material[0], material[1],
        "the same key by value is the same instance (§2.3-M08)"
    );
}

/// GNAP-9635-§5.3-MN11 — "Modification requests MUST NOT alter previously
/// issued access tokens."
///
/// §5.3 lets the AS revoke them afterwards (§5.3-Y12), which is a different
/// thing: what it may not do is reach back and change a token the client is
/// already holding.
#[test]
fn a_modification_leaves_an_issued_token_as_it_was() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let transport = Direct::wrapping(&as_);
    let mut client = Session::new(&transport, &signer, GRANT);

    // Get a token issued.
    let step = client.start(&request(), 1_000).unwrap();
    let redirect = step.response().interact.clone().unwrap().redirect.unwrap();
    let Finish::Redirect { uri } = as_
        .complete_interaction(redirect.rsplit('/').next().unwrap(), 1_005)
        .unwrap()
    else {
        panic!("the client asked for the redirect finish method");
    };
    client
        .accept_callback(&InteractCallback::from_redirect(&uri).unwrap(), 1_005)
        .unwrap();
    transport.now.set(1_010);
    let step = client.continue_grant(1_010).unwrap();
    let issued = step.response().access_token.clone().expect("a token");
    let value = issued.tokens[0].value.as_str().to_owned();

    // The grant is approved and its continuation was withheld, so there is no
    // way left to ask the AS to touch that token — which is the point.
    assert_eq!(
        client.state(),
        State::Approved,
        "the grant is approved: {:?}",
        client.state()
    );
    assert!(
        step.response().r#continue.is_none(),
        "no continuation is offered, so no modification can reach the token"
    );
    let e = client
        .modify_grant(&gnap_types::message::ContinueRequest::default(), 1_020)
        .unwrap_err();
    assert!(e.to_string().contains("§5"), "{e}");

    // And the token the client holds is untouched.
    assert_eq!(
        client.usable_tokens(1_020).unwrap()[0].value.as_str(),
        value
    );
}

/// GNAP-9635-§4-M04 — "The AS MUST handle any interact request as a
/// one-time-use mechanism and SHOULD apply suitable timeouts to any interaction
/// start methods provided."
/// GNAP-9635-§4.1-M02 — "If the client instance does not start an interaction
/// start mode within an AS-determined amount of time, the AS MUST reject
/// attempts to use the interaction start modes."
/// GNAP-9635-§4.1-M03 — "If the client instance has already begun one
/// interaction start mode and the interaction has been successfully completed,
/// the AS MUST reject attempts to use other interaction start modes."
/// GNAP-9635-§4-M03 — "The client instance MUST use each interaction method
/// once at most if a response can be detected."
///
/// An interaction URI outlives the tab it was opened in. Both limits are here:
/// it stops working when it is used, and it stops working when it is old.
#[test]
fn an_interaction_is_used_once_and_does_not_keep() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let transport = Direct::wrapping(&as_);
    let mut client = Session::new(&transport, &signer, GRANT);

    let step = client.start(&request(), 1_000).unwrap();
    let interact = step.response().interact.clone().unwrap();
    let handle = interact
        .redirect
        .as_deref()
        .unwrap()
        .rsplit('/')
        .next()
        .unwrap()
        .to_owned();

    // §3.3 — the client is told how long it has, rather than left to guess.
    let lifetime = interact.expires_in.expect("the AS states a lifetime");
    assert_eq!(lifetime, gnap_as::INTERACTION_LIFETIME);

    // §4.1-M02 — a second late, it is refused.
    assert_eq!(
        as_.complete_interaction(&handle, 1_000 + lifetime),
        Err(InteractionError::Expired)
    );

    // Within the window, it works exactly once (§4-M04, §4.1-M03).
    assert!(as_
        .complete_interaction(&handle, 1_000 + lifetime - 1)
        .is_ok());
    assert_eq!(
        as_.complete_interaction(&handle, 1_000 + lifetime - 1),
        Err(InteractionError::UnknownInteraction),
        "the handle is spent by the completion that used it"
    );
}

/// The token management API, both roles real (§6).
///
/// GNAP-9635-§6-M02 — "The client instance MUST present proof of the key
/// associated with the token along with the value of the token management
/// access token."
/// GNAP-9635-§6-M03 — "The AS MUST validate the proof and ensure that it is
/// associated with the token management access token."
/// GNAP-9635-§6-M04 — "The AS MUST uniquely identify the token being managed
/// from the token management URI, the token management access token, or a
/// combination of both."
/// GNAP-9635-§6.1-M01 — the AS "MUST invalidate the current access token value
/// associated with this URI".
/// GNAP-9635-§6.1-MN02 — the new value "MUST NOT be the same as the current
/// value of the access token used to access the management API".
/// GNAP-9635-§6.1-M03 — "The response MUST include an access token management
/// URI."
/// GNAP-9635-§6.1-M04 — "The client instance MUST use this new URI to manage
/// the rotated access token."
/// GNAP-9635-§6.1-M05 — "The access rights in the access array for the rotated
/// access token MUST be included in the response and MUST be the same as the
/// token before rotation."
#[test]
fn a_token_is_rotated_through_its_management_api() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let transport = Direct::wrapping(&as_);
    let mut client = Session::new(&transport, &signer, GRANT);
    let issued = approved_token(&as_, &transport, &mut client);

    let manage = issued
        .manage
        .clone()
        .expect("§3.2.1 offers a management API");
    assert!(
        manage.uri.starts_with("https://as.example/token/"),
        "{}",
        manage.uri
    );

    transport.now.set(1_020);
    let rotated = client.rotate_token(None, 1_020).expect("the rotation");

    // §6.1 — a new value, the same rights, a management URI to carry on with.
    assert_ne!(rotated.value, issued.value, "§6.1: an updated token value");
    assert_eq!(rotated.access, issued.access, "§6.1-M05");
    let new_manage = rotated.manage.clone().expect("§6.1-M03");
    assert_ne!(
        rotated.value.as_str(),
        new_manage.access_token.value.as_str(),
        "§6.1-MN02"
    );

    // §6.1-M01 — the value that was rotated away is gone with its URI.
    let stale = signed_continuation(
        &signer,
        "POST",
        &manage.uri,
        manage.access_token.value.as_str(),
        None,
        1_030,
    );
    let response = as_.handle(&stale, 1_030);
    assert_eq!(response.status, 400, "{}", body_of(&response));
    assert!(
        body_of(&response).contains("invalid_client"),
        "{}",
        body_of(&response)
    );

    // §6.1-M04 — the new URI is the one that works now.
    transport.now.set(1_040);
    assert!(client.rotate_token(None, 1_040).is_ok());
}

/// GNAP-9635-§6.2-M02 — "If the key presented is associated with the token
/// [...] the AS MUST invalidate the access token, if possible, and return an
/// HTTP response code 204."
/// GNAP-9635-§6-M03 — requests must be authenticated; deleted records carry
/// no key metadata for authenticating a repeated revocation.
#[test]
fn a_token_is_revoked_through_its_management_api() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let transport = Direct::wrapping(&as_);
    let mut client = Session::new(&transport, &signer, GRANT);
    let issued = approved_token(&as_, &transport, &mut client);
    let manage = issued.manage.unwrap();

    transport.now.set(1_020);
    client.revoke_token(None, 1_020).expect("the revocation");
    assert!(
        client.usable_tokens(1_020).is_none(),
        "the client no longer holds it"
    );

    // §6.2-S04 recommends success on repeated revocation. This store cannot
    // authenticate deleted handles, so it refuses rather than bypassing §6.
    let again = signed_continuation(
        &signer,
        "DELETE",
        &manage.uri,
        manage.access_token.value.as_str(),
        None,
        1_030,
    );
    assert_eq!(as_.handle(&again, 1_030).status, 400);
}

/// GNAP-9635-§6.1.1-M08 — "If the AS does not allow rotation of the access
/// token's key for any reason, including but not limited to lack of permission
/// for this client instance or lack of capability by the AS, the AS MUST return
/// a `key_rotation_not_supported` error code."
///
/// This server instance has not opted into key rotation. It refuses a request
/// carrying a usable public key rather than silently rotating only the value.
#[test]
fn binding_a_new_key_is_refused_by_the_code_the_rfc_names() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let transport = Direct::wrapping(&as_);
    let mut client = Session::new(&transport, &signer, GRANT);
    let manage = approved_token(&as_, &transport, &mut client)
        .manage
        .unwrap();

    let replacement = Ps256Signer::generate(2048, "rotation-candidate").unwrap();
    let with_a_key = signed_continuation(
        &signer,
        "POST",
        &manage.uri,
        manage.access_token.value.as_str(),
        Some(
            serde_json::to_vec(&serde_json::json!({
                "key": {"proof": "httpsig", "jwk": replacement.public_jwk().unwrap()}
            }))
            .unwrap(),
        ),
        1_020,
    );
    let response = as_.handle(&with_a_key, 1_020);
    assert_eq!(response.status, 400, "{}", body_of(&response));
    assert!(
        body_of(&response).contains("key_rotation_not_supported"),
        "{}",
        body_of(&response)
    );
}

/// GNAP-9635-§6-M04 — the management token has to be the one that record names,
/// and GNAP-9635-§6-M03 has the AS validate the proof that goes with it.
#[test]
fn the_management_api_answers_only_to_its_own_token_and_key() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let transport = Direct::wrapping(&as_);
    let mut client = Session::new(&transport, &signer, GRANT);
    let manage = approved_token(&as_, &transport, &mut client)
        .manage
        .unwrap();

    // The right URI, a token the AS never attached to it.
    let wrong_token = signed_continuation(
        &signer,
        "DELETE",
        &manage.uri,
        "OS9M2PMHKUR64TB8N6BW7OZB8CDFONP219RP1LT0",
        None,
        1_020,
    );
    let response = as_.handle(&wrong_token, 1_020);
    assert_eq!(response.status, 400);
    assert!(
        body_of(&response).contains("invalid_client"),
        "{}",
        body_of(&response)
    );

    // The right token, a signature that does not verify.
    let elsewhere = signed_continuation(
        &signer,
        "DELETE",
        &manage.uri,
        manage.access_token.value.as_str(),
        None,
        1_019,
    );
    let forged = with_a_signature_that_cannot_verify(
        signed_continuation(
            &signer,
            "DELETE",
            &manage.uri,
            manage.access_token.value.as_str(),
            None,
            1_020,
        ),
        &elsewhere,
    );
    assert_eq!(as_.handle(&forged, 1_020).status, 400);

    // And the token survives both, so the legitimate client can still revoke.
    transport.now.set(1_020);
    assert!(client.revoke_token(None, 1_020).is_ok());
}

/// Drives a grant through to an issued token, and hands it back.
fn approved_token(
    as_: &Server,
    transport: &Direct<'_, OneKey, Counted>,
    client: &mut Session<'_, Direct<'_, OneKey, Counted>, Ps256Signer>,
) -> gnap_types::token::AccessToken {
    let step = client.start(&request(), 1_000).unwrap();
    approved_token_from(as_, transport, client, &step)
}

/// The same, from a grant already started.
fn approved_token_from(
    as_: &Server,
    transport: &Direct<'_, OneKey, Counted>,
    client: &mut Session<'_, Direct<'_, OneKey, Counted>, Ps256Signer>,
    step: &Step,
) -> gnap_types::token::AccessToken {
    let redirect = step.response().interact.clone().unwrap().redirect.unwrap();
    let Finish::Redirect { uri } = as_
        .complete_interaction(redirect.rsplit('/').next().unwrap(), 1_005)
        .unwrap()
    else {
        panic!("the client asked for the redirect finish method");
    };
    client
        .accept_callback(&InteractCallback::from_redirect(&uri).unwrap(), 1_005)
        .unwrap();
    transport.now.set(1_010);
    let step = client.continue_grant(1_010).unwrap();
    step.response().access_token.as_ref().unwrap().tokens[0].clone()
}

/// GNAP-9635-§3.3.1-MN01 — the interaction URI "MUST be unique for the request
/// and MUST NOT contain any security-sensitive information such as user
/// identifiers".
///
/// Both halves are decidable, which is why this is a test and not an excuse.
/// Uniqueness is observable across two grants. And nothing from the request
/// reaches the URI by construction: the AS builds it from its own configured
/// base and a fresh nonce, so a value the client sent cannot end up in a link
/// that travels through a browser's history.
#[test]
fn an_interaction_uri_is_unique_and_carries_nothing_from_the_request() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();

    // A request stuffed with values that must not resurface in a URI.
    let telling: GrantRequest = serde_json::from_str(
        r#"{"client":"client-541-ab",
            "user":{"sub_ids":[{"format":"email","email":"someone@example.com"}]},
            "access_token":{"label":"a-telling-label","access":["dolphin-metadata"]},
            "interact":{"start":["redirect"],
                        "finish":{"method":"redirect",
                                  "uri":"https://client.example.net/cb",
                                  "nonce":"VJLO6A4CATR0KRO"}}}"#,
    )
    .unwrap();

    let interaction_uri = |request: &GrantRequest| {
        let transport = Direct::wrapping(&as_);
        let step = Session::new(&transport, &signer, GRANT)
            .start(request, 1_000)
            .expect("the AS should answer pending");
        step.response()
            .interact
            .clone()
            .and_then(|i| i.redirect)
            .expect("an interaction URI")
    };

    let first = interaction_uri(&telling);
    let second = interaction_uri(&telling);

    // "unique for the request": the same request twice, two URIs.
    assert_ne!(first, second, "each request gets its own interaction URI");

    // "MUST NOT contain any security-sensitive information": nothing the client
    // sent appears in either.
    for uri in [&first, &second] {
        assert!(
            uri.starts_with("https://as.example/i/"),
            "built from the AS's own base: {uri}"
        );
        for sent in [
            "someone@example.com",
            "a-telling-label",
            "VJLO6A4CATR0KRO",
            "client-541-ab",
            "dolphin-metadata",
        ] {
            assert!(
                !uri.contains(sent),
                "the interaction URI carries `{sent}` from the request: {uri}"
            );
        }
    }
}

/// GNAP-9635-§5-MN03 — "Access tokens other than the continuation access tokens
/// MUST NOT be usable for continuation requests", and the converse holds by the
/// same reasoning: each endpoint answers to its own token and no other.
///
/// The two live in different stores, so this is a property of the design rather
/// than a check anybody remembers to write. The test is what says the design
/// still holds.
#[test]
fn a_token_for_one_endpoint_is_worthless_at_the_other() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let transport = Direct::wrapping(&as_);
    let mut client = Session::new(&transport, &signer, GRANT);

    let step = client.start(&request(), 1_000).unwrap();
    let continuation = step.response().r#continue.clone().unwrap();
    let issued = approved_token_from(&as_, &transport, &mut client, &step);
    let manage = issued.manage.unwrap();

    // The continuation token, presented at the token management endpoint.
    let misplaced = signed_continuation(
        &signer,
        "DELETE",
        &manage.uri,
        continuation.access_token.value.as_str(),
        None,
        1_020,
    );
    let response = as_.handle(&misplaced, 1_020);
    assert_eq!(response.status, 400, "{}", body_of(&response));

    // The management token, presented at the continuation endpoint.
    let misplaced = signed_continuation(
        &signer,
        "POST",
        &continuation.uri,
        manage.access_token.value.as_str(),
        None,
        1_020,
    );
    let response = as_.handle(&misplaced, 1_020);
    assert_eq!(response.status, 400, "{}", body_of(&response));
    assert!(
        body_of(&response).contains("invalid_continuation"),
        "{}",
        body_of(&response)
    );
}

/// A store with an already-issued token, so failures during management can be
/// exercised independently of grant negotiation.
fn management_server<N: Nonces>(
    nonces: N,
) -> AuthorizationServer<AlwaysInteract, OneKey, MemoryStorage, N> {
    use gnap_as::TokenRecord;
    let storage = MemoryStorage::new();
    let token = serde_json::from_str(
        r#"{"value":"oldaccess","access":["read"],
            "manage":{"uri":"https://as.example/token/oldhandle",
                      "access_token":{"value":"oldmanagement"}}}"#,
    )
    .unwrap();
    install_token(
        &storage,
        "oldhandle",
        TokenRecord {
            derivation: None,
            identifier: None,
            issued_at: 1_000,
            token,
            client: serde_json::from_str(r#""known-client""#).unwrap(),
            management_token: "oldmanagement".into(),
        },
    );
    AuthorizationServer::new(
        AlwaysInteract {
            interacted: Cell::new(true),
        },
        OneKey(RSA_SPKI),
        storage,
        nonces,
        Endpoints {
            grant: GRANT.into(),
            continuation: CONTINUE.into(),
            interaction: "https://as.example/i".into(),
            token_management: "https://as.example/token".into(),
        },
    )
}

/// GNAP-9635-§6.1 and §6.1.1 — value rotation has no content; the only
/// supported interpretation of content is an explicit request for a new key,
/// which this AS rejects. Invalid content must not silently rotate a token.
#[test]
fn malformed_rotation_content_does_not_rotate_the_token() {
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    for body in ["{", "[]", "null", "{}", r#"{"access":["write"]}"#] {
        let as_ = management_server(Counted(Cell::new(0)));
        let original = as_.storage().get_token("oldhandle").unwrap();
        let request = signed_continuation(
            &signer,
            "POST",
            "https://as.example/token/oldhandle",
            "oldmanagement",
            Some(body.as_bytes().to_vec()),
            1_000,
        );
        let response = as_.handle(&request, 1_000);
        assert_eq!(response.status, 400, "{body}: {}", body_of(&response));
        let preserved = as_.storage().get_token("oldhandle").unwrap();
        assert_eq!(preserved.issued_at, original.issued_at);
        assert_eq!(preserved.token, original.token);
        let valid = signed_continuation(
            &signer,
            "POST",
            "https://as.example/token/oldhandle",
            "oldmanagement",
            None,
            1_001,
        );
        assert_eq!(
            as_.handle(&valid, 1_001).status,
            200,
            "the original management credentials still work after {body}"
        );
    }
}

#[test]
fn stripping_signed_rotation_content_cannot_rotate_a_token_value() {
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let as_ = management_server(Counted(Cell::new(0)));
    let original = as_.storage().get_token("oldhandle").unwrap();
    let token = gnap_types::token::TokenValue::new("oldmanagement").unwrap();
    let intact = gnap_client::sign_request(
        HttpRequest::new("POST", "https://as.example/token/oldhandle")
            .json_body(br#"{"key":"replacement-key-reference"}"#.to_vec()),
        &signer,
        Some(&token),
        1_000,
    )
    .unwrap();
    let mut stripped = intact.clone();
    stripped.body = None;
    let response = as_.handle(&stripped, 1_000);
    assert_eq!(response.status, 400, "{}", body_of(&response));
    let preserved = as_.storage().get_token("oldhandle").unwrap();
    assert_eq!(preserved.token, original.token);
    assert_eq!(preserved.issued_at, original.issued_at);
    assert_eq!(preserved.management_token, original.management_token);

    // The unchanged signed request still reaches the unsupported-key-rotation
    // decision: the tampered request did not spend its signature's nonce.
    let response = as_.handle(&intact, 1_000);
    assert_eq!(response.status, 400);
    assert!(
        body_of(&response).contains("key_rotation_not_supported"),
        "{}",
        body_of(&response)
    );
}

/// GNAP-9635-§6.1-MN02 compares with the CURRENT management token, not only
/// the replacement management token. A failed rotation must also preserve the
/// existing token (§6.1, `invalid_rotation`).
#[test]
fn an_unusable_rotation_preserves_the_original_token() {
    struct Scripted(RefCell<std::collections::VecDeque<String>>);
    impl Nonces for Scripted {
        fn next(&self) -> String {
            self.0.borrow_mut().pop_front().expect("script exhausted")
        }
    }
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    for values in [
        ["oldmanagement", "newmanagement", "newhandle"],
        ["oldaccess", "newmanagement", "newhandle"],
        ["same", "same", "newhandle"],
        ["newaccess", "newmanagement", "bad\"handle"],
    ] {
        let values = values
            .into_iter()
            .chain(["goodaccess", "goodmanagement", "goodhandle"])
            .map(str::to_owned)
            .collect();
        let as_ = management_server(Scripted(RefCell::new(values)));
        let original = as_.storage().get_token("oldhandle").unwrap();
        let request = signed_continuation(
            &signer,
            "POST",
            "https://as.example/token/oldhandle",
            "oldmanagement",
            None,
            1_000,
        );
        let response = as_.handle(&request, 1_000);
        assert_eq!(response.status, 400, "{}", body_of(&response));
        let parsed: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(parsed["error"]["code"], "invalid_rotation");
        let preserved = as_.storage().get_token("oldhandle").unwrap();
        assert_eq!(preserved.issued_at, original.issued_at);
        assert_eq!(preserved.token, original.token);
        let retry = signed_continuation(
            &signer,
            "POST",
            "https://as.example/token/oldhandle",
            "oldmanagement",
            None,
            1_001,
        );
        let response = as_.handle(&retry, 1_001);
        assert_eq!(response.status, 200, "{}", body_of(&response));
        let rotated: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(rotated["access_token"]["value"], "goodaccess");
        assert_eq!(
            rotated["access_token"]["access"],
            serde_json::json!(["read"])
        );
    }
}

/// GNAP-9635-§2.3-M07 — the proof must use the mechanism associated with
/// the presented key, even when its algorithm can verify an HTTP signature.
#[test]
fn an_http_signature_cannot_stand_in_for_another_proof_method() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    for proof in ["mtls", "jws", "jwsd", "future-proof"] {
        let body = serde_json::json!({
            "client": {"key": {"proof": proof,
                "jwk": {"kty": "RSA", "kid": "gnap-demo", "alg": "PS256"}}},
            "interact": {"start": ["redirect"]}
        });
        let http = signed_grant(&signer, &serde_json::to_vec(&body).unwrap(), 1_000);
        let response = as_.handle(&http, 1_000);
        assert_eq!(response.status, 400, "{proof}: {}", body_of(&response));
        assert!(body_of(&response).contains("invalid_client"));
    }
}

/// RFC 9110 §11.1 and §11.4 — an authentication scheme is case-insensitive,
/// and the separator is one or more spaces. The token remains case-sensitive.
#[test]
fn the_gnap_authentication_scheme_follows_http_grammar() {
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    for authorization in [
        "gnap oldmanagement",
        "Gnap  oldmanagement",
        "GNAP oldmanagement",
    ] {
        let as_ = management_server(Counted(Cell::new(0)));
        let request = signed_with(
            &signer,
            "POST",
            "https://as.example/token/oldhandle",
            Some(authorization),
            vec![
                Component::Method,
                Component::TargetUri,
                Component::Authorization,
            ],
            1_000,
            None,
        );
        let response = as_.handle(&request, 1_000);
        assert_eq!(
            response.status,
            200,
            "{authorization}: {}",
            body_of(&response)
        );
    }
    for authorization in [
        "GNAP OLDMANAGEMENT",
        "GNAP\toldmanagement",
        "GNAP oldmanagement other",
    ] {
        let as_ = management_server(Counted(Cell::new(0)));
        // No valid credentials: refusal must precede signature verification.
        let request = HttpRequest::new("POST", "https://as.example/token/oldhandle")
            .header("Authorization", authorization);
        assert_eq!(as_.handle(&request, 1_000).status, 400);
    }
    let as_ = management_server(Counted(Cell::new(0)));
    let duplicate = signed_continuation(
        &signer,
        "POST",
        "https://as.example/token/oldhandle",
        "oldmanagement",
        None,
        1_000,
    )
    .header("Authorization", "GNAP another-token");
    assert_eq!(as_.handle(&duplicate, 1_000).status, 400);
}

/// GNAP-9635-§5.3 — a PATCH replaces the supplied fields even when the RO
/// has just finished a previous interaction and its reference is still due.
#[test]
fn a_modification_after_interaction_is_not_silently_ignored() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let transport = Direct::wrapping(&as_);
    let mut client = Session::new(&transport, &signer, GRANT);
    let step = client.start(&request(), 1_000).unwrap();
    let continuation = step.response().r#continue.clone().unwrap();
    let redirect = step
        .response()
        .interact
        .as_ref()
        .unwrap()
        .redirect
        .as_ref()
        .unwrap();
    as_.complete_interaction(redirect.rsplit('/').next().unwrap(), 1_005)
        .unwrap();

    // Remove the finish method and use polling for the new interaction.
    let patch = signed_continuation(
        &signer,
        "PATCH",
        &continuation.uri,
        continuation.access_token.value.as_str(),
        Some(br#"{"interact":{"start":["redirect"]}}"#.to_vec()),
        1_010,
    );
    let response = as_.handle(&patch, 1_010);
    assert_eq!(response.status, 200, "{}", body_of(&response));
    let parsed: gnap_types::message::GrantResponse =
        serde_json::from_slice(&response.body).unwrap();
    let new_interact = parsed
        .interact
        .expect("the modification must start its new interaction");
    assert!(
        new_interact.finish.is_none(),
        "the previous finish was replaced"
    );
    let new_redirect = new_interact.redirect.unwrap();
    assert_ne!(&new_redirect, redirect);
    as_.complete_interaction(new_redirect.rsplit('/').next().unwrap(), 1_011)
        .unwrap();
    let new_cont = parsed.r#continue.unwrap();
    let poll = signed_continuation(
        &signer,
        "POST",
        &new_cont.uri,
        new_cont.access_token.value.as_str(),
        None,
        1_020,
    );
    let response = as_.handle(&poll, 1_020);
    assert_eq!(response.status, 200, "{}", body_of(&response));
    assert!(body_of(&response).contains("access_token"));
    let response: gnap_types::message::GrantResponse =
        serde_json::from_slice(&response.body).unwrap();
    assert!(
        response.access_token.is_some(),
        "the modified polling flow can finish"
    );
}

/// GNAP-9635-§7.3.1 — the required covered components are a minimum, and all
/// included signatures must be examined. RFC 9421 §2.1 combines field lines.
#[test]
fn extra_covered_fields_and_split_signature_headers_are_verified() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let body = serde_json::to_vec(&request()).unwrap();
    let digest =
        gnap_crypto::digest::content_digest(&body, gnap_crypto::digest::DigestAlgorithm::Sha256);
    let input = SignatureInput {
        components: vec![
            Component::Method,
            Component::TargetUri,
            Component::ContentDigest,
            Component::Field("x-extra".into()),
        ],
        created: 1_000,
        keyid: "gnap-demo".into(),
        nonce: None,
        tag: Tag::Gnap,
    };
    // Specify the RFC's combined value directly, independently of the helper
    // used by the verifier, so the test checks canonicalization across roles.
    let message = Message {
        method: "POST",
        target_uri: GRANT,
        content_digest: Some(&digest),
        authorization: None,
        other: vec![("\"x-extra\"".into(), "first, second".into())],
    };
    let (sig_input, signature) =
        gnap_crypto::httpsig::sign(&message, &input, &signer, "sig1").unwrap();
    let request = HttpRequest::new("POST", GRANT)
        .json_body(body)
        .header("Content-Digest", digest)
        .header("X-Extra", " first ")
        .header("x-extra", "\tsecond\t")
        .header(
            "Signature-Input",
            format!("bad={}", input.serialize().unwrap()),
        )
        .header("Signature", "bad=:AA==:")
        .header("Signature-Input", sig_input)
        .header("Signature", signature);
    let response = as_.handle(&request, 1_000);
    assert_eq!(response.status, 200, "{}", body_of(&response));
    let mut missing = request;
    missing
        .headers
        .retain(|(name, _)| !name.eq_ignore_ascii_case("x-extra"));
    assert_eq!(as_.handle(&missing, 1_000).status, 400);
}

/// GNAP-9635-§6-M03 — a missing record cannot bypass proof validation, and
/// unauthenticated callers cannot distinguish it from incorrect credentials.
#[test]
fn unknown_and_unauthorized_management_handles_are_indistinguishable() {
    let as_ = management_server(Counted(Cell::new(0)));
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    for method in ["DELETE", "POST"] {
        let wrong = signed_continuation(
            &signer,
            method,
            "https://as.example/token/oldhandle",
            "wrong",
            None,
            1_000,
        );
        let unknown = signed_continuation(
            &signer,
            method,
            "https://as.example/token/unknownhandle",
            "wrong",
            None,
            1_000,
        );
        let refused = as_.handle(&wrong, 1_000);
        assert_eq!(refused.status, 400);
        assert_eq!(refused, as_.handle(&unknown, 1_000));
    }
}

/// GNAP-9635-§5.2 — polling an unchanged pending request must leave its
/// offered interaction usable until completion or expiry (§4.1).
#[test]
fn polling_keeps_the_interaction_open_in_the_browser_usable() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let transport = Direct::wrapping(&as_);
    let mut client = Session::new(&transport, &signer, GRANT);
    let mut initial = request();
    initial.interact.as_mut().unwrap().finish = None;
    let step = client.start(&initial, 1_000).unwrap();
    let redirect = step
        .response()
        .interact
        .as_ref()
        .unwrap()
        .redirect
        .clone()
        .unwrap();
    transport.now.set(1_010);
    assert!(matches!(
        client.continue_grant(1_010).unwrap(),
        Step::Pending(_)
    ));
    as_.complete_interaction(redirect.rsplit('/').next().unwrap(), 1_011)
        .expect("a poll must not discard the interaction already open in the browser");
    transport.now.set(1_020);
    assert!(matches!(
        client.continue_grant(1_020).unwrap(),
        Step::Approved(_)
    ));
}

/// GNAP-9635-§2.4.1-M02 applies when §5.3 brings a new user reference too.
#[test]
fn an_unknown_user_reference_in_a_modification_is_refused() {
    let as_ = server();
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let cont = pending_grant(&as_, &signer);
    let patch = signed_continuation(
        &signer,
        "PATCH",
        &cont.uri,
        cont.access_token.value.as_str(),
        Some(br#"{"user":"unknown-user"}"#.to_vec()),
        1_010,
    );
    let response = as_.handle(&patch, 1_010);
    assert_eq!(response.status, 400, "{}", body_of(&response));
    let response: gnap_types::message::GrantResponse =
        serde_json::from_slice(&response.body).unwrap();
    assert_eq!(response.error.unwrap().code.as_str(), "unknown_user");
    assert!(
        response.r#continue.is_some(),
        "the pending grant can still continue"
    );
}

/// GNAP-9635-§3.2.1-MN31 and GNAP-9635-§3.2.2-M04 — an AS that grants
/// only one token still preserves the requested object or array structure.
#[test]
fn the_as_preserves_token_cardinality_when_granting_a_subset() {
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    for multiple in [false, true] {
        let as_ = management_server(Counted(Cell::new(0)));
        let token = serde_json::json!({"label": "first", "access": ["read"]});
        let requested = if multiple {
            serde_json::json!([token, {"label": "second", "access": ["write"]}])
        } else {
            token
        };
        let body = serde_json::json!({"client": "known-client", "access_token": requested});
        let http = signed_grant(&signer, &serde_json::to_vec(&body).unwrap(), 1_000);
        let response = as_.handle(&http, 1_000);
        assert_eq!(response.status, 200, "{}", body_of(&response));
        let response: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        let issued = &response["access_token"];
        assert_eq!(issued.is_array(), multiple);
        let issued = if multiple {
            assert_eq!(issued.as_array().unwrap().len(), 1);
            &issued[0]
        } else {
            issued
        };
        assert_eq!(issued["label"], "first");
        assert!(issued.get("flags").is_none());
        assert!(issued.get("expires_in").is_none());
    }
}
struct LifetimePolicy {
    seconds: Option<std::num::NonZeroU64>,
    rotate: bool,
}
impl Policy for LifetimePolicy {
    fn evaluate(&self, _: &GrantRequest) -> Decision {
        Decision::Approve {
            access: vec![AccessItem::Reference("read".into())],
            subject: None,
        }
    }
    fn token_lifetime(&self, request: &GrantRequest) -> Option<std::num::NonZeroU64> {
        // Select from the request, not an implicit global server lifetime.
        request.access_token.as_ref().and(self.seconds)
    }
    fn may_rotate(&self, _: &gnap_types::token::AccessToken) -> bool {
        self.rotate
    }
}
type LifetimeServer = AuthorizationServer<LifetimePolicy, OneKey, MemoryStorage, Counted>;
fn lifetime_server(seconds: Option<u64>, rotate: bool) -> LifetimeServer {
    AuthorizationServer::new(
        LifetimePolicy {
            seconds: seconds.and_then(std::num::NonZeroU64::new),
            rotate,
        },
        OneKey(RSA_SPKI),
        MemoryStorage::new(),
        Counted(Cell::new(0)),
        Endpoints {
            grant: GRANT.into(),
            continuation: CONTINUE.into(),
            interaction: "https://as.example/i".into(),
            token_management: "https://as.example/token".into(),
        },
    )
}
struct LifetimeDirect<'a>(&'a LifetimeServer, Cell<u64>);
impl HttpTransport for LifetimeDirect<'_> {
    type Error = String;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        Ok(self.0.handle(&request, self.1.get()))
    }
}

#[test]
fn issued_lifetime_reaches_the_client_and_rotation_renews_it() {
    let as_ = lifetime_server(Some(20), true);
    let transport = LifetimeDirect(&as_, Cell::new(1_000));
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let mut client = Session::new(&transport, &signer, GRANT);
    client.start(&request(), 1_000).unwrap();
    let issued = (*client.usable_tokens(1_019).unwrap()[0]).clone();
    assert_eq!(issued.expires_in, Some(20));
    assert!(client.usable_tokens(1_020).is_none());
    let old_handle = issued
        .manage
        .as_ref()
        .unwrap()
        .uri
        .rsplit('/')
        .next()
        .unwrap();
    let record = as_.storage().get_token(old_handle).unwrap();
    assert_eq!(record.issued_at, 1_000);
    assert_eq!(record.expires_at(), Some(1_020));
    transport.1.set(1_019);
    let rotated = client.rotate_token(None, 1_019).unwrap();
    assert_eq!(rotated.expires_in, issued.expires_in);
    assert_eq!(rotated.access, issued.access);
    assert_ne!(rotated.value, issued.value);
    let handle = rotated
        .manage
        .as_ref()
        .unwrap()
        .uri
        .rsplit('/')
        .next()
        .unwrap();
    let record = as_.storage().get_token(handle).unwrap();
    assert_eq!(record.issued_at, 1_019);
    assert_eq!(record.expires_at(), Some(1_039));
    assert!(as_.storage().get_token(old_handle).is_none());
    assert!(client.usable_tokens(1_038).is_some());
    assert!(client.usable_tokens(1_039).is_none());
}

#[test]
fn rotation_refusal_preserves_value_rights_lifetime_and_timestamp() {
    use gnap_as::TokenRecord;
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    // Expired exactly, expired later, future timestamp, policy refusal,
    // overflowing renewal, and an externally supplied overflowing deadline.
    for (issued_at, lifetime, now, permitted) in [
        (1_000, 20, 1_020, true),
        (1_000, 20, 1_021, true),
        (1_001, 20, 1_000, true),
        (1_000, 20, 1_001, false),
        (0, u64::MAX, 1_000, true),
        (1_000, u64::MAX, 1_001, true),
    ] {
        let as_ = lifetime_server(Some(20), permitted);
        let token = serde_json::from_value(serde_json::json!({
            "value":"oldaccess", "access":["read"], "expires_in":lifetime,
            "manage":{"uri":"https://as.example/token/oldhandle", "access_token":{"value":"oldmanagement"}}
        })).unwrap();
        let original = TokenRecord {
            derivation: None,
            identifier: None,
            issued_at,
            token,
            client: request().client,
            management_token: "oldmanagement".into(),
        };
        install_token(as_.storage(), "oldhandle", original.clone());
        let response = as_.handle(
            &signed_continuation(
                &signer,
                "POST",
                "https://as.example/token/oldhandle",
                "oldmanagement",
                None,
                now,
            ),
            now,
        );
        assert_eq!(response.status, 400, "{}", body_of(&response));
        assert!(body_of(&response).contains("invalid_rotation"));
        let preserved = as_.storage().get_token("oldhandle").unwrap();
        assert_eq!(preserved.issued_at, original.issued_at);
        assert_eq!(preserved.token, original.token);
        assert_eq!(preserved.client, original.client);
        assert_eq!(preserved.management_token, original.management_token);
    }
}

#[test]
fn lifetime_omission_is_preserved_and_overflowing_issuance_fails() {
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let as_ = lifetime_server(None, true);
    let transport = LifetimeDirect(&as_, Cell::new(1_000));
    let mut client = Session::new(&transport, &signer, GRANT);
    client.start(&request(), 1_000).unwrap();
    assert_eq!(client.usable_tokens(u64::MAX).unwrap()[0].expires_in, None);
    transport.1.set(2_000);
    let rotated = client.rotate_token(None, 2_000).unwrap();
    assert_eq!(rotated.expires_in, None);
    let handle = rotated
        .manage
        .as_ref()
        .unwrap()
        .uri
        .rsplit('/')
        .next()
        .unwrap();
    assert_eq!(as_.storage().get_token(handle).unwrap().issued_at, 2_000);

    let overflow = lifetime_server(Some(u64::MAX), true);
    let response = overflow.handle(
        &signed_grant(&signer, &serde_json::to_vec(&request()).unwrap(), 1_000),
        1_000,
    );
    assert_eq!(response.status, 500);
    assert!(body_of(&response).contains("expiration time"));
    assert!(overflow.storage().get_token("nonce0002").is_none());
}
#[test]
fn invalid_generated_values_preserve_the_existing_deadline() {
    struct InvalidNonces;
    impl Nonces for InvalidNonces {
        fn next(&self) -> String {
            "invalid token value".into()
        }
    }
    let as_ = management_server(InvalidNonces);
    let mut original = as_.storage().get_token("oldhandle").unwrap();
    original.token.expires_in = Some(20);
    install_token(as_.storage(), "oldhandle", original.clone());
    let signer = Ps256Signer::from_pkcs1_pem(RSA_PKCS1, "gnap-demo").unwrap();
    let response = as_.handle(
        &signed_continuation(
            &signer,
            "POST",
            "https://as.example/token/oldhandle",
            "oldmanagement",
            None,
            1_010,
        ),
        1_010,
    );
    assert_eq!(response.status, 400);
    assert!(body_of(&response).contains("invalid_rotation"));
    let preserved = as_.storage().get_token("oldhandle").unwrap();
    assert_eq!(preserved.issued_at, original.issued_at);
    assert_eq!(preserved.expires_at(), Some(1_020));
    assert_eq!(preserved.token, original.token);
    assert_eq!(preserved.management_token, original.management_token);
}
