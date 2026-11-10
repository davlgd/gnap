//! Resource requests proven with `jws` or `jwsd` (RFC 9635 §7.3.3, §7.3.4),
//! against independently scripted AS responses.

use gnap_client::{HttpTransport, sign_jose_request, sign_request};
use gnap_crypto::Es256Signer;
use gnap_crypto::jws::{JwsMethod, ReplayCache};
use gnap_rs::{AudiencePolicy, AuthorizationError, Authorized, Authorizer, TokenInfo, TrustedAs};
use gnap_types::{
    access::AccessItem,
    http::{HttpRequest, HttpResponse},
    rs::ResourceServer,
    token::TokenValue,
};
use serde_json::{Value, json};
use std::cell::{Cell, RefCell};
use std::sync::OnceLock;

const GRANT: &str = "https://as.example/gnap";
const INTROSPECT: &str = "https://as.example/introspect";
const RESOURCE: &str = "https://rs.example/files/a";
const VALUE: &str = "synthetic-token";
const NOW: u64 = 1_000;

fn client() -> &'static Es256Signer {
    static KEY: OnceLock<Es256Signer> = OnceLock::new();
    KEY.get_or_init(|| Es256Signer::generate("client-key").unwrap())
}
fn rs() -> &'static Es256Signer {
    static KEY: OnceLock<Es256Signer> = OnceLock::new();
    KEY.get_or_init(|| Es256Signer::generate("rs-key").unwrap())
}
fn token() -> TokenValue {
    TokenValue::new(VALUE).unwrap()
}
fn response(value: &Value) -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: serde_json::to_vec(value).unwrap(),
    }
}

/// Answers discovery, then introspection with a token bound to `proof`.
struct Scripted {
    proof: &'static str,
    calls: RefCell<Vec<HttpRequest>>,
}
impl Scripted {
    const fn new(proof: &'static str) -> Self {
        Self {
            proof,
            calls: RefCell::new(Vec::new()),
        }
    }
}
impl HttpTransport for Scripted {
    type Error = &'static str;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        let mut calls = self.calls.borrow_mut();
        let first = calls.len().is_multiple_of(2);
        calls.push(request);
        Ok(if first {
            response(&json!({"grant_request_endpoint": GRANT,
                "introspection_endpoint": INTROSPECT, "key_proofs_supported": ["httpsig"]}))
        } else {
            response(
                &json!({"active": true, "iss": GRANT, "iat": NOW, "exp": NOW + 100,
                "access": ["files:read"],
                "key": {"proof": self.proof, "jwk": client().public_jwk().unwrap()}}),
            )
        })
    }
}

#[allow(clippy::unnecessary_wraps)]
const fn permit(_: &TokenInfo<'_>) -> Result<(), AuthorizationError> {
    Ok(())
}
#[allow(clippy::unnecessary_wraps)]
const fn deny(_: &TokenInfo<'_>) -> Result<(), AuthorizationError> {
    Err(AuthorizationError::Denied)
}

fn authorize(
    transport: &Scripted,
    replay: Option<&ReplayCache>,
    request: &HttpRequest,
    policy: fn(&TokenInfo<'_>) -> Result<(), AuthorizationError>,
    clock: &dyn Fn() -> u64,
) -> Result<Authorized, AuthorizationError> {
    let trusted = TrustedAs::new(GRANT, INTROSPECT).unwrap();
    let identity = ResourceServer::ByReference("files".into());
    let nonces = |_: &str, _: u64| true;
    let authorizer = Authorizer::new(
        &trusted,
        &identity,
        transport,
        rs(),
        &nonces,
        &AudiencePolicy::IntrospectionContext,
    );
    let authorizer = match replay {
        Some(replay) => authorizer.with_jose_proofs(replay),
        None => authorizer,
    };
    authorizer.authorize(
        request,
        &[AccessItem::Reference("files:read".into())],
        &policy,
        clock,
    )
}

fn jose(method: JwsMethod, request: HttpRequest) -> HttpRequest {
    sign_jose_request(request, method, client(), Some(&token()), NOW).unwrap()
}

/// Both methods authorize a request with or without content, and the RS
/// gets the authenticated content: the body for `jwsd`, whatever its media
/// type, and the JWS payload for `jws`. Introspection names no proof method.
#[test]
fn a_jose_proven_request_is_authorized_with_its_content() {
    let json = br#"{"note":"hello"}"#.to_vec();
    let binary = vec![0_u8, 159, 146, 150];
    for (method, request, content) in [
        (
            JwsMethod::Jwsd,
            HttpRequest::new("GET", RESOURCE),
            Vec::new(),
        ),
        (
            JwsMethod::Jws,
            HttpRequest::new("GET", RESOURCE),
            Vec::new(),
        ),
        (
            JwsMethod::Jws,
            HttpRequest::new("POST", RESOURCE).json_body(json.clone()),
            json,
        ),
        (
            JwsMethod::Jwsd,
            {
                let mut request = HttpRequest::new("POST", RESOURCE)
                    .header("Content-Type", "application/octet-stream");
                request.body = Some(binary.clone());
                request
            },
            binary,
        ),
    ] {
        let transport = Scripted::new(method.name());
        let replay = ReplayCache::new(16, 300);
        let signed = jose(method, request);
        let authorized = authorize(&transport, Some(&replay), &signed, permit, &|| NOW)
            .unwrap_or_else(|e| panic!("{}: {e}", method.name()));
        assert_eq!(
            authorized.content(),
            content.as_slice(),
            "{}",
            method.name()
        );
        let introspection: Value =
            serde_json::from_slice(transport.calls.borrow()[1].body.as_ref().unwrap()).unwrap();
        assert!(introspection.get("proof").is_none(), "{introspection}");
    }
}

/// Without a JOSE replay memory, a token bound to a JOSE key is unavailable.
#[test]
fn a_jose_token_needs_the_activation() {
    let transport = Scripted::new("jwsd");
    let signed = jose(JwsMethod::Jwsd, HttpRequest::new("GET", RESOURCE));
    assert_eq!(
        authorize(&transport, None, &signed, permit, &|| NOW),
        Err(AuthorizationError::Unavailable)
    );
}

/// The method is the introspected key's: an `httpsig` signature doesn't
/// prove a JOSE-bound token, a JOSE proof doesn't prove an `httpsig`-bound
/// one, and neither proves next to the other's envelope.
#[test]
fn the_proof_method_is_the_introspected_key() {
    let replay = ReplayCache::new(16, 300);
    let httpsig = sign_request(
        HttpRequest::new("GET", RESOURCE),
        client(),
        Some(&token()),
        NOW,
    )
    .unwrap();
    let detached = jose(JwsMethod::Jwsd, HttpRequest::new("GET", RESOURCE));
    let mut both = httpsig.clone();
    both.headers.extend(
        detached
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("detached-jws"))
            .cloned(),
    );
    for (proof, request) in [
        ("jwsd", &httpsig),
        ("httpsig", &detached),
        ("httpsig", &both),
        ("jwsd", &both),
    ] {
        let transport = Scripted::new(proof);
        let result = authorize(&transport, Some(&replay), request, permit, &|| NOW);
        assert_eq!(result, Err(AuthorizationError::Denied), "{proof}");
    }
}

/// `ath` binds the presented token, and a proof is spent once.
#[test]
fn a_jose_proof_binds_the_token_and_is_spent_once() {
    let replay = ReplayCache::new(16, 300);
    let other = TokenValue::new("another-token").unwrap();
    let mut wrong = sign_jose_request(
        HttpRequest::new("GET", RESOURCE),
        JwsMethod::Jwsd,
        client(),
        Some(&other),
        NOW,
    )
    .unwrap();
    wrong
        .headers
        .retain(|(name, _)| !name.eq_ignore_ascii_case("authorization"));
    wrong = wrong.header("Authorization", format!("GNAP {VALUE}"));
    let transport = Scripted::new("jwsd");
    assert_eq!(
        authorize(&transport, Some(&replay), &wrong, permit, &|| NOW),
        Err(AuthorizationError::Denied)
    );

    let signed = jose(JwsMethod::Jwsd, HttpRequest::new("GET", RESOURCE));
    assert!(authorize(&transport, Some(&replay), &signed, permit, &|| NOW).is_ok());
    assert_eq!(
        authorize(&transport, Some(&replay), &signed, permit, &|| NOW),
        Err(AuthorizationError::Denied)
    );
}

/// The policy decides before the proof is spent, so a refused request's
/// proof still serves; a late clock refusal comes after, and spends it.
#[test]
fn the_policy_runs_before_the_proof_and_the_last_clock_after() {
    let replay = ReplayCache::new(16, 300);
    let transport = Scripted::new("jws");
    let signed = jose(JwsMethod::Jws, HttpRequest::new("GET", RESOURCE));
    assert_eq!(
        authorize(&transport, Some(&replay), &signed, deny, &|| NOW),
        Err(AuthorizationError::Denied)
    );
    assert!(authorize(&transport, Some(&replay), &signed, permit, &|| NOW).is_ok());

    let late = jose(
        JwsMethod::Jws,
        HttpRequest::new("GET", "https://rs.example/files/b"),
    );
    let reads = Cell::new(0);
    let clock = || {
        reads.set(reads.get() + 1);
        if reads.get() < 3 { NOW } else { NOW + 200 }
    };
    assert!(authorize(&transport, Some(&replay), &late, permit, &clock).is_err());
    assert_eq!(
        authorize(&transport, Some(&replay), &late, permit, &|| NOW),
        Err(AuthorizationError::Denied),
        "the proof was spent before the last clock check"
    );
}
