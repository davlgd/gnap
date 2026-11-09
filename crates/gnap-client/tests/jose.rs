//! What a session refuses to sign with `jws` or `jwsd`, before it sends
//! anything (RFC 9635 §2.3, §7.3.3, §7.3.4).

use gnap_client::{ClientError, HttpRequest, HttpResponse, HttpTransport, Session};
use gnap_crypto::{Es256Signer, JwkSigner, Ps256Signer};
use gnap_types::message::GrantRequest;
use serde_json::{json, Value};

/// A transport that must never be reached.
struct Unreachable;
impl HttpTransport for Unreachable {
    type Error = std::convert::Infallible;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        panic!("nothing may be sent: {request:?}");
    }
}

fn request(proof: &Value, jwk: &Value) -> GrantRequest {
    serde_json::from_value(json!({
        "client": {"key": {"proof": proof, "jwk": jwk}},
        "access_token": {"access": ["read"]}
    }))
    .unwrap()
}

fn refused(signer: &(dyn JwkSigner + Sync), grant: &GrantRequest) -> String {
    match Session::new(Unreachable, signer, "https://as.example/gnap").start(grant, 1_000) {
        Err(ClientError::Usage(reason)) => reason,
        other => panic!("expected a usage error, got {other:?}"),
    }
}

#[test]
fn a_session_refuses_a_jose_proof_its_signer_cannot_make() {
    let es256 = Es256Signer::generate("es256-key").unwrap();
    let jwk = Value::Object(es256.public_jwk().unwrap());

    let reason = refused(&es256, &request(&json!({"method": "jws", "x": 1}), &jwk));
    assert!(reason.contains("no parameters"), "{reason}");

    let mut renamed = jwk.clone();
    renamed["kid"] = json!("another-key");
    let reason = refused(&es256, &request(&json!("jwsd"), &renamed));
    assert!(reason.contains("kid"), "{reason}");

    let mut realg = jwk.clone();
    realg["alg"] = json!("EdDSA");
    let reason = refused(&es256, &request(&json!("jws"), &realg));
    assert!(reason.contains("alg"), "{reason}");

    let ps256 = Ps256Signer::generate(2048, "ps256-key").unwrap();
    let ps_jwk = Value::Object(ps256.public_jwk().unwrap());
    let reason = refused(&ps256, &request(&json!("jws"), &ps_jwk));
    assert!(reason.contains("PS256"), "{reason}");

    let reason = refused(&es256, &request(&json!("mtls"), &jwk));
    assert!(reason.contains("mtls"), "{reason}");
}

/// An empty detailed proof is the method without parameters.
#[test]
fn an_empty_detailed_proof_is_accepted_up_to_the_transport() {
    struct Reached;
    impl HttpTransport for Reached {
        type Error = String;
        fn send(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
            assert!(request
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("detached-jws")));
            Err("reached".into())
        }
    }
    let es256 = Es256Signer::generate("es256-key").unwrap();
    let jwk = Value::Object(es256.public_jwk().unwrap());
    let result = Session::new(Reached, &es256, "https://as.example/gnap")
        .start(&request(&json!({"method": "jwsd"}), &jwk), 1_000);
    assert!(
        matches!(result, Err(ClientError::Transport(_))),
        "{result:?}"
    );
}

/// A JWK with a private member, or the public key of another signer, never
/// leaves: the session imports the JWK as a public key, and checks its own
/// proof under it before sending.
#[test]
fn a_session_sends_only_the_public_key_its_signer_holds() {
    let es256 = Es256Signer::generate("es256-key").unwrap();
    let jwk = Value::Object(es256.public_jwk().unwrap());
    for method in ["jws", "jwsd"] {
        let mut private = jwk.clone();
        private["d"] = json!("SYNTHETIC_PRIVATE_MEMBER_NOT_A_REAL_KEY");
        let reason = refused(&es256, &request(&json!(method), &private));
        assert!(reason.contains("client.key"), "{method}: {reason}");

        let other = Es256Signer::generate("es256-key").unwrap();
        let reason = refused(&other, &request(&json!(method), &jwk));
        assert!(reason.contains("doesn't verify"), "{method}: {reason}");
    }
}

/// A transport that counts the requests it is handed, and fails them.
#[derive(Default)]
struct Failing(std::cell::Cell<u32>, std::cell::RefCell<Vec<HttpRequest>>);
impl HttpTransport for &Failing {
    type Error = String;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        self.0.set(self.0.get() + 1);
        self.1.borrow_mut().push(request);
        Err("unreachable network".into())
    }
}

/// A client named by reference, or one whose key is named by reference,
/// proves with `httpsig`; and a start lost at the transport leaves no grant,
/// so the session can start again, with another method too.
#[test]
fn references_prove_with_httpsig_and_a_lost_start_can_be_retried() {
    let es256 = Es256Signer::generate("es256-key").unwrap();
    for client in [json!("client-reference"), json!({"key": "key-reference"})] {
        let transport = Failing::default();
        let grant: GrantRequest = serde_json::from_value(json!({
            "client": client, "access_token": {"access": ["read"]}
        }))
        .unwrap();
        let mut session = Session::new(&transport, &es256, "https://as.example/gnap");
        assert!(matches!(
            session.start(&grant, 1_000),
            Err(ClientError::Transport(_))
        ));
        let sent = transport.1.borrow();
        assert!(sent[0]
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("signature-input")));
    }

    let transport = Failing::default();
    let jwk = Value::Object(es256.public_jwk().unwrap());
    let mut session = Session::new(&transport, &es256, "https://as.example/gnap");
    for method in ["jws", "jwsd"] {
        let result = session.start(&request(&json!(method), &jwk), 1_000);
        assert!(
            matches!(result, Err(ClientError::Transport(_))),
            "{method}: {result:?}"
        );
    }
    assert_eq!(transport.0.get(), 2, "the lost start left no grant behind");
}
