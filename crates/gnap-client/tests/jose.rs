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
