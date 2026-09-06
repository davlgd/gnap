//! Wire requests and independently scripted AS responses, without an AS store.
use gnap_client::{sign_request, HttpTransport};
use gnap_crypto::{
    proof::Signer,
    ps256::Ps256Signer,
    verify::{verify_request, Expectations, NonceMemory, SignedRequest},
};
use gnap_rs::{
    AccessPolicy, Audience, AudiencePolicy, AuthorizationError, Authorizer, TokenInfo, TrustedAs,
};
use gnap_types::{
    access::AccessItem,
    http::{HttpRequest, HttpResponse},
    rs::ResourceServer,
    token::TokenValue,
};
use serde_json::{json, Value};
use std::{
    cell::{Cell, RefCell},
    collections::HashSet,
    sync::OnceLock,
};

const GRANT: &str = "https://as.example/gnap?tenant=one";
const INTROSPECT: &str = "https://as.example/introspect";
const RESOURCE: &str = "https://rs.example/files/a?raw=%2f";
const VALUE: &str = "synthetic-token";

fn client() -> &'static Ps256Signer {
    static KEY: OnceLock<Ps256Signer> = OnceLock::new();
    KEY.get_or_init(|| {
        Ps256Signer::from_pkcs1_pem(
            include_str!("../../gnap-crypto/tests/rfc9421-b12.pkcs1.pem"),
            "same-kid",
        )
        .unwrap()
    })
}
fn rs() -> &'static Ps256Signer {
    static KEY: OnceLock<Ps256Signer> = OnceLock::new();
    KEY.get_or_init(|| Ps256Signer::generate(2048, "same-kid").unwrap())
}
fn right() -> AccessItem {
    AccessItem::Reference("files:read".into())
}
fn response(value: &Value) -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![("Content-Type".into(), "application/json".into())],
        body: serde_json::to_vec(value).unwrap(),
    }
}
fn active() -> Value {
    json!({"active":true,"iss":GRANT,"iat":1000,"exp":1100,"access":["files:read"],
        "key":{"proof":"httpsig","jwk":client().public_jwk().unwrap()}})
}
fn discovery() -> Value {
    json!({"grant_request_endpoint":GRANT,"introspection_endpoint":INTROSPECT,"key_proofs_supported":["httpsig"]})
}
#[derive(Default)]
struct Replay(RefCell<HashSet<String>>);
impl NonceMemory for Replay {
    fn remember_nonce(&self, value: &str, _: u64) -> bool {
        self.0.borrow_mut().insert(value.into())
    }
}
struct Scripted {
    discovery: HttpResponse,
    introspection: HttpResponse,
    error_at: Option<usize>,
    calls: RefCell<Vec<HttpRequest>>,
}
impl Scripted {
    fn new() -> Self {
        Self {
            discovery: response(&discovery()),
            introspection: response(&active()),
            error_at: None,
            calls: RefCell::default(),
        }
    }
}
impl HttpTransport for Scripted {
    type Error = &'static str;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        let mut calls = self.calls.borrow_mut();
        let position = calls.len() % 2;
        calls.push(request);
        if self.error_at == Some(position) {
            return Err("secret transport diagnostic must not escape");
        }
        Ok(if position == 0 {
            self.discovery.clone()
        } else {
            self.introspection.clone()
        })
    }
}
fn request() -> HttpRequest {
    sign_request(
        HttpRequest::new("GET", RESOURCE),
        client(),
        Some(&TokenValue::new(VALUE).unwrap()),
        1000,
    )
    .unwrap()
}
// An intentionally accepting callback with the required policy signature.
#[allow(clippy::unnecessary_wraps)]
const fn permit(_: &TokenInfo<'_>) -> Result<(), AuthorizationError> {
    Ok(())
}
fn authorize(
    transport: &Scripted,
    nonces: &Replay,
    request: &HttpRequest,
    audience: &AudiencePolicy,
    policy: &(impl AccessPolicy + ?Sized),
    clock: impl Fn() -> u64,
) -> Result<(), AuthorizationError> {
    let trusted = TrustedAs::new(GRANT, INTROSPECT).unwrap();
    let identity = ResourceServer::ByReference("rs-registration-not-audience".into());
    Authorizer::new(&trusted, &identity, transport, rs(), nonces, audience).authorize(
        request,
        &[right()],
        policy,
        clock,
    )
}

#[test]
fn success_uses_two_exact_requests_and_a_distinct_rs_proof_without_cache() {
    let transport = Scripted::new();
    let nonces = Replay::default();
    for _ in 0..2 {
        assert_eq!(
            authorize(
                &transport,
                &nonces,
                &request(),
                &AudiencePolicy::IntrospectionContext,
                &permit,
                || 1000
            ),
            Ok(())
        );
    }
    let calls = transport.calls.borrow();
    assert_eq!(calls.len(), 4);
    for pair in calls.chunks(2) {
        assert_eq!(
            (&*pair[0].method, &*pair[0].url),
            ("GET", "https://as.example/.well-known/gnap-as-rs")
        );
        let outgoing = &pair[1];
        assert_eq!((&*outgoing.method, &*outgoing.url), ("POST", INTROSPECT));
        assert!(outgoing.header_value("authorization").is_none());
        let body: Value = serde_json::from_slice(outgoing.body.as_ref().unwrap()).unwrap();
        assert_eq!(
            body,
            json!({"resource_server":"rs-registration-not-audience","access_token":VALUE,"proof":"httpsig","access":["files:read"]})
        );
        let signed = SignedRequest {
            method: &outgoing.method,
            target_uri: &outgoing.url,
            headers: &outgoing.headers,
            body: outgoing.body.as_deref(),
        };
        let expected = Expectations {
            now: 1000,
            max_clock_skew: 300,
            key_id: None,
        };
        assert!(verify_request(&signed, &rs().verifier(), &expected, &Replay::default()).is_ok());
        assert!(
            verify_request(&signed, &client().verifier(), &expected, &Replay::default()).is_err()
        );
    }
}

#[test]
fn trusted_endpoints_use_shared_url_validation_and_explicit_loopback_deviation() {
    for (grant, introspection) in [
        ("http://as.example/gnap", INTROSPECT),
        (GRANT, "http://as.example/i"),
        ("https://as.example/gnap#fragment", INTROSPECT),
        ("https:///missing", INTROSPECT),
    ] {
        assert!(TrustedAs::new(grant, introspection).is_err());
    }
    assert!(TrustedAs::new("http://127.0.0.1/gnap", "http://127.0.0.1/i").is_err());
    let local =
        TrustedAs::for_local_development("http://127.0.0.1:8080/gnap", "http://[::1]:8081/i")
            .unwrap();
    assert_eq!(
        local.discovery_endpoint(),
        "http://127.0.0.1:8080/.well-known/gnap-as-rs"
    );
    assert!(TrustedAs::for_local_development("http://evil.example/g", INTROSPECT).is_err());
    let separate = TrustedAs::new(GRANT, "https://trusted-separate.example/i").unwrap();
    assert_eq!(
        separate.introspection_endpoint(),
        "https://trusted-separate.example/i"
    );
}

#[test]
fn endpoint_userinfo_is_refused_without_confusing_at_in_path_or_query() {
    for (grant, endpoint) in [
        ("https://user@as.example/g", INTROSPECT),
        ("https://user:password@as.example/g", INTROSPECT),
        (GRANT, "https://user@as.example/i"),
        (GRANT, "https://user:password@as.example/i"),
    ] {
        assert_eq!(
            TrustedAs::new(grant, endpoint).unwrap_err(),
            gnap_types::message::DiscoveryError::InvalidEndpoint
        );
        assert_eq!(
            TrustedAs::for_local_development(grant, endpoint).unwrap_err(),
            gnap_types::message::DiscoveryError::InvalidEndpoint
        );
    }
    for local in [false, true] {
        let grant = "https://as.example/@path?email=owner@example";
        let endpoint = "https://as.example/introspect?contact=admin@example";
        let trusted = if local {
            TrustedAs::for_local_development(grant, endpoint)
        } else {
            TrustedAs::new(grant, endpoint)
        }
        .unwrap();
        assert_eq!(trusted.grant_endpoint(), grant);
        assert_eq!(trusted.introspection_endpoint(), endpoint);
        assert_eq!(
            trusted.discovery_endpoint(),
            "https://as.example/.well-known/gnap-as-rs"
        );
    }
}

#[test]
fn discovery_cannot_replace_configured_issuer_destination_or_proof() {
    for (field, value) in [
        ("grant_request_endpoint", json!("https://evil.example/gnap")),
        (
            "grant_request_endpoint",
            json!("https://as.example/gnap?tenant=two"),
        ),
        (
            "introspection_endpoint",
            json!("https://evil.example/introspect"),
        ),
        ("introspection_endpoint", Value::Null),
        ("key_proofs_supported", json!([])),
        ("key_proofs_supported", json!(["mtls"])),
    ] {
        let mut transport = Scripted::new();
        let mut metadata = discovery();
        metadata[field] = value;
        transport.discovery = response(&metadata);
        assert_eq!(
            authorize(
                &transport,
                &Replay::default(),
                &request(),
                &AudiencePolicy::IntrospectionContext,
                &permit,
                || 1000
            ),
            Err(AuthorizationError::Unavailable),
            "{field}"
        );
        assert_eq!(transport.calls.borrow().len(), 1);
    }
    let mut transport = Scripted::new();
    let mut metadata = discovery();
    metadata
        .as_object_mut()
        .unwrap()
        .remove("key_proofs_supported");
    transport.discovery = response(&metadata);
    assert_eq!(
        authorize(
            &transport,
            &Replay::default(),
            &request(),
            &AudiencePolicy::IntrospectionContext,
            &permit,
            || 1000
        ),
        Ok(())
    );
}

#[test]
fn malformed_or_ambiguous_authorization_is_rejected_without_network_work() {
    for credentials in [
        "Bearer synthetic-token",
        "GNAP",
        "GNAP token suffix",
        "GNAP token\t",
        "GNAP ",
    ] {
        let transport = Scripted::new();
        let mut request = request();
        for (name, value) in &mut request.headers {
            if name.eq_ignore_ascii_case("authorization") {
                *value = credentials.into();
            }
        }
        assert_eq!(
            authorize(
                &transport,
                &Replay::default(),
                &request,
                &AudiencePolicy::IntrospectionContext,
                &permit,
                || 1000
            ),
            Err(AuthorizationError::Denied)
        );
        assert!(transport.calls.borrow().is_empty());
    }
    let transport = Scripted::new();
    let mut request = request();
    request
        .headers
        .push(("AUTHORIZATION".into(), format!("GNAP {VALUE}")));
    assert_eq!(
        authorize(
            &transport,
            &Replay::default(),
            &request,
            &AudiencePolicy::IntrospectionContext,
            &permit,
            || 1000
        ),
        Err(AuthorizationError::Denied)
    );
    assert!(transport.calls.borrow().is_empty());
}

#[test]
fn policy_acceptance_never_bypasses_a_wrong_key_or_tampered_request() {
    for attack in 0..4 {
        let mut request = request();
        let mut transport = Scripted::new();
        match attack {
            0 => {
                let mut value = active();
                value["key"]["jwk"] = serde_json::to_value(rs().public_jwk().unwrap()).unwrap();
                transport.introspection = response(&value);
            }
            1 => request.url = "https://rs.example/files/b?raw=%2f".into(),
            2 => request.method = "DELETE".into(),
            _ => {
                for (name, value) in &mut request.headers {
                    if name.eq_ignore_ascii_case("authorization") {
                        *value = "GNAP other-token".into();
                    }
                }
            }
        }
        let calls = Cell::new(0);
        let policy = |_: &TokenInfo<'_>| {
            calls.set(calls.get() + 1);
            Ok(())
        };
        let nonces = Replay::default();
        assert_eq!(
            authorize(
                &transport,
                &nonces,
                &request,
                &AudiencePolicy::IntrospectionContext,
                &policy,
                || 1000
            ),
            Err(AuthorizationError::Denied)
        );
        assert_eq!(calls.get(), 1);
        assert!(nonces.0.borrow().is_empty());
    }
}

#[test]
fn policy_refusal_preserves_the_nonce_and_a_later_replay_is_refused() {
    let transport = Scripted::new();
    let nonces = Replay::default();
    let request = request();
    for error in [AuthorizationError::Denied, AuthorizationError::Unavailable] {
        let policy = |_: &TokenInfo<'_>| Err(error);
        assert_eq!(
            authorize(
                &transport,
                &nonces,
                &request,
                &AudiencePolicy::IntrospectionContext,
                &policy,
                || 1000
            ),
            Err(error)
        );
        assert!(nonces.0.borrow().is_empty());
    }
    assert_eq!(
        authorize(
            &transport,
            &nonces,
            &request,
            &AudiencePolicy::IntrospectionContext,
            &permit,
            || 1000
        ),
        Ok(())
    );
    assert_eq!(nonces.0.borrow().len(), 1);
    assert_eq!(
        authorize(
            &transport,
            &nonces,
            &request,
            &AudiencePolicy::IntrospectionContext,
            &permit,
            || 1000
        ),
        Err(AuthorizationError::Denied)
    );
}

#[test]
fn required_rights_are_nonempty_exact_and_not_overridden_by_policy() {
    let transport = Scripted::new();
    let trusted = TrustedAs::new(GRANT, INTROSPECT).unwrap();
    let identity = ResourceServer::ByReference("rs".into());
    let nonces = Replay::default();
    let authorizer = Authorizer::new(
        &trusted,
        &identity,
        &transport,
        rs(),
        &nonces,
        &AudiencePolicy::IntrospectionContext,
    );
    assert_eq!(
        authorizer.authorize(&request(), &[], &permit, || 1000),
        Err(AuthorizationError::Denied)
    );
    assert!(transport.calls.borrow().is_empty());
    assert_eq!(
        authorizer.authorize(
            &request(),
            &[AccessItem::Reference("files:write".into())],
            &permit,
            || 1000
        ),
        Err(AuthorizationError::Denied)
    );
    assert!(nonces.0.borrow().is_empty());
    // Profile rejection must keep its classification even when rights are absent.
    let unavailable = |_: &TokenInfo<'_>| Err(AuthorizationError::Unavailable);
    assert_eq!(
        authorizer.authorize(
            &request(),
            &[AccessItem::Reference("files:write".into())],
            &unavailable,
            || 1000
        ),
        Err(AuthorizationError::Unavailable)
    );
}

#[test]
fn inactive_and_unusable_token_profiles_remain_fail_closed() {
    let inactive = Scripted {
        introspection: response(&json!({"active":false})),
        ..Scripted::new()
    };
    assert_eq!(
        authorize(
            &inactive,
            &Replay::default(),
            &request(),
            &AudiencePolicy::IntrospectionContext,
            &permit,
            || 1000
        ),
        Err(AuthorizationError::Denied)
    );
    for (field, value) in [
        ("iss", json!("https://evil.example/gnap")),
        ("iat", Value::Null),
        ("exp", json!(1000)),
        ("key", Value::Null),
        ("flags", json!(["bearer"])),
        ("flags", json!(["durable"])),
        ("unknown", json!(true)),
        ("nbf", json!(-1)),
        ("nbf", json!(1000.5)),
        ("nbf", Value::Null),
        ("sub", json!(4)),
        ("sub", Value::Null),
        ("instance_id", json!({})),
        ("aud", json!(["rs", 1])),
        ("aud", Value::Null),
    ] {
        let mut data = active();
        data[field] = value;
        let transport = Scripted {
            introspection: response(&data),
            ..Scripted::new()
        };
        let nonces = Replay::default();
        assert_eq!(
            authorize(
                &transport,
                &nonces,
                &request(),
                &AudiencePolicy::IntrospectionContext,
                &permit,
                || 1000
            ),
            Err(AuthorizationError::Unavailable),
            "{field}"
        );
        assert!(nonces.0.borrow().is_empty());
    }
    for proof in [json!("mtls"), json!({"method":"httpsig","extra":true})] {
        let mut data = active();
        data["key"]["proof"] = proof;
        let transport = Scripted {
            introspection: response(&data),
            ..Scripted::new()
        };
        assert_eq!(
            authorize(
                &transport,
                &Replay::default(),
                &request(),
                &AudiencePolicy::IntrospectionContext,
                &permit,
                || 1000
            ),
            Err(AuthorizationError::Unavailable)
        );
    }
}

#[test]
fn audience_is_explicit_and_never_inferred_from_the_rs_reference() {
    for audience in [
        json!("resource-audience"),
        json!(["other", "resource-audience"]),
    ] {
        let mut data = active();
        data["aud"] = audience;
        let transport = Scripted {
            introspection: response(&data),
            ..Scripted::new()
        };
        assert_eq!(
            authorize(
                &transport,
                &Replay::default(),
                &request(),
                &AudiencePolicy::IntrospectionContext,
                &permit,
                || 1000
            ),
            Err(AuthorizationError::Unavailable)
        );
        assert_eq!(
            authorize(
                &transport,
                &Replay::default(),
                &request(),
                &AudiencePolicy::Exact("resource-audience".into()),
                &permit,
                || 1000
            ),
            Ok(())
        );
        assert_eq!(
            authorize(
                &transport,
                &Replay::default(),
                &request(),
                &AudiencePolicy::Exact("rs-registration-not-audience".into()),
                &permit,
                || 1000
            ),
            Err(AuthorizationError::Denied)
        );
    }
    assert_eq!(
        authorize(
            &Scripted::new(),
            &Replay::default(),
            &request(),
            &AudiencePolicy::Exact("resource-audience".into()),
            &permit,
            || 1000
        ),
        Err(AuthorizationError::Denied)
    );
}

#[test]
fn policy_receives_strict_typed_claims_without_keys_or_raw_tokens() {
    let mut data = active();
    data["aud"] = json!(["rs-audience"]);
    data["nbf"] = json!(1000);
    data["sub"] = json!("owner");
    data["instance_id"] = json!("client-instance");
    let transport = Scripted {
        introspection: response(&data),
        ..Scripted::new()
    };
    let policy = |info: &TokenInfo<'_>| {
        assert_eq!(info.access, &[right()]);
        assert_eq!(info.issued_at, 1000);
        assert_eq!(info.expires_at, 1100);
        assert_eq!(info.not_before, Some(1000));
        assert_eq!(info.subject, Some("owner"));
        assert_eq!(info.instance_id, Some("client-instance"));
        assert_eq!(info.audience, Some(Audience::Multiple(vec!["rs-audience"])));
        Ok(())
    };
    assert_eq!(
        authorize(
            &transport,
            &Replay::default(),
            &request(),
            &AudiencePolicy::Exact("rs-audience".into()),
            &policy,
            || 1000
        ),
        Ok(())
    );
}

#[test]
fn three_clock_reads_enforce_expiration_monotonicity_and_not_before_without_skew() {
    for (times, expected, consumed) in [
        ([1000, 1000, 1000], Ok(()), true),
        ([1000, 999, 1000], Err(AuthorizationError::Denied), false),
        ([1000, 1001, 1000], Err(AuthorizationError::Denied), true),
        ([1000, 1099, 1100], Err(AuthorizationError::Denied), true),
        ([1000, 1100, 1100], Err(AuthorizationError::Denied), false),
        ([999, 999, 999], Err(AuthorizationError::Denied), false),
    ] {
        let position = Cell::new(0);
        let clock = || {
            let index = position.get();
            position.set(index + 1);
            times[index]
        };
        let nonces = Replay::default();
        assert_eq!(
            authorize(
                &Scripted::new(),
                &nonces,
                &request(),
                &AudiencePolicy::IntrospectionContext,
                &permit,
                clock
            ),
            expected
        );
        assert_eq!(!nonces.0.borrow().is_empty(), consumed);
        assert_eq!(position.get(), if consumed { 3 } else { 2 });
    }
    for (nbf, expected) in [
        (999, Ok(())),
        (1000, Ok(())),
        (1001, Err(AuthorizationError::Denied)),
    ] {
        let mut data = active();
        data["nbf"] = json!(nbf);
        let transport = Scripted {
            introspection: response(&data),
            ..Scripted::new()
        };
        assert_eq!(
            authorize(
                &transport,
                &Replay::default(),
                &request(),
                &AudiencePolicy::IntrospectionContext,
                &permit,
                || 1000
            ),
            expected
        );
    }
}

#[test]
fn network_status_mime_json_and_body_limits_are_redacted_unavailability() {
    for stage in 0..2 {
        for mode in 0..7 {
            let mut transport = Scripted::new();
            let response = if stage == 0 {
                &mut transport.discovery
            } else {
                &mut transport.introspection
            };
            match mode {
                0 => response.status = 503,
                1 => response.headers.clear(),
                2 => response
                    .headers
                    .push(("CONTENT-TYPE".into(), "application/json".into())),
                3 => response.headers[0].1 = "text/html".into(),
                4 => response.body = b"{invalid sensitive token response".to_vec(),
                5 => response.body = vec![b' '; 8193],
                _ => transport.error_at = Some(stage),
            }
            let error = authorize(
                &transport,
                &Replay::default(),
                &request(),
                &AudiencePolicy::IntrospectionContext,
                &permit,
                || 1000,
            )
            .unwrap_err();
            assert_eq!(error, AuthorizationError::Unavailable);
            assert_eq!(error.to_string(), "resource authorization unavailable");
            assert_eq!(format!("{error:?}"), "Unavailable");
            assert_eq!(transport.calls.borrow().len(), stage + 1);
        }
    }
    let mut transport = Scripted::new();
    transport.introspection.body.resize(8192, b' ');
    transport.introspection.headers[0].1 = "Application/JSON; charset=utf-8".into();
    assert_eq!(
        authorize(
            &transport,
            &Replay::default(),
            &request(),
            &AudiencePolicy::IntrospectionContext,
            &permit,
            || 1000
        ),
        Ok(())
    );
}

#[test]
fn nonce_is_required_even_when_otherwise_valid_signature_omits_it() {
    use gnap_crypto::httpsig::{sign, Component, Message, SignatureInput, Tag};
    for nonce in [None, Some("")] {
        let mut request = HttpRequest::new("GET", RESOURCE);
        request
            .headers
            .push(("Authorization".into(), format!("GNAP {VALUE}")));
        let message = Message {
            method: &request.method,
            target_uri: &request.url,
            authorization: request.header_value("authorization"),
            content_digest: None,
            other: Vec::new(),
        };
        let headers = sign(
            &message,
            &SignatureInput {
                components: vec![
                    Component::Method,
                    Component::TargetUri,
                    Component::Authorization,
                ],
                created: 1000,
                keyid: client().key_id().into(),
                nonce: nonce.map(str::to_owned),
                tag: Tag::Gnap,
            },
            client(),
            "sig1",
        )
        .unwrap();
        request.headers.push(("Signature-Input".into(), headers.0));
        request.headers.push(("Signature".into(), headers.1));
        assert_eq!(
            authorize(
                &Scripted::new(),
                &Replay::default(),
                &request,
                &AudiencePolicy::IntrospectionContext,
                &permit,
                || 1000
            ),
            Err(AuthorizationError::Denied)
        );
    }
}

#[test]
fn well_formed_bearer_reference_binding_and_malformed_jwk_are_not_supported() {
    for mode in 0..3 {
        let mut data = active();
        match mode {
            0 => {
                data["flags"] = json!(["bearer"]);
                data.as_object_mut().unwrap().remove("key");
            }
            1 => data["key"] = json!("client-key-reference"),
            _ => {
                data["key"]["jwk"].as_object_mut().unwrap().remove("n");
            }
        }
        // These are usable introspection envelopes. The RS profile, rather
        // than a missing-bound-key envelope check, must refuse them.
        let _: gnap_types::rs::IntrospectionResponse =
            serde_json::from_value(data.clone()).unwrap();
        let transport = Scripted {
            introspection: response(&data),
            ..Scripted::new()
        };
        let nonces = Replay::default();
        assert_eq!(
            authorize(
                &transport,
                &nonces,
                &request(),
                &AudiencePolicy::IntrospectionContext,
                &permit,
                || 1000
            ),
            Err(AuthorizationError::Unavailable)
        );
        assert!(nonces.0.borrow().is_empty());
    }
}

#[test]
fn by_value_rs_identity_is_serialized_without_becoming_the_audience_or_client_key() {
    let public_identity = json!({"key":{"proof":"httpsig","jwk":rs().public_jwk().unwrap()}});
    let identity: ResourceServer = serde_json::from_value(public_identity.clone()).unwrap();
    let mut data = active();
    data["aud"] = json!("resource-audience");
    let transport = Scripted {
        introspection: response(&data),
        ..Scripted::new()
    };
    let trusted = TrustedAs::new(GRANT, INTROSPECT).unwrap();
    let nonces = Replay::default();
    assert_eq!(
        Authorizer::new(
            &trusted,
            &identity,
            &transport,
            rs(),
            &nonces,
            &AudiencePolicy::Exact("resource-audience".into())
        )
        .authorize(&request(), &[right()], &permit, || 1000),
        Ok(())
    );
    let calls = transport.calls.borrow();
    let outgoing: Value = serde_json::from_slice(calls[1].body.as_ref().unwrap()).unwrap();
    assert_eq!(outgoing["resource_server"], public_identity);
    assert_eq!(outgoing["access_token"], VALUE);
    assert_eq!(outgoing["proof"], "httpsig");
    assert_eq!(nonces.0.borrow().len(), 1);
}
