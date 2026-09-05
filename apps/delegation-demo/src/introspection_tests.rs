use super::*;
use gnap_types::rs::{IntrospectionResponse, ResourceServer};
use tests::{test_aggregate, test_app, test_app_at, test_record};
use tower::ServiceExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_introspection_transport_bounds_time_size_and_redirects() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = count.clone();
    let target = format!("{origin}/must-not-be-followed");
    let router = Router::new()
        .route(
            "/.well-known/gnap-as-rs",
            get(move || async move { (StatusCode::TEMPORARY_REDIRECT, [("location", target)]) }),
        )
        .route(
            "/must-not-be-followed",
            get(move || async move {
                observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                "not reached"
            }),
        )
        .route(
            "/introspect",
            post(|body: Bytes| async move {
                if body.as_ref() == b"slow" {
                    tokio::time::sleep(Duration::from_millis(2300)).await;
                    "{}".to_owned()
                } else {
                    "x".repeat(8193)
                }
            }),
        );
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    tokio::task::spawn_blocking(move || {
        let http = introspection::Http {
            origin: origin.clone(),
        };
        assert_eq!(
            http.send(HttpRequest::new(
                "GET",
                format!("{origin}/.well-known/gnap-as-rs")
            ))
            .unwrap()
            .status,
            307
        );
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(
            http.send(HttpRequest::new("POST", format!("{origin}/introspect")))
                .is_err(),
            "oversized body rejected"
        );
        let mut slow = HttpRequest::new("POST", format!("{origin}/introspect"));
        slow.body = Some(b"slow".to_vec());
        assert!(
            http.send(slow).is_err(),
            "response exceeds two-second timeout"
        );
        assert!(
            http.send(HttpRequest::new(
                "GET",
                "http://127.0.0.1:1/.well-known/gnap-as-rs"
            ))
            .is_err(),
            "fixed origin checked before network"
        );
    })
    .await
    .unwrap();
    server.abort();
    let _ = server.await;
}

fn introspection_request(app: &App, token: &str, signer: &Ps256Signer) -> HttpRequest {
    let mut request = HttpRequest::new("POST", format!("{}/introspect", app.origin));
    request
        .headers
        .push(("content-type".into(), "application/json".into()));
    request.body = Some(serde_json::to_vec(&json!({"access_token":token,"resource_server":"delegation-demo-rs","proof":"httpsig","access":[FOLDER_READ]})).unwrap());
    sign_request(request, signer, None, now()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_http_introspection_authenticates_rs_and_protects_resource_lifecycle() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let mut app = test_app_at(&origin);
    app.resource_client = Arc::new(introspection::ResourceClient {
        origin: origin.clone(),
        signer: app.resource_client.signer.clone(),
        transport: Arc::new(introspection::Http {
            origin: origin.clone(),
        }),
        nonces: MemoryStorage::default(),
    });
    let router = application_router(app.clone(), CanonicalOrigin::parse(&origin).unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let worker_app = app.clone();
    tokio::task::spawn_blocking(move || {
        let app = worker_app;
        let http = introspection::Http {
            origin: app.origin.clone(),
        };
        let snapshot = app
            .storage
            .create(test_aggregate("handle", test_record("secret-access")))
            .unwrap();
        let metadata = http
            .send(HttpRequest::new(
                "GET",
                format!("{}/.well-known/gnap-as-rs", app.origin),
            ))
            .unwrap();
        assert_eq!(metadata.status, 200);
        assert!(metadata
            .headers
            .iter()
            .any(|(name, value)| name == "cache-control" && value == "no-store"));
        let response = http
            .send(introspection_request(
                &app,
                "secret-access",
                &app.resource_client.signer,
            ))
            .unwrap();
        let IntrospectionResponse::Active(active) = serde_json::from_slice(&response.body).unwrap()
        else {
            panic!("expected active token")
        };
        assert_eq!(
            active.key.unwrap().as_value().unwrap(),
            &app.rs_registration.client_key
        );
        assert_ne!(app.rs_registration.client_key, app.rs_registration.key);
        assert_eq!(
            app.rs_registration.client_key,
            introspection::public_key(&app.signer)
        );
        // Exercise the actual client-reference resolver as well as comparing
        // JWKs: the key disclosed by introspection must validate its client's
        // proof, while the independently registered RS key must not.
        let client_resolver = KnownKeys {
            signer: app.signer.clone(),
            decisions: app.decisions.clone(),
        };
        let resolved = client_resolver
            .resolve(&snapshot.aggregate.tokens["handle"].client)
            .unwrap();
        let challenge = b"introspection client binding regression";
        let proof = gnap_crypto::proof::Signer::sign(app.signer.as_ref(), challenge).unwrap();
        assert!(resolved.verify(challenge, &proof).is_ok());
        let returned = gnap_crypto::Ps256Verifier::from_public_jwk(
            app.rs_registration.client_key.jwk.as_ref().unwrap(),
        )
        .unwrap();
        assert!(returned.verify(challenge, &proof).is_ok());
        assert!(app
            .resource_client
            .signer
            .verifier()
            .verify(challenge, &proof)
            .is_err());
        assert!(!String::from_utf8_lossy(&response.body).contains("secret-access"));
        let signed = introspection_request(&app, "secret-access", &app.resource_client.signer);
        assert_eq!(http.send(signed.clone()).unwrap().status, 200);
        assert_eq!(http.send(signed).unwrap().status, 400, "RS replay rejected");
        let wrong = http
            .send(introspection_request(&app, "secret-access", &app.signer))
            .unwrap();
        assert_eq!(wrong.status, 400, "client key cannot impersonate the RS");
        assert!(!String::from_utf8_lossy(&wrong.body).contains("secret-access"));
        let network = Network {
            origin: app.origin.clone(),
            client: reqwest::blocking::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
        };
        let read = resource_request(&app.origin, "secret-access", &app.signer).unwrap();
        let accepted = network.send(read.clone()).unwrap();
        assert_eq!(accepted.status, 200);
        assert!(
            serde_json::from_slice::<Value>(&accepted.body).unwrap()["decision_source"]
                .as_str()
                .unwrap()
                .contains("introspection")
        );
        assert_eq!(
            network.send(read).unwrap().status,
            401,
            "client replay rejected separately"
        );
        let wrong_proof =
            resource_request(&app.origin, "secret-access", &app.resource_client.signer).unwrap();
        assert_eq!(
            network.send(wrong_proof).unwrap().status,
            401,
            "RS key cannot impersonate client"
        );
        let mut replacement = snapshot.aggregate;
        replacement.tokens.clear();
        replacement
            .tokens
            .insert("rotated-handle".into(), test_record("secret-rotated"));
        let rotated = app
            .storage
            .compare_exchange(snapshot.id, snapshot.revision, replacement)
            .unwrap();
        assert_eq!(
            network
                .send(resource_request(&app.origin, "secret-access", &app.signer).unwrap())
                .unwrap()
                .status,
            401
        );
        assert_eq!(
            network
                .send(resource_request(&app.origin, "secret-rotated", &app.signer).unwrap())
                .unwrap()
                .status,
            200
        );
        let mut revoked = rotated.aggregate;
        revoked.revoked = true;
        revoked.tokens.clear();
        app.storage
            .compare_exchange(rotated.id, rotated.revision, revoked)
            .unwrap();
        assert_eq!(
            network
                .send(resource_request(&app.origin, "secret-rotated", &app.signer).unwrap())
                .unwrap()
                .status,
            401
        );
    })
    .await
    .unwrap();
    server.abort();
    let _ = server.await;
    // The RS handler still runs, but its configured AS is now unreachable.
    let request = resource_request(&app.origin, "secret-never-reflected", &app.signer).unwrap();
    let mut incoming = axum::http::Request::builder()
        .uri("/resource/folder")
        .header("host", origin.strip_prefix("http://").unwrap());
    for (name, value) in request.headers {
        incoming = incoming.header(name, value);
    }
    let response = application_router(app, CanonicalOrigin::parse(&origin).unwrap())
        .oneshot(incoming.body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key("www-authenticate"));
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap(),
        r#"{"error":"introspection_unavailable"}"#
    );
}

struct Altered {
    direct: introspection::Direct,
    discovery: Option<Value>,
    response: Option<Value>,
    calls: Arc<Mutex<Vec<String>>>,
}
impl HttpTransport for Altered {
    type Error = &'static str;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        self.calls.lock().unwrap().push(request.url.clone());
        let replacement = if request.method == "GET" {
            &self.discovery
        } else {
            &self.response
        };
        if let Some(value) = replacement {
            return Ok(HttpResponse {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body: serde_json::to_vec(value).unwrap(),
            });
        }
        self.direct.send(request)
    }
}

#[test]
fn remote_metadata_and_responses_cannot_remove_local_proof_or_deadline_policy() {
    let mut app = test_app();
    app.storage
        .create(test_aggregate("handle", test_record("access")))
        .unwrap();
    let good: Value = serde_json::from_slice(
        &introspection::handle(
            &app,
            &introspection_request(&app, "access", &app.resource_client.signer),
            now(),
        )
        .body,
    )
    .unwrap();
    let bad_metadata = json!({"grant_request_endpoint":"https://demo.example/gnap","introspection_endpoint":"https://untrusted.example/introspect"});
    let cases = [
        (Some(bad_metadata), None),
        (None, Some(json!({"active":false,"key":"unexpected"}))),
        (
            None,
            Some(json!({"active":true,"iss":"https://demo.example/gnap","access":[FOLDER_READ]})),
        ),
    ];
    for (discovery, response) in cases {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let only_discovery = discovery.is_some();
        app.resource_client = Arc::new(introspection::ResourceClient {
            origin: app.origin.clone(),
            signer: app.resource_client.signer.clone(),
            nonces: MemoryStorage::default(),
            transport: Arc::new(Altered {
                direct: introspection::Direct {
                    server: app.server.clone(),
                    storage: app.storage.clone(),
                    registration: app.rs_registration.clone(),
                    origin: app.origin.clone(),
                },
                discovery,
                response,
                calls: calls.clone(),
            }),
        });
        assert!(matches!(
            read_resource(
                &app,
                &resource_request(&app.origin, "access", &app.signer).unwrap()
            ),
            Err(ResourceError::Unavailable)
        ));
        assert_eq!(
            calls.lock().unwrap().len(),
            if only_discovery { 1 } else { 2 }
        );
    }
    for (field, value) in [
        ("iss", json!("https://untrusted.example/gnap")),
        ("exp", Value::Null),
        ("iat", json!(u64::MAX)),
        ("exp", json!(u64::MAX)),
        ("nbf", json!(now() + 60)),
        (
            "key",
            json!({"proof":"httpsig","jwk":app.resource_client.signer.public_jwk().unwrap()}),
        ),
    ] {
        let mut response = good.clone();
        response[field] = value;
        app.resource_client = Arc::new(introspection::ResourceClient {
            origin: app.origin.clone(),
            signer: app.resource_client.signer.clone(),
            nonces: MemoryStorage::default(),
            transport: Arc::new(Altered {
                direct: introspection::Direct {
                    server: app.server.clone(),
                    storage: app.storage.clone(),
                    registration: app.rs_registration.clone(),
                    origin: app.origin.clone(),
                },
                discovery: None,
                response: Some(response),
                calls: Arc::default(),
            }),
        });
        assert!(
            read_resource(
                &app,
                &resource_request(&app.origin, "access", &app.signer).unwrap()
            )
            .is_err(),
            "field {field}"
        );
    }
}

#[test]
fn policy_refuses_unknown_audience_or_rights_and_clock_rollback() {
    use gnap_as::{IntrospectionDecision, IntrospectionPolicy};
    let app = test_app();
    let token = test_record("access");
    let mut unresolved_key = token.clone();
    unresolved_key.token.key = Some(gnap_types::key::Key::ByReference("unresolved-key".into()));
    assert!(matches!(
        app.rs_registration.evaluate(
            &ResourceServer::ByReference("delegation-demo-rs".into()),
            &unresolved_key,
            None
        ),
        IntrospectionDecision::Inactive
    ));
    assert!(matches!(
        app.rs_registration.evaluate(
            &ResourceServer::ByReference("unknown-rs".into()),
            &token,
            None
        ),
        IntrospectionDecision::Inactive
    ));
    assert!(matches!(
        app.rs_registration.evaluate(
            &ResourceServer::ByReference("delegation-demo-rs".into()),
            &token,
            Some(&[AccessItem::Reference("unrecognized:write".into())])
        ),
        IntrospectionDecision::Inactive
    ));
    app.storage.create(test_aggregate("handle", token)).unwrap();
    for rollback_at in [1, 2] {
        let time = now();
        let calls = std::cell::Cell::new(0);
        assert!(read_resource_with_clock(
            &app,
            &resource_request(&app.origin, "access", &app.signer).unwrap(),
            || {
                let index = calls.get();
                calls.set(index + 1);
                if index >= rollback_at {
                    time - 1
                } else {
                    time
                }
            }
        )
        .is_err());
    }
}
