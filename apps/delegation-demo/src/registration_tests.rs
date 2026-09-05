use super::*;
use gnap_as::{ResourceSetStore, RsId};
use resource_registration::{bootstrap, leaves, RS_OWNER};
use std::sync::atomic::{AtomicU64, Ordering};
use tower::ServiceExt;

enum Reply {
    Pass,
    LostAfterCommit,
    Status(u16, Value),
}
struct Script {
    direct: introspection::Direct,
    replies: Mutex<VecDeque<Reply>>,
    requests: Mutex<Vec<HttpRequest>>,
}
impl HttpTransport for Script {
    type Error = &'static str;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        self.requests.lock().unwrap().push(request.clone());
        let next = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Reply::Pass);
        match next {
            Reply::Pass => self.direct.send(request),
            Reply::LostAfterCommit => {
                assert_eq!(self.direct.send(request)?.status, 200);
                Err("synthetic lost response")
            }
            Reply::Status(status, body) => Ok(HttpResponse {
                status,
                headers: vec![("content-type".into(), "application/json".into())],
                body: serde_json::to_vec(&body).unwrap(),
            }),
        }
    }
}
fn script(app: &mut App, replies: Vec<Reply>) -> Arc<Script> {
    let transport = Arc::new(Script {
        direct: introspection::Direct {
            server: app.server.clone(),
            registration: app.rs_registration.clone(),
            storage: app.storage.clone(),
            origin: app.origin.clone(),
        },
        replies: Mutex::new(replies.into()),
        requests: Mutex::new(Vec::new()),
    });
    app.resource_client = Arc::new(introspection::ResourceClient {
        origin: app.origin.clone(),
        signer: app.resource_client.signer.clone(),
        transport: transport.clone(),
        nonces: MemoryStorage::default(),
    });
    transport
}

#[test]
fn bootstrap_retries_lost_commit_without_duplicate_sets_or_reused_signatures() {
    let mut app = tests::starting_app_at("https://demo.example");
    let observed = script(
        &mut app,
        vec![Reply::Pass, Reply::Pass, Reply::LostAfterCommit],
    );
    let elapsed = AtomicU64::new(0);
    let refs = bootstrap(
        &app,
        || Duration::from_secs(elapsed.load(Ordering::SeqCst)),
        |delay| {
            elapsed.fetch_add(delay.as_secs(), Ordering::SeqCst);
        },
    )
    .unwrap();
    assert!(
        app.bootstrap.get().is_none(),
        "no automatic partial publication"
    );
    assert_ne!(refs.folder, refs.both);
    let owner = RsId(RS_OWNER.into());
    assert_eq!(
        app.rs_registration
            .resources
            .register_or_get(&owner, "rsr_unused_candidate", &leaves(false))
            .unwrap()
            .reference,
        refs.folder
    );
    assert_eq!(
        app.rs_registration
            .resources
            .register_or_get(&owner, "rsr_unused_candidate", &leaves(true))
            .unwrap()
            .reference,
        refs.both
    );
    let requests = observed.requests.lock().unwrap();
    assert_eq!(requests.len(), 6);
    let nonces: HashSet<_> = requests
        .iter()
        .filter(|r| r.method == "POST")
        .map(|request| {
            request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("signature-input"))
                .unwrap()
                .1
                .split("nonce=\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap()
        })
        .collect();
    assert_eq!(nonces.len(), 4, "each retry is freshly signed");
    for request in requests.iter().filter(|r| r.method == "POST") {
        let body: Value = serde_json::from_slice(request.body.as_ref().unwrap()).unwrap();
        assert!(body.get("token_formats_supported").is_none());
        assert_eq!(body["token_introspection_required"], true);
    }
    assert!(app
        .storage
        .lock()
        .unwrap()
        .continuation_deadlines
        .is_empty());
}

#[test]
fn bootstrap_does_not_publish_partial_wrong_owner_or_foreign_instance_references() {
    let mut app = tests::starting_app_at("https://demo.example");
    let observed = script(
        &mut app,
        vec![
            Reply::Pass,
            Reply::Pass,
            Reply::Status(400, json!({"error":{"code":"invalid_request"}})),
        ],
    );
    assert!(bootstrap(
        &app,
        || Duration::ZERO,
        |_| panic!("permanent error must not retry")
    )
    .is_err());
    assert_eq!(observed.requests.lock().unwrap().len(), 3);
    assert!(app.bootstrap.get().is_none());
    assert!(app
        .storage
        .lock()
        .unwrap()
        .continuation_deadlines
        .is_empty());
    // A well-formed old-instance ACK must not publish a reference absent here.
    let observed = script(
        &mut app,
        (0..6)
            .flat_map(|_| {
                [
                    Reply::Pass,
                    Reply::Status(200, json!({"resource_reference":"rsr_old_instance"})),
                ]
            })
            .collect(),
    );
    assert!(bootstrap(&app, || Duration::ZERO, |_| {}).is_err());
    assert_eq!(
        observed.requests.lock().unwrap().len(),
        12,
        "six attempts exactly"
    );
    assert!(app.bootstrap.get().is_none());
    // Even a locally known reference cannot cross the authenticated owner.
    app.rs_registration
        .resources
        .register_or_get(
            &RsId("other-owner".into()),
            "rsr_other_owner",
            &leaves(false),
        )
        .unwrap();
    script(
        &mut app,
        vec![
            Reply::Pass,
            Reply::Status(200, json!({"resource_reference":"rsr_other_owner"})),
        ],
    );
    assert!(bootstrap(
        &app,
        || Duration::ZERO,
        |_| panic!("wrong ownership must stop")
    )
    .is_err());
}

#[test]
fn bootstrap_budget_rollback_and_retry_classes_are_bounded() {
    let mut app = tests::starting_app_at("https://demo.example");
    for status in [404, 503, 400] {
        let observed = script(
            &mut app,
            vec![Reply::Status(
                status,
                json!({"error":{"code":"invalid_resource_server"}}),
            )],
        );
        let elapsed = AtomicU64::new(0);
        assert!(bootstrap(
            &app,
            || Duration::from_secs(elapsed.load(Ordering::SeqCst)),
            |delay| {
                elapsed.fetch_add(delay.as_secs(), Ordering::SeqCst);
            }
        )
        .is_ok());
        assert_eq!(observed.requests.lock().unwrap().len(), 4);
    }
    let observed = script(&mut app, vec![Reply::Status(503, json!({}))]);
    let calls = AtomicU64::new(0);
    assert!(bootstrap(
        &app,
        || if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            Duration::from_secs(119)
        } else {
            Duration::from_secs(120)
        },
        |_| {}
    )
    .is_err());
    assert_eq!(observed.requests.lock().unwrap().len(), 1);
    let calls = AtomicU64::new(0);
    let observed = script(&mut app, vec![]);
    assert!(bootstrap(
        &app,
        || if calls.fetch_add(1, Ordering::SeqCst) == 0 {
            Duration::from_secs(1)
        } else {
            Duration::ZERO
        },
        |_| {}
    )
    .is_err());
    assert_eq!(observed.requests.lock().unwrap().len(), 1);
    // Deadline reached after the second successful POST still forbids publishing.
    let calls = AtomicU64::new(0);
    let observed = script(&mut app, vec![]);
    assert!(bootstrap(
        &app,
        || if calls.fetch_add(1, Ordering::SeqCst) >= 7 {
            Duration::from_secs(120)
        } else {
            Duration::ZERO
        },
        |_| {}
    )
    .is_err());
    assert_eq!(observed.requests.lock().unwrap().len(), 3);
    assert!(app.bootstrap.get().is_none());
}

#[test]
fn both_wire_error_envelopes_retry_invalid_resource_server() {
    let mut app = tests::starting_app_at("https://demo.example");
    for error in [
        json!({"error":"invalid_resource_server"}),
        json!({"error":{"code":"invalid_resource_server","description":"synthetic old-instance response"}}),
    ] {
        let observed = script(&mut app, vec![Reply::Status(400, error)]);
        assert!(bootstrap(&app, || Duration::ZERO, |_| {}).is_ok());
        assert_eq!(observed.requests.lock().unwrap().len(), 4);
    }
}

#[test]
fn missing_old_instance_capabilities_retry_but_changed_destinations_stop() {
    let mut app = tests::starting_app_at("https://demo.example");
    for missing in ["resource_registration_endpoint", "introspection_endpoint"] {
        let mut metadata = json!({"grant_request_endpoint":"https://demo.example/gnap","resource_registration_endpoint":"https://demo.example/register-resources","introspection_endpoint":"https://demo.example/introspect"});
        metadata.as_object_mut().unwrap().remove(missing);
        let observed = script(&mut app, vec![Reply::Status(200, metadata)]);
        assert!(bootstrap(&app, || Duration::ZERO, |_| {}).is_ok());
        assert_eq!(observed.requests.lock().unwrap().len(), 4);
    }
    for field in ["resource_registration_endpoint", "introspection_endpoint"] {
        let mut metadata = json!({"grant_request_endpoint":"https://demo.example/gnap","resource_registration_endpoint":"https://demo.example/register-resources","introspection_endpoint":"https://demo.example/introspect"});
        metadata[field] = json!("https://untrusted.example/endpoint");
        let observed = script(&mut app, vec![Reply::Status(200, metadata)]);
        assert!(bootstrap(
            &app,
            || Duration::ZERO,
            |_| panic!("untrusted endpoint must not retry")
        )
        .is_err());
        assert_eq!(observed.requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_http_bootstrap_gates_start_and_formats_then_publishes_only_local_sets() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let mut app = tests::starting_app_at(&origin);
    app.resource_client = Arc::new(introspection::ResourceClient {
        origin: origin.clone(),
        signer: app.resource_client.signer.clone(),
        transport: Arc::new(introspection::Http {
            origin: origin.clone(),
        }),
        nonces: MemoryStorage::default(),
    });
    let router = application_router(app.clone(), CanonicalOrigin::parse(&origin).unwrap());
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(
            &axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap()
        )
        .unwrap()["bootstrap"],
        "starting"
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/start")
                .header("host", origin.strip_prefix("http://").unwrap())
                .header("origin", &origin)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key("set-cookie"));
    assert!(app.starts.lock().unwrap().is_empty());
    let serving = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let worker_app = app.clone();
    let refs = tokio::task::spawn_blocking(move || {
        let started = Instant::now();
        let refs = bootstrap(
            &worker_app,
            || started.elapsed(),
            |_| panic!("local bootstrap must succeed once"),
        )
        .unwrap();
        for reference in [&refs.folder, &refs.both] {
            assert!(reference.starts_with("rsr_"));
            let request =
                resource_request(&worker_app.origin, reference, &worker_app.signer).unwrap();
            assert!(
                matches!(
                    read_resource(&worker_app, &request),
                    Err(ResourceError::Denied)
                ),
                "a resource reference is not an access token"
            );
        }
        let mut registration = HttpRequest::new(
            "POST",
            format!("{}{}", worker_app.origin, resource_registration::PATH),
        );
        registration
            .headers
            .push(("content-type".into(), "application/json".into()));
        registration.body = Some(
            serde_json::to_vec(&json!({
                "access": leaves(false), "resource_server": introspection::RS_ID,
                "token_introspection_required": true
            }))
            .unwrap(),
        );
        assert_eq!(
            worker_app
                .resource_client
                .transport
                .send(registration.clone())
                .unwrap()
                .status,
            400
        );
        let wrong_key = sign_request(
            registration.clone(),
            worker_app.signer.as_ref(),
            None,
            now(),
        )
        .unwrap();
        assert_eq!(
            worker_app
                .resource_client
                .transport
                .send(wrong_key)
                .unwrap()
                .status,
            400
        );
        let signed = sign_request(
            registration.clone(),
            worker_app.resource_client.signer.as_ref(),
            None,
            now(),
        )
        .unwrap();
        assert_eq!(
            worker_app
                .resource_client
                .transport
                .send(signed.clone())
                .unwrap()
                .status,
            200
        );
        assert_eq!(
            worker_app
                .resource_client
                .transport
                .send(signed)
                .unwrap()
                .status,
            400
        );
        for formats in [json!([]), json!(["jwt"]), json!(["unknown"])] {
            let mut request = registration.clone();
            request.body = Some(
                serde_json::to_vec(&json!({
                    "access": leaves(false), "resource_server": introspection::RS_ID,
                    "token_formats_supported": formats, "token_introspection_required": true
                }))
                .unwrap(),
            );
            let signed = sign_request(
                request,
                worker_app.resource_client.signer.as_ref(),
                None,
                now(),
            )
            .unwrap();
            assert_eq!(
                worker_app
                    .resource_client
                    .transport
                    .send(signed)
                    .unwrap()
                    .status,
                400
            );
        }
        refs
    })
    .await
    .unwrap();
    assert!(app.bootstrap.get().is_none());
    app.bootstrap.set(Ok(refs.clone())).unwrap();
    assert_eq!(resource_registration::state(&app.bootstrap), "ready");
    let request: GrantRequest = serde_json::from_value(
        json!({"client":"test-client","access_token":{"access":[refs.both]}}),
    )
    .unwrap();
    let rights = requested_rights(&request, &app.rs_registration.resources).unwrap();
    assert_eq!(rights.len(), 2);
    assert!(rights.iter().all(resource_registration::known_leaf));
    let restarted = tests::starting_app_at(&origin);
    assert!(requested_rights(&request, &restarted.rs_registration.resources).is_none());
    serving.abort();
    let _ = serving.await;
}
