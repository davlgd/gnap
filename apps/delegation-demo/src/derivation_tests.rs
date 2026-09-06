use super::*;
use gnap_types::token::AccessToken;

fn signed(app: &App, path: &str, token: &TokenValue, signer: &Ps256Signer) -> HttpRequest {
    sign_request(
        HttpRequest::new("GET", format!("{}{path}", app.origin)),
        signer,
        Some(token),
        now(),
    )
    .unwrap()
}
fn derivation_request(app: &App, parent: &TokenValue, signer: &Ps256Signer) -> HttpRequest {
    signed_grant(
        app,
        json!({"client":introspection::RS_ID,"existing_access_token":parent,"access_token":{"access":[derivation::METADATA_READ]}}),
        signer,
    )
}
fn signed_grant(app: &App, body: Value, signer: &Ps256Signer) -> HttpRequest {
    let mut request = HttpRequest::new("POST", format!("{}/gnap", app.origin));
    request
        .headers
        .push(("content-type".into(), "application/json".into()));
    request.body = Some(serde_json::to_vec(&body).unwrap());
    sign_request(request, signer, None, now()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_http_derivation_separates_roles_bounds_children_and_cascades_parent_retirement() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let mut app = tests::test_app_at(&origin);
    app.resource_client = Arc::new(introspection::ResourceClient {
        origin: origin.clone(),
        signer: app.resource_client.signer.clone(),
        transport: Arc::new(introspection::Http {
            origin: origin.clone(),
        }),
        nonces: MemoryStorage::default(),
    });
    let router = application_router(app.clone(), CanonicalOrigin::parse(&origin).unwrap());
    let serving = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    tokio::task::spawn_blocking(move || downstream_scenario(app, origin))
        .await
        .unwrap();
    serving.abort();
    let _ = serving.await;
}

fn downstream_scenario(app: App, origin: String) {
    let network = Network {
        origin: origin.clone(),
        client: reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap(),
    };
    let http = introspection::Http {
        origin: origin.clone(),
    };
    let references = app.bootstrap.get().unwrap().as_ref().unwrap();
    let request: GrantRequest = serde_json::from_value(json!({"client":"test-client","access_token":{"access":[references.folder]},"interact":{"start":["redirect"],"finish":{"method":"redirect","uri":format!("{origin}/callback"),"nonce":fresh_nonce().unwrap()}}})).unwrap();
    let mut session = Session::new(&network, app.signer.as_ref(), format!("{origin}/gnap"))
        .supporting(&["redirect"]);
    let pending = session.start(&request, now()).unwrap();
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
    let snapshot = app
        .storage
        .lookup(GrantSelector::Interaction(handle))
        .unwrap()
        .unwrap();
    let finish = consent_finish(
        &app.server,
        &app.storage,
        &app.decisions,
        "test-client",
        snapshot.id,
        handle,
        true,
    )
    .unwrap();
    session
        .accept_callback(&InteractCallback::from_redirect(&finish).unwrap(), now())
        .unwrap();
    std::thread::sleep(Duration::from_secs(
        pending
            .response()
            .r#continue
            .as_ref()
            .unwrap()
            .effective_wait(),
    ));
    let approved = session.continue_grant(now()).unwrap();
    let parent = approved.response().access_token.as_ref().unwrap().tokens[0]
        .value
        .clone();
    let child = derivation::issue(&app.resource_client, &parent, now()).unwrap();
    let before = app
        .storage
        .lookup(GrantSelector::AccessToken(parent.as_str()))
        .unwrap()
        .unwrap();
    let candidate = app
        .storage
        .lookup(GrantSelector::AccessToken(child.value.as_str()))
        .unwrap()
        .unwrap()
        .aggregate;
    let retained = app.storage.lock().unwrap().continuation_deadlines.clone();
    assert!(matches!(
        app.storage
            .create_derived(before.id, Revision(u64::MAX), &parent, candidate, &now),
        Err(StoreError::Conflict)
    ));
    let after = app
        .storage
        .lookup(GrantSelector::Id(before.id))
        .unwrap()
        .unwrap();
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.aggregate.tokens.len(), before.aggregate.tokens.len());
    assert!(before.aggregate.tokens.iter().all(|(handle, record)| {
        after.aggregate.tokens.get(handle).is_some_and(|retained| {
            retained.token == record.token
                && retained.issued_at == record.issued_at
                && retained.management_token == record.management_token
        })
    }));
    assert!(
        app.storage.lock().unwrap().continuation_deadlines == retained,
        "failed child insertion does not publish retention or change the parent"
    );
    assert!(child.expires_in.is_some_and(|ttl| (1..=60).contains(&ttl)));
    assert_eq!(
        child.access,
        Some(vec![AccessItem::Reference(
            derivation::METADATA_READ.into()
        )])
    );
    assert!(child.key.as_ref().unwrap().as_value() == Some(&app.rs_registration.key));
    assert_ne!(app.rs_registration.key, app.rs_registration.client_key);
    assert_ne!(app.rs_registration.key, app.rs_registration.metadata_key);
    assert_ne!(
        app.rs_registration.client_key,
        app.rs_registration.metadata_key
    );
    assert_eq!(
        http.send(signed(&app, derivation::RS2_PATH, &parent, &app.signer))
            .unwrap()
            .status,
        401,
        "parent is not an RS2 credential"
    );
    assert_eq!(
        network
            .send(signed(
                &app,
                "/resource/folder",
                &child.value,
                &app.resource_client.signer
            ))
            .unwrap()
            .status,
        401,
        "child is not an RS1 credential"
    );
    assert_eq!(
        http.send(signed(
            &app,
            derivation::RS2_PATH,
            &child.value,
            &app.signer
        ))
        .unwrap()
        .status,
        401,
        "client cannot use the RS1-bound child"
    );
    let read = signed(
        &app,
        derivation::RS2_PATH,
        &child.value,
        &app.resource_client.signer,
    );
    assert_eq!(http.send(read.clone()).unwrap().status, 200);
    assert_eq!(http.send(read).unwrap().status, 401, "RS2 rejects replay");
    let occupied = app
        .resource_admission
        .clone()
        .try_acquire_many_owned(2)
        .unwrap();
    assert_eq!(
        http.send(signed(
            &app,
            derivation::RS2_PATH,
            &child.value,
            &app.resource_client.signer
        ))
        .unwrap()
        .status,
        200,
        "RS2 and AS remain usable while every RS1 worker permit is held"
    );
    drop(occupied);

    let wrong = derivation_request(&app, &parent, &app.signer);
    assert_eq!(
        http.send(wrong).unwrap().status,
        400,
        "client cannot impersonate RS1"
    );
    for body in [
        json!({"client":introspection::RS_ID,"existing_access_token":parent,"access_token":{"access":[FOLDER_READ]}}),
        json!({"client":introspection::RS_ID,"access_token":{"access":[FOLDER_READ]}}),
    ] {
        assert_eq!(
            http.send(signed_grant(&app, body, &app.resource_client.signer))
                .unwrap()
                .status,
            400,
            "neither parent-right reuse nor an ordinary RS1 grant is allowed"
        );
    }
    let wrong_rs = signed_grant(
        &app,
        json!({"client":introspection::RS2_ID,"existing_access_token":parent,"access_token":{"access":[derivation::METADATA_READ]}}),
        &app.metadata_client.signer,
    );
    assert_eq!(
        http.send(wrong_rs).unwrap().status,
        400,
        "parent is appropriate only at RS1"
    );
    assert!(
        derivation::issue(&app.resource_client, &child.value, now()).is_err(),
        "a second derivation hop is forbidden"
    );
    let mut tampered = derivation_request(&app, &parent, &app.resource_client.signer);
    tampered.body.as_mut().unwrap().push(b' ');
    assert_eq!(
        http.send(tampered).unwrap().status,
        400,
        "signed body must match"
    );
    let request = derivation_request(&app, &parent, &app.resource_client.signer);
    assert_eq!(http.send(request.clone()).unwrap().status, 200);
    assert_eq!(
        http.send(request).unwrap().status,
        400,
        "derivation nonce is single-use"
    );
    let manage = child.manage.as_ref().unwrap();
    let rotate = sign_request(
        HttpRequest::new("POST", &manage.uri),
        app.resource_client.signer.as_ref(),
        Some(&manage.access_token.value),
        now(),
    )
    .unwrap();
    assert_eq!(
        http.send(rotate).unwrap().status,
        400,
        "child rotation is refused"
    );
    assert_eq!(
        http.send(signed(
            &app,
            derivation::RS2_PATH,
            &child.value,
            &app.resource_client.signer
        ))
        .unwrap()
        .status,
        200,
        "refused rotation leaves child unchanged"
    );
    let rotated = session.rotate_token(None, now()).unwrap();
    assert_eq!(
        http.send(signed(
            &app,
            derivation::RS2_PATH,
            &child.value,
            &app.resource_client.signer
        ))
        .unwrap()
        .status,
        401,
        "retiring exact parent cascades"
    );

    // The browser-facing response contains only the fixed metadata profile.
    // Repeated completed reads DELETE their children, not exhaust an 8-child cap.
    for _ in 0..10 {
        let result = network
            .send(signed(
                &app,
                derivation::RS1_PATH,
                &rotated.value,
                &app.signer,
            ))
            .unwrap();
        assert_eq!(result.status, 200);
        let body: Value = serde_json::from_slice(&result.body).unwrap();
        assert_eq!(
            body["metadata"],
            json!({"source":"synthetic-archive","document_count":1})
        );
        assert_eq!(body["derived_right"], derivation::METADATA_READ);
        assert!(!String::from_utf8_lossy(&result.body).contains(rotated.value.as_str()));
        assert!(body.get("access_token").is_none());
    }
    let source = app
        .storage
        .lookup(GrantSelector::AccessToken(rotated.value.as_str()))
        .unwrap()
        .unwrap();
    let mut aged = source.aggregate;
    aged.tokens.values_mut().next().unwrap().issued_at = now() - 1190;
    app.storage
        .compare_exchange(source.id, source.revision, aged)
        .unwrap();
    let short = derivation::issue(&app.resource_client, &rotated.value, now()).unwrap();
    assert!(
        short.expires_in.is_some_and(|ttl| (1..=10).contains(&ttl)),
        "child never exceeds remaining parent lifetime"
    );
    session.revoke_token(None, now()).unwrap();
    assert_eq!(
        http.send(signed(
            &app,
            derivation::RS2_PATH,
            &short.value,
            &app.resource_client.signer
        ))
        .unwrap()
        .status,
        401,
        "parent DELETE cascades too"
    );
    assert!(derivation::issue(&app.resource_client, &rotated.value, now()).is_err());
    app.storage.cleanup().unwrap();
}

struct Reply(HttpResponse);
impl HttpTransport for Reply {
    type Error = &'static str;
    fn send(&self, _: HttpRequest) -> Result<HttpResponse, Self::Error> {
        Ok(self.0.clone())
    }
}

struct FailedDownstream {
    app: App,
    transport_failure: bool,
    lost_cleanup: bool,
    deletes: std::sync::atomic::AtomicUsize,
}
impl HttpTransport for FailedDownstream {
    type Error = &'static str;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        if request.url.ends_with(derivation::RS2_PATH) {
            return if self.transport_failure {
                Err("synthetic downstream outage")
            } else {
                Ok(HttpResponse {
                    status: 401,
                    headers: vec![],
                    body: vec![],
                })
            };
        }
        if request.url.ends_with("/gnap")
            || derivation::management_destination(&self.app.origin, &request.url)
        {
            let rs = &self.app.rs_registration;
            let response = self.app.server.handle_grant_with_derivation(
                &request,
                &derivation::Requesters(rs),
                rs.as_ref(),
                &rs.derivation_nonces,
                &now,
            );
            if request.method == "DELETE" {
                self.deletes
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                assert_eq!(response.status, 204);
                if self.lost_cleanup {
                    return Err("synthetic lost cleanup reply");
                }
            }
            return Ok(response);
        }
        Ok(introspection::handle(&self.app, &request, now()))
    }
}

#[test]
fn downstream_read_uses_the_injected_clock_at_parent_expiration() {
    let mut app = tests::test_app();
    let parent = tests::test_record("synthetic-parent");
    let time = parent.issued_at;
    let expires = time + parent.token.expires_in.unwrap();
    app.storage
        .create(tests::test_aggregate("handle", parent))
        .unwrap();
    let transport = Arc::new(FailedDownstream {
        app: app.clone(),
        transport_failure: false,
        lost_cleanup: false,
        deletes: Default::default(),
    });
    app.resource_client = Arc::new(introspection::ResourceClient {
        origin: app.origin.clone(),
        signer: app.resource_client.signer.clone(),
        nonces: MemoryStorage::default(),
        transport: transport.clone(),
    });
    let request = signed(
        &app,
        derivation::RS1_PATH,
        &TokenValue::new("synthetic-parent").unwrap(),
        &app.signer,
    );
    let calls = std::cell::Cell::new(0);
    let result = read_resource_with_clock(&app, &request, || {
        let call = calls.get();
        calls.set(call + 1);
        if call < 2 {
            time
        } else {
            expires
        }
    });
    assert!(matches!(result, Err(ResourceError::Denied)));
    assert_eq!(
        calls.get(),
        3,
        "expiry is checked again after proof verification"
    );
    assert_eq!(
        transport.deletes.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no child is issued when the parent expires during authorization"
    );
    assert_eq!(app.storage.lock().unwrap().continuation_deadlines.len(), 1);
}

#[test]
fn failed_downstream_still_deletes_once_and_lost_cleanup_is_not_success() {
    let app = tests::test_app();
    app.storage
        .create(tests::test_aggregate(
            "handle",
            tests::test_record("synthetic-parent"),
        ))
        .unwrap();
    for (transport_failure, lost_cleanup) in [(false, false), (true, false), (false, true)] {
        let transport = Arc::new(FailedDownstream {
            app: app.clone(),
            transport_failure,
            lost_cleanup,
            deletes: Default::default(),
        });
        let client = introspection::ResourceClient {
            origin: app.origin.clone(),
            signer: app.resource_client.signer.clone(),
            nonces: MemoryStorage::default(),
            transport: transport.clone(),
        };
        let request = signed(
            &app,
            derivation::RS1_PATH,
            &TokenValue::new("synthetic-parent").unwrap(),
            &app.signer,
        );
        let result = derivation::read(&client, &request, now);
        if transport_failure || lost_cleanup {
            assert!(matches!(result, Err(ResourceError::Unavailable)));
        } else {
            assert!(matches!(result, Err(ResourceError::Denied)));
        }
        assert_eq!(
            transport.deletes.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        app.storage.cleanup().unwrap();
        assert_eq!(
            app.storage.lock().unwrap().continuation_deadlines.len(),
            1,
            "only parent retained; no blind retry or leaked child"
        );
    }
}

#[test]
fn derived_reply_must_match_the_local_profile_without_reflecting_errors() {
    let app = tests::test_app();
    let valid = json!({"access_token":{"value":"synthetic-child","access":[derivation::METADATA_READ],"expires_in":60,"manage":{"uri":"https://demo.example/token/handle","access_token":{"value":"synthetic-management"}}}});
    let mut variants = vec![valid.clone()];
    for (field, value) in [
        ("expires_in", json!(61)),
        ("access", json!([FOLDER_READ])),
        ("flags", json!(["bearer"])),
        ("secret-extension", json!("synthetic-secret")),
    ] {
        let mut bad = valid.clone();
        bad["access_token"][field] = value;
        variants.push(bad);
    }
    let mut bad_manage = valid.clone();
    bad_manage["access_token"]["manage"]["uri"] = json!("https://other.example/token/handle");
    variants.push(bad_manage);
    let mut bad_key = valid.clone();
    bad_key["access_token"]["key"] = serde_json::to_value(&app.rs_registration.client_key).unwrap();
    variants.push(bad_key);
    for (index, body) in variants.into_iter().enumerate() {
        let client = introspection::ResourceClient {
            origin: app.origin.clone(),
            signer: app.resource_client.signer.clone(),
            nonces: MemoryStorage::default(),
            transport: Arc::new(Reply(HttpResponse {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body: serde_json::to_vec(&body).unwrap(),
            })),
        };
        assert_eq!(
            derivation::issue(
                &client,
                &TokenValue::new("synthetic-parent").unwrap(),
                now()
            )
            .is_ok(),
            index == 0
        );
    }
    let client = introspection::ResourceClient {
        origin: app.origin.clone(),
        signer: app.resource_client.signer.clone(),
        nonces: MemoryStorage::default(),
        transport: Arc::new(Reply(HttpResponse {
            status: 400,
            headers: vec![("content-type".into(), "text/plain".into())],
            body: b"synthetic-secret".to_vec(),
        })),
    };
    assert!(matches!(
        derivation::issue(
            &client,
            &TokenValue::new("synthetic-parent").unwrap(),
            now()
        ),
        Err(ResourceError::Unavailable)
    ));
}

#[test]
fn child_cleanup_requires_an_empty_204_and_never_accepts_an_arbitrary_destination() {
    let app = tests::test_app();
    let child: AccessToken = serde_json::from_value(json!({"value":"synthetic-child","access":[derivation::METADATA_READ],"expires_in":60,"manage":{"uri":"https://demo.example/token/handle","access_token":{"value":"synthetic-management"}}})).unwrap();
    for (status, body, accepted) in [
        (204, "", true),
        (204, "synthetic-secret", false),
        (200, "", false),
        (503, "", false),
    ] {
        let client = introspection::ResourceClient {
            origin: app.origin.clone(),
            signer: app.resource_client.signer.clone(),
            nonces: MemoryStorage::default(),
            transport: Arc::new(Reply(HttpResponse {
                status,
                body: body.as_bytes().to_vec(),
                headers: vec![],
            })),
        };
        assert_eq!(derivation::revoke(&client, &child, now()).is_ok(), accepted);
    }
    for destination in [
        "https://other.example/token/handle",
        "https://demo.example/token/a/b",
        "https://demo.example/token/handle?next=secret",
        "https://demo.example/token/%2f",
        "https://demo.example/token/",
    ] {
        assert!(!derivation::management_destination(
            &app.origin,
            destination
        ));
    }
}
