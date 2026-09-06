use super::*;
use axum::body::{to_bytes, Body};
use tower::ServiceExt;

fn code_request() -> GrantRequest {
    serde_json::from_value(json!({"client":"test-client", "access_token":{"access":[FOLDER_READ]}, "interact":{"start":["user_code_uri"]}})).unwrap()
}

struct Direct<'a>(&'a As, u64);
impl HttpTransport for Direct<'_> {
    type Error = String;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        Ok(self.0.handle(&request, self.1))
    }
}

fn pending(app: &App) -> (Pending, gnap_client::Step) {
    let transport = Direct(&app.server, now());
    let mut client = Session::new(
        &transport,
        app.signer.as_ref(),
        format!("{}/gnap", app.origin),
    )
    .supporting(&["user_code_uri"]);
    let step = client.start(&code_request(), now()).unwrap();
    let code = &step
        .response()
        .interact
        .as_ref()
        .unwrap()
        .user_code_uri
        .as_ref()
        .unwrap()
        .code;
    let handle = app.server.resolve_user_code(code, now()).unwrap();
    let snapshot = app
        .storage
        .lookup(GrantSelector::Interaction(&handle))
        .unwrap()
        .unwrap();
    (
        Pending {
            id: snapshot.id,
            handle,
            request: snapshot.aggregate.record.request,
            as_nonce: snapshot.aggregate.record.as_nonce,
        },
        step,
    )
}

#[test]
fn owner_admission_bounds_attempts_and_does_not_extend_sessions() {
    let mut entries = Entries::default();
    let at = Instant::now();
    entries.owners.insert(
        "owner".into(),
        Owner {
            born: at,
            attempts: 4,
            ticket: "ticket".into(),
            pending: None,
        },
    );
    for _ in 0..GLOBAL_ATTEMPTS {
        assert!(entries.admit(at));
    }
    assert!(!entries.admit(at + Duration::from_secs(59)));
    assert!(entries.admit(at + Duration::from_secs(60)));
    entries.cleanup(at + Duration::from_secs(599));
    assert_eq!(entries.owners["owner"].attempts, 4);
    entries.cleanup(at + Duration::from_secs(600));
    assert!(entries.owners.is_empty());
    let mut headers = HeaderMap::new();
    headers.insert(
        "cookie",
        "gnap_demo=abcdefghijklmnopqrstuv".parse().unwrap(),
    );
    assert_eq!(owner_cookie(&headers), None);
    headers.append(
        "cookie",
        "gnap_owner=abcdefghijklmnopqrstuv; gnap_owner=zyxwvutsrqponmlkjihgfe"
            .parse()
            .unwrap(),
    );
    assert_eq!(owner_cookie(&headers), None);
}

#[test]
fn changed_requests_and_expired_codes_cannot_consume_consent() {
    let app = crate::tests::test_app();
    let (mut old, _) = pending(&app);
    old.request.access_token = None;
    assert!(complete(&app, old, multiple::Choice::All).is_err());
    assert!(app.decisions.lock().unwrap().grants.is_empty());
    let (old, _) = pending(&app);
    let snapshot = app
        .storage
        .lookup(GrantSelector::Id(old.id))
        .unwrap()
        .unwrap();
    let mut changed = snapshot.aggregate;
    changed.record.interact_expires_at = Some(now());
    app.storage
        .compare_exchange(snapshot.id, snapshot.revision, changed)
        .unwrap();
    assert!(complete(&app, old, multiple::Choice::All).is_err());
    assert!(app.decisions.lock().unwrap().grants.is_empty());
    let (old, _) = pending(&app);
    let snapshot = app
        .storage
        .lookup(GrantSelector::Id(old.id))
        .unwrap()
        .unwrap();
    let mut changed = snapshot.aggregate;
    changed.record.as_nonce = Some("renewed-window".into());
    app.storage
        .compare_exchange(snapshot.id, snapshot.revision, changed)
        .unwrap();
    assert!(complete(&app, old, multiple::Choice::All).is_err());
}

#[test]
fn completed_poll_waits_for_its_choice_instead_of_observing_a_missing_decision() {
    let mut app = crate::tests::test_app();
    let (pending, step) = pending(&app);
    let continuation = step.response().r#continue.as_ref().unwrap();
    let request = sign_request(
        HttpRequest::new("POST", &continuation.uri),
        app.signer.as_ref(),
        Some(&continuation.access_token.value),
        now() + 5,
    )
    .unwrap();
    let (entered, entry) = mpsc::channel();
    let (proceed, resume) = mpsc::channel();
    let resume = Mutex::new(resume);
    app.code_completion_hook = Some(Arc::new(move || {
        entered.send(()).unwrap();
        resume
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
    }));
    let (completed, completion) = mpsc::channel();
    let owner_app = app.clone();
    let owner = std::thread::spawn(move || {
        completed
            .send(complete(&owner_app, pending, multiple::Choice::All))
            .unwrap();
    });
    entry.recv_timeout(Duration::from_secs(5)).unwrap(); // Committed, still holding choices.
    let (polled, poll) = mpsc::channel();
    let server = app.server.clone();
    let client = std::thread::spawn(move || {
        polled.send(server.handle(&request, now() + 5)).unwrap();
    });
    assert!(poll.recv_timeout(Duration::from_millis(100)).is_err());
    proceed.send(()).unwrap();
    assert!(completion
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .is_ok());
    let response = poll.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(response.status, 200);
    let response: Value = serde_json::from_slice(&response.body).unwrap();
    assert!(response.get("access_token").is_some(), "{response}");
    owner.join().unwrap();
    client.join().unwrap();
}

#[test]
fn competing_poll_and_completion_publish_only_the_winning_snapshot() {
    use std::sync::atomic::{AtomicBool, Ordering};
    for completion_loses in [true, false] {
        let app = crate::tests::test_app();
        let (pending, step) = pending(&app);
        let retry_pending = Pending {
            id: pending.id,
            handle: pending.handle.clone(),
            request: pending.request.clone(),
            as_nonce: pending.as_nonce.clone(),
        };
        let continuation = step.response().r#continue.clone().unwrap();
        let code = step
            .response()
            .interact
            .as_ref()
            .unwrap()
            .user_code_uri
            .as_ref()
            .unwrap()
            .code
            .clone();
        let poll_request = || {
            sign_request(
                HttpRequest::new("POST", &continuation.uri),
                app.signer.as_ref(),
                Some(&continuation.access_token.value),
                now() + 5,
            )
            .unwrap()
        };
        let (entered, entry) = mpsc::channel();
        let (resume_poll, poll_wait) = mpsc::channel();
        let (resume_owner, owner_wait) = mpsc::channel();
        let waits = [Mutex::new(poll_wait), Mutex::new(owner_wait)];
        let once = [AtomicBool::new(false), AtomicBool::new(false)];
        *app.storage.before_exchange.lock().unwrap() = Some(Arc::new(move |replacement| {
            let index = usize::from(replacement.record.interaction_completed);
            if !once[index].swap(true, Ordering::SeqCst) {
                entered.send(index).unwrap();
                waits[index]
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            }
        }));
        // Authenticate and prepare the poll before completion locks choices.
        // Both operations now hold snapshots of the same revision.
        let request = poll_request();
        let server = app.server.clone();
        let (polled, poll_result) = mpsc::channel();
        let poll = std::thread::spawn(move || {
            polled.send(server.handle(&request, now() + 5)).unwrap();
        });
        assert_eq!(entry.recv_timeout(Duration::from_secs(5)).unwrap(), 0);
        let owner_app = app.clone();
        let (completed, owner_result) = mpsc::channel();
        let owner = std::thread::spawn(move || {
            completed
                .send(complete(
                    &owner_app,
                    pending,
                    if completion_loses {
                        multiple::Choice::All
                    } else {
                        multiple::Choice::Denied
                    },
                ))
                .unwrap();
        });
        assert_eq!(entry.recv_timeout(Duration::from_secs(5)).unwrap(), 1);
        if completion_loses {
            resume_poll.send(()).unwrap();
            assert_eq!(
                poll_result
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap()
                    .status,
                200
            );
            resume_owner.send(()).unwrap();
            assert!(owner_result
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .is_err());
            assert!(app.decisions.lock().unwrap().grants.is_empty());
            assert!(app.server.resolve_user_code(&code, now()).is_ok());
            // Explicit retry uses the same displayed request, not a new grant.
            assert!(complete(&app, retry_pending, multiple::Choice::All).is_ok());
        } else {
            resume_owner.send(()).unwrap();
            assert!(owner_result
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .is_ok());
            resume_poll.send(()).unwrap();
            assert_eq!(
                poll_result
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap()
                    .status,
                503
            );
            assert!(app.server.resolve_user_code(&code, now()).is_err());
            // The refused CAS did not rotate the credential. A fresh proof
            // using it obtains the owner's denial, not an accidental approval.
            let response = app.server.handle(&poll_request(), now() + 5);
            let response: Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(response["error"]["code"], "user_denied");
        }
        owner.join().unwrap();
        poll.join().unwrap();
    }
}

#[tokio::test]
async fn malformed_unknown_expired_codes_and_origin_body_limits_are_checked() {
    let app = crate::tests::test_app();
    let (pending, step) = pending(&app);
    let code = step
        .response()
        .interact
        .as_ref()
        .unwrap()
        .user_code_uri
        .as_ref()
        .unwrap()
        .code
        .clone();
    let snapshot = app
        .storage
        .lookup(GrantSelector::Id(pending.id))
        .unwrap()
        .unwrap();
    let mut expired = snapshot.aggregate;
    expired.record.interact_expires_at = Some(now());
    app.storage
        .compare_exchange(snapshot.id, snapshot.revision, expired)
        .unwrap();
    let router = application_router(app.clone(), CanonicalOrigin::parse(&app.origin).unwrap());
    let (_, headers, page) = router_call(&router, "GET", "/code", "", Value::Null).await;
    let cookie = headers["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let mut csrf = ticket(&page).to_owned();
    for code in ["bad".to_owned(), "ZZZZZZZZ".to_owned(), code] {
        let (status, headers, body) = router_call(
            &router,
            "POST",
            "/code/lookup",
            cookie,
            json!({"ticket":csrf,"code":code}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(headers.get("location").is_none());
        let result: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(result["error"], INVALID);
        assert!(!body.contains(&code));
        csrf = result["ticket"].as_str().unwrap().to_owned();
    }
    assert_eq!(app.code_entries.lock().unwrap().attempts.len(), 3);
    for _ in 0..65 {
        assert_eq!(
            router_call(&router, "POST", "/code/lookup", "", json!({}))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(app.code_entries.lock().unwrap().attempts.len(), 3);
    for (origin, body, expected) in [
        ("https://evil.example", vec![], StatusCode::FORBIDDEN),
        (
            "https://demo.example",
            vec![b' '; 1025],
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/code/lookup")
                    .header("host", "demo.example")
                    .header("origin", origin)
                    .header("cookie", cookie)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    assert_eq!(app.code_entries.lock().unwrap().attempts.len(), 3);
}

async fn router_call(
    router: &Router,
    method: &str,
    path: &str,
    cookie: &str,
    ticket: Value,
) -> (StatusCode, HeaderMap, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("host", "demo.example")
                .header("origin", "https://demo.example")
                .header("cookie", cookie)
                .header("content-type", "application/json")
                .body(Body::from(if method == "POST" {
                    serde_json::to_vec(&ticket).unwrap()
                } else {
                    Vec::new()
                }))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = String::from_utf8(
        to_bytes(response.into_body(), 16384)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    (status, headers, body)
}
fn ticket(page: &str) -> &str {
    page.split("data-ticket=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
}

#[tokio::test]
async fn entry_rejects_client_cookies_csrf_replays_and_excess_attempts() {
    let app = crate::tests::test_app();
    let (_, step) = pending(&app);
    let code = &step
        .response()
        .interact
        .as_ref()
        .unwrap()
        .user_code_uri
        .as_ref()
        .unwrap()
        .code;
    let router = application_router(app.clone(), CanonicalOrigin::parse(&app.origin).unwrap());
    assert_eq!(
        router_call(
            &router,
            "POST",
            "/code/lookup",
            "gnap_demo=abcdefghijklmnopqrstuv",
            json!({"ticket":"fake","code":code})
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, headers, page) = router_call(&router, "GET", "/code", "", Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers["referrer-policy"], "no-referrer");
    let set_cookie = headers["set-cookie"].to_str().unwrap();
    assert!(set_cookie.contains("HttpOnly; SameSite=Strict"));
    assert!(set_cookie.contains("Secure"));
    let cookie = set_cookie.split(';').next().unwrap();
    assert!(!page.contains(code));
    assert_eq!(
        router_call(&router, "GET", "/code?code=secret", cookie, Value::Null)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let (_, _, reply) = router_call(
        &router,
        "POST",
        "/code/lookup",
        cookie,
        json!({"ticket":ticket(&page),"code":code.to_lowercase()}),
    )
    .await;
    let reply: Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(reply["rights"][0]["rights"], json!([FOLDER_READ]));
    assert!(reply.get("handle").is_none());
    assert_eq!(
        router_call(
            &router,
            "POST",
            "/code/consent",
            cookie,
            json!({"ticket":ticket(&page),"choice":"allow"})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        router_call(
            &router,
            "POST",
            "/code/consent",
            cookie,
            json!({"ticket":reply["ticket"],"choice":"deny"})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(app.server.resolve_user_code(code, now()).is_err());
    // A consumed ticket cannot replay a decision; refusals count too.
    for expected in [
        StatusCode::FORBIDDEN,
        StatusCode::FORBIDDEN,
        StatusCode::TOO_MANY_REQUESTS,
    ] {
        assert_eq!(
            router_call(
                &router,
                "POST",
                "/code/consent",
                cookie,
                json!({"ticket":reply["ticket"],"choice":"allow"})
            )
            .await
            .0,
            expected
        );
    }
    let (_, _, reloaded) = router_call(&router, "GET", "/code", cookie, Value::Null).await;
    assert!(reloaded.contains("0 of five attempts"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_independent_http_sessions_decide_then_poll_and_read_the_resource() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let mut app = crate::tests::test_app_at(&origin);
    app.resource_client = Arc::new(introspection::ResourceClient {
        origin: origin.clone(),
        signer: app.resource_client.signer.clone(),
        transport: Arc::new(introspection::Http {
            origin: origin.clone(),
        }),
        nonces: MemoryStorage::default(),
    });
    let (sender, receiver) = mpsc::sync_channel(8);
    app.commands = sender;
    let (worker_origin, signer, server, storage, decisions) = (
        app.origin.clone(),
        app.signer.clone(),
        app.server.clone(),
        app.storage.clone(),
        app.decisions.clone(),
    );
    let references = app.bootstrap.get().unwrap().as_ref().unwrap().clone();
    let worker = std::thread::spawn(move || {
        client_worker(
            worker_origin,
            signer,
            server,
            storage,
            decisions,
            receiver,
            references,
        )
    });
    let router = application_router(app.clone(), CanonicalOrigin::parse(&origin).unwrap());
    let serving = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let owner = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    for allow in [true, false] {
        let response = client
            .post(format!("{origin}/api/start-code"))
            .header("origin", &origin)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let client_cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let started: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
        assert_eq!(started["state"], "pending");
        assert!(started["interaction_uri"].is_null());
        assert_eq!(started["user_code_uri"]["uri"], format!("{origin}/code"));
        let response = client
            .post(format!("{origin}/api/approve"))
            .header("origin", &origin)
            .header("cookie", &client_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = owner.get(format!("{origin}/code")).send().await.unwrap();
        let owner_cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        assert_ne!(owner_cookie, client_cookie);
        let page = response.text().await.unwrap();
        let response = owner
            .post(format!("{origin}/code/lookup"))
            .header("origin", &origin)
            .header("cookie", &owner_cookie)
            .header("content-type", "application/json")
            .body(
                json!({"ticket":ticket(&page),"code":started["user_code_uri"]["code"]}).to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let looked: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
        assert_eq!(
            looked["rights"][0]["rights"],
            json!([ARCHIVE_READ, FOLDER_READ])
        );
        // A real polling round trip changes the revision while the owner reads.
        tokio::time::sleep(Duration::from_secs(
            started["continuation_wait_seconds"].as_u64().unwrap(),
        ))
        .await;
        let response = client
            .post(format!("{origin}/api/continue"))
            .header("origin", &origin)
            .header("cookie", &client_cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let polled: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
        assert_eq!(polled["state"], "pending");
        assert_eq!(polled["token_present"], false);
        let response = owner
            .post(format!("{origin}/code/consent"))
            .header("origin", &origin)
            .header("cookie", &owner_cookie)
            .header("content-type", "application/json")
            .body(
                json!({"ticket":looked["ticket"],"choice":if allow {"allow"} else {"deny"}})
                    .to_string(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get("location").is_none());
        tokio::time::sleep(Duration::from_secs(
            polled["continuation_wait_seconds"].as_u64().unwrap(),
        ))
        .await;
        let response = client
            .post(format!("{origin}/api/continue"))
            .header("origin", &origin)
            .header("cookie", &client_cookie)
            .send()
            .await
            .unwrap();
        let result: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
        assert_eq!(
            result["state"],
            if allow { "approved" } else { "denied" },
            "{result}"
        );
        if allow {
            let response = client
                .post(format!("{origin}/api/read"))
                .header("origin", &origin)
                .header("cookie", &client_cookie)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let result: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
            assert_eq!(result["last_resource_status"], 200);
        } else {
            assert_eq!(result["token_present"], false);
        }
    }
    serving.abort();
    let _ = serving.await;
    drop(app);
    tokio::task::spawn_blocking(move || worker.join().unwrap())
        .await
        .unwrap();
}
