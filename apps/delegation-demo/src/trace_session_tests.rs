//! The exchange record of real sessions: what it keeps, what it never shows,
//! and that two browsers never see each other's exchanges.
use super::*;
use tower::ServiceExt;

/// Starts a session through the front door, as a browser would, and returns
/// the identity its cookie carries.
pub(super) async fn start(router: &Router, origin: &str) -> String {
    start_with(router, origin, "start").await
}

pub(super) async fn start_with(router: &Router, origin: &str, action: &str) -> String {
    start_proving(router, origin, action, "").await
}

/// Starts a session with `body`, which may choose the proof method.
pub(super) async fn start_proving(
    router: &Router,
    origin: &str,
    action: &str,
    body: &str,
) -> String {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/{action}"))
                .header("host", origin.strip_prefix("http://").unwrap())
                .header("origin", origin)
                .body(axum::body::Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    if response.status() != StatusCode::OK {
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        panic!(
            "{action} answered {status}: {}",
            String::from_utf8_lossy(&body)
        );
    }
    let cookie = response.headers()["set-cookie"].to_str().unwrap();
    cookie
        .split(';')
        .next()
        .and_then(|pair| pair.strip_prefix("gnap_demo="))
        .unwrap()
        .to_owned()
}

/// The routes of a session's recorded attempts, in order.
pub(super) fn routes(view: &Value) -> Vec<String> {
    view["trace"]["attempts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|attempt| attempt["request"]["route"].as_str().unwrap().to_owned())
        .collect()
}

/// A lab served on a loopback port, with its worker, whose sessions last
/// `lifetime`.
pub(super) async fn lab(lifetime: Duration) -> (App, Router, String) {
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
        jose_replay: introspection::jose_replay(),
    });
    let (sender, receiver) = mpsc::sync_channel(8);
    app.commands = sender;
    let (worker_origin, signer, server, storage, decisions) = (
        origin.clone(),
        app.signer.clone(),
        app.server.clone(),
        app.storage.clone(),
        app.decisions.clone(),
    );
    let references = app.bootstrap.get().unwrap().as_ref().unwrap().clone();
    std::thread::spawn(move || {
        client_worker(
            Worker {
                origin: worker_origin,
                signer,
                server,
                storage,
                decisions,
                references,
                lifetime,
            },
            receiver,
        )
    });
    let router = application_router(app.clone(), CanonicalOrigin::parse(&origin).unwrap());
    let served = router.clone();
    tokio::spawn(async move { axum::serve(listener, served).await.unwrap() });
    (app, router, origin)
}

/// The status a browser reads, with the cookie it holds, if any.
pub(super) async fn status(router: &Router, origin: &str, cookie: Option<&str>) -> Value {
    let mut request = Request::builder()
        .uri("/api/status")
        .header("host", origin.strip_prefix("http://").unwrap());
    if let Some(cookie) = cookie {
        request = request.header("cookie", format!("gnap_demo={cookie}"));
    }
    let response = router
        .clone()
        .oneshot(request.body(axum::body::Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_sessions_record_their_own_exchanges_and_no_secret() {
    let (app, router, origin) = lab(SESSION_LIFETIME).await;

    // Two browsers, their steps interleaved.
    let (a, b) = (start(&router, &origin).await, start(&router, &origin).await);
    let mut handles = Vec::new();
    for id in [&a, &b] {
        let view = dispatch(&app, id.clone(), "status".into()).await.unwrap();
        handles.push(
            view["interaction_uri"]
                .as_str()
                .unwrap()
                .rsplit('/')
                .next()
                .unwrap()
                .to_owned(),
        );
        let finish = dispatch(&app, id.clone(), "approve".into()).await.unwrap();
        dispatch(
            &app,
            id.clone(),
            format!("callback:{}", finish["redirect"].as_str().unwrap()),
        )
        .await
        .unwrap();
    }
    let wait = dispatch(&app, a.clone(), "status".into()).await.unwrap()
        ["continuation_wait_seconds"]
        .as_u64()
        .unwrap();
    tokio::time::sleep(Duration::from_secs(wait)).await;
    dispatch(&app, a.clone(), "continue".into()).await.unwrap();
    dispatch(&app, b.clone(), "continue".into()).await.unwrap();
    dispatch(&app, a.clone(), "read".into()).await.unwrap();
    dispatch(&app, a.clone(), "rotate".into()).await.unwrap();
    dispatch(&app, b.clone(), "read-archive".into())
        .await
        .unwrap();

    let view_a = dispatch(&app, a.clone(), "status".into()).await.unwrap();
    let view_b = dispatch(&app, b.clone(), "status".into()).await.unwrap();
    assert_eq!(
        routes(&view_a),
        ["grant", "continue", "folder", "token_management"]
    );
    assert_eq!(routes(&view_b), ["grant", "continue", "archive"]);
    assert_eq!(view_a["trace"]["dropped"], 0);

    // Every secret the exchanges carried: tokens and their management
    // credentials, continuation tokens, nonces, interaction handles and
    // references.
    let mut secrets = handles;
    let ids: Vec<_> = app
        .storage
        .lock()
        .unwrap()
        .continuation_deadlines
        .keys()
        .copied()
        .collect();
    for id in ids {
        let snapshot = app.storage.lookup(GrantSelector::Id(id)).unwrap().unwrap();
        let record = &snapshot.aggregate.record;
        secrets.extend(record.continuation_token.clone());
        secrets.extend(record.as_nonce.clone());
        secrets.extend(record.interact_handle.clone());
        for (key, token) in &snapshot.aggregate.tokens {
            secrets.push(key.clone());
            secrets.push(token.token.value.as_str().to_owned());
            if let Some(manage) = &token.token.manage {
                secrets.push(manage.access_token.value.as_str().to_owned());
            }
        }
    }
    for consent in app.decisions.lock().unwrap().grants.values() {
        secrets.extend(consent.interaction_reference.clone());
    }
    assert!(secrets.len() >= 8, "the test found the secrets it checks");
    for view in [&view_a, &view_b] {
        let trace = view["trace"].to_string();
        for secret in &secrets {
            assert!(
                !trace.contains(secret.as_str()),
                "a secret reached the record"
            );
        }
    }
}

/// Over HTTP, each cookie reads its own session's record and nothing else; no
/// cookie, or an unknown one, reads none; and a session that expired while
/// the worker waited serves nothing, whatever the cookie.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_record_is_read_by_its_own_cookie_until_the_session_expires() {
    let lifetime = Duration::from_secs(3);
    let (_, router, origin) = lab(lifetime).await;
    // Two scenarios whose first requests differ: one token, then two labelled ones.
    let a = start(&router, &origin).await;
    let b = start_with(&router, &origin, "start-multiple").await;
    let labels = |view: &Value| {
        view["trace"]["attempts"][0]["request"]["body"]["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .map(|token| token["label"].clone())
            .collect::<Vec<_>>()
    };
    let view_a = status(&router, &origin, Some(&a)).await;
    let view_b = status(&router, &origin, Some(&b)).await;
    assert_eq!(routes(&view_a), ["grant"]);
    assert_eq!(routes(&view_b), ["grant"]);
    assert_eq!(labels(&view_a), [Value::Null]);
    assert_eq!(labels(&view_b), [json!("documents"), json!("reports")]);
    // A well-formed identity that names no session.
    let unknown = "unknownunknownunknown1";
    let mut headers = HeaderMap::new();
    headers.insert("cookie", format!("gnap_demo={unknown}").parse().unwrap());
    assert_eq!(
        session_cookie(&headers).as_deref(),
        Some(unknown),
        "the cookie is well formed"
    );
    for cookie in [None, Some(unknown)] {
        let view = status(&router, &origin, cookie).await;
        assert!(view.get("trace").is_none_or(Value::is_null), "{view}");
    }
    // The worker now waits for its next command; the sessions expire meanwhile.
    tokio::time::sleep(lifetime + Duration::from_secs(1)).await;
    for cookie in [&a, &b] {
        let view = status(&router, &origin, Some(cookie)).await;
        assert!(view.get("trace").is_none_or(Value::is_null), "{view}");
    }
}
