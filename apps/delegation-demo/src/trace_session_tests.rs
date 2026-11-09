//! The exchange record of real sessions: what it keeps, what it never shows,
//! and that two browsers never see each other's exchanges.
use super::*;
use tower::ServiceExt;

/// Starts a session through the front door, as a browser would, and returns
/// the identity its cookie carries.
async fn start(router: &Router, origin: &str) -> String {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/start")
                .header("host", origin.strip_prefix("http://").unwrap())
                .header("origin", origin)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()["set-cookie"].to_str().unwrap();
    cookie
        .split(';')
        .next()
        .and_then(|pair| pair.strip_prefix("gnap_demo="))
        .unwrap()
        .to_owned()
}

/// The routes of a session's recorded attempts, in order.
fn routes(view: &Value) -> Vec<String> {
    view["trace"]["attempts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|attempt| attempt["request"]["route"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_sessions_record_their_own_exchanges_and_no_secret() {
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
    let served = router.clone();
    tokio::spawn(async move { axum::serve(listener, served).await.unwrap() });

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
