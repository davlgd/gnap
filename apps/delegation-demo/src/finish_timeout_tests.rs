//! Real HTTP grant responses, with an explicit clock at callback acceptance.
//! No five-minute sleep or simulated AS reply: only the callback clock advances.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browser_client_policy_refuses_late_finish_before_the_as_window_ends() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let app = tests::test_app_at(&origin);
    let router = application_router(app.clone(), CanonicalOrigin::parse(&origin).unwrap());
    let serving = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let outcome = tokio::task::spawn_blocking(move || scenario(app, origin)).await;
    serving.abort();
    let _ = serving.await;
    outcome.unwrap();
}

fn scenario(app: App, origin: String) {
    let network = Network {
        origin: origin.clone(),
        client: reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap(),
    };
    let references = app.bootstrap.get().unwrap().as_ref().unwrap();
    for offset in [FINISH_TIMEOUT.get() - 1, FINISH_TIMEOUT.get()] {
        // Use exactly the constructor used by the browser's command worker.
        let mut client = client_session(&network, app.signer.as_ref(), &origin);
        let request: GrantRequest = serde_json::from_value(json!({
            "client":"test-client", "access_token":{"access":[references.both]},
            "interact":{"start":["redirect"],"finish":{"method":"redirect","uri":format!("{origin}/callback"),"nonce":fresh_nonce().unwrap()}}
        })).unwrap();
        let started = now();
        let pending = client.start(&request, started).unwrap();
        let interaction = pending.response().interact.as_ref().unwrap();
        assert!(interaction.expires_in.unwrap() > FINISH_TIMEOUT.get());
        let handle = interaction
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
        // Consent is completed by the application's real policy/storage path;
        // this test does not drive the browser's /callback HTTP handler.
        let callback = consent_finish(
            &app.server,
            &app.storage,
            &app.decisions,
            "test-client",
            snapshot.id,
            handle,
            true,
        )
        .unwrap();
        let result = client.accept_redirect(&callback, started + offset);
        if offset < FINISH_TIMEOUT.get() {
            result.unwrap();
        } else {
            let error = result.unwrap_err();
            assert!(error.to_string().contains("client-configured"));
            assert!(client.continuation().is_some());
            assert!(client.continue_grant(started + offset).is_err());
            // A local refusal is not a remote grant deletion.
            assert!(app
                .storage
                .lookup(GrantSelector::Id(snapshot.id))
                .unwrap()
                .is_some());
        }
    }
}
