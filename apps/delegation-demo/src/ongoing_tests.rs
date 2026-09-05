//! Consumer regressions: real Session, AS policy, consent and protected reads.
use super::*;
use gnap_client::Step;

struct Direct<'a>(&'a As);
impl HttpTransport for Direct<'_> {
    type Error = String;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        Ok(self.0.handle(&request, now()))
    }
}
fn request(rights: &[&str]) -> GrantRequest {
    serde_json::from_value(json!({
        "client":"test-client", "access_token":{"access":rights},
        "interact":{"start":["redirect"],"finish":{"method":"redirect","uri":"https://demo.example/callback","nonce":fresh_nonce().unwrap()}}
    })).unwrap()
}
fn changes(rights: &[&str]) -> ContinueRequest {
    let request = request(rights);
    ContinueRequest {
        access_token: request.access_token,
        interact: request.interact,
        ..Default::default()
    }
}
fn wait(step: &Step) {
    // This consumer's maintenance uses real wall time. Honor the real SDK wait
    // instead of issuing future-dated tokens or replacing its clock behavior.
    std::thread::sleep(Duration::from_secs(
        step.response()
            .r#continue
            .as_ref()
            .and_then(|c| c.wait)
            .unwrap_or(0),
    ));
}
fn choice(app: &App, step: &Step, allowed: bool) -> String {
    let handle = step
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
    consent_finish(
        &app.server,
        &app.storage,
        &app.decisions,
        "test-client",
        snapshot.id,
        handle,
        allowed,
    )
    .unwrap()
}
fn value(step: &Step) -> TokenValue {
    step.response().access_token.as_ref().unwrap().tokens[0]
        .value
        .clone()
}
fn read(app: &App, token: &TokenValue, path: &str) -> Result<Value, ResourceError> {
    let request = sign_request(
        HttpRequest::new("GET", format!("{}{path}", app.origin)),
        app.signer.as_ref(),
        Some(token),
        now(),
    )
    .unwrap();
    read_resource(app, &request)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_http_starts_get_new_ids_and_worker_duplicate_preserves_existing_authority() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let mut app = tests::test_app_at(&origin);
    // Exercise the migrated RS through real HTTP discovery/introspection,
    // using the same registered RS key but no direct token-store lookup.
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
    let worker = std::thread::spawn(move || {
        client_worker(worker_origin, signer, server, storage, decisions, receiver)
    });
    let starts = Arc::new(AtomicUsize::new(0));
    let counted = starts.clone();
    let router = application_router(app.clone(), CanonicalOrigin::parse(&origin).unwrap()).layer(
        axum::middleware::from_fn(move |request: Request, next: Next| {
            if request.method() == Method::POST && request.uri().path() == "/gnap" {
                counted.fetch_add(1, Ordering::SeqCst);
            }
            async move { next.run(request).await }
        }),
    );
    let served = router.clone();
    let serving = tokio::spawn(async move {
        axum::serve(listener, served).await.unwrap();
    });

    // Exercise the actual front door with the same incoming cookie twice.
    // It intentionally creates fresh identities, never replaces this cookie's ID.
    let supplied = "abcdefghijklmnopqrstuv";
    let mut identities = Vec::new();
    for _ in 0..2 {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/start")
                    .header("host", origin.strip_prefix("http://").unwrap())
                    .header("origin", &origin)
                    .header("cookie", format!("gnap_demo={supplied}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let identity = cookie.strip_prefix("gnap_demo=").unwrap().to_owned();
        assert!(identity != supplied, "HTTP start must issue a new identity");
        identities.push(identity);
    }
    assert!(
        identities[0] != identities[1],
        "Repeated HTTP starts must not reuse the browser identity"
    );
    assert_eq!(starts.load(Ordering::SeqCst), 2);

    for id in &identities {
        let finish = dispatch(&app, id.clone(), "approve".into()).await.unwrap();
        dispatch(
            &app,
            id.clone(),
            format!("callback:{}", finish["redirect"].as_str().unwrap()),
        )
        .await
        .unwrap();
    }
    let pending = dispatch(&app, identities[0].clone(), "status".into())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(
        pending["continuation_wait_seconds"].as_u64().unwrap(),
    ))
    .await;
    let approved = dispatch(&app, identities[0].clone(), "continue".into())
        .await
        .unwrap();
    assert_eq!(approved["token_present"], true);
    let grant_ids: HashSet<_> = app
        .storage
        .lock()
        .unwrap()
        .continuation_deadlines
        .keys()
        .copied()
        .collect();
    let consent_before: HashMap<_, _> = app
        .decisions
        .lock()
        .unwrap()
        .grants
        .iter()
        .map(|(id, consent)| {
            (
                *id,
                (
                    consent.request.clone(),
                    consent.interaction_reference.clone(),
                    consent.allowed,
                ),
            )
        })
        .collect();
    assert_eq!(consent_before.len(), 2);
    let old = grant_ids
        .iter()
        .find_map(|id| {
            let snapshot = app.storage.lookup(GrantSelector::Id(*id)).unwrap().unwrap();
            (!snapshot.aggregate.tokens.is_empty()).then_some(snapshot)
        })
        .unwrap();
    let token = old
        .aggregate
        .tokens
        .values()
        .next()
        .unwrap()
        .token
        .value
        .clone();
    let reader = app.clone();
    let presented = token.clone();
    assert!(tokio::task::spawn_blocking(
        move || read(&reader, &presented, "/resource/folder").is_ok()
    )
    .await
    .unwrap());
    let other_before = dispatch(&app, identities[1].clone(), "status".into())
        .await
        .unwrap();

    // Directly exercise the worker's invalid internal duplicate-ID command.
    let duplicate = dispatch(&app, identities[0].clone(), "start".into()).await;
    assert!(
        duplicate.is_err(),
        "Duplicate worker start must be rejected, not replace the existing session"
    );
    assert_eq!(
        starts.load(Ordering::SeqCst),
        2,
        "Duplicate rejection must happen before another AS call"
    );
    assert!(
        app.storage
            .lock()
            .unwrap()
            .continuation_deadlines
            .keys()
            .copied()
            .collect::<HashSet<_>>()
            == grant_ids
    );
    {
        let choices = app.decisions.lock().unwrap();
        assert!(identities.iter().all(|id| choices.clients.contains(id)));
        assert_eq!(choices.grants.len(), consent_before.len());
        assert!(consent_before
            .iter()
            .all(|(id, before)| choices
                .grants
                .get(id)
                .is_some_and(|after| after.request == before.0
                    && after.interaction_reference == before.1
                    && after.allowed == before.2)));
    }
    let current = app
        .storage
        .lookup(GrantSelector::Id(old.id))
        .unwrap()
        .unwrap();
    assert_eq!(current.revision, old.revision);
    assert!(!current.aggregate.revoked);
    let reader = app.clone();
    let presented = token.clone();
    assert!(tokio::task::spawn_blocking(
        move || read(&reader, &presented, "/resource/folder").is_ok()
    )
    .await
    .unwrap());
    let retained = dispatch(&app, identities[0].clone(), "status".into())
        .await
        .unwrap();
    assert_eq!(retained["token_present"], true);
    assert!(retained["events"] == approved["events"]);
    let other_after = dispatch(&app, identities[1].clone(), "status".into())
        .await
        .unwrap();
    assert!(
        other_after["state"] == other_before["state"]
            && other_after["events"] == other_before["events"]
    );
    // The original Session is still usable for ordinary token revocation.
    dispatch(&app, identities[0].clone(), "revoke".into())
        .await
        .unwrap();
    let reader = app.clone();
    let presented = token.clone();
    assert!(tokio::task::spawn_blocking(
        move || read(&reader, &presented, "/resource/folder").is_err()
    )
    .await
    .unwrap());

    serving.abort();
    let _ = serving.await;
    drop(router);
    drop(app);
    worker.join().unwrap();
}

#[test]
fn ongoing_grant_polls_downscopes_reconsents_and_revokes_all_tokens() {
    let app = tests::test_app();
    let network = Direct(&app.server);
    let mut client = Session::new(&network, app.signer.as_ref(), "https://demo.example/gnap")
        .supporting(&["redirect"]);
    let pending = client
        .start(&request(&[FOLDER_READ, ARCHIVE_READ]), now())
        .unwrap();
    let finish = choice(&app, &pending, true);
    client
        .accept_callback(&InteractCallback::from_redirect(&finish).unwrap(), now())
        .unwrap();
    wait(&pending);
    let approved = client.continue_grant(now()).unwrap();
    assert!(approved.response().r#continue.is_some());
    let original = value(&approved);
    let before = app
        .storage
        .lookup(GrantSelector::AccessToken(original.as_str()))
        .unwrap()
        .unwrap();
    assert!(read(&app, &original, "/resource/folder").is_ok());
    assert!(read(&app, &original, "/resource/archive").is_ok());
    wait(&approved);
    let polled = client.continue_grant(now()).unwrap();
    assert!(polled.response().access_token.is_none());
    let current = app
        .storage
        .lookup(GrantSelector::Id(before.id))
        .unwrap()
        .unwrap();
    let old_record = before.aggregate.tokens.values().next().unwrap();
    let polled_record = current.aggregate.tokens.values().next().unwrap();
    assert_eq!(old_record.token, polled_record.token);
    assert_eq!(old_record.issued_at, polled_record.issued_at);
    assert_eq!(client.usable_tokens(now()).unwrap()[0].value, original);
    wait(&polled);
    let reduced = client
        .modify_grant(&changes(&[FOLDER_READ]), now())
        .unwrap();
    assert!(reduced.response().interact.is_none());
    let reduced_value = value(&reduced);
    assert_eq!(
        reduced.response().access_token.as_ref().unwrap().tokens[0].access,
        Some(vec![AccessItem::Reference(FOLDER_READ.into())])
    );
    assert!(read(&app, &original, "/resource/folder").is_err());
    assert!(read(&app, &reduced_value, "/resource/folder").is_ok());
    assert!(read(&app, &reduced_value, "/resource/archive").is_err());
    let mut expired_context = app
        .storage
        .lookup(GrantSelector::AccessToken(reduced_value.as_str()))
        .unwrap()
        .unwrap();
    for token in expired_context.aggregate.tokens.values_mut() {
        token.issued_at = 0;
    }
    assert_eq!(
        ConsentPolicy(app.decisions.clone()).evaluate_context(
            &request(&[FOLDER_READ]),
            EvaluationContext::Modification(&expired_context)
        ),
        Decision::RequireInteraction
    );
    wait(&reduced);
    let expanded = client
        .modify_grant(&changes(&[FOLDER_READ, ARCHIVE_READ]), now())
        .unwrap();
    assert!(expanded.response().interact.is_some());
    assert_eq!(client.usable_tokens(now()).unwrap()[0].value, reduced_value);
    assert!(read(&app, &reduced_value, "/resource/folder").is_ok());
    assert!(read(&app, &reduced_value, "/resource/archive").is_err());
    // Even another token created before this approval belongs to the same
    // aggregate and must be retired. The current demo normally issues one.
    let snapshot = app
        .storage
        .lookup(GrantSelector::AccessToken(reduced_value.as_str()))
        .unwrap()
        .unwrap();
    let mut candidate = snapshot.aggregate.clone();
    let mut sibling = candidate.tokens.values().next().unwrap().clone();
    sibling.token.value = TokenValue::new("synthetic-sibling-before-approval").unwrap();
    sibling.token.manage = None;
    sibling.management_token = "synthetic-sibling-management-before-approval".into();
    let sibling_value = sibling.token.value.clone();
    candidate
        .tokens
        .insert("sibling-before-approval".into(), sibling);
    app.storage
        .compare_exchange(snapshot.id, snapshot.revision, candidate)
        .unwrap();
    let finish = choice(&app, &expanded, true);
    client
        .accept_callback(&InteractCallback::from_redirect(&finish).unwrap(), now())
        .unwrap();
    wait(&expanded);
    let reapproved = client.continue_grant(now()).unwrap();
    let renewed = value(&reapproved);
    assert!(read(&app, &renewed, "/resource/archive").is_ok());
    for old in [&reduced_value, &sibling_value] {
        assert!(read(&app, old, "/resource/folder").is_err());
    }
    let snapshot = app
        .storage
        .lookup(GrantSelector::AccessToken(renewed.as_str()))
        .unwrap()
        .unwrap();
    let mut candidate = snapshot.aggregate.clone();
    let mut sibling = candidate.tokens.values().next().unwrap().clone();
    sibling.token.value = TokenValue::new("synthetic-sibling-before-revoke").unwrap();
    sibling.token.manage = None;
    sibling.management_token = "synthetic-sibling-management-before-revoke".into();
    let sibling_value = sibling.token.value.clone();
    candidate
        .tokens
        .insert("sibling-before-revoke".into(), sibling);
    app.storage
        .compare_exchange(snapshot.id, snapshot.revision, candidate)
        .unwrap();
    wait(&reapproved);
    client.revoke_grant(now()).unwrap();
    assert!(client.usable_tokens(now()).is_none());
    assert!(client.continue_grant(now()).is_err());
    for old in [&renewed, &sibling_value] {
        assert!(read(&app, old, "/resource/folder").is_err());
    }
}

#[test]
fn denied_expansion_closes_continuation_without_revoking_previous_tokens() {
    let app = tests::test_app();
    let network = Direct(&app.server);
    let mut client = Session::new(&network, app.signer.as_ref(), "https://demo.example/gnap")
        .supporting(&["redirect"]);
    let pending = client.start(&request(&[FOLDER_READ]), now()).unwrap();
    let finish = choice(&app, &pending, true);
    client
        .accept_callback(&InteractCallback::from_redirect(&finish).unwrap(), now())
        .unwrap();
    wait(&pending);
    let approved = client.continue_grant(now()).unwrap();
    let token = value(&approved);
    wait(&approved);
    let pending = client
        .modify_grant(&changes(&[FOLDER_READ, ARCHIVE_READ]), now())
        .unwrap();
    let finish = choice(&app, &pending, false);
    client
        .accept_callback(&InteractCallback::from_redirect(&finish).unwrap(), now())
        .unwrap();
    wait(&pending);
    assert!(
        matches!(client.continue_grant(now()), Err(gnap_client::ClientError::Server(e)) if e.code == gnap_registry::ErrorCode::UserDenied)
    );
    assert!(client.continue_grant(now()).is_err());
    assert_eq!(client.usable_tokens(now()).unwrap()[0].value, token);
    assert!(read(&app, &token, "/resource/folder").is_ok());
    assert!(read(&app, &token, "/resource/archive").is_err());
    client.revoke_token(None, now()).unwrap();
    assert!(read(&app, &token, "/resource/folder").is_err());
}

#[test]
fn consent_cannot_cross_grants_clients_requests_or_interaction_references() {
    let app = tests::test_app();
    let network = Direct(&app.server);
    let mut first = Session::new(&network, app.signer.as_ref(), "https://demo.example/gnap")
        .supporting(&["redirect"]);
    let pending = first.start(&request(&[FOLDER_READ]), now()).unwrap();
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
    assert!(consent_finish(
        &app.server,
        &app.storage,
        &app.decisions,
        "another-client",
        snapshot.id,
        handle,
        true
    )
    .is_err());
    assert!(app
        .storage
        .lookup(GrantSelector::Interaction(handle))
        .unwrap()
        .is_some());
    choice(&app, &pending, true);
    assert!(consent_finish(
        &app.server,
        &app.storage,
        &app.decisions,
        "test-client",
        snapshot.id,
        handle,
        false
    )
    .is_err());
    let snapshot = app
        .storage
        .lookup(GrantSelector::Id(snapshot.id))
        .unwrap()
        .unwrap();
    let policy = ConsentPolicy(app.decisions.clone());
    assert!(matches!(
        policy.evaluate_context(
            &snapshot.aggregate.record.request,
            EvaluationContext::AfterInteraction(&snapshot)
        ),
        Decision::Approve { .. }
    ));
    let mut other = Session::new(&network, app.signer.as_ref(), "https://demo.example/gnap")
        .supporting(&["redirect"]);
    let other = other.start(&request(&[FOLDER_READ]), now()).unwrap();
    let other_handle = other
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
    let other = app
        .storage
        .lookup(GrantSelector::Interaction(other_handle))
        .unwrap()
        .unwrap();
    assert!(consent_finish(
        &app.server,
        &app.storage,
        &app.decisions,
        "test-client",
        snapshot.id,
        other_handle,
        true
    )
    .is_err());
    let mut changed = snapshot.clone();
    changed.id = other.id;
    assert!(matches!(
        policy.evaluate_context(
            &snapshot.aggregate.record.request,
            EvaluationContext::AfterInteraction(&changed)
        ),
        Decision::Deny(_)
    ));
    let mut wrong_reference = snapshot.clone();
    wrong_reference.aggregate.record.interact_ref = Some("unrelated-interaction".into());
    assert!(matches!(
        policy.evaluate_context(
            &snapshot.aggregate.record.request,
            EvaluationContext::AfterInteraction(&wrong_reference)
        ),
        Decision::Deny(_)
    ));
    let mut wrong_request = snapshot.aggregate.record.request.clone();
    wrong_request.access_token = request(&[FOLDER_READ, ARCHIVE_READ]).access_token;
    assert!(matches!(
        policy.evaluate_context(
            &wrong_request,
            EvaluationContext::AfterInteraction(&snapshot)
        ),
        Decision::Deny(_)
    ));
}
