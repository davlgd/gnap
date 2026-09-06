use super::*;

#[test]
fn registrations_are_private_per_client_and_removed_at_cleanup() {
    let mut registry = Registry::default();
    let first = registry.register("first", "https://demo.example").unwrap();
    let second = registry.register("second", "https://demo.example").unwrap();
    assert_eq!(first.id.len(), 22);
    assert_ne!(first.id, second.id);
    assert!(registry.register("first", "https://demo.example").is_err());
    assert!(!view(Some(&first)).to_string().contains(&first.id));
    registry.remove_client("first");
    assert!(!registry.slots.contains_key(&first.id));
    assert!(registry.slots.contains_key(&second.id));
}

#[test]
fn push_policy_requires_the_registered_client_and_exact_selected_shape() {
    let mut registry = Registry::default();
    let registration = registry.register("first", "https://demo.example").unwrap();
    let value = json!({"client":"first", "access_token":{"access":[FOLDER_READ]},
        "interact":{"start":["redirect"], "finish":{"method":"push", "uri":registration.uri, "nonce":"nonce"}}});
    let request: GrantRequest = serde_json::from_value(value.clone()).unwrap();
    assert!(acceptable_request(&request, &registry));
    for (pointer, replacement) in [
        ("/client", json!("other")),
        (
            "/interact/finish/uri",
            json!("https://demo.example/push-callback/aaaaaaaaaaaaaaaaaaaaaa"),
        ),
        ("/interact/start", json!(["redirect", "user_code"])),
        (
            "/access_token",
            json!([{"label":"documents", "access":[FOLDER_READ]}]),
        ),
    ] {
        let mut altered = value.clone();
        *altered.pointer_mut(pointer).unwrap() = replacement;
        let request = serde_json::from_value(altered).unwrap();
        assert!(!acceptable_request(&request, &registry), "{pointer}");
    }
    let mut subject = request.clone();
    subject.subject = Some(serde_json::from_value(identity::request()).unwrap());
    assert!(!acceptable_request(&subject, &registry));
    assert!(!acceptable_request(&request, &Registry::default()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_push_approves_denies_and_rejects_invalid_replayed_and_expired_callbacks() {
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
    let worker_app = app.clone();
    let references = app.bootstrap.get().unwrap().as_ref().unwrap().clone();
    // Do not retain the sender in the worker, so shutdown can close the queue.
    let App {
        origin: worker_origin,
        signer,
        server,
        storage,
        decisions,
        commands: unused_sender,
        ..
    } = worker_app;
    drop(unused_sender);
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
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // Unknown callback IDs do not consume the budget for registered deliveries.
    for _ in 0..65 {
        assert_eq!(
            http.post(format!("{origin}/push-callback/aaaaaaaaaaaaaaaaaaaaaa"))
                .header("content-type", "application/json")
                .body("{}")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    assert!(app.decisions.lock().unwrap().push.attempts.is_empty());

    let start = dispatch(&app, "allow".into(), "start-push".into())
        .await
        .unwrap();
    assert_eq!(start["state"], "pending");
    assert!(!start.to_string().contains("push-callback"));
    assert!(dispatch(&app, "allow".into(), "continue".into())
        .await
        .is_err());
    let (uri, grant) = {
        let choices = app.decisions.lock().unwrap();
        let slot = choices
            .push
            .slots
            .values()
            .find(|slot| slot.client == "allow")
            .unwrap();
        (slot.registration.uri.clone(), slot.grant.unwrap())
    };
    let approved = dispatch(&app, "allow".into(), "approve".into())
        .await
        .unwrap();
    assert_eq!(approved["state"], "awaiting_push");
    let ready = tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            let state = dispatch(&app, "allow".into(), "status".into())
                .await
                .unwrap();
            if state["push_finish"]["delivery"] == "delivered" {
                break state;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(ready["state"], "ready");
    assert_eq!(ready["push_finish"]["received"], true);
    tokio::time::sleep(Duration::from_secs(
        ready["continuation_wait_seconds"].as_u64().unwrap(),
    ))
    .await;
    let issued = dispatch(&app, "allow".into(), "continue".into())
        .await
        .unwrap();
    assert_eq!(issued["token_present"], true);
    assert_eq!(issued["continuation_open"], false);
    assert_eq!(
        dispatch(&app, "allow".into(), "read".into()).await.unwrap()["last_resource_status"],
        200
    );
    let replay = http
        .post(&uri)
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        serde_json::from_slice::<Value>(&replay.bytes().await.unwrap()).unwrap(),
        json!({"error":"unknown_interaction"})
    );
    assert!(app
        .storage
        .lookup(GrantSelector::Id(grant))
        .unwrap()
        .is_some());

    // Hold the reply ourselves to inspect and deliver the SDK's exact outbox
    // bytes. Invalid callbacks must not consume the valid pending reference.
    dispatch(&app, "deny".into(), "start-push".into())
        .await
        .unwrap();
    let (reply, received) = tokio::sync::oneshot::channel();
    app.commands
        .send(WorkerCommand::Browser(Command {
            session: "deny".into(),
            action: "deny".into(),
            reply,
        }))
        .unwrap();
    received.await.unwrap().unwrap();
    let (uri, body, status) = {
        let mut choices = app.decisions.lock().unwrap();
        let slot = choices
            .push
            .slots
            .values_mut()
            .find(|slot| slot.client == "deny")
            .unwrap();
        let job = slot.outbox.take().unwrap();
        (job.uri, job.body, job.status)
    };
    dispatch(&app, "other".into(), "start-push".into())
        .await
        .unwrap();
    let (reply, received) = tokio::sync::oneshot::channel();
    app.commands
        .send(WorkerCommand::Browser(Command {
            session: "other".into(),
            action: "approve".into(),
            reply,
        }))
        .unwrap();
    received.await.unwrap().unwrap();
    let other = app
        .decisions
        .lock()
        .unwrap()
        .push
        .slots
        .values_mut()
        .find(|slot| slot.client == "other")
        .unwrap()
        .outbox
        .take()
        .unwrap();
    let crossed = http
        .post(&uri)
        .header("content-type", "application/json")
        .body(other.body)
        .send()
        .await
        .unwrap();
    assert_eq!(crossed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_slice::<Value>(&crossed.bytes().await.unwrap()).unwrap(),
        json!({"error":"unknown_interaction"})
    );
    for malformed in [
        b"{".to_vec(),
        br#"{"hash":"wrong","interact_ref":"wrong"}"#.to_vec(),
    ] {
        let result = http
            .post(&uri)
            .header("content-type", "application/json")
            .body(malformed)
            .send()
            .await
            .unwrap();
        assert_eq!(result.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            serde_json::from_slice::<Value>(&result.bytes().await.unwrap()).unwrap(),
            json!({"error":"unknown_interaction"})
        );
    }
    assert_eq!(
        http.post(&uri)
            .header("content-type", "application/json")
            .body(vec![b'x'; 1025])
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert!(!status.lock().unwrap().received);
    let first = http
        .post(&uri)
        .header("content-type", "application/json")
        .body(body.clone())
        .send();
    let second = http
        .post(&uri)
        .header("content-type", "application/json")
        .body(body)
        .send();
    let (first, second) = tokio::join!(first, second);
    let mut codes = [
        first.unwrap().status().as_u16(),
        second.unwrap().status().as_u16(),
    ];
    codes.sort();
    assert_eq!(codes, [204, 404]);
    let state = dispatch(&app, "deny".into(), "status".into())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(
        state["continuation_wait_seconds"].as_u64().unwrap(),
    ))
    .await;
    let denied = dispatch(&app, "deny".into(), "continue".into())
        .await
        .unwrap();
    assert_eq!(denied["state"], "denied");
    assert_eq!(denied["token_present"], false);

    // Capacity refusal consumes the one attempt, never rolls back consent or
    // silently enables AS polling. A later status refresh must not retry it.
    let mut saturated = app.clone();
    saturated.push_outbound = Arc::new(tokio::sync::Semaphore::new(0));
    dispatch(&saturated, "capacity".into(), "start-push".into())
        .await
        .unwrap();
    dispatch(&saturated, "capacity".into(), "approve".into())
        .await
        .unwrap();
    let failed = dispatch(&app, "capacity".into(), "status".into())
        .await
        .unwrap();
    assert_eq!(failed["push_finish"]["delivery"], "refused_before_send");
    assert_eq!(failed["push_finish"]["received"], false);
    assert!(dispatch(&app, "capacity".into(), "continue".into())
        .await
        .is_err());
    {
        let choices = app.decisions.lock().unwrap();
        let slot = choices
            .push
            .slots
            .values()
            .find(|slot| slot.client == "capacity")
            .unwrap();
        assert!(slot.outbox.is_none());
        let snapshot = app
            .storage
            .lookup(GrantSelector::Id(slot.grant.unwrap()))
            .unwrap()
            .unwrap();
        assert!(snapshot.aggregate.record.interaction_completed);
    }
    drop(saturated);

    dispatch(&app, "expired".into(), "start-push".into())
        .await
        .unwrap();
    let uri = {
        let choices = app.decisions.lock().unwrap();
        let slot = choices
            .push
            .slots
            .values()
            .find(|slot| slot.client == "expired")
            .unwrap();
        slot.registration.status.lock().unwrap().created = Instant::now() - CALLBACK_WINDOW;
        slot.registration.uri.clone()
    };
    assert!(dispatch(&app, "expired".into(), "approve".into())
        .await
        .is_err());
    assert_eq!(
        http.post(&uri)
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    serving.abort();
    let _ = serving.await;
    drop(http);
    drop(app);
    tokio::task::spawn_blocking(move || worker.join().unwrap())
        .await
        .unwrap();
}
