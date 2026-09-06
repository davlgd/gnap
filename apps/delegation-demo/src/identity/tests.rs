use super::*;

struct Direct<'a>(&'a As);
impl HttpTransport for Direct<'_> {
    type Error = String;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        Ok(self.0.handle(&request, now()))
    }
}

#[test]
fn identity_endpoint_refuses_unregistered_keys_and_reference_impersonation() {
    let app = crate::tests::test_app();
    app.decisions.lock().unwrap().identity = Identity::generate(&app.origin, &app.signer).unwrap();
    let other_signer = app.resource_client.signer.as_ref();
    assert_ne!(other_signer.thumbprint(), app.signer.thumbprint());
    let body = |client: Value| {
        json!({
            "client":client, "access_token":{"access":[FOLDER_READ]}, "subject":super::request(),
            "interact":{"start":["redirect"],"finish":{"method":"redirect", "uri":"https://demo.example/callback", "nonce":fresh_nonce().unwrap()}}
        })
    };
    for client in [
        json!({"key":introspection::public_key(other_signer)}),
        json!("test-client"),
    ] {
        let value = body(client);
        let _: GrantRequest = serde_json::from_value(value.clone()).unwrap();
        let request = HttpRequest::new("POST", format!("{}/gnap", app.origin))
            .json_body(serde_json::to_vec(&value).unwrap());
        let signed = sign_request(request, other_signer, None, now()).unwrap();
        let response = app.server.handle(&signed, now());
        assert!((400..500).contains(&response.status));
        let response: Value = serde_json::from_slice(&response.body).unwrap();
        assert!(response.get("error").is_some());
        for field in ["subject", "interact", "access_token", "continue"] {
            assert!(response.get(field).is_none(), "unexpected {field}");
        }
    }
    // Positive control: the same subject request is valid when its registered
    // reference is actually proved with the shared application's client key.
    let request = HttpRequest::new("POST", format!("{}/gnap", app.origin))
        .json_body(serde_json::to_vec(&body(json!("test-client"))).unwrap());
    let signed = sign_request(request, app.signer.as_ref(), None, now()).unwrap();
    let response = app.server.handle(&signed, now());
    assert!((200..300).contains(&response.status));
    let response: Value = serde_json::from_slice(&response.body).unwrap();
    assert!(response.get("interact").is_some());
    assert!(response.get("subject").is_none());
}

#[test]
fn identity_release_requires_matching_consent_and_verified_consumer_context() {
    let app = crate::tests::test_app();
    let identity = Identity::generate(&app.origin, &app.signer)
        .unwrap()
        .unwrap();
    app.decisions.lock().unwrap().identity = Some(identity.clone());
    let transport = Direct(&app.server);
    let policy = ConsentPolicy(app.decisions.clone(), app.rs_registration.resources.clone());
    for allow in [false, true] {
        let mut request: GrantRequest = serde_json::from_value(json!({
            "client":"test-client", "access_token":{"access":[FOLDER_READ]},
            "subject": super::request(),
            "interact":{"start":["redirect"],"finish":{"method":"redirect","uri":"https://demo.example/callback","nonce":fresh_nonce().unwrap()}}
        })).unwrap();
        assert!(!policy.keep_grant_open(&request));
        assert!(matches!(
            policy.evaluate_context(&request, EvaluationContext::Initial),
            Decision::RequireInteraction
        ));
        let mut client = Session::new(
            &transport,
            app.signer.as_ref(),
            format!("{}/gnap", app.origin),
        );
        let pending = client.start(&request, now()).unwrap();
        assert!(pending.response().subject.is_none());
        assert_eq!(
            verified_view(&client, &identity, now())["status"],
            "unavailable"
        );
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
        assert!(matches!(
            policy.evaluate_context(&request, EvaluationContext::AfterInteraction(&snapshot)),
            Decision::Deny(_)
        ));
        let callback = consent_finish(
            &app.server,
            &app.storage,
            &app.decisions,
            "test-client",
            snapshot.id,
            handle,
            allow,
        )
        .unwrap();
        let snapshot = app
            .storage
            .lookup(GrantSelector::Id(snapshot.id))
            .unwrap()
            .unwrap();
        assert!(matches!(
            policy.evaluate_context(&request, EvaluationContext::Modification(&snapshot)),
            Decision::Deny(_)
        ));
        // An unrelated request cannot consume this consent or receive identity.
        request
            .interact
            .as_mut()
            .unwrap()
            .finish
            .as_mut()
            .unwrap()
            .nonce = fresh_nonce().unwrap();
        assert!(matches!(
            policy.evaluate_context(&request, EvaluationContext::AfterInteraction(&snapshot)),
            Decision::Deny(_)
        ));
        client.accept_redirect(&callback, now()).unwrap();
        std::thread::sleep(Duration::from_secs(
            pending
                .response()
                .r#continue
                .as_ref()
                .and_then(|c| c.wait)
                .unwrap_or(0),
        ));
        let result = client.continue_grant(now());
        if !allow {
            assert!(result.is_err());
            assert!(client.subject().is_none());
            continue;
        }
        let approved = result.unwrap();
        assert!(approved.response().r#continue.is_none());
        let subject = approved.response().subject.as_ref().unwrap();
        let nonce = snapshot
            .aggregate
            .record
            .request
            .interact
            .as_ref()
            .unwrap()
            .finish
            .as_ref()
            .unwrap()
            .nonce
            .as_str();
        // Same nonce and assertion, but an actual independently generated RS
        // key used as recipient: a key does not become this grant's client.
        assert_ne!(
            app.resource_client.signer.thumbprint(),
            app.signer.thumbprint()
        );
        assert_eq!(
            identity
                .trust()
                .verify_subject(
                    subject,
                    &identity.endpoint,
                    &app.resource_client.signer.thumbprint(),
                    nonce,
                    now()
                )
                .unwrap_err(),
            gnap_subject::AssertionError::Recipient
        );
        assert_eq!(
            identity
                .trust()
                .verify_subject(
                    subject,
                    &identity.endpoint,
                    &identity.audience,
                    "different-session",
                    now()
                )
                .unwrap_err(),
            gnap_subject::AssertionError::Nonce
        );
        let wrong_key = app.resource_client.signer.verifier();
        let wrong_key_trust = Trust {
            key: &wrong_key,
            ..identity.trust()
        };
        assert!(wrong_key_trust
            .verify_subject(
                subject,
                &identity.endpoint,
                &identity.audience,
                nonce,
                now()
            )
            .is_err());
        let wrong_issuer = Trust {
            issuer: "https://other.example",
            ..identity.trust()
        };
        assert_eq!(
            wrong_issuer
                .verify_subject(
                    subject,
                    &identity.endpoint,
                    &identity.audience,
                    nonce,
                    now()
                )
                .unwrap_err(),
            gnap_subject::AssertionError::Recipient
        );
        let view = verified_view(&client, &identity, now());
        assert_eq!(view["status"], "verified");
        assert_eq!(view["as_endpoint"], "https://demo.example/gnap");
        assert_eq!(view["subject"], identity.subject);
        assert_eq!(view.as_object().unwrap().len(), 5);
        assert_eq!(
            verified_view(&client, &identity, view["expires_at"].as_u64().unwrap())["status"],
            "unavailable"
        );
        let assertions = approved
            .response()
            .subject
            .as_ref()
            .unwrap()
            .assertions
            .as_ref()
            .unwrap();
        assert!(!view.to_string().contains(&assertions[0].value));
        assert!(client.usable_tokens(now()).is_some());
    }
    assert!(Identity::generate("http://127.0.0.1:8080", &app.signer)
        .unwrap()
        .is_none());
    let unsupported: GrantRequest = serde_json::from_value(json!({"client":"test-client", "access_token":{"access":[FOLDER_READ]}, "subject":{"assertion_formats":["saml2"]}})).unwrap();
    assert!(matches!(policy.evaluate(&unsupported), Decision::Deny(_)));
}

#[test]
fn local_http_worker_refuses_identity_before_creating_client_or_grant() {
    let app = crate::tests::test_app_at("http://127.0.0.1:8080");
    let clients_before = app.decisions.lock().unwrap().clients.len();
    let decisions = app.decisions.clone();
    let references = app.bootstrap.get().unwrap().as_ref().unwrap().clone();
    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        client_worker(
            app.origin,
            app.signer,
            app.server,
            app.storage,
            app.decisions,
            receiver,
            references,
        )
    });
    let (reply, received) = tokio::sync::oneshot::channel();
    sender
        .send(Command {
            session: "unused-client".into(),
            action: "start-identity".into(),
            reply,
        })
        .unwrap();
    let result = received.blocking_recv().unwrap();
    drop(sender);
    worker.join().unwrap();
    assert!(result.unwrap_err().contains("HTTPS"));
    assert_eq!(decisions.lock().unwrap().clients.len(), clients_before);
    assert!(decisions.lock().unwrap().grants.is_empty());
}
