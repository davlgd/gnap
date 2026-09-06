use super::*;
use gnap_client::Step;
use gnap_types::message::GrantResponse;
use std::sync::OnceLock;

fn signer() -> &'static Ps256Signer {
    static KEY: OnceLock<Ps256Signer> = OnceLock::new();
    KEY.get_or_init(|| Ps256Signer::generate(2048, "external-workbench-test").unwrap())
}
fn configuration(callback: &str) -> String {
    serde_json::to_string(&json!([{"jwk":signer().public_jwk().unwrap(),"callback":callback}]))
        .unwrap()
}
fn request(callback: &str) -> GrantRequest {
    serde_json::from_value(json!({"client":{"key":introspection::public_key(signer())},"access_token":{"access":[FOLDER_READ]},
        "interact":{"start":["redirect"],"finish":{"method":"redirect","uri":callback,"nonce":fresh_nonce().unwrap()}}})).unwrap()
}
fn configured(callback: &str) -> App {
    let app = crate::tests::test_app();
    app.decisions.lock().unwrap().external =
        Registry::parse(Some(&configuration(callback)), &app.origin).unwrap();
    app
}
fn signed(app: &App, body: &GrantRequest, key: &Ps256Signer) -> HttpRequest {
    sign_request(
        HttpRequest::new("POST", format!("{}/gnap", app.origin))
            .json_body(serde_json::to_vec(body).unwrap()),
        key,
        None,
        now(),
    )
    .unwrap()
}

#[test]
fn configuration_is_all_or_nothing_and_never_reflects_material() {
    let callback = "https://workbench.example/lifecycle/callback";
    assert!(Registry::parse(None, "https://demo.example")
        .unwrap()
        .allowed
        .is_empty());
    assert!(Registry::parse(Some("[]"), "https://demo.example")
        .unwrap()
        .allowed
        .is_empty());
    assert_eq!(
        Registry::parse(Some(&configuration(callback)), "https://demo.example")
            .unwrap()
            .allowed
            .len(),
        1
    );
    for callback in [
        "https://user:secret@workbench.example/lifecycle/callback",
        "https://WORKBENCH.example/lifecycle/callback",
        "https://workbench.example:443/lifecycle/callback",
        "https://workbench.example/lifecycle/callback?x=y",
        "https://workbench.example/lifecycle/callback#fragment",
        "https://workbench.example/other",
        "http://127.0.0.1/lifecycle/callback",
    ] {
        let error = Registry::parse(Some(&configuration(callback)), "https://demo.example")
            .err()
            .unwrap();
        assert_eq!(error, "GNAP_EXTERNAL_CLIENTS: invalid entry at index 0");
        assert!(!error.contains(callback));
    }
    assert!(Registry::parse(
        Some(&configuration("http://127.0.0.1:1234/lifecycle/callback")),
        "http://127.0.0.1:5678"
    )
    .is_ok());
    assert!(Registry::parse(
        Some(&configuration("http://evil.example/lifecycle/callback")),
        "http://127.0.0.1:5678"
    )
    .is_err());
    for raw in ["null", "{}", "not json"] {
        assert!(Registry::parse(Some(raw), "https://demo.example").is_err());
    }
    let entry: Value = serde_json::from_str::<Value>(&configuration(callback)).unwrap()[0].clone();
    assert!(Registry::parse(
        Some(&serde_json::to_string(&vec![entry.clone(); 9]).unwrap()),
        "https://demo.example"
    )
    .is_err());
    assert!(Registry::parse(
        Some(&serde_json::to_string(&vec![entry.clone(); 2]).unwrap()),
        "https://demo.example"
    )
    .is_err());
    for mutation in 0..4 {
        let mut entry = entry.clone();
        match mutation {
            0 => {
                entry["jwk"]["d"] = json!("private-material-must-never-appear");
            }
            1 => {
                entry["jwk"]["alg"] = json!("RS256");
            }
            2 => {
                entry["jwk"].as_object_mut().unwrap().remove("kid");
            }
            _ => {
                entry["jwk"]["n"] = json!(format!("g{}B", "A".repeat(682)));
            }
        }
        let raw = serde_json::to_string(&vec![entry]).unwrap();
        assert_eq!(
            Registry::parse(Some(&raw), "https://demo.example")
                .err()
                .unwrap(),
            "GNAP_EXTERNAL_CLIENTS: invalid entry at index 0"
        );
    }
    // Public 1024-bit odd modulus: no private fixture or unsupported signer.
    let mut weak = entry;
    weak["jwk"]["n"] = json!(format!("g{}E", "A".repeat(169)));
    let raw = serde_json::to_string(&vec![weak]).unwrap();
    assert!(Registry::parse(Some(&raw), "https://demo.example").is_err());
}

#[test]
fn external_keys_do_not_alias_internal_references_or_trust_a_matching_kid() {
    let callback = "https://workbench.example/lifecycle/callback";
    let app = configured(callback);
    let body = request(callback);
    let disabled = crate::tests::test_app();
    assert_eq!(
        disabled
            .server
            .handle(&signed(&disabled, &body, signer()), now())
            .status,
        400
    );
    let wrong = Ps256Signer::generate(2048, "external-workbench-test").unwrap();
    assert_eq!(
        app.server
            .handle(&signed(&app, &body, &wrong), now())
            .status,
        400
    );
    let mut unregistered = body.clone();
    unregistered.client =
        serde_json::from_value(json!({"key":introspection::public_key(&wrong)})).unwrap();
    assert_eq!(
        app.server
            .handle(&signed(&app, &unregistered, &wrong), now())
            .status,
        400
    );
    let mut reference = body.clone();
    reference.client = Client::ByReference("test-client".into());
    assert_eq!(
        app.server
            .handle(&signed(&app, &reference, signer()), now())
            .status,
        400
    );
    assert_eq!(
        app.server
            .handle(&signed(&app, &body, signer()), now())
            .status,
        200
    );
}

#[test]
fn unsupported_modes_rights_and_callback_changes_never_reach_consent() {
    let callback = "https://workbench.example/lifecycle/callback";
    let app = configured(callback);
    let original = serde_json::to_value(request(callback)).unwrap();
    let mut cases = Vec::new();
    for field in ["subject", "user", "extra"] {
        let mut body = original.clone();
        body[field] = json!({});
        cases.push(body);
    }
    for start in [
        json!(["user_code_uri"]),
        json!(["redirect", "user_code"]),
        json!([{"method":"redirect"}]),
    ] {
        let mut body = original.clone();
        body["interact"]["start"] = start;
        cases.push(body);
    }
    for method in ["push", "unknown"] {
        let mut body = original.clone();
        body["interact"]["finish"]["method"] = json!(method);
        cases.push(body);
    }
    let mut changed = original.clone();
    changed["interact"]["finish"]["uri"] = json!("https://evil.example/lifecycle/callback");
    cases.push(changed);
    let mut extra = original.clone();
    extra["access_token"]["formats"] = json!(["jwt-signed"]);
    cases.push(extra);
    let mut extra = original.clone();
    extra["access_token"]["label"] = json!("a");
    cases.push(extra);
    let mut extra = original.clone();
    extra["access_token"]["flags"] = json!(["bearer"]);
    cases.push(extra);
    let mut rights = original.clone();
    rights["access_token"]["access"] = json!([ARCHIVE_READ]);
    cases.push(rights);
    let mut multiple = original.clone();
    multiple["access_token"] = json!([{"label":"one","access":[FOLDER_READ]}]);
    cases.push(multiple);
    for body in cases {
        let Ok(parsed) = serde_json::from_value::<GrantRequest>(body.clone()) else {
            continue; // Invalid GNAP shapes are already rejected by the SDK parser.
        };
        assert!(
            app.decisions
                .lock()
                .unwrap()
                .external
                .profile(&parsed)
                .is_none()
                || !wire_profile(&signed(&app, &parsed, signer()))
        );
        let response = app.server.handle(&signed(&app, &parsed, signer()), now());
        assert_eq!(response.status, 400, "{body}");
    }
    let mut null = original;
    null["subject"] = Value::Null;
    let request = HttpRequest::new("POST", format!("{}/gnap", app.origin))
        .json_body(serde_json::to_vec(&null).unwrap());
    assert!(!wire_profile(&request));
}

#[test]
fn admission_counts_live_external_grants_without_using_internal_capacity() {
    let callback = "https://workbench.example/lifecycle/callback";
    let app = configured(callback);
    for _ in 0..MAX_PER_KEY {
        assert_eq!(
            app.server
                .handle(&signed(&app, &request(callback), signer()), now())
                .status,
            200
        );
    }
    assert_eq!(
        app.server
            .handle(&signed(&app, &request(callback), signer()), now())
            .status,
        503
    );
    let internal:GrantRequest=serde_json::from_value(json!({"client":"test-client","access_token":{"access":[FOLDER_READ]},"interact":{"start":["redirect"]}})).unwrap();
    assert_eq!(
        app.server
            .handle(&signed(&app, &internal, &app.signer), now())
            .status,
        200
    );
}

fn pending(app: &App, callback: &str) -> (String, GrantSnapshot) {
    let response = app
        .server
        .handle(&signed(app, &request(callback), signer()), now());
    assert_eq!(response.status, 200);
    let response: GrantResponse = serde_json::from_slice(&response.body).unwrap();
    let uri = response.interact.unwrap().redirect.unwrap();
    let handle = uri.rsplit('/').next().unwrap().to_owned();
    let snapshot = app
        .storage
        .lookup(GrantSelector::Interaction(&handle))
        .unwrap()
        .unwrap();
    (handle, snapshot)
}
fn consent_owner(app: &App, handle: &str) -> (HeaderMap, String) {
    let response = entry(app, handle, &HeaderMap::new());
    assert_eq!(response.status(), 200);
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("cookie", cookie.parse().unwrap());
    headers.insert(
        "content-type",
        "application/x-www-form-urlencoded".parse().unwrap(),
    );
    let id = owner_cookie(&headers).unwrap();
    let ticket = app.decisions.lock().unwrap().external.owners[id]
        .ticket
        .clone()
        .unwrap();
    (headers, ticket)
}

#[test]
fn consent_is_bound_to_owner_grant_request_nonce_and_original_deadline() {
    let callback = "https://workbench.example/lifecycle/callback";
    let app = configured(callback);
    let (first, snapshot) = pending(&app, callback);
    let (second, _) = pending(&app, callback);
    let (headers, ticket) = consent_owner(&app, &first);
    let (other_headers, _) = consent_owner(&app, &second);
    let body = format!("ticket={ticket}&choice=allow");
    assert_eq!(
        submitted(&app, &first, &other_headers, body.as_bytes()).status(),
        403
    );
    assert_eq!(
        submitted(&app, &second, &headers, body.as_bytes()).status(),
        403
    );
    // A different handle does not enter this owner's form-admission domain.
    assert_eq!(
        app.decisions.lock().unwrap().external.owners[owner_cookie(&headers).unwrap()]
            .ticket
            .as_deref(),
        Some(ticket.as_str())
    );
    assert!(
        !app.storage
            .lookup(GrantSelector::Id(snapshot.id))
            .unwrap()
            .unwrap()
            .aggregate
            .record
            .interaction_completed
    );

    for mutation in 0..3 {
        let before = app
            .storage
            .lookup(GrantSelector::Id(snapshot.id))
            .unwrap()
            .unwrap();
        let (headers, ticket) = consent_owner(&app, &first);
        let mut changed = before.aggregate.clone();
        match mutation {
            0 => {
                changed
                    .record
                    .request
                    .interact
                    .as_mut()
                    .unwrap()
                    .finish
                    .as_mut()
                    .unwrap()
                    .nonce = fresh_nonce().unwrap()
            }
            1 => changed.record.as_nonce = Some(fresh_nonce().unwrap()),
            _ => {
                changed.record.interact_expires_at =
                    changed.record.interact_expires_at.map(|time| time + 1)
            }
        }
        app.storage
            .compare_exchange(before.id, before.revision, changed)
            .unwrap();
        assert_eq!(
            submitted(
                &app,
                &first,
                &headers,
                format!("ticket={ticket}&choice=allow").as_bytes()
            )
            .status(),
            400
        );
        assert!(app.decisions.lock().unwrap().external.decisions.is_empty());
    }
    let before = app
        .storage
        .lookup(GrantSelector::Id(snapshot.id))
        .unwrap()
        .unwrap();
    let mut expired = before.aggregate;
    expired.record.interact_expires_at =
        Some(now() + gnap_as::server::INTERACTION_LIFETIME - LIFETIME);
    app.storage
        .compare_exchange(before.id, before.revision, expired)
        .unwrap();
    assert_eq!(entry(&app, &first, &HeaderMap::new()).status(), 410);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn anonymous_posts_do_not_exhaust_the_owner_consent_budget() {
    use tower::ServiceExt;
    let callback = "https://workbench.example/lifecycle/callback";
    let app = configured(callback);
    let (handle, _) = pending(&app, callback);
    let (headers, ticket) = consent_owner(&app, &handle);
    let before = app.decisions.lock().unwrap().external.attempts.len();
    let router = application_router(app.clone(), CanonicalOrigin::parse(&app.origin).unwrap());
    for _ in 0..200 {
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/interact/unknown")
            .header("host", "demo.example")
            .header("origin", &app.origin)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(axum::body::Body::from("ticket=unknown&choice=allow"))
            .unwrap();
        assert_eq!(router.clone().oneshot(request).await.unwrap().status(), 401);
    }
    assert_eq!(
        app.decisions.lock().unwrap().external.attempts.len(),
        before
    );
    // A real owner's invalid ticket or malformed form remains budgeted.
    assert_eq!(
        submitted(&app, &handle, &headers, b"ticket=invalid&choice=allow").status(),
        403
    );
    assert_eq!(
        submitted(&app, &handle, &headers, b"malformed").status(),
        400
    );
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/interact/{handle}"))
        .header("host", "demo.example")
        .header("origin", &app.origin)
        .header("cookie", headers["cookie"].clone())
        .header("content-type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(format!(
            "ticket={ticket}&choice=allow"
        )))
        .unwrap();
    assert_eq!(router.oneshot(request).await.unwrap().status(), 303);
    assert_eq!(
        app.decisions.lock().unwrap().external.attempts.len(),
        before + 3
    );
}

#[test]
fn owner_state_and_attempts_are_bounded_and_reload_never_extends_consent() {
    let callback = "https://workbench.example/lifecycle/callback";
    let app = configured(callback);
    let (handle, snapshot) = pending(&app, callback);
    let expected = deadline(&snapshot.aggregate.record).unwrap();
    let (headers, _) = consent_owner(&app, &handle);
    let id = owner_cookie(&headers).unwrap();
    let born = app.decisions.lock().unwrap().external.owners[id].born;
    assert_eq!(entry(&app, &handle, &headers).status(), 200);
    {
        let decisions = app.decisions.lock().unwrap();
        let owner = &decisions.external.owners[id];
        assert_eq!(owner.born, born);
        assert_eq!(owner.pending.deadline, expected);
    }
    for _ in 1..MAX_OWNERS {
        assert_eq!(entry(&app, &handle, &HeaderMap::new()).status(), 200);
    }
    assert_eq!(entry(&app, &handle, &HeaderMap::new()).status(), 429);
    {
        let mut decisions = app.decisions.lock().unwrap();
        let registry = &mut decisions.external;
        registry.owners.get_mut(id).unwrap().born = Instant::now() - Duration::from_secs(LIFETIME);
        registry.cleanup();
        assert!(!registry.owners.contains_key(id));
    }
    // A replacement owner inherits the original grant deadline.
    let (new_headers, _) = consent_owner(&app, &handle);
    assert_eq!(
        app.decisions.lock().unwrap().external.owners[owner_cookie(&new_headers).unwrap()]
            .pending
            .deadline,
        expected
    );
    let mut decisions = app.decisions.lock().unwrap();
    while decisions.external.admit() {}
    assert_eq!(decisions.external.attempts.len(), MAX_ATTEMPTS);
    assert!(!decisions.external.admit());
    assert_eq!(decisions.external.owners.len(), MAX_OWNERS);
}

#[test]
fn store_caps_include_closed_token_bearing_grants_and_release_expired_ones() {
    let app = crate::tests::test_app();
    let client = request("https://workbench.example/lifecycle/callback").client;
    let exponents = ["Aw", "BQ", "Bw", "CQ", "Cw", "DQ", "Dw", "EQ"];
    let mut snapshots = Vec::new();
    for (key_index, exponent) in exponents.into_iter().enumerate() {
        for slot in 0..MAX_PER_KEY {
            let name = format!("external-{key_index}-{slot}");
            let mut aggregate =
                crate::tests::test_aggregate(&name, crate::tests::test_record(&name));
            let mut separate = serde_json::to_value(&client).unwrap();
            // Storage tests need distinct public material, not private signers.
            separate["key"]["jwk"]["e"] = json!(exponent);
            let separate: Client = serde_json::from_value(separate).unwrap();
            aggregate.record.request.client = separate.clone();
            let token = aggregate.tokens.values_mut().next().unwrap();
            token.client = separate;
            token.token.expires_in = Some(LIFETIME);
            snapshots.push(app.storage.create(aggregate).unwrap());
        }
    }
    assert_eq!(snapshots.len(), MAX_GRANTS);
    let mut candidate = snapshots[0].aggregate.clone();
    candidate.tokens.clear();
    candidate
        .tokens
        .insert("new-handle".into(), crate::tests::test_record("new-value"));
    candidate.tokens.values_mut().next().unwrap().client = candidate.record.request.client.clone();
    assert!(matches!(
        app.storage.create(candidate.clone()),
        Err(StoreError::Unavailable)
    ));
    let expired = &snapshots[0];
    let mut expired_record = expired.aggregate.clone();
    expired_record.tokens.values_mut().next().unwrap().issued_at = now() - LIFETIME;
    app.storage
        .compare_exchange(expired.id, expired.revision, expired_record)
        .unwrap();
    app.storage
        .create(candidate)
        .expect("expired closed grant releases both quotas");
    assert!(app
        .storage
        .lookup(GrantSelector::Id(expired.id))
        .unwrap()
        .is_none());
}

struct Network(reqwest::blocking::Client);
impl HttpTransport for Network {
    type Error = &'static str;
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, Self::Error> {
        let mut outgoing = self.0.request(
            reqwest::Method::from_bytes(request.method.as_bytes()).map_err(|_| "method")?,
            &request.url,
        );
        for (name, value) in request.headers {
            outgoing = outgoing.header(name, value);
        }
        if let Some(body) = request.body {
            outgoing = outgoing.body(body);
        }
        let response = outgoing.send().map_err(|_| "transport")?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_str().unwrap_or_default().into()))
            .collect();
        let body = response.bytes().map_err(|_| "body")?.to_vec();
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}
fn browser() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}
fn ticket(page: &str) -> String {
    page.split("name=\"ticket\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .into()
}
fn owner(client: &reqwest::blocking::Client, uri: &str) -> (String, String) {
    let response = client.get(uri).send().unwrap();
    assert_eq!(response.status(), 200);
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert!(cookie.starts_with("gnap_external_owner="));
    let page = response.text().unwrap();
    assert!(page.contains("synthetic-folder:read"));
    (cookie, ticket(&page))
}
fn decide(
    client: &reqwest::blocking::Client,
    uri: &str,
    origin: &str,
    cookie: &str,
    ticket: &str,
    choice: &str,
) -> reqwest::blocking::Response {
    client
        .post(uri)
        .header("origin", origin)
        .header("cookie", cookie)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!("ticket={ticket}&choice={choice}"))
        .send()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_http_manual_consent_rotation_revocation_and_denial() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let callback_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let callback = format!(
        "http://{}/lifecycle/callback",
        callback_listener.local_addr().unwrap()
    );
    let callback_server = tokio::spawn(async move {
        axum::serve(
            callback_listener,
            Router::new().route(
                "/lifecycle/callback",
                get(|| async { StatusCode::NO_CONTENT }),
            ),
        )
        .await
        .unwrap();
    });
    let mut app = crate::tests::test_app_at(&origin);
    app.decisions.lock().unwrap().external =
        Registry::parse(Some(&configuration(&callback)), &origin).unwrap();
    app.resource_client = Arc::new(introspection::ResourceClient {
        origin: origin.clone(),
        signer: app.resource_client.signer.clone(),
        transport: Arc::new(introspection::Http {
            origin: origin.clone(),
        }),
        nonces: MemoryStorage::default(),
    });
    let router = application_router(app.clone(), CanonicalOrigin::parse(&origin).unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    tokio::task::spawn_blocking(move || {
        let transport = Network(browser());
        let owner_browser = browser();
        let mut invalid = serde_json::to_value(request(&callback)).unwrap();
        invalid["subject"] = Value::Null;
        let response = transport.send(sign_request(HttpRequest::new("POST", format!("{origin}/gnap")).json_body(serde_json::to_vec(&invalid).unwrap()), signer(), None, now()).unwrap()).unwrap();
        assert_eq!(response.status, 400);
        assert_eq!(serde_json::from_slice::<Value>(&response.body).unwrap(), json!({"error":"request_denied"}));
        for allow in [true, false] {
            let mut client = Session::new(&transport, signer(), format!("{origin}/gnap"))
                .with_finish_timeout(FINISH_TIMEOUT);
            let step = client.start(&request(&callback), now()).unwrap();
            let interaction = step
                .response()
                .interact
                .as_ref()
                .unwrap()
                .redirect
                .as_ref()
                .unwrap()
                .clone();
            let (cookie, csrf) = owner(&owner_browser, &interaction);
            // A GET only displays the pending choice, never approves it.
            assert!(client.usable_tokens(now()).is_none());
            let form = format!("ticket={csrf}&choice=allow");
            assert_eq!(owner_browser.post(&interaction).header("origin", &origin).header("origin", "https://other.example")
                .header("cookie", &cookie).header("content-type", "application/x-www-form-urlencoded").body(form.clone()).send().unwrap().status(), 403);
            assert_eq!(owner_browser.post(&interaction).header("origin", &origin).header("host", "other.example")
                .header("cookie", &cookie).header("content-type", "application/x-www-form-urlencoded").body(form).send().unwrap().status(), 421);
            assert_eq!(
                decide(
                    &owner_browser,
                    &interaction,
                    "https://other.example",
                    &cookie,
                    &csrf,
                    "allow"
                )
                .status(),
                403
            );
            assert_eq!(
                decide(
                    &owner_browser,
                    &interaction,
                    &origin,
                    &cookie,
                    "wrong-ticket",
                    "allow"
                )
                .status(),
                403
            );
            let response = decide(
                &owner_browser,
                &interaction,
                &origin,
                &cookie,
                &csrf,
                if allow { "allow" } else { "deny" },
            );
            assert_eq!(response.status(), 303);
            let location = response.headers()["location"].to_str().unwrap().to_owned();
            assert_eq!(location.split('?').next(), Some(callback.as_str()));
            assert_eq!(transport.0.get(&location).send().unwrap().status(), 204);
            assert_ne!(
                decide(
                    &owner_browser,
                    &interaction,
                    &origin,
                    &cookie,
                    &csrf,
                    "allow"
                )
                .status(),
                303
            );
            client.accept_redirect(&location, now()).unwrap();
            std::thread::sleep(Duration::from_secs(5));
            let outcome = client.continue_grant(now());
            if !allow {
                assert!(matches!(outcome, Err(gnap_client::ClientError::Server(error)) if error.code == gnap_registry::ErrorCode::UserDenied));
                assert!(client.usable_tokens(now()).is_none());
                continue;
            }
            let step = outcome.unwrap();
            assert!(matches!(step, Step::Approved(_)));
            assert!(step.response().r#continue.is_none());
            let token = client.usable_tokens(now()).unwrap()[0].clone();
            assert_eq!(token.expires_in, Some(300));
            assert!(token.key.is_none());
            let read = |token: &gnap_types::token::AccessToken| {
                transport
                    .send(
                        sign_request(
                            HttpRequest::new("GET", format!("{origin}/resource/folder")),
                            signer(),
                            Some(&token.value),
                            now(),
                        )
                        .unwrap(),
                    )
                    .unwrap()
                    .status
            };
            assert_eq!(read(&token), 200);
            for path in ["/resource/archive", derivation::RS1_PATH, multiple::REPORTS_PATH] {
                let denied = transport.send(sign_request(HttpRequest::new("GET", format!("{origin}{path}")), signer(), Some(&token.value), now()).unwrap()).unwrap();
                assert_eq!(denied.status, 401, "external authority must not reach {path}");
            }
            client.rotate_token(None, now()).unwrap();
            let rotated = client.usable_tokens(now()).unwrap()[0].clone();
            assert_ne!(rotated.value, token.value);
            assert_eq!(read(&token), 401);
            assert_eq!(read(&rotated), 200);
            client.revoke_token(None, now()).unwrap();
            assert_eq!(read(&rotated), 401);
        }
    })
    .await
    .unwrap();
    server.abort();
    callback_server.abort();
}
