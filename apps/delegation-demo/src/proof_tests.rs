//! The proof method a session chooses at its start: its key, its requests,
//! and the lab's refusal of anything that doesn't match it.
use super::trace_session_tests::{lab, observed_lab, start_proving, status};
use super::*;
use tower::ServiceExt;

/// The last recorded attempt's announced proof and route.
fn last_attempt(view: &Value) -> (String, String) {
    let attempts = view["trace"]["attempts"].as_array().unwrap();
    let last = &attempts[attempts.len() - 1]["request"];
    (
        last["proof"].as_str().unwrap().to_owned(),
        last["route"].as_str().unwrap().to_owned(),
    )
}

async fn act(app: &App, id: &str, action: &str) -> Value {
    dispatch(app, id.to_owned(), action.to_owned())
        .await
        .unwrap()
}

/// Consent in the browser, then the whole use of the grant, for each proof
/// method: every request proves with the method the session chose. A `jws`
/// request without content carries its JWS detached, in the `Detached-JWS`
/// field (RFC 9635 §7.3.4), which is what the record observes for a read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_proof_method_runs_the_whole_lab() {
    let (app, router, origin) = lab(SESSION_LIFETIME).await;
    for (method, alg, bodiless) in [
        ("jwsd", "EdDSA", "jwsd"),
        ("jws", "EdDSA", "jwsd"),
        ("httpsig", "PS256", "httpsig"),
    ] {
        let id = start_proving(
            &router,
            &origin,
            "start",
            &format!(r#"{{"proof":"{method}"}}"#),
        )
        .await;
        let view = status(&router, &origin, Some(&id)).await;
        assert_eq!(
            view["proof"],
            json!({"method": method, "alg": alg}),
            "{method}"
        );
        assert_eq!(last_attempt(&view), (method.to_owned(), "grant".to_owned()));

        let finish = act(&app, &id, "approve").await;
        act(
            &app,
            &id,
            &format!("callback:{}", finish["redirect"].as_str().unwrap()),
        )
        .await;
        let wait = act(&app, &id, "status").await["continuation_wait_seconds"]
            .as_u64()
            .unwrap();
        tokio::time::sleep(Duration::from_secs(wait)).await;
        let approved = act(&app, &id, "continue").await;
        assert_eq!(approved["token_present"], true, "{method}: {approved}");

        for action in ["read", "read-metadata", "read-archive"] {
            let view = act(&app, &id, action).await;
            assert!(view.get("error").is_none(), "{method} {action}: {view}");
            assert_eq!(last_attempt(&view).0, bodiless, "{method} {action}");
            if action == "read-metadata" {
                // The documents server derived a token for the metadata one.
                assert_eq!(
                    view["folder"]["derived_right"],
                    derivation::METADATA_READ,
                    "{method}: {view}"
                );
            }
        }
        let view = act(&app, &id, "read").await;
        assert_eq!(view["folder"]["granted_right"], FOLDER_READ, "{method}");
        act(&app, &id, "rotate").await;
        let view = act(&app, &id, "read").await;
        assert_eq!(
            view["folder"]["granted_right"], FOLDER_READ,
            "{method} after rotation"
        );
        act(&app, &id, "revoke").await;
        let view = act(&app, &id, "check-retired").await;
        assert!(
            view.get("error").is_none(),
            "{method}: the retired token is refused"
        );
        assert_eq!(
            last_attempt(&view),
            (bodiless.to_owned(), "folder".to_owned())
        );
    }
}

/// The second screen and the two-token request, with a session's own key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_second_screen_and_two_tokens_take_a_jose_proof() {
    let (app, router, origin) = lab(SESSION_LIFETIME).await;

    let id = start_proving(&router, &origin, "start-multiple", r#"{"proof":"jwsd"}"#).await;
    let finish = act(&app, &id, "approve-reports").await;
    act(
        &app,
        &id,
        &format!("callback:{}", finish["redirect"].as_str().unwrap()),
    )
    .await;
    let wait = act(&app, &id, "status").await["continuation_wait_seconds"]
        .as_u64()
        .unwrap();
    tokio::time::sleep(Duration::from_secs(wait)).await;
    act(&app, &id, "continue").await;
    let view = act(&app, &id, "read-reports").await;
    assert!(view.get("error").is_none(), "{view}");
    assert_eq!(
        last_attempt(&view),
        ("jwsd".to_owned(), "reports".to_owned())
    );

    let id = start_proving(&router, &origin, "start-code", r#"{"proof":"jws"}"#).await;
    let view = act(&app, &id, "status").await;
    assert_eq!(last_attempt(&view), ("jws".to_owned(), "grant".to_owned()));
    assert!(view["user_code_uri"]["code"].is_string());
}

/// A token bound to a session's own key is refused with any other key: the
/// shared key, or a key the lab never registered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_jose_sessions_token_proves_only_with_its_key() {
    let (app, router, origin) = lab(SESSION_LIFETIME).await;
    let id = start_proving(&router, &origin, "start", r#"{"proof":"jwsd"}"#).await;
    let finish = act(&app, &id, "approve").await;
    act(
        &app,
        &id,
        &format!("callback:{}", finish["redirect"].as_str().unwrap()),
    )
    .await;
    let wait = act(&app, &id, "status").await["continuation_wait_seconds"]
        .as_u64()
        .unwrap();
    tokio::time::sleep(Duration::from_secs(wait)).await;
    act(&app, &id, "continue").await;

    let token = {
        let ids: Vec<_> = app
            .storage
            .lock()
            .unwrap()
            .continuation_deadlines
            .keys()
            .copied()
            .collect();
        ids.into_iter()
            .find_map(|grant| {
                let snapshot = app.storage.lookup(GrantSelector::Id(grant)).unwrap()?;
                snapshot
                    .aggregate
                    .tokens
                    .values()
                    .next()
                    .map(|token| token.token.value.clone())
            })
            .unwrap()
    };
    let path = format!("{origin}/resource/folder");
    let foreign = gnap_crypto::Ed25519Signer::generate("foreign").unwrap();
    for request in [
        sign_request(
            HttpRequest::new("GET", &path),
            app.signer.as_ref(),
            Some(&token),
            now(),
        )
        .unwrap(),
        gnap_client::sign_jose_request(
            HttpRequest::new("GET", &path),
            gnap_crypto::jws::JwsMethod::Jwsd,
            &foreign,
            Some(&token),
            now(),
        )
        .unwrap(),
    ] {
        let reader = app.clone();
        let refused =
            tokio::task::spawn_blocking(move || read_resource(&reader, &request).is_err())
                .await
                .unwrap();
        assert!(refused);
    }
}

/// A start's body names a proof method and nothing else, and a refused body
/// creates no session, no key and no grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_body_is_read_strictly() {
    let (app, router, origin) = lab(SESSION_LIFETIME).await;
    let send = |action: &'static str, body: String| {
        let router = router.clone();
        let origin = origin.clone();
        async move {
            router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/api/{action}"))
                        .header("host", origin.strip_prefix("http://").unwrap())
                        .header("origin", &origin)
                        .body(axum::body::Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap()
        }
    };
    let before = app.storage.lab.lock().unwrap().count();
    for body in [
        r#"{"proof":null}"#.to_owned(),
        r#"["jwsd"]"#.to_owned(),
        r#"{"proof":"jwsd","proof":"jws"}"#.to_owned(),
        r#"{"proof":"jwsd","x":1}"#.to_owned(),
        r#"{"proof":"mtls"}"#.to_owned(),
        r#"{}"#.to_owned(),
        format!(r#"{{"proof":"jwsd"}}{}"#, " ".repeat(lab::MAX_START_BODY)),
    ] {
        let response = send("start", body.clone()).await;
        assert!(
            response.status().is_client_error(),
            "{body}: {}",
            response.status()
        );
        assert!(!response.headers().contains_key("set-cookie"), "{body}");
    }
    for action in ["start-identity", "start-push"] {
        let response = send(action, r#"{"proof":"jwsd"}"#.into()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{action}");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&body).contains("use HTTP message signatures in this lab"),
            "{action} is refused for its proof, before anything else"
        );
    }
    // Any other action carries no body, whatever it says.
    for action in ["continue", "read"] {
        let response = send(action, r#"{"proof":"jwsd"}"#.into()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{action}");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(
            String::from_utf8_lossy(&body).contains("Unexpected request body"),
            "{action} is refused for its body"
        );
    }
    assert_eq!(app.storage.lab.lock().unwrap().count(), before);
    assert!(
        app.storage
            .lock()
            .unwrap()
            .continuation_deadlines
            .is_empty(),
        "no grant was created"
    );
}

/// Only the key a live session registered, with its own proof and nothing
/// else, is the lab's; any other key presented by value goes no further.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_a_registered_key_with_its_proof_is_resolved() {
    let lifetime = Duration::from_secs(3);
    let (app, router, origin) = lab(lifetime).await;
    let id = start_proving(&router, &origin, "start", r#"{"proof":"jwsd"}"#).await;
    let presented = {
        let ids: Vec<_> = app
            .storage
            .lock()
            .unwrap()
            .continuation_deadlines
            .keys()
            .copied()
            .collect();
        let snapshot = app
            .storage
            .lookup(GrantSelector::Id(ids[0]))
            .unwrap()
            .unwrap();
        snapshot.aggregate.record.request.client
    };
    assert!(
        presented.as_value().is_some(),
        "the JOSE session presents its key"
    );
    let resolver = KnownKeys {
        signer: app.signer.clone(),
        rs_key: app.rs_registration.key.clone(),
        decisions: app.decisions.clone(),
        lab: app.storage.lab.clone(),
    };
    assert!(resolver.resolve(&presented).is_some());

    let mut other_proof = serde_json::to_value(&presented).unwrap();
    other_proof["key"]["proof"] = json!("jws");
    let other_proof: Client = serde_json::from_value(other_proof).unwrap();
    assert!(
        resolver.resolve(&other_proof).is_none(),
        "the same key with another proof"
    );

    let stranger = gnap_crypto::Ed25519Signer::generate("stranger").unwrap();
    let stranger: Client = serde_json::from_value(
        json!({"key": {"proof": "jwsd", "jwk": stranger.public_jwk().unwrap()}}),
    )
    .unwrap();
    assert!(
        resolver.resolve(&stranger).is_none(),
        "a key the lab never registered"
    );

    // Once the session's lifetime ends, its key is no longer the lab's.
    tokio::time::sleep(lifetime + Duration::from_secs(1)).await;
    assert!(resolver.resolve(&presented).is_none());
    assert!(status(&router, &origin, Some(&id))
        .await
        .get("trace")
        .is_none_or(Value::is_null));
}

async fn approved(app: &App, router: &Router, origin: &str, proof: &str) -> String {
    let id = start_proving(
        router,
        origin,
        "start",
        &format!(r#"{{"proof":"{proof}"}}"#),
    )
    .await;
    consent(app, router, origin, &id).await;
    act(app, &id, "continue").await;
    id
}

/// Opens the session's interaction page as its browser would, with its
/// cookie, then approves and follows the callback, and waits for the
/// continuation to answer again.
async fn consent(app: &App, router: &Router, origin: &str, id: &str) {
    let uri = act(app, id, "status").await["interaction_uri"]
        .as_str()
        .unwrap()
        .to_owned();
    let page = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri.strip_prefix(origin).unwrap())
                .header("host", origin.strip_prefix("http://").unwrap())
                .header("cookie", format!("gnap_demo={id}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK, "the lab's own page, {uri}");
    let body = axum::body::to_bytes(page.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        String::from_utf8_lossy(&body).contains("Proof for the next start"),
        "the lab's page, not the external client's"
    );
    let finish = act(app, id, "approve").await;
    act(
        app,
        id,
        &format!("callback:{}", finish["redirect"].as_str().unwrap()),
    )
    .await;
    let wait = act(app, id, "status").await["continuation_wait_seconds"]
        .as_u64()
        .unwrap();
    tokio::time::sleep(Duration::from_secs(wait)).await;
}

/// A JOSE session changes its grant as the others do: a reduction directly,
/// an expansion after a new consent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_jose_session_reduces_then_expands_its_grant() {
    let (app, router, origin) = lab(SESSION_LIFETIME).await;
    let id = approved(&app, &router, &origin, "jwsd").await;
    // The continuation answers again only after its wait.
    let wait = act(&app, &id, "status").await["continuation_wait_seconds"]
        .as_u64()
        .unwrap();
    tokio::time::sleep(Duration::from_secs(wait)).await;
    let reduced = act(&app, &id, "downscope").await;
    assert_eq!(reduced["rights"], json!([FOLDER_READ]), "{reduced}");
    assert_eq!(
        last_attempt(&reduced),
        ("jwsd".to_owned(), "continue".to_owned())
    );
    let wait = reduced["continuation_wait_seconds"].as_u64().unwrap_or(0);
    tokio::time::sleep(Duration::from_secs(wait)).await;
    let pending = act(&app, &id, "expand").await;
    assert_eq!(pending["state"], "pending", "{pending}");
    consent(&app, &router, &origin, &id).await;
    let expanded = act(&app, &id, "continue").await;
    assert_eq!(expanded["token_present"], true);
    let view = act(&app, &id, "read-archive").await;
    assert!(view.get("error").is_none(), "{view}");
}

/// Two JOSE sessions of the same method keep apart: each callback finishes
/// only its own session, and each grant names its own key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_jose_sessions_of_one_method_keep_apart() {
    let (app, router, origin) = lab(SESSION_LIFETIME).await;
    let a = start_proving(&router, &origin, "start", r#"{"proof":"jwsd"}"#).await;
    let b = start_proving(&router, &origin, "start", r#"{"proof":"jwsd"}"#).await;
    // Both await their callback, so a refusal can only come from the binding.
    let redirect = |finish: Value| finish["redirect"].as_str().unwrap().to_owned();
    let finish_a = redirect(act(&app, &a, "approve").await);
    let finish_b = redirect(act(&app, &b, "approve").await);
    for (session, other) in [(&b, &finish_a), (&a, &finish_b)] {
        let crossed = dispatch(&app, session.clone(), format!("callback:{other}")).await;
        assert!(crossed.is_err(), "another session's callback");
    }
    for (session, own) in [(&a, &finish_a), (&b, &finish_b)] {
        act(&app, session, &format!("callback:{own}")).await;
        let wait = act(&app, session, "status").await["continuation_wait_seconds"]
            .as_u64()
            .unwrap();
        tokio::time::sleep(Duration::from_secs(wait)).await;
        let view = act(&app, session, "continue").await;
        assert_eq!(view["token_present"], true, "{view}");
    }
    let keys: Vec<_> = grants(&app)
        .iter()
        .map(|snapshot| {
            lab::presented_thumbprint(&snapshot.aggregate.record.request.client).unwrap()
        })
        .collect();
    assert_eq!(keys.len(), 2);
    assert_ne!(keys[0], keys[1], "each session presents its own key");
}

/// Every grant the lab's authorization server holds.
fn grants(app: &App) -> Vec<gnap_as::storage::GrantSnapshot> {
    let ids: Vec<_> = app
        .storage
        .lock()
        .unwrap()
        .continuation_deadlines
        .keys()
        .copied()
        .collect();
    ids.into_iter()
        .filter_map(|grant| app.storage.lookup(GrantSelector::Id(grant)).unwrap())
        .collect()
}

/// The access token of the grant whose client presents `key`.
fn token_of(app: &App, key: &gnap_crypto::Ed25519Signer) -> gnap_types::token::TokenValue {
    let jwk = key.public_jwk().unwrap();
    grants(app)
        .into_iter()
        .find(|snapshot| {
            snapshot
                .aggregate
                .record
                .request
                .client
                .as_value()
                .and_then(|value| value.key.as_value())
                .and_then(|key| key.jwk.as_ref())
                == Some(&jwk)
        })
        .and_then(|snapshot| {
            snapshot
                .aggregate
                .tokens
                .values()
                .next()
                .map(|token| token.token.value.clone())
        })
        .unwrap()
}

/// Sends a signed request over the network, as a client would.
async fn send(request: &HttpRequest) -> u16 {
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let mut outgoing = client.request(request.method.parse().unwrap(), &request.url);
    for (name, value) in &request.headers {
        outgoing = outgoing.header(name, value);
    }
    if let Some(body) = &request.body {
        outgoing = outgoing.body(body.clone());
    }
    outgoing.send().await.unwrap().status().as_u16()
}

/// Two live JOSE sessions: neither key proves the other's token, and a JOSE
/// proof is accepted once, by the resource server as by the authorization
/// server, and refused when it comes again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_jose_proof_proves_its_own_token_once() {
    let (app, router, origin, generated) = observed_lab(SESSION_LIFETIME, None).await;
    let a = approved(&app, &router, &origin, "jwsd").await;
    let b = approved(&app, &router, &origin, "jwsd").await;
    let keys: std::collections::HashMap<_, _> = generated.try_iter().collect();
    let (key_a, key_b) = (keys[&a].clone(), keys[&b].clone());
    let (token_a, token_b) = (token_of(&app, &key_a), token_of(&app, &key_b));
    assert_ne!(token_a, token_b);

    let read = |key: &gnap_crypto::Ed25519Signer, token: &gnap_types::token::TokenValue| {
        gnap_client::sign_jose_request(
            HttpRequest::new("GET", format!("{origin}/resource/folder")),
            gnap_crypto::jws::JwsMethod::Jwsd,
            key,
            Some(token),
            now(),
        )
        .unwrap()
    };
    assert_eq!(
        send(&read(&key_b, &token_a)).await,
        401,
        "B's key, A's token"
    );
    assert_eq!(
        send(&read(&key_a, &token_b)).await,
        401,
        "A's key, B's token"
    );
    let own = read(&key_a, &token_a);
    assert_eq!(send(&own).await, 200, "A's key, A's token");
    assert_eq!(send(&own).await, 401, "the same proof again");

    // A grant request signed by A's key, sent twice.
    let references = app.bootstrap.get().unwrap().as_ref().unwrap().clone();
    let body = json!({
        "client": {"key": {"proof": "jwsd", "jwk": key_a.public_jwk().unwrap()}},
        "access_token": {"access": [&references.both]},
        "interact": {"start": ["redirect"], "finish": {"method": "redirect", "uri": format!("{origin}/callback"), "nonce": "replay-test-nonce"}}
    });
    let mut request = HttpRequest::new("POST", format!("{origin}/gnap"));
    request
        .headers
        .push(("content-type".into(), "application/json".into()));
    request.body = Some(serde_json::to_vec(&body).unwrap());
    let signed = gnap_client::sign_jose_request(
        request,
        gnap_crypto::jws::JwsMethod::Jwsd,
        key_a.as_ref(),
        None,
        now(),
    )
    .unwrap();
    assert_eq!(send(&signed).await, 200, "A's grant request");
    assert_ne!(send(&signed).await, 200, "the same grant request again");
}

/// A start that fails once its client is registered gives its place in the
/// registry back, whichever its proof method.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_start_gives_its_registration_back() {
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("http://{}", listener.local_addr().unwrap())
    };
    let (app, router, origin, generated) = observed_lab(SESSION_LIFETIME, Some(closed)).await;
    let before = app.storage.lab.lock().unwrap().count();
    for body in [r#"{"proof":"jwsd"}"#, r#"{"proof":"httpsig"}"#] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/start")
                    .header("host", origin.strip_prefix("http://").unwrap())
                    .header("origin", &origin)
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(response.status(), StatusCode::OK, "{body}");
        assert_eq!(app.storage.lab.lock().unwrap().count(), before, "{body}");
    }
    assert_eq!(
        generated.try_iter().count(),
        1,
        "the JOSE start went as far as its key"
    );
}

/// A JOSE read waits for a later second than the last one, on the monotonic
/// clock and for a bounded time: a wall clock set back can't hold the worker.
#[test]
fn a_jose_read_waits_for_a_later_second_but_not_forever() {
    let budget = Duration::from_millis(300);
    let started = Instant::now();
    assert_eq!(fresh_second(100, || 90, budget), None);
    assert_eq!(fresh_second(100, || 100, budget), None);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(fresh_second(100, || 101, budget), Some(101));
    let ticks = std::cell::Cell::new(99);
    let advancing = || {
        ticks.set(ticks.get() + 1);
        ticks.get()
    };
    assert_eq!(fresh_second(100, advancing, budget), Some(101));
}
