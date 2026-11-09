//! The proof method a session chooses at its start: its key, its requests,
//! and the lab's refusal of anything that doesn't match it.
use super::trace_session_tests::{lab, start_proving, status};
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
    let response = send("status", r#"{"proof":"jwsd"}"#.into()).await;
    assert!(
        response.status().is_client_error(),
        "a body on another action"
    );
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
    let finish = act(app, &id, "approve").await;
    act(
        app,
        &id,
        &format!("callback:{}", finish["redirect"].as_str().unwrap()),
    )
    .await;
    let wait = act(app, &id, "status").await["continuation_wait_seconds"]
        .as_u64()
        .unwrap();
    tokio::time::sleep(Duration::from_secs(wait)).await;
    act(app, &id, "continue").await;
    id
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
    let expanded = act(&app, &id, "continue").await;
    assert_eq!(expanded["token_present"], true);
    let view = act(&app, &id, "read-archive").await;
    assert!(view.get("error").is_none(), "{view}");
}

/// Two JOSE sessions of the same method keep apart: one's callback is no
/// other's, and each grant names its own key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_jose_sessions_of_one_method_keep_apart() {
    let (app, router, origin) = lab(SESSION_LIFETIME).await;
    let a = start_proving(&router, &origin, "start", r#"{"proof":"jwsd"}"#).await;
    let b = start_proving(&router, &origin, "start", r#"{"proof":"jwsd"}"#).await;
    let finish_a = act(&app, &a, "approve").await;
    let crossed = dispatch(
        &app,
        b.clone(),
        format!("callback:{}", finish_a["redirect"].as_str().unwrap()),
    )
    .await;
    assert!(crossed.is_err(), "A's callback is not B's");
    let keys: Vec<_> = {
        let ids: Vec<_> = app
            .storage
            .lock()
            .unwrap()
            .continuation_deadlines
            .keys()
            .copied()
            .collect();
        ids.into_iter()
            .map(|grant| {
                let snapshot = app
                    .storage
                    .lookup(GrantSelector::Id(grant))
                    .unwrap()
                    .unwrap();
                lab::presented_thumbprint(&snapshot.aggregate.record.request.client).unwrap()
            })
            .collect()
    };
    assert_eq!(keys.len(), 2);
    assert_ne!(keys[0], keys[1], "each session presents its own key");
}
