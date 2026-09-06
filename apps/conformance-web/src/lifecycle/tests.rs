use super::*;
use axum::{
    body::{to_bytes, Body},
    http::Request,
};
use std::sync::OnceLock;
use tower::ServiceExt;

fn target() -> Target {
    Target {
        name: "Synthetic test".into(),
        grant: "https://as.example/gnap".into(),
        continuation: "https://as.example/continue".into(),
        interaction: "https://as.example/interact/".into(),
        management: "https://as.example/token/".into(),
        resource: "https://rs.example/resource/folder".into(),
    }
}

fn fixture_signer() -> Arc<Ps256Signer> {
    static KEY: OnceLock<Arc<Ps256Signer>> = OnceLock::new();
    KEY.get_or_init(|| {
        Arc::new(
            Ps256Signer::from_pkcs1_pem(
                include_str!("../../../../crates/gnap-crypto/tests/rfc9421-b12.pkcs1.pem"),
                "workbench-test",
            )
            .unwrap(),
        )
    })
    .clone()
}

fn state() -> Lifecycle {
    Lifecycle(Some(Arc::new(Inner {
        origin: "https://workbench.example".into(),
        local: false,
        targets: vec![target()],
        signer: fixture_signer(),
        wrong_signer: fixture_signer(),
        probes: crate::probe::Probes::disabled(),
        workers: Arc::new(Semaphore::new(4)),
        sessions: Mutex::new(HashMap::new()),
    })))
}

async fn bytes(response: Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), 16_384)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

#[test]
fn configuration_and_destinations_never_follow_response_urls_freely() {
    let t = target();
    let raw = serde_json::to_string(&vec![t.clone()]).unwrap();
    assert_eq!(config::targets(&raw, false).unwrap().len(), 1);
    assert!(t.permits("POST", &t.grant));
    assert!(t.permits("DELETE", "https://as.example/token/abc_-12"));
    for uri in [
        "https://as.example/token/",
        "https://as.example/token/../gnap",
        "https://as.example/token/abc?secret=x",
        "https://as.example/token/abc/def",
        "https://as.example/token/abc%2fdef",
        "https://evil.example/token/abc",
    ] {
        assert!(!t.permits("DELETE", uri), "{uri}");
    }
    assert!(!t.permits("GET", &t.continuation));
    assert!(!t.permits("GET", "https://rs.example/resource/folder?x=1"));
    for raw in [
        "https://user@as.example/gnap",
        "https://as.example:444/gnap",
        "http://as.example/gnap",
        "https://127.0.0.1/gnap",
        "https://as.example/gnap#x",
        "https://as.example/gnap?x=1",
        "https://as.example/a/../gnap",
        "https://AS.EXAMPLE/gnap",
    ] {
        assert!(config::endpoint(raw, false).is_err(), "{raw}");
    }
    assert!(config::endpoint("http://127.0.0.1:18081/gnap", false).is_err());
    assert!(config::endpoint("http://127.0.0.1:18081/gnap", true).is_ok());
    assert!(config::endpoint("http://10.0.0.1/gnap", true).is_err());
    assert!(config::origin("https://workbench.example").is_ok());
    for origin in [
        "https://workbench.example/",
        "https://user@workbench.example",
        "http://workbench.example",
        "https://workbench.example/path",
    ] {
        assert!(config::origin(origin).is_err());
    }
    assert!(config::targets(&serde_json::to_string(&vec![t; 5]).unwrap(), false).is_err());
}

#[tokio::test]
async fn disabled_feature_keeps_diagnostics_available_and_exposes_no_key() {
    let router = crate::app();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/lifecycle/key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/lifecycle/targets")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bytes(response).await, "[]");
}

#[tokio::test]
async fn public_key_is_only_public_and_does_not_start_work() {
    let state = state();
    let response = state
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .uri("/api/lifecycle/key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let raw: Value = serde_json::from_str(&bytes(response).await).unwrap();
    assert_eq!(raw["jwk"]["kty"], "RSA");
    assert_eq!(raw["jwk"]["alg"], "PS256");
    for field in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        assert!(raw["jwk"].get(field).is_none());
    }
    assert_eq!(
        raw["callback"],
        "https://workbench.example/lifecycle/callback"
    );
    assert_eq!(state.0.unwrap().sessions.lock().unwrap().len(), 0);
}

#[tokio::test]
async fn start_refuses_cross_origin_bad_envelopes_and_capacity_without_network() {
    let state = state();
    for (host, origin, body, expected) in [
        (
            "workbench.example",
            "https://evil.example",
            r#"{"target_id":0,"consent":true}"#,
            StatusCode::FORBIDDEN,
        ),
        (
            "evil.example",
            "https://workbench.example",
            r#"{"target_id":0,"consent":true}"#,
            StatusCode::FORBIDDEN,
        ),
        (
            "workbench.example",
            "https://workbench.example",
            r#"{"target_id":0,"consent":false}"#,
            StatusCode::BAD_REQUEST,
        ),
        (
            "workbench.example",
            "https://workbench.example",
            r#"{"target_id":0,"consent":true,"url":"TOP-SECRET"}"#,
            StatusCode::BAD_REQUEST,
        ),
        (
            "workbench.example",
            "https://workbench.example",
            r#"{"target_id":9,"consent":true}"#,
            StatusCode::NOT_FOUND,
        ),
    ] {
        let response = state
            .clone()
            .router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/lifecycle/start")
                    .header("host", host)
                    .header("origin", origin)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert!(!bytes(response).await.contains("TOP-SECRET"));
    }
    let permit = state
        .0
        .as_ref()
        .unwrap()
        .workers
        .clone()
        .acquire_many_owned(4)
        .await
        .unwrap();
    let response = state
        .clone()
        .router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/lifecycle/start")
                .header("host", "workbench.example")
                .header("origin", "https://workbench.example")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"target_id":0,"consent":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(state.0.as_ref().unwrap().sessions.lock().unwrap().len(), 0);
    drop(permit);
}

#[test]
fn shared_cooldown_and_cookie_parsing_are_fail_closed() {
    let probes = crate::probe::Probes::disabled();
    assert!(probes.admit().is_ok());
    assert_eq!(probes.clone().admit(), Err(StatusCode::TOO_MANY_REQUESTS));
    let id = "abcdefghijklmnopqrstuv";
    let mut headers = HeaderMap::new();
    headers.insert("cookie", format!("gnap_lifecycle={id}").parse().unwrap());
    assert_eq!(cookie(&headers), Some(id));
    headers.append("cookie", format!("gnap_lifecycle={id}").parse().unwrap());
    assert_eq!(cookie(&headers), None);
}

#[tokio::test]
async fn callback_without_matching_live_cookie_cannot_reach_a_worker() {
    let state = state();
    for cookie in [None, Some("gnap_lifecycle=abcdefghijklmnopqrstuv")] {
        let mut request = Request::builder()
            .uri("/lifecycle/callback?hash=TOP-SECRET&interact_ref=secret")
            .header("host", "workbench.example");
        if let Some(cookie) = cookie {
            request = request.header("cookie", cookie);
        }
        let response = state
            .clone()
            .router()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(!bytes(response).await.contains("TOP-SECRET"));
    }
}

#[tokio::test]
async fn bounded_network_runs_on_a_dedicated_thread_and_rejects_redirects_and_oversize() {
    use gnap_client::{HttpRequest, HttpTransport};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/ok", get(|| async { "ok" }))
        .route("/large", get(|| async { "x".repeat(8193) }))
        .route(
            "/redirect",
            get(|| async {
                (
                    StatusCode::FOUND,
                    [("location", "http://169.254.169.254/secret")],
                )
            }),
        );
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let runtime = tokio::runtime::Handle::current();
    for (path, expected) in [
        ("/ok", Some(200)),
        ("/large", None),
        ("/redirect", Some(302)),
    ] {
        let mut target = target();
        target.resource = format!("http://{address}{path}");
        let runtime = runtime.clone();
        let result = tokio::task::spawn_blocking(move || {
            let network = network::Network::new(target, true, runtime);
            let response = network.send(HttpRequest::new("GET", &network.target.resource));
            assert!(network
                .send(HttpRequest::new("GET", "http://169.254.169.254/secret"))
                .is_err());
            assert!(
                network.last().is_none(),
                "failure clears previous captured response"
            );
            response.ok().map(|r| r.status)
        })
        .await
        .unwrap();
        assert_eq!(result, expected);
    }
    server.abort();
}
