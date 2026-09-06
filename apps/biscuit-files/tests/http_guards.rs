use axum::{
    body::Body,
    http::{Request, Version},
    routing::get,
    Router,
};
use gnap_biscuit_files::http::{self, Origin};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::Semaphore;
use tower::ServiceExt;

#[tokio::test]
async fn canonical_authority_handles_real_http_versions_and_ignores_forwarded() {
    let router = http::guarded(
        Router::new()
            .route("/probe", get(|| async { "ok" }))
            .route("/health", get(|| async { "ok" })),
        Origin::parse("https://files.example").unwrap(),
    );
    for (target, host, version, expected) in [
        ("/probe", Some("files.example"), Version::HTTP_11, 200),
        ("/probe", Some("alias.example"), Version::HTTP_11, 421),
        ("/probe", None, Version::HTTP_11, 400),
        ("https://files.example/probe", None, Version::HTTP_2, 200),
        ("http://files.example/probe", None, Version::HTTP_2, 200),
        (
            "https://alias.example/probe",
            Some("files.example"),
            Version::HTTP_2,
            400,
        ),
        ("/probe", Some("files.example:bad"), Version::HTTP_11, 400),
        ("/health", Some("alias.example"), Version::HTTP_11, 200),
    ] {
        let mut request = Request::builder()
            .uri(target)
            .version(version)
            .header("forwarded", "host=files.example;proto=https");
        if let Some(host) = host {
            request = request.header("host", host);
        }
        let response = router
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(response.headers().get("location").is_none());
        assert!(response.headers().get("set-cookie").is_none());
    }
    let request = Request::builder()
        .uri("/probe")
        .header("host", "files.example")
        .header("host", "files.example")
        .body(Body::empty())
        .unwrap();
    assert_eq!(router.oneshot(request).await.unwrap().status(), 400);
}

#[tokio::test]
async fn cancelled_http_waiter_does_not_release_running_cpu_worker() {
    let workers = Arc::new(Semaphore::new(1));
    let origin = Origin::parse("http://127.0.0.1:18080").unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (finish_tx, finish_rx) = std::sync::mpsc::channel();
    let done = Arc::new(AtomicBool::new(false));
    let worker_semaphore = workers.clone();
    let job_done = done.clone();
    let waiter = tokio::spawn(async move {
        http::dispatch(
            Request::builder()
                .uri("/probe")
                .body(Body::empty())
                .unwrap(),
            &origin,
            worker_semaphore,
            move |_| {
                let _ = started_tx.send(());
                finish_rx.recv().unwrap();
                job_done.store(true, Ordering::SeqCst);
                http::denied(400)
            },
        )
        .await
    });
    started_rx.await.unwrap();
    waiter.abort();
    assert_eq!(workers.available_permits(), 0);
    let refused = http::dispatch(
        Request::builder()
            .uri("/probe")
            .body(Body::empty())
            .unwrap(),
        &Origin::parse("http://127.0.0.1:18080").unwrap(),
        workers.clone(),
        |_| panic!("full worker queue accepted work"),
    )
    .await;
    assert_eq!(refused.status(), 503);
    finish_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while workers.available_permits() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(done.load(Ordering::SeqCst));
}

#[test]
fn origins_reject_remote_http_credentials_and_noncanonical_forms() {
    for origin in [
        "http://files.example",
        "https://files.example/",
        "https://user@files.example",
        "https://FILES.example",
        "https://files.example/path",
        "https://files.example?query=1",
    ] {
        assert!(Origin::parse(origin).is_err());
    }
    assert!(Origin::parse("http://[::1]:18080").is_ok());
}
