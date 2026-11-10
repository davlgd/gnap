//! The GNAP diagnostic workbench: a web page over the checks of
//! [`gnap_conformance`], and opt-in authenticated scenarios. Imports remain
//! stateless. This is not a certification suite.

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Request},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

pub use gnap_conformance::{
    Check, Import, MAX_MESSAGE, MAX_UPLOAD, MessageKind, Observation, Report, RsContext, Status,
    TokenBinding, analyze, cli, discovery, net, observation, scenario,
};
pub mod lifecycle;
pub mod probe;

pub fn app() -> Router {
    app_with_probes(probe::Probes::disabled())
}

pub fn app_with_probes(probes: probe::Probes) -> Router {
    app_with_lifecycle(probes, lifecycle::Lifecycle::disabled())
}

pub fn app_with_lifecycle(probes: probe::Probes, lifecycle: lifecycle::Lifecycle) -> Router {
    let permits = Arc::new(Semaphore::new(16));
    Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("../static/index.html")) }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../static/app.js"),
                )
            }),
        )
        // The suite's shared design, from `apps/ui`.
        .route(
            "/assets/gnap.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../../ui/gnap.css"),
                )
            }),
        )
        .route(
            "/assets/gnap.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../../ui/gnap.js"),
                )
            }),
        )
        // The workbench is one page: each tool is a section of it.
        .route("/inspect", get(|| async { Redirect::to("/#inspect") }))
        .route("/probe", get(|| async { Redirect::to("/#probe-endpoint") }))
        .route("/health", get(|| async { "ok" }))
        .route("/api/analyze", post(import_handler))
        .route("/api/targets", get(probe::targets))
        .route("/api/probe", post(probe::handler))
        .with_state(probes)
        .merge(lifecycle.router())
        .layer(DefaultBodyLimit::max(MAX_UPLOAD))
        .layer(middleware::from_fn(move |request: Request, next: Next| {
            let permits = permits.clone();
            async move {
                let Ok(_permit) = permits.try_acquire_owned() else {
                    return secured(StatusCode::TOO_MANY_REQUESTS.into_response());
                };
                let response = tokio::time::timeout(Duration::from_secs(5), next.run(request))
                    .await
                    .unwrap_or_else(|_| StatusCode::REQUEST_TIMEOUT.into_response());
                secured(response)
            }
        }))
}

fn secured(mut response: Response) -> Response {
    for (name, value) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        (
            "content-security-policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
        ),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=()",
        ),
    ] {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    response
}

async fn import_handler(headers: axum::http::HeaderMap, body: Bytes) -> Response {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| {
            !v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/json")
        })
    {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Expected application/json.",
        )
            .into_response();
    }
    let Ok(input) = serde_json::from_slice::<Import>(&body) else {
        return (StatusCode::BAD_REQUEST, "Invalid import envelope. Expected kind and body string, with optional headers array and content_digest string. Use queried_endpoint and http_status for as_discovery, or an applicable rs_context object for RFC 9767 messages.").into_response();
    };
    match analyze(&input) {
        Ok(report) => Json(report).into_response(),
        Err(reason) => (StatusCode::BAD_REQUEST, reason).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt;

    fn imported(kind: MessageKind, body: &str) -> Import {
        Import {
            kind,
            body: body.into(),
            headers: None,
            content_digest: None,
            rs_context: None,
            queried_endpoint: None,
            http_status: None,
        }
    }
    fn status(report: &Report, id: &str) -> Status {
        report.checks.iter().find(|c| c.id == id).unwrap().status
    }

    #[test]
    fn shape_does_not_mean_certification() {
        let report = analyze(&imported(
            MessageKind::GrantRequest,
            r#"{"client":"demo-client"}"#,
        ))
        .unwrap();
        assert_eq!(status(&report, "message-shape"), Status::Pass);
        assert_eq!(status(&report, "key-presentation"), Status::NotTested);
        assert_eq!(status(&report, "request-proof"), Status::NotTested);
        assert!(!report.certification);
    }

    #[test]
    fn continuation_cannot_repeat_client() {
        let report = analyze(&imported(
            MessageKind::ContinueRequest,
            r#"{"client":"demo-client"}"#,
        ))
        .unwrap();
        assert_eq!(status(&report, "message-shape"), Status::Fail);
    }

    #[test]
    fn catches_semantic_key_error_after_deserializing() {
        let report = analyze(&imported(
            MessageKind::GrantRequest,
            r#"{"client":{"key":{"proof":"httpsig"}}}"#,
        ))
        .unwrap();
        assert_eq!(status(&report, "message-shape"), Status::Pass);
        assert_eq!(status(&report, "key-presentation"), Status::Fail);
    }

    #[test]
    fn absent_and_captured_empty_headers_are_distinct() {
        let mut input = imported(MessageKind::GrantResponse, "{}");
        assert_eq!(
            status(
                &analyze(&imported(MessageKind::GrantResponse, "{}")).unwrap(),
                "response-no-store"
            ),
            Status::NotTested
        );
        input.headers = Some(vec![]);
        assert_eq!(
            status(&analyze(&input).unwrap(), "response-no-store"),
            Status::Fail
        );
        let mut input = imported(MessageKind::GrantResponse, "{}");
        input.headers = Some(vec![("cache-control".into(), "private, no-store".into())]);
        assert_eq!(
            status(&analyze(&input).unwrap(), "response-no-store"),
            Status::Pass
        );
    }

    #[test]
    fn digest_uses_exact_bytes_and_detects_tampering() {
        let mut input = imported(MessageKind::ContinueRequest, "{ }");
        input.content_digest = Some(gnap_crypto::content_digest(
            b"{}",
            gnap_crypto::DigestAlgorithm::Sha256,
        ));
        assert_eq!(
            status(&analyze(&input).unwrap(), "content-digest"),
            Status::Fail
        );
        let mut input = imported(MessageKind::ContinueRequest, "{}");
        input.content_digest = Some(gnap_crypto::content_digest(
            b"{}",
            gnap_crypto::DigestAlgorithm::Sha256,
        ));
        assert_eq!(
            status(&analyze(&input).unwrap(), "content-digest"),
            Status::Pass
        );
    }

    #[test]
    fn no_reflection_of_values_in_parser_or_validation_errors() {
        for body in [
            r#"{"client":123,"secret":"<script>TOP-SECRET</script>"}"#,
            r#"{"client":{"key":{"proof":"httpsig"},"display":{"uri":"TOP-SECRET"}}}"#,
        ] {
            let report = serde_json::to_string(
                &analyze(&imported(MessageKind::GrantRequest, body)).unwrap(),
            )
            .unwrap();
            assert!(!report.contains("TOP-SECRET"));
            assert!(!report.contains("<script>"));
        }
    }

    #[test]
    fn message_and_header_limits() {
        assert!(
            analyze(&imported(
                MessageKind::ContinueRequest,
                &" ".repeat(MAX_MESSAGE + 1)
            ))
            .is_err()
        );
        let mut input = imported(MessageKind::ContinueRequest, "{}");
        input.headers = Some(vec![("x".into(), "secret\r\nheader".into())]);
        assert!(analyze(&input).is_err());
        let mut input = imported(MessageKind::ContinueRequest, "{}");
        input.headers = Some(vec![("x".into(), "y".into()); 65]);
        assert!(analyze(&input).is_err());
    }

    #[tokio::test]
    async fn http_limits_headers_and_no_arbitrary_fetch_route() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/analyze")
                    .header("content-type", "application/json")
                    .body(Body::from(" ".repeat(MAX_UPLOAD + 1)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/probe?url=http://169.254.169.254")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    /// Every page loads only same-origin assets that this server serves with
    /// their exact type, under the workbench's CSP, and carries no inline
    /// style, script, or handler that the CSP would have to allow.
    #[tokio::test]
    async fn pages_load_only_served_assets_without_inline_code() {
        let get = |uri: &'static str| async move {
            let lifecycle = lifecycle::Lifecycle::disabled();
            app_with_lifecycle(probe::Probes::disabled(), lifecycle)
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap()
        };
        let csp = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";
        for (page, assets) in [
            ("/", ["/assets/gnap.css", "/assets/gnap.js", "/app.js"]),
            (
                "/lifecycle",
                ["/assets/gnap.css", "/assets/gnap.js", "/lifecycle.js"],
            ),
        ] {
            let response = get(page).await;
            assert_eq!(response.status(), StatusCode::OK, "{page}");
            assert_eq!(response.headers()["content-security-policy"], csp);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let html = String::from_utf8(body.to_vec()).unwrap();
            for forbidden in [
                "<style",
                " style=",
                "<script>",
                " onclick=",
                " onload=",
                "javascript:",
            ] {
                assert!(!html.contains(forbidden), "{page} carries {forbidden}");
            }
            for asset in assets {
                assert!(
                    html.contains(&format!("\"{asset}\"")),
                    "{page} loads {asset}"
                );
                let response = get(asset).await;
                assert_eq!(response.status(), StatusCode::OK, "{asset}");
                let kind = response.headers()["content-type"].to_str().unwrap();
                let expected = if asset.ends_with(".css") {
                    "text/css"
                } else {
                    "text/javascript"
                };
                assert!(kind.starts_with(expected), "{asset}: {kind}");
                assert_eq!(response.headers()["x-content-type-options"], "nosniff");
                assert_eq!(response.headers()["content-security-policy"], csp);
            }
        }
        let body = axum::body::to_bytes(get("/").await.into_body(), usize::MAX)
            .await
            .unwrap();
        let home = String::from_utf8(body.to_vec()).unwrap();
        for (alias, section) in [("/inspect", "/#inspect"), ("/probe", "/#probe-endpoint")] {
            let anchor = format!("id=\"{}\"", &section[2..]);
            assert_eq!(home.matches(&anchor).count(), 1, "{section}");
            let response = get(alias).await;
            assert!(response.status().is_redirection(), "{alias}");
            assert_eq!(response.headers()["location"], section);
        }
    }

    #[tokio::test]
    async fn http_bad_envelope_does_not_echo_secret() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/analyze")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"kind":"TOP-SECRET"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            !String::from_utf8(
                to_bytes(response.into_body(), MAX_UPLOAD)
                    .await
                    .unwrap()
                    .to_vec()
            )
            .unwrap()
            .contains("TOP-SECRET")
        );
    }

    #[test]
    fn browser_uses_text_only_no_persistence_or_external_assets() {
        let script = include_str!("../static/app.js");
        assert!(!script.contains("innerHTML"));
        assert!(!script.contains("localStorage"));
        assert!(!script.contains("sessionStorage"));
        assert!(script.contains("textContent"));
    }
}
