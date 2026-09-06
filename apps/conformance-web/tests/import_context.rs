//! Integration boundaries between AS discovery and the RS-facing import kinds.
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use gnap_conformance_web::{analyze, app, Import};
use serde_json::json;
use tower::ServiceExt;

#[test]
fn discovery_and_rs_comparison_contexts_are_not_interchangeable() {
    for kind in [
        "grant_request",
        "grant_response",
        "continue_request",
        "rs_discovery",
        "introspection_request",
        "introspection_response",
        "rs_error_response",
    ] {
        for context in [
            json!({"queried_endpoint":"https://private-context.example/gnap"}),
            json!({"http_status":200}),
        ] {
            let mut envelope = json!({"kind":kind,"body":"{}"});
            envelope
                .as_object_mut()
                .unwrap()
                .extend(context.as_object().unwrap().clone());
            let input = serde_json::from_value::<Import>(envelope).unwrap();
            assert_eq!(
                analyze(input).err(),
                Some("queried_endpoint and http_status are only supported for kind as_discovery."),
                "wrong context diagnostic for {kind}",
            );
        }
    }
    for kind in [
        "as_discovery",
        "grant_request",
        "grant_response",
        "continue_request",
        "introspection_request",
    ] {
        // Even an empty RS context must not silently acquire another meaning.
        for context in [json!({}), json!({"http_status":400})] {
            let input = serde_json::from_value::<Import>(json!({
                "kind":kind,"body":"{}","rs_context":context,
            }))
            .unwrap();
            assert_eq!(
                analyze(input).err(),
                Some("rs_context fields are not applicable to this message kind."),
                "wrong context diagnostic for {kind}",
            );
        }
    }
}

#[test]
fn both_discovery_profiles_remain_distinct_when_unused_context_is_null() {
    for (fixture, expected_profile) in [
        (
            include_str!("../fixtures/as-discovery.json"),
            "gnap-as-discovery-diagnostics-v1",
        ),
        (
            include_str!("../fixtures/rs-discovery.json"),
            "gnap-rs-discovery-import-v1",
        ),
    ] {
        let mut envelope: serde_json::Value = serde_json::from_str(fixture).unwrap();
        for field in ["rs_context", "queried_endpoint", "http_status"] {
            envelope
                .as_object_mut()
                .unwrap()
                .entry(field)
                .or_insert(serde_json::Value::Null);
        }
        let report = analyze(serde_json::from_value(envelope).unwrap()).unwrap();
        assert_eq!(report.profile, expected_profile);
        assert_eq!(report.observation.source, "import");
        assert!(!report.certification);
    }
}

#[tokio::test]
async fn the_import_route_rejects_cross_profile_context_without_echoing_it() {
    for envelope in [
        json!({"kind":"rs_discovery","body":"{}","queried_endpoint":"https://private-context.example/gnap"}),
        json!({"kind":"as_discovery","body":"{}","rs_context":{"grant_request_endpoint":"https://private-context.example/gnap"}}),
    ] {
        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/analyze")
                    .header("content-type", "application/json")
                    .body(Body::from(envelope.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(!text.contains("private-context.example"));
    }
}
