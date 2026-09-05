//! Synthetic wire fixtures and independent expected outcomes, not live evidence.
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use gnap_conformance_web::{analyze, app, Import, Report, Status, MAX_UPLOAD};
use serde_json::{json, Value};
use tower::ServiceExt;

fn report(kind: &str, body: Value, context: Option<Value>) -> Report {
    let input = json!({"kind":kind, "body":body.to_string(), "rs_context":context});
    analyze(serde_json::from_value(input).unwrap()).unwrap()
}
fn status(report: &Report, id: &str) -> Status {
    report
        .checks
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("missing check {id}"))
        .status
}
fn active() -> Value {
    json!({"active":true,"access":[],"iss":"https://as.example/gnap","key":"test-key-reference"})
}

#[test]
fn positive_fixtures_have_scoped_passes_and_never_certify() {
    for fixture in [
        include_str!("../fixtures/rs-discovery.json"),
        include_str!("../fixtures/introspection-request.json"),
        include_str!("../fixtures/introspection-active.json"),
        include_str!("../fixtures/introspection-inactive.json"),
        include_str!("../fixtures/rs-error-response.json"),
    ] {
        let r = analyze(serde_json::from_str::<Import>(fixture).unwrap()).unwrap();
        assert!(!r.certification);
        assert_eq!(r.observation.source, "import");
        assert!(r.independence.contains("not gnap-types validators"));
        assert!(r.checks.iter().any(|c| c.status == Status::Pass));
        assert!(r.checks.iter().all(|c| c.status != Status::Fail));
        assert_eq!(status(&r, "rs-authentication-and-state"), Status::NotTested);
        assert_eq!(
            status(&r, "rs-http-and-discovery-publication"),
            Status::NotTested
        );
    }
}

#[test]
fn active_requires_access_and_issuer_despite_incomplete_rfc_example() {
    for (field, check) in [
        ("access", "introspection-active-access"),
        ("iss", "introspection-active-issuer"),
    ] {
        for value in [None, Some(Value::Null), Some(json!(42))] {
            let mut body = active();
            if let Some(v) = value {
                body[field] = v;
            } else {
                body.as_object_mut().unwrap().remove(field);
            }
            assert_eq!(
                status(&report("introspection_response", body, None), check),
                Status::Fail
            );
        }
    }
    assert_eq!(
        status(
            &report("introspection_response", active(), None),
            "introspection-active-access"
        ),
        Status::Pass
    );
}

#[test]
fn inactive_omits_every_other_member_and_value_is_always_forbidden() {
    for field in ["key", "iss", "access", "value", "unknown_extension"] {
        let mut body = json!({"active":false});
        body[field] = Value::Null;
        let r = report("introspection_response", body, None);
        assert_eq!(status(&r, "introspection-inactive-only"), Status::Fail);
    }
    for active in [true, false] {
        assert_eq!(
            status(
                &report(
                    "introspection_response",
                    json!({"active":active,"value":"test"}),
                    None
                ),
                "introspection-response-no-value"
            ),
            Status::Fail
        );
    }
    for body in [json!({}), json!({"active":"false"}), json!({"active":0})] {
        assert_eq!(
            status(
                &report("introspection_response", body, None),
                "introspection-response-active"
            ),
            Status::Fail
        );
    }
}

#[test]
fn binding_condition_is_declared_and_cannot_override_bearer_key_contradiction() {
    let mut body = active();
    assert_eq!(
        status(
            &report("introspection_response", body.clone(), None),
            "introspection-key-condition"
        ),
        Status::NotTested
    );
    assert_eq!(
        status(
            &report(
                "introspection_response",
                body.clone(),
                Some(json!({"token_binding":"bound"}))
            ),
            "introspection-key-condition"
        ),
        Status::Pass
    );
    body["flags"] = json!(["bearer"]);
    for context in [
        None,
        Some(json!({"token_binding":"bearer"})),
        Some(json!({"token_binding":"bound"})),
    ] {
        assert_eq!(
            status(
                &report("introspection_response", body.clone(), context),
                "introspection-key-condition"
            ),
            Status::Fail
        );
    }
    body.as_object_mut().unwrap().remove("key");
    assert_eq!(
        status(
            &report("introspection_response", body.clone(), None),
            "introspection-key-condition"
        ),
        Status::Pass
    );
    assert_eq!(
        status(
            &report(
                "introspection_response",
                body,
                Some(json!({"token_binding":"bound"}))
            ),
            "introspection-key-condition"
        ),
        Status::Fail
    );
}

#[test]
fn request_recommendation_optional_access_and_unknown_extensions_are_not_must_failures() {
    let body = json!({"access_token":"synthetic","resource_server":"test-rs"});
    let r = report("introspection_request", body.clone(), None);
    assert_eq!(status(&r, "introspection-request-proof"), Status::NotTested);
    assert_eq!(
        status(&r, "introspection-request-access"),
        Status::NotTested
    );
    assert!(r.checks.iter().all(|c| c.status != Status::Fail));
    let mut body = body;
    body["proof"] = json!("future-method");
    body["custom"] = json!({"unknown":true});
    let r = report("introspection_request", body, None);
    assert_eq!(status(&r, "introspection-request-proof"), Status::NotTested);
    assert_eq!(status(&r, "rs-extension-semantics"), Status::NotTested);
    assert!(r
        .checks
        .iter()
        .find(|c| c.id == "rs-extension-semantics")
        .unwrap()
        .detail
        .contains("Additional members"));
}

#[test]
fn request_required_fields_and_selected_access_dimensions_fail_when_malformed() {
    for body in [json!({}), json!({"access_token":42,"resource_server":[]})] {
        let r = report("introspection_request", body, None);
        assert_eq!(status(&r, "introspection-request-token"), Status::Fail);
        assert_eq!(status(&r, "introspection-request-rs"), Status::Fail);
    }
    for access in [
        json!({}),
        json!([{}]),
        json!([{"type":42}]),
        json!([{"type":"files","actions":"read"}]),
        json!([null]),
    ] {
        let r = report(
            "introspection_request",
            json!({"access_token":"test","resource_server":"rs","access":access,"proof":42}),
            None,
        );
        assert_eq!(status(&r, "introspection-request-access"), Status::Fail);
        assert_eq!(status(&r, "introspection-request-proof"), Status::Fail);
    }
}

#[test]
fn discovery_endpoint_constraints_optional_services_and_registered_names() {
    let body = json!({"grant_request_endpoint":"https://as.example/gnap"});
    let r = report("rs_discovery", body.clone(), None);
    for id in [
        "rs-discovery-grant-identity",
        "rs-discovery-declared-location",
        "rs-discovery-introspection-endpoint",
        "rs-discovery-registration-endpoint",
        "rs-discovery-key-proofs",
        "rs-discovery-token-formats",
    ] {
        assert_eq!(status(&r, id), Status::NotTested);
    }
    for endpoint in [
        "/gnap",
        "http://as.example/gnap",
        "https:///gnap",
        "https://as.example/gnap#f",
        "https://host:letters/",
        "https://as.example/space here",
        "https://as.example/%ZZ",
        "https://höst/",
    ] {
        assert_eq!(
            status(
                &report(
                    "rs_discovery",
                    json!({"grant_request_endpoint":endpoint}),
                    None
                ),
                "rs-discovery-grant-endpoint"
            ),
            Status::Fail,
            "{endpoint}"
        );
    }
    for endpoint in [
        "https://[v1.future]/gnap",
        "https://host:999999999999/",
        "https://%FF.example/",
        "https://999.999/",
    ] {
        assert_eq!(
            status(
                &report(
                    "rs_discovery",
                    json!({"grant_request_endpoint":endpoint}),
                    None
                ),
                "rs-discovery-grant-endpoint"
            ),
            Status::NotTested,
            "{endpoint}"
        );
    }
    let r = report(
        "rs_discovery",
        json!({"grant_request_endpoint":"https://as.example/gnap","introspection_endpoint":null,"token_formats_supported":["future"],"key_proofs_supported":[42]}),
        None,
    );
    assert_eq!(
        status(&r, "rs-discovery-introspection-endpoint"),
        Status::Fail
    );
    assert_eq!(status(&r, "rs-discovery-token-formats"), Status::NotTested);
    assert_eq!(status(&r, "rs-discovery-key-proofs"), Status::Fail);
    let r = report(
        "rs_discovery",
        body,
        Some(
            json!({"grant_request_endpoint":"https://as.example/other","discovery_url":"https://other.example/.well-known/gnap-as-rs"}),
        ),
    );
    assert_eq!(status(&r, "rs-discovery-grant-identity"), Status::Fail);
    assert_eq!(status(&r, "rs-discovery-declared-location"), Status::Fail);
}

#[test]
fn userinfo_is_a_recipient_profile_failure_not_a_gnap_must() {
    for endpoint in ["https://user:pw@host/gnap", "https://@host/gnap"] {
        for field in [
            "grant_request_endpoint",
            "introspection_endpoint",
            "resource_registration_endpoint",
        ] {
            let mut body = json!({"grant_request_endpoint":"https://as.example/gnap"});
            body[field] = json!(endpoint);
            let result = report("rs_discovery", body, None);
            let id = match field {
                "grant_request_endpoint" => "rs-discovery-grant-endpoint",
                "introspection_endpoint" => "rs-discovery-introspection-endpoint",
                _ => "rs-discovery-registration-endpoint",
            };
            let check = result.checks.iter().find(|check| check.id == id).unwrap();
            assert_eq!(check.status, Status::Fail);
            assert!(check.reference.ends_with("rfc9110.html#section-4.2.4"));
            assert!(check.detail.contains("SHOULD"));
            assert!(check.detail.contains("not an additional GNAP MUST"));
            assert!(!check.detail.contains(endpoint));
        }
    }
}

#[test]
fn optional_metadata_checks_types_not_authenticated_values() {
    let mut body = active();
    body["exp"] = json!(1);
    body["aud"] = json!("untrusted-audience");
    assert_eq!(
        status(
            &report("introspection_response", body.clone(), None),
            "introspection-optional-metadata"
        ),
        Status::Pass
    );
    for (field, value) in [
        ("exp", json!(1.5)),
        ("iat", json!("123")),
        ("aud", json!(123)),
        ("sub", json!([])),
        ("flags", json!([3])),
    ] {
        let mut body = body.clone();
        body[field] = value;
        assert_eq!(
            status(
                &report("introspection_response", body, None),
                "introspection-optional-metadata"
            ),
            Status::Fail
        );
    }
}

#[test]
fn rs_errors_are_separate_and_http_400_is_conditional_on_declared_context() {
    for error in [
        json!("invalid_access"),
        json!({"code":"invalid_request","description":"test"}),
    ] {
        let r = report("rs_error_response", json!({"error":error}), None);
        assert_eq!(status(&r, "rs-error-shape"), Status::Pass);
        assert_eq!(status(&r, "rs-error-http-status"), Status::NotTested);
    }
    for body in [
        json!({"error":42}),
        json!({"error":{"description":"test"}}),
        json!({"error":"invalid_request","active":false}),
        json!({"error":{"code":"é"}}),
    ] {
        assert_eq!(
            status(&report("rs_error_response", body, None), "rs-error-shape"),
            Status::Fail
        );
    }
    let r = report(
        "rs_error_response",
        json!({"error":"future_error"}),
        Some(json!({"http_status":200})),
    );
    assert_eq!(status(&r, "rs-error-code"), Status::NotTested);
    assert_eq!(status(&r, "rs-error-http-status"), Status::Fail);
}

#[test]
fn duplicate_members_at_any_depth_are_inconclusive_without_last_wins() {
    for body in [
        r#"{"active":false,"active":true}"#,
        r#"{"active":true,"access":[{"type":"a","type":"b"}],"iss":"https://as.example/gnap"}"#,
    ] {
        let input =
            serde_json::from_value(json!({"kind":"introspection_response","body":body})).unwrap();
        let r = analyze(input).unwrap();
        assert_eq!(status(&r, "rs-json-unambiguous"), Status::NotTested);
        assert!(!r
            .checks
            .iter()
            .any(|c| c.id == "introspection-response-active"));
    }
}

#[test]
fn contexts_are_bounded_kind_specific_and_never_hide_invalid_json() {
    for (kind, context) in [
        ("grant_request", json!({})),
        ("introspection_request", json!({})),
        ("introspection_response", json!({"http_status":400})),
        ("rs_discovery", json!({"token_binding":"bound"})),
        (
            "rs_error_response",
            json!({"discovery_url":"https://as.example/"}),
        ),
        ("rs_error_response", json!({"http_status":99})),
        (
            "rs_discovery",
            json!({"grant_request_endpoint":"x".repeat(4097)}),
        ),
    ] {
        let input =
            serde_json::from_value(json!({"kind":kind,"body":"{}","rs_context":context})).unwrap();
        assert!(analyze(input).is_err());
    }
    let r=analyze(serde_json::from_value(json!({"kind":"rs_discovery","body":"{","rs_context":{"grant_request_endpoint":"https://as.example/gnap"}})).unwrap()).unwrap();
    assert_eq!(status(&r, "rs-message-json-object"), Status::Fail);
}

#[tokio::test]
async fn all_import_routes_return_redacted_reports_and_ui_explains_context() {
    for kind in [
        "rs_discovery",
        "introspection_request",
        "introspection_response",
        "rs_error_response",
    ] {
        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/analyze")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"kind":kind,"body":"{\"secret\":\"<script>TOP-SECRET</script>\"}"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let bytes = to_bytes(response.into_body(), MAX_UPLOAD).await.unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains("TOP-SECRET"));
        assert!(!text.contains("<script>"));
        let r: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(r["certification"], false);
        assert_eq!(r["kind"], kind);
    }
    let response = app()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let html = String::from_utf8(
        to_bytes(response.into_body(), MAX_UPLOAD)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(html.contains("AS discovery for resource servers"));
    assert!(html.contains("Optional caller-declared comparison context"));
    assert!(html.contains("id=\"context-section\" hidden"));
}

#[test]
fn invalid_fixture_fails_exact_assertions_without_a_global_verdict() {
    let r = analyze(
        serde_json::from_str(include_str!(
            "../fixtures/invalid-introspection-active.json"
        ))
        .unwrap(),
    )
    .unwrap();
    for id in [
        "introspection-active-issuer",
        "introspection-response-no-value",
        "introspection-key-condition",
    ] {
        assert_eq!(status(&r, id), Status::Fail);
    }
    assert!(!r.certification);
}

#[test]
fn imported_http_headers_do_not_create_unstated_200_or_single_header_requirements() {
    let input=serde_json::from_value(json!({"kind":"rs_discovery","body":"{\"grant_request_endpoint\":\"https://as.example/gnap\"}","headers":[["content-type","application/json"],["content-type","text/html"]]})).unwrap();
    let r = analyze(input).unwrap();
    assert!(r.checks.iter().all(|c| c.status != Status::Fail));
    assert_eq!(
        status(&r, "rs-http-and-discovery-publication"),
        Status::NotTested
    );
}

#[test]
fn json_parser_range_and_depth_limits_are_not_normative_shape_failures() {
    for body in [
        "{\"extension\":1e999999}".to_owned(),
        format!("{{\"extension\":{}0{}}}", "[".repeat(150), "]".repeat(150)),
    ] {
        let r =
            analyze(serde_json::from_value(json!({"kind":"rs_discovery","body":body})).unwrap())
                .unwrap();
        assert_eq!(status(&r, "rs-message-json-object"), Status::NotTested);
        assert!(!r
            .checks
            .iter()
            .any(|c| c.id == "rs-discovery-grant-endpoint"));
    }
}

#[test]
fn declared_discovery_location_is_not_repaired_into_the_well_known_path() {
    for location in [
        "https://as.example/other/../.well-known/gnap-as-rs",
        "https://as.example/.well-known/gnap-as-rs?x=1",
        "http://as.example/.well-known/gnap-as-rs",
        "https://as.example/.well-known/gnap-as-rs#fragment",
    ] {
        let r = report(
            "rs_discovery",
            json!({"grant_request_endpoint":"https://as.example/gnap"}),
            Some(json!({"discovery_url":location})),
        );
        assert_eq!(status(&r, "rs-discovery-declared-location"), Status::Fail);
    }
}
