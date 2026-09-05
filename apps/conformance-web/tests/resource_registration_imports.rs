//! Synthetic diagnostic-oracle tests, not evidence of a live AS registration.
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use gnap_conformance_web::{analyze, app, Import, Report, Status, MAX_UPLOAD};
use serde_json::{json, Value};
use tower::ServiceExt;

const REQUEST: &str = "resource_registration_request";
const RESPONSE: &str = "resource_registration_response";
const UNOBSERVABLE: [&str; 3] = [
    "registration-format-compatibility",
    "registration-introspection-support",
    "registration-authentication-and-state",
];

fn report(kind: &str, body: Value) -> Report {
    raw_report(kind, &body.to_string())
}
fn raw_report(kind: &str, body: &str) -> Report {
    analyze(serde_json::from_value(json!({"kind":kind,"body":body})).unwrap()).unwrap()
}
fn status(report: &Report, id: &str) -> Status {
    report
        .checks
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("missing check {id}"))
        .status
}
fn request() -> Value {
    json!({"access":[],"resource_server":"synthetic-rs"})
}

#[test]
fn positive_fixtures_have_distinct_profiles_and_only_scoped_observations() {
    for (fixture, profile) in [
        (
            include_str!("../fixtures/resource-registration-request.json"),
            "gnap-resource-registration-request-import-v1",
        ),
        (
            include_str!("../fixtures/resource-registration-response.json"),
            "gnap-resource-registration-response-import-v1",
        ),
    ] {
        let r = analyze(serde_json::from_str::<Import>(fixture).unwrap()).unwrap();
        assert_eq!(r.profile, profile);
        assert!(!r.certification);
        assert_eq!(r.observation.source, "import");
        assert!(r.independence.contains("not gnap-types validators"));
        assert!(r.checks.iter().any(|c| c.status == Status::Pass));
        assert!(r.checks.iter().all(|c| c.status != Status::Fail));
        let field_checks: &[&str] = if profile.contains("-request-") {
            &[
                "registration-request-access",
                "registration-request-rs",
                "registration-request-token-formats",
                "registration-request-introspection-required",
            ]
        } else {
            &[
                "registration-response-reference",
                "registration-response-instance-id",
                "registration-response-introspection-endpoint",
            ]
        };
        for id in field_checks {
            assert_eq!(status(&r, id), Status::Pass);
        }
        for id in UNOBSERVABLE {
            assert_eq!(status(&r, id), Status::NotTested);
        }
    }
}

#[test]
fn required_request_members_cannot_be_missing_or_malformed() {
    for (field, id, malformed) in [
        (
            "access",
            "registration-request-access",
            vec![
                Value::Null,
                json!({}),
                json!("right"),
                json!([7]),
                json!([{}]),
            ],
        ),
        (
            "resource_server",
            "registration-request-rs",
            vec![
                Value::Null,
                json!(7),
                json!([]),
                json!({}),
                json!({"key":true}),
            ],
        ),
    ] {
        let mut body = request();
        body.as_object_mut().unwrap().remove(field);
        assert_eq!(status(&report(REQUEST, body), id), Status::Fail);
        for bad in malformed {
            let mut body = request();
            body[field] = bad;
            assert_eq!(status(&report(REQUEST, body), id), Status::Fail);
        }
    }
}

#[test]
fn access_arrays_and_key_presentation_do_not_imply_rights_or_key_validation() {
    for access in [
        json!([]),
        json!(["right-reference"]),
        json!([{"type":"demo","actions":["read"]}]),
    ] {
        for rs in [
            json!("rs-reference"),
            json!({"key":"key-reference"}),
            json!({"key":{}}),
        ] {
            let r = report(REQUEST, json!({"access":access,"resource_server":rs}));
            assert_eq!(status(&r, "registration-request-access"), Status::Pass);
            assert_eq!(status(&r, "registration-request-rs"), Status::Pass);
            assert_eq!(
                status(&r, "registration-authentication-and-state"),
                Status::NotTested
            );
        }
    }
    // Section 3.4 refers to RFC 9635 section 8, whose object type is REQUIRED,
    // even though the resource-registration example omits it.
    let r = report(
        REQUEST,
        json!({"access":[{"actions":["read"]}],"resource_server":"rs"}),
    );
    assert_eq!(status(&r, "registration-request-access"), Status::Fail);
}

#[test]
fn formats_are_registry_checks_never_an_as_intersection() {
    let absent = report(REQUEST, request());
    assert_eq!(
        status(&absent, "registration-request-token-formats"),
        Status::NotTested
    );
    for (formats, expected) in [
        (json!(["biscuit"]), Status::Pass),
        (json!(["opaque"]), Status::NotTested),
        (json!([]), Status::Pass),
        (json!(["future-test-format"]), Status::NotTested),
        (json!(["biscuit", "future-test-format"]), Status::NotTested),
        (json!(null), Status::Fail),
        (json!("opaque"), Status::Fail),
        (json!(["opaque", 7]), Status::Fail),
    ] {
        let mut body = request();
        body["token_formats_supported"] = formats;
        let r = report(REQUEST, body);
        assert_eq!(status(&r, "registration-request-token-formats"), expected);
        assert_eq!(
            status(&r, "registration-format-compatibility"),
            Status::NotTested
        );
    }
}

#[test]
fn optional_introspection_boolean_never_establishes_as_support() {
    assert_eq!(
        status(
            &report(REQUEST, request()),
            "registration-request-introspection-required"
        ),
        Status::NotTested
    );
    for (value, expected) in [
        (json!(true), Status::Pass),
        (json!(false), Status::Pass),
        (json!(null), Status::Fail),
        (json!(1), Status::Fail),
        (json!("true"), Status::Fail),
    ] {
        let mut body = request();
        body["token_introspection_required"] = value;
        let r = report(REQUEST, body);
        assert_eq!(
            status(&r, "registration-request-introspection-required"),
            expected
        );
        assert_eq!(
            status(&r, "registration-introspection-support"),
            Status::NotTested
        );
    }
}

#[test]
fn response_reference_is_required_but_not_a_token_value() {
    for body in [
        json!({}),
        json!({"resource_reference":null}),
        json!({"resource_reference":7}),
        json!({"resource_reference":{}}),
    ] {
        assert_eq!(
            status(&report(RESPONSE, body), "registration-response-reference"),
            Status::Fail
        );
    }
    for reference in ["", " ", "référence avec espaces", "\n"] {
        let r = report(RESPONSE, json!({"resource_reference":reference}));
        assert_eq!(status(&r, "registration-response-reference"), Status::Pass);
        assert_eq!(
            status(&r, "registration-authentication-and-state"),
            Status::NotTested
        );
    }
}

#[test]
fn optional_response_strings_do_not_gain_discovery_uri_rules() {
    for (field, id) in [
        ("instance_id", "registration-response-instance-id"),
        (
            "introspection_endpoint",
            "registration-response-introspection-endpoint",
        ),
    ] {
        assert_eq!(
            status(&report(RESPONSE, json!({"resource_reference":"ref"})), id),
            Status::NotTested
        );
        for (value, expected) in [
            (json!(null), Status::Fail),
            (json!({}), Status::Fail),
            (json!(7), Status::Fail),
            (json!(""), Status::Pass),
            (
                json!("http://user:password@invalid.example/#fragment"),
                Status::Pass,
            ),
        ] {
            let mut body = json!({"resource_reference":"ref"});
            body[field] = value;
            let r = report(RESPONSE, body);
            assert_eq!(status(&r, id), expected);
            assert_eq!(
                status(&r, "rs-http-and-discovery-publication"),
                Status::NotTested
            );
        }
    }
}

#[test]
fn extensions_are_not_forbidden_or_claimed_understood() {
    for (kind, mut body) in [
        (REQUEST, request()),
        (RESPONSE, json!({"resource_reference":"ref"})),
    ] {
        body["future_extension"] = json!({"opaque":"data"});
        let r = report(kind, body);
        assert!(r.checks.iter().all(|c| c.status != Status::Fail));
        assert_eq!(status(&r, "rs-extension-semantics"), Status::NotTested);
        let detail = r
            .checks
            .iter()
            .find(|c| c.id == "rs-extension-semantics")
            .unwrap()
            .detail;
        assert!(!detail.contains("MUST NOT declare the token active"));
    }
}

#[test]
fn registration_accepts_no_declared_comparison_context_even_empty() {
    for kind in [REQUEST, RESPONSE] {
        for context in [
            json!({}),
            json!({"http_status":200}),
            json!({"token_binding":"bound"}),
        ] {
            let input =
                serde_json::from_value(json!({"kind":kind,"body":"{}","rs_context":context}))
                    .unwrap();
            assert_eq!(
                analyze(input).unwrap_err(),
                "rs_context fields are not applicable to this message kind."
            );
        }
    }
}

#[test]
fn duplicate_members_and_parser_limits_do_not_create_last_wins_or_gnap_failures() {
    for kind in [REQUEST, RESPONSE] {
        for body in [
            r#"{"access":[],"access":null}"#,
            r#"{"resource_reference":"a","resource_reference":7}"#,
            r#"{"extra":{"same":1,"same":2}}"#,
        ] {
            let r = raw_report(kind, body);
            assert_eq!(status(&r, "rs-json-unambiguous"), Status::NotTested);
            assert!(!r
                .checks
                .iter()
                .any(|c| c.id.starts_with("registration-request-")
                    || c.id.starts_with("registration-response-")));
            assert!(r.checks.iter().all(|c| c.status != Status::Fail));
            for id in UNOBSERVABLE {
                assert_eq!(status(&r, id), Status::NotTested);
            }
        }
        for body in [
            "{\"huge\":1e999}".to_owned(),
            format!("{}0{}", "[".repeat(140), "]".repeat(140)),
        ] {
            assert_eq!(
                status(&raw_report(kind, &body), "rs-message-json-object"),
                Status::NotTested
            );
        }
        for body in ["{", "[]", "null"] {
            assert_eq!(
                status(&raw_report(kind, body), "rs-message-json-object"),
                Status::Fail
            );
        }
    }
}

#[test]
fn negative_fixtures_fail_named_fields_without_certification() {
    for (fixture, ids) in [
        (
            include_str!("../fixtures/invalid-resource-registration-request.json"),
            vec![
                "registration-request-access",
                "registration-request-rs",
                "registration-request-token-formats",
                "registration-request-introspection-required",
            ],
        ),
        (
            include_str!("../fixtures/invalid-resource-registration-response.json"),
            vec![
                "registration-response-reference",
                "registration-response-instance-id",
                "registration-response-introspection-endpoint",
            ],
        ),
    ] {
        let r = analyze(serde_json::from_str(fixture).unwrap()).unwrap();
        for id in ids {
            assert_eq!(status(&r, id), Status::Fail);
        }
        assert!(!r.certification);
    }
}

#[tokio::test]
async fn imported_routes_redact_data_and_do_not_interpret_headers_as_network_evidence() {
    for kind in [REQUEST, RESPONSE] {
        let input = json!({"kind":kind,"body":"{\"resource_reference\":\"<script>PRIVATE-TEST-MARKER</script>\",\"future_extension\":\"PRIVATE-TEST-MARKER\"}","headers":[["content-type","application/json"],["content-type","text/html"]]});
        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/analyze")
                    .header("content-type", "application/json")
                    .body(Body::from(input.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let bytes = to_bytes(response.into_body(), MAX_UPLOAD).await.unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains("PRIVATE-TEST-MARKER"));
        assert!(!text.contains("<script>"));
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["certification"], false);
        assert_eq!(value["kind"], kind);
        assert!(
            value["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["id"] == "rs-http-and-discovery-publication"
                    && c["status"] == "not_tested")
        );
    }
    for (path, expected) in [
        ("/", "value=\"resource_registration_request\""),
        ("/", "value=\"resource_registration_response\""),
        ("/app.js", "No comparison context is accepted."),
    ] {
        let response = app()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), MAX_UPLOAD).await.unwrap();
        assert!(std::str::from_utf8(&bytes).unwrap().contains(expected));
    }
}
