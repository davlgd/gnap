use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use gnap_conformance_web::{
    analyze, app, app_with_probes, discovery, probe::Probes, Check, Import, Status, MAX_UPLOAD,
};
use serde_json::{json, Value};
use tower::ServiceExt;

fn status(checks: &[Check], id: &str) -> Status {
    checks.iter().find(|c| c.id == id).unwrap().status
}

#[test]
fn minimal_document_needs_no_optional_capabilities() {
    let checks = discovery::checks(
        br#"{"grant_request_endpoint":"https://as.example/gnap"}"#,
        None,
        None,
        None,
    );
    assert_eq!(status(&checks, "discovery-json-object"), Status::Pass);
    assert_eq!(status(&checks, "discovery-endpoint"), Status::Pass);
    for id in [
        "discovery-http-200",
        "discovery-media-type",
        "discovery-endpoint-match",
        "key_proofs_supported",
        "discovery-key-rotation-type",
    ] {
        assert_eq!(status(&checks, id), Status::NotTested, "{id}");
    }
    assert!(checks.iter().all(|c| c.status != Status::Fail));
}

#[test]
fn malformed_json_and_required_field_fail_without_http_context() {
    for body in ["{", "[]", "null", "42", "{} {}"] {
        let checks = discovery::checks(body.as_bytes(), None, None, None);
        assert_eq!(status(&checks, "discovery-json-object"), Status::Fail);
        assert_eq!(
            status(&checks, "discovery-endpoint-match"),
            Status::NotTested
        );
    }
    for body in [
        "{}",
        r#"{"grant_request_endpoint":null}"#,
        r#"{"grant_request_endpoint":123}"#,
    ] {
        assert_eq!(
            status(
                &discovery::checks(body.as_bytes(), None, None, None),
                "discovery-endpoint"
            ),
            Status::Fail
        );
    }
}

#[test]
fn url_checks_do_not_accept_parser_repairs_or_local_http_deviations() {
    for endpoint in [
        "http://localhost/gnap",
        "http://127.0.0.1/gnap",
        "https:///as.example/gnap",
        "https:as.example",
        "https://",
        "https://as.example/#fragment",
        "https://as.example/%xx",
        "https://as.example/has space",
        "https://as.example\\gnap",
        "https://[::1]evil/gnap",
        "https://as.example/<script>",
        "https://as.example/?a=[bad]",
    ] {
        let body = json!({"grant_request_endpoint": endpoint}).to_string();
        let checks = discovery::checks(
            body.as_bytes(),
            Some(&[(
                "GNAP-Development-Only".into(),
                "insecure-loopback-discovery".into(),
            )]),
            Some(200),
            Some(endpoint),
        );
        assert_eq!(
            status(&checks, "discovery-endpoint"),
            Status::Fail,
            "{endpoint}"
        );
    }
    for endpoint in [
        "https://as.example/gnap",
        "HTTPS://AS.EXAMPLE:8443/a/../gnap?q=%2f",
        "https://[::1]:8443/gnap",
    ] {
        let body = json!({"grant_request_endpoint": endpoint}).to_string();
        let checks = discovery::checks(body.as_bytes(), None, None, Some(endpoint));
        assert_eq!(
            status(&checks, "discovery-endpoint"),
            Status::Pass,
            "{endpoint}"
        );
        assert_eq!(status(&checks, "discovery-endpoint-match"), Status::Pass);
    }
    let checks = discovery::checks(
        br#"{"grant_request_endpoint":"https://as.example/a/../gnap"}"#,
        None,
        None,
        Some("https://as.example/gnap"),
    );
    assert_eq!(status(&checks, "discovery-endpoint-match"), Status::Fail);
}

#[test]
fn grammatical_url_forms_outside_the_parser_are_unresolved_not_failed() {
    for endpoint in [
        "https://[v1.future]/gnap",
        "https://[VF.a:b!c]:443/gnap",
        "https://as.example:65536/gnap",
        "https://as.example:99999999999999999999999999999999999999/gnap",
    ] {
        let body = json!({"grant_request_endpoint":endpoint}).to_string();
        let checks = discovery::checks(body.as_bytes(), None, None, Some(endpoint));
        assert_eq!(
            status(&checks, "discovery-endpoint"),
            Status::NotTested,
            "{endpoint}"
        );
        assert_eq!(status(&checks, "discovery-endpoint-match"), Status::Pass);
        assert!(checks
            .iter()
            .find(|c| c.id == "discovery-endpoint")
            .unwrap()
            .detail
            .contains("coverage limit"));
        let checks = discovery::checks(
            body.as_bytes(),
            None,
            None,
            Some("https://different.example/gnap"),
        );
        assert_eq!(status(&checks, "discovery-endpoint-match"), Status::Fail);
    }
    for endpoint in [
        "https://[v.future]/gnap",
        "https://[vG.future]/gnap",
        "https://[v1.]/gnap",
        "https://[v1.a%20b]/gnap",
        "https://[v1.future]:letters/gnap",
        "https://as.example:letters/gnap",
        "https://as.example:999999999/gnap#bad",
        "https://[broken]:999999999/gnap",
        "https://as.example:999999999/has space",
        "https://user@@[v1.future]/gnap",
    ] {
        let body = json!({"grant_request_endpoint":endpoint}).to_string();
        assert_eq!(
            status(
                &discovery::checks(body.as_bytes(), None, None, Some(endpoint)),
                "discovery-endpoint"
            ),
            Status::Fail,
            "{endpoint}"
        );
    }
}

#[test]
fn reg_names_rejected_by_whatwg_are_not_misreported_as_gnap_failures() {
    // Parse and import only: these strings are never resolved or fetched.
    // Passing the reg-name production does not assert full UTF-8/IDNA or
    // scheme-specific validity, notably for the percent-encoded FF octet.
    for endpoint in [
        "https://%FF.example/gnap",
        "https://%2F.example/gnap",
        "https://999.999.999.999/gnap",
        "https://example.123/gnap",
        "https://09/gnap",
        "https://1.2.3.4.5/gnap",
    ] {
        assert!(
            reqwest::Url::parse(endpoint).is_err(),
            "fixture must exercise a real parser refusal: {endpoint}"
        );
        let body = json!({"grant_request_endpoint": endpoint}).to_string();
        let checks = discovery::checks(body.as_bytes(), None, None, Some(endpoint));
        assert_eq!(
            status(&checks, "discovery-endpoint"),
            Status::NotTested,
            "{endpoint}"
        );
        assert_eq!(status(&checks, "discovery-endpoint-match"), Status::Pass);
        assert!(checks
            .iter()
            .find(|c| c.id == "discovery-endpoint")
            .unwrap()
            .detail
            .contains("production semantics remain unresolved"));
        let checks = discovery::checks(
            body.as_bytes(),
            None,
            None,
            Some("https://other.example/gnap"),
        );
        assert_eq!(status(&checks, "discovery-endpoint-match"), Status::Fail);
    }
    for endpoint in [
        "https://%FG.example/gnap",
        "https://example.123:letters/gnap",
        "https://999.999.999.999/has space",
        "https://%FF.example/gnap#fragment",
        "http://example.123/gnap",
    ] {
        let body = json!({"grant_request_endpoint": endpoint}).to_string();
        assert_eq!(
            status(
                &discovery::checks(body.as_bytes(), None, None, None),
                "discovery-endpoint"
            ),
            Status::Fail,
            "{endpoint}"
        );
    }
}

#[test]
fn userinfo_is_a_safe_profile_failure_not_an_invented_gnap_must() {
    for endpoint in [
        "https://user@as.example/gnap",
        "https://user:TOP-SECRET@as.example/gnap",
        "https://@as.example/gnap",
        "https://user@[v1.future]/gnap",
    ] {
        let body = json!({"grant_request_endpoint":endpoint}).to_string();
        let checks = discovery::checks(body.as_bytes(), None, None, Some(endpoint));
        let finding = checks
            .iter()
            .find(|c| c.id == "discovery-endpoint")
            .unwrap();
        assert_eq!(finding.status, Status::Fail);
        assert!(finding.detail.starts_with("Safe discovery profile:"));
        assert!(finding.detail.contains("SHOULD"));
        assert!(finding.detail.contains("not an additional GNAP MUST"));
        assert_eq!(
            finding.reference,
            "https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.4"
        );
        assert!(finding.remediation.unwrap().contains("Remove userinfo"));
        assert!(!serde_json::to_string(&checks)
            .unwrap()
            .contains("TOP-SECRET"));
    }
    let checks = discovery::checks(
        br#"{"grant_request_endpoint":"https://as.example/path@segment?email=user@example"}"#,
        None,
        None,
        None,
    );
    assert_eq!(status(&checks, "discovery-endpoint"), Status::Pass);
}

#[test]
fn raw_iri_and_spaces_fail_but_encoded_uri_characters_are_supported() {
    for endpoint in [
        "https://éxample.example/gnap",
        "https://as.example/café",
        "https://as.example/has space",
    ] {
        let body = json!({"grant_request_endpoint":endpoint}).to_string();
        assert_eq!(
            status(
                &discovery::checks(body.as_bytes(), None, None, None),
                "discovery-endpoint"
            ),
            Status::Fail
        );
    }
    for endpoint in [
        "https://xn--xample-9ua.example/gnap",
        "https://as.example/caf%C3%A9",
        "https://as.example/has%20space",
    ] {
        let body = json!({"grant_request_endpoint":endpoint}).to_string();
        assert_eq!(
            status(
                &discovery::checks(body.as_bytes(), None, None, None),
                "discovery-endpoint"
            ),
            Status::Pass
        );
    }
}

#[test]
fn capability_types_registry_membership_and_unknown_are_distinct() {
    for field in [
        "interaction_start_modes_supported",
        "interaction_finish_methods_supported",
        "key_proofs_supported",
        "sub_id_formats_supported",
        "assertion_formats_supported",
    ] {
        for value in [json!(null), json!("httpsig"), json!(["httpsig", 42])] {
            let body = json!({"grant_request_endpoint":"https://as.example/gnap", field:value})
                .to_string();
            assert_eq!(
                status(&discovery::checks(body.as_bytes(), None, None, None), field),
                Status::Fail
            );
        }
        let body = json!({"grant_request_endpoint":"https://as.example/gnap", field:["UNKNOWN-TOP-SECRET"]}).to_string();
        let checks = discovery::checks(body.as_bytes(), None, None, None);
        let finding = checks.iter().find(|c| c.id == field).unwrap();
        assert_eq!(finding.status, Status::NotTested);
        assert!(finding.detail.contains("unknown"));
        assert!(finding.remediation.is_some());
        assert!(!serde_json::to_string(&checks)
            .unwrap()
            .contains("TOP-SECRET"));
    }
    let checks = discovery::checks(br#"{"grant_request_endpoint":"https://as.example/gnap","interaction_start_modes_supported":["redirect","app","user_code","user_code_uri"],"interaction_finish_methods_supported":["push","redirect"],"key_proofs_supported":["httpsig","mtls","jws","jwsd"],"sub_id_formats_supported":["phone_number","did","uri","aliases"],"assertion_formats_supported":["id_token","saml2"],"key_rotation_supported":true}"#, None, None, None);
    for field in [
        "interaction_start_modes_supported",
        "interaction_finish_methods_supported",
        "key_proofs_supported",
        "sub_id_formats_supported",
        "assertion_formats_supported",
        "discovery-key-rotation-type",
    ] {
        assert_eq!(status(&checks, field), Status::Pass, "{field}");
    }
    assert_eq!(
        status(&checks, "discovery-capability-behavior"),
        Status::NotTested
    );
    for value in [json!(null), json!("false"), json!(0)] {
        let body = json!({"grant_request_endpoint":"https://as.example/gnap", "key_rotation_supported":value}).to_string();
        assert_eq!(
            status(
                &discovery::checks(body.as_bytes(), None, None, None),
                "discovery-key-rotation-type"
            ),
            Status::Fail
        );
    }
}

#[test]
fn ambiguous_duplicate_members_are_not_last_wins_passes() {
    let checks = discovery::checks(br#"{"grant_request_endpoint":"http://localhost/gnap","grant_request_endpoint":"https://as.example/gnap"}"#, None, None, None);
    assert_eq!(status(&checks, "discovery-duplicate-members"), Status::Fail);
    assert_eq!(status(&checks, "discovery-endpoint"), Status::NotTested);
}

#[test]
fn captured_http_status_and_media_are_independent_of_a_good_body() {
    let body = br#"{"grant_request_endpoint":"https://as.example/gnap"}"#;
    for code in [204, 302, 401, 403, 405, 500] {
        let checks = discovery::checks(body, Some(&[]), Some(code), None);
        assert_eq!(status(&checks, "discovery-http-200"), Status::Fail);
        assert_eq!(status(&checks, "discovery-media-type"), Status::Fail);
        assert_eq!(status(&checks, "discovery-json-object"), Status::Pass);
    }
    for media in ["application/json", "Application/JSON; charset=utf-8"] {
        let headers = [("Content-Type".into(), media.into())];
        assert_eq!(
            status(
                &discovery::checks(body, Some(&headers), Some(200), None),
                "discovery-media-type"
            ),
            Status::Pass
        );
    }
    let headers = [
        ("content-type".into(), "application/json".into()),
        ("Content-Type".into(), "application/json".into()),
    ];
    assert_eq!(
        status(
            &discovery::checks(body, Some(&headers), None, None),
            "discovery-media-type"
        ),
        Status::Fail
    );
}

fn request(path: &str, value: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(value.to_string()))
        .unwrap()
}

#[tokio::test]
async fn imports_report_checks_without_fetching_or_echoing_context() {
    let response = app().oneshot(request("/api/analyze", json!({"kind":"as_discovery", "body":"{\"grant_request_endpoint\":\"http://localhost/TOP-SECRET\",\"extension\":\"<script>TOP-SECRET</script>\"}", "queried_endpoint":"http://169.254.169.254/TOP-SECRET", "http_status":200, "headers":[["content-type","text/html"], ["authorization", "TOP-SECRET"]]}))).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let bytes = to_bytes(response.into_body(), MAX_UPLOAD).await.unwrap();
    assert!(!std::str::from_utf8(&bytes).unwrap().contains("TOP-SECRET"));
    let report: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(report["certification"], false);
    assert_eq!(report["profile"], "gnap-as-discovery-diagnostics-v1");
    assert_eq!(report["observation"]["source"], "import");
}

#[tokio::test]
async fn discovery_context_for_another_import_kind_is_an_explicit_error() {
    for kind in ["grant_request", "grant_response", "continue_request"] {
        for extra in [
            json!({"queried_endpoint":"https://as.example/TOP-SECRET"}),
            json!({"http_status":200}),
        ] {
            let mut envelope = json!({"kind":kind, "body":"{}"});
            envelope
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            let response = app()
                .oneshot(request("/api/analyze", envelope))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = to_bytes(response.into_body(), MAX_UPLOAD).await.unwrap();
            let message = std::str::from_utf8(&body).unwrap();
            assert!(message.contains("only supported for kind as_discovery"));
            assert!(!message.contains("TOP-SECRET"));
        }
    }
}

#[tokio::test]
async fn probe_route_rejects_arbitrary_urls_unknown_operations_and_wrong_roles_without_leaks() {
    let configured = Probes::from_json(r#"["https://as.example/gnap"]"#)
        .unwrap()
        .with_resource_targets(r#"["https://rs.example/resource"]"#)
        .unwrap();
    for value in [
        json!({"target_id":0,"consent":true,"operation":"TOP-SECRET"}),
        json!({"target_id":0,"consent":true,"operation":"as_discovery","url":"http://169.254.169.254/TOP-SECRET"}),
        json!({"target_id":1,"consent":true,"operation":"as_discovery"}),
        json!({"target_id":0,"consent":false,"operation":"as_discovery"}),
    ] {
        let response = app_with_probes(configured.clone())
            .oneshot(request("/api/probe", value))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), MAX_UPLOAD).await.unwrap();
        assert!(!std::str::from_utf8(&body).unwrap().contains("TOP-SECRET"));
    }
}

#[test]
fn context_limits_and_synthetic_fixture_are_checked() {
    for extra in [
        json!({"queried_endpoint":"x".repeat(4097)}),
        json!({"http_status":600}),
    ] {
        let mut value = json!({"kind":"as_discovery","body":"{}"});
        value
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let input: Import = serde_json::from_value(value).unwrap();
        assert!(analyze(input).is_err());
    }
    let input: Import =
        serde_json::from_str(include_str!("../fixtures/as-discovery.json")).unwrap();
    let report = analyze(input).unwrap();
    assert!(report.checks.iter().all(|c| c.status != Status::Fail));
    assert!(report
        .checks
        .iter()
        .find(|c| c.id == "discovery-key-rotation-type")
        .unwrap()
        .detail
        .contains("declares key rotation unsupported"));
}

#[tokio::test]
async fn ui_serves_accessible_discovery_controls_without_claiming_rs_discovery() {
    let response = app()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("content-security-policy"));
    let body = to_bytes(response.into_body(), MAX_UPLOAD).await.unwrap();
    let html = std::str::from_utf8(&body).unwrap();
    for label in [
        "for=\"queried-endpoint\"",
        "for=\"http-status\"",
        "for=\"operation\"",
        "not a certification",
        "RFC 9767",
    ] {
        assert!(html.contains(label));
    }
}
