//! Synthetic offline oracle tests, not downstream-token execution evidence.
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use gnap_conformance_web::{analyze, app, Report, Status, MAX_MESSAGE, MAX_UPLOAD};
use serde_json::{json, Value};
use tower::ServiceExt;

const REQUEST: &str = "derivation_request";
const RESPONSE: &str = "derivation_response";
const UNOBSERVABLE: [&str; 6] = [
    "derivation-proof-and-parent-validity",
    "derivation-parent-rs-suitability",
    "derivation-effective-rights-and-audience",
    "derivation-revocation-and-lineage",
    "derivation-grant-exchange",
    "derivation-token-value-encoding",
];
fn raw(kind: &str, body: &str) -> Report {
    analyze(serde_json::from_value(json!({"kind":kind,"body":body})).unwrap()).unwrap()
}
fn report(kind: &str, body: Value) -> Report {
    raw(kind, &body.to_string())
}
fn status(report: &Report, id: &str) -> Status {
    report
        .checks
        .iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("missing {id}"))
        .status
}
fn request() -> Value {
    json!({"existing_access_token":"synthetic-parent","client":"synthetic-rs1","access_token":{"access":[]}})
}
fn response() -> Value {
    json!({"access_token":{"value":"synthetic-child","access":[]}})
}
fn inconclusive(r: &Report) {
    assert!(!r.certification);
    assert_eq!(r.observation.source, "import");
    for id in UNOBSERVABLE {
        assert_eq!(status(r, id), Status::NotTested);
    }
}

#[test]
fn positive_fixtures_have_distinct_profiles_and_no_protocol_verdict() {
    for (fixture, profile, ids) in [
        (
            include_str!("../fixtures/derivation-request.json"),
            "gnap-derivation-request-import-v1",
            vec![
                "derivation-request-parent",
                "derivation-request-client",
                "derivation-request-token-shape",
                "derivation-request-access",
                "derivation-request-labels",
            ],
        ),
        (
            include_str!("../fixtures/derivation-response.json"),
            "gnap-derivation-response-import-v1",
            vec![
                "derivation-response-token-shape",
                "derivation-response-value",
                "derivation-response-access",
                "derivation-response-labels",
                "derivation-response-token-optionals",
            ],
        ),
    ] {
        let r = analyze(serde_json::from_str(fixture).unwrap()).unwrap();
        assert_eq!(r.profile, profile);
        assert!(r.independence.contains("not gnap-types validators"));
        for id in ids {
            assert_eq!(status(&r, id), Status::Pass);
        }
        assert!(r.checks.iter().all(|c| c.status != Status::Fail));
        inconclusive(&r);
    }
}

#[test]
fn selected_token_request_requires_parent_client_and_access_token() {
    for (field, id, bad) in [
        (
            "existing_access_token",
            "derivation-request-parent",
            vec![json!(null), json!(7), json!({})],
        ),
        (
            "client",
            "derivation-request-client",
            vec![json!(null), json!({}), json!({"key":7}), json!([])],
        ),
        (
            "access_token",
            "derivation-request-token-shape",
            vec![json!(null), json!("token"), json!([{}, 7])],
        ),
    ] {
        let mut body = request();
        body.as_object_mut().unwrap().remove(field);
        assert_eq!(status(&report(REQUEST, body), id), Status::Fail);
        for bad in bad {
            let mut body = request();
            body[field] = bad;
            assert_eq!(status(&report(REQUEST, body), id), Status::Fail);
        }
    }
    let mut body = request();
    body.as_object_mut().unwrap().remove("client");
    body["resource_server"] = json!("not-a-client-replacement");
    assert_eq!(
        status(&report(REQUEST, body), "derivation-request-client"),
        Status::Fail
    );
}

#[test]
fn string_parent_and_outer_key_shape_are_not_token_or_proof_validation() {
    for parent in [
        "",
        "a parent with spaces",
        "un jeton éphémère",
        "not-token68:\n",
    ] {
        for client in [json!("rs1"), json!({"key":"reference"}), json!({"key":{}})] {
            let mut body = request();
            body["existing_access_token"] = json!(parent);
            body["client"] = client;
            let r = report(REQUEST, body);
            assert_eq!(status(&r, "derivation-request-parent"), Status::Pass);
            assert_eq!(status(&r, "derivation-request-client"), Status::Pass);
            inconclusive(&r);
        }
    }
}

#[test]
fn access_requires_gnap_array_and_object_type_without_a_nonempty_profile_rule() {
    for (kind, base, id) in [
        (REQUEST, request(), "derivation-request-access"),
        (RESPONSE, response(), "derivation-response-access"),
    ] {
        let mut missing = base.clone();
        missing["access_token"]
            .as_object_mut()
            .unwrap()
            .remove("access");
        assert_eq!(status(&report(kind, missing), id), Status::Fail);
        for (access, expected) in [
            (json!([]), Status::Pass),
            (json!(["reference"]), Status::Pass),
            (json!([{"type":"api","actions":["read"]}]), Status::Pass),
            (json!(null), Status::Fail),
            (json!({}), Status::Fail),
            (json!([7]), Status::Fail),
            (json!([{"actions":["read"]}]), Status::Fail),
            (json!([{"type":"api","actions":true}]), Status::Fail),
        ] {
            let mut body = base.clone();
            body["access_token"]["access"] = access;
            assert_eq!(status(&report(kind, body), id), expected);
        }
    }
}

#[test]
fn multiple_token_labels_are_required_strings_and_unique_in_each_message() {
    for (kind, base, id) in [
        (REQUEST, request(), "derivation-request-labels"),
        (RESPONSE, response(), "derivation-response-labels"),
    ] {
        for (labels, expected) in [
            (
                vec![Some(json!("first")), Some(json!("second"))],
                Status::Pass,
            ),
            (vec![Some(json!("")), Some(json!("second"))], Status::Pass),
            (vec![Some(json!("same")), Some(json!("same"))], Status::Fail),
            (vec![Some(json!("first")), None], Status::Fail),
            (vec![Some(json!(7))], Status::Fail),
        ] {
            let mut body = base.clone();
            body["access_token"] = Value::Array(
                labels
                    .into_iter()
                    .map(|label| {
                        let mut token = base["access_token"].clone();
                        if let Some(label) = label {
                            token["label"] = label;
                        }
                        token
                    })
                    .collect(),
            );
            let r = report(kind, body);
            assert_eq!(status(&r, id), expected);
            assert_eq!(status(&r, "derivation-grant-exchange"), Status::NotTested);
        }
        assert_eq!(status(&report(kind, base.clone()), id), Status::NotTested);
        let mut body = base;
        body["access_token"]["label"] = json!(7);
        assert_eq!(status(&report(kind, body), id), Status::Fail);
    }
}

#[test]
fn flags_are_unique_strings_without_forbidding_extensions_or_bearer_requests() {
    for (kind, base, id) in [
        (REQUEST, request(), "derivation-request-flags"),
        (RESPONSE, response(), "derivation-response-flags"),
    ] {
        for (flags, expected) in [
            (json!(["bearer"]), Status::Pass),
            (json!(["future-flag"]), Status::Pass),
            (json!([]), Status::Pass),
            (json!(["bearer", "bearer"]), Status::Fail),
            (json!(null), Status::Fail),
            (json!([1]), Status::Fail),
        ] {
            let mut body = base.clone();
            body["access_token"]["flags"] = flags;
            let r = report(kind, body);
            assert_eq!(status(&r, id), expected);
            inconclusive(&r);
        }
    }
}

#[test]
fn response_value_is_required_but_encoding_is_explicitly_not_checked() {
    let mut missing = response();
    missing["access_token"]
        .as_object_mut()
        .unwrap()
        .remove("value");
    assert_eq!(
        status(&report(RESPONSE, missing), "derivation-response-value"),
        Status::Fail
    );
    for (value, expected) in [
        (json!(7), Status::Fail),
        (json!(null), Status::Fail),
        (json!(""), Status::Pass),
        (json!("outside token68:\né"), Status::Pass),
    ] {
        let mut body = response();
        body["access_token"]["value"] = value;
        let r = report(RESPONSE, body);
        assert_eq!(status(&r, "derivation-response-value"), expected);
        assert_eq!(
            status(&r, "derivation-token-value-encoding"),
            Status::NotTested
        );
        assert!(r
            .checks
            .iter()
            .find(|c| c.id == "derivation-response-value")
            .unwrap()
            .detail
            .contains("string shape ONLY"));
    }
}

#[test]
fn bearer_key_contradiction_fails_but_no_key_does_not_prove_rs1_binding() {
    for key in [json!(null), json!("reference"), json!({})] {
        let mut body = response();
        body["access_token"]["flags"] = json!(["bearer"]);
        body["access_token"]["key"] = key;
        assert_eq!(
            status(
                &report(RESPONSE, body),
                "derivation-response-key-binding-shape"
            ),
            Status::Fail
        );
    }
    for key in [json!("reference"), json!({})] {
        let mut body = response();
        body["access_token"]["key"] = key;
        let r = report(RESPONSE, body);
        assert_eq!(
            status(&r, "derivation-response-key-binding-shape"),
            Status::Pass
        );
        inconclusive(&r);
    }
    inconclusive(&report(RESPONSE, response()));
}

#[test]
fn interaction_subject_extensions_and_type_token_are_not_demo_profile_failures() {
    let mut body = request();
    body["interact"] = json!({"start":["redirect"]});
    body["subject"] = json!({});
    body["user"] = json!("reference");
    body["type_token"] = json!({"future":"extension"});
    body["access_token"]["type_token"] = json!("biscuit");
    let r = report(REQUEST, body);
    assert!(r.checks.iter().all(|c| c.status != Status::Fail));
    inconclusive(&r);
    assert_eq!(status(&r, "rs-extension-semantics"), Status::NotTested);
    for (field, value) in [
        ("interact", json!([])),
        ("subject", json!(null)),
        ("user", json!(7)),
    ] {
        let mut body = request();
        body[field] = value;
        assert_eq!(
            status(&report(REQUEST, body), "derivation-request-optional-shape"),
            Status::Fail
        );
    }
}

#[test]
fn pending_error_empty_and_empty_token_array_never_establish_issuance() {
    for body in [
        json!({}),
        json!({"continue":{}}),
        json!({"interact":{}}),
        json!({"error":"invalid_request"}),
        json!({"error":{"code":"invalid_request"}}),
    ] {
        let r = report(RESPONSE, body);
        for id in [
            "derivation-response-token-shape",
            "derivation-response-value",
            "derivation-response-access",
        ] {
            assert_eq!(status(&r, id), Status::NotTested);
        }
        assert!(r.checks.iter().all(|c| c.status != Status::Fail));
        inconclusive(&r);
    }
    for kind in [REQUEST, RESPONSE] {
        let mut body = request();
        body["access_token"] = json!([]);
        let r = report(kind, body);
        let id = if kind == REQUEST {
            "derivation-request-access"
        } else {
            "derivation-response-access"
        };
        assert_eq!(status(&r, id), Status::NotTested);
        inconclusive(&r);
    }
}

#[test]
fn optional_response_fields_only_check_their_named_outer_types() {
    for (field, value, expected) in [
        ("expires_in", json!(12), Status::Pass),
        ("expires_in", json!(-1), Status::Pass),
        ("expires_in", json!(1.5), Status::Fail),
        ("manage", json!({}), Status::Pass),
        ("manage", json!(null), Status::Fail),
    ] {
        let mut body = response();
        body["access_token"][field] = value;
        assert_eq!(
            status(
                &report(RESPONSE, body),
                "derivation-response-token-optionals"
            ),
            expected
        );
    }
    for field in ["continue", "interact", "subject", "instance_id", "error"] {
        let mut body = response();
        body[field] = json!(7);
        assert_eq!(
            status(
                &report(RESPONSE, body),
                "derivation-response-optional-shape"
            ),
            Status::Fail
        );
    }
}

#[test]
fn ambiguity_limits_and_context_do_not_smuggle_evidence_or_echo_values() {
    for kind in [REQUEST, RESPONSE] {
        for body in [
            r#"{"client":"first","client":"second"}"#,
            r#"{"extra":{"secret":1,"secret":2}}"#,
        ] {
            let r = raw(kind, body);
            assert_eq!(status(&r, "rs-json-unambiguous"), Status::NotTested);
            assert!(!r
                .checks
                .iter()
                .any(|c| c.id.starts_with("derivation-request-")
                    || c.id.starts_with("derivation-response-")));
            inconclusive(&r);
        }
        for body in [
            "{\"big\":1e999}".to_owned(),
            format!("{}0{}", "[".repeat(140), "]".repeat(140)),
        ] {
            assert_eq!(
                status(&raw(kind, &body), "rs-message-json-object"),
                Status::NotTested
            );
        }
        for body in ["{", "null", "[]"] {
            assert_eq!(
                status(&raw(kind, body), "rs-message-json-object"),
                Status::Fail
            );
        }
        for context in [
            json!({}),
            json!({"http_status":200}),
            json!({"token_binding":"bound"}),
        ] {
            assert!(analyze(
                serde_json::from_value(json!({"kind":kind,"body":"{}","rs_context":context}))
                    .unwrap()
            )
            .is_err());
        }
        assert!(analyze(
            serde_json::from_value(json!({"kind":kind,"body":"x".repeat(MAX_MESSAGE + 1)}))
                .unwrap()
        )
        .is_err());
    }
}

#[test]
fn negative_fixtures_fail_precisely_without_certification() {
    for (fixture, ids) in [
        (
            include_str!("../fixtures/invalid-derivation-request.json"),
            vec![
                "derivation-request-parent",
                "derivation-request-client",
                "derivation-request-access",
                "derivation-request-labels",
                "derivation-request-flags",
            ],
        ),
        (
            include_str!("../fixtures/invalid-derivation-response.json"),
            vec![
                "derivation-response-value",
                "derivation-response-access",
                "derivation-response-key-binding-shape",
                "derivation-response-token-optionals",
            ],
        ),
    ] {
        let r = analyze(serde_json::from_str(fixture).unwrap()).unwrap();
        for id in ids {
            assert_eq!(status(&r, id), Status::Fail);
        }
        inconclusive(&r);
    }
}

#[tokio::test]
async fn http_routes_and_ui_preserve_redaction_and_scope() {
    for kind in [REQUEST, RESPONSE] {
        let mut body = request();
        body["existing_access_token"] = json!("PRIVATE-MARKER<script>");
        body["client"] = json!({"key":"PRIVATE-MARKER<script>"});
        body["access_token"]["value"] = json!("PRIVATE-MARKER<script>");
        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/analyze")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"kind":kind,"body":body.to_string()}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let bytes = to_bytes(response.into_body(), MAX_UPLOAD).await.unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains("PRIVATE-MARKER"));
        assert!(!text.contains("<script>"));
        let r: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(r["certification"], false);
        assert_eq!(r["kind"], kind);
    }
    for (path, expected) in [
        ("/", "value=\"derivation_request\""),
        ("/", "value=\"derivation_response\""),
        ("/app.js", "not token68 encoding"),
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
