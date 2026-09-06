//! Caller-declared pairs test label relationships, not authenticated exchanges.
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use gnap_conformance_web::{analyze, app, Report, Status, MAX_MESSAGE};
use serde_json::{json, Value};
use tower::ServiceExt;

fn pair(request: Value, response: Value) -> Value {
    json!({"request":{"access_token":request},"response":{"access_token":response}})
}
fn requested() -> Value {
    json!([{"label":"documents","access":["documents:read"]},
        {"label":"reports","access":["reports:read"]}])
}
fn issued(label: &str) -> Value {
    json!({"label":label,"value":"synthetic-only","access":[]})
}
fn raw(body: &str) -> Report {
    analyze(serde_json::from_value(json!({"kind":"token_exchange","body":body})).unwrap()).unwrap()
}
fn report(body: Value) -> Report {
    raw(&body.to_string())
}
fn status(report: &Report, id: &str) -> Status {
    report
        .checks
        .iter()
        .find(|check| check.id == id)
        .unwrap_or_else(|| panic!("missing {id}"))
        .status
}
fn unobserved(report: &Report) {
    assert_eq!(report.profile, "gnap-token-exchange-import-v1");
    assert!(!report.certification);
    assert_eq!(report.observation.source, "import");
    assert!(report.independence.contains("not gnap-types validators"));
    for id in [
        "token-exchange-authenticity",
        "token-exchange-authority",
        "token-exchange-lifecycle",
    ] {
        assert_eq!(status(report, id), Status::NotTested);
    }
}

#[test]
fn partial_and_reordered_labels_match_without_an_issuance_verdict() {
    for response in [
        json!([issued("reports")]),
        json!([issued("reports"), issued("documents")]),
    ] {
        let r = report(pair(requested(), response));
        assert_eq!(
            status(&r, "token-exchange-label-correspondence"),
            Status::Pass
        );
        assert_eq!(status(&r, "token-exchange-cardinality"), Status::Pass);
        assert!(r.checks.iter().all(|c| c.status != Status::Fail));
        unobserved(&r);
    }
}

#[test]
fn unknown_missing_duplicate_and_nonstring_labels_are_distinct_failures() {
    let r = report(pair(requested(), json!([issued("unknown")])));
    assert_eq!(status(&r, "token-exchange-response-labels"), Status::Pass);
    assert_eq!(
        status(&r, "token-exchange-label-correspondence"),
        Status::Fail
    );
    for answer in [
        json!([{"value":"synthetic"}]),
        json!([issued("reports"), issued("reports")]),
        json!([{"label":null}]),
        json!([{"label":7}]),
    ] {
        let r = report(pair(requested(), answer));
        assert_eq!(status(&r, "token-exchange-response-labels"), Status::Fail);
        assert_eq!(
            status(&r, "token-exchange-label-correspondence"),
            Status::NotTested
        );
        unobserved(&r);
    }
    for request in [
        json!([{"access":[]}]),
        json!([{"label":"reports"},{"label":"reports"}]),
    ] {
        let r = report(pair(request, json!([issued("reports")])));
        assert_eq!(status(&r, "token-exchange-request-labels"), Status::Fail);
        assert_eq!(
            status(&r, "token-exchange-label-correspondence"),
            Status::NotTested
        );
    }
}

#[test]
fn singleton_labels_follow_the_request_but_may_be_added_by_the_as() {
    for label in ["", "données/日本語", "documents"] {
        let r = report(pair(json!({"access":[]}), issued(label)));
        assert_eq!(
            status(&r, "token-exchange-label-correspondence"),
            Status::Pass
        );
        let r = report(pair(json!({"label":label,"access":[]}), issued(label)));
        assert_eq!(
            status(&r, "token-exchange-label-correspondence"),
            Status::Pass
        );
    }
    for response in [json!({"value":"synthetic"}), issued("another")] {
        let r = report(pair(json!({"label":"documents","access":[]}), response));
        assert_eq!(
            status(&r, "token-exchange-label-correspondence"),
            Status::Fail
        );
    }
    let r = report(pair(json!({"label":"é"}), issued("e\u{301}")));
    assert_eq!(
        status(&r, "token-exchange-label-correspondence"),
        Status::Fail
    );
}

#[test]
fn cardinality_does_not_collapse_for_a_partial_response() {
    for body in [
        pair(requested(), issued("reports")),
        pair(json!({"label":"reports"}), json!([issued("reports")])),
    ] {
        let r = report(body);
        assert_eq!(status(&r, "token-exchange-cardinality"), Status::Fail);
        assert_eq!(
            status(&r, "token-exchange-label-correspondence"),
            Status::NotTested
        );
    }
}

#[test]
fn absent_empty_or_malformed_fields_do_not_establish_issuance() {
    for response in [
        json!({}),
        json!({"continue":{}}),
        json!({"error":"request_denied"}),
        json!({"interact":{}}),
    ] {
        let r = report(json!({"request":{"access_token":requested()},"response":response}));
        assert_eq!(
            status(&r, "token-exchange-response-shape"),
            Status::NotTested
        );
        assert_eq!(
            status(&r, "token-exchange-label-correspondence"),
            Status::NotTested
        );
        unobserved(&r);
    }
    let r = report(pair(requested(), json!([])));
    assert_eq!(status(&r, "token-exchange-response-shape"), Status::Pass);
    assert_eq!(
        status(&r, "token-exchange-response-labels"),
        Status::NotTested
    );
    assert_eq!(
        status(&r, "token-exchange-label-correspondence"),
        Status::NotTested
    );
    for malformed in [json!(null), json!(7), json!("token"), json!([{}, 7])] {
        let r = report(pair(requested(), malformed));
        assert_eq!(status(&r, "token-exchange-response-shape"), Status::Fail);
        assert_eq!(status(&r, "token-exchange-cardinality"), Status::NotTested);
    }
}

#[test]
fn ambiguous_or_limited_json_is_inconclusive_without_last_wins_checks() {
    for body in [
        r#"{"request":{},"request":{},"response":{}}"#,
        r#"{"request":{"access_token":[{"label":"a","label":"b"}]},"response":{}}"#,
    ] {
        let r = raw(body);
        assert_eq!(
            status(&r, "token-exchange-json-unambiguous"),
            Status::NotTested
        );
        assert!(!r.checks.iter().any(|c| c.id == "token-exchange-pair"));
        unobserved(&r);
    }
    for body in [
        "{\"number\":1e999}".to_owned(),
        format!("{}0{}", "[".repeat(150), "]".repeat(150)),
    ] {
        let r = raw(&body);
        assert_eq!(status(&r, "token-exchange-json-object"), Status::NotTested);
    }
    for body in ["no json", "[]", "null"] {
        assert_eq!(
            status(&raw(body), "token-exchange-json-object"),
            Status::Fail
        );
    }
}

#[test]
fn envelope_constraints_and_reports_do_not_echo_submitted_values() {
    let marker = "NEVER-REFLECT-PRIVATE-VALUE";
    let r = report(pair(requested(), json!([issued(marker)])));
    assert!(!serde_json::to_string(&r).unwrap().contains(marker));
    for extra in [
        json!({"headers":[]}),
        json!({"content_digest":"sha-256=:AAAA:"}),
        json!({"rs_context":{}}),
    ] {
        let mut envelope = json!({"kind":"token_exchange","body":"{}"});
        envelope
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        assert!(analyze(serde_json::from_value(envelope).unwrap()).is_err());
    }
    assert!(analyze(
        serde_json::from_value(json!({"kind":"token_exchange","body":" ".repeat(MAX_MESSAGE+1)}))
            .unwrap()
    )
    .is_err());
    for malformed in [
        json!({}),
        json!({"request":null,"response":{}}),
        json!({"request":{},"response":[]}),
    ] {
        assert_eq!(
            status(&report(malformed), "token-exchange-pair"),
            Status::Fail
        );
    }
}

#[tokio::test]
async fn http_import_is_bounded_stateless_and_not_a_probe() {
    let input = json!({"kind":"token_exchange","body":pair(requested(), json!([issued("reports")])).to_string()});
    let response = app()
        .oneshot(
            Request::post("/api/analyze")
                .header("content-type", "application/json")
                .body(Body::from(input.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers()["cache-control"]
        .to_str()
        .unwrap()
        .contains("no-store"));
    let body = to_bytes(response.into_body(), 65_536).await.unwrap();
    let report: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(report["certification"], false);
    assert_eq!(report["profile"], "gnap-token-exchange-import-v1");
    let oversized = json!({"kind":"token_exchange","body":" ".repeat(MAX_MESSAGE + 1)});
    let response = app()
        .oneshot(
            Request::post("/api/analyze")
                .header("content-type", "application/json")
                .body(Body::from(oversized.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn fixtures_and_browser_help_name_the_local_pair_and_its_limits() {
    for (fixture, expected) in [
        (
            include_str!("../fixtures/token-exchange.json"),
            Status::Pass,
        ),
        (
            include_str!("../fixtures/invalid-token-exchange.json"),
            Status::Fail,
        ),
    ] {
        let report = analyze(serde_json::from_str(fixture).unwrap()).unwrap();
        assert_eq!(
            status(&report, "token-exchange-label-correspondence"),
            expected
        );
        unobserved(&report);
    }
    let html = include_str!("../static/index.html");
    let js = include_str!("../static/app.js");
    assert!(html.contains("value=\"token_exchange\""));
    assert!(html.contains("id=\"token-fixture\""));
    assert!(html.contains("not a GNAP wire message"));
    assert!(js.contains("byId(id).disabled = kind === 'token_exchange'"));
    assert!(!js.contains("innerHTML"));
}
