//! The JSON media type of a message: one field, whatever the parameters.

use gnap_types::http::{HttpRequest, HttpResponse};

#[test]
fn json_body_makes_application_json_the_only_content_type() {
    let request = HttpRequest::new("POST", "https://as.example/gnap")
        .header("Content-Type", "text/html")
        .header("content-type", "text/plain")
        .json_body(b"{}".to_vec());
    assert_eq!(
        request.header_values("content-type").collect::<Vec<_>>(),
        ["application/json"]
    );
    assert!(request.has_json_content_type());
}

#[test]
fn a_json_content_type_is_one_field_naming_application_json() {
    let response = |types: &[&str]| HttpResponse {
        status: 200,
        headers: types
            .iter()
            .map(|value| ("Content-Type".to_owned(), (*value).to_owned()))
            .collect(),
        body: b"{}".to_vec(),
    };
    for accepted in [
        &["application/json"][..],
        &["Application/JSON; charset=utf-8"],
    ] {
        assert!(response(accepted).has_json_content_type(), "{accepted:?}");
    }
    for refused in [
        &[][..],
        &["text/html"],
        &["application/json", "application/json"],
        &["text/html", "application/json"],
        &["application/jsonx"],
    ] {
        assert!(!response(refused).has_json_content_type(), "{refused:?}");
    }
}

/// One-time secrets stay out of the `Debug` output of the messages that
/// carry them: finish nonces, interaction references, and user codes.
#[test]
fn message_debug_output_hides_one_time_secrets() {
    use gnap_types::interact::{InteractCallback, InteractResponse};
    use gnap_types::message::{ContinueRequest, GrantRequest};

    let request: GrantRequest = serde_json::from_str(
        r#"{"client":"c","access_token":{"access":["read"]},
            "interact":{"start":["redirect"],"finish":{"method":"redirect",
            "uri":"https://client.example/cb","nonce":"SECRET-CLIENT-NONCE"}}}"#,
    )
    .unwrap();
    let response: InteractResponse = serde_json::from_str(
        r#"{"redirect":"https://as.example/i/handle","finish":"SECRET-AS-NONCE",
            "user_code":"SECRET-CODE",
            "user_code_uri":{"code":"SECRET-CODE","uri":"https://as.example/code"}}"#,
    )
    .unwrap();
    let callback = InteractCallback {
        hash: "hash".into(),
        interact_ref: "SECRET-REF".into(),
    };
    let continuation = ContinueRequest {
        interact_ref: Some("SECRET-REF".into()),
        ..ContinueRequest::default()
    };
    let shown = format!("{request:?} {response:?} {callback:?} {continuation:?}");
    assert!(
        !shown.contains("SECRET"),
        "a one-time secret leaked: {shown}"
    );
    assert!(shown.contains("https://client.example/cb"), "{shown}");
}
