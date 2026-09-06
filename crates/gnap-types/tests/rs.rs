//! RFC 9767 discovery and introspection message boundaries.

use gnap_types::rs::{
    IntrospectionRequest, IntrospectionResponse, ResourceServer, RsDiscovery, RsErrorResponse,
};

#[test]
fn introspection_has_its_own_required_resource_server_identity() {
    let request: IntrospectionRequest = serde_json::from_str(
        r#"{"access_token":"opaque","resource_server":"files","extension":true}"#,
    )
    .unwrap();
    assert_eq!(request.resource_server.as_reference(), Some("files"));
    assert!(request.proof.is_none());
    assert!(request.access.is_none());
    assert_eq!(request.extra["extension"], true);
    for body in [
        r#"{"access_token":"opaque","client":"files"}"#,
        r#"{"resource_server":"files"}"#,
        r#"{"access_token":"opaque","resource_server":{}}"#,
        r#"{"access_token":"opaque","resource_server":""}"#,
    ] {
        assert!(serde_json::from_str::<IntrospectionRequest>(body).is_err());
    }
    let value: ResourceServer = serde_json::from_str(r#"{"key":"registered-rs-key"}"#).unwrap();
    assert!(value.as_value().is_some());
}

#[test]
fn inactive_is_only_active_false_and_active_requires_issuer_and_access() {
    assert_eq!(
        serde_json::to_string(&IntrospectionResponse::Inactive).unwrap(),
        r#"{"active":false}"#
    );
    for body in [
        r#"{"active":false,"access":[]}"#,
        r#"{"active":false,"extension":true}"#,
        r#"{"active":true,"access":[]}"#,
        r#"{"active":true,"iss":"https://as.example/gnap"}"#,
        r#"{"active":true,"access":[],"iss":"https://as.example/gnap","value":"secret"}"#,
    ] {
        assert!(
            serde_json::from_str::<IntrospectionResponse>(body).is_err(),
            "{body}"
        );
    }
}

#[test]
fn discovery_is_at_the_grant_origin_not_its_path_or_query() {
    let discovery: RsDiscovery = serde_json::from_str(
        r#"{"grant_request_endpoint":"https://as.example:8443/a/gnap?tenant=1","introspection_endpoint":"https://as.example:8443/introspect"}"#,
    )
    .unwrap();
    assert_eq!(
        discovery.discovery_url().unwrap(),
        "https://as.example:8443/.well-known/gnap-as-rs"
    );
    for endpoint in [
        "http://as.example/gnap",
        "https:///gnap",
        "https://as.example/gnap#fragment",
    ] {
        let mut invalid = discovery.clone();
        invalid.grant_request_endpoint = endpoint.into();
        assert!(invalid.discovery_url().is_err());
    }
}

#[test]
fn key_binding_and_duplicate_response_fields_are_not_ambiguous() {
    for body in [
        r#"{"active":true,"access":[],"iss":"https://as.example/gnap","key":"registered-client-key","extension":true}"#,
        r#"{"active":true,"access":[],"iss":"https://as.example/gnap","flags":["bearer"]}"#,
    ] {
        let response: IntrospectionResponse = serde_json::from_str(body).unwrap();
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            serde_json::from_str::<serde_json::Value>(body).unwrap()
        );
    }
    for body in [
        r#"{"active":true,"access":[],"iss":"https://as.example/gnap"}"#,
        r#"{"active":true,"access":[],"iss":"https://as.example/gnap","key":"key","flags":["bearer"]}"#,
        r#"{"active":false,"active":true}"#,
        r#"{"active":true,"access":[],"access":["expanded"],"iss":"https://as.example/gnap","key":"key"}"#,
        r#"{"active":true,"access":[],"iss":"https://as.example/gnap","key":"key","manage":{"uri":"https://as.example/token/handle"}}"#,
    ] {
        assert!(
            serde_json::from_str::<IntrospectionResponse>(body).is_err(),
            "{body}"
        );
    }
}

#[test]
fn rs_errors_are_strings_or_objects_inside_a_single_error_field() {
    for body in [
        r#"{"error":"invalid_resource_server"}"#,
        r#"{"error":{"code":"invalid_access","description":"Not permitted for this RS"}}"#,
    ] {
        let response: RsErrorResponse = serde_json::from_str(body).unwrap();
        assert_eq!(
            serde_json::to_value(response).unwrap(),
            serde_json::from_str::<serde_json::Value>(body).unwrap()
        );
    }
    for body in [
        r#"{"error":"invalid_access","active":false}"#,
        r#"{"error":false}"#,
        r#"{"error":""}"#,
        r#"{"error":"échec"}"#,
        r#"{"error":{"code":"échec"}}"#,
        r#"{"error":{"description":"missing code"}}"#,
    ] {
        assert!(serde_json::from_str::<RsErrorResponse>(body).is_err());
    }
}

#[test]
fn http_loopback_is_an_explicit_discovery_deviation() {
    for host in ["localhost", "127.0.0.1", "[::1]"] {
        let discovery: RsDiscovery = serde_json::from_value(serde_json::json!({"grant_request_endpoint":format!("http://{host}:8080/gnap?x=1"),"introspection_endpoint":format!("http://{host}:8080/introspect")})).unwrap();
        assert!(discovery.discovery_url().is_err());
        assert_eq!(
            discovery.discovery_url_for_local_development().unwrap(),
            format!("http://{host}:8080/.well-known/gnap-as-rs")
        );
    }
    for endpoint in [
        "http://remote.example/gnap",
        "https://[::1]evil/gnap",
        "https://as.example:bad/gnap",
    ] {
        let discovery: RsDiscovery =
            serde_json::from_value(serde_json::json!({"grant_request_endpoint":endpoint})).unwrap();
        assert!(discovery.discovery_url_for_local_development().is_err());
    }
}
