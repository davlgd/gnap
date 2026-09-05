//! Bounded, stateless GNAP message diagnostics. This is not a certification suite.

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Request},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use gnap_types::{ContinueRequest, GrantRequest, GrantResponse};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

pub mod probe;
mod rs_import;
pub use rs_import::{Binding as TokenBinding, Context as RsContext};

pub const MAX_UPLOAD: usize = 65_536;
pub const MAX_MESSAGE: usize = 32_768;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    GrantRequest,
    GrantResponse,
    ContinueRequest,
    RsDiscovery,
    IntrospectionRequest,
    IntrospectionResponse,
    RsErrorResponse,
}

/// Headers are optional: absence means the trace did not capture them, not an
/// empty list of actual headers. Keep duplicates and the exact message bytes.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Import {
    pub kind: MessageKind,
    pub body: String,
    pub headers: Option<Vec<(String, String)>>,
    pub content_digest: Option<String>,
    pub rs_context: Option<RsContext>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    Fail,
    NotTested,
}

#[derive(Debug, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub status: Status,
    pub detail: &'static str,
    pub reference: &'static str,
    pub remediation: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct Observation {
    pub source: &'static str,
    pub harness_version: &'static str,
    pub revision: String,
    pub observed_at_unix_seconds_utc: u64,
}

pub fn observation(source: &'static str) -> Observation {
    let revision = std::env::var("CC_COMMIT_ID")
        .ok()
        .filter(|v| (7..=64).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_hexdigit()))
        .unwrap_or_else(|| "unknown".into());
    Observation {
        source,
        harness_version: env!("CARGO_PKG_VERSION"),
        revision,
        observed_at_unix_seconds_utc: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    }
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: u8,
    pub profile: &'static str,
    pub kind: MessageKind,
    pub certification: bool,
    pub independence: &'static str,
    pub observation: Observation,
    pub checks: Vec<Check>,
}

fn check(
    id: &'static str,
    outcome: Option<bool>,
    detail: &'static str,
    reference: &'static str,
) -> Check {
    let remediation = (outcome == Some(false)).then_some(match id {
        "message-shape" => "Check required fields and JSON types for the selected message kind. A continuation must not repeat client. Token request arrays require labels. Consult the linked section; submitted values are deliberately not echoed.",
        "key-presentation" => "Supply exactly one key format. A JWK must have string alg and kid, alg must not be none, and kty must not be oct when sent by value.",
        "display-uris" | "continuation-uri" => "Replace relative URIs with absolute URIs. Do not paste a production token or private URL into this public tool.",
        "interaction-finish" => "Check finish method, absolute callback URI without fragment, and a nonempty ASCII nonce without newline.",
        "response-no-store" | "error-response-no-store" => "Add Cache-Control: no-store to the AS response, including error responses. If capture is incomplete, omit headers instead of submitting an empty captured list.",
        "content-digest" => "Compute Content-Digest from the original exact body bytes; do not reformat JSON afterward. Use a supported sha-256 or sha-512 dictionary member and valid Structured Fields syntax.",
        "user-identifiers" | "subject-identifiers" => "Ensure identifiers from the same issuer do not disagree about the subject; identity and assertion authenticity need separate validation.",
        "malformed-request-gnap-error-only" => "Return a GNAP error without access tokens or interaction results. An error response may include continue only for a pending grant.",
        "malformed-request-http-4xx" => "A suitable 4xx status is recommended by this deployment profile, not required by RFC 9635. Evaluate the GNAP error body separately.",
        "known-error-code" => "Compare the code with the current IANA GNAP Error Codes registry; this build's vendored snapshot may lag a new registration.",
        "error-response-json" => "Return application/json and a GNAP error field for rejected grant requests. Check reverse-proxy errors separately from AS errors.",
        "protected-resource-rejects-unauthenticated" => "Verify that this exact endpoint is intended to require authentication. If it is, reject credential-free access. A public resource is not an appropriate target for this policy test.",
        _ => "Inspect the linked RFC section and the named SDK validation rule. No raw submitted values are included in this report.",
    });
    Check {
        id,
        status: match outcome {
            Some(true) => Status::Pass,
            Some(false) => Status::Fail,
            None => Status::NotTested,
        },
        detail,
        reference,
        remediation,
    }
}

const RFC: &str = "https://www.rfc-editor.org/rfc/rfc9635.html";

fn parse_check<T: serde::de::DeserializeOwned>(
    body: &str,
    checks: &mut Vec<Check>,
    reference: &'static str,
) -> Option<T> {
    // Error Display implementations can contain submitted secrets. Deliberately
    // return stable diagnostics, never the supplied field value or parser text.
    let parsed = serde_json::from_str(body);
    checks.push(check("message-shape", Some(parsed.is_ok()), "Typed JSON shape only; extensions may be accepted. Does not validate protocol state or every normative requirement.", reference));
    parsed.ok()
}

pub fn analyze(input: Import) -> Result<Report, &'static str> {
    if input.body.len() > MAX_MESSAGE {
        return Err("Message exceeds 32768 UTF-8 bytes.");
    }
    if input.headers.as_ref().is_some_and(|h| {
        h.len() > 64
            || h.iter().any(|(n, v)| {
                n.len() > 128
                    || v.len() > 4096
                    || n.contains(['\r', '\n'])
                    || v.contains(['\r', '\n'])
            })
    }) {
        return Err("At most 64 headers; names <=128 bytes, values <=4096 bytes, no CR/LF.");
    }
    if input
        .content_digest
        .as_ref()
        .is_some_and(|d| d.len() > 4096)
    {
        return Err("Content-Digest exceeds 4096 bytes.");
    }
    let mut checks = Vec::new();
    rs_import::validate_context(&input)?;
    match input.kind {
        MessageKind::RsDiscovery
        | MessageKind::IntrospectionRequest
        | MessageKind::IntrospectionResponse
        | MessageKind::RsErrorResponse => return rs_import::analyze(&input),
        MessageKind::GrantRequest => {
            if let Some(req) = parse_check::<GrantRequest>(
                &input.body,
                &mut checks,
                "https://www.rfc-editor.org/rfc/rfc9635.html#section-2",
            ) {
                let client = req.client.as_value();
                checks.push(check("key-presentation", client.and_then(|c| c.key.as_value()).map(|k| k.validate().is_ok()), "Selected key presentation rules: exactly one format, JWK alg/kid strings, no alg none or symmetric key by value. Not mathematical key validation, certificate validation or private-parameter detection. References are not resolved.", "https://www.rfc-editor.org/rfc/rfc9635.html#section-7.1"));
                checks.push(check("display-uris", client.and_then(|c| c.display.as_ref()).map(|d| d.validate().is_ok()), "When display is present, supplied display URIs must be absolute. No URI is fetched.", "https://www.rfc-editor.org/rfc/rfc9635.html#section-2.3.2"));
                finish_check(req.interact.as_ref(), &mut checks);
                checks.push(check("user-identifiers", req.user.as_ref().and_then(|u| u.as_value()).map(|u| u.validate().is_ok()), "Selected same-issuer subject identifier consistency; does not prove real-world identity or validate assertions.", "https://www.rfc-editor.org/rfc/rfc9635.html#section-2.4"));
            }
        }
        MessageKind::ContinueRequest => {
            if let Some(req) = parse_check::<ContinueRequest>(
                &input.body,
                &mut checks,
                "https://www.rfc-editor.org/rfc/rfc9635.html#section-5.3",
            ) {
                finish_check(req.interact.as_ref(), &mut checks);
                checks.push(check(
                    "user-identifiers",
                    req.user
                        .as_ref()
                        .and_then(|u| u.as_value())
                        .map(|u| u.validate().is_ok()),
                    "Selected same-issuer subject consistency only; no grant or identity lookup.",
                    "https://www.rfc-editor.org/rfc/rfc9635.html#section-2.4",
                ));
            }
        }
        MessageKind::GrantResponse => {
            if let Some(res) = parse_check::<GrantResponse>(
                &input.body,
                &mut checks,
                "https://www.rfc-editor.org/rfc/rfc9635.html#section-3",
            ) {
                checks.push(check("continuation-uri", res.r#continue.as_ref().map(|c| c.validate().is_ok()), "Continuation URI absolute syntax only; reachability, transport and token validity are not checked.", "https://www.rfc-editor.org/rfc/rfc9635.html#section-3.1"));
                checks.push(check("issued-token-constraints", res.access_token.as_ref().map(|t| t.validate().is_ok()), "Selected access-token flags, key and management constraints implemented by the SDK. No lifecycle, rights or request/response cardinality comparison.", "https://www.rfc-editor.org/rfc/rfc9635.html#section-3.2"));
                checks.push(check("subject-identifiers", res.subject.as_ref().map(|s| s.validate().is_ok()), "Selected same-issuer subject identifier consistency only; assertions are not cryptographically verified.", "https://www.rfc-editor.org/rfc/rfc9635.html#section-3.4"));
            }
            checks.push(check("response-no-store", input.headers.as_ref().map(|h| gnap_types::http::HttpResponse { status: 200, headers: h.clone(), body: vec![] }.has_no_store()), "The captured response must contain a no-store Cache-Control directive. Omitted headers mean not tested; an empty captured list fails.", "https://www.rfc-editor.org/rfc/rfc9635.html#section-3"));
        }
    }
    checks.push(check("content-digest", input.content_digest.as_ref().map(|d| gnap_crypto::verify_content_digest(input.body.as_bytes(), d).is_ok()), "Checks the separately supplied digest against the exact UTF-8 body bytes. Missing digest is not tested, not proof that omission is allowed. This is not a signature check.", "https://www.rfc-editor.org/rfc/rfc9635.html#section-7.3.1"));
    checks.extend([
        check("request-proof", None, "Not tested: cryptographic signature, required covered components, trusted key, token binding, timestamps and nonce replay need full request context and state.", "https://www.rfc-editor.org/rfc/rfc9635.html#section-7"),
        check("grant-lifecycle", None, "Not tested: consent, continuation timing, callback hash, rotation, revocation, expiration, state transitions, rights and cross-message relationships.", RFC),
        check("resource-server", None, "Not tested: RS authentication, introspection, audience and rights enforcement, discovery and resource registration.", "https://www.rfc-editor.org/rfc/rfc9767.html"),
        check("transport-and-interop", None, "Not tested: TLS, actual HTTP status/media types, live AS/RS behavior, independent implementation interoperability, mtls/jwsd/jws profiles.", RFC),
    ]);
    Ok(Report { schema_version: 1, profile: "gnap-import-diagnostics-v1", kind: input.kind, certification: false, independence: "Shared gnap-types and gnap-crypto implementation; not an independent conformance oracle. Pass applies only to each named check.", observation: observation("import"), checks })
}

fn finish_check(interact: Option<&gnap_types::interact::InteractRequest>, checks: &mut Vec<Check>) {
    checks.push(check("interaction-finish", interact.and_then(|i| i.finish.as_ref()).map(|f| f.validate().is_ok()), "Selected finish URI and nonce shape rules only. Does not test callback execution, entropy or uniqueness.", "https://www.rfc-editor.org/rfc/rfc9635.html#section-2.5.2"));
}

pub fn app() -> Router {
    app_with_probes(probe::Probes::disabled())
}

pub fn app_with_probes(probes: probe::Probes) -> Router {
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
        .route(
            "/style.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../static/style.css"),
                )
            }),
        )
        .route("/health", get(|| async { "ok" }))
        .route("/api/analyze", post(import_handler))
        .route("/api/targets", get(probe::targets))
        .route("/api/probe", post(probe::run))
        .with_state(probes)
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
        ("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"),
        ("permissions-policy", "camera=(), microphone=(), geolocation=()"),
    ] { response.headers_mut().insert(name, HeaderValue::from_static(value)); }
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
        return (StatusCode::BAD_REQUEST, "Invalid import envelope. Expected kind, body string, optional headers array, content_digest string and kind-specific rs_context object.").into_response();
    };
    match analyze(input) {
        Ok(report) => Json(report).into_response(),
        Err(reason) => (StatusCode::BAD_REQUEST, reason).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
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
        }
    }
    fn status(report: &Report, id: &str) -> Status {
        report.checks.iter().find(|c| c.id == id).unwrap().status
    }

    #[test]
    fn shape_does_not_mean_certification() {
        let report = analyze(imported(
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
        let report = analyze(imported(
            MessageKind::ContinueRequest,
            r#"{"client":"demo-client"}"#,
        ))
        .unwrap();
        assert_eq!(status(&report, "message-shape"), Status::Fail);
    }

    #[test]
    fn catches_semantic_key_error_after_deserializing() {
        let report = analyze(imported(
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
                &analyze(imported(MessageKind::GrantResponse, "{}")).unwrap(),
                "response-no-store"
            ),
            Status::NotTested
        );
        input.headers = Some(vec![]);
        assert_eq!(
            status(&analyze(input).unwrap(), "response-no-store"),
            Status::Fail
        );
        let mut input = imported(MessageKind::GrantResponse, "{}");
        input.headers = Some(vec![("cache-control".into(), "private, no-store".into())]);
        assert_eq!(
            status(&analyze(input).unwrap(), "response-no-store"),
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
            status(&analyze(input).unwrap(), "content-digest"),
            Status::Fail
        );
        let mut input = imported(MessageKind::ContinueRequest, "{}");
        input.content_digest = Some(gnap_crypto::content_digest(
            b"{}",
            gnap_crypto::DigestAlgorithm::Sha256,
        ));
        assert_eq!(
            status(&analyze(input).unwrap(), "content-digest"),
            Status::Pass
        );
    }

    #[test]
    fn no_reflection_of_values_in_parser_or_validation_errors() {
        for body in [
            r#"{"client":123,"secret":"<script>TOP-SECRET</script>"}"#,
            r#"{"client":{"key":{"proof":"httpsig"},"display":{"uri":"TOP-SECRET"}}}"#,
        ] {
            let report =
                serde_json::to_string(&analyze(imported(MessageKind::GrantRequest, body)).unwrap())
                    .unwrap();
            assert!(!report.contains("TOP-SECRET"));
            assert!(!report.contains("<script>"));
        }
    }

    #[test]
    fn message_and_header_limits() {
        assert!(analyze(imported(
            MessageKind::ContinueRequest,
            &" ".repeat(MAX_MESSAGE + 1)
        ))
        .is_err());
        let mut input = imported(MessageKind::ContinueRequest, "{}");
        input.headers = Some(vec![("x".into(), "secret\r\nheader".into())]);
        assert!(analyze(input).is_err());
        let mut input = imported(MessageKind::ContinueRequest, "{}");
        input.headers = Some(vec![("x".into(), "y".into()); 65]);
        assert!(analyze(input).is_err());
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
        assert!(!String::from_utf8(
            to_bytes(response.into_body(), MAX_UPLOAD)
                .await
                .unwrap()
                .to_vec()
        )
        .unwrap()
        .contains("TOP-SECRET"));
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
