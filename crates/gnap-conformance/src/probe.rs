//! The checks of an unsigned probe.
//!
//! They read an authorization server's answer to a malformed initial grant
//! request, or a protected resource's answer to a request without
//! credentials. The caller sends the request and captures the answer.

use crate::{Check, check};

/// The checks of a protected resource's answer to a request without
/// credentials, from its status: a 401 or 403 passes, which a server that
/// denies everything also does.
#[must_use]
pub fn unauthenticated_resource_checks(status: u16) -> Vec<Check> {
    vec![
        check(
            "protected-resource-rejects-unauthenticated",
            Some(matches!(status, 401 | 403)),
            "Deployment policy: operator-declared protected resource returned 401 or 403 to a credential-free GET. This is not proof of GNAP enforcement; a deny-all server also passes.",
            "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5",
        ),
        check(
            "rs-proof-rights-and-introspection",
            None,
            "Not tested: valid token acceptance, cryptographic key binding, rights/audience, replay rejection, rotation, revocation and introspection. No token or signature was presented.",
            "https://www.rfc-editor.org/rfc/rfc9767.html",
        ),
    ]
}

/// The checks of an AS's answer to the fixed malformed grant request, from
/// the captured status, headers, and body.
#[must_use]
pub fn rejection_checks(status: u16, headers: &[(String, String)], body: &[u8]) -> Vec<Check> {
    // One `Content-Type`, naming JSON: a repeated one is ambiguous.
    let response = gnap_types::http::HttpResponse {
        status,
        headers: headers.to_vec(),
        body: vec![],
    };
    let media = response.has_json_content_type();
    let no_store = response.has_no_store();
    let status = reqwest::StatusCode::from_u16(status).unwrap_or(reqwest::StatusCode::OK);
    as_response_checks(status, media, no_store, body)
}

/// The malformed initial grant request of the probe: a POST of `{`.
pub const MALFORMED_GRANT: &[u8] = b"{";

fn as_response_checks(
    status: reqwest::StatusCode,
    media: bool,
    no_store: bool,
    body: &[u8],
) -> Vec<Check> {
    let error = serde_json::from_slice::<gnap_types::GrantResponse>(body)
        .ok()
        .and_then(|r| r.error);
    let only_error_fields = serde_json::from_slice::<serde_json::Value>(body).is_ok_and(|v| {
        v.as_object()
            .is_some_and(|o| o.keys().all(|k| matches!(k.as_str(), "error" | "continue")))
    });
    // An unknown code may be a registration newer than this build's snapshot:
    // undecided, not a deviation.
    let registered = error.as_ref().map(|e| e.code.is_registered());
    let mut known = check(
        "known-error-code",
        registered.filter(|registered| *registered),
        "Error code membership in this build's vendored IANA registry snapshot only. An unknown code requires checking the current registry before asserting a normative failure.",
        "https://www.rfc-editor.org/rfc/rfc9635.html#section-3.6",
    );
    if registered == Some(false) {
        known.undecided = true;
        known.remediation = Some(
            "Compare the code with the current IANA GNAP Error Codes registry; this build's vendored snapshot may lag a new registration.",
        );
    }
    vec![
        check(
            "malformed-request-gnap-error-only",
            Some(error.is_some() && only_error_fields),
            "The malformed initial request returned a GNAP error without success fields. Only error and continue may appear; whether any continuation belongs to a pending grant remains untested.",
            "https://www.rfc-editor.org/rfc/rfc9635.html#section-3.6",
        ),
        check(
            "malformed-request-http-4xx",
            Some(status.is_client_error()),
            "Deployment policy: prefer HTTP 4xx for this client error. RFC 9635 does not prescribe this status class; HTTP 200 with a GNAP error is not by itself a GNAP conformance failure. Redirects are not followed.",
            "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5",
        ),
        check(
            "error-response-json",
            Some(media && error.is_some()),
            "Response media type must be application/json and the parsed GNAP response must contain an error field. Does not determine whether the chosen error code is appropriate.",
            "https://www.rfc-editor.org/rfc/rfc9635.html#section-3",
        ),
        known,
        check(
            "error-response-no-store",
            Some(no_store),
            "Error response must include Cache-Control: no-store.",
            "https://www.rfc-editor.org/rfc/rfc9635.html#section-3",
        ),
        check(
            "authenticated-flow",
            None,
            "No authenticated request was sent. Signature rejection, grant creation, RS access and stateful lifecycle remain untested.",
            "https://www.rfc-editor.org/rfc/rfc9635.html",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_status_policy_does_not_replace_gnap_error_checks() {
        let checks = as_response_checks(
            reqwest::StatusCode::OK,
            true,
            true,
            br#"{"error":"invalid_request"}"#,
        );
        assert_eq!(
            checks
                .iter()
                .find(|c| c.id == "malformed-request-gnap-error-only")
                .unwrap()
                .status,
            crate::Status::Pass
        );
        let policy = checks
            .iter()
            .find(|c| c.id == "malformed-request-http-4xx")
            .unwrap();
        assert_eq!(policy.status, crate::Status::Fail);
        assert!(policy.detail.starts_with("Deployment policy:"));
        assert!(
            policy
                .remediation
                .unwrap()
                .contains("not required by RFC 9635")
        );
    }

    #[test]
    fn an_error_mixed_with_success_fields_does_not_pass_rejection() {
        let checks = as_response_checks(
            reqwest::StatusCode::BAD_REQUEST,
            true,
            true,
            br#"{"error":"invalid_request","access_token":{"value":"synthetic"}}"#,
        );
        assert_eq!(
            checks
                .iter()
                .find(|c| c.id == "malformed-request-gnap-error-only")
                .unwrap()
                .status,
            crate::Status::Fail
        );
    }
}
