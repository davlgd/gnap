//! The HTTP responses the server sends, with the headers GNAP requires.

use crate::storage::StoreError;
use gnap_registry::ErrorCode;
use gnap_types::GnapError;
use gnap_types::http::{HttpRequest, HttpResponse};
use gnap_types::message::GrantResponse;

/// An empty 204, as §5.4 requires of a successful revocation.
pub(super) fn no_content() -> HttpResponse {
    HttpResponse {
        status: 204,
        headers: vec![("Cache-Control".into(), "no-store".into())],
        body: Vec::new(),
    }
}

/// A successful response, with the cache directive §3 requires.
pub(super) fn ok(response: &GrantResponse) -> HttpResponse {
    HttpResponse {
        status: 200,
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            // §3 — "The AS MUST include the HTTP Cache-Control response
            // header field [RFC9111] with a value set to no-store."
            ("Cache-Control".into(), "no-store".into()),
        ],
        body: serde_json::to_vec(response).unwrap_or_else(|_| b"{}".to_vec()),
    }
}

/// An error response (§3.6).
pub(super) fn error(code: ErrorCode, description: &str) -> HttpResponse {
    let response = GrantResponse {
        error: Some(GnapError::with_description(code, description)),
        ..Default::default()
    };
    HttpResponse {
        status: 400,
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Cache-Control".into(), "no-store".into()),
        ],
        body: serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec()),
    }
}

/// The deployment handed the server something it cannot use.
///
/// Invalid generated values, endpoint configuration or policy output land here.
/// This is a technical failure, not an authoritative GNAP error response: no
/// grant change has been committed. In particular, a client must not mistake
/// this response for a denial that terminates its continuation.
pub(super) fn misconfigured(what: &str) -> HttpResponse {
    HttpResponse {
        status: 500,
        headers: vec![
            ("Content-Type".into(), "text/plain; charset=utf-8".into()),
            ("Cache-Control".into(), "no-store".into()),
        ],
        body: format!("server configuration: {what}").into_bytes(),
    }
}

/// Checks the content type §2 requires of a request that carries JSON.
///
/// §2-Y07 lets a key proofing mechanism define an alternative content type "as
/// long as the content is formed from the JSON object"; `httpsig` defines none,
/// so `application/json` is the only one this server accepts.
pub(super) fn require_json_content(request: &HttpRequest) -> Result<(), HttpResponse> {
    // A body is what carries the JSON; a request without one (polling a
    // continuation) has no content type to check.
    if request.body.as_ref().is_none_or(Vec::is_empty) {
        return Ok(());
    }

    if request.has_json_content_type() {
        Ok(())
    } else {
        Err(unsupported_media_type())
    }
}

/// Whether the request's content is an attached JWS (RFC 9635 §7.3.4): one
/// `Content-Type` field whose media type is `application/jose`.
pub(super) fn is_jose_content(request: &HttpRequest) -> bool {
    let mut types = request.header_values("content-type");
    let jose = types.next().is_some_and(|value| {
        value
            .split(';')
            .next()
            .unwrap_or_default()
            .trim_matches([' ', '\t'])
            .eq_ignore_ascii_case(gnap_crypto::jws::JOSE_MEDIA_TYPE)
    });
    jose && types.next().is_none()
}

/// The refusal of a key whose proof method this server doesn't verify.
pub(super) fn unsupported_proof() -> HttpResponse {
    error(
        ErrorCode::InvalidClient,
        "the presented key requires a proof method this server does not support \
         (RFC 9635 §2.3, §7.3)",
    )
}

/// 405, naming the methods the endpoint does answer.
pub(super) fn method_not_allowed(allowed: &str) -> HttpResponse {
    HttpResponse {
        status: 405,
        headers: vec![
            ("Cache-Control".into(), "no-store".into()),
            ("Allow".into(), allowed.into()),
        ],
        body: Vec::new(),
    }
}

/// 415, for content that is not the JSON object §2 requires.
pub(super) fn unsupported_media_type() -> HttpResponse {
    HttpResponse {
        status: 415,
        headers: vec![
            ("Cache-Control".into(), "no-store".into()),
            ("Accept".into(), "application/json".into()),
        ],
        body: Vec::new(),
    }
}

pub(super) fn not_found() -> HttpResponse {
    HttpResponse {
        status: 404,
        headers: vec![("Cache-Control".into(), "no-store".into())],
        body: Vec::new(),
    }
}

// A transaction failure is not a committed GNAP decision. In particular, do not
// return a fabricated continuation or success whose indexes were never published.
pub(super) fn storage_failure(failure: StoreError) -> HttpResponse {
    HttpResponse {
        status: match failure {
            StoreError::Invalid | StoreError::Collision => 500,
            _ => 503,
        },
        headers: vec![("Cache-Control".into(), "no-store".into())],
        body: Vec::new(),
    }
}
