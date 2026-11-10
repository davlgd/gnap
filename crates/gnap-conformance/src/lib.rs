//! Selected GNAP checks, for diagnostics rather than certification.
//!
//! This crate checks GNAP ([RFC 9635](https://www.rfc-editor.org/rfc/rfc9635))
//! and GNAP resource-server ([RFC 9767](https://www.rfc-editor.org/rfc/rfc9767))
//! messages and servers:
//!
//! - [`analyze`] checks one captured message, offline, and never fetches what it names;
//! - [`discovery`] and [`probe`] check an authorization server's discovery
//!   document and its answer to a malformed grant request;
//! - [`scenario`] runs one grant's lifecycle against an authorization server,
//!   through the bounded transport of [`net`];
//! - [`cli`] selects those checks and reports them, as the `gnap-conformance`
//!   command line does.
//!
//! Each check names the clause it relies on. Passing the selected checks isn't
//! conformance, and no report is a certification.

use gnap_types::{ContinueRequest, GrantRequest, GrantResponse};
use serde::{Deserialize, Serialize};

pub mod cli;
pub mod discovery;
pub mod net;
pub mod probe;
#[allow(
    clippy::redundant_pub_crate,
    reason = "Import checks stay crate-private; unreachable_pub rejects pub in this module"
)]
mod rs_import;
pub mod scenario;
#[allow(
    clippy::redundant_pub_crate,
    reason = "Import checks stay crate-private; unreachable_pub rejects pub in this module"
)]
mod token_exchange;
pub use rs_import::{Binding as TokenBinding, Context as RsContext};

/// The largest import envelope a caller should accept, in bytes: the message
/// and its captured context together.
pub const MAX_UPLOAD: usize = 65_536;
/// The largest message [`analyze`] reads, in UTF-8 bytes.
pub const MAX_MESSAGE: usize = 32_768;

/// What a captured message is, which selects the checks [`analyze`] runs.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    /// A grant request (RFC 9635 §2).
    GrantRequest,
    /// A grant response (RFC 9635 §3).
    GrantResponse,
    /// A continuation request (RFC 9635 §5).
    ContinueRequest,
    /// An authorization server's discovery document (RFC 9635 §9).
    AsDiscovery,
    /// The AS's discovery document for resource servers (RFC 9767 §3.1).
    RsDiscovery,
    /// A token introspection request (RFC 9767 §3.3).
    IntrospectionRequest,
    /// A token introspection response (RFC 9767 §3.3).
    IntrospectionResponse,
    /// A resource server's error response (RFC 9767).
    RsErrorResponse,
    /// A resource-set registration request (RFC 9767 §3.4).
    ResourceRegistrationRequest,
    /// A resource-set registration response (RFC 9767 §3.4).
    ResourceRegistrationResponse,
    /// A downstream token derivation request (RFC 9767 §4).
    DerivationRequest,
    /// A downstream token derivation response (RFC 9767 §4).
    DerivationResponse,
    /// A grant request and its response, compared token by token (RFC 9635 §3.2).
    TokenExchange,
}

/// A captured message and its context, as [`analyze`] reads it.
///
/// Headers are optional: absence means the trace did not capture them, not an
/// empty list of actual headers. Keep duplicates and the exact message bytes.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Import {
    /// What the message is.
    pub kind: MessageKind,
    /// The message body, exactly as captured.
    pub body: String,
    /// The captured header fields, in order and with duplicates, if any were captured.
    pub headers: Option<Vec<(String, String)>>,
    /// The captured `Content-Digest` field, checked against the exact body.
    pub content_digest: Option<String>,
    /// Caller-declared comparison context for the RFC 9767 kinds only.
    pub rs_context: Option<RsContext>,
    /// Captured discovery context only. This value is never fetched.
    pub queried_endpoint: Option<String>,
    /// The captured HTTP status of a discovery response.
    pub http_status: Option<u16>,
}

/// The outcome of one check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// What the check examined met its rule.
    Pass,
    /// What the check examined broke its rule.
    Fail,
    /// The check examined nothing, or couldn't decide: see [`Check::undecided`].
    NotTested,
}

/// One named check, with the rule it applies and where that rule comes from.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    /// A stable identifier.
    pub id: &'static str,
    /// The outcome.
    pub status: Status,
    /// What the check examines, and what it doesn't.
    pub detail: &'static str,
    /// The clause the check relies on, as a URL.
    pub reference: &'static str,
    /// What to change, for a failed or undecided check. It never repeats the examined values.
    pub remediation: Option<&'static str>,
    /// A check the oracle couldn't decide, as opposed to one it had nothing
    /// to examine for: both are `NotTested` to the web view, which shows
    /// their detail, and the command line tells them apart.
    #[serde(skip)]
    pub undecided: bool,
}

/// When and by what a report was produced.
#[derive(Debug, Serialize)]
pub struct Observation {
    /// Where the examined message came from: `import` or `live`.
    pub source: &'static str,
    /// The version of this crate.
    pub harness_version: &'static str,
    /// The value of the `CC_COMMIT_ID` environment variable of the running
    /// process when it is a hexadecimal commit identifier, `unknown` otherwise.
    /// The operator sets it; it doesn't attest the source of this crate.
    pub revision: String,
    /// The time of the observation, in Unix seconds, or 0 when the clock is before the epoch.
    pub observed_at_unix_seconds_utc: u64,
}

/// An observation from `source`, made now.
#[must_use]
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

/// The report of [`analyze`] on one message.
#[derive(Debug, Serialize)]
pub struct Report {
    /// The version of this report's format.
    pub schema_version: u8,
    /// The named set of checks that ran.
    pub profile: &'static str,
    /// What the message was.
    pub kind: MessageKind,
    /// Always `false`: a report is never a certification.
    pub certification: bool,
    /// How independent the checks are from the implementation they test.
    pub independence: &'static str,
    /// When and by what the report was produced.
    pub observation: Observation,
    /// The checks, in order.
    pub checks: Vec<Check>,
}

impl Check {
    /// A check named `id`: passed when `outcome` is `Some(true)`, failed when
    /// `Some(false)`, not tested when `None`. A failed check carries the
    /// remediation this crate has for its identifier, or a generic one.
    #[must_use]
    pub fn new(
        id: &'static str,
        outcome: Option<bool>,
        detail: &'static str,
        reference: &'static str,
    ) -> Self {
        check(id, outcome, detail, reference)
    }
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
        "discovery-http-200" => "Configure the grant endpoint to answer OPTIONS successfully without credentials. HTTP 200 is this diagnostic profile's expectation, not an explicit status-code MUST in RFC 9635 section 9. Redirects are not followed.",
        "discovery-media-type" => "Return exactly one Content-Type field with media type application/json. Check OPTIONS routing, authentication middleware and reverse-proxy error pages.",
        "discovery-json-object" => "Return one JSON object, not an array, scalar, HTML page or malformed JSON.",
        "discovery-endpoint" => "Provide a string grant_request_endpoint: an absolute HTTPS URL with a host and no fragment. Local HTTP development is not a normative exception.",
        "discovery-endpoint-match" => "Advertise the exact URL queried by the client, including path and query. Do not normalize or substitute another endpoint.",
        "discovery-key-rotation-type" => "When supplied, key_rotation_supported must be a JSON boolean, not a string or null. Omission means unsupported.",
        "discovery-duplicate-members" => "Use unique top-level JSON member names. Ambiguous duplicate fields are rejected by this diagnostic profile; RFC 8259 recommends unique names.",
        _ if id.starts_with("token-exchange-") => "Check the local request/response pair and the named shape or label relationship against the linked section. These independent JSON comparisons do not verify authority, token contents or an authenticated exchange.",
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
        undecided: false,
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

/// Checks one captured message, offline: it fetches nothing the message names.
///
/// # Errors
///
/// Refuses, with a reason that repeats none of the input, a message over
/// [`MAX_MESSAGE`] bytes, more than 64 headers or an oversized one, a header
/// with a line break, an oversized digest or discovery context, a discovery
/// context on another kind of message, or an RFC 9767 context that doesn't
/// apply to the message.
#[allow(
    clippy::too_many_lines,
    reason = "Each message kind is one arm, with its checks in the order the report gives them"
)]
pub fn analyze(input: &Import) -> Result<Report, &'static str> {
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
    if input
        .queried_endpoint
        .as_ref()
        .is_some_and(|url| url.len() > 4096)
        || input
            .http_status
            .is_some_and(|status| !(100..=599).contains(&status))
    {
        return Err(
            "Discovery context requires an endpoint <=4096 bytes and HTTP status 100..599.",
        );
    }
    if !matches!(input.kind, MessageKind::AsDiscovery)
        && (input.queried_endpoint.is_some() || input.http_status.is_some())
    {
        return Err("queried_endpoint and http_status are only supported for kind as_discovery.");
    }
    let mut checks = Vec::new();
    rs_import::validate_context(input)?;
    match input.kind {
        MessageKind::TokenExchange => return token_exchange::analyze(input),
        MessageKind::AsDiscovery => {
            return Ok(Report {
                schema_version: 1,
                profile: "gnap-as-discovery-diagnostics-v1",
                kind: input.kind,
                certification: false,
                independence: discovery::INDEPENDENCE,
                observation: observation("import"),
                checks: discovery::checks(
                    input.body.as_bytes(),
                    input.headers.as_deref(),
                    input.http_status,
                    input.queried_endpoint.as_deref(),
                ),
            });
        }
        MessageKind::RsDiscovery
        | MessageKind::IntrospectionRequest
        | MessageKind::IntrospectionResponse
        | MessageKind::RsErrorResponse
        | MessageKind::ResourceRegistrationRequest
        | MessageKind::ResourceRegistrationResponse
        | MessageKind::DerivationRequest
        | MessageKind::DerivationResponse => return rs_import::analyze(input),
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
    Ok(Report {
        schema_version: 1,
        profile: "gnap-import-diagnostics-v1",
        kind: input.kind,
        certification: false,
        independence: "Shared gnap-types and gnap-crypto implementation; not an independent conformance oracle. Pass applies only to each named check.",
        observation: observation("import"),
        checks,
    })
}

fn finish_check(interact: Option<&gnap_types::interact::InteractRequest>, checks: &mut Vec<Check>) {
    checks.push(check("interaction-finish", interact.and_then(|i| i.finish.as_ref()).map(|f| f.validate().is_ok()), "Selected finish URI and nonce shape rules only. Does not test callback execution, entropy or uniqueness.", "https://www.rfc-editor.org/rfc/rfc9635.html#section-2.5.2"));
}
