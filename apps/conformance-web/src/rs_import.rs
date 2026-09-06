//! Independent, bounded RFC 9767 JSON diagnostics, not state or proof validation.

use crate::{check, observation, Check, Import, MessageKind, Report};
use serde::{
    de::{MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{Map, Value};

const DISCOVERY: &str = "https://www.rfc-editor.org/rfc/rfc9767.html#section-3.1";
const INTRO: &str = "https://www.rfc-editor.org/rfc/rfc9767.html#section-3.3";
const ERROR: &str = "https://www.rfc-editor.org/rfc/rfc9767.html#section-3.5";
const REGISTRATION: &str = "https://www.rfc-editor.org/rfc/rfc9767.html#section-3.4";
const ACCESS: &str = "https://www.rfc-editor.org/rfc/rfc9635.html#section-8";

/// Caller-declared comparison context, never an authenticated observation.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub grant_request_endpoint: Option<String>,
    pub discovery_url: Option<String>,
    pub token_binding: Option<Binding>,
    pub http_status: Option<u16>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Binding {
    Bound,
    Bearer,
}

pub fn validate_context(input: &Import) -> Result<(), &'static str> {
    let Some(c) = &input.rs_context else {
        return Ok(());
    };
    let valid = match input.kind {
        MessageKind::RsDiscovery => c.token_binding.is_none() && c.http_status.is_none(),
        MessageKind::IntrospectionResponse => {
            c.grant_request_endpoint.is_none()
                && c.discovery_url.is_none()
                && c.http_status.is_none()
        }
        MessageKind::RsErrorResponse => {
            c.grant_request_endpoint.is_none()
                && c.discovery_url.is_none()
                && c.token_binding.is_none()
        }
        _ => false,
    };
    if !valid {
        return Err("rs_context fields are not applicable to this message kind.");
    }
    if [&c.grant_request_endpoint, &c.discovery_url]
        .into_iter()
        .flatten()
        .any(|s| s.is_empty() || s.len() > 4096)
        || c.http_status.is_some_and(|s| !(100..=599).contains(&s))
    {
        return Err("Context URLs must contain 1..4096 UTF-8 bytes; HTTP status must be 100..599.");
    }
    Ok(())
}

fn add(
    checks: &mut Vec<Check>,
    id: &'static str,
    outcome: Option<bool>,
    detail: &'static str,
    reference: &'static str,
) {
    let mut c = check(id, outcome, detail, reference);
    c.remediation = (outcome == Some(false)).then_some("Correct the named field or contradiction using the linked section. These checks do not validate server state, keys or rights; submitted values are never echoed.");
    checks.push(c);
}

// A separate recursive parse detects duplicate names before using Value's map.
// Ambiguity is inconclusive, not a newly invented GNAP MUST for unique names.
struct Unique;
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Any;
        impl<'de> Visitor<'de> for Any {
            type Value = Unique;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON with unambiguous member names")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut m: M) -> Result<Unique, M::Error> {
                let mut names = std::collections::HashSet::new();
                while let Some(k) = m.next_key::<String>()? {
                    if !names.insert(k) {
                        return Err(serde::de::Error::custom("ambiguous member"));
                    }
                    m.next_value::<Unique>()?;
                }
                Ok(Unique)
            }
            fn visit_seq<S: SeqAccess<'de>>(self, mut s: S) -> Result<Unique, S::Error> {
                while s.next_element::<Unique>()?.is_some() {}
                Ok(Unique)
            }
            fn visit_bool<E>(self, _: bool) -> Result<Unique, E> {
                Ok(Unique)
            }
            fn visit_i64<E>(self, _: i64) -> Result<Unique, E> {
                Ok(Unique)
            }
            fn visit_u64<E>(self, _: u64) -> Result<Unique, E> {
                Ok(Unique)
            }
            fn visit_f64<E>(self, _: f64) -> Result<Unique, E> {
                Ok(Unique)
            }
            fn visit_str<E>(self, _: &str) -> Result<Unique, E> {
                Ok(Unique)
            }
            fn visit_unit<E>(self) -> Result<Unique, E> {
                Ok(Unique)
            }
        }
        d.deserialize_any(Any)
    }
}

fn strings(v: &Value) -> bool {
    v.as_array().is_some_and(|a| a.iter().all(Value::is_string))
}
fn key_shape(v: &Value) -> bool {
    v.is_string() || v.is_object()
}
fn access_shape(v: &Value) -> bool {
    v.as_array().is_some_and(|a| {
        a.iter().all(|item| {
            item.is_string()
                || item.as_object().is_some_and(|o| {
                    o.get("type").is_some_and(Value::is_string)
                        && ["actions", "locations", "datatypes", "privileges"]
                            .iter()
                            .all(|k| o.get(*k).is_none_or(strings))
                        && o.get("identifier").is_none_or(Value::is_string)
                })
        })
    })
}

fn registered_list(value: &Value, registry: &[&str]) -> Option<bool> {
    if !strings(value) {
        return Some(false);
    }
    value
        .as_array()?
        .iter()
        .all(|v| registry.contains(&v.as_str().unwrap_or("")))
        .then_some(true)
}

// Conservative lexical prechecks prevent WHATWG repair from hiding proven
// violations. Unsupported URL-library cases remain inconclusive, not invalid.
// In particular, this does not apply an extra GNAP prohibition on userinfo.
fn endpoint(raw: &str) -> Option<bool> {
    let Some((scheme, rest)) = raw.split_once("://") else {
        return Some(false);
    };
    if !scheme.eq_ignore_ascii_case("https") || raw.contains('#') {
        return Some(false);
    }
    let bytes = raw.as_bytes();
    if bytes.iter().enumerate().any(|(i, b)| {
        !(b.is_ascii_alphanumeric() || b"-._~:/?[]@!$&'()*+,;=%".contains(b))
            || (*b == b'%'
                && !(bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                    && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit)))
    }) {
        return Some(false);
    }
    let authority = rest.split(['/', '?']).next().unwrap_or("");
    if authority.is_empty() || rest[authority.len()..].contains(['[', ']']) {
        return Some(false);
    }
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if host_port.is_empty() {
        return Some(false);
    }
    if !host_port.starts_with('[') {
        let (host, port) = host_port
            .rsplit_once(':')
            .map_or((host_port, None), |(h, p)| (h, Some(p)));
        if host.is_empty()
            || host.contains(['[', ']', ':'])
            || port.is_some_and(|p| !p.bytes().all(|b| b.is_ascii_digit()))
        {
            return Some(false);
        }
    }
    // Userinfo requires separate HTTP recipient-policy analysis; do not turn
    // either acceptance or refusal here into an invented GNAP MUST.
    if authority.contains('@') {
        return None;
    }
    reqwest::Url::parse(raw).ok().and_then(|u| {
        (u.host_str().is_some_and(|h| !h.is_empty()) && u.fragment().is_none()).then_some(true)
    })
}

fn uri_field(o: &Map<String, Value>, field: &str) -> Option<bool> {
    o.get(field)
        .map_or(Some(false), |v| v.as_str().map_or(Some(false), endpoint))
}

fn add_uri(
    checks: &mut Vec<Check>,
    id: &'static str,
    outcome: Option<bool>,
    raw: Option<&str>,
    detail: &'static str,
    reference: &'static str,
) {
    let userinfo = raw.is_some_and(|raw| {
        raw.split_once("://").is_some_and(|(_, rest)| {
            rest.split(['/', '?', '#'])
                .next()
                .is_some_and(|authority| authority.contains('@'))
        })
    });
    if userinfo {
        add(checks, id, Some(false), "Safe discovery profile: userinfo (including an empty userinfo before @) is rejected. RFC 9110 section 4.2.4 recommends that recipients treat userinfo in an untrusted received URI as an error (SHOULD). This is not an additional GNAP MUST or an assertion that JSON members are HTTP field values.", "https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.4");
    } else {
        add(checks, id, outcome, detail, reference);
    }
}

fn discovery(o: &Map<String, Value>, c: Option<&Context>, checks: &mut Vec<Check>) {
    add_uri(checks, "rs-discovery-grant-endpoint", uri_field(o, "grant_request_endpoint"), o.get("grant_request_endpoint").and_then(Value::as_str), "Required string endpoint: selected raw HTTPS/host/no-fragment URI checks. URL parser limitations are inconclusive; no URL is fetched.", DISCOVERY);
    add(checks, "rs-discovery-grant-identity", c.and_then(|c| c.grant_request_endpoint.as_ref()).map(|expected| o.get("grant_request_endpoint").and_then(Value::as_str) == Some(expected.as_str())), "Exact equality with caller-declared client grant endpoint, if supplied. This cannot attest which endpoint clients really use.", DISCOVERY);
    // RFC 9767 §3.1: "A GNAP AS offering RS-facing services can publish its
    // features on a well-known discovery document at the URL with the same
    // schema and authority as the grant request endpoint URL, at the path
    // /.well-known/gnap-as-rs."
    let location = c
        .and_then(|c| c.discovery_url.as_deref())
        .and_then(|location| {
            match endpoint(location) {
                Some(false) => return Some(false),
                None => return None,
                Some(true) => {}
            }
            let grant = o.get("grant_request_endpoint")?.as_str()?;
            let grant = reqwest::Url::parse(grant).ok()?;
            let url = reqwest::Url::parse(location).ok()?;
            let (_, authority_and_path) = location.split_once("://")?;
            let raw_path = authority_and_path
                .find('/')
                .map(|start| &authority_and_path[start..]);
            Some(
                url.scheme() == grant.scheme()
                    && url.host_str() == grant.host_str()
                    && url.port() == grant.port()
                    && raw_path == Some("/.well-known/gnap-as-rs")
                    && url.query().is_none()
                    && url.fragment().is_none(),
            )
        });
    add_uri(checks, "rs-discovery-declared-location", location, c.and_then(|c| c.discovery_url.as_deref()), "Compare the caller-declared location to the same scheme/authority and /.well-known/gnap-as-rs path. No request or actual publication has been observed.", DISCOVERY);
    for (field, id) in [
        (
            "introspection_endpoint",
            "rs-discovery-introspection-endpoint",
        ),
        (
            "resource_registration_endpoint",
            "rs-discovery-registration-endpoint",
        ),
    ] {
        // RFC 9767 §3.1: "REQUIRED if the AS supports introspection. An absent
        // value indicates that the AS does not support introspection."
        let detail = if field == "introspection_endpoint" {
            "Required if the AS supports introspection. An absent value indicates that the AS does not support introspection. If present, selected HTTPS endpoint syntax checks apply; import cannot verify the advertised service's actual behavior."
        } else {
            "Required if the AS supports dynamic resource registration. An absent value indicates that the AS does not support this feature. If present, selected HTTPS endpoint syntax checks apply; import cannot verify the advertised service's actual behavior."
        };
        add_uri(
            checks,
            id,
            o.contains_key(field).then(|| uri_field(o, field)).flatten(),
            o.get(field).and_then(Value::as_str),
            detail,
            DISCOVERY,
        );
    }
    for (field, id, registry) in [
        (
            "token_formats_supported",
            "rs-discovery-token-formats",
            gnap_registry::TokenFormat::REGISTERED,
        ),
        (
            "key_proofs_supported",
            "rs-discovery-key-proofs",
            gnap_registry::KeyProofingMethod::REGISTERED,
        ),
    ] {
        add(checks, id, o.get(field).and_then(|v| registered_list(v, registry)), "Optional string array. Known names match the vendored GNAP registry; unknown names need external registry review. Absence is optional/not announced, not a missing required field. Membership does not prove support.", DISCOVERY);
    }
}

fn request(o: &Map<String, Value>, checks: &mut Vec<Check>) {
    add(checks, "introspection-request-token", Some(o.get("access_token").is_some_and(Value::is_string)), "access_token is a required string: the exact token presented to the RS. Equality to the original presentation is not tested.", INTRO);
    add(checks, "introspection-request-rs", Some(o.get("resource_server").is_some_and(|v| v.is_string() || v.as_object().is_some_and(|o| o.get("key").is_some_and(key_shape)))), "Required RS identity reference or object with key. Only outer shape: no key resolution, key presentation validation, signature or RS authorization.", "https://www.rfc-editor.org/rfc/rfc9767.html#section-3.2");
    let proof = o.get("proof").and_then(|v| match v.as_str() {
        None => Some(false),
        Some(s) => gnap_registry::KeyProofingMethod::REGISTERED
            .contains(&s)
            .then_some(true),
    });
    add(checks, "introspection-request-proof", proof, "proof is RECOMMENDED, not REQUIRED. If supplied it must be a string naming a registered method. Absence needs recommendation/context review; an unknown name needs external registry review. This describes the client's proof, not the RS's signature.", INTRO);
    add(checks, "introspection-request-access", o.get("access").map(access_shape), "Optional minimum access: array of references or objects with string type and selected standard dimensions. Absence is allowed. This is shape, not rights semantics or proof that the AS understood every parameter.", ACCESS);
}

fn response(o: &Map<String, Value>, c: Option<&Context>, checks: &mut Vec<Check>) {
    let active = o.get("active").and_then(Value::as_bool);
    add(checks, "introspection-response-active", Some(active.is_some()), "active is REQUIRED and boolean. A true value is only an imported declaration, not verified token state.", INTRO);
    add(
        checks,
        "introspection-response-no-value",
        Some(!o.contains_key("value")),
        "The response MUST NOT include the access token value member.",
        INTRO,
    );
    add(checks, "introspection-inactive-only", active.filter(|v| !v).map(|_| o.len() == 1), "When active is false, all other fields must be omitted, including extensions. Not applicable to an active response.", INTRO);
    if active != Some(true) {
        return;
    }
    add(checks, "introspection-active-access", Some(o.get("access").is_some_and(access_shape)), "An active response requires access in GNAP array form. An empty array is explicitly permitted; actual rights are not verified.", INTRO);
    add_uri(checks, "introspection-active-issuer", uri_field(o, "iss"), o.get("iss").and_then(Value::as_str), "An active response requires iss, the issuer's grant endpoint URL, even though the RFC example omits it. Selected URL syntax only; issuer identity/trust is not verified.", INTRO);
    add(checks, "introspection-key-shape", o.get("key").map(key_shape), "When supplied, key is an object or reference string. Its contents, cryptographic validity and binding to the token are not tested.", INTRO);
    let flags = o.get("flags");
    let bearer = flags
        .and_then(Value::as_array)
        .is_some_and(|a| a.iter().any(|v| v.as_str() == Some("bearer")));
    let key = o.contains_key("key");
    let binding = if bearer && key {
        Some(false)
    } else {
        c.and_then(|c| c.token_binding)
            .map(|b| match b {
                Binding::Bound => key && !bearer,
                Binding::Bearer => !key,
            })
            .or_else(|| bearer.then_some(!key))
    };
    add(checks, "introspection-key-condition", binding, "A bound token requires key; a bearer token forbids it. Bearer plus key is a message contradiction regardless of caller context. Otherwise the condition uses declared token_binding, not verified token properties; absent context can be inconclusive.", INTRO);
    let optional_shape = ["exp", "iat", "nbf"]
        .iter()
        .all(|k| o.get(*k).is_none_or(|v| v.is_i64() || v.is_u64()))
        && flags.is_none_or(strings)
        && o.get("aud").is_none_or(|v| v.is_string() || strings(v))
        && ["sub", "instance_id"]
            .iter()
            .all(|k| o.get(*k).is_none_or(Value::is_string));
    let present = ["exp", "iat", "nbf", "flags", "aud", "sub", "instance_id"]
        .iter()
        .any(|k| o.contains_key(*k));
    add(checks, "introspection-optional-metadata", present.then_some(optional_shape), "Selected optional metadata types only: integer timestamps, string/array audience, string identifiers and string-array flags. Missing optional metadata is allowed; times, audiences and subjects are not authenticated.", INTRO);
}

fn error_response(o: &Map<String, Value>, c: Option<&Context>, checks: &mut Vec<Check>) {
    let error = o.get("error");
    let code = error.and_then(|v| v.as_str().or_else(|| v.as_object()?.get("code")?.as_str()));
    let shape = o.len() == 1
        && code.is_some_and(str::is_ascii)
        && error.is_some_and(|v| {
            v.is_string()
                || v.as_object()
                    .is_some_and(|o| o.get("description").is_none_or(Value::is_string))
        });
    add(checks, "rs-error-shape", Some(shape), "RS-facing error: a single error member, string code or object with ASCII string code and optional string description. This is not the core AS error registry.", ERROR);
    add(checks, "rs-error-code", code.and_then(|s| gnap_registry::RsErrorCode::REGISTERED.contains(&s).then_some(true)), "Known code in the vendored RS-facing registry. Unknown codes need external registry/extension review, not silent acceptance or a claim that registrations cannot change.", ERROR);
    add(checks, "rs-error-http-status", c.and_then(|c| c.http_status).map(|s| s == 400), "RFC 9767 section 3.5 specifies HTTP 400 for RS-facing API errors. This compares only caller-declared status; without it HTTP is not tested.", ERROR);
}

fn registration_request(o: &Map<String, Value>, checks: &mut Vec<Check>) {
    add(checks, "registration-request-access", Some(o.get("access").is_some_and(access_shape)), "access is REQUIRED: an array of reference strings or GNAP access objects with string type and selected standard dimensions. Empty arrays are not prohibited here. Resource-type semantics, reference resolution and the AS's actual interpretation are not tested.", ACCESS);
    add(checks, "registration-request-rs", Some(o.get("resource_server").is_some_and(|v| v.is_string() || v.as_object().is_some_and(|o| o.get("key").is_some_and(key_shape)))), "resource_server is REQUIRED: an identity reference string or object containing key as object/reference. Only outer presentation is checked; key contents, mathematical validity, ownership, signature and RS authorization are not verified.", "https://www.rfc-editor.org/rfc/rfc9767.html#section-3.2");
    add(checks, "registration-request-token-formats", o.get("token_formats_supported").and_then(|v| registered_list(v, gnap_registry::TokenFormat::REGISTERED)), "Optional string array whose values MUST be registered in the GNAP Token Formats registry. Known values match this build's registry snapshot; unknown values need external registry review and are inconclusive. Absence leaves the format to the AS. An empty array establishes no compatible format.", REGISTRATION);
    add(checks, "registration-request-introspection-required", o.get("token_introspection_required").map(Value::is_boolean), "Optional boolean: true declares that the RS expects to introspect these tokens; absent or false declares that it does not anticipate needing introspection. This does not establish the AS's support for this RS.", REGISTRATION);
}

fn registration_response(o: &Map<String, Value>, checks: &mut Vec<Check>) {
    add(checks, "registration-response-reference", Some(o.get("resource_reference").is_some_and(Value::is_string)), "resource_reference is a REQUIRED string representing the registered resource list, not an access token. No token-value, nonempty or ASCII restriction is imposed. Whether this reference identifies the submitted resources is not tested.", REGISTRATION);
    add(checks, "registration-response-instance-id", o.get("instance_id").map(Value::is_string), "Optional string RS instance identifier. Its assignment, persistence, resolution and binding to the RS are not tested.", REGISTRATION);
    add(checks, "registration-response-introspection-endpoint", o.get("introspection_endpoint").map(Value::is_string), "Optional string naming the AS introspection endpoint. Only its JSON type is checked here; URI syntax, transport, ownership and actual introspection are not verified. No URL is fetched and discovery-specific URI rules are not transposed to this field.", REGISTRATION);
}

pub fn analyze(input: &Import) -> Result<Report, &'static str> {
    let (profile, reference, known): (&str, &str, &[&str]) = match input.kind {
        MessageKind::RsDiscovery => (
            "gnap-rs-discovery-import-v1",
            DISCOVERY,
            &[
                "grant_request_endpoint",
                "introspection_endpoint",
                "resource_registration_endpoint",
                "token_formats_supported",
                "key_proofs_supported",
            ],
        ),
        MessageKind::IntrospectionRequest => (
            "gnap-introspection-request-import-v1",
            INTRO,
            &["access_token", "resource_server", "proof", "access"],
        ),
        MessageKind::IntrospectionResponse => (
            "gnap-introspection-response-import-v1",
            INTRO,
            &[
                "active",
                "access",
                "key",
                "flags",
                "exp",
                "iat",
                "nbf",
                "aud",
                "sub",
                "iss",
                "instance_id",
                "value",
            ],
        ),
        MessageKind::RsErrorResponse => ("gnap-rs-error-import-v1", ERROR, &["error"]),
        MessageKind::ResourceRegistrationRequest => (
            "gnap-resource-registration-request-import-v1",
            REGISTRATION,
            &[
                "access",
                "resource_server",
                "token_formats_supported",
                "token_introspection_required",
            ],
        ),
        MessageKind::ResourceRegistrationResponse => (
            "gnap-resource-registration-response-import-v1",
            REGISTRATION,
            &[
                "resource_reference",
                "instance_id",
                "introspection_endpoint",
            ],
        ),
        _ => return Err("Unsupported RFC 9767 import kind."),
    };
    let mut checks = Vec::new();
    let parsed = serde_json::from_str::<Value>(&input.body);
    let object = parsed.as_ref().ok().and_then(Value::as_object);
    let unique = parsed
        .as_ref()
        .ok()
        .map(|_| serde_json::from_str::<Unique>(&input.body).is_ok());
    let json_shape = match &parsed {
        Ok(value) => Some(value.is_object()),
        Err(error)
            if error.to_string().starts_with("number out of range")
                || error.to_string().starts_with("recursion limit exceeded") =>
        {
            None
        }
        Err(_) => Some(false),
    };
    add(
        &mut checks,
        "rs-message-json-object",
        json_shape,
        "Selected RFC 9767 messages are JSON objects. No SDK message validator is used. Parser number-range/depth limits are inconclusive, not proof of invalid JSON.",
        reference,
    );
    add(&mut checks, "rs-json-unambiguous", unique.filter(|u| *u), "Duplicate JSON members at any depth make interpretation inconclusive; no last-wins checks are applied. This is not a GNAP MUST for unique names.", "https://www.rfc-editor.org/rfc/rfc8259.html#section-4");
    if let Some(o) = object.filter(|_| unique == Some(true)) {
        match input.kind {
            MessageKind::RsDiscovery => discovery(o, input.rs_context.as_ref(), &mut checks),
            MessageKind::IntrospectionRequest => request(o, &mut checks),
            MessageKind::IntrospectionResponse => {
                response(o, input.rs_context.as_ref(), &mut checks)
            }
            MessageKind::RsErrorResponse => {
                error_response(o, input.rs_context.as_ref(), &mut checks)
            }
            MessageKind::ResourceRegistrationRequest => registration_request(o, &mut checks),
            MessageKind::ResourceRegistrationResponse => registration_response(o, &mut checks),
            _ => {}
        }
        add(
            &mut checks,
            "rs-extension-semantics",
            None,
            if o.keys().any(|k| !known.contains(&k.as_str()))
                && matches!(
                    input.kind,
                    MessageKind::IntrospectionRequest | MessageKind::IntrospectionResponse
                )
            {
                "Additional members are present. Their registration and semantics are not tested; an AS unable to process an introspection request parameter MUST NOT declare the token active. An import cannot test that behavior."
            } else if o.keys().any(|k| !known.contains(&k.as_str())) {
                "Additional members are present. Their registration and semantics are not tested. This does not make extensions forbidden or prove that a receiver understands them."
            } else {
                "No unrecognized top-level member detected, but extension semantics, nested key contents and resource-type-specific rules remain outside this import diagnostic."
            },
            reference,
        );
    }
    if matches!(
        input.kind,
        MessageKind::ResourceRegistrationRequest | MessageKind::ResourceRegistrationResponse
    ) {
        add(&mut checks, "registration-format-compatibility", None, "Not tested: if the AS supports none of the requested token formats, it MUST return an error. Registry membership, an omitted list or an empty list cannot establish an AS/RS format intersection or actual error behavior.", REGISTRATION);
        add(&mut checks, "registration-introspection-support", None, "Not tested: when introspection is required by the RS, the AS must support it for this RS or return an error. An imported declaration or endpoint string cannot establish that support or the AS's error behavior.", REGISTRATION);
        add(&mut checks, "registration-authentication-and-state", None, "Not tested: the RS MUST identify itself with its own key and sign the request. Key ownership, signature, authorization, resource registration, reference persistence/resolution and request-response correspondence require an authenticated exchange and state. Never upload private keys.", REGISTRATION);
    }
    add(&mut checks, "content-digest", input.content_digest.as_ref().map(|d| gnap_crypto::verify_content_digest(input.body.as_bytes(), d).is_ok()), "Separate shared gnap-crypto digest check against exact body bytes, if supplied. Not a signature or HTTP authentication check.", "https://www.rfc-editor.org/rfc/rfc9635.html#section-7.3.1");
    add(&mut checks, "rs-authentication-and-state", None, "Not tested: RS signature/authorization, client proof/key binding, issuer trust, actual token value, active state, expiration, revocation, audience, permissions or final resource decision. Never send private keys or production tokens.", INTRO);
    add(&mut checks, "rs-http-and-discovery-publication", None, "No network operation: actual HTTP status/media, TLS, well-known publication and announced capability execution are not verified. Imported headers do not establish these facts; no HTTP 200 or single-header rule is imposed.", DISCOVERY);
    Ok(Report { schema_version: 1, profile, kind: input.kind, certification: false, independence: "RFC 9767 JSON assertions use serde_json directly, not gnap-types validators. Registry membership reuses gnap-registry data; the optional digest check reuses gnap-crypto. Not an independent protocol implementation or certification.", observation: observation("import"), checks })
}
