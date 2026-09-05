//! Independent wire assertions for RFC 9635 section 9, not SDK message validation.

use crate::{check, Check};
use serde::{
    de::{MapAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::Value;

const RFC: &str = "https://www.rfc-editor.org/rfc/rfc9635.html#section-9";
pub const INDEPENDENCE: &str = "Discovery HTTP/JSON/URL assertions do not use gnap-types validation. GNAP registry membership reuses gnap-registry data; Subject Identifier names use an IANA snapshot checked 2026-09-05. This is not an independent protocol implementation or certification.";

// This registry is not in gnap-registry. Source checked 2026-09-05:
// https://www.iana.org/assignments/secevent/#subject-identifier-formats
const SUBJECT_FORMATS: &[&str] = &[
    "account",
    "email",
    "iss_sub",
    "opaque",
    "phone_number",
    "did",
    "uri",
    "aliases",
];

/// Only HTTP media type, not charset/content decoding or a complete header audit.
fn json_media(headers: &[(String, String)]) -> bool {
    let values: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .collect();
    values.len() == 1
        && values[0]
            .1
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("application/json")
}

/// Check raw RFC 3986 characters before URL parsing, which otherwise repairs
/// spaces, backslashes, missing slashes and malformed percent escapes. The raw
/// URL is kept for identity comparison; parser normalization is never compared.
fn https_endpoint(raw: &str) -> Option<bool> {
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
    let tail = &rest[authority.len()..];
    if authority.is_empty() || tail.contains(['[', ']']) {
        return Some(false);
    }
    // Safe-recipient profile adopts RFC 9110 section 4.2.4's SHOULD to treat
    // userinfo in an untrusted received URI as an error. This is not a new
    // GNAP MUST, nor a claim that a JSON member is an HTTP field value.
    if authority.contains('@') {
        return Some(false);
    }
    // Recognize, but do not turn URL-library limits into normative failures:
    // RFC 3986 IP-literal includes IPvFuture, and port is *DIGIT without a
    // u16 range limit. Reject proven grammar violations before this distinction.
    let host_port = authority;
    let (port, ipv_future) = if let Some(literal) = host_port.strip_prefix('[') {
        let Some((host, suffix)) = literal.split_once(']') else {
            return Some(false);
        };
        let port = if suffix.is_empty() {
            None
        } else if let Some(port) = suffix.strip_prefix(':') {
            Some(port)
        } else {
            return Some(false);
        };
        let future = host.starts_with(['v', 'V']);
        if future {
            let Some((version, address)) = host[1..].split_once('.') else {
                return Some(false);
            };
            if version.is_empty()
                || !version.bytes().all(|b| b.is_ascii_hexdigit())
                || address.is_empty()
                || !address
                    .bytes()
                    .all(|b| (reg_name_byte(b) && b != b'%') || b == b':')
            {
                return Some(false);
            }
        } else if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Some(false);
        }
        (port, future)
    } else {
        let (host, port) = host_port
            .rsplit_once(':')
            .map_or((host_port, None), |(host, port)| (host, Some(port)));
        if host.is_empty() || !host.bytes().all(reg_name_byte) {
            return Some(false);
        }
        (port, false)
    };
    if port.is_some_and(|p| !p.bytes().all(|b| b.is_ascii_digit())) {
        return Some(false);
    }
    if ipv_future || port.is_some_and(|p| !p.is_empty() && p.parse::<u16>().is_err()) {
        return None;
    }
    // RFC 3986 section 3.2.2 permits a reg-name when IPv4address does not
    // match. WHATWG instead interprets numeric-looking names as IPv4 and
    // applies additional percent-decoding/IDNA rules. A failure here is not
    // evidence that the raw syntax checks above failed. Nor does passing
    // those checks prove all URI production rules (e.g. host UTF-8 encoding).
    // RFC 9110 section 4.2.2 refers to that authority grammar; it does not make
    // this particular URL library's acceptance the definition of conformance.
    reqwest::Url::parse(raw).ok().and_then(|url| {
        (url.scheme() == "https"
            && url.host_str().is_some_and(|host| !host.is_empty())
            && url.fragment().is_none())
        .then_some(true)
    })
}

fn reg_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=%".contains(&b)
}

fn has_userinfo(raw: &str) -> bool {
    raw.split_once("://").is_some_and(|(_, rest)| {
        rest.split(['/', '?', '#'])
            .next()
            .is_some_and(|authority| authority.contains('@'))
    })
}

struct UniqueMembers;
impl<'de> Deserialize<'de> for UniqueMembers {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Members;
        impl<'de> Visitor<'de> for Members {
            type Value = UniqueMembers;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("unique object members")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut names = std::collections::HashSet::new();
                while let Some(name) = map.next_key::<String>()? {
                    if !names.insert(name) {
                        return Err(serde::de::Error::custom("duplicate member"));
                    }
                    map.next_value::<serde::de::IgnoredAny>()?;
                }
                Ok(UniqueMembers)
            }
        }
        deserializer.deserialize_map(Members)
    }
}

pub fn checks(
    body: &[u8],
    headers: Option<&[(String, String)]>,
    status: Option<u16>,
    queried_endpoint: Option<&str>,
) -> Vec<Check> {
    let parsed = serde_json::from_slice::<Value>(body).ok();
    let object = parsed.as_ref().and_then(Value::as_object);
    let unique = object.map(|_| serde_json::from_slice::<UniqueMembers>(body).is_ok());
    // Never validate a last-wins interpretation of an ambiguous document.
    let document = object.filter(|_| unique == Some(true));
    let endpoint = document
        .and_then(|o| o.get("grant_request_endpoint"))
        .and_then(Value::as_str);
    let userinfo = endpoint.is_some_and(has_userinfo);
    let mut checks = vec![
        check("discovery-http-200", status.map(|s| s == 200), "OPTIONS success profile expects HTTP 200 without credentials. Section 9 does not explicitly mandate this status code. Missing captured status is not tested; redirects are not followed.", RFC),
        check("discovery-media-type", headers.map(json_media), "Captured HTTP response has one application/json Content-Type. Missing captured headers are not tested; an empty captured list fails.", RFC),
        check("discovery-json-object", Some(object.is_some()), "Response bytes parse as one JSON object. This assertion is independent of SDK message deserialization.", RFC),
        check("discovery-duplicate-members", unique, "Diagnostic profile: top-level member names must be unambiguous. RFC 8259 recommends unique names; duplicates are not interpreted with last-wins semantics here.", "https://www.rfc-editor.org/rfc/rfc8259.html#section-4"),
        check("discovery-endpoint", document.and_then(|_| endpoint.map_or(Some(false), https_endpoint)), if userinfo { "Safe discovery profile: userinfo (including an empty userinfo before @) is rejected. RFC 9110 section 4.2.4 recommends that recipients treat userinfo in an untrusted received URI as an error (SHOULD). This is not an additional GNAP MUST or an assertion that JSON members are HTTP field values." } else if endpoint.is_some_and(|e| https_endpoint(e).is_none()) { "Not tested: endpoint passes raw URI syntax prechecks but its interpretation is unsupported by this URL parser (for example IPvFuture, oversized numeric port or a registered name). This coverage limit is neither a normative failure nor full URI validation; host encoding/production semantics remain unresolved. Exact endpoint identity is checked separately." } else { "Required grant_request_endpoint is a string containing an absolute HTTPS URL with a host, valid URL syntax and no fragment. HTTP loopback remains nonconformant, even if labelled development-only." }, if userinfo { "https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.4" } else { RFC }),
        check("discovery-endpoint-match", document.and_then(|_| queried_endpoint.map(|queried| endpoint == Some(queried))), "Compare the announced URL with the exact URL queried, without normalization. No imported URL is fetched. Missing queried_endpoint means this contextual check is not tested.", RFC),
    ];
    if userinfo {
        if let Some(finding) = checks
            .iter_mut()
            .find(|finding| finding.id == "discovery-endpoint")
        {
            finding.remediation = Some("Remove userinfo and its @ delimiter from the announced endpoint. This diagnostic profile never needs or accepts embedded credentials.");
        }
    }
    for (field, registered) in [
        (
            "interaction_start_modes_supported",
            (|v: &str| gnap_registry::InteractionStartMode::from(v).is_registered())
                as fn(&str) -> bool,
        ),
        (
            "interaction_finish_methods_supported",
            (|v: &str| gnap_registry::InteractionFinishMethod::from(v).is_registered())
                as fn(&str) -> bool,
        ),
        (
            "key_proofs_supported",
            (|v: &str| gnap_registry::KeyProofingMethod::from(v).is_registered())
                as fn(&str) -> bool,
        ),
        (
            "sub_id_formats_supported",
            (|v: &str| SUBJECT_FORMATS.contains(&v)) as fn(&str) -> bool,
        ),
        (
            "assertion_formats_supported",
            (|v: &str| gnap_registry::AssertionFormat::from(v).is_registered()) as fn(&str) -> bool,
        ),
    ] {
        let value = document.and_then(|o| o.get(field));
        let (outcome, detail, remediation) = match value {
            None if document.is_none() => (None, "Not tested: no unambiguous discovery object is available to inspect this capability list.", None),
            None => (None, "Optional capability list not announced. Omission is not a protocol failure and does not establish supported capabilities.", None),
            Some(Value::Array(values)) if values.iter().all(Value::is_string) => {
                if values.is_empty() {
                    (None, "Optional capability list is a correctly typed empty array: no capability is announced or exercised.", None)
                } else if values.iter().all(|v| registered(v.as_str().unwrap_or_default())) {
                    (Some(true), "All announced names occur in this build's registry snapshot. This verifies names only, not whether these capabilities actually work or are allowed for a particular client.", None)
                } else {
                    (None, "At least one name is unknown to this build's registry snapshot. Registration is unresolved, not accepted or certified; submitted values are not echoed.", Some("Check the current IANA registry linked in the page references and README before deciding whether the name is registered; update the snapshot or correct the announcement."))
                }
            }
            Some(_) => (Some(false), "When announced, this capability must be an array containing only JSON strings; null is not omission.", Some("Use an array of registered string names, or omit this optional field.")),
        };
        let mut finding = check(field, outcome, detail, RFC);
        finding.remediation = remediation;
        checks.push(finding);
    }
    let rotation = document.and_then(|o| o.get("key_rotation_supported"));
    let rotation_detail = if document.is_none() {
        "Not tested: no unambiguous discovery object is available to inspect the key rotation declaration."
    } else {
        match rotation {
            None => "Optional field not announced; section 9 defines omission as key rotation unsupported. This is not a failure.",
            Some(Value::Bool(false)) => "AS declares key rotation unsupported. This pass checks the boolean declaration only; no key rotation request was executed.",
            Some(Value::Bool(true)) => "AS declares key rotation supported. This pass checks the boolean declaration only; it does not prove rotation works or that any particular client is authorized.",
            Some(_) => "When present, the key rotation declaration must be a JSON boolean, not a string, number or null.",
        }
    };
    checks.push(check(
        "discovery-key-rotation-type",
        rotation.map(Value::is_boolean),
        rotation_detail,
        RFC,
    ));
    checks.push(check("discovery-capability-behavior", None, "Not tested: execution of advertised capabilities, authenticated grants, token/key rotation, client discovery helpers, RS discovery or RFC 9767. Unknown extension fields are not validated. No overall conformance verdict.", RFC));
    checks
}
