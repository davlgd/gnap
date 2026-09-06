//! Selected grant-message JSON assertions for AS-mediated derivation, not an
//! opaque-token, single-hop or non-interactive deployment profile.
use super::{access_shape, add, key_shape, strings, Check, Map, Value};
use std::collections::HashSet;

pub(super) const RFC: &str = "https://www.rfc-editor.org/rfc/rfc9767.html#section-4";
const REQUEST: &str = "https://www.rfc-editor.org/rfc/rfc9635.html#section-2.1";
const RESPONSE: &str = "https://www.rfc-editor.org/rfc/rfc9635.html#section-3.2";

fn tokens(value: &Value) -> Option<Vec<&Map<String, Value>>> {
    if let Some(object) = value.as_object() {
        Some(vec![object])
    } else {
        value.as_array()?.iter().map(Value::as_object).collect()
    }
}

// A syntactically empty token array provides no token on which to check fields.
// Do not turn a vacuous iterator result into evidence of issuance or a new
// prohibition on empty arrays; report the outer shape separately.
fn every(
    tokens: Option<&[&Map<String, Value>]>,
    f: impl Fn(&Map<String, Value>) -> bool,
) -> Option<bool> {
    tokens
        .filter(|t| !t.is_empty())
        .map(|t| t.iter().all(|o| f(o)))
}

fn labels(value: &Value, objects: &[&Map<String, Value>]) -> Option<bool> {
    if objects.is_empty() {
        return None;
    }
    let multiple = value.is_array();
    if !multiple && !objects[0].contains_key("label") {
        return None;
    }
    let mut seen = HashSet::new();
    Some(objects.iter().all(|o| {
        o.get("label")
            .and_then(Value::as_str)
            .is_some_and(|s| seen.insert(s))
    }))
}

fn flags_valid(v: &Value) -> bool {
    if !strings(v) {
        return false;
    }
    let mut seen = HashSet::new();
    v.as_array()
        .is_some_and(|values| values.iter().all(|v| seen.insert(v.as_str())))
}

fn token_details(value: Option<&Value>, response: bool, checks: &mut Vec<Check>) {
    let objects = value.and_then(tokens);
    let objects = objects.as_deref();
    let reference = if response { RESPONSE } else { REQUEST };
    add(
        checks,
        if response {
            "derivation-response-access"
        } else {
            "derivation-request-access"
        },
        every(objects, |o| o.get("access").is_some_and(access_shape)),
        concat!(
            "Each selected token object requires access in GNAP array form, with ",
            "string type for access objects and selected standard dimensions. Empty ",
            "rights arrays are not prohibited. Requested or declared rights are not ",
            "verified effective rights; no token objects means not tested.",
        ),
        reference,
    );
    add(
        checks,
        if response {
            "derivation-response-labels"
        } else {
            "derivation-request-labels"
        },
        value.zip(objects).and_then(|(v, t)| labels(v, t)),
        if response {
            concat!(
                "Each object in a multiple-token response requires a unique string ",
                "label (RFC 9635 section 3.2.2). A supplied singleton label must be a ",
                "string. Matching labels to the request, singleton label necessity and ",
                "response cardinality need the original request and are not tested.",
            )
        } else {
            concat!(
                "Each object in a multiple-token request requires a unique string label ",
                "(RFC 9635 section 2.1.2). A singleton label is optional but must be a ",
                "string when supplied. An empty token array provides no labels to ",
                "check.",
            )
        },
        reference,
    );
    let flags = objects.filter(|t| t.iter().any(|o| o.contains_key("flags")));
    add(
        checks,
        if response {
            "derivation-response-flags"
        } else {
            "derivation-request-flags"
        },
        every(flags, |o| o.get("flags").is_none_or(flags_valid)),
        concat!(
            "Optional flag arrays contain strings without repeated values. Unknown ",
            "flags are not forbidden by this check: their registration and ",
            "semantics remain untested. Absence is optional, not a missing-MUST ",
            "failure.",
        ),
        reference,
    );
    if response {
        add(
            checks,
            "derivation-response-value",
            every(objects, |o| o.get("value").is_some_and(Value::is_string)),
            concat!(
                "Each issued token object requires value. This check verifies string ",
                "shape ONLY, not the token68 character-set requirement, cryptographic ",
                "format, usability, validity or parent-child relationship.",
            ),
            RESPONSE,
        );
        add(
            checks,
            "derivation-response-key-binding-shape",
            every(objects, |o| {
                let bearer = o
                    .get("flags")
                    .and_then(Value::as_array)
                    .is_some_and(|flags| flags.iter().any(|f| f.as_str() == Some("bearer")));
                !(bearer && o.contains_key("key")) && o.get("key").is_none_or(key_shape)
            }),
            concat!(
                "A bearer flag forbids any key member. Otherwise a supplied key is ",
                "checked only as object/reference string. Omitted key is allowed; this ",
                "check proves neither a valid key nor binding to RS1's request key.",
            ),
            RESPONSE,
        );
        let optional = objects.filter(|t| {
            t.iter()
                .any(|o| o.contains_key("expires_in") || o.contains_key("manage"))
        });
        add(
            checks,
            "derivation-response-token-optionals",
            every(optional, |o| {
                o.get("expires_in").is_none_or(|v| v.is_i64() || v.is_u64())
                    && o.get("manage").is_none_or(Value::is_object)
            }),
            concat!(
                "Selected optional types only: expires_in is an integer and manage an ",
                "object. No expiration, management token/URI, nested required-field, ",
                "key or lifetime checks are performed.",
            ),
            RESPONSE,
        );
    }
}

pub(super) fn request(o: &Map<String, Value>, checks: &mut Vec<Check>) {
    add(
        checks,
        "derivation-request-parent",
        Some(o.get("existing_access_token").is_some_and(Value::is_string)),
        concat!(
            "existing_access_token is the string carrying the presented parent ",
            "token in this selected derivation request. String shape does not prove ",
            "its format, equality to the token received by RS1, validity or ",
            "suitability for RS1. Never upload a production token.",
        ),
        RFC,
    );
    add(
        checks,
        "derivation-request-client",
        Some(o.get("client").is_some_and(|v| {
            v.is_string()
                || v.as_object()
                    .is_some_and(|c| c.get("key").is_some_and(key_shape))
        })),
        concat!(
            "The RS acts as a client: client is required as an identity reference ",
            "or an object with key as object/reference. This is outer shape only; ",
            "the RS must identify itself with its own key and sign, which JSON ",
            "cannot verify. resource_server is not a replacement for client.",
        ),
        RFC,
    );
    let token = o.get("access_token");
    add(
        checks,
        "derivation-request-token-shape",
        Some(token.is_some_and(|v| tokens(v).is_some())),
        concat!(
            "This profile selects a request for derived access tokens, so ",
            "access_token is required as an object or array of objects under RFC ",
            "9635 section 2.1. This is not a universal requirement for every GNAP ",
            "GrantRequest or a successful-grant verdict.",
        ),
        REQUEST,
    );
    token_details(token, false, checks);
    let present = ["subject", "user", "interact"]
        .iter()
        .any(|k| o.contains_key(*k));
    add(
        checks,
        "derivation-request-optional-shape",
        present.then(|| {
            ["subject", "interact"]
                .iter()
                .all(|k| o.get(*k).is_none_or(Value::is_object))
                && o.get("user").is_none_or(|v| v.is_string() || v.is_object())
        }),
        concat!(
            "Selected outer types only: subject/interact objects and user ",
            "object/reference. Interaction is not forbidden by the section 4 ",
            "diagram. Nested required fields, real interaction capabilities and ",
            "user/subject semantics remain untested.",
        ),
        "https://www.rfc-editor.org/rfc/rfc9635.html#section-2",
    );
}

pub(super) fn response(o: &Map<String, Value>, checks: &mut Vec<Check>) {
    let token = o.get("access_token");
    add(
        checks,
        "derivation-response-token-shape",
        token.map(|v| tokens(v).is_some()),
        concat!(
            "If supplied, access_token is an object or array of objects. Absence is ",
            "not tested, not an issuance success or failure: a grant response may ",
            "instead contain continuation, interaction or error. An empty array ",
            "establishes no issued token.",
        ),
        RESPONSE,
    );
    token_details(token, true, checks);
    let present = ["continue", "interact", "subject", "instance_id", "error"]
        .iter()
        .any(|k| o.contains_key(*k));
    add(
        checks,
        "derivation-response-optional-shape",
        present.then(|| {
            ["continue", "interact", "subject"]
                .iter()
                .all(|k| o.get(*k).is_none_or(Value::is_object))
                && o.get("instance_id").is_none_or(Value::is_string)
                && o.get("error")
                    .is_none_or(|v| v.is_string() || v.is_object())
        }),
        concat!(
            "Selected outer grant-response types only: continue/interact/subject ",
            "objects, instance_id string and error object/string. Their nested ",
            "fields, error conventions, state applicability and consistency are not ",
            "tested; passing shape is not a completed derivation.",
        ),
        "https://www.rfc-editor.org/rfc/rfc9635.html#section-3",
    );
}

pub(super) fn unobservable(checks: &mut Vec<Check>) {
    for (id, detail) in [
        (
            "derivation-proof-and-parent-validity",
            concat!(
                "Not tested: RS1 must sign with its own key, not the parent token's key ",
                "or original client's key. JSON proves neither key possession/ownership ",
                "nor signature, replay protection, parent token validity or equality to ",
                "its original presentation.",
            ),
        ),
        (
            "derivation-parent-rs-suitability",
            concat!(
                "Not tested: the AS MUST determine that the presented parent token is ",
                "appropriate for use at the RS requesting derivation. Imported ",
                "identifiers cannot establish that audience, policy, identity or ",
                "authorization decision.",
            ),
        ),
        (
            "derivation-effective-rights-and-audience",
            concat!(
                "Not tested: requested/declared access does not prove effective rights, ",
                "audience at a downstream RS, consent or safe delegation. No ",
                "opaque-only, single-hop, non-interactive or generic subset rule is ",
                "inferred from the demonstration.",
            ),
        ),
        (
            "derivation-revocation-and-lineage",
            concat!(
                "Not tested: parent-child lineage, expiry, later revocation, ",
                "propagation or non-resurrection need authenticated stateful ",
                "observations. A cascading-revocation policy is not established by JSON ",
                "or imposed here as a blanket section 4 rule.",
            ),
        ),
        (
            "derivation-grant-exchange",
            concat!(
                "Not tested: request/response label matching and cardinality, approval, ",
                "interaction, continuation, error semantics, nested key and management ",
                "validation, token formats and extensions require additional ",
                "checks/context. No client completion or successful issuance is ",
                "inferred.",
            ),
        ),
    ] {
        add(checks, id, None, detail, RFC);
    }
    add(
        checks,
        "derivation-token-value-encoding",
        None,
        concat!(
            "Not tested: RFC 9635 section 3.2.1 restricts issued token values to ",
            "the token68 character set. The separately named value assertion checks ",
            "only JSON string shape; neither it nor this report validates token ",
            "encoding or content.",
        ),
        RESPONSE,
    );
}
