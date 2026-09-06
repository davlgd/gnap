//! Cross-message label diagnostics over a caller-declared pair of JSON objects.
//! This import envelope is local tooling, not a GNAP message or live exchange.

use crate::{check, observation, rs_import, Check, Import, Report};
use serde_json::{Map, Value};
use std::collections::HashSet;

const REQUEST: &str = "https://www.rfc-editor.org/rfc/rfc9635.html#section-2.1";
const RESPONSE: &str = "https://www.rfc-editor.org/rfc/rfc9635.html#section-3.2";

struct Tokens<'a> {
    multiple: bool,
    objects: Vec<&'a Map<String, Value>>,
}
impl<'a> Tokens<'a> {
    fn from(value: &'a Value) -> Option<Self> {
        match value {
            Value::Object(object) => Some(Self {
                multiple: false,
                objects: vec![object],
            }),
            Value::Array(array) => Some(Self {
                multiple: true,
                objects: array.iter().map(Value::as_object).collect::<Option<_>>()?,
            }),
            _ => None,
        }
    }
    fn valid_labels(&self) -> Option<bool> {
        if self.objects.is_empty() {
            return None;
        }
        let mut seen = HashSet::new();
        Some(self.objects.iter().all(|object| match object.get("label") {
            None => !self.multiple,
            Some(value) => value.as_str().is_some_and(|label| seen.insert(label)),
        }))
    }
}

fn correspondence(request: &Tokens<'_>, response: &Tokens<'_>) -> Option<bool> {
    if request.valid_labels() != Some(true)
        || response.valid_labels() != Some(true)
        || request.multiple != response.multiple
    {
        return None;
    }
    if request.multiple {
        let requested: HashSet<_> = request
            .objects
            .iter()
            .filter_map(|token| token.get("label").and_then(Value::as_str))
            .collect();
        Some(response.objects.iter().all(|token| {
            token
                .get("label")
                .and_then(Value::as_str)
                .is_some_and(|label| requested.contains(label))
        }))
    } else {
        let requested = request.objects[0].get("label").and_then(Value::as_str);
        let answered = response.objects[0].get("label").and_then(Value::as_str);
        Some(requested.is_none_or(|label| answered == Some(label)))
    }
}

fn pair_checks(pair: &Map<String, Value>, checks: &mut Vec<Check>) {
    let request = pair.get("request").and_then(Value::as_object);
    let response = pair.get("response").and_then(Value::as_object);
    checks.push(check(
        "token-exchange-pair",
        Some(request.is_some() && response.is_some()),
        concat!(
            "Local import envelope requires request and response objects. Their ",
            "asserted relationship is supplied by the caller, not authenticated ",
            "or observed by this tool.",
        ),
        RESPONSE,
    ));
    let (Some(request), Some(response)) = (request, response) else {
        return;
    };
    let requested_value = request.get("access_token");
    let answered_value = response.get("access_token");
    let requested = requested_value.and_then(Tokens::from);
    let answered = answered_value.and_then(Tokens::from);
    for (id, value, tokens, reference) in [
        (
            "token-exchange-request-shape",
            requested_value,
            requested.as_ref(),
            REQUEST,
        ),
        (
            "token-exchange-response-shape",
            answered_value,
            answered.as_ref(),
            RESPONSE,
        ),
    ] {
        checks.push(check(
            id,
            value.map(|_| tokens.is_some()),
            concat!(
                "When present, access_token is an object or an array of objects. ",
                "An absent field is not tested; an empty array supplies no token ",
                "whose labels can be compared. Token values, rights and other ",
                "fields are not validated here.",
            ),
            reference,
        ));
    }
    for (id, tokens, reference) in [
        ("token-exchange-request-labels", requested.as_ref(), REQUEST),
        (
            "token-exchange-response-labels",
            answered.as_ref(),
            RESPONSE,
        ),
    ] {
        checks.push(check(
            id,
            tokens.and_then(Tokens::valid_labels),
            concat!(
                "Every token in an array requires a unique string label. A ",
                "singleton label is optional here but must be a string when ",
                "supplied; request-response correspondence is a separate check. ",
                "No token objects means not tested.",
            ),
            reference,
        ));
    }
    let both = requested.as_ref().zip(answered.as_ref());
    checks.push(check(
        "token-exchange-cardinality",
        both.map(|(a, b)| a.multiple == b.multiple),
        concat!(
            "An issued token field retains the requested object or array shape, ",
            "including a one-token partial response to an array request. ",
            "Missing or malformed fields leave this comparison untested.",
        ),
        RESPONSE,
    ));
    checks.push(check(
        "token-exchange-label-correspondence",
        both.and_then(|(a, b)| correspondence(a, b)),
        concat!(
            "Issued array labels must come from the request, in any order; ",
            "a subset is allowed. A requested singleton label must be echoed; ",
            "without one the AS may add a label. Missing tokens, invalid labels ",
            "or incompatible shapes leave correspondence untested. Matching ",
            "labels does not prove issuance or correct rights.",
        ),
        RESPONSE,
    ));
}

pub(crate) fn analyze(input: &Import) -> Result<Report, &'static str> {
    if input.headers.is_some() || input.content_digest.is_some() {
        return Err(concat!(
            "A token_exchange import is a pair, not one HTTP message; ",
            "omit headers and content_digest.",
        ));
    }
    let mut checks = Vec::new();
    let parsed = serde_json::from_str::<Value>(&input.body);
    let shape = match &parsed {
        Ok(value) => Some(value.is_object()),
        Err(error)
            if error.to_string().starts_with("number out of range")
                || error.to_string().starts_with("recursion limit exceeded") =>
        {
            None
        }
        Err(_) => Some(false),
    };
    checks.push(check(
        "token-exchange-json-object",
        shape,
        concat!(
            "The local pair envelope is a JSON object. Parser depth and number-range ",
            "limits are inconclusive, not GNAP violations.",
        ),
        "https://www.rfc-editor.org/rfc/rfc8259.html",
    ));
    let unique = parsed
        .as_ref()
        .ok()
        .map(|_| rs_import::unambiguous(&input.body));
    checks.push(check(
        "token-exchange-json-unambiguous",
        unique.filter(|ok| *ok),
        concat!(
            "Duplicate members at any depth make interpretation inconclusive. ",
            "No last-wins comparison is performed; this is not an added GNAP ",
            "MUST for unique names.",
        ),
        "https://www.rfc-editor.org/rfc/rfc8259.html#section-4",
    ));
    if let Some(pair) = parsed
        .as_ref()
        .ok()
        .and_then(Value::as_object)
        .filter(|_| unique == Some(true))
    {
        pair_checks(pair, &mut checks);
    }
    checks.extend([
        check(
            "token-exchange-authenticity",
            None,
            concat!(
                "Not tested: the two objects' provenance and actual relationship, ",
                "signatures, trusted keys, HTTP status, headers, TLS and nonce ",
                "replay. This tool makes no network request.",
            ),
            REQUEST,
        ),
        check(
            "token-exchange-authority",
            None,
            concat!(
                "Not tested: effective rights, audience, token values or formats, ",
                "consent and reasons for omitted tokens. Correct labels are not ",
                "proof of a correct authorization decision.",
            ),
            RESPONSE,
        ),
        check(
            "token-exchange-lifecycle",
            None,
            concat!(
                "Not tested: atomic publication, partial failures, continuation, ",
                "per-token rotation or revocation, key rotation, expiration and ",
                "downstream cascades. These require stateful execution.",
            ),
            "https://www.rfc-editor.org/rfc/rfc9635.html#section-6",
        ),
    ]);
    Ok(Report {
        schema_version: 1,
        profile: "gnap-token-exchange-import-v1",
        kind: input.kind,
        certification: false,
        independence: concat!(
            "Cross-message JSON comparisons use serde_json directly, not ",
            "gnap-types validators. A caller-declared pair is not an independent ",
            "protocol implementation, observed exchange or certification.",
        ),
        observation: observation("import"),
        checks,
    })
}
