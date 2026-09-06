//! Assertions over captured HTTP/JSON, not GNAP SDK deserializers or validators.
//! A passing selected profile check is not a complete protocol verdict.
use super::config::{member, Target, RIGHT};
use crate::{check, Check};
use gnap_types::http::HttpResponse;
use serde_json::Value;

const RFC: &str = "https://www.rfc-editor.org/rfc/rfc9635.html";

pub fn assertion(id: &'static str, outcome: bool, detail: &'static str) -> Check {
    check(id, Some(outcome), detail, RFC)
}

fn json(response: &HttpResponse) -> Option<Value> {
    let media: Vec<_> = response
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("content-type"))
        .collect();
    if media.len() != 1
        || !media[0]
            .1
            .split(';')
            .next()?
            .trim()
            .eq_ignore_ascii_case("application/json")
    {
        return None;
    }
    serde_json::from_slice(&response.body).ok()
}

fn token_value(value: &Value) -> Option<&str> {
    let value = value.as_str()?;
    let core = value.trim_end_matches('=');
    (!core.is_empty()
        && value.len() <= 4096
        && core
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b)))
    .then_some(value)
}

fn management(token: &Value, target: &Target) -> bool {
    let Some(resource) = token.get("value").and_then(token_value) else {
        return false;
    };
    let Some(manage) = token.get("manage") else {
        return false;
    };
    let Some(uri) = manage.get("uri").and_then(Value::as_str) else {
        return false;
    };
    let Some(protector) = manage.get("access_token") else {
        return false;
    };
    member(uri, &target.management)
        && protector
            .get("value")
            .and_then(token_value)
            .is_some_and(|value| {
                value != resource && !uri.contains(value) && !uri.contains(resource)
            })
        && protector.get("key").is_none()
        && protector.get("manage").is_none()
        && protector
            .get("flags")
            .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty))
}

#[derive(Clone, Copy)]
pub enum Phase {
    Pending,
    Issued,
    Rotated,
    Denied,
}

pub fn headers(response: &HttpResponse, checks: &mut Vec<Check>, phase: Phase) {
    let (cache_id, json_id) = match phase {
        Phase::Pending => ("lifecycle-pending-no-store", "lifecycle-pending-json"),
        Phase::Issued => ("lifecycle-issued-no-store", "lifecycle-issued-json"),
        Phase::Rotated => ("lifecycle-rotated-no-store", "lifecycle-rotated-json"),
        Phase::Denied => ("lifecycle-denial-no-store", "lifecycle-denial-json"),
    };
    let no_store = response
        .headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("cache-control"))
        .flat_map(|(_, v)| v.split(','))
        .any(|v| v.trim().eq_ignore_ascii_case("no-store"));
    checks.push(assertion(cache_id, no_store,
        "Observed AS response includes Cache-Control: no-store; checked directly from captured headers."));
    checks.push(assertion(json_id, json(response).is_some(),
        "Observed AS response has one application/json Content-Type and valid JSON. This does not validate every message member."));
}

pub fn pending(response: &HttpResponse, target: &Target, checks: &mut Vec<Check>) -> bool {
    headers(response, checks, Phase::Pending);
    let body = json(response);
    let valid = body.as_ref().is_some_and(|b| {
        response.status == 200
            && b.get("error").is_none()
            && b.get("access_token").is_none()
            && b.pointer("/continue/uri").and_then(Value::as_str)
                == Some(target.continuation.as_str())
            && b.pointer("/interact/redirect")
                .and_then(Value::as_str)
                .is_some_and(|uri| member(uri, &target.interaction))
            && b.pointer("/interact/finish")
                .and_then(Value::as_str)
                .is_some_and(|nonce| !nonce.is_empty())
    });
    checks.push(assertion("lifecycle-manual-consent-required", valid,
        "Selected scenario: initial HTTP 200 response requests redirect consent at the configured AS, with the exact continuation endpoint and no issued access token. HTTP 200 and this interaction shape are scenario expectations, not universal GNAP requirements."));
    valid
}

pub fn token(
    response: &HttpResponse,
    target: &Target,
    previous: Option<&str>,
    checks: &mut Vec<Check>,
) -> bool {
    headers(
        response,
        checks,
        if previous.is_some() {
            Phase::Rotated
        } else {
            Phase::Issued
        },
    );
    let body = json(response);
    let token = body
        .as_ref()
        .and_then(|b| b.get("access_token"))
        .filter(|v| v.is_object());
    let profile = token.is_some_and(|t| {
        management(t, target)
            && t.get("access") == Some(&serde_json::json!([RIGHT]))
            && t.get("expires_in")
                .and_then(Value::as_u64)
                .is_some_and(|n| (1..=300).contains(&n))
            && t.get("key").is_none()
            && t.get("flags")
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty))
    }) && response.status == 200
        && body
            .as_ref()
            .is_some_and(|b| b.get("error").is_none() && b.get("continue").is_none());
    checks.push(assertion(if previous.is_some() { "lifecycle-rotated-token-profile" } else { "lifecycle-issued-token-profile" }, profile,
        "Selected scenario: one managed token with token68 values, a distinct protecting token absent from the management URI, implicit binding, no flags, the exact synthetic read right, lifetime 1–300 seconds and closed continuation. Exact rights, lifetime bounds, no flags and closed continuation are profile choices; management credential constraints come from RFC 9635 §3.2.1."));
    if let Some(previous) = previous {
        checks.push(assertion("lifecycle-rotation-changes-value", token.and_then(|t| t.get("value")).and_then(Value::as_str).is_some_and(|s| s != previous),
            "Rotation returned a different access-token value; neither value is included in the report."));
    }
    profile
}

pub fn read(response: &HttpResponse, id: &'static str, checks: &mut Vec<Check>) {
    let body = json(response);
    checks.push(assertion(id, response.status == 200 && body.as_ref().is_some_and(|b| {
        b.get("granted_right").and_then(Value::as_str) == Some(RIGHT)
            && b.get("documents").and_then(Value::as_array).is_some_and(|v| !v.is_empty())
    }), "Selected synthetic resource returned HTTP 200 and its declared read result to a freshly signed request. This positive control prevents a deny-all service from passing the negative tests."));
}

pub fn refusal(response: &HttpResponse, id: &'static str, checks: &mut Vec<Check>) {
    let detail = if id == "lifecycle-replay-refused" {
        "The protected resource refused the identical signed request, with unchanged nonce and creation time, using HTTP 401 or 403. This is this profile's nonce-replay policy; a fresh signature using the same live token is tested separately."
    } else {
        "Selected protected resource refused this negative probe with HTTP 401 or 403. This is an observed deployment-policy check, not a prescribed status for every GNAP resource."
    };
    checks.push(assertion(id, matches!(response.status, 401 | 403), detail));
}

pub fn revoked(response: &HttpResponse, checks: &mut Vec<Check>) {
    checks.push(assertion("lifecycle-token-revocation-response", response.status == 204 && response.body.is_empty(),
        "Token management returned the HTTP 204 empty response expected by the GNAP client after deletion. A subsequent fresh resource request tests the retired token separately."));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_token_uses_an_object_with_a_separate_protecting_token() {
        let target = Target {
            name: "fixture".into(),
            grant: "https://as.example/gnap".into(),
            continuation: "https://as.example/continue".into(),
            interaction: "https://as.example/interact/".into(),
            management: "https://as.example/token/".into(),
            resource: "https://rs.example/resource/folder".into(),
        };
        let body = serde_json::json!({"access_token":{
            "value":"synthetic-resource-token", "access":[RIGHT], "expires_in":300,
            "manage":{"uri":"https://as.example/token/management-id", "access_token":{"value":"synthetic-management-token"}}
        }});
        let response = |body: &Value| HttpResponse {
            status: 200,
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("cache-control".into(), "no-store".into()),
            ],
            body: serde_json::to_vec(body).unwrap(),
        };
        let mut checks = Vec::new();
        assert!(token(&response(&body), &target, None, &mut checks));
        assert!(checks.iter().all(|c| c.status == crate::Status::Pass));
        assert!(!serde_json::to_string(&checks)
            .unwrap()
            .contains("synthetic-resource-token"));
        for invalid in [
            Value::Null,
            Value::String("https://as.example/token/management-id".into()),
            serde_json::json!({"uri":"https://evil.example/token/id","access_token":{"value":"secret"}}),
            serde_json::json!({"uri":"https://as.example/token/id","access_token":{"value":""}}),
            serde_json::json!({"uri":"https://as.example/token/id","access_token":{"value":"synthetic-resource-token"}}),
            serde_json::json!({"uri":"https://as.example/token/secret","access_token":{"value":"secret"}}),
            serde_json::json!({"uri":"https://as.example/token/id","access_token":{"value":"secret", "key":null}}),
            serde_json::json!({"uri":"https://as.example/token/id","access_token":{"value":"secret", "manage":null}}),
            serde_json::json!({"uri":"https://as.example/token/id","access_token":{"value":"secret", "flags":["bearer"]}}),
            serde_json::json!({"uri":"https://as.example/token/id","access_token":{"value":"not a token"}}),
        ] {
            let mut changed = body.clone();
            changed["access_token"]["manage"] = invalid;
            assert!(!token(&response(&changed), &target, None, &mut Vec::new()));
        }
    }

    #[test]
    fn token68_allows_only_trailing_padding_and_nonempty_content() {
        for value in ["token", "-._~+/09azAZ", "a=", "a=="] {
            assert_eq!(token_value(&Value::String(value.into())), Some(value));
        }
        for value in ["", "=", "==", "a=b", "white space", "é", "a\n"] {
            assert_eq!(token_value(&Value::String(value.into())), None);
        }
    }

    #[test]
    fn failures_do_not_reflect_response_values() {
        let response = HttpResponse {
            status: 500,
            headers: vec![],
            body: b"TOP-SECRET".to_vec(),
        };
        let mut checks = Vec::new();
        headers(&response, &mut checks, Phase::Pending);
        read(&response, "lifecycle-valid-token-read", &mut checks);
        refusal(&response, "lifecycle-replay-refused", &mut checks);
        revoked(&response, &mut checks);
        assert!(checks.iter().all(|c| c.status == crate::Status::Fail));
        assert!(!serde_json::to_string(&checks)
            .unwrap()
            .contains("TOP-SECRET"));
    }
}
