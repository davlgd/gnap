//! Deliberately small active test against operator-owned, exact allowlist URLs.
//! No URL supplied in the public request is ever resolved or fetched.

use crate::{check, observation, Check, Observation};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const COOLDOWN: Duration = Duration::from_secs(60);
const RESPONSE_LIMIT: usize = 32_768;

#[derive(Clone)]
pub struct Probes {
    targets: Arc<Vec<ConfiguredTarget>>,
    last_started: Arc<Mutex<Option<Instant>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    As,
    Rs,
}

#[derive(Clone)]
struct ConfiguredTarget {
    url: reqwest::Url,
    role: Role,
}

impl Probes {
    /// Configuration is operator consent to send the fixed malformed-grant
    /// probe. It is not an assertion of third-party ownership verification.
    pub fn from_json(configuration: &str) -> Result<Self, &'static str> {
        let targets: Vec<String> = serde_json::from_str(configuration).map_err(|_| {
            "GNAP_TEST_TARGETS must be a JSON array of exact HTTPS grant endpoint URLs"
        })?;
        if targets.len() > 8 {
            return Err("At most eight probe targets are permitted");
        }
        let targets = targets.into_iter().map(|raw| {
            let url = reqwest::Url::parse(&raw).map_err(|_| "Invalid probe target URL")?;
            if url.scheme() != "https" || url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() || url.port_or_known_default() != Some(443) || url.query().is_some() || url.fragment().is_some() || url.as_str() != raw {
                return Err("Probe targets must be canonical exact HTTPS URLs on port 443, without credentials, query or fragment");
            }
            if url.host_str().is_some_and(|host| host.parse::<IpAddr>().is_ok() || host.starts_with('[') || !host.contains('.')) {
                return Err("Probe target requires a public DNS hostname, not an IP literal or single-label host");
            }
            Ok(ConfiguredTarget { url, role: Role::As })
        }).collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            targets: Arc::new(targets),
            last_started: Arc::new(Mutex::new(None)),
        })
    }

    pub fn disabled() -> Self {
        Self::from_json("[]").expect("empty probe configuration is valid")
    }

    /// Protected RS endpoints use the identical URL and network safety policy.
    pub fn with_resource_targets(mut self, configuration: &str) -> Result<Self, &'static str> {
        let resources = Self::from_json(configuration)?;
        let mut combined = self.targets.as_ref().clone();
        combined.extend(resources.targets.iter().cloned().map(|mut target| {
            target.role = Role::Rs;
            target
        }));
        self.targets = Arc::new(combined);
        Ok(self)
    }
}

#[derive(Serialize)]
pub struct Target {
    id: usize,
    url: String,
    role: Role,
}

pub async fn targets(State(probes): State<Probes>) -> Json<Vec<Target>> {
    Json(
        probes
            .targets
            .iter()
            .enumerate()
            .map(|(id, target)| Target {
                id,
                url: target.url.to_string(),
                role: target.role,
            })
            .collect(),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeRequest {
    target_id: usize,
    consent: bool,
}

#[derive(Serialize)]
pub struct ProbeReport {
    schema_version: u8,
    profile: &'static str,
    certification: bool,
    observation: Observation,
    target_id: usize,
    role: Role,
    checks: Vec<Check>,
    limitations: &'static str,
}

pub async fn run(State(probes): State<Probes>, Json(input): Json<ProbeRequest>) -> Response {
    if !input.consent {
        return (
            StatusCode::BAD_REQUEST,
            "Explicit consent is required for the fixed test request.",
        )
            .into_response();
    }
    let Some(target) = probes.targets.get(input.target_id) else {
        return (StatusCode::NOT_FOUND, "No such operator-approved target.").into_response();
    };
    {
        let Ok(mut last) = probes.last_started.lock() else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        if last.is_some_and(|previous| previous.elapsed() < COOLDOWN) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "Global probe cooldown: one request per 60 seconds per process.",
            )
                .into_response();
        }
        *last = Some(Instant::now());
    }
    match tokio::time::timeout(Duration::from_secs(4), request(target)).await {
        Ok(Ok(checks)) => Json(ProbeReport {
            schema_version: 1, profile: match target.role { Role::As => "gnap-malformed-initial-request-v1", Role::Rs => "gnap-protected-resource-unauthenticated-v1" }, certification: false, observation: observation("live"),
            target_id: input.target_id, role: target.role, checks,
            limitations: "One unsigned request only. AS: malformed initial request. RS: credential-free GET against an operator-declared protected resource (policy test, not a general RFC requirement for all resources). No successful grants, proof verification, replay defense, rights enforcement, introspection or overall conformance. Scenarios are separate from SDK tests; AS response parsing reuses gnap-types. Network failures are inconclusive.",
        }).into_response(),
        _ => (StatusCode::BAD_GATEWAY, "Probe inconclusive: target resolution, address policy, TLS, deadline, body limit or network failed. No response content is returned.").into_response(),
    }
}

/// Conservative public-unicast policy: deliberately excludes some legitimate
/// special-purpose public ranges. False negatives are safer than an SSRF path.
fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, c, _] = v.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 0 || b == 168 || (b == 88 && c == 99)))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            // Native global unicast only; no mapped IPv4, NAT64, transition,
            // documentation, local, multicast or unknown future allocation.
            (s[0] & 0xe000) == 0x2000
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}

async fn request(target: &ConfiguredTarget) -> Result<Vec<Check>, ()> {
    let host = target.url.host_str().ok_or(())?;
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, 443))
        .await
        .map_err(|_| ())?
        .take(17)
        .collect();
    if addresses.is_empty()
        || addresses.len() > 16
        || addresses.iter().any(|address| !public_ip(address.ip()))
    {
        return Err(());
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host, &addresses)
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(3))
        .pool_max_idle_per_host(0)
        .build()
        .map_err(|_| ())?;
    let request = match target.role {
        Role::As => client
            .post(target.url.clone())
            .header("Content-Type", "application/json")
            .body("{"),
        Role::Rs => client.get(target.url.clone()),
    };
    let mut response = request
        .header("Accept", "application/json")
        .header(
            "User-Agent",
            "gnap-conformance-web/0.1 bounded-unsigned-probe",
        )
        .send()
        .await
        .map_err(|_| ())?;
    let status = response.status();
    let media = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/json")
        });
    let headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.to_string(), v.to_string()))
        })
        .collect();
    let no_store = gnap_types::http::HttpResponse {
        status: status.as_u16(),
        headers,
        body: vec![],
    }
    .has_no_store();
    if response
        .content_length()
        .is_some_and(|len| len > RESPONSE_LIMIT as u64)
    {
        return Err(());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if body.len() + chunk.len() > RESPONSE_LIMIT {
            return Err(());
        }
        body.extend_from_slice(&chunk);
    }
    if target.role == Role::Rs {
        return Ok(vec![
            check("protected-resource-rejects-unauthenticated", Some(matches!(status.as_u16(), 401 | 403)), "Deployment policy: operator-declared protected resource returned 401 or 403 to a credential-free GET. This is not proof of GNAP enforcement; a deny-all server also passes.", "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5"),
            check("rs-proof-rights-and-introspection", None, "Not tested: valid token acceptance, cryptographic key binding, rights/audience, replay rejection, rotation, revocation and introspection. No token or signature was presented.", "https://www.rfc-editor.org/rfc/rfc9767.html"),
        ]);
    }
    Ok(as_response_checks(status, media, no_store, &body))
}

fn as_response_checks(
    status: reqwest::StatusCode,
    media: bool,
    no_store: bool,
    body: &[u8],
) -> Vec<Check> {
    let error = serde_json::from_slice::<gnap_types::GrantResponse>(body)
        .ok()
        .and_then(|r| r.error);
    let only_error_fields = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .is_some_and(|v| {
            v.as_object()
                .is_some_and(|o| o.keys().all(|k| matches!(k.as_str(), "error" | "continue")))
        });
    vec![
        check("malformed-request-gnap-error-only", Some(error.is_some() && only_error_fields), "The malformed initial request returned a GNAP error without success fields. Only error and continue may appear; whether any continuation belongs to a pending grant remains untested.", "https://www.rfc-editor.org/rfc/rfc9635.html#section-3.6"),
        check("malformed-request-http-4xx", Some(status.is_client_error()), "Deployment policy: prefer HTTP 4xx for this client error. RFC 9635 does not prescribe this status class; HTTP 200 with a GNAP error is not by itself a GNAP conformance failure. Redirects are not followed.", "https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5"),
        check("error-response-json", Some(media && error.is_some()), "Response media type must be application/json and the parsed GNAP response must contain an error field. Does not determine whether the chosen error code is appropriate.", "https://www.rfc-editor.org/rfc/rfc9635.html#section-3"),
        check("known-error-code", error.as_ref().map(|e| e.code.is_registered()), "Error code membership in this build's vendored IANA registry snapshot only. An unknown code requires checking the current registry before asserting a normative failure.", "https://www.rfc-editor.org/rfc/rfc9635.html#section-3.6"),
        check("error-response-no-store", Some(no_store), "Error response must include Cache-Control: no-store.", "https://www.rfc-editor.org/rfc/rfc9635.html#section-3"),
        check("authenticated-flow", None, "No authenticated request was sent. Signature rejection, grant creation, RS access and stateful lifecycle remain untested.", "https://www.rfc-editor.org/rfc/rfc9635.html"),
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
        assert!(policy
            .remediation
            .unwrap()
            .contains("not required by RFC 9635"));
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
    #[test]
    fn targets_are_exact_canonical_operator_config_not_user_urls() {
        assert!(Probes::from_json(r#"["https://example.com/gnap"]"#).is_ok());
        for target in [
            "http://example.com/gnap",
            "https://localhost/gnap",
            "https://127.0.0.1/gnap",
            "https://[::1]/gnap",
            "https://user:secret@example.com/gnap",
            "https://example.com:8443/gnap",
            "https://example.com/gnap?token=secret",
            "https://example.com/gnap#x",
            "https://example.com/a/../gnap",
        ] {
            assert!(
                Probes::from_json(&serde_json::to_string(&vec![target]).unwrap()).is_err(),
                "{target}"
            );
        }
        assert!(serde_json::from_str::<ProbeRequest>(
            r#"{"target_id":0,"consent":true,"url":"https://attacker.example"}"#
        )
        .is_err());
    }

    #[tokio::test]
    async fn roles_use_server_selected_targets_and_shared_cooldown() {
        let probes = Probes::from_json(r#"["https://example.com/gnap"]"#)
            .unwrap()
            .with_resource_targets(r#"["https://example.com/resource"]"#)
            .unwrap();
        assert_eq!(probes.targets[0].role, Role::As);
        assert_eq!(probes.targets[1].role, Role::Rs);
        *probes.last_started.lock().unwrap() = Some(Instant::now());
        assert_eq!(
            run(
                State(probes.clone()),
                Json(ProbeRequest {
                    target_id: 0,
                    consent: true
                })
            )
            .await
            .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            run(
                State(probes),
                Json(ProbeRequest {
                    target_id: 1,
                    consent: true
                })
            )
            .await
            .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    #[test]
    fn denies_private_metadata_and_transition_addresses() {
        for address in [
            "0.0.0.0",
            "10.2.3.4",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.1.1",
            "192.0.0.9",
            "192.0.2.1",
            "192.88.99.1",
            "198.18.0.1",
            "198.51.100.2",
            "203.0.113.5",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::ffff:127.0.0.1",
            "fc00::1",
            "fe80::1",
            "64:ff9b::a00:1",
            "2002:7f00:1::1",
            "2001:db8::1",
            "2001::1",
            "3fff::1",
        ] {
            assert!(!public_ip(address.parse().unwrap()), "{address}");
        }
        for address in [
            "8.8.8.8",
            "1.1.1.1",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
        ] {
            assert!(public_ip(address.parse().unwrap()), "{address}");
        }
    }
    #[tokio::test]
    async fn missing_consent_and_unknown_target_never_fetch() {
        assert_eq!(
            run(
                State(Probes::disabled()),
                Json(ProbeRequest {
                    target_id: 0,
                    consent: false
                })
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            run(
                State(Probes::disabled()),
                Json(ProbeRequest {
                    target_id: 0,
                    consent: true
                })
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
    }
}
