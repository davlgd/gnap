//! The command line's checks and report, independent of its arguments and
//! of the network, so that tests can drive them with any transport.
//!
//! A report says which selected checks passed, failed, or couldn't be
//! decided. It never says that a server conforms to GNAP: the checks are a
//! selection, documented one by one with the clause they rely on.

use crate::{discovery, probe, Check, Status};
use gnap_client::{HttpRequest, HttpTransport};
use serde::Serialize;

/// The version of the report format.
pub const SCHEMA: &str = "gnap-conformance/1";

/// What one check concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The observed behaviour matches what the check expects.
    Passed,
    /// The observed behaviour departs from what the check expects.
    Failed,
    /// The check couldn't decide, such as when the exchange failed.
    Inconclusive,
    /// The check didn't run: what it needs wasn't observed.
    Skipped,
    /// The check doesn't apply to this target or scenario.
    NotApplicable,
}

/// One check of a report.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// A stable identifier.
    pub id: &'static str,
    /// What the check concluded.
    pub outcome: Outcome,
    /// The clause the check relies on.
    pub reference: &'static str,
    /// What the check examines, and its limits.
    pub detail: &'static str,
}

impl From<Check> for Finding {
    fn from(check: Check) -> Self {
        Self {
            id: check.id,
            outcome: match check.status {
                Status::Pass => Outcome::Passed,
                Status::Fail => Outcome::Failed,
                Status::NotTested if check.undecided => Outcome::Inconclusive,
                Status::NotTested => Outcome::Skipped,
            },
            reference: check.reference,
            detail: check.detail,
        }
    }
}

/// How many checks reached each outcome.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub passed: usize,
    pub failed: usize,
    pub inconclusive: usize,
    pub skipped: usize,
    pub not_applicable: usize,
}

/// A command's report: what ran against which target, and what it found.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema: &'static str,
    pub tool: &'static str,
    pub version: &'static str,
    pub command: &'static str,
    /// The endpoint the command was given, which carries no credentials.
    pub target: String,
    /// The time the command started, in seconds since the Unix epoch.
    pub started: u64,
    /// What a scenario was asked to run, so that its results can be told
    /// apart from another run's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<Profile>,
    pub findings: Vec<Finding>,
    pub summary: Summary,
    /// What the report doesn't establish.
    pub scope: &'static str,
}

/// The plan of a scenario, without its rights or its resource URI, which
/// may name what the operator keeps private.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Profile {
    pub proof: &'static str,
    pub alg: &'static str,
    /// How many rights the grant requests.
    pub access: usize,
    /// Whether the scenario reads a resource.
    pub resource: bool,
    pub rotate_key: bool,
    /// The longest wait for an interaction, in seconds.
    pub wait: u64,
}

/// What a report never claims.
pub const SCOPE: &str = "Selected checks only, each scoped by its detail. Passing them is not \
     GNAP conformance or certification, and a failure is a deviation from the stated \
     expectation, which its reference qualifies.";

impl Report {
    fn new(command: &'static str, target: &str, started: u64, findings: Vec<Finding>) -> Self {
        let mut summary = Summary::default();
        for finding in &findings {
            *match finding.outcome {
                Outcome::Passed => &mut summary.passed,
                Outcome::Failed => &mut summary.failed,
                Outcome::Inconclusive => &mut summary.inconclusive,
                Outcome::Skipped => &mut summary.skipped,
                Outcome::NotApplicable => &mut summary.not_applicable,
            } += 1;
        }
        Self {
            schema: SCHEMA,
            tool: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
            command,
            target: target.to_owned(),
            started,
            profile: None,
            findings,
            summary,
            scope: SCOPE,
        }
    }

    /// The report of the `lifecycle` scenario.
    #[must_use]
    pub fn scenario(target: &str, started: u64, profile: Profile, findings: Vec<Finding>) -> Self {
        Self {
            profile: Some(profile),
            ..Self::new("lifecycle", target, started, findings)
        }
    }

    /// The process exit code: 1 when a check failed, 2 when one couldn't be
    /// decided or none passed, and 0 only when every selected check that
    /// applied passed.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        if self.summary.failed > 0 {
            1
        } else if self.summary.inconclusive > 0 || self.summary.passed == 0 {
            2
        } else {
            0
        }
    }

    /// The report for a terminal: one line per check, then the summary.
    #[must_use]
    pub fn text(&self) -> String {
        let mut text = format!("{} {} — {}\n\n", self.command, self.target, self.scope);
        if let Some(p) = self.profile {
            text.push_str(&format!(
                "profile: {} {}, {} right(s), resource {}, key rotation {}, wait {} s\n\n",
                p.proof,
                p.alg,
                p.access,
                if p.resource { "read" } else { "not read" },
                if p.rotate_key { "asked" } else { "not asked" },
                p.wait
            ));
        }
        for finding in &self.findings {
            let outcome = match finding.outcome {
                Outcome::Passed => "PASS",
                Outcome::Failed => "FAIL",
                Outcome::Inconclusive => "????",
                Outcome::Skipped => "SKIP",
                Outcome::NotApplicable => "N/A ",
            };
            text.push_str(&format!(
                "{outcome}  {}\n      {}\n      {}\n",
                finding.id, finding.detail, finding.reference
            ));
        }
        let s = self.summary;
        text.push_str(&format!(
            "\n{} passed, {} failed, {} inconclusive, {} skipped, {} not applicable\n",
            s.passed, s.failed, s.inconclusive, s.skipped, s.not_applicable
        ));
        text
    }
}

/// The finding for an exchange that didn't complete.
const fn unreachable(id: &'static str, reference: &'static str) -> Finding {
    Finding {
        id,
        outcome: Outcome::Inconclusive,
        reference,
        detail: "The exchange didn't complete: the target was unreachable, refused by the \
                 destination policy, too slow, or answered beyond the size bounds. Nothing \
                 is concluded about the server.",
    }
}

/// `discover`: sends OPTIONS to the grant endpoint and checks the discovery
/// document (RFC 9635 §9). No link it announces is fetched.
pub fn discover(transport: &impl HttpTransport, endpoint: &str, started: u64) -> Report {
    let findings = transport
        .send(HttpRequest::new("OPTIONS", endpoint).header("Accept", "application/json"))
        .map_or_else(
            |_| {
                vec![unreachable(
                    "discovery-exchange",
                    "https://www.rfc-editor.org/rfc/rfc9635.html#section-9",
                )]
            },
            |response| {
                discovery::checks(
                    &response.body,
                    Some(&response.headers),
                    Some(response.status),
                    Some(endpoint),
                )
                .into_iter()
                .map(Finding::from)
                .collect()
            },
        );
    Report::new("discover", endpoint, started, findings)
}

/// `probe`: sends the fixed malformed initial grant request, which carries
/// no client and no proof, and checks the refusal (RFC 9635 §3.6).
pub fn probe(transport: &impl HttpTransport, endpoint: &str, started: u64) -> Report {
    let mut request = HttpRequest::new("POST", endpoint)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json");
    request.body = Some(probe::MALFORMED_GRANT.to_vec());
    let findings = transport.send(request).map_or_else(
        |_| {
            vec![unreachable(
                "rejection-exchange",
                "https://www.rfc-editor.org/rfc/rfc9635.html#section-3.6",
            )]
        },
        |response| {
            probe::rejection_checks(response.status, &response.headers, &response.body)
                .into_iter()
                .map(Finding::from)
                .collect()
        },
    );
    Report::new("probe", endpoint, started, findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnap_client::HttpResponse;

    /// Answers every request with the same response, or fails.
    struct Scripted(Option<HttpResponse>);
    impl HttpTransport for Scripted {
        type Error = &'static str;
        fn send(&self, _: HttpRequest) -> Result<HttpResponse, Self::Error> {
            self.0.clone().ok_or("unreachable")
        }
    }

    const ENDPOINT: &str = "https://as.example/gnap";

    fn json(status: u16, body: &serde_json::Value) -> Scripted {
        Scripted(Some(HttpResponse {
            status,
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
                ("Cache-Control".into(), "no-store".into()),
            ],
            body: serde_json::to_vec(body).unwrap(),
        }))
    }

    #[test]
    fn a_valid_discovery_document_passes_the_selected_checks() {
        let report = discover(
            &json(
                200,
                &serde_json::json!({"grant_request_endpoint": ENDPOINT}),
            ),
            ENDPOINT,
            1,
        );
        assert_eq!(report.summary.failed, 0, "{}", report.text());
        assert!(report.summary.passed > 0);
        assert_eq!(report.exit_code(), 0);
        assert_eq!(report.schema, SCHEMA);
    }

    #[test]
    fn a_deviation_fails_and_an_unreachable_target_decides_nothing() {
        let elsewhere = discover(
            &json(
                200,
                &serde_json::json!({"grant_request_endpoint": "https://other.example/gnap"}),
            ),
            ENDPOINT,
            1,
        );
        assert!(elsewhere
            .findings
            .iter()
            .any(|f| f.id == "discovery-endpoint-match" && f.outcome == Outcome::Failed));
        assert_eq!(elsewhere.exit_code(), 1);

        let unreachable = discover(&Scripted(None), ENDPOINT, 1);
        assert_eq!(unreachable.summary.inconclusive, 1);
        assert_eq!(unreachable.exit_code(), 2);
    }

    #[test]
    fn the_probe_expects_a_gnap_error_and_refuses_success_fields() {
        let refused = probe(
            &json(
                400,
                &serde_json::json!({"error": {"code": "invalid_request"}}),
            ),
            ENDPOINT,
            1,
        );
        assert_eq!(refused.summary.failed, 0, "{}", refused.text());
        let accepted = probe(
            &json(200, &serde_json::json!({"access_token": {"value": "x"}})),
            ENDPOINT,
            1,
        );
        assert_eq!(accepted.exit_code(), 1, "{}", accepted.text());
    }

    /// An unknown capability name leaves its registration undecided: alone,
    /// the report is inconclusive; next to a deviation, the deviation wins
    /// and both findings stay.
    #[test]
    fn an_undecided_check_is_inconclusive_not_skipped() {
        let minimal = discover(
            &json(
                200,
                &serde_json::json!({"grant_request_endpoint": ENDPOINT}),
            ),
            ENDPOINT,
            1,
        );
        assert_eq!(minimal.exit_code(), 0, "{}", minimal.text());
        let unknown = discover(
            &json(
                200,
                &serde_json::json!({"grant_request_endpoint": ENDPOINT,
                    "key_proofs_supported": ["synthetic-unknown-method"]}),
            ),
            ENDPOINT,
            1,
        );
        let proofs = unknown
            .findings
            .iter()
            .find(|f| f.id == "key_proofs_supported")
            .unwrap();
        assert_eq!(proofs.outcome, Outcome::Inconclusive);
        assert_eq!(unknown.exit_code(), 2, "{}", unknown.text());
        let both = discover(
            &json(
                200,
                &serde_json::json!({"grant_request_endpoint": "https://other.example/gnap",
                    "key_proofs_supported": ["synthetic-unknown-method"]}),
            ),
            ENDPOINT,
            1,
        );
        assert_eq!(both.exit_code(), 1);
        assert_eq!(
            (both.summary.failed, both.summary.inconclusive),
            (1, 1),
            "{}",
            both.text()
        );
    }

    /// A repeated `Content-Type` makes the refusal's media type ambiguous.
    #[test]
    fn a_repeated_content_type_fails_the_refusal() {
        let mut response = json(
            400,
            &serde_json::json!({"error": {"code": "invalid_request"}}),
        );
        if let Some(response) = response.0.as_mut() {
            response
                .headers
                .push(("Content-Type".into(), "text/plain".into()));
        }
        let report = probe(&response, ENDPOINT, 1);
        let media = report
            .findings
            .iter()
            .find(|f| f.id == "error-response-json")
            .unwrap();
        assert_eq!(media.outcome, Outcome::Failed);
        assert_eq!(report.exit_code(), 1);
    }

    /// A code the registry snapshot doesn't know may be newer than it: the
    /// refusal check is undecided, not failed.
    #[test]
    fn an_unregistered_error_code_is_undecided() {
        let report = probe(
            &json(
                400,
                &serde_json::json!({"error": {"code": "synthetic_future_code"}}),
            ),
            ENDPOINT,
            1,
        );
        let known = report
            .findings
            .iter()
            .find(|f| f.id == "known-error-code")
            .unwrap();
        assert_eq!(known.outcome, Outcome::Inconclusive, "{}", report.text());
        assert_eq!(report.exit_code(), 2);
    }

    #[test]
    fn no_passing_check_is_never_a_success() {
        let report = Report::new(
            "discover",
            ENDPOINT,
            1,
            vec![Finding {
                id: "only-skipped",
                outcome: Outcome::Skipped,
                reference: "",
                detail: "",
            }],
        );
        assert_eq!(report.exit_code(), 2);
    }

    #[test]
    fn the_json_report_has_a_stable_shape() {
        let report = discover(&Scripted(None), ENDPOINT, 7);
        let value = serde_json::to_value(&report).unwrap();
        for member in [
            "schema", "tool", "version", "command", "target", "started", "findings", "summary",
            "scope",
        ] {
            assert!(value.get(member).is_some(), "{member}");
        }
        assert_eq!(value["findings"][0]["outcome"], "inconclusive");
    }
}
